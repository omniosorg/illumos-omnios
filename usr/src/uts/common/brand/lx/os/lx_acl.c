/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * POSIX ACLs.
 *
 * Linux keeps POSIX draft ACLs in the system.posix_acl_access and
 * system.posix_acl_default extended attributes. illumos file systems keep
 * either NFSv4-style ACEs (ZFS) or POSIX draft aclent_t entries (UFS), and
 * acl_translate() converts between the two. tmpfs has no ACLs. Linux sets
 * the access and the default ACL separately, but here they are stored
 * together, so each change reads the current ACL as aclent_t entries,
 * replaces one half and writes the whole ACL back. The Linux tag values are
 * the same as the aclent_t types, with default entries also carrying
 * ACL_DEFAULT.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/sunddi.h>
#include <sys/pathname.h>
#include <sys/unistd.h>
#include <sys/acl.h>
#include <acl/acl_common.h>
#include <sys/lx_acl.h>


typedef struct {
	uint16_t lpaxe_tag;
	uint16_t lpaxe_perm;
	uint32_t lpaxe_id;
} lx_posix_acl_xattr_entry_t;

typedef struct {
	uint32_t			lpaxh_version;
	lx_posix_acl_xattr_entry_t	lpaxh_entries[];
} lx_posix_acl_xattr_header_t;

#define	LX_POSIX_ACL_XATTR_VERSION	0x0002
#define	LX_ACL_UNDEFINED_ID		((uint32_t)-1)
#define	LX_ACL_PERM_MASK		0x7

/* e_tag entry in struct posix_acl_entry */
#define	LX_ACL_USER_OBJ		0x01	/* USER_OBJ	*/
#define	LX_ACL_USER		0x02	/* USER		*/
#define	LX_ACL_GROUP_OBJ	0x04	/* GROUP_OBJ	*/
#define	LX_ACL_GROUP		0x08	/* GROUP	*/
#define	LX_ACL_MASK		0x10	/* CLASS_OBJ	*/
#define	LX_ACL_OTHER		0x20	/* OTHER_OBJ	*/

CTASSERT(LX_ACL_USER_OBJ == USER_OBJ && LX_ACL_USER == USER &&
    LX_ACL_GROUP_OBJ == GROUP_OBJ && LX_ACL_GROUP == GROUP &&
    LX_ACL_MASK == CLASS_OBJ && LX_ACL_OTHER == OTHER_OBJ);

static int
lx_acl_from_xattr(enum lx_acl_type atype, void *xattr, uint_t xlen,
    acl_t **aclpp)
{
	lx_posix_acl_xattr_header_t *head = xattr;
	lx_posix_acl_xattr_entry_t *entry;
	int err = 0;
	uint_t count, sz = xlen;
	const uint_t mask = (atype == LX_ACL_DEFAULT) ? ACL_DEFAULT : 0;
	acl_t *acl;
	aclent_t *acle;

	if (xattr == NULL) {
		/* Handle zero-length set operations */
		acl = acl_alloc(ACLENT_T);
		*aclpp = acl;
		return (0);
	}

	if (xlen < sizeof (*head)) {
		return (EINVAL);
	} else if (head->lpaxh_version != LX_POSIX_ACL_XATTR_VERSION) {
		return (EOPNOTSUPP);
	}

	sz -= sizeof (lx_posix_acl_xattr_header_t);
	if (sz % sizeof (lx_posix_acl_xattr_entry_t) != 0) {
		return (EINVAL);
	}
	count = sz / sizeof (lx_posix_acl_xattr_entry_t);

	acl = acl_alloc(ACLENT_T);
	if (count == 0) {
		*aclpp = acl;
		return (0);
	}

	acle = kmem_zalloc(count * sizeof (aclent_t), KM_SLEEP);
	acl->acl_cnt = count;
	acl->acl_aclp = acle;
	entry = head->lpaxh_entries;
	for (uint_t i = 0; i < count && err == 0; i++, entry++, acle++) {
		switch (entry->lpaxe_tag) {
		case LX_ACL_USER_OBJ:
		case LX_ACL_GROUP_OBJ:
		case LX_ACL_OTHER:
		case LX_ACL_MASK:
			acle->a_id = 0;
			break;
		case LX_ACL_USER:
		case LX_ACL_GROUP:
			if (entry->lpaxe_id > MAXUID)
				err = EINVAL;
			acle->a_id = entry->lpaxe_id;
			break;
		default:
			err = EINVAL;
			break;
		}
		acle->a_type = entry->lpaxe_tag | mask;
		acle->a_perm = entry->lpaxe_perm & LX_ACL_PERM_MASK;
	}
	if (err != 0) {
		acl_free(acl);
		return (err);
	}

	*aclpp = acl;
	return (0);
}

/*
 * Find out which kind of ACL, if any, the file system keeps.
 */
static int
lx_acl_flavor(vnode_t *vp, int *flavorp)
{
	ulong_t val;

	if (VOP_PATHCONF(vp, _PC_ACL_ENABLED, &val, CRED(), NULL) != 0 ||
	    val == 0) {
		return (EOPNOTSUPP);
	}
	*flavorp = ((val & _ACL_ACE_ENABLED) != 0) ? _ACL_ACE_ENABLED :
	    _ACL_ACLENT_ENABLED;
	return (0);
}

static boolean_t
lx_acl_ent_is(const aclent_t *acle, enum lx_acl_type atype)
{
	boolean_t isdef = (acle->a_type & ACL_DEFAULT) != 0;

	return (isdef == (atype == LX_ACL_DEFAULT));
}

/*
 * An access ACL with only the owner, group and other entries just mirrors
 * the file mode, and Linux reports it as absent. A mask equal to the group
 * entry, with no named entries, changes nothing either, and translated
 * ACLs often have one. Any default entries make up a default ACL.
 */
static boolean_t
lx_acl_is_extended(const acl_t *acl, enum lx_acl_type atype)
{
	const aclent_t *acle = acl->acl_aclp;
	int gperm = -1, mperm = -1;

	for (int i = 0; i < acl->acl_cnt; i++) {
		if (!lx_acl_ent_is(&acle[i], atype))
			continue;
		if (atype == LX_ACL_DEFAULT)
			return (B_TRUE);
		switch (acle[i].a_type) {
		case USER:
		case GROUP:
			return (B_TRUE);
		case GROUP_OBJ:
			gperm = acle[i].a_perm;
			break;
		case CLASS_OBJ:
			mperm = acle[i].a_perm;
			break;
		default:
			break;
		}
	}
	return (mperm >= 0 && mperm != gperm);
}

/*
 * An ACL with neither an extended access ACL nor a default ACL.
 */
static boolean_t
lx_acl_is_mode_only(const acl_t *acl)
{
	return (!lx_acl_is_extended(acl, LX_ACL_ACCESS) &&
	    !lx_acl_is_extended(acl, LX_ACL_DEFAULT));
}

/*
 * The file mode equivalent to a mode-only ACL.
 */
static mode_t
lx_acl_mode(const acl_t *acl)
{
	const aclent_t *acle = acl->acl_aclp;
	mode_t mode = 0;

	for (int i = 0; i < acl->acl_cnt; i++) {
		switch (acle[i].a_type) {
		case USER_OBJ:
			mode |= (acle[i].a_perm & LX_ACL_PERM_MASK) << 6;
			break;
		case GROUP_OBJ:
			mode |= (acle[i].a_perm & LX_ACL_PERM_MASK) << 3;
			break;
		case OTHER_OBJ:
			mode |= acle[i].a_perm & LX_ACL_PERM_MASK;
			break;
		default:
			break;
		}
	}
	return (mode);
}

/*
 * Work out the read, write and execute permissions which an ACE ACL grants
 * one principal, taking the first ACE which decides each right as ZFS does.
 */
static uint16_t
lx_acl_ace_perm(const ace_t *ace, int cnt, int who, uid_t id, uid_t owner,
    gid_t group)
{
	static const struct {
		uint32_t	ace_bit;
		uint16_t	perm;
	} bits[] = {
		{ ACE_READ_DATA,	4 },
		{ ACE_WRITE_DATA,	2 },
		{ ACE_EXECUTE,		1 }
	};
	uint16_t perm = 0;

	for (uint_t b = 0; b < ARRAY_SIZE(bits); b++) {
		for (int i = 0; i < cnt; i++) {
			uint16_t f = ace[i].a_flags;
			boolean_t everyone = (f & ACE_EVERYONE) != 0;
			boolean_t gobj = (f & ACE_GROUP) != 0;
			boolean_t ngroup = !gobj &&
			    (f & ACE_IDENTIFIER_GROUP) != 0;
			boolean_t nuser = (f & (ACE_OWNER | ACE_GROUP |
			    ACE_EVERYONE | ACE_IDENTIFIER_GROUP)) == 0;
			boolean_t match;

			if ((f & ACE_INHERIT_ONLY_ACE) != 0 ||
			    (ace[i].a_access_mask & bits[b].ace_bit) == 0 ||
			    (ace[i].a_type != ACE_ACCESS_ALLOWED_ACE_TYPE &&
			    ace[i].a_type != ACE_ACCESS_DENIED_ACE_TYPE)) {
				continue;
			}

			switch (who) {
			case USER_OBJ:
				match = everyone || (f & ACE_OWNER) != 0 ||
				    (nuser && ace[i].a_who == owner);
				break;
			case USER:
				match = everyone ||
				    (nuser && ace[i].a_who == id);
				break;
			case GROUP_OBJ:
				match = everyone || gobj ||
				    (ngroup && ace[i].a_who == group);
				break;
			case GROUP:
				match = everyone ||
				    (ngroup && ace[i].a_who == id);
				break;
			default:
				match = everyone;
				break;
			}
			if (!match)
				continue;
			if (ace[i].a_type == ACE_ACCESS_ALLOWED_ACE_TYPE)
				perm |= bits[b].perm;
			break;
		}
	}
	return (perm);
}

/*
 * Append an entry of type "who", USER or GROUP, for each distinct named user
 * or group in the ACE ACL. Returns the new entry count.
 */
static int
lx_acl_add_named(aclent_t *acle, int n, int who, const ace_t *ace, int cnt,
    uid_t owner, gid_t group)
{
	for (int i = 0; i < cnt; i++) {
		uint16_t f = ace[i].a_flags;
		boolean_t seen = B_FALSE;
		boolean_t named;

		if (who == USER) {
			named = (f & (ACE_OWNER | ACE_GROUP | ACE_EVERYONE |
			    ACE_IDENTIFIER_GROUP)) == 0;
		} else {
			named = (f & ACE_IDENTIFIER_GROUP) != 0 &&
			    (f & ACE_GROUP) == 0;
		}
		if (!named || (f & ACE_INHERIT_ONLY_ACE) != 0)
			continue;

		for (int j = 0; j < n && !seen; j++) {
			seen = acle[j].a_type == who &&
			    acle[j].a_id == ace[i].a_who;
		}
		if (seen)
			continue;

		acle[n].a_type = who;
		acle[n].a_id = ace[i].a_who;
		acle[n].a_perm = lx_acl_ace_perm(ace, cnt, who, ace[i].a_who,
		    owner, group);
		n++;
	}
	return (n);
}

/*
 * acl_translate() only understands ACE ACLs that look like the ones it
 * creates. ZFS rewrites the ACLs it creates by inheritance, marking the
 * entries as inherited and, depending on aclinherit, trimming rights and
 * appending entries for the file mode. For those, build the access ACL from
 * the rights which the ACEs grant to the owner, each named user, the group,
 * each named group and everyone else. Named entries keep their effective
 * rights, and the mask allows all of them.
 */
static acl_t *
lx_acl_from_aces(const ace_t *ace, int cnt, uid_t owner, gid_t group)
{
	/* Owner, group, mask and other, plus at most one per ACE. */
	const size_t sz = (cnt + 4) * sizeof (aclent_t);
	aclent_t *acle;
	acl_t *acl;
	int n = 0, nuser, ngroup;
	uint16_t mask = 0;

	acle = kmem_zalloc(sz, KM_SLEEP);

	acle[n].a_type = USER_OBJ;
	acle[n++].a_perm = lx_acl_ace_perm(ace, cnt, USER_OBJ, 0, owner, group);
	nuser = n;
	n = lx_acl_add_named(acle, n, USER, ace, cnt, owner, group);
	nuser = n - nuser;

	acle[n].a_type = GROUP_OBJ;
	acle[n++].a_perm = lx_acl_ace_perm(ace, cnt, GROUP_OBJ, 0, owner,
	    group);
	ngroup = n;
	n = lx_acl_add_named(acle, n, GROUP, ace, cnt, owner, group);
	ngroup = n - ngroup;

	if (nuser + ngroup > 0) {
		for (int i = 1; i < n; i++)
			mask |= acle[i].a_perm;
		acle[n].a_type = CLASS_OBJ;
		acle[n++].a_perm = mask;
	}
	acle[n].a_type = OTHER_OBJ;
	acle[n++].a_perm = lx_acl_ace_perm(ace, cnt, OTHER_OBJ, 0, owner,
	    group);

	acl = acl_alloc(ACLENT_T);
	acl->acl_cnt = n;
	acl->acl_aclp = kmem_alloc(n * sizeof (aclent_t), KM_SLEEP);
	bcopy(acle, acl->acl_aclp, n * sizeof (aclent_t));
	kmem_free(acle, sz);
	return (acl);
}

/*
 * Read the current ACL, access and default entries together, as aclent_t
 * entries. A trivial ACE ACL, one which only reflects the file mode, becomes
 * the owner, group and other entries for that mode. acl_translate() cannot
 * convert those, since they grant NFSv4 rights which POSIX doesn't have.
 * Other ACE ACLs which it cannot convert, such as those ZFS creates by
 * inheritance, go through lx_acl_from_aces().
 */
static int
lx_acl_read(vnode_t *vp, int flavor, acl_t **aclpp)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	vsecattr_t vsa;
	vattr_t va;
	acl_t *acl;
	int err;

	va.va_mask = AT_UID | AT_GID | AT_MODE;
	if ((err = VOP_GETATTR(vp, &va, 0, CRED(), NULL)) != 0)
		return (err);

	bzero(&vsa, sizeof (vsa));
	if (flavor == _ACL_ACE_ENABLED) {
		vsa.vsa_mask = VSA_ACE | VSA_ACECNT;
		if ((err = VOP_GETSECATTR(vp, &vsa, 0, CRED(), NULL)) != 0)
			return (err);

		if (ace_trivial(vsa.vsa_aclentp, vsa.vsa_aclcnt) == 0) {
			aclent_t *acle;

			if (vsa.vsa_aclentp != NULL)
				kmem_free(vsa.vsa_aclentp, vsa.vsa_aclentsz);

			acle = kmem_zalloc(3 * sizeof (aclent_t), KM_SLEEP);
			acle[0].a_type = USER_OBJ;
			acle[0].a_perm = (va.va_mode >> 6) & LX_ACL_PERM_MASK;
			acle[1].a_type = GROUP_OBJ;
			acle[1].a_perm = (va.va_mode >> 3) & LX_ACL_PERM_MASK;
			acle[2].a_type = OTHER_OBJ;
			acle[2].a_perm = va.va_mode & LX_ACL_PERM_MASK;

			acl = acl_alloc(ACLENT_T);
			acl->acl_cnt = 3;
			acl->acl_aclp = acle;
			*aclpp = acl;
			return (0);
		}

		acl = acl_alloc(ACE_T);
		acl->acl_cnt = vsa.vsa_aclcnt;
		if (vsa.vsa_aclcnt > 0) {
			acl->acl_aclp = kmem_alloc(vsa.vsa_aclcnt *
			    sizeof (ace_t), KM_SLEEP);
			bcopy(vsa.vsa_aclentp, acl->acl_aclp,
			    vsa.vsa_aclcnt * sizeof (ace_t));
		}
		if (vsa.vsa_aclentp != NULL)
			kmem_free(vsa.vsa_aclentp, vsa.vsa_aclentsz);

		err = acl_translate(acl, _ACL_ACLENT_ENABLED, is_dir,
		    va.va_uid, va.va_gid);
		if (err != 0) {
			acl_t *derived = lx_acl_from_aces(acl->acl_aclp,
			    acl->acl_cnt, va.va_uid, va.va_gid);

			acl_free(acl);
			acl = derived;
		}
	} else {
		int cnt;

		vsa.vsa_mask = VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT;
		if ((err = VOP_GETSECATTR(vp, &vsa, 0, CRED(), NULL)) != 0)
			return (err);

		cnt = vsa.vsa_aclcnt + vsa.vsa_dfaclcnt;
		acl = acl_alloc(ACLENT_T);
		acl->acl_cnt = cnt;
		if (cnt > 0) {
			acl->acl_aclp = kmem_alloc(cnt * sizeof (aclent_t),
			    KM_SLEEP);
		}
		if (vsa.vsa_aclcnt > 0) {
			bcopy(vsa.vsa_aclentp, acl->acl_aclp,
			    vsa.vsa_aclcnt * sizeof (aclent_t));
			kmem_free(vsa.vsa_aclentp,
			    vsa.vsa_aclcnt * sizeof (aclent_t));
		}
		if (vsa.vsa_dfaclcnt > 0) {
			bcopy(vsa.vsa_dfaclentp,
			    (aclent_t *)acl->acl_aclp + vsa.vsa_aclcnt,
			    vsa.vsa_dfaclcnt * sizeof (aclent_t));
			kmem_free(vsa.vsa_dfaclentp,
			    vsa.vsa_dfaclcnt * sizeof (aclent_t));
		}
	}

	*aclpp = acl;
	return (0);
}

/*
 * Write a combined aclent_t ACL back in the file system's own form. The
 * caller holds the vnode's write lock.
 */
static int
lx_acl_write(vnode_t *vp, int flavor, acl_t *acl)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	vsecattr_t vsa;
	vattr_t va;
	int err;

	bzero(&vsa, sizeof (vsa));
	if (flavor == _ACL_ACE_ENABLED && lx_acl_is_mode_only(acl)) {
		ace_t *ace;
		int cnt;

		/*
		 * Write the trivial ACL for the equivalent mode, which is what
		 * ZFS itself keeps for a file without an ACL. Translating the
		 * entries would give an equivalent but non-trivial ACL.
		 */
		err = acl_trivial_create(lx_acl_mode(acl), is_dir, &ace, &cnt);
		if (err != 0)
			return (err);
		vsa.vsa_mask = VSA_ACE;
		vsa.vsa_aclcnt = cnt;
		vsa.vsa_aclentp = ace;
		vsa.vsa_aclentsz = cnt * sizeof (ace_t);
		err = VOP_SETSECATTR(vp, &vsa, 0, CRED(), NULL);
		kmem_free(ace, cnt * sizeof (ace_t));
		return (err);
	} else if (flavor == _ACL_ACE_ENABLED) {
		va.va_mask = AT_UID | AT_GID;
		if ((err = VOP_GETATTR(vp, &va, 0, CRED(), NULL)) != 0)
			return (err);
		err = acl_translate(acl, _ACL_ACE_ENABLED, is_dir, va.va_uid,
		    va.va_gid);
		if (err != 0)
			return (err);

		vsa.vsa_mask = VSA_ACE;
		vsa.vsa_aclcnt = acl->acl_cnt;
		vsa.vsa_aclentp = acl->acl_aclp;
		vsa.vsa_aclentsz = acl->acl_cnt * sizeof (ace_t);
	} else {
		aclent_t *acle = acl->acl_aclp;
		int i;

		/* Access entries come first, then the default entries. */
		for (i = 0; i < acl->acl_cnt; i++) {
			if ((acle[i].a_type & ACL_DEFAULT) != 0)
				break;
		}
		vsa.vsa_mask = VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT;
		vsa.vsa_aclcnt = i;
		vsa.vsa_aclentp = acle;
		vsa.vsa_dfaclcnt = acl->acl_cnt - i;
		vsa.vsa_dfaclentp = (vsa.vsa_dfaclcnt > 0) ? &acle[i] : NULL;
	}

	return (VOP_SETSECATTR(vp, &vsa, 0, CRED(), NULL));
}

/*
 * Build a combined ACL from the entries of the current ACL which are not of
 * type atype together with the replacement entries, keeping the access
 * entries before the default entries.
 */
static acl_t *
lx_acl_merge(const acl_t *cur, enum lx_acl_type atype, const aclent_t *repl,
    int nrepl)
{
	const aclent_t *cacle = cur->acl_aclp;
	aclent_t *nacle;
	acl_t *acl;
	int keep = 0, n = 0;

	for (int i = 0; i < cur->acl_cnt; i++) {
		if (!lx_acl_ent_is(&cacle[i], atype))
			keep++;
	}

	acl = acl_alloc(ACLENT_T);
	acl->acl_cnt = keep + nrepl;
	if (acl->acl_cnt == 0)
		return (acl);
	nacle = kmem_alloc(acl->acl_cnt * sizeof (aclent_t), KM_SLEEP);
	acl->acl_aclp = nacle;

	if (atype == LX_ACL_ACCESS) {
		bcopy(repl, nacle, nrepl * sizeof (aclent_t));
		n = nrepl;
	}
	for (int i = 0; i < cur->acl_cnt; i++) {
		if (!lx_acl_ent_is(&cacle[i], atype))
			nacle[n++] = cacle[i];
	}
	if (atype == LX_ACL_DEFAULT)
		bcopy(repl, &nacle[n], nrepl * sizeof (aclent_t));

	return (acl);
}

/*
 * The access entries which just mirror the file mode, and which replace an
 * extended access ACL when it is removed. As on Linux, the group entry takes
 * the mask's permissions, since those are what the mode's group bits show.
 */
static void
lx_acl_minimal(const acl_t *cur, aclent_t min[3])
{
	const aclent_t *acle = cur->acl_aclp;
	int gperm = 0, mperm = -1;

	bzero(min, 3 * sizeof (aclent_t));
	min[0].a_type = USER_OBJ;
	min[1].a_type = GROUP_OBJ;
	min[2].a_type = OTHER_OBJ;
	for (int i = 0; i < cur->acl_cnt; i++) {
		switch (acle[i].a_type) {
		case USER_OBJ:
			min[0].a_perm = acle[i].a_perm;
			break;
		case GROUP_OBJ:
			gperm = acle[i].a_perm;
			break;
		case CLASS_OBJ:
			mperm = acle[i].a_perm;
			break;
		case OTHER_OBJ:
			min[2].a_perm = acle[i].a_perm;
			break;
		default:
			break;
		}
	}
	min[1].a_perm = (mperm >= 0) ? mperm : gperm;
}

/*
 * Because systemd has decided to scope-creep its way into a position
 * of moribund domination over all things system software, there exist
 * work-arounds which are required to address its numerous bugs and
 * shortcomings.  One such case involves the FreeIPA installer needing
 * to perform setfacl(3) on /run/systemd/ask-password.
 *
 * Where the file system has no ACL support at all, faked success for root
 * under /run/systemd is the only palatable course of action.
 *
 * See also: https://bugzilla.redhat.com/show_bug.cgi?id=1322167
 */
static int
lx_acl_fake_systemd(vnode_t *vp)
{
	cred_t *cr = CRED();
	int err = EOPNOTSUPP;

	if (crgetuid(cr) == 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if (vnodetopath(NULL, vp, path, MAXPATHLEN, cr) == 0 &&
		    strncmp(path, "/run/systemd/", 13) == 0) {
			/* Saccharin-sweet fake success */
			err = 0;
		}
		kmem_free(path, MAXPATHLEN);
	}
	return (err);
}

int
lx_acl_setxattr(vnode_t *vp, enum lx_acl_type atype, void *data, size_t len)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	acl_t *newacl = NULL, *cur = NULL, *acl;
	int flavor, err;

	if (vp->v_type == VLNK) {
		return (EOPNOTSUPP);
	} else if (atype == LX_ACL_DEFAULT && !is_dir) {
		return (EACCES);
	}

	if ((err = lx_acl_from_xattr(atype, data, len, &newacl)) != 0)
		return (err);

	if (lx_acl_flavor(vp, &flavor) != 0) {
		acl_free(newacl);
		return (lx_acl_fake_systemd(vp));
	}

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
	if ((err = lx_acl_read(vp, flavor, &cur)) == 0) {
		/*
		 * An empty access ACL leaves just the entries which mirror the
		 * file mode, as removing it does.
		 */
		if (atype == LX_ACL_ACCESS && newacl->acl_cnt == 0) {
			aclent_t min[3];

			lx_acl_minimal(cur, min);
			acl = lx_acl_merge(cur, atype, min, 3);
		} else {
			acl = lx_acl_merge(cur, atype, newacl->acl_aclp,
			    newacl->acl_cnt);
		}
		err = lx_acl_write(vp, flavor, acl);
		acl_free(acl);
		acl_free(cur);
	}
	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
	acl_free(newacl);

	return (err);
}

int
lx_acl_getxattr(vnode_t *vp, enum lx_acl_type atype, void *data, size_t slen,
    ssize_t *solen)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	lx_posix_acl_xattr_header_t *head = data;
	lx_posix_acl_xattr_entry_t *entry;
	const aclent_t *acle;
	acl_t *acl;
	size_t need;
	int flavor, err, n = 0;

	if (vp->v_type == VLNK) {
		return (EOPNOTSUPP);
	} else if (atype == LX_ACL_DEFAULT && !is_dir) {
		return (ENODATA);
	}

	if (lx_acl_flavor(vp, &flavor) != 0)
		return (ENODATA);
	if ((err = lx_acl_read(vp, flavor, &acl)) != 0)
		return ((err == ENOENT) ? ENODATA : err);

	if (!lx_acl_is_extended(acl, atype)) {
		acl_free(acl);
		return (ENODATA);
	}

	acle = acl->acl_aclp;
	for (int i = 0; i < acl->acl_cnt; i++) {
		if (lx_acl_ent_is(&acle[i], atype))
			n++;
	}
	need = sizeof (*head) + n * sizeof (*entry);

	/* A zero-length buffer asks for the size. */
	if (slen == 0) {
		acl_free(acl);
		*solen = need;
		return (0);
	} else if (slen < need) {
		acl_free(acl);
		return (ERANGE);
	}

	head->lpaxh_version = LX_POSIX_ACL_XATTR_VERSION;
	entry = head->lpaxh_entries;
	for (int i = 0; i < acl->acl_cnt; i++) {
		uint16_t tag;

		if (!lx_acl_ent_is(&acle[i], atype))
			continue;
		tag = acle[i].a_type & ~ACL_DEFAULT;
		entry->lpaxe_tag = tag;
		entry->lpaxe_perm = acle[i].a_perm & LX_ACL_PERM_MASK;
		entry->lpaxe_id = (tag == USER || tag == GROUP) ?
		    acle[i].a_id : LX_ACL_UNDEFINED_ID;
		entry++;
	}
	acl_free(acl);

	*solen = need;
	return (0);
}

int
lx_acl_removexattr(vnode_t *vp, enum lx_acl_type atype)
{
	acl_t *cur, *acl;
	int flavor, err;

	if (vp->v_type == VLNK)
		return (EOPNOTSUPP);
	if (lx_acl_flavor(vp, &flavor) != 0)
		return (ENODATA);

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
	if ((err = lx_acl_read(vp, flavor, &cur)) == 0) {
		if (!lx_acl_is_extended(cur, atype)) {
			err = ENODATA;
		} else if (atype == LX_ACL_ACCESS) {
			aclent_t min[3];

			lx_acl_minimal(cur, min);
			acl = lx_acl_merge(cur, atype, min, 3);
			err = lx_acl_write(vp, flavor, acl);
			acl_free(acl);
		} else {
			acl = lx_acl_merge(cur, atype, NULL, 0);
			err = lx_acl_write(vp, flavor, acl);
			acl_free(acl);
		}
		acl_free(cur);
	}
	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);

	return (err);
}

/*
 * Add the names of the ACL attributes which are present. *needp accumulates
 * the space needed, and the names are copied out if uio has room for any.
 */
int
lx_acl_listxattr(vnode_t *vp, uio_t *uio, size_t *needp)
{
	static const char *names[] = {
		"system." LX_XATTR_POSIX_ACL_ACCESS,
		"system." LX_XATTR_POSIX_ACL_DEFAULT
	};
	static const enum lx_acl_type types[] = {
		LX_ACL_ACCESS,
		LX_ACL_DEFAULT
	};
	acl_t *acl;
	int flavor, err = 0;

	if (vp->v_type == VLNK || lx_acl_flavor(vp, &flavor) != 0 ||
	    lx_acl_read(vp, flavor, &acl) != 0) {
		return (0);
	}

	for (uint_t i = 0; i < ARRAY_SIZE(names) && err == 0; i++) {
		size_t len = strlen(names[i]) + 1;

		if (!lx_acl_is_extended(acl, types[i]))
			continue;
		*needp += len;
		if (uio->uio_resid == 0)
			continue;
		if (uio->uio_resid < len) {
			err = ERANGE;
			break;
		}
		err = uiomove((void *)names[i], len, UIO_READ, uio);
	}
	acl_free(acl);

	return (err);
}
