/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#include <libfdt.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/sunddi.h>

/*
 * XXXARM:
 *
 * The rest of the system expects the "PROM" to provide device name and
 * unit-address as properties, however the devicetree specification gives
 * nodes true names, formed <name>@<unit-address>.
 *
 * We synthesize these properties at runtime, rather unfortunately.  An
 * alternative is to stuff them as actual properties into the devicetree, but
 * depending on platform this runs us out of string space in the FDT.
 *
 * It's possible in future it would be better to:
 * 1) Just resize the FDT to be big enough in prom_init (though this
 *    would move it, and leave the old one dangling).
 * 2) Specify a larger FDT in u-boot or other boot firmware
 * 3) Copy the whole FDT into a data structure of our own,
 *    rather than manipulating the actual FDT.
 */

static const struct fdt_header *fdtp;

/*
 * This exists to keep us from trying to check for over-long property names
 * before the system can support us doing it.
 *
 * Can be tuned _to 0_ to prevent any warnings.  Tuning to 1 is absolutely
 * fatal.
 */
#ifdef DEBUG
int prom_propname_warn = -1;
#else
int prom_propname_warn = 0;
#endif

const struct fdt_header *
prom_get_fdtp(void)
{
	return (fdtp);
}

static phandle_t
get_phandle(int offset)
{
	int len;
	uint32_t v;
	const void *prop = fdt_getprop(fdtp, offset, "phandle", &len);

	VERIFY3P(prop, !=, NULL);
	VERIFY3U(len, ==, sizeof (uint32_t));

	memcpy(&v, prop, sizeof (uint32_t));
	return (ntohl(v));
}

pnode_t
prom_fdt_findnode_by_phandle(phandle_t phandle)
{
	int offset = fdt_node_offset_by_phandle(fdtp, phandle);
	if (offset < 0)
		return (-1);
	return ((pnode_t)phandle);
}

static void
prom_check_overlong_property(pnode_t nodeid, const char *name)
{
	/*
	 * We are called very early in boot, in limited circumstances.  So
	 * early we can't actually tell anyone we've failed.  Bail out if
	 * we're unready, or have been tuned off.
	 */
	if (prom_propname_warn <= 0)
		return;

	if ((strlen(name) + 1) > OBP_STANDARD_MAXPROPNAME) {
		int offset = fdt_node_offset_by_phandle(fdtp, nodeid);
		const char *nodename = NULL;
		int len;

		if (offset < 0)
			goto no_name;

		nodename = fdt_get_name(fdtp, offset, &len);
		if ((nodename == NULL) || nodename[0] == '\0')
			goto no_name;

		cmn_err(CE_WARN,
		    "PROM node '%s' request for over long property '%s'",
		    nodename, name);
		return;

no_name:
		cmn_err(CE_WARN,
		    "PROM node %u request for over long property '%s'",
		    nodeid, name);
	}
}

int
prom_getprop(pnode_t nodeid, const char *name, caddr_t value)
{
	int offset = fdt_node_offset_by_phandle(fdtp, nodeid);

	prom_check_overlong_property(nodeid, name);

	if (offset < 0)
		return (-1);

	int len;
	const void *prop = fdt_getprop(fdtp, offset, name, &len);

	if (prop == NULL) {
		if (strcmp(name, "name") == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');

			if (!name_ptr)
				return (-1);

			if (p) {
				len = p - name_ptr;
			} else {
				len = strlen(name_ptr);
			}
			memcpy(value, name_ptr, len);
			value[len] = '\0';

			return (len + 1);
		}
		if (strcmp(name, "unit-address") == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				p++;
				len = strlen(p);
			} else {
				return (-1);
			}
			if (len == 0)
				return (-1);

			memcpy(value, p, len);
			value[len] = '\0';
			return (len + 1);
		}

		return (-1);
	}

	memcpy(value, prop, len);
	return (len);
}

int
prom_getproplen(pnode_t nodeid, const char *name)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);

	if (offset < 0)
		return (-1);

	prom_check_overlong_property(nodeid, name);

	int len;
	const struct fdt_property *prop = fdt_get_property(fdtp, offset, name,
	    &len);

	if (prop == NULL) {
		if (strcmp(name, "name") == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			if (!name_ptr)
				return (-1);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				len = p - name_ptr;
			} else {
				len = strlen(name_ptr);
			}

			return (len + 1);
		}
		if (strcmp(name, "unit-address") == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			if (!name_ptr)
				return (-1);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				p++;
				len = strlen(p);
			} else {
				return (-1);
			}
			if (len == 0)
				return (-1);
			return (len + 1);
		}

		return (-1);
	}

	return (len);
}

pnode_t
prom_finddevice(const char *device)
{
	int offset = fdt_path_offset(fdtp, device);
	if (offset < 0)
		return (OBP_BADNODE);

	phandle_t phandle = get_phandle(offset);
	if (phandle < 0)
		return (OBP_BADNODE);

	return ((pnode_t)phandle);
}

pnode_t
prom_rootnode(void)
{
	pnode_t root = prom_finddevice("/");
	if (root < 0) {
		return (OBP_NONODE);
	}
	return (root);
}

pnode_t
prom_chosennode(void)
{
	pnode_t node = prom_finddevice("/chosen");
	if (node != OBP_BADNODE)
		return (node);
	return (OBP_NONODE);
}

pnode_t
prom_optionsnode(void)
{
	pnode_t node = prom_finddevice("/options");
	if (node != OBP_BADNODE)
		return (node);
	return (OBP_NONODE);
}

/*
 * Returning NULL means something went wrong, returning '\0' means no more
 * properties.
 */
char *
prom_nextprop(pnode_t nodeid, const char *name, char *next)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return (NULL);

	/*
	 * The first time we're called, present the "name" pseudo-property
	 */
	if (name[0] == '\0') {
		strlcpy(next, "name", OBP_MAXPROPNAME);
		return (next);
	}

	/*
	 * The second time we're called, present the "unit-address"
	 * pseudo-property, if appropriate
	 */
	if (strcmp(name, "name") == 0) {
		int len;
		const char *fullname = fdt_get_name(fdtp, offset, &len);

		if (strchr(fullname, '@') != NULL) {
			strlcpy(next, "unit-address", OBP_MAXPROPNAME);
			return (next);
		}

		/* Fall through to get real properties */
	}

	*next = '\0';
	offset = fdt_first_property_offset(fdtp, offset);
	if (offset < 0) {
		return (next);
	}

	const struct fdt_property *data;
	for (;;) {
		data = fdt_get_property_by_offset(fdtp, offset, NULL);
		const char *name0 = fdt_string(fdtp,
		    fdt32_to_cpu(data->nameoff));
		if (name0) {
			/*
			 * If we reach here with name equal to one of our
			 * pseudo-properties, give the first real property.
			 */
			if ((strcmp(name, "name") == 0) ||
			    (strcmp(name, "unit-address") == 0)) {
				strlcpy(next, name0, OBP_MAXPROPNAME);
				return (next);
			}
			if (strcmp(name, name0) == 0)
				break;
		}
		offset = fdt_next_property_offset(fdtp, offset);
		if (offset < 0) {
			return (next);
		}
	}
	offset = fdt_next_property_offset(fdtp, offset);
	if (offset < 0) {
		return (next);
	}
	data = fdt_get_property_by_offset(fdtp, offset, NULL);
	strlcpy(next, (char *)fdt_string(fdtp, fdt32_to_cpu(data->nameoff)),
	    OBP_MAXPROPNAME);
	return (next);
}

pnode_t
prom_nextnode(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return (prom_rootnode());

	int offset = fdt_node_offset_by_phandle(fdtp, (phandle_t)nodeid);
	if (offset < 0)
		return (OBP_BADNODE);

	int child = fdt_next_subnode(fdtp, offset);
	if (child == -FDT_ERR_NOTFOUND) {
		return (OBP_NONODE);
	} else if (child < 0) {
		return (OBP_BADNODE);
	}

	phandle_t phandle = get_phandle(child);
	if (phandle < 0)
		return (OBP_NONODE);

	return ((pnode_t)phandle);
}

pnode_t
prom_childnode(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return (prom_rootnode());

	int offset = fdt_node_offset_by_phandle(fdtp, (phandle_t)nodeid);
	if (offset < 0)
		return (OBP_NONODE);

	int child = fdt_first_subnode(fdtp, offset);
	if (child == -FDT_ERR_NOTFOUND) {
		return (OBP_NONODE);
	} else if (child < 0) {
		return (OBP_BADNODE);
	}

	phandle_t phandle = get_phandle(child);
	if (phandle < 0)
		return (OBP_NONODE);
	return ((pnode_t)phandle);
}

pnode_t
prom_fdt_parentnode(pnode_t nodeid)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return (OBP_NONODE);

	int parent_offset = fdt_parent_offset(fdtp, offset);
	if (parent_offset < 0)
		return (OBP_NONODE);
	phandle_t phandle = get_phandle(parent_offset);
	if (phandle < 0)
		return (OBP_NONODE);
	return ((pnode_t)phandle);
}

char *
prom_decode_composite_string(void *buf, size_t buflen, char *prev)
{
	if ((buf == 0) || (buflen == 0) || ((int)buflen == -1))
		return (NULL);

	if (prev == 0)
		return (buf);

	prev += strlen(prev) + 1;
	if (prev >= ((char *)buf + buflen))
		return (NULL);
	return (prev);
}

int
prom_bounded_getprop(pnode_t nodeid, char *name, caddr_t value, int len)
{
	int prop_len = prom_getproplen(nodeid, name);
	if (prop_len < 0 || len < prop_len) {
		return (-1);
	}

	return (prom_getprop(nodeid, name, value));
}

pnode_t
prom_alias_node(void)
{
	return (OBP_BADNODE);
}

/*ARGSUSED*/
void
prom_pathname(char *buf)
{
	/* nothing, just to get consconfig_dacf to compile */
}

/*
 * `prom_init' for devicetree systems expects that a valid non-NULL DTB is
 * passed in the `cookie' argument.
 *
 * The passed DTB pointer is treated as read-only, so the various bootloaders
 * involved in bringing up the system are expected to peform any fixups that
 * may be needed prior to starting `unix'.
 */
void
prom_init(char *pgmname, void *cookie)
{
	if (fdt_check_header((struct fdt_header *)cookie) == 0)
		fdtp = (const struct fdt_header *)cookie;
}

void
prom_setup(void)
{
	if (prom_propname_warn == -1)
		prom_propname_warn = 1;
}

static void
prom_walk_dev(pnode_t nodeid, void(*func)(pnode_t, void*), void *arg)
{
	func(nodeid, arg);

	pnode_t child = prom_childnode(nodeid);
	while (child > 0) {
		prom_walk_dev(child, func, arg);
		child = prom_nextnode(child);
	}
}

void
prom_fdt_walk(void(*func)(pnode_t, void*), void *arg)
{
	prom_walk_dev(prom_rootnode(), func, arg);
}
