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
 * Copyright 2016 Joyent, Inc.
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/model.h>
#include <sys/mode.h>
#include <sys/stat.h>
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_types.h>
#include <sys/lx_impl.h>
#include <sys/brand.h>
#include <sys/ddi.h>

/* From "uts/common/syscall/stat.c" */
extern int cstatat_getvp(int, char *, int, vnode_t **, cred_t **);

typedef struct lx_timespec32 {
	int32_t	ts_sec;
	int32_t	ts_nsec;
} lx_timespec32_t;

typedef struct lx_timespec64 {
	int64_t	ts_sec;
	int64_t	ts_nsec;
}lx_timespec64_t;

struct lx_stat32 {
	uint16_t	st_dev;
	uint16_t	st_pad1;
	uint32_t	st_ino;
	uint16_t	st_mode;
	uint16_t	st_nlink;
	uint16_t	st_uid;
	uint16_t	st_gid;
	uint16_t	st_rdev;
	uint16_t 	st_pad2;
	uint32_t	st_size;
	uint32_t	st_blksize;
	uint32_t	st_blocks;
	lx_timespec32_t	st_atime;
	lx_timespec32_t	st_mtime;
	lx_timespec32_t	st_ctime;
	uint32_t	st_pad3;
	uint32_t	st_pad4;
};

#pragma pack(4)
struct lx_stat64_32 {
	uint64_t	st_dev;
	uint32_t	st_pad1;
	uint32_t	st_small_ino;
	uint32_t	st_mode;
	uint32_t	st_nlink;
	uint32_t	st_uid;
	uint32_t	st_gid;
	uint64_t	st_rdev;
	uint32_t	st_pad2;
	uint64_t	st_size;
	uint32_t	st_blksize;
	uint64_t	st_blocks;
	lx_timespec32_t	st_atime;
	lx_timespec32_t	st_mtime;
	lx_timespec32_t	st_ctime;
	uint64_t	st_ino;
};
#pragma pack()

#if defined(_LP64)
struct lx_stat64_64 {
	uint64_t	st_dev;
	uint64_t	st_ino;
	uint64_t	st_nlink;	/* yes, the order really is */
	uint32_t	st_mode;	/* different for these two */
	uint32_t	st_uid;
	uint32_t	st_gid;
	uint32_t	st_pad0;
	uint64_t	st_rdev;
	int64_t		st_size;
	int64_t		st_blksize;
	int64_t		st_blocks;
	lx_timespec64_t	st_atime;
	lx_timespec64_t	st_mtime;
	lx_timespec64_t	st_ctime;
	int64_t		st_unused[3];
};
#endif /* defined(_LP64) */

/*
 * struct statx has the same layout for 32-bit and 64-bit processes. Fields
 * after stx_dev_minor are not filled in and are not included in stx_mask.
 */
typedef struct lx_statx_timestamp {
	int64_t		sxt_sec;
	uint32_t	sxt_nsec;
	int32_t		sxt_reserved;
} lx_statx_timestamp_t;

struct lx_statx {
	uint32_t		stx_mask;
	uint32_t		stx_blksize;
	uint64_t		stx_attributes;
	uint32_t		stx_nlink;
	uint32_t		stx_uid;
	uint32_t		stx_gid;
	uint16_t		stx_mode;
	uint16_t		stx_spare0;
	uint64_t		stx_ino;
	uint64_t		stx_size;
	uint64_t		stx_blocks;
	uint64_t		stx_attributes_mask;
	lx_statx_timestamp_t	stx_atime;
	lx_statx_timestamp_t	stx_btime;
	lx_statx_timestamp_t	stx_ctime;
	lx_statx_timestamp_t	stx_mtime;
	uint32_t		stx_rdev_major;
	uint32_t		stx_rdev_minor;
	uint32_t		stx_dev_major;
	uint32_t		stx_dev_minor;
	uint64_t		stx_spare[14];
};
CTASSERT(sizeof (struct lx_statx) == 256);

#define	LX_STATX_BASIC_STATS	0x000007ffU
#define	LX_STATX__RESERVED	0x80000000U

typedef enum lx_stat_fmt {
	LXF_STAT32,
	LXF_STAT64_32,
	LXF_STAT64_64,
	LXF_STATX
} lx_stat_fmt_t;

static void
lx_stat_xlate_dev(vattr_t *vattr)
{
	lx_zone_data_t *lxzd = ztolxzd(curproc->p_zone);
	dev_t dev;
	lx_virt_disk_t *vd;
	boolean_t is_dev;

	if (S_ISCHR(vattr->va_mode) || S_ISBLK(vattr->va_mode)) {
		dev = vattr->va_rdev;
		is_dev = B_TRUE;
	} else {
		dev = vattr->va_fsid;
		is_dev = B_FALSE;
	}

	/*
	 * See if this is the /dev/zfs device. If it is, the device number has
	 * already been converted to Linux format in the lx devfs so we have
	 * to check for that and not a native major/minor style.
	 */
	if (S_ISCHR(vattr->va_mode) &&
	    LX_GETMAJOR(dev) == getmajor(lxzd->lxzd_zfs_dev) &&
	    LX_GETMINOR(dev) == 0) {
		/*
		 * We use the /dev/zfs device as a placeholder for our in-zone
		 * fabricated /dev/zfsds0 device that we're pretending / is
		 * mounted on. lx_zone_get_zfsds has pre-allocated this
		 * entry in the emulated device list. Reset dev so we can
		 * properly match in the following loop.
		 */
		dev = curproc->p_zone->zone_rootvp->v_vfsp->vfs_dev;
	}

	/* Substitute emulated major/minor on zvols or mounted datasets. */
	vd = list_head(lxzd->lxzd_vdisks);
	while (vd != NULL) {
		if (vd->lxvd_real_dev == dev) {
			dev = vd->lxvd_emul_dev;
			/*
			 * We only update rdev for matching zfds/zvol devices
			 * so that the other devices are unchanged.
			 */
			if (is_dev) {
				vattr->va_rdev = LX_MAKEDEVICE(getmajor(dev),
				    getminor(dev));
			}
			break;
		}
		vd = list_next(lxzd->lxzd_vdisks, vd);
	}

	/* Mangle st_dev into expected format */
	vattr->va_fsid = LX_MAKEDEVICE(getmajor(dev), getminor(dev));
}

static long
lx_stat_common(vnode_t *vp, cred_t *cr, void *outp, lx_stat_fmt_t fmt,
    int follow)
{
	vattr_t vattr;
	mode_t mode;
	int error, flags;

	/*
	 * When symlink following is desired, the ATTR_REAL flag is necessary
	 * to circumvent some of the weird behavior present in filesystems like
	 * lx_proc.
	 */
	flags = (follow == FOLLOW) ? ATTR_REAL : 0;

	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;
	if ((error = VOP_GETATTR(vp, &vattr, flags, cr, NULL)) != 0) {
		return (error);
	}

	mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	if ((mode & S_IFMT) == S_IFBLK) {
		/* Linux seems to report a 0 st_size for all block devices */
		vattr.va_size = 0;
	}
	if (vattr.va_rdev == NODEV) {
		/* Linux leaves st_rdev zeroed when it is absent */
		vattr.va_rdev = 0;
	}

	lx_stat_xlate_dev(&vattr);

	if (fmt == LXF_STAT32) {
		struct lx_stat32 sb;

		if (vattr.va_fsid > USHRT_MAX || vattr.va_rdev > USHRT_MAX ||
		    vattr.va_nlink > USHRT_MAX || vattr.va_size > INT_MAX) {
			return (EOVERFLOW);
		}

		bzero(&sb, sizeof (sb));
		sb.st_dev = vattr.va_fsid;
		sb.st_ino = vattr.va_nodeid;
		sb.st_mode = mode;
		sb.st_nlink = vattr.va_nlink;
		sb.st_uid = LX_UID32_TO_UID16(vattr.va_uid);
		sb.st_gid = LX_GID32_TO_GID16(vattr.va_gid);
		sb.st_rdev = vattr.va_rdev;
		sb.st_size = vattr.va_size;
		sb.st_blksize = vattr.va_blksize;
		sb.st_blocks = vattr.va_nblocks;
		sb.st_atime.ts_sec = vattr.va_atime.tv_sec;
		sb.st_atime.ts_nsec = vattr.va_atime.tv_nsec;
		sb.st_mtime.ts_sec = vattr.va_mtime.tv_sec;
		sb.st_mtime.ts_nsec = vattr.va_mtime.tv_nsec;
		sb.st_ctime.ts_sec = vattr.va_ctime.tv_sec;
		sb.st_ctime.ts_nsec = vattr.va_ctime.tv_nsec;
		if (copyout(&sb, outp, sizeof (sb)) != 0) {
			return (EFAULT);
		}
		return (0);
	} else if (fmt == LXF_STAT64_32) {
		struct lx_stat64_32 sb;

		bzero(&sb, sizeof (sb));
		sb.st_dev = vattr.va_fsid;
		sb.st_ino = vattr.va_nodeid;
		sb.st_small_ino = (vattr.va_nodeid & UINT_MAX);
		sb.st_mode = mode;
		sb.st_nlink = vattr.va_nlink;
		sb.st_uid = vattr.va_uid;
		sb.st_gid = vattr.va_gid;
		sb.st_rdev = vattr.va_rdev;
		sb.st_size = vattr.va_size;
		sb.st_blksize = vattr.va_blksize;
		sb.st_blocks = vattr.va_nblocks;
		sb.st_atime.ts_sec = vattr.va_atime.tv_sec;
		sb.st_atime.ts_nsec = vattr.va_atime.tv_nsec;
		sb.st_mtime.ts_sec = vattr.va_mtime.tv_sec;
		sb.st_mtime.ts_nsec = vattr.va_mtime.tv_nsec;
		sb.st_ctime.ts_sec = vattr.va_ctime.tv_sec;
		sb.st_ctime.ts_nsec = vattr.va_ctime.tv_nsec;
		if (copyout(&sb, outp, sizeof (sb)) != 0) {
			return (EFAULT);
		}
		return (0);
	} else if (fmt == LXF_STAT64_64) {
#if defined(_LP64)
		struct lx_stat64_64 sb;

		bzero(&sb, sizeof (sb));
		sb.st_dev = vattr.va_fsid;
		sb.st_ino = vattr.va_nodeid;
		sb.st_mode = mode;
		sb.st_nlink = vattr.va_nlink;
		sb.st_uid = vattr.va_uid;
		sb.st_gid = vattr.va_gid;
		sb.st_rdev = vattr.va_rdev;
		sb.st_size = vattr.va_size;
		sb.st_blksize = vattr.va_blksize;
		sb.st_blocks = vattr.va_nblocks;
		sb.st_atime.ts_sec = vattr.va_atime.tv_sec;
		sb.st_atime.ts_nsec = vattr.va_atime.tv_nsec;
		sb.st_mtime.ts_sec = vattr.va_mtime.tv_sec;
		sb.st_mtime.ts_nsec = vattr.va_mtime.tv_nsec;
		sb.st_ctime.ts_sec = vattr.va_ctime.tv_sec;
		sb.st_ctime.ts_nsec = vattr.va_ctime.tv_nsec;
		if (copyout(&sb, outp, sizeof (sb)) != 0) {
			return (EFAULT);
		}
		return (0);
#else
		/* Invalid output format on 32-bit */
		VERIFY(0);
#endif
	} else if (fmt == LXF_STATX) {
		struct lx_statx sx;

		bzero(&sx, sizeof (sx));
		sx.stx_mask = LX_STATX_BASIC_STATS;
		sx.stx_blksize = vattr.va_blksize;
		sx.stx_nlink = vattr.va_nlink;
		sx.stx_uid = vattr.va_uid;
		sx.stx_gid = vattr.va_gid;
		sx.stx_mode = mode;
		sx.stx_ino = vattr.va_nodeid;
		sx.stx_size = vattr.va_size;
		sx.stx_blocks = vattr.va_nblocks;
		sx.stx_atime.sxt_sec = vattr.va_atime.tv_sec;
		sx.stx_atime.sxt_nsec = vattr.va_atime.tv_nsec;
		sx.stx_mtime.sxt_sec = vattr.va_mtime.tv_sec;
		sx.stx_mtime.sxt_nsec = vattr.va_mtime.tv_nsec;
		sx.stx_ctime.sxt_sec = vattr.va_ctime.tv_sec;
		sx.stx_ctime.sxt_nsec = vattr.va_ctime.tv_nsec;
		sx.stx_rdev_major = LX_GETMAJOR(vattr.va_rdev);
		sx.stx_rdev_minor = LX_GETMINOR(vattr.va_rdev);
		sx.stx_dev_major = LX_GETMAJOR(vattr.va_fsid);
		sx.stx_dev_minor = LX_GETMINOR(vattr.va_fsid);
		if (copyout(&sx, outp, sizeof (sx)) != 0)
			return (EFAULT);
		return (0);
	}

	/* Invalid output format */
	VERIFY(0);
	return (0);
}

long
lx_stat32(char *name, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	int error;

	if ((error = cstatat_getvp(AT_FDCWD, name, FOLLOW, &vp, &cr)) != 0) {
		return (set_errno(error));
	}
	error = lx_stat_common(vp, cr, outp, LXF_STAT32, FOLLOW);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_fstat32(int fd, void *outp)
{
	file_t *fp;
	int error;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}
	error = lx_stat_common(fp->f_vnode, fp->f_cred, outp, LXF_STAT32,
	    FOLLOW);
	releasef(fd);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_lstat32(char *name, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	int error;

	if ((error = cstatat_getvp(AT_FDCWD, name, NO_FOLLOW, &vp, &cr)) != 0) {
		return (set_errno(error));
	}
	error = lx_stat_common(vp, cr, outp, LXF_STAT32, NO_FOLLOW);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_stat64(char *name, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	model_t model = get_udatamodel();
	int error;

	if ((error = cstatat_getvp(AT_FDCWD, name, FOLLOW, &vp, &cr)) != 0) {
		return (set_errno(error));
	}
	error = lx_stat_common(vp, cr, outp,
	    (model == DATAMODEL_LP64) ? LXF_STAT64_64 : LXF_STAT64_32, FOLLOW);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_fstat64(int fd, void *outp)
{
	file_t *fp;
	model_t model = get_udatamodel();
	int error;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}
	error = lx_stat_common(fp->f_vnode, fp->f_cred, outp,
	    (model == DATAMODEL_LP64) ? LXF_STAT64_64 : LXF_STAT64_32, FOLLOW);
	releasef(fd);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

#define	LX_FSTATAT_ALLOWED	(LX_AT_SYMLINK_NOFOLLOW | LX_AT_EMPTY_PATH | \
    LX_AT_NO_AUTOMOUNT)
#define	LX_STATX_ALLOWED	(LX_FSTATAT_ALLOWED | LX_AT_STATX_SYNC_TYPE)

/*
 * Find the vnode for an fstatat(2) or statx(2) request. On success, the
 * caller must release both the vnode and the credential.
 */
static int
lx_statat_getvp(int fd, char *name, int flag, vnode_t **vpp, cred_t **crp,
    int *followp)
{
	int follow = FOLLOW;
	char c;

	if (fd == LX_AT_FDCWD)
		fd = AT_FDCWD;
	if ((flag & LX_AT_SYMLINK_NOFOLLOW) != 0)
		follow = NO_FOLLOW;
	if ((flag & LX_AT_NO_AUTOMOUNT) != 0)
		follow |= __FLXNOAUTO;
	*followp = follow;

	/*
	 * Linux accepts a NULL name in place of an empty string when
	 * AT_EMPTY_PATH is set.
	 */
	if (name == NULL && (flag & LX_AT_EMPTY_PATH) != 0)
		c = '\0';
	else if (copyin(name, &c, sizeof (c)) != 0)
		return (EFAULT);

	if (c != '\0')
		return (cstatat_getvp(fd, name, follow, vpp, crp));

	if ((flag & LX_AT_EMPTY_PATH) == 0)
		return (ENOENT);

	/*
	 * When AT_EMPTY_PATH is set and an empty string has been
	 * passed for the name parameter, direct the lookup against the
	 * vnode for that fd.
	 */
	if (fd == AT_FDCWD) {
		mutex_enter(&curproc->p_lock);
		*vpp = PTOU(curproc)->u_cdir;
		VN_HOLD(*vpp);
		mutex_exit(&curproc->p_lock);
		*crp = CRED();
		crhold(*crp);
	} else {
		file_t *fp;

		if ((fp = getf(fd)) == NULL)
			return (EBADF);
		*vpp = fp->f_vnode;
		VN_HOLD(*vpp);
		*crp = fp->f_cred;
		crhold(*crp);
		releasef(fd);
	}

	return (0);
}

long
lx_fstatat64(int fd, char *name, void *outp, int flag)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	model_t model = get_udatamodel();
	int follow;
	int error;

	if ((flag & ~LX_FSTATAT_ALLOWED) != 0)
		return (set_errno(EINVAL));

	error = lx_statat_getvp(fd, name, flag, &vp, &cr, &follow);
	if (error != 0)
		return (set_errno(error));

	error = lx_stat_common(vp, cr, outp,
	    (model == DATAMODEL_LP64) ? LXF_STAT64_64 : LXF_STAT64_32, follow);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0)
		return (set_errno(error));
	return (0);
}

/*
 * The basic stat fields are always returned, whatever was requested in mask,
 * and the requested synchronisation type is ignored. Linux allows for both.
 */
long
lx_statx(int fd, char *name, int flag, uint_t mask, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	int follow;
	int error;

	if ((flag & ~LX_STATX_ALLOWED) != 0 ||
	    (flag & LX_AT_STATX_SYNC_TYPE) == LX_AT_STATX_SYNC_TYPE ||
	    (mask & LX_STATX__RESERVED) != 0) {
		return (set_errno(EINVAL));
	}

	error = lx_statat_getvp(fd, name, flag, &vp, &cr, &follow);
	if (error != 0)
		return (set_errno(error));

	error = lx_stat_common(vp, cr, outp, LXF_STATX, follow);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0)
		return (set_errno(error));
	return (0);
}

long
lx_lstat64(char *name, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	model_t model = get_udatamodel();
	int error;

	if ((error = cstatat_getvp(AT_FDCWD, name, NO_FOLLOW, &vp, &cr)) != 0) {
		return (set_errno(error));
	}
	error = lx_stat_common(vp, cr, outp,
	    (model == DATAMODEL_LP64) ? LXF_STAT64_64 : LXF_STAT64_32,
	    NO_FOLLOW);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}
