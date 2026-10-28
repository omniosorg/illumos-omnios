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

#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_misc.h>

#define	LX_LINK_ALLOWED	(LX_AT_SYMLINK_FOLLOW | LX_AT_EMPTY_PATH)

/* From "uts/common/syscall/stat.c" */
extern int cstatat_getvp(int, char *, int, vnode_t **, cred_t **);
/* From uts/common/syscall/unlink.c */
extern int unlinkat(int, char *, int);
/* From uts/common/syscall/symlink.c */
extern int symlinkat(char *, int, char *);
/* From uts/common/syscall/readlink.c */
extern ssize_t readlinkat(int, char *, char *, size_t);

static long
lx_link_common(int ffd, char *from, int tfd, char *to, int flags)
{
	int error;
	vnode_t *fsvp = NULL, *tsvp = NULL;
	enum symfollow follow = NO_FOLLOW;

	if ((flags & ~LX_LINK_ALLOWED) != 0) {
		return (set_errno(EINVAL));
	}
	if ((flags & LX_AT_EMPTY_PATH) == 0) {
		char c;

		/*
		 * Check that both 'from' and 'to' names are non-empty if
		 * AT_EMPTY_PATH is not set.
		 */
		if (copyin(from, &c, sizeof (c)) != 0) {
			return (set_errno(EFAULT));
		} else if (c == '\0') {
			return (set_errno(ENOENT));
		}
		if (copyin(to, &c, sizeof (c)) != 0) {
			return (set_errno(EFAULT));
		} else if (c == '\0') {
			return (set_errno(ENOENT));
		}

		/*
		 * XXX: When our support for LX capabilities improves, ENOENT
		 * should be thrown when a process lacking CAP_DAC_READ_SEARCH
		 * attempts to use the AT_EMPTY_PATH flag.
		 */
	}
	if ((flags & LX_AT_SYMLINK_FOLLOW) != 0) {
		follow = FOLLOW;
	}

	if ((error = fgetstartvp(ffd, from, &fsvp)) != 0) {
		goto out;
	}
	if ((error = fgetstartvp(tfd, to, &tsvp)) != 0) {
		goto out;
	}
	error = vn_linkat(fsvp, from, follow, tsvp, to, UIO_USERSPACE);

out:
	if (fsvp != NULL) {
		VN_RELE(fsvp);
	}
	if (tsvp != NULL) {
		VN_RELE(tsvp);
	}
	if (error) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_link(char *from, char *to)
{
	return (lx_link_common(AT_FDCWD, from, AT_FDCWD, to, 0));
}

long
lx_linkat(int ffd, char *from, int tfd, char *to, int flags)
{
	ffd = (ffd == LX_AT_FDCWD) ? AT_FDCWD : ffd;
	tfd = (tfd == LX_AT_FDCWD) ? AT_FDCWD : tfd;

	return (lx_link_common(ffd, from, tfd, to, flags));
}

static boolean_t
lx_isdir(int atfd, char *path)
{
	cred_t *cr = NULL;
	vnode_t *vp = NULL;
	boolean_t is_dir;

	if (cstatat_getvp(atfd, path, NO_FOLLOW, &vp, &cr) != 0)
		return (B_FALSE);

	crfree(cr);
	is_dir = (vp->v_type == VDIR);
	VN_RELE(vp);

	return (is_dir);
}

long
lx_unlink(char *path)
{
	int err;

	if ((err = unlinkat(AT_FDCWD, path, 0)) == EPERM) {
		/* On Linux, an unlink of a dir returns EISDIR, not EPERM. */
		if (lx_isdir(AT_FDCWD, path))
			return (set_errno(EISDIR));
	}

	return (err);
}

long
lx_unlinkat(int atfd, char *path, int flag)
{
	int err;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	if ((flag = ltos_at_flag(flag, AT_REMOVEDIR, B_TRUE)) < 0)
		return (set_errno(EINVAL));

	err = unlinkat(atfd, path, flag);
	if (err == EPERM && !(flag & AT_REMOVEDIR)) {
		/* On Linux, an unlink of a dir returns EISDIR, not EPERM. */
		if (lx_isdir(atfd, path))
			return (set_errno(EISDIR));
	}
	if (err == EEXIST && (flag & AT_REMOVEDIR)) {
		/*
		 * On Linux, an unlink of a non-empty dir returns ENOTEMPTY,
		 * not EEXIST.
		 */
		if (lx_isdir(atfd, path))
			return (set_errno(ENOTEMPTY));
	}

	return (err);
}

long
lx_symlink(char *name1, char *name2)
{
	return (symlinkat(name1, AT_FDCWD, name2));
}

long
lx_symlinkat(char *name1, int atfd, char *name2)
{
	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	return (symlinkat(name1, atfd, name2));
}

long
lx_readlink(char *path, char *buf, size_t bufsize)
{
	if (bufsize <= 0)
		return (set_errno(EINVAL));

	return (readlinkat(AT_FDCWD, path, buf, bufsize));
}

/*
 * Read the symbolic link that a file descriptor refers to, typically one
 * obtained with open(2) and O_PATH | O_NOFOLLOW.
 */
static long
lx_readlink_fd(int fd, char *buf, size_t bufsize)
{
	file_t *fp;
	vnode_t *vp;
	vattr_t vattr;
	struct iovec aiov;
	struct uio auio;
	ssize_t cnt;
	int error;

	if ((cnt = (ssize_t)bufsize) < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));
	vp = fp->f_vnode;

	/*
	 * As in readlinkat(), allow the file system to present an object as
	 * a symbolic link, as lx procfs does. Linux reports anything which is
	 * not a link as ENOENT here.
	 */
	if (vp->v_type != VLNK) {
		vattr.va_mask = AT_TYPE;
		if (VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) != 0 ||
		    vattr.va_type != VLNK) {
			releasef(fd);
			return (set_errno(ENOENT));
		}
	}

	aiov.iov_base = buf;
	aiov.iov_len = cnt;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = 0;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_extflg = UIO_COPY_CACHED;
	auio.uio_resid = cnt;
	error = VOP_READLINK(vp, &auio, CRED(), NULL);
	releasef(fd);
	if (error != 0)
		return (set_errno(error));
	return (cnt - auio.uio_resid);
}

long
lx_readlinkat(int atfd, char *path, char *buf, size_t bufsize)
{
	char c;

	if (bufsize <= 0)
		return (set_errno(EINVAL));

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	/*
	 * With an empty path, Linux reads the link that atfd itself refers
	 * to. The native lookup would fail an empty name with ENOENT, which
	 * remains the answer for AT_FDCWD.
	 */
	if (path != NULL && atfd != AT_FDCWD) {
		if (copyin(path, &c, sizeof (c)) != 0)
			return (set_errno(EFAULT));
		if (c == '\0')
			return (lx_readlink_fd(atfd, buf, bufsize));
	}

	return (readlinkat(atfd, path, buf, bufsize));
}
