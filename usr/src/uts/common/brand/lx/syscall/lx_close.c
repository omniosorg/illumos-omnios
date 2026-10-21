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
 * Copyright 2017 Joyent, Inc.
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/brand.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/sysmacros.h>

#include <sys/lx_brand.h>
#include <sys/lx_syscalls.h>


extern int close(int);

long
lx_close(int fdes)
{
	return (close(fdes));
}

#define	LX_CLOSE_RANGE_UNSHARE	(1 << 1)
#define	LX_CLOSE_RANGE_CLOEXEC	(1 << 2)
/*
 * Linux does not have a flag for CLOFORK due to ongoing shenanigans about the
 * value of it.
 */

long
lx_close_range(uint_t low, uint_t high, uint_t flags)
{
	int fdflags = 0;

	if (low > high)
		return (set_errno(EINVAL));
	if ((flags & ~(LX_CLOSE_RANGE_UNSHARE | LX_CLOSE_RANGE_CLOEXEC)) != 0)
		return (set_errno(EINVAL));

	if (flags & LX_CLOSE_RANGE_CLOEXEC)
		fdflags |= FD_CLOEXEC;

	/*
	 * LX_CLOSE_RANGE_UNSHARE asks Linux to give the calling task a
	 * private copy of the file descriptor table before acting on the
	 * range, so that tasks sharing the table through clone(CLONE_FILES)
	 * are unaffected. Here the descriptor table is always per-process
	 * and cannot be unshared from the other threads in the process,
	 * which are the only possible sharers. The flag is accepted and
	 * ignored, which gives the common caller the behaviour it expects.
	 */

	fdcloserange((int)MIN(low, INT_MAX), (int)MIN(high, INT_MAX),
	    fdflags);

	return (0);
}
