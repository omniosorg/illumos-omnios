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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2022 Michael van der Westhuizen
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	All Rights Reserved	*/

#ifndef _SYS_MCONTEXT_H
#define	_SYS_MCONTEXT_H

#include <sys/feature_tests.h>
#include <sys/fp.h>

#if !defined(_ASM)
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A gregset_t is defined as an array type for compatibility with the reference
 * source. This is important due to differences in the way the C language
 * treats arrays and structures as parameters.
 */
#define	_NGREG	36

#ifndef _ASM
typedef long	greg_t;
typedef greg_t	gregset_t[_NGREG];

/*
 * Floating point definitions.
 */
typedef struct fpu {
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
	fpreg_t			d_fpregs[32];
	uint32_t		fp_cr;
	uint32_t		fp_sr;
#else
	fpreg_t			__d_fpregs[32];
	uint32_t		__fp_cr;
	uint32_t		__fp_sr;
#endif
} fpregset_t;

/*
 * Structure mcontext defines the complete hardware machine state.
 */
typedef struct {
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
	gregset_t	gregs;	/* general register set */
	fpregset_t	fpregs;	/* floating point register set */
#else
	gregset_t	__gregs;	/* general register set */
	fpregset_t	__fpregs;	/* floating point register set */
#endif
} mcontext_t;

#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MCONTEXT_H */
