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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_ASM)
#define	ADDRESS_C(c)	(c)
#else
#include <sys/types.h>
#include <sys/int_const.h>
#define	ADDRESS_C(c)	UINT64_C(c)
#endif

#define	NCPU		128
#define	NCPU_LOG2	7
#define	NCPU_P2		(1 << NCPU_LOG2)

#define	MMU_PAGE_SIZES	3
#define	MMU_PAGE_LEVELS	4

/*
 * XXX make sure the MMU_PAGESHIFT definition here is
 * consistent with the one in param.h
 */
#define	MMU_PAGESHIFT		12
#define	MMU_PAGESIZE		(ADDRESS_C(1) << MMU_PAGESHIFT)
#define	MMU_PAGEOFFSET		(MMU_PAGESIZE - 1)
#define	MMU_PAGEMASK		(~MMU_PAGEOFFSET)

#define	MMU_PAGESHIFT2M		21
#define	MMU_PAGESIZE2M		(ADDRESS_C(1) << MMU_PAGESHIFT2M)
#define	MMU_PAGEOFFSET2M	(MMU_PAGESIZE2M - 1)
#define	MMU_PAGEMASK2M		(~MMU_PAGEOFFSET2M)

#define	MMU_PAGESHIFT1G		30
#define	MMU_PAGESIZE1G		(ADDRESS_C(1) << MMU_PAGESHIFT1G)
#define	MMU_PAGEOFFSET1G	(MMU_PAGESIZE1G - 1)
#define	MMU_PAGEMASK1G		(~MMU_PAGEOFFSET1G)

#define	PAGESHIFT		MMU_PAGESHIFT
#define	PAGESIZE		MMU_PAGESIZE
#define	PAGEOFFSET		MMU_PAGEOFFSET
#define	PAGEMASK		MMU_PAGEMASK

/*
 * DATA_ALIGN is used to define the alignment of the Unix data segment.
 */
#define	DATA_ALIGN	PAGESIZE

/*
 * DEFAULT KERNEL THREAD stack size.
 */
#define	DEFAULTSTKSZ	(5*PAGESIZE)

/*
 * DEFAULT initial thread stack size.
 */
#define	T0STKSZ		(2 * DEFAULTSTKSZ)

/*
 * Virtual Address Spaces
 */
#define	PTE_BITS	3
#define	VA_BITS		(MMU_PAGESHIFT + (MMU_PAGESHIFT - PTE_BITS) * \
	MMU_PAGE_LEVELS + 1)

#define	HOLE_START	(ADDRESS_C(1) << (VA_BITS - 1))
#define	HOLE_END	(~(HOLE_START - 1))

/*
 * KERNELBASE is the virtual address at which the kernel segments start in
 * all contexts.
 */
#define	CONSOLE_SIZE	(8L * 1024L * 1024L)
#define	SEGDEBUGSIZE	(8L * 1024L * 1024L)
#define	MISC_VA_SIZE	(1L * 1024L * 1024L * 1024L)
#define	SEGKPM_SIZE	(1ull << (VA_BITS - 2))

#define	CONSOLE_BASE	(- CONSOLE_SIZE)		// 0xffffffff_ff800000
#define	BOOT_VEC_BASE	(CONSOLE_BASE)

#define	SEGDEBUGBASE	(CONSOLE_BASE - SEGDEBUGSIZE)	// 0xffffffff_ff000000
#define	KERNEL_TEXT	ADDRESS_C(0xfffffffffe000000)	// 0xffffffff_fe000000
							// ...
#define	VALLOC_BASE	(MISC_VA_BASE + MISC_VA_SIZE)
#define	MISC_VA_BASE	(SEGKPM_BASE + SEGKPM_SIZE)
#define	SEGKPM_BASE	KERNELBASE
#define	KERNELBASE	HOLE_END

/*
 * default and boundary sizes for segkp
 */
#define	SEGKPDEFSIZE	(2L * 1024L * 1024L * 1024L)		/*   2G */
#define	SEGKPMAXSIZE	(8L * 1024L * 1024L * 1024L)		/*   8G */
#define	SEGKPMINSIZE	(200L * 1024 * 1024L)			/* 200M */

/*
 * minimum size for segzio
 */
#define	SEGZIOMINSIZE	(400L * 1024 * 1024L)			/* 400M */

/*
 * Define upper limit on user address space
 */
#define	USERLIMIT	(ADDRESS_C(1) << (VA_BITS - 1))

/*
 * This limit, traditionally for ILP32 processes, may also be applied to LP64
 * processes with the SF1_SUNW_ADDR32 flag set.
 */
#define	USERLIMIT32	((ADDRESS_C(1) << 32) - 0x1000)

/*
 * The heap has a region allocated from it of HEAPTEXT_SIZE bytes specifically
 * for module text.
 */
#define	HEAPTEXT_SIZE	(64 * 1024 * 1024)	/* bytes */

#define	ARGSBASE	HOLE_START

/*
 * Use a slightly larger thread stack size for interrupt threads rather than
 * the default. This is useful for cases where the networking stack may do an
 * rx and a tx in the context of a single interrupt and when combined with
 * various promisc hooks that need memory, can cause us to get dangerously
 * close to the edge of the traditional stack sizes. This is only a few pages
 * more than a traditional stack and given that we don't have that many
 * interrupt threads, the memory costs end up being more than worthwhile.
 */
#define	LL_INTR_STKSZ_NPGS	8
#define	LL_INTR_STKSZ		(LL_INTR_STKSZ_NPGS * PAGESIZE)

#if !defined(_ASM) && !defined(_KMDB)
extern uintptr_t kernelbase, segmap_start, segmapsize;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHPARAM_H */
