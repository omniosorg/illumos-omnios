/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 */

#ifndef _SYS_PTE_H
#define	_SYS_PTE_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#include <sys/types.h>
#endif /* _ASM */

#ifndef _ASM
typedef uint64_t pte_t;

#define	NPTESHIFT	(MMU_PAGESHIFT - PTE_BITS)

#define	NPTEPERPT	(MMU_PAGESIZE / sizeof (pte_t))


#define	MAIR_STRONG_ORDER	0
#define	MAIR_DEVICE		1
#define	MAIR_NORMAL_MEMORY	2
#define	MAIR_NORMAL_MEMORY_WT	3
#define	MAIR_NORMAL_MEMORY_UC	4
#define	MAIR_UNORDERED		5

#define	PTE_BLOCK		0x1
#define	PTE_TABLE		0x3
#define	PTE_PAGE		0x3
#define	PTE_TYPE_MASK		0x3
#define	PTE_VALID		0x1

#define	PTE_SFW_SHIFT		(55)
#define	PTE_SFW_MASK		(0xFull << PTE_SFW_SHIFT)

#define	PTE_UXN			(1ull << 54)
#define	PTE_PXN			(1ull << 53)
#define	PTE_CONTIG_HINT		(1ull << 52)
#define	PTE_DBM			(1ull << 51)
#define	PTE_GP			(1ull << 50) /* Guarded Page (BTI) */

#define	PTE_nT			(1ull << 16)
#define	PTE_NG			(1ull << 11)
#define	PTE_AF			(1ull << 10)
#define	PTE_SH_MASK		(3ull << 8)
#define	PTE_SH_INNER		(3ull << 8)
#define	PTE_SH_OUTER		(2ull << 8)
#define	PTE_SH_NONSHARE		(0ull << 8)
#define	PTE_AP_MASK		(3ull << 6)
#define	PTE_AP_RO		(1ull << 7)

#define	PTE_AP_USER		(1ull << 6)
#define	PTE_AP_KRWUNA		0
#define	PTE_AP_KRWURW		PTE_AP_USER
#define	PTE_AP_KROUNA		PTE_AP_RO
#define	PTE_AP_KROURO		(PTE_AP_RO | PTE_AP_USER)

#define	PTE_NS			(1ull << 5)
#define	PTE_ATTR_SHIFT		(2)
#define	PTE_ATTR_MASK		(7ull << PTE_ATTR_SHIFT)
#define	PTE_ATTR_STRONG		((pte_t)MAIR_STRONG_ORDER  << PTE_ATTR_SHIFT)
#define	PTE_ATTR_DEVICE		((pte_t)MAIR_DEVICE	   << PTE_ATTR_SHIFT)
#define	PTE_ATTR_NORMEM		((pte_t)MAIR_NORMAL_MEMORY << PTE_ATTR_SHIFT)
#define	PTE_ATTR_NORMEM_WT	((pte_t)MAIR_NORMAL_MEMORY_WT << PTE_ATTR_SHIFT)
#define	PTE_ATTR_NORMEM_UC	((pte_t)MAIR_NORMAL_MEMORY_UC << PTE_ATTR_SHIFT)
#define	PTE_ATTR_UNORDERED	((pte_t)MAIR_UNORDERED << PTE_ATTR_SHIFT)

#define	PTE_TABLE_NST		(1ull << 63)
#define	PTE_TABLE_APT_MASK	(3ull << 61)
#define	PTE_TABLE_APT_RO	(2ull << 61)
#define	PTE_TABLE_APT_NOUSER	(1ull << 61)
#define	PTE_TABLE_UXNT		(1ull << 60)
#define	PTE_TABLE_PXNT		(1ull << 59)
#define	PTE_TABLE_PROTECTED	(1ull << 52)

#define	PTE_PFN_MASK		0x0000fffffffff000ull

#endif /* !_ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PTE_H */
