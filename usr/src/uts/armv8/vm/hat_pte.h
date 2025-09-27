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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef _VM_HAT_PTE_H
#define	_VM_HAT_PTE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/pte.h>
#include <sys/machparam.h>

typedef int32_t level_t;

/*
 * The software bits are used by the HAT to track attributes.
 * Note that the attributes are inclusive as the values increase.
 *
 * PT_NOSYNC - The PT_REF/PT_MOD bits are not sync'd to page_t.
 *             The hat will install them as always set.
 *
 * PT_NOCONSIST - There is no hment entry for this mapping.
 *
 */
#define	PAGE_LEVEL		(0)
#define	MAX_PAGE_LEVEL		(MMU_PAGE_LEVELS - 1)

#define	PTE_SOFTWARE		PTE_SFW_MASK
#define	PTE_NOSYNC		(0x4ul << PTE_SFW_SHIFT)
#define	PTE_NOCONSIST		(0x8ul << PTE_SFW_SHIFT)

#define	PTE_ISVALID(pte)	((pte) & PTE_VALID)
#define	PTE_EQUIV(a, b)		(((a) | PTE_AF) == ((b) | PTE_AF))
#define	PTE_ISPAGE(p, l)	(PTE_ISVALID(p) && (((l) == PAGE_LEVEL) || \
	(((p) & PTE_TYPE_MASK) == PTE_BLOCK)))

#define	MAKEPTE(pfn, l)		(((pfn) << MMU_PAGESHIFT) | PTE_SH_INNER | \
	(l == PAGE_LEVEL? PTE_PAGE: PTE_BLOCK))
#define	MAKEPTP(pfn, l, k)	(((pfn) << MMU_PAGESHIFT) | PTE_TABLE | \
	((k)? (PTE_TABLE_UXNT | PTE_TABLE_APT_NOUSER): PTE_TABLE_PXNT))

#define	TOP_LEVEL(hat)		MAX_PAGE_LEVEL

/*
 * HAT/MMU parameters that depend on kernel mode and/or processor type
 */
struct htable;
struct hat_mmu_info {
	uintptr_t kmap_addr;	/* start addr of kmap */
	uintptr_t kmap_eaddr;	/* end addr of kmap */
	struct htable **kmap_htables; /* htables for segmap + 32 bit heap */
	pte_t *kmap_ptes;	/* mapping of pagetables that map kmap */
	uint32_t max_asid;
	int max_level;
	uintptr_t kernelbase;
};
extern struct hat_mmu_info mmu;

#define	PT_INDEX_PTR(p, x)	((pte_t *)((uintptr_t)(p) + ((x) << PTE_BITS)))

#define	pfn_to_pa(pfn)		mmu_ptob((paddr_t)(pfn))
#define	pa_to_kseg(pa)		((void *)((paddr_t)SEGKPM_BASE|(paddr_t)(pa)))
#define	pfn_to_kseg(pfn)	pa_to_kseg(pfn_to_pa(pfn))

#define	IN_VA_HOLE(va)		(HOLE_START <= (va) && (va) < HOLE_END)
#define	FMT_PTE			"0x%lx"
#define	GET_PTE(ptr)		(*(volatile pte_t *)(ptr))
#define	SET_PTE(ptr, pte)	(*(volatile pte_t *)(ptr) = (pte))
#define	LEVEL_SHIFT(l)		(MMU_PAGESHIFT + (l) * NPTESHIFT)
#define	LEVEL_SIZE(l)		(1ul << LEVEL_SHIFT(l))
#define	LEVEL_OFFSET(l)		(LEVEL_SIZE(l)-1)
#define	LEVEL_MASK(l)		(~LEVEL_OFFSET(l))

#define	PTE_SET(p, f)		((p) |= (f))
#define	PTE_CLR(p, f)		((p) &= ~(pte_t)(f))
#define	PTE_GET(p, f)		((p) & (f))

#define	PTE2PFN(p, lvl)		(((p) & PTE_PFN_MASK) >> MMU_PAGESHIFT)
#define	CAS_PTE(ptr, x, y)	atomic_cas_64(ptr, x, y)

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HAT_PTE_H */
