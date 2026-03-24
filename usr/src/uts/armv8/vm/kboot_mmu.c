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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 * Copyright 2026 Richard Lowe
 */

/*
 * Early boot MMU management to map pages prior to the HAT running
 */

#include <sys/bootconf.h>
#include <sys/controlregs.h>
#include <sys/debug.h>
#include <sys/sunddi.h>
#include <sys/types.h>

#include <vm/hat_aarch64.h>
#include <vm/seg_kmem.h>

#define	KBM_ASSERT(EX) \
	((void)((EX) || (bop_panic("%s:%d: %s: assertion failed: %s\n", \
	    __FILE__, __LINE__, __func__, #EX), 0)))

/*
 * Discover enough hardware parameters for kbm.
 *
 * This is a cutdown `mmu_init` which is not callable soon enough, which
 * discovers just enough MMU parameters for kbm to function.
 *
 * XXX: At present, we don't actually _discover_ anything.
 */
static uint8_t kbm_max_page_level;
static uint8_t kbm_max_level;

void
kbm_init(void)
{
	kbm_max_page_level = MMU_PAGE_SIZES - 1;
	kbm_max_level = MMU_PAGE_LEVELS - 1;
}

/* Allocate a physical page for use as a page table */
static paddr_t
pt_alloc(bootops_t *bop)
{
	extern int physMemInit;
	paddr_t pa = BOP_PALLOC(bop, MMU_PAGESIZE, MMU_PAGESIZE);

	/* We rely on being identity mapped */
	KBM_ASSERT(khat_running == 0);

	if (pa == 0)
		bop_panic("failed to allocate physical page table\n");

	if (physMemInit != 0)
		boot_mapin((caddr_t)(uintptr_t)pa, MMU_PAGESIZE);

	bzero((void *)(uintptr_t)pa, MMU_PAGESIZE);
	return (pa);
}

/*
 * Map virtual address `va` to physical `pa`.  `level` denotes the size of the
 * mapping in terms of the level of page table used.
 */
void
kbm_map(uintptr_t vaddr, paddr_t paddr, uint_t level)
{
	KBM_ASSERT(kbm_max_page_level > 0);
	KBM_ASSERT(level <= kbm_max_page_level);
	KBM_ASSERT(IS_KERNEL_MAPPING(vaddr));
	KBM_ASSERT((paddr & LEVEL_OFFSET(level)) == 0);
	KBM_ASSERT((vaddr & LEVEL_OFFSET(level)) == 0);

	pte_t *ptbl = (pte_t *)TTBR_BADDR48(read_ttbr1());

	for (int l = kbm_max_level; l > level; l--) {
		/* Need a new entry */
		if (!PTE_ISVALID(ptbl[LEVEL_INDEX(vaddr, l)])) {
			paddr_t pa = pt_alloc(bootops);

			/* XXX: MAKEPTE(...) */
			ptbl[LEVEL_INDEX(vaddr, l)] = pa |
			    PTE_TABLE_UXNT | PTE_TABLE_APT_NOUSER |
			    PTE_TABLE;
			dsb(ish);
			isb();
		} else if (!PTE_ISTABLE(ptbl[LEVEL_INDEX(vaddr, l)], l)) {
			bop_panic("overlapping %s allocation for 0x%lx at "
			    "level %d (needed a table)\n", __func__, vaddr, l);
		}

		ptbl = (pte_t *)PTE2ADDR(ptbl[LEVEL_INDEX(vaddr, l)], l);
	}

	if (PTE_ISVALID(ptbl[LEVEL_INDEX(vaddr, level)])) {
		bop_panic("overlapping %s allocation for 0x%lx at level %d\n",
		    __func__, vaddr, level);
	}

	/*
	 * XXX: MAKEPTE
	 */
	uint_t type = (level == 0) ? PTE_PAGE : PTE_BLOCK;
	ptbl[LEVEL_INDEX(vaddr, level)] = paddr |
	    PTE_NOCONSIST | PTE_AF | PTE_SH_INNER | PTE_UXN | PTE_AP_KRWUNA |
	    PTE_ATTR_NORMEM | type;
	dsb(ish);
	isb();
}
