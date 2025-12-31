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

#include <sys/machparam.h>
#include <vm/hat.h>
#include <vm/hat_aarch64.h>
#include <vm/seg_kpm.h>
#include <sys/cmn_err.h>

/*
 * Kernel Physical Mapping (segkpm) hat interface routines.
 *
 * The kseg is used as segkpm on aarch64.
 */

caddr_t
hat_kpm_pfn2va(pfn_t pfn)
{
	return (caddr_t)(SEGKPM_BASE + (pfn<<MMU_PAGESHIFT));
}


pfn_t
hat_kpm_va2pfn(caddr_t vaddr)
{
	ASSERT(IS_KPM_ADDR(vaddr));
	return (mmu_btop((uintptr_t)vaddr - SEGKPM_BASE));
}

caddr_t
hat_kpm_mapin(struct page *pp, struct kpme *kpme)
{
	return (hat_kpm_pfn2va(pp->p_pagenum));
}

void
hat_kpm_mapout(struct page *pp, struct kpme *kpme, caddr_t vaddr)
{}

caddr_t
hat_kpm_mapin_pfn(pfn_t pfn)
{
	return (hat_kpm_pfn2va(pfn));
}

void
hat_kpm_mapout_pfn(pfn_t pfn)
{}

caddr_t
hat_kpm_page2va(struct page *pp, int checkswap)
{
	return (hat_kpm_pfn2va(pp->p_pagenum));
}

page_t *
hat_kpm_vaddr2page(caddr_t vaddr)
{
	ASSERT(IS_KPM_ADDR(vaddr));

	return (page_numtopp_nolock(hat_kpm_va2pfn(vaddr)));
}

int
hat_kpm_fault(hat_t *hat, caddr_t vaddr)
{
	panic("pagefault in seg_kpm.  hat: 0x%p  vaddr: 0x%p",
	    (void *)hat, (void *)vaddr);

	return (0);
}

void
hat_kpm_mseghash_clear(int nentries)
{}

void
hat_kpm_mseghash_update(pgcnt_t inx, struct memseg *msp)
{}

void
hat_kpm_addmem_mseg_update(struct memseg *msp, pgcnt_t nkpmpgs,
    offset_t kpm_pages_off)
{}

void
hat_kpm_addmem_mseg_insert(struct memseg *msp)
{}

void
hat_kpm_addmem_memsegs_update(struct memseg *msp)
{}

caddr_t
hat_kpm_mseg_reuse(struct memseg *msp)
{
	return ((caddr_t)msp->epages);
}

void
hat_kpm_delmem_mseg_update(struct memseg *msp, struct memseg **mspp)
{}

void
hat_kpm_split_mseg_update(struct memseg *msp, struct memseg **mspp,
    struct memseg *lo, struct memseg *mid, struct memseg *hi)
{}

void
hat_kpm_walk(void (*func)(void *, void *, size_t), void *arg)
{
	pfn_t	pbase, pend;
	void	*base;
	size_t	size;
	struct memseg *msp;

	for (msp = memsegs; msp; msp = msp->next) {
		pbase = msp->pages_base;
		pend = msp->pages_end;
		base = hat_kpm_pfn2va(pbase);
		size = mmu_ptob(pend - pbase);
		func(arg, base, size);
	}
}
