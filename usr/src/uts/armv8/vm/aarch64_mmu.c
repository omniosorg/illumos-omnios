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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/t_lock.h>
#include <sys/memlist.h>
#include <sys/cpuvar.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/vm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/vm_machparam.h>
#include <sys/vnode.h>
#include <vm/hat.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>
#include <vm/hat_aarch64.h>
#include <sys/promif.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/sunddi.h>
#include <sys/ddidmareq.h>
#include <sys/controlregs.h>
#include <sys/pte.h>
#include <sys/cpuid.h>

/*
 * Flag is not set early in boot. Once it is set we are no longer
 * using boot's page tables.
 */
uint_t khat_running = 0;

/*
 * Initialize a special area in the kernel that always holds some PTEs for
 * faster performance. This always holds segmap's PTEs.
 * In the 32 bit kernel this maps the kernel heap too.
 */
void
hat_kmap_init(uintptr_t base, size_t len)
{
	uintptr_t map_addr;	/* base rounded down to large page size */
	uintptr_t map_eaddr;	/* base + len rounded up */
	size_t map_len;
	caddr_t ptes;		/* mapping area in kernel for kmap ptes */
	size_t window_size;	/* size of mapping area for ptes */
	ulong_t htable_cnt;	/* # of page tables to cover map_len */
	ulong_t i;
	htable_t *ht;
	uintptr_t va;

	/*
	 * We have to map in an area that matches an entire page table.
	 * The PTEs are large page aligned to avoid spurious pagefaults
	 * on the hypervisor.
	 */
	map_addr = base & LEVEL_MASK(PAGE_LEVEL + 1);
	map_eaddr = (base + len + LEVEL_SIZE(PAGE_LEVEL + 1) - 1) &
	    LEVEL_MASK(PAGE_LEVEL + 1);
	map_len = map_eaddr - map_addr;
	window_size = mmu_btop(map_len) * sizeof (pte_t);
	window_size = (window_size + LEVEL_SIZE(PAGE_LEVEL + 1)) &
	    LEVEL_MASK(PAGE_LEVEL + 1);
	htable_cnt = map_len >> LEVEL_SHIFT(PAGE_LEVEL + 1);

	/*
	 * allocate vmem for the kmap_ptes
	 */
	ptes = vmem_xalloc(heap_arena, window_size, LEVEL_SIZE(PAGE_LEVEL + 1),
	    0, 0, NULL, NULL, VM_SLEEP);
	mmu.kmap_htables =
	    kmem_alloc(htable_cnt * sizeof (htable_t *), KM_SLEEP);

	/*
	 * Map the page tables that cover kmap into the allocated range.
	 * Note we don't ever htable_release() the kmap page tables - they
	 * can't ever be stolen, freed, etc.
	 */
	for (va = map_addr, i = 0; i < htable_cnt;
	    va += LEVEL_SIZE(PAGE_LEVEL + 1), ++i) {
		ht = htable_create(kas.a_hat, va, PAGE_LEVEL, NULL);
		if (ht == NULL)
			panic("hat_kmap_init: ht == NULL");
		mmu.kmap_htables[i] = ht;

		hat_devload(kas.a_hat, ptes + i * MMU_PAGESIZE,
		    MMU_PAGESIZE, ht->ht_pfn,
		    PROT_READ | PROT_WRITE | HAT_NOSYNC,
		    HAT_LOAD | HAT_LOAD_NOCONSIST);
	}

	/*
	 * set information in mmu to activate handling of kmap
	 */
	mmu.kmap_addr = map_addr;
	mmu.kmap_eaddr = map_eaddr;
	mmu.kmap_ptes = (pte_t *)ptes;
}

/*
 * Routine to pre-allocate data structures for hat_kern_setup(). It computes
 * how many pagetables it needs by walking the boot loader's page tables.
 */
void
hat_kern_alloc(
	caddr_t	segmap_base,
	size_t	segmap_size,
	caddr_t	ekernelheap)
{
	uint_t		table_cnt = 1;
	uint_t		mapping_cnt;

	pte_t *l1_ptbl = (pte_t *)pa_to_kseg(TTBR_BADDR48(read_ttbr1()));

	for (int i = 0; i < NPTEPERPT; i++) {
		if ((l1_ptbl[i] & PTE_TYPE_MASK) != PTE_TABLE)
			continue;
		++table_cnt;

		pte_t *l2_ptbl = (pte_t *)pa_to_kseg(l1_ptbl[i] & PTE_PFN_MASK);
		for (int j = 0; j < NPTEPERPT; j++) {
			if ((l2_ptbl[j] & PTE_TYPE_MASK) != PTE_TABLE)
				continue;
			++table_cnt;

			pte_t *l3_ptbl = (pte_t *)pa_to_kseg(l2_ptbl[j] &
			    PTE_PFN_MASK);
			for (int k = 0; k < NPTEPERPT; k++) {
				if ((l3_ptbl[k] & PTE_TYPE_MASK) != PTE_TABLE)
					continue;
				++table_cnt;

			}
		}
	}

	/*
	 * Besides the boot loader mappings, we're going to fill in
	 * the entire top level page table for the kernel. Make sure there's
	 * enough reserve for that too.
	 */
	table_cnt += NPTEPERPT - ((kernelbase >> LEVEL_SHIFT(MAX_PAGE_LEVEL)) &
	    (NPTEPERPT - 1));

	/*
	 * Add 1/4 more into table_cnt for extra slop.  The unused
	 * slop is freed back when we htable_adjust_reserve() later.
	 */
	table_cnt += table_cnt >> 2;

	/*
	 * We only need mapping entries (hments) for shared pages.
	 * This should be far, far fewer than the total possible,
	 * We'll allocate enough for 1/16 of all possible PTEs.
	 */
	mapping_cnt = (table_cnt * NPTEPERPT) >> 4;

	/*
	 * Now create the initial htable/hment reserves
	 */
	htable_initial_reserve(table_cnt);
	hment_reserve(mapping_cnt);
}


/*
 * This routine handles the work of creating the kernel's initial mappings
 * by deciphering the mappings in the page tables created by the boot program.
 *
 * We maintain large page mappings, but only to a level 1 pagesize.
 * The boot loader can only add new mappings once this function starts.
 * In particular it can not change the pagesize used for any existing
 * mappings or this code breaks!
 */

void
hat_kern_setup(void)
{
	/*
	 * Attach htables to the existing pagetables
	 */
	htable_attach(kas.a_hat, _kernelbase, mmu.max_level, NULL,
	    mmu_btop(TTBR_BADDR48(read_ttbr1())));

	/*
	 * The kernel HAT is now officially open for business.
	 */
	khat_running = 1;

	CPU->cpu_current_hat = kas.a_hat;
}

/*
 * This routine is like page_numtopp, but accepts only free pages, which
 * it allocates (unfrees) and returns with the exclusive lock held.
 * It is used by machdep.c/dma_init() to find contiguous free pages.
 *
 * XXX this and some others should probably be in vm_machdep.c
 */
page_t *
page_numtopp_alloc(pfn_t pfnum)
{
	page_t *pp;

retry:
	pp = page_numtopp_nolock(pfnum);
	if (pp == NULL) {
		return (NULL);
	}

	if (!page_trylock(pp, SE_EXCL)) {
		return (NULL);
	}

	if (page_pptonum(pp) != pfnum) {
		page_unlock(pp);
		goto retry;
	}

	if (!PP_ISFREE(pp)) {
		page_unlock(pp);
		return (NULL);
	}
	if (pp->p_szc) {
		page_demote_free_pages(pp);
		page_unlock(pp);
		goto retry;
	}

	/* If associated with a vnode, destroy mappings */

	if (pp->p_vnode) {

		page_destroy_free(pp);

		if (!page_lock(pp, SE_EXCL, (kmutex_t *)NULL, P_NO_RECLAIM)) {
			return (NULL);
		}

		if (page_pptonum(pp) != pfnum) {
			page_unlock(pp);
			goto retry;
		}
	}

	if (!PP_ISFREE(pp)) {
		page_unlock(pp);
		return (NULL);
	}

	if (!page_reclaim(pp, (kmutex_t *)NULL))
		return (NULL);

	return (pp);
}

/*
 * This procedure is callable only while the boot loader is in charge of the
 * MMU. It assumes that PA == VA for page table pointers.  It doesn't live in
 * kboot_mmu.c since it's used from common code.
 */
pfn_t
va_to_pfn(void *vaddr)
{
	uintptr_t va = ALIGN2PAGE(vaddr);

	if (khat_running)
		panic("va_to_pfn(): called too late\n");

	write_s1e1r(va);
	isb();

	uint64_t par = read_par_el1();
	if (par & PAR_F)
		return (PFN_INVALID);

	uint64_t pa = (par & PAR_PA_MASK);

	return (mmu_btop(pa));
}

static boolean_t
is_reserved_memory(paddr_t pa)
{
	pfn_t pfn = mmu_btop(pa);
	page_t *pp = page_numtopp_nolock(pfn);
	if (pp == NULL)
		return (B_FALSE);
	if (!PAGE_EXCL(pp))
		return (B_FALSE);
	if (pp->p_lckcnt != 1)
		return (B_FALSE);
	return (B_TRUE);
}

void
boot_reserve(void)
{
	size_t count = 0;

	size_t pa_size_array[] = {
		[MMFR0_PARANGE_4G] =	(1ul << 32),	/* 4G */
		[MMFR0_PARANGE_64G] =	(1ul << 36),	/* 64G */
		[MMFR0_PARANGE_1T] =	(1ul << 40),	/* 1TB */
		[MMFR0_PARANGE_4T] =	(1ul << 42),	/* 4TB */
		[MMFR0_PARANGE_16T] =	(1ul << 44),	/* 16TB */
		[MMFR0_PARANGE_256T] =	(1ul << 48),	/* 256TB */
		[MMFR0_PARANGE_4P] =	(1ul << 52),	/* 4PB */
		[MMFR0_PARANGE_64P] =	(1ul << 56)	/* 64PB */
	};

	uintptr_t va = KERNELBASE;
	pte_t *ptbl[MMU_PAGE_LEVELS] = {0};

	ptbl[MMU_PAGE_LEVELS - 1] =
	    (pte_t *)pa_to_kseg(TTBR_BADDR48(read_ttbr1()));

	ASSERT(MMFR0_PARANGE(read_id_aa64mmfr0()) < ARRAY_SIZE(pa_size_array));

	size_t pa_size = pa_size_array[MMFR0_PARANGE(read_id_aa64mmfr0())];

	ASSERT(is_reserved_memory(TTBR_BADDR48(read_ttbr1())));

	int l = 0;
	while (va != 0) {
		if (ptbl[l] == NULL) {
			l++;
			continue;
		}
		size_t page_size = LEVEL_SIZE(l);
		if (va == SEGKPM_BASE) {
			ASSERT(l == MMU_PAGE_LEVELS - 1);
			va += SEGKPM_SIZE;
			ptbl[l] += SEGKPM_SIZE / page_size;
			continue;
		}
		if ((*ptbl[l] & PTE_VALID) == 0) {
			va += page_size;
			++ptbl[l];
			if (((uintptr_t)ptbl[l] & MMU_PAGEOFFSET) == 0) {
				ptbl[l] = NULL;
			}
			continue;
		}

		if (l > 0 && (*ptbl[l] & PTE_TYPE_MASK) == PTE_TABLE) {
			ASSERT(ptbl[l - 1] == NULL);
			ptbl[l - 1] = (pte_t *)pa_to_kseg(*ptbl[l] &
			    PTE_PFN_MASK);

			ASSERT(is_reserved_memory(*ptbl[l] & PTE_PFN_MASK));

			++ptbl[l];
			if (((uintptr_t)ptbl[l] & MMU_PAGEOFFSET) == 0) {
				ptbl[l] = NULL;
			}

			l--;
			continue;
		}

		*ptbl[l] |= PTE_NOCONSIST;
		uint64_t pa = (*ptbl[l] & ~(page_size - 1)) & (pa_size - 1);
		for (uint64_t x = 0; x < page_size / MMU_PAGESIZE; x++) {
			pfn_t pfn = mmu_btop(pa + MMU_PAGESIZE * x);
			page_t *pp = page_numtopp_nolock(pfn);
			if (pp) {
				ASSERT(PAGE_EXCL(pp));
				ASSERT(pp->p_lckcnt == 1);

				if (pp->p_vnode == NULL) {
					page_hashin(pp, &kvp,
					    va + MMU_PAGESIZE * x, NULL);
				}
				count++;
			}
		}

		va += page_size;
		++ptbl[l];
		if (((uintptr_t)ptbl[l] & MMU_PAGEOFFSET) == 0) {
			ptbl[l] = NULL;
		}
	}

	if (page_resv(count, KM_NOSLEEP) == 0)
		panic("boot_reserve: page_resv failed");
}
