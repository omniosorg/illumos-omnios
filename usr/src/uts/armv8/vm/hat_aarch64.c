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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2014, 2015 by Delphix. All rights reserved.
 */

#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/cpu.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/shm.h>
#include <sys/sysmacros.h>
#include <sys/machparam.h>
#include <sys/vmem.h>
#include <sys/vmsystm.h>
#include <sys/promif.h>
#include <sys/var.h>
#include <sys/atomic.h>
#include <sys/bitmap.h>
#include <sys/controlregs.h>
#include <sys/archsystm.h>

#include <vm/seg_kmem.h>
#include <vm/hat_aarch64.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/page.h>
#include <vm/seg_kp.h>
#include <vm/seg_kpm.h>
#include <vm/vm_dep.h>
#include <vm/seg_spt.h>
#include <sys/cmn_err.h>

/*
 * Basic parameters for hat operation.
 */
struct hat_mmu_info mmu;

/*
 * forward declaration of internal utility routines
 */
static pte_t hati_update_pte(htable_t *ht, uint_t entry, pte_t expected,
    pte_t new);

uint_t use_boot_reserve = 1;	/* cleared after early boot process */
uint_t can_steal_post_boot = 0;	/* set late in boot to enable stealing */

/*
 * management stuff for hat structures
 */
kmutex_t	hat_list_lock;
kcondvar_t	hat_list_cv;
kmem_cache_t	*hat_cache;
kmem_cache_t	*hat_hash_cache;

/*
 * Simple statistics
 */
struct hatstats hatstat;

#define	PP_GETRM(pp, rmmask)    (pp->p_nrm & rmmask)
#define	PP_ISMOD(pp)		PP_GETRM(pp, P_MOD)
#define	PP_ISREF(pp)		PP_GETRM(pp, P_REF)
#define	PP_ISRO(pp)		PP_GETRM(pp, P_RO)

#define	PP_SETRM(pp, rm)	atomic_or_8(&(pp->p_nrm), rm)
#define	PP_SETMOD(pp)		PP_SETRM(pp, P_MOD)
#define	PP_SETREF(pp)		PP_SETRM(pp, P_REF)
#define	PP_SETRO(pp)		PP_SETRM(pp, P_RO)

#define	PP_CLRRM(pp, rm)	atomic_and_8(&(pp->p_nrm), ~(rm))
#define	PP_CLRMOD(pp)		PP_CLRRM(pp, P_MOD)
#define	PP_CLRREF(pp)		PP_CLRRM(pp, P_REF)
#define	PP_CLRRO(pp)		PP_CLRRM(pp, P_RO)
#define	PP_CLRALL(pp)		PP_CLRRM(pp, P_MOD | P_REF | P_RO)

/*
 * kmem cache constructor for struct hat
 */
static int
hati_constructor(void *buf, void *handle, int kmflags)
{
	hat_t	*hat = buf;

	mutex_init(&hat->hat_mutex, NULL, MUTEX_DEFAULT, NULL);
	bzero(hat->hat_pages_mapped, sizeof (pgcnt_t) * MMU_PAGE_LEVELS);
	hat->hat_ism_pgcnt = 0;
	hat->hat_stats = 0;
	hat->hat_flags = 0;
	hat->hat_htable = NULL;
	hat->hat_ht_hash = NULL;
	return (0);
}

/*
 * Allocate a hat structure for as. We also create the top level
 * htable and initialize it to contain the kernel hat entries.
 */
hat_t *
hat_alloc(struct as *as)
{
	hat_t			*hat;
	htable_t		*ht;	/* top level htable */

	/*
	 * Once we start creating user process HATs we can enable
	 * the htable_steal() code.
	 */
	if (can_steal_post_boot == 0)
		can_steal_post_boot = 1;

	ASSERT(AS_WRITE_HELD(as));
	hat = kmem_cache_alloc(hat_cache, KM_SLEEP);
	hat->hat_as = as;
	mutex_init(&hat->hat_mutex, NULL, MUTEX_DEFAULT, NULL);
	ASSERT(hat->hat_flags == 0);

	hat->hat_ht_hash = kmem_cache_alloc(hat_hash_cache, KM_SLEEP);
	bzero(hat->hat_ht_hash, HTABLE_NUM_HASH * sizeof (htable_t *));

	hat->hat_htable = NULL;
	hat->hat_ht_cached = NULL;
	/* create top level */
	ht = htable_create(hat, (uintptr_t)0, MAX_PAGE_LEVEL, NULL);
	hat->hat_htable = ht;

	/*
	 * Put it at the start of the global list of all hats (used by stealing)
	 *
	 * kas.a_hat is not in the list but is instead used to find the
	 * first and last items in the list.
	 *
	 * - kas.a_hat->hat_next points to the start of the user hats.
	 *   The list ends where hat->hat_next == NULL
	 *
	 * - kas.a_hat->hat_prev points to the last of the user hats.
	 *   The list begins where hat->hat_prev == NULL
	 */
	mutex_enter(&hat_list_lock);
	hat->hat_prev = NULL;
	hat->hat_next = kas.a_hat->hat_next;
	if (hat->hat_next)
		hat->hat_next->hat_prev = hat;
	else
		kas.a_hat->hat_prev = hat;
	kas.a_hat->hat_next = hat;
	mutex_exit(&hat_list_lock);

	for (int cpuid = 0; cpuid < NCPU; cpuid++) {
		hat->hat_asid_gen[cpuid] = -1;
		hat->hat_asid[cpuid] = 0;
	}

	return (hat);
}

/*
 * process has finished executing but as has not been cleaned up yet.
 */
/*ARGSUSED*/
void
hat_free_start(hat_t *hat)
{
	ASSERT(AS_WRITE_HELD(hat->hat_as));

	/*
	 * If the hat is currently a stealing victim, wait for the stealing
	 * to finish.  Once we mark it as HAT_FREEING, htable_steal()
	 * won't look at its pagetables anymore.
	 */
	mutex_enter(&hat_list_lock);
	while (hat->hat_flags & HAT_VICTIM)
		cv_wait(&hat_list_cv, &hat_list_lock);
	hat->hat_flags |= HAT_FREEING;
	mutex_exit(&hat_list_lock);
}

/*
 * An address space is being destroyed, so we destroy the associated hat.
 */
void
hat_free_end(hat_t *hat)
{
	ASSERT(hat->hat_flags & HAT_FREEING);

	/*
	 * Remove it from the list of HATs
	 */
	mutex_enter(&hat_list_lock);
	if (hat->hat_prev)
		hat->hat_prev->hat_next = hat->hat_next;
	else
		kas.a_hat->hat_next = hat->hat_next;
	if (hat->hat_next)
		hat->hat_next->hat_prev = hat->hat_prev;
	else
		kas.a_hat->hat_prev = hat->hat_prev;
	mutex_exit(&hat_list_lock);
	hat->hat_next = hat->hat_prev = NULL;

	/*
	 * Make a pass through the htables freeing them all up.
	 */
	htable_purge_hat(hat);

	/*
	 * Decide which kmem cache the hash table came from, then free it.
	 */
	kmem_cache_free(hat_hash_cache, hat->hat_ht_hash);
	hat->hat_ht_hash = NULL;

	hat->hat_flags = 0;
	kmem_cache_free(hat_cache, hat);
}

/*
 * Initialize hat data structures based on processor MMU information.
 */
void
mmu_init(void)
{
	hole_start = HOLE_START;
	hole_end = HOLE_END;
	mmu.max_asid = ((read_tcr() & TCR_AS)? 0xFFFF: 0xFF);
	mmu.max_level = MAX_PAGE_LEVEL;
	mmu.kernelbase = ~((1ul << (VA_BITS - 1)) - 1);
}

/*
 * initialize hat data structures
 */
void
hat_init()
{
	cv_init(&hat_list_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * initialize kmem caches
	 */
	htable_init();
	hment_init();

	hat_cache = kmem_cache_create("hat_t", sizeof (hat_t),
	    0, hati_constructor, NULL, NULL, NULL, 0, 0);
	hat_hash_cache = kmem_cache_create("HatHash", MMU_PAGESIZE,
	    0, NULL, NULL, NULL, NULL, 0, 0);

	/*
	 * Set up the kernel's hat
	 */
	AS_LOCK_ENTER(&kas, RW_WRITER);
	kas.a_hat = kmem_cache_alloc(hat_cache, KM_NOSLEEP);
	mutex_init(&kas.a_hat->hat_mutex, NULL, MUTEX_DEFAULT, NULL);
	kas.a_hat->hat_as = &kas;
	kas.a_hat->hat_flags = 0;
	AS_LOCK_EXIT(&kas);

	/*
	 * The kernel hat's next pointer serves as the head of the hat list .
	 * The kernel hat's prev pointer tracks the last hat on the list for
	 * htable_steal() to use.
	 */
	kas.a_hat->hat_next = NULL;
	kas.a_hat->hat_prev = NULL;

	/*
	 * Allocate an htable hash bucket for the kernel
	 * XX64 - tune for 64 bit procs
	 */
	kas.a_hat->hat_ht_hash = kmem_cache_alloc(hat_hash_cache, KM_NOSLEEP);
	bzero(kas.a_hat->hat_ht_hash, MMU_PAGESIZE);

	/*
	 * zero out the top level and cached htable pointers
	 */
	kas.a_hat->hat_ht_cached = NULL;
	kas.a_hat->hat_htable = NULL;

	/*
	 * Pre-allocate hrm_hashtab before enabling the collection of
	 * refmod statistics.  Allocating on the fly would mean us
	 * running the risk of suffering recursive mutex enters or
	 * deadlocks.
	 */
	hrm_hashtab = kmem_zalloc(HRM_HASHSIZE * sizeof (struct hrmstat *),
	    KM_SLEEP);
}

/*
 * Finish filling in the kernel hat.
 * Pre fill in all top level kernel page table entries for the kernel's
 * part of the address range.  From this point on we can't use any new
 * kernel large pages if they need PTE's at max_level
 *
 * create the kmap mappings.
 */
void
hat_init_finish(void)
{
	/*
	 * We are now effectively running on the kernel hat.
	 * Clearing use_boot_reserve shuts off using the pre-allocated boot
	 * reserve for all HAT allocations.  From here on, the reserves are
	 * only used when avoiding recursion in kmem_alloc().
	 */
	use_boot_reserve = 0;
	htable_adjust_reserve();

	/*
	 * Create kmap (cached mappings of kernel PTEs)
	 * for 64 bit we map from segmap_start .. segmap_start + segmapsize;
	 */
	hat_kmap_init((uintptr_t)segmap_start, segmapsize);
}

/*
 * Switch to a new active hat.
 */
void
hat_switch(hat_t *hat)
{
	cpu_t *cpu = CPU;
	hat_t *old = cpu->cpu_current_hat;

	if (old != hat) {
		if (hat == kas.a_hat) {
			write_tcr(read_tcr() | TCR_EPD0);
			isb();
		} else {
			if (old == kas.a_hat || old == NULL) {
				write_tcr(read_tcr() & ~TCR_EPD0);
			}

			processorid_t cpuid = cpu->cpu_id;
			uint64_t cur_gen = cpu->cpu_asid_gen;
			int req_tlbi = 0;

			if (hat->hat_asid_gen[cpuid] != cur_gen) {
				uint32_t cur_asid = cpu->cpu_asid + 1;
				if (cur_asid > mmu.max_asid) {
					cur_gen++;
					cpu->cpu_asid_gen = cur_gen;
					cur_asid = 1;
					req_tlbi = 1;
				}
				cpu->cpu_asid = cur_asid;
				hat->hat_asid_gen[cpuid] = cur_gen;
				hat->hat_asid[cpuid] = cur_asid;
			}
			write_ttbr0(((uint64_t)hat->hat_asid[cpuid] <<
			    TTBR_ASID_SHIFT) |
			    pfn_to_pa(hat->hat_htable->ht_pfn));
			isb();
			if (req_tlbi) {
				tlbi_allis();
				dsb(ish);
				isb();
			}
		}
		cpu->cpu_current_hat = hat;
	}
}

/*
 * Utility to return a valid pte_t from protections, pfn, and level number
 */
static pte_t
hati_mkpte(pfn_t pfn, uint_t attr, level_t level, uint_t flags)
{
	pte_t	pte;
	uint_t	cache_attr = (attr & HAT_ORDER_MASK);

	pte = MAKEPTE(pfn, level);

	if (!(attr & PROT_WRITE))
		PTE_SET(pte, PTE_AP_RO);

	if (attr & PROT_USER)
		PTE_SET(pte, PTE_AP_USER);

	if (!(attr & PROT_EXEC))
		PTE_SET(pte, (attr & PROT_USER)? PTE_UXN: PTE_PXN);

	if (flags & HAT_LOAD_NOCONSIST)
		PTE_SET(pte, PTE_NOCONSIST | PTE_AF);
	else if (attr & HAT_NOSYNC)
		PTE_SET(pte, PTE_NOSYNC | PTE_AF);

	switch (cache_attr) {
	case HAT_STRICTORDER:
		PTE_SET(pte, PTE_ATTR_DEVICE);
		break;
	case HAT_UNORDERED_OK:
		PTE_SET(pte, PTE_ATTR_UNORDERED);
		break;
	case HAT_MERGING_OK:
		PTE_SET(pte, PTE_ATTR_NORMEM_UC);
		break;
	case HAT_LOADCACHING_OK:
		PTE_SET(pte, PTE_ATTR_NORMEM_WT);
		break;
	case HAT_STORECACHING_OK:
		PTE_SET(pte, PTE_ATTR_NORMEM);
		break;
	default:
		panic("hati_mkpte(): bad caching attributes: %x\n", cache_attr);
	}

	return (pte);
}

/*
 * Duplicate address translations of the parent to the child.
 * This function really isn't used anymore.
 */
/*ARGSUSED*/
int
hat_dup(hat_t *old, hat_t *new, caddr_t addr, size_t len, uint_t flag)
{
	ASSERT((uintptr_t)addr < kernelbase);
	ASSERT(new != kas.a_hat);
	ASSERT(old != kas.a_hat);
	return (0);
}

/*
 * Allocate any hat resources required for a process being swapped in.
 */
/*ARGSUSED*/
void
hat_swapin(hat_t *hat)
{
	/* do nothing - we let everything fault back in */
}

/*
 * Unload all translations associated with an address space of a process
 * that is being swapped out.
 */
void
hat_swapout(hat_t *hat)
{
	uintptr_t	vaddr = (uintptr_t)0;
	uintptr_t	eaddr = _userlimit;
	htable_t	*ht = NULL;
	level_t		l;

	/*
	 * We can't just call hat_unload(hat, 0, _userlimit...)  here, because
	 * seg_spt and shared pagetables can't be swapped out.
	 * Take a look at segspt_shmswapout() - it's a big no-op.
	 *
	 * Instead we'll walk through all the address space and unload
	 * any mappings which we are sure are not shared, not locked.
	 */
	ASSERT(IS_PAGEALIGNED(vaddr));
	ASSERT(IS_PAGEALIGNED(eaddr));
	ASSERT(AS_LOCK_HELD(hat->hat_as));
	if ((uintptr_t)hat->hat_as->a_userlimit < eaddr)
		eaddr = (uintptr_t)hat->hat_as->a_userlimit;

	while (vaddr < eaddr) {
		(void) htable_walk(hat, &ht, &vaddr, eaddr);
		if (ht == NULL)
			break;

		ASSERT(!IN_VA_HOLE(vaddr));

		/*
		 * If the page table is shared skip its entire range.
		 */
		l = ht->ht_level;
		if (ht->ht_flags & HTABLE_SHARED_PFN) {
			vaddr = ht->ht_vaddr + LEVEL_SIZE(l + 1);
			htable_release(ht);
			ht = NULL;
			continue;
		}

		/*
		 * If the page table has no locked entries, unload this one.
		 */
		if (ht->ht_lock_cnt == 0)
			hat_unload(hat, (caddr_t)vaddr, LEVEL_SIZE(l),
			    HAT_UNLOAD_UNMAP);

		/*
		 * If we have a level 0 page table with locked entries,
		 * skip the entire page table, otherwise skip just one entry.
		 */
		if (ht->ht_lock_cnt > 0 && l == PAGE_LEVEL)
			vaddr = ht->ht_vaddr + LEVEL_SIZE(l + 1);
		else
			vaddr += LEVEL_SIZE(l);
	}
	if (ht)
		htable_release(ht);

	/*
	 * We're in swapout because the system is low on memory, so
	 * go back and flush all the htables off the cached list.
	 */
	htable_purge_hat(hat);
}

/*
 * returns number of bytes that have valid mappings in hat.
 */
size_t
hat_get_mapped_size(hat_t *hat)
{
	size_t total = 0;
	int l;

	for (l = 0; l < MMU_PAGE_LEVELS; l++)
		total += (hat->hat_pages_mapped[l] << LEVEL_SHIFT(l));
	total += hat->hat_ism_pgcnt;

	return (total);
}

/*
 * enable/disable collection of stats for hat.
 */
int
hat_stats_enable(hat_t *hat)
{
	atomic_inc_32(&hat->hat_stats);
	return (1);
}

void
hat_stats_disable(hat_t *hat)
{
	atomic_dec_32(&hat->hat_stats);
}

/*
 * Utility to sync the ref/mod bits from a page table entry to the page_t
 * We must be holding the mapping list lock when this is called.
 */
static void
hati_sync_pte_to_page(page_t *pp, pte_t pte, level_t level)
{
	uint_t	rm = 0;
	pgcnt_t	pgcnt;

	if (PTE_GET(pte, PTE_SOFTWARE) >= PTE_NOSYNC)
		return;

	switch (PTE_GET(pte, PTE_AF | PTE_AP_RO)) {
	case PTE_AF:
		rm |= (P_REF | P_MOD);
		break;
	case PTE_AF | PTE_AP_RO:
		rm |= P_REF;
		break;
	default:
		break;
	}

	if (rm == 0)
		return;

	/*
	 * sync to all constituent pages of a large page
	 */
	ASSERT(hm_held(pp));
	pgcnt = page_get_pagecnt(level);
	ASSERT(IS_P2ALIGNED(pp->p_pagenum, pgcnt));
	for (; pgcnt > 0; --pgcnt) {
		/*
		 * hat_page_demote() can't decrease
		 * pszc below this mapping size
		 * since this large mapping existed after we
		 * took mlist lock.
		 */
		ASSERT(pp->p_szc >= level);
		hat_page_setattr(pp, rm);
		++pp;
	}
}

/*
 * This the set of PTE bits for PFN, permissions and caching
 * that are allowed to change on a HAT_LOAD_REMAP
 */
#define	PTE_REMAP_BITS							\
	(PTE_PFN_MASK | PTE_UXN | PTE_PXN | PTE_AF | PTE_AP_RO | PTE_ATTR_MASK)


#define	REMAPASSERT(EX)	if (!(EX)) panic("hati_pte_map: " #EX)
/*
 * Do the low-level work to get a mapping entered into a HAT's pagetables
 * and in the mapping list of the associated page_t.
 */
static int
hati_pte_map(
	htable_t	*ht,
	uint_t		entry,
	page_t		*pp,
	pte_t		pte,
	int		flags,
	void		*pte_ptr)
{
	hat_t		*hat = ht->ht_hat;
	pte_t		old_pte;
	level_t		l = ht->ht_level;
	hment_t		*hm;
	uint_t		is_consist;
	uint_t		is_locked;
	int		rv = 0;

	/*
	 * Is this a consistent (ie. need mapping list lock) mapping?
	 */
	is_consist = (pp != NULL && (flags & HAT_LOAD_NOCONSIST) == 0);

	/*
	 * Track locked mapping count in the htable.  Do this first,
	 * as we track locking even if there already is a mapping present.
	 */
	is_locked = (flags & HAT_LOAD_LOCK) != 0 && hat != kas.a_hat;
	if (is_locked)
		HTABLE_LOCK_INC(ht);

	/*
	 * Acquire the page's mapping list lock and get an hment to use.
	 * Note that hment_prepare() might return NULL.
	 */
	if (is_consist) {
		hm_enter(pp);
		hm = hment_prepare(ht, entry, pp);
	}

	/*
	 * Set the new pte, retrieving the old one at the same time.
	 */
	old_pte = pte_set(ht, entry, pte, pte_ptr);

	/*
	 * Did we get a large page / page table collision?
	 */
	if (old_pte == LPAGE_ERROR) {
		if (is_locked)
			HTABLE_LOCK_DEC(ht);
		rv = -1;
		goto done;
	}

	/*
	 * If the mapping didn't change there is nothing more to do.
	 */
	if (PTE_EQUIV(pte, old_pte))
		goto done;

	/*
	 * Install a new mapping in the page's mapping list
	 */
	if (!PTE_ISVALID(old_pte)) {
		if (is_consist) {
			hment_assign(ht, entry, pp, hm);
			hm_exit(pp);
		} else {
			ASSERT(flags & HAT_LOAD_NOCONSIST);
		}
		HTABLE_INC(ht->ht_valid_cnt);
		PGCNT_INC(hat, l);
		return (rv);
	}

	/*
	 * Remap's are more complicated:
	 *  - HAT_LOAD_REMAP must be specified if changing the pfn.
	 *    We also require that NOCONSIST be specified.
	 *  - Otherwise only permission or caching bits may change.
	 */
	if (!PTE_ISPAGE(old_pte, l))
		panic("non-null/page mapping pte=" FMT_PTE, old_pte);

	if (PTE2PFN(old_pte, l) != PTE2PFN(pte, l)) {
		REMAPASSERT(flags & HAT_LOAD_REMAP);
		REMAPASSERT(flags & HAT_LOAD_NOCONSIST);
		REMAPASSERT(PTE_GET(old_pte, PTE_SOFTWARE) >= PTE_NOCONSIST);
		REMAPASSERT(pf_is_memory(PTE2PFN(old_pte, l)) ==
		    pf_is_memory(PTE2PFN(pte, l)));
		REMAPASSERT(!is_consist);
	}

	/*
	 * We only let remaps change the certain bits in the PTE.
	 */
	if (PTE_GET(old_pte, ~PTE_REMAP_BITS) != PTE_GET(pte, ~PTE_REMAP_BITS))
		panic("remap bits changed: old_pte="FMT_PTE", pte="FMT_PTE"\n",
		    old_pte, pte);

	/*
	 * We don't create any mapping list entries on a remap, so release
	 * any allocated hment after we drop the mapping list lock.
	 */
done:
	if (is_consist) {
		hm_exit(pp);
		if (hm != NULL)
			hment_free(hm);
	}
	return (rv);
}

static void
clean_dcache(caddr_t addr, uint_t len)
{
	uint64_t data_line_size = CTR_DMINLINE_SIZE(read_ctr_el0());

	for (uintptr_t v = P2ALIGN((uintptr_t)addr, data_line_size);
	    v < (uintptr_t)addr + len; v += data_line_size) {
		clean_data_cache_pou(v);
	}
	dsb(ish);
}

/*
 * Internal routine to load a single page table entry. This only fails if
 * we attempt to overwrite a page table link with a large page.
 */
static int
hati_load_common(
	hat_t		*hat,
	uintptr_t	va,
	page_t		*pp,
	uint_t		attr,
	uint_t		flags,
	level_t		level,
	pfn_t		pfn)
{
	htable_t	*ht;
	uint_t		entry;
	pte_t	pte;
	int		rv = 0;

	/*
	 * The number 16 is arbitrary and here to catch a recursion problem
	 * early before we blow out the kernel stack.
	 */
	++curthread->t_hatdepth;
	ASSERT(curthread->t_hatdepth < 16);

	ASSERT(hat == kas.a_hat || AS_LOCK_HELD(hat->hat_as));

	if (flags & HAT_LOAD_SHARE)
		hat->hat_flags |= HAT_SHARED;

	/*
	 * Find the page table that maps this page if it already exists.
	 */
	ht = htable_lookup(hat, va, level);

	/*
	 * We must have HAT_LOAD_NOCONSIST if page_t is NULL.
	 */
	if (pp == NULL)
		flags |= HAT_LOAD_NOCONSIST;

	if (ht == NULL) {
		ht = htable_create(hat, va, level, NULL);
		ASSERT(ht != NULL);
	}
	entry = htable_va2entry(va, ht);

	/*
	 * a bunch of paranoid error checking
	 */
	ASSERT(ht->ht_busy > 0);
	if (ht->ht_vaddr > va || va > HTABLE_LAST_PAGE(ht))
		panic("hati_load_common: bad htable %p, va %p",
		    (void *)ht, (void *)va);
	ASSERT(ht->ht_level == level);

	/*
	 * construct the new PTE
	 */
	if (hat == kas.a_hat)
		attr &= ~PROT_USER;
	pte = hati_mkpte(pfn, attr, level, flags);
	if (hat != kas.a_hat)
		PTE_SET(pte, PTE_NG | PTE_PXN);
	else
		PTE_SET(pte, PTE_UXN);

	if (((attr & PROT_EXEC) ||
	    (attr & HAT_ORDER_MASK) != HAT_STORECACHING_OK) &&
	    pf_is_memory(pfn)) {
		clean_dcache(hat_kpm_pfn2va(pfn), LEVEL_SIZE(level));
	}

	/*
	 * establish the mapping
	 */
	rv = hati_pte_map(ht, entry, pp, pte, flags, NULL);

	/*
	 * release the htable and any reserves
	 */
	htable_release(ht);
	--curthread->t_hatdepth;
	return (rv);
}

/*
 * special case of hat_memload to deal with some kernel addrs for performance
 */
static void
hat_kmap_load(
	caddr_t		addr,
	page_t		*pp,
	uint_t		attr,
	uint_t		flags)
{
	uintptr_t	va = (uintptr_t)addr;
	pte_t		pte;
	pfn_t		pfn = page_pptonum(pp);
	pgcnt_t		pg_off = mmu_btop(va - mmu.kmap_addr);
	htable_t	*ht;
	uint_t		entry;
	void		*pte_ptr;

	/*
	 * construct the requested PTE
	 */
	attr &= ~PROT_USER;
	attr &= ~HAT_ORDER_MASK;
	attr |= HAT_STORECACHING_OK;
	pte = hati_mkpte(pfn, attr, 0, flags);

	/*
	 * Figure out the pte_ptr and htable and use common code to finish up
	 */
	pte_ptr = mmu.kmap_ptes + pg_off;
	ht = mmu.kmap_htables[(va - mmu.kmap_htables[0]->ht_vaddr) >>
	    LEVEL_SHIFT(1)];
	entry = htable_va2entry(va, ht);
	++curthread->t_hatdepth;
	ASSERT(curthread->t_hatdepth < 16);
	(void) hati_pte_map(ht, entry, pp, pte, flags, pte_ptr);
	--curthread->t_hatdepth;
}

/*
 * hat_memload() - load a translation to the given page struct
 *
 * Flags for hat_memload/hat_devload/hat_*attr.
 *
 *	HAT_LOAD	Default flags to load a translation to the page.
 *
 *	HAT_LOAD_LOCK	Lock down mapping resources; hat_map(), hat_memload(),
 *			and hat_devload().
 *
 *	HAT_LOAD_NOCONSIST Do not add mapping to page_t mapping list.
 *			sets PT_NOCONSIST
 *
 *	HAT_LOAD_SHARE	A flag to hat_memload() to indicate h/w page tables
 *			that map some user pages (not kas) is shared by more
 *			than one process (eg. ISM).
 *
 *	HAT_LOAD_REMAP	Reload a valid pte with a different page frame.
 *
 *	HAT_NO_KALLOC	Do not kmem_alloc while creating the mapping; at this
 *			point, it's setting up mapping to allocate internal
 *			hat layer data structures.  This flag forces hat layer
 *			to tap its reserves in order to prevent infinite
 *			recursion.
 *
 * The following is a protection attribute (like PROT_READ, etc.)
 *
 *	HAT_NOSYNC	set PT_NOSYNC - this mapping's ref/mod bits
 *			are never cleared.
 *
 * Installing new valid PTE's and creation of the mapping list
 * entry are controlled under the same lock. It's derived from the
 * page_t being mapped.
 */
static uint_t supported_memload_flags =
	HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_ADV | HAT_LOAD_NOCONSIST |
	HAT_LOAD_SHARE | HAT_NO_KALLOC | HAT_LOAD_REMAP | HAT_LOAD_TEXT;

void
hat_memload(
	hat_t		*hat,
	caddr_t		addr,
	page_t		*pp,
	uint_t		attr,
	uint_t		flags)
{
	uintptr_t	va = (uintptr_t)addr;
	level_t		level = 0;
	pfn_t		pfn = page_pptonum(pp);

	ASSERT(IS_PAGEALIGNED(va));
	ASSERT(hat == kas.a_hat || va < _userlimit);
	ASSERT(hat == kas.a_hat || AS_LOCK_HELD(hat->hat_as));
	ASSERT((flags & supported_memload_flags) == flags);

	ASSERT(!IN_VA_HOLE(va));
	ASSERT(!PP_ISFREE(pp));

	/*
	 * kernel address special case for performance.
	 */
	if (mmu.kmap_addr <= va && va < mmu.kmap_eaddr) {
		ASSERT(hat == kas.a_hat);
		hat_kmap_load(addr, pp, attr, flags);
		return;
	}

	/*
	 * This is used for memory with normal caching enabled, so
	 * always set HAT_STORECACHING_OK.
	 */
	attr &= ~HAT_ORDER_MASK;
	attr |= HAT_STORECACHING_OK;
	if (hati_load_common(hat, va, pp, attr, flags, level, pfn) != 0)
		panic("unexpected hati_load_common() failure");
}

/* ARGSUSED */
void
hat_memload_region(struct hat *hat, caddr_t addr, struct page *pp,
    uint_t attr, uint_t flags, hat_region_cookie_t rcookie)
{
	hat_memload(hat, addr, pp, attr, flags);
}

/*
 * Load the given array of page structs using large pages when possible
 */
void
hat_memload_array(
	hat_t		*hat,
	caddr_t		addr,
	size_t		len,
	page_t		**pages,
	uint_t		attr,
	uint_t		flags)
{
	uintptr_t	va = (uintptr_t)addr;
	uintptr_t	eaddr = va + len;
	level_t		level;
	size_t		pgsize;
	pgcnt_t		pgindx = 0;
	pfn_t		pfn;
	pgcnt_t		i;

	ASSERT(IS_PAGEALIGNED(va));
	ASSERT(hat == kas.a_hat || va + len <= _userlimit);
	ASSERT(hat == kas.a_hat || AS_LOCK_HELD(hat->hat_as));
	ASSERT((flags & supported_memload_flags) == flags);

	/*
	 * memload is used for memory with full caching enabled, so
	 * set HAT_STORECACHING_OK.
	 */
	attr &= ~HAT_ORDER_MASK;
	attr |= HAT_STORECACHING_OK;

	/*
	 * handle all pages using largest possible pagesize
	 */
	while (va < eaddr) {
		/*
		 * decide what level mapping to use (ie. pagesize)
		 */
		pfn = page_pptonum(pages[pgindx]);
		for (level = MAX_PAGE_LEVEL; ; --level) {
			pgsize = LEVEL_SIZE(level);
			if (level == 0)
				break;

			if (!IS_P2ALIGNED(va, pgsize) ||
			    (eaddr - va) < pgsize ||
			    !IS_P2ALIGNED(pfn_to_pa(pfn), pgsize))
				continue;

			/*
			 * To use a large mapping of this size, all the
			 * pages we are passed must be sequential subpages
			 * of the large page.
			 * hat_page_demote() can't change p_szc because
			 * all pages are locked.
			 */
			if (pages[pgindx]->p_szc >= level) {
				for (i = 0; i < mmu_btop(pgsize); ++i) {
					if (pfn + i !=
					    page_pptonum(pages[pgindx + i]))
						break;
					ASSERT(pages[pgindx + i]->p_szc >=
					    level);
					ASSERT(pages[pgindx] + i ==
					    pages[pgindx + i]);
				}
				if (i == mmu_btop(pgsize)) {
					break;
				}
			}
		}

		/*
		 * Load this page mapping. If the load fails, try a smaller
		 * pagesize.
		 */
		ASSERT(!IN_VA_HOLE(va));
		while (hati_load_common(hat, va, pages[pgindx], attr,
		    flags, level, pfn) != 0) {
			if (level == 0)
				panic("unexpected hati_load_common() failure");
			--level;
			pgsize = LEVEL_SIZE(level);
		}

		/*
		 * move to next page
		 */
		va += pgsize;
		pgindx += mmu_btop(pgsize);
	}
}

/* ARGSUSED */
void
hat_memload_array_region(struct hat *hat, caddr_t addr, size_t len,
    struct page **pps, uint_t attr, uint_t flags,
    hat_region_cookie_t rcookie)
{
	hat_memload_array(hat, addr, len, pps, attr, flags);
}

/*
 * void hat_devload(hat, addr, len, pf, attr, flags)
 *	load/lock the given page frame number
 *
 * Advisory ordering attributes. Apply only to device mappings.
 *
 * HAT_STRICTORDER: the CPU must issue the references in order, as the
 *	programmer specified.  This is the default.
 * HAT_UNORDERED_OK: the CPU may reorder the references (this is all kinds
 *	of reordering; store or load with store or load).
 * HAT_MERGING_OK: merging and batching: the CPU may merge individual stores
 *	to consecutive locations (for example, turn two consecutive byte
 *	stores into one halfword store), and it may batch individual loads
 *	(for example, turn two consecutive byte loads into one halfword load).
 *	This also implies re-ordering.
 * HAT_LOADCACHING_OK: the CPU may cache the data it fetches and reuse it
 *	until another store occurs.  The default is to fetch new data
 *	on every load.  This also implies merging.
 * HAT_STORECACHING_OK: the CPU may keep the data in the cache and push it to
 *	the device (perhaps with other data) at a later time.  The default is
 *	to push the data right away.  This also implies load caching.
 *
 * Equivalent of hat_memload(), but can be used for device memory where
 * there are no page_t's and we support additional flags (write merging, etc).
 * Note that we can have large page mappings with this interface.
 */
int supported_devload_flags = HAT_LOAD | HAT_LOAD_LOCK |
	HAT_LOAD_NOCONSIST;

void
hat_devload(
	hat_t		*hat,
	caddr_t		addr,
	size_t		len,
	pfn_t		pfn,
	uint_t		attr,
	int		flags)
{
	uintptr_t	va = ALIGN2PAGE(addr);
	uintptr_t	eva = va + len;
	level_t		level;
	size_t		pgsize;
	page_t		*pp;
	int		f;	/* per PTE copy of flags  - maybe modified */
	uint_t		a;	/* per PTE copy of attr */

	ASSERT(IS_PAGEALIGNED(va));
	ASSERT(hat == kas.a_hat || eva <= _userlimit);
	ASSERT(hat == kas.a_hat || AS_LOCK_HELD(hat->hat_as));
	ASSERT((flags & supported_devload_flags) == flags);

	/*
	 * handle all pages
	 */
	while (va < eva) {

		/*
		 * decide what level mapping to use (ie. pagesize)
		 */
		for (level = MAX_PAGE_LEVEL; ; --level) {
			pgsize = LEVEL_SIZE(level);
			if (level == 0)
				break;
			if (IS_P2ALIGNED(va, pgsize) &&
			    (eva - va) >= pgsize &&
			    IS_P2ALIGNED(pfn, mmu_btop(pgsize))) {
				break;
			}
		}

		/*
		 * If this is just memory then allow caching (this happens
		 * for the nucleus pages) - though HAT_PLAT_NOCACHE can be used
		 * to override that. If we don't have a page_t then make sure
		 * NOCONSIST is set.
		 */
		a = attr;
		f = flags;
		if (!pf_is_memory(pfn))
			f |= HAT_LOAD_NOCONSIST;
		else if (!(a & HAT_PLAT_NOCACHE))
			a |= HAT_STORECACHING_OK;

		if (f & HAT_LOAD_NOCONSIST)
			pp = NULL;
		else
			pp = page_numtopp_nolock(pfn);

		/*
		 * Check to make sure we are really trying to map a valid
		 * memory page. The caller wishing to intentionally map
		 * free memory pages will have passed the HAT_LOAD_NOCONSIST
		 * flag, then pp will be NULL.
		 */
		if (pp != NULL) {
			if (PP_ISFREE(pp)) {
				panic("hat_devload: loading "
				    "a mapping to free page %p", (void *)pp);
			}

			if (!PAGE_LOCKED(pp) && !PP_ISNORELOC(pp)) {
				panic("hat_devload: loading a mapping "
				    "to an unlocked page %p",
				    (void *)pp);
			}
		}

		/*
		 * load this page mapping
		 */
		ASSERT(!IN_VA_HOLE(va));
		while (hati_load_common(hat, va, pp, a, f, level, pfn) != 0) {
			if (level == 0)
				panic("unexpected hati_load_common() failure");
			--level;
			pgsize = LEVEL_SIZE(level);
		}

		/*
		 * move to next page
		 */
		va += pgsize;
		pfn += mmu_btop(pgsize);
	}
}

/*
 * void hat_unlock(hat, addr, len)
 *	unlock the mappings to a given range of addresses
 *
 * Locks are tracked by ht_lock_cnt in the htable.
 */
void
hat_unlock(hat_t *hat, caddr_t addr, size_t len)
{
	uintptr_t	vaddr = (uintptr_t)addr;
	uintptr_t	eaddr = vaddr + len;
	htable_t	*ht = NULL;

	/*
	 * kernel entries are always locked, we don't track lock counts
	 */
	ASSERT(hat == kas.a_hat || eaddr <= _userlimit);
	ASSERT(IS_PAGEALIGNED(vaddr));
	ASSERT(IS_PAGEALIGNED(eaddr));
	if (hat == kas.a_hat)
		return;
	if (eaddr > _userlimit)
		panic("hat_unlock() address out of range - above _userlimit");

	ASSERT(AS_LOCK_HELD(hat->hat_as));
	while (vaddr < eaddr) {
		(void) htable_walk(hat, &ht, &vaddr, eaddr);
		if (ht == NULL)
			break;

		ASSERT(!IN_VA_HOLE(vaddr));

		if (ht->ht_lock_cnt < 1)
			panic("hat_unlock(): lock_cnt < 1, "
			    "htable=%p, vaddr=%p\n", (void *)ht, (void *)vaddr);
		HTABLE_LOCK_DEC(ht);

		vaddr += LEVEL_SIZE(ht->ht_level);
	}
	if (ht)
		htable_release(ht);
}

/* ARGSUSED */
void
hat_unlock_region(struct hat *hat, caddr_t addr, size_t len,
    hat_region_cookie_t rcookie)
{
	panic("No shared region support on aarch64");
}

/*
 * Internal routine to do cross calls to invalidate a range of pages on
 * all CPUs using a given hat.
 */
void
hat_tlb_inval_range(hat_t *hat, uintptr_t va, size_t len)
{
	/*
	 * If the hat is being destroyed, there are no more users, so
	 * demap need not do anything.
	 */
	if (hat->hat_flags & HAT_FREEING)
		return;

	dsb(ish);
	if (va == DEMAP_ALL_ADDR) {
			tlbi_allis();
	} else {
		for (size_t i = 0; i < len; i += MMU_PAGESIZE)
			tlbi_mva(va + i);
	}
	dsb(ish);
	isb();
}

void
hat_tlb_inval(hat_t *hat, uintptr_t va)
{
	hat_tlb_inval_range(hat, va, MMU_PAGESIZE);
}

/*
 * Interior routine for HAT_UNLOADs from hat_unload_callback(),
 * hat_kmap_unload() OR from hat_steal() code.  This routine doesn't
 * handle releasing of the htables.
 */
void
hat_pte_unmap(
	htable_t	*ht,
	uint_t		entry,
	uint_t		flags,
	pte_t	old_pte,
	void		*pte_ptr,
	boolean_t	tlb)
{
	hat_t		*hat = ht->ht_hat;
	hment_t		*hm = NULL;
	page_t		*pp = NULL;
	level_t		l = ht->ht_level;
	pfn_t		pfn;

	/*
	 * We always track the locking counts, even if nothing is unmapped
	 */
	if ((flags & HAT_UNLOAD_UNLOCK) != 0 && hat != kas.a_hat) {
		ASSERT(ht->ht_lock_cnt > 0);
		HTABLE_LOCK_DEC(ht);
	}

	/*
	 * Figure out which page's mapping list lock to acquire using the PFN
	 * passed in "old" PTE. We then attempt to invalidate the PTE.
	 * If another thread, probably a hat_pageunload, has asynchronously
	 * unmapped/remapped this address we'll loop here.
	 */
	ASSERT(ht->ht_busy > 0);
	while (PTE_ISVALID(old_pte)) {
		pfn = PTE2PFN(old_pte, l);
		if (PTE_GET(old_pte, PTE_SOFTWARE) >= PTE_NOCONSIST) {
			pp = NULL;
		} else {
			if (pfn == PFN_INVALID)
				panic("Invalid PFN, but not PT_NOCONSIST");
			pp = page_numtopp_nolock(pfn);
			if (pp == NULL) {
				panic("no page_t, not NOCONSIST: old_pte="
				    FMT_PTE " ht=%lx entry=0x%x pte_ptr=%lx",
				    old_pte, (uintptr_t)ht, entry,
				    (uintptr_t)pte_ptr);
			}
			hm_enter(pp);
		}

		old_pte = pte_inval(ht, entry, old_pte, pte_ptr, tlb);

		/*
		 * If the page hadn't changed we've unmapped it and can proceed
		 */
		if (PTE_ISVALID(old_pte) && PTE2PFN(old_pte, l) == pfn)
			break;

		/*
		 * Otherwise, we'll have to retry with the current old_pte.
		 * Drop the hment lock, since the pfn may have changed.
		 */
		if (pp != NULL) {
			hm_exit(pp);
			pp = NULL;
		} else {
			ASSERT(PTE_GET(old_pte, PTE_SOFTWARE) >= PTE_NOCONSIST);
		}
	}

	/*
	 * If the old mapping wasn't valid, there's nothing more to do
	 */
	if (!PTE_ISVALID(old_pte)) {
		if (pp != NULL)
			hm_exit(pp);
		return;
	}

	/*
	 * Take care of syncing any MOD/REF bits and removing the hment.
	 */
	if (pp != NULL) {
		if (!(flags & HAT_UNLOAD_NOSYNC))
			hati_sync_pte_to_page(pp, old_pte, l);
		hm = hment_remove(pp, ht, entry);
		hm_exit(pp);
		if (hm != NULL)
			hment_free(hm);
	}

	/*
	 * Handle book keeping in the htable and hat
	 */
	ASSERT(ht->ht_valid_cnt > 0);
	HTABLE_DEC(ht->ht_valid_cnt);
	PGCNT_DEC(hat, l);
}

/*
 * very cheap unload implementation to special case some kernel addresses
 */
static void
hat_kmap_unload(caddr_t addr, size_t len, uint_t flags)
{
	uintptr_t	va = (uintptr_t)addr;
	uintptr_t	eva = va + len;
	pgcnt_t		pg_index;
	htable_t	*ht;
	uint_t		entry;
	pte_t		*pte_ptr;
	pte_t		old_pte;

	for (; va < eva; va += MMU_PAGESIZE) {
		/*
		 * Get the PTE
		 */
		pg_index = mmu_btop(va - mmu.kmap_addr);
		pte_ptr = PT_INDEX_PTR(mmu.kmap_ptes, pg_index);
		old_pte = GET_PTE(pte_ptr);

		/*
		 * get the htable / entry
		 */
		ht = mmu.kmap_htables[(va - mmu.kmap_htables[0]->ht_vaddr)
		    >> LEVEL_SHIFT(1)];
		entry = htable_va2entry(va, ht);

		/*
		 * use mostly common code to unmap it.
		 */
		hat_pte_unmap(ht, entry, flags, old_pte, pte_ptr, B_TRUE);
	}
}


/*
 * unload a range of virtual address space (no callback)
 */
void
hat_unload(hat_t *hat, caddr_t addr, size_t len, uint_t flags)
{
	uintptr_t va = (uintptr_t)addr;

	ASSERT(hat == kas.a_hat || va + len <= _userlimit);

	/*
	 * special case for performance.
	 */
	if (mmu.kmap_addr <= va && va < mmu.kmap_eaddr) {
		ASSERT(hat == kas.a_hat);
		hat_kmap_unload(addr, len, flags);
	} else {
		hat_unload_callback(hat, addr, len, flags, NULL);
	}
}

/*
 * Do the callbacks for ranges being unloaded.
 */
typedef struct range_info {
	uintptr_t	rng_va;
	ulong_t		rng_cnt;
	level_t		rng_level;
} range_info_t;

/*
 * Invalidate the TLB, and perform the callback to the upper level VM system,
 * for the specified ranges of contiguous pages.
 */
static void
handle_ranges(hat_t *hat, hat_callback_t *cb, uint_t cnt, range_info_t *range)
{
	while (cnt > 0) {
		size_t len;

		--cnt;
		len = range[cnt].rng_cnt << LEVEL_SHIFT(range[cnt].rng_level);
		hat_tlb_inval_range(hat, (uintptr_t)range[cnt].rng_va, len);

		if (cb != NULL) {
			cb->hcb_start_addr = (caddr_t)range[cnt].rng_va;
			cb->hcb_end_addr = cb->hcb_start_addr;
			cb->hcb_end_addr += len;
			cb->hcb_function(cb);
		}
	}
}

/*
 * Unload a given range of addresses (has optional callback)
 *
 * Flags:
 * define	HAT_UNLOAD		0x00
 * define	HAT_UNLOAD_NOSYNC	0x02
 * define	HAT_UNLOAD_UNLOCK	0x04
 * define	HAT_UNLOAD_OTHER	0x08 - not used
 * define	HAT_UNLOAD_UNMAP	0x10 - same as HAT_UNLOAD
 */
#define	MAX_UNLOAD_CNT (8)
void
hat_unload_callback(
	hat_t		*hat,
	caddr_t		addr,
	size_t		len,
	uint_t		flags,
	hat_callback_t	*cb)
{
	uintptr_t	vaddr = (uintptr_t)addr;
	uintptr_t	eaddr = vaddr + len;
	htable_t	*ht = NULL;
	uint_t		entry;
	uintptr_t	contig_va = (uintptr_t)-1L;
	range_info_t	r[MAX_UNLOAD_CNT];
	uint_t		r_cnt = 0;
	pte_t		old_pte;

	ASSERT(hat == kas.a_hat || eaddr <= _userlimit);
	ASSERT(IS_PAGEALIGNED(vaddr));
	ASSERT(IS_PAGEALIGNED(eaddr));

	/*
	 * Special case a single page being unloaded for speed. This happens
	 * quite frequently, COW faults after a fork() for example.
	 */
	if (cb == NULL && len == MMU_PAGESIZE) {
		ht = htable_getpte(hat, vaddr, &entry, &old_pte, 0);
		if (ht != NULL) {
			if (PTE_ISVALID(old_pte)) {
				hat_pte_unmap(ht, entry, flags, old_pte,
				    NULL, B_TRUE);
			}
			htable_release(ht);
		}
		return;
	}

	while (vaddr < eaddr) {
		old_pte = htable_walk(hat, &ht, &vaddr, eaddr);
		if (ht == NULL)
			break;

		ASSERT(!IN_VA_HOLE(vaddr));

		if (vaddr < (uintptr_t)addr)
			panic("hat_unload_callback(): unmap inside large page");

		/*
		 * We'll do the call backs for contiguous ranges
		 */
		if (vaddr != contig_va ||
		    (r_cnt > 0 && r[r_cnt - 1].rng_level != ht->ht_level)) {
			if (r_cnt == MAX_UNLOAD_CNT) {
				handle_ranges(hat, cb, r_cnt, r);
				r_cnt = 0;
			}
			r[r_cnt].rng_va = vaddr;
			r[r_cnt].rng_cnt = 0;
			r[r_cnt].rng_level = ht->ht_level;
			++r_cnt;
		}

		/*
		 * Unload one mapping (for a single page) from the page tables.
		 * Note that we do not remove the mapping from the TLB yet,
		 * as indicated by the tlb=FALSE argument to hat_pte_unmap().
		 * handle_ranges() will clear the TLB entries with one call to
		 * hat_tlb_inval_range() per contiguous range.  This is
		 * safe because the page can not be reused until the
		 * callback is made (or we return).
		 */
		entry = htable_va2entry(vaddr, ht);
		hat_pte_unmap(ht, entry, flags, old_pte, NULL, B_FALSE);
		ASSERT(ht->ht_level <= MAX_PAGE_LEVEL);
		vaddr += LEVEL_SIZE(ht->ht_level);
		contig_va = vaddr;
		++r[r_cnt - 1].rng_cnt;
	}
	if (ht)
		htable_release(ht);

	/*
	 * handle last range for callbacks
	 */
	if (r_cnt > 0)
		handle_ranges(hat, cb, r_cnt, r);
}

/*
 * Invalidate a virtual address translation on a slave CPU during
 * panic() dumps.
 */
void
hat_flush_range(hat_t *hat, caddr_t va, size_t size)
{
	ssize_t sz;
	caddr_t endva = va + size;

	dsb(ish);
	while (va < endva) {
		sz = hat_getpagesize(hat, va);
		if (sz < 0) {
			tlbi_allis();
			break;
		}
		tlbi_mva((uintptr_t)va);
		va += sz;
	}
	dsb(ish);
	isb();
}

/*
 * synchronize mapping with software data structures
 *
 * This interface is currently only used by the working set monitor
 * driver.
 */
/*ARGSUSED*/
void
hat_sync(hat_t *hat, caddr_t addr, size_t len, uint_t flags)
{
	uintptr_t	vaddr = (uintptr_t)addr;
	uintptr_t	eaddr = vaddr + len;
	htable_t	*ht = NULL;
	uint_t		entry;
	pte_t	pte;
	pte_t	save_pte;
	pte_t	new;
	page_t		*pp;

	ASSERT(!IN_VA_HOLE(vaddr));
	ASSERT(IS_PAGEALIGNED(vaddr));
	ASSERT(IS_PAGEALIGNED(eaddr));
	ASSERT(hat == kas.a_hat || eaddr <= _userlimit);

	for (; vaddr < eaddr; vaddr += LEVEL_SIZE(ht->ht_level)) {
try_again:
		pte = htable_walk(hat, &ht, &vaddr, eaddr);
		if (ht == NULL)
			break;
		entry = htable_va2entry(vaddr, ht);

		if (PTE_GET(pte, PTE_SOFTWARE) >= PTE_NOSYNC ||
		    PTE_GET(pte, PTE_AF) == 0)
			continue;

		/*
		 * We need to acquire the mapping list lock to protect
		 * against hat_pageunload(), hat_unload(), etc.
		 */
		pp = page_numtopp_nolock(PTE2PFN(pte, ht->ht_level));
		if (pp == NULL)
			break;
		hm_enter(pp);
		save_pte = pte;
		pte = pte_get(ht, entry);
		if (pte != save_pte) {
			hm_exit(pp);
			goto try_again;
		}
		if (PTE_GET(pte, PTE_SOFTWARE) >= PTE_NOSYNC ||
		    PTE_GET(pte, PTE_AF) == 0) {
			hm_exit(pp);
			continue;
		}

		/*
		 * Need to clear ref or mod bits. We may compete with
		 * hardware updating the R/M bits and have to try again.
		 */
		if (flags == HAT_SYNC_ZERORM) {
			new = pte;
			PTE_CLR(new, PTE_AF);
			pte = hati_update_pte(ht, entry, pte, new);
			if (pte != 0) {
				hm_exit(pp);
				goto try_again;
			}
		} else {
			/*
			 * sync the PTE to the page_t
			 */
			hati_sync_pte_to_page(pp, save_pte, ht->ht_level);
		}
		hm_exit(pp);
	}
	if (ht)
		htable_release(ht);
}

/*
 * void	hat_map(hat, addr, len, flags)
 */
/*ARGSUSED*/
void
hat_map(hat_t *hat, caddr_t addr, size_t len, uint_t flags)
{
	/* does nothing */
}

/*
 * uint_t hat_getattr(hat, addr, *attr)
 *	returns attr for <hat,addr> in *attr.  returns 0 if there was a
 *	mapping and *attr is valid, nonzero if there was no mapping and
 *	*attr is not valid.
 */
uint_t
hat_getattr(hat_t *hat, caddr_t addr, uint_t *attr)
{
	uintptr_t	vaddr = ALIGN2PAGE(addr);
	htable_t	*ht = NULL;
	pte_t	pte;

	ASSERT(hat == kas.a_hat || vaddr <= _userlimit);

	if (IN_VA_HOLE(vaddr))
		return ((uint_t)-1);

	ht = htable_getpte(hat, vaddr, NULL, &pte, MAX_PAGE_LEVEL);
	if (ht == NULL)
		return ((uint_t)-1);

	if (!PTE_ISVALID(pte) || !PTE_ISPAGE(pte, ht->ht_level)) {
		htable_release(ht);
		return ((uint_t)-1);
	}

	*attr = PROT_READ;
	if (!PTE_GET(pte, PTE_AP_RO))
		*attr |= PROT_WRITE;
	if (PTE_GET(pte, PTE_AP_USER)) {
		*attr |= PROT_USER;
		if (!PTE_GET(pte, PTE_UXN))
			*attr |= PROT_EXEC;
	} else {
		if (!PTE_GET(pte, PTE_PXN))
			*attr |= PROT_EXEC;
	}
	if (PTE_GET(pte, PTE_SOFTWARE) >= PTE_NOSYNC)
		*attr |= HAT_NOSYNC;

	switch (PTE_GET(pte, PTE_ATTR_MASK)) {
	case PTE_ATTR_DEVICE:		*attr |= HAT_STRICTORDER;	break;
	case PTE_ATTR_UNORDERED:	*attr |= HAT_UNORDERED_OK;	break;
	case PTE_ATTR_NORMEM_UC:	*attr |= HAT_MERGING_OK;	break;
	case PTE_ATTR_NORMEM_WT:	*attr |= HAT_LOADCACHING_OK;	break;
	case PTE_ATTR_NORMEM:		*attr |= HAT_STORECACHING_OK;	break;
	default:
		panic("hat_getattr(): bad caching attributes: %llx\n",
		    PTE_GET(pte, PTE_ATTR_MASK));
	}

	htable_release(ht);
	return (0);
}

/*
 * hat_updateattr() applies the given attribute change to an existing mapping
 */
#define	HAT_LOAD_ATTR		1
#define	HAT_SET_ATTR		2
#define	HAT_CLR_ATTR		3
#define	HAT_CHG_PROT		4

static void
hat_updateattr(hat_t *hat, caddr_t addr, size_t len, uint_t attr, int what)
{
	uintptr_t	vaddr = (uintptr_t)addr;
	uintptr_t	eaddr = (uintptr_t)addr + len;
	htable_t	*ht = NULL;
	uint_t		entry;
	pte_t		oldpte, newpte;
	page_t		*pp;

	ASSERT(IS_PAGEALIGNED(vaddr));
	ASSERT(IS_PAGEALIGNED(eaddr));
	ASSERT(hat == kas.a_hat || AS_LOCK_HELD(hat->hat_as));
	for (; vaddr < eaddr; vaddr += LEVEL_SIZE(ht->ht_level)) {
try_again:
		oldpte = htable_walk(hat, &ht, &vaddr, eaddr);
		if (ht == NULL)
			break;
		if (PTE_GET(oldpte, PTE_SOFTWARE) >= PTE_NOCONSIST)
			continue;

		pp = page_numtopp_nolock(PTE2PFN(oldpte, ht->ht_level));
		if (pp == NULL)
			continue;
		hm_enter(pp);

		newpte = oldpte;
		/*
		 * We found a page table entry in the desired range,
		 * figure out the new attributes.
		 */
		switch (what) {
		case HAT_SET_ATTR:
			if (attr & PROT_WRITE)
				newpte &= ~PTE_AP_RO;
			if (attr & HAT_NOSYNC)
				newpte |= PTE_NOSYNC;
			if (attr & PROT_EXEC)
				newpte &= ~(PTE_GET(oldpte, PTE_AP_USER) ?
				    PTE_UXN : PTE_PXN);
			break;

		case HAT_LOAD_ATTR:
			if (attr & HAT_NOSYNC)
				newpte |= PTE_NOSYNC;
			else
				newpte &= ~PTE_SOFTWARE;

			// fall through
		case HAT_CHG_PROT:
			if (attr & PROT_WRITE)
				newpte &= ~PTE_AP_RO;
			else
				newpte |= PTE_AP_RO;
			newpte |= (PTE_GET(oldpte, PTE_AP_USER) ?
			    PTE_PXN : PTE_UXN);
			if (attr & PROT_EXEC)
				newpte &= ~(PTE_GET(oldpte, PTE_AP_USER) ?
				    PTE_UXN : PTE_PXN);
			else
				newpte |= (PTE_GET(oldpte, PTE_AP_USER) ?
				    PTE_UXN : PTE_PXN);
			break;

		case HAT_CLR_ATTR:
			if (attr & PROT_WRITE)
				newpte |= PTE_AP_RO;
			if (attr & HAT_NOSYNC)
				newpte &= ~PTE_SOFTWARE;
			if (attr & PROT_EXEC)
				newpte |= (PTE_GET(oldpte, PTE_AP_USER) ?
				    PTE_UXN : PTE_PXN);
			break;
		}

		/*
		 * Ensure NOSYNC/NOCONSIST mappings have REF and MOD set.
		 * pte_set() depends on this.
		 */
		if (PTE_GET(newpte, PTE_SOFTWARE) >= PTE_NOSYNC)
			newpte |= PTE_AF;

		/*
		 * what about PROT_READ or others? this code only handles:
		 * EXEC, WRITE, NOSYNC
		 */

		/*
		 * If new PTE really changed, update the table.
		 */
		if (newpte != oldpte) {
			entry = htable_va2entry(vaddr, ht);

			if ((newpte ^ oldpte) & (PTE_UXN | PTE_PXN)) {
				clean_dcache(hat_kpm_pfn2va((PTE2PFN(oldpte,
				    ht->ht_level))), LEVEL_SIZE(ht->ht_level));
			}

			oldpte = hati_update_pte(ht, entry, oldpte, newpte);
			if (oldpte != 0) {
				hm_exit(pp);
				goto try_again;
			}
		}
		hm_exit(pp);
	}
	if (ht)
		htable_release(ht);
}

/*
 * Various wrappers for hat_updateattr()
 */
void
hat_setattr(hat_t *hat, caddr_t addr, size_t len, uint_t attr)
{
	ASSERT(hat == kas.a_hat || (uintptr_t)addr + len <= _userlimit);
	hat_updateattr(hat, addr, len, attr, HAT_SET_ATTR);
}

void
hat_clrattr(hat_t *hat, caddr_t addr, size_t len, uint_t attr)
{
	ASSERT(hat == kas.a_hat || (uintptr_t)addr + len <= _userlimit);
	hat_updateattr(hat, addr, len, attr, HAT_CLR_ATTR);
}

void
hat_chgattr(hat_t *hat, caddr_t addr, size_t len, uint_t attr)
{
	ASSERT(hat == kas.a_hat || (uintptr_t)addr + len <= _userlimit);
	hat_updateattr(hat, addr, len, attr, HAT_LOAD_ATTR);
}

void
hat_chgprot(hat_t *hat, caddr_t addr, size_t len, uint_t vprot)
{
	ASSERT(hat == kas.a_hat || (uintptr_t)addr + len <= _userlimit);
	hat_updateattr(hat, addr, len, vprot & HAT_PROT_MASK, HAT_CHG_PROT);
}

/*
 * size_t hat_getpagesize(hat, addr)
 *	returns pagesize in bytes for <hat, addr>. returns -1 of there is
 *	no mapping. This is an advisory call.
 */
ssize_t
hat_getpagesize(hat_t *hat, caddr_t addr)
{
	uintptr_t	vaddr = ALIGN2PAGE(addr);
	htable_t	*ht;
	size_t		pagesize;

	ASSERT(hat == kas.a_hat || vaddr <= _userlimit);
	if (IN_VA_HOLE(vaddr))
		return (-1);
	ht = htable_getpage(hat, vaddr, NULL);
	if (ht == NULL)
		return (-1);
	pagesize = LEVEL_SIZE(ht->ht_level);
	htable_release(ht);
	return (pagesize);
}



/*
 * pfn_t hat_getpfnum(hat, addr)
 *	returns pfn for <hat, addr> or PFN_INVALID if mapping is invalid.
 */
pfn_t
hat_getpfnum(hat_t *hat, caddr_t addr)
{
	uintptr_t	vaddr = ALIGN2PAGE(addr);
	htable_t	*ht;
	uint_t		entry;
	pfn_t		pfn = PFN_INVALID;

	ASSERT(hat == kas.a_hat || vaddr <= _userlimit);
	if (khat_running == 0)
		return (PFN_INVALID);

	if (IN_VA_HOLE(vaddr))
		return (PFN_INVALID);

	/*
	 * A very common use of hat_getpfnum() is from the DDI for kernel pages.
	 * Use the kmap_ptes (which also covers the 32 bit heap) to speed
	 * this up.
	 */
	if (mmu.kmap_addr <= vaddr && vaddr < mmu.kmap_eaddr) {
		pte_t pte;
		pgcnt_t pg_index;

		pg_index = mmu_btop(vaddr - mmu.kmap_addr);
		pte = GET_PTE(PT_INDEX_PTR(mmu.kmap_ptes, pg_index));
		if (PTE_ISVALID(pte))
			/*LINTED [use of constant 0 causes a lint warning] */
			pfn = PTE2PFN(pte, 0);
		return (pfn);
	}

	ht = htable_getpage(hat, vaddr, &entry);
	if (ht == NULL) {
		return (PFN_INVALID);
	}
	ASSERT(vaddr >= ht->ht_vaddr);
	ASSERT(vaddr <= HTABLE_LAST_PAGE(ht));
	pfn = PTE2PFN(pte_get(ht, entry), ht->ht_level);
	if (ht->ht_level > 0)
		pfn += mmu_btop(vaddr & LEVEL_OFFSET(ht->ht_level));
	htable_release(ht);
	return (pfn);
}

/*
 * int hat_probe(hat, addr)
 *	return 0 if no valid mapping is present.  Faster version
 *	of hat_getattr in certain architectures.
 */
int
hat_probe(hat_t *hat, caddr_t addr)
{
	uintptr_t	vaddr = ALIGN2PAGE(addr);
	uint_t		entry;
	htable_t	*ht;
	pgcnt_t		pg_off;

	ASSERT(hat == kas.a_hat || vaddr <= _userlimit);
	ASSERT(hat == kas.a_hat || AS_LOCK_HELD(hat->hat_as));
	if (IN_VA_HOLE(vaddr))
		return (0);

	/*
	 * Most common use of hat_probe is from segmap. We special case it
	 * for performance.
	 */
	if (mmu.kmap_addr <= vaddr && vaddr < mmu.kmap_eaddr) {
		pg_off = mmu_btop(vaddr - mmu.kmap_addr);
		return (PTE_ISVALID(mmu.kmap_ptes[pg_off]));
	}

	ht = htable_getpage(hat, vaddr, &entry);
	htable_release(ht);
	return (ht != NULL);
}

/*
 * Find out if the segment for hat_share()/hat_unshare() is DISM or locked ISM.
 */
static int
is_it_dism(hat_t *hat, caddr_t va)
{
	struct seg *seg;
	struct shm_data *shmd;
	struct spt_data *sptd;

	seg = as_findseg(hat->hat_as, va, 0);
	ASSERT(seg != NULL);
	ASSERT(seg->s_base <= va);
	shmd = (struct shm_data *)seg->s_data;
	ASSERT(shmd != NULL);
	sptd = (struct spt_data *)shmd->shm_sptseg->s_data;
	ASSERT(sptd != NULL);
	if (sptd->spt_flags & SHM_PAGEABLE)
		return (1);
	return (0);
}

/*
 * Simple implementation of ISM. hat_share() is similar to hat_memload_array(),
 * except that we use the ism_hat's existing mappings to determine the pages
 * and protections to use for this hat. If we find a full properly aligned
 * and sized pagetable, we will attempt to share the pagetable itself.
 */
/*ARGSUSED*/
int
hat_share(
	hat_t		*hat,
	caddr_t		addr,
	hat_t		*ism_hat,
	caddr_t		src_addr,
	size_t		len,	/* almost useless value, see below.. */
	uint_t		ismszc)
{
	uintptr_t	vaddr_start = (uintptr_t)addr;
	uintptr_t	vaddr;
	uintptr_t	eaddr = vaddr_start + len;
	uintptr_t	ism_addr_start = (uintptr_t)src_addr;
	uintptr_t	ism_addr = ism_addr_start;
	uintptr_t	e_ism_addr = ism_addr + len;
	htable_t	*ism_ht = NULL;
	htable_t	*ht;
	pte_t		pte;
	page_t		*pp;
	pfn_t		pfn;
	level_t		l;
	pgcnt_t		pgcnt;
	uint_t		prot;
	int		is_dism;
	int		flags;

	/*
	 * We might be asked to share an empty DISM hat by as_dup()
	 */
	ASSERT(hat != kas.a_hat);
	ASSERT(eaddr <= _userlimit);
	if (!(ism_hat->hat_flags & HAT_SHARED)) {
		ASSERT(hat_get_mapped_size(ism_hat) == 0);
		return (0);
	}

	/*
	 * The SPT segment driver often passes us a size larger than there are
	 * valid mappings. That's because it rounds the segment size up to a
	 * large pagesize, even if the actual memory mapped by ism_hat is less.
	 */
	ASSERT(IS_PAGEALIGNED(vaddr_start));
	ASSERT(IS_PAGEALIGNED(ism_addr_start));
	ASSERT(ism_hat->hat_flags & HAT_SHARED);
	is_dism = is_it_dism(hat, addr);
	while (ism_addr < e_ism_addr) {
		/*
		 * use htable_walk to get the next valid ISM mapping
		 */
		pte = htable_walk(ism_hat, &ism_ht, &ism_addr, e_ism_addr);
		if (ism_ht == NULL)
			break;

		/*
		 * First check to see if we already share the page table.
		 */
		l = ism_ht->ht_level;
		vaddr = vaddr_start + (ism_addr - ism_addr_start);
		ht = htable_lookup(hat, vaddr, l);
		if (ht != NULL) {
			if (ht->ht_flags & HTABLE_SHARED_PFN)
				goto shared;
			htable_release(ht);
			goto not_shared;
		}

		/*
		 * Can't ever share top table.
		 */
		if (l == MAX_PAGE_LEVEL)
			goto not_shared;

		/*
		 * Avoid level mismatches later due to DISM faults.
		 */
		if (is_dism && l > 0)
			goto not_shared;

		/*
		 * addresses and lengths must align
		 * table must be fully populated
		 * no lower level page tables
		 */
		if (ism_addr != ism_ht->ht_vaddr ||
		    (vaddr & LEVEL_OFFSET(l + 1)) != 0)
			goto not_shared;

		/*
		 * The range of address space must cover a full table.
		 */
		if (e_ism_addr - ism_addr < LEVEL_SIZE(l + 1))
			goto not_shared;

		/*
		 * All entries in the ISM page table must be leaf PTEs.
		 */
		if (l > 0) {
			int e;

			/*
			 * We know the 0th is from htable_walk() above.
			 */
			for (e = 1; e < HTABLE_NUM_PTES(ism_ht); ++e) {
				pte_t pte;
				pte = pte_get(ism_ht, e);
				if (!PTE_ISPAGE(pte, l))
					goto not_shared;
			}
		}

		/*
		 * share the page table
		 */
		ht = htable_create(hat, vaddr, l, ism_ht);
shared:
		ASSERT(ht->ht_flags & HTABLE_SHARED_PFN);
		ASSERT(ht->ht_shares == ism_ht);
		hat->hat_ism_pgcnt +=
		    (ism_ht->ht_valid_cnt - ht->ht_valid_cnt) <<
		    (LEVEL_SHIFT(ht->ht_level) - MMU_PAGESHIFT);
		ht->ht_valid_cnt = ism_ht->ht_valid_cnt;
		htable_release(ht);
		ism_addr = ism_ht->ht_vaddr + LEVEL_SIZE(l + 1);
		htable_release(ism_ht);
		ism_ht = NULL;
		continue;

not_shared:
		/*
		 * Unable to share the page table. Instead we will
		 * create new mappings from the values in the ISM mappings.
		 * Figure out what level size mappings to use;
		 */
		for (l = ism_ht->ht_level; l > 0; --l) {
			if (LEVEL_SIZE(l) <= eaddr - vaddr &&
			    (vaddr & LEVEL_OFFSET(l)) == 0)
				break;
		}

		/*
		 * The ISM mapping might be larger than the share area,
		 * be careful to truncate it if needed.
		 */
		if (eaddr - vaddr >= LEVEL_SIZE(ism_ht->ht_level)) {
			pgcnt = mmu_btop(LEVEL_SIZE(ism_ht->ht_level));
		} else {
			pgcnt = mmu_btop(eaddr - vaddr);
			l = 0;
		}

		pfn = PTE2PFN(pte, ism_ht->ht_level);
		ASSERT(pfn != PFN_INVALID);
		while (pgcnt > 0) {
			/*
			 * Make a new pte for the PFN for this level.
			 * Copy protections for the pte from the ISM pte.
			 */
			pp = page_numtopp_nolock(pfn);
			ASSERT(pp != NULL);

			prot = PROT_USER | PROT_READ | HAT_STORECACHING_OK;
			if (!PTE_GET(pte, PTE_AP_RO))
				prot |= PROT_WRITE;
			if (PTE_GET(pte, PTE_AP_USER)) {
				if (!PTE_GET(pte, PTE_UXN))
					prot |= PROT_EXEC;
			} else {
				if (!PTE_GET(pte, PTE_PXN))
					prot |= PROT_EXEC;
			}

			flags = HAT_LOAD;
			if (!is_dism)
				flags |= HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST;
			while (hati_load_common(hat, vaddr, pp, prot, flags,
			    l, pfn) != 0) {
				if (l == 0)
					panic("hati_load_common() failure");
				--l;
			}

			vaddr += LEVEL_SIZE(l);
			ism_addr += LEVEL_SIZE(l);
			pfn += mmu_btop(LEVEL_SIZE(l));
			pgcnt -= mmu_btop(LEVEL_SIZE(l));
		}
	}
	if (ism_ht != NULL)
		htable_release(ism_ht);
	return (0);
}


/*
 * hat_unshare() is similar to hat_unload_callback(), but
 * we have to look for empty shared pagetables. Note that
 * hat_unshare() is always invoked against an entire segment.
 */
/*ARGSUSED*/
void
hat_unshare(hat_t *hat, caddr_t addr, size_t len, uint_t ismszc)
{
	uint64_t	vaddr = (uintptr_t)addr;
	uintptr_t	eaddr = vaddr + len;
	htable_t	*ht = NULL;
	uint_t		need_demaps = 0;
	int		flags = HAT_UNLOAD_UNMAP;
	level_t		l;

	ASSERT(hat != kas.a_hat);
	ASSERT(eaddr <= _userlimit);
	ASSERT(IS_PAGEALIGNED(vaddr));
	ASSERT(IS_PAGEALIGNED(eaddr));

	/*
	 * First go through and remove any shared pagetables.
	 *
	 * Note that it's ok to delay the TLB shootdown till the entire range is
	 * finished, because if hat_pageunload() were to unload a shared
	 * pagetable page, its hat_tlb_inval() will do a global TLB invalidate.
	 */
	l = MAX_PAGE_LEVEL;
	if (l == MAX_PAGE_LEVEL)
		--l;
	for (; l >= 0; --l) {
		for (vaddr = (uintptr_t)addr; vaddr < eaddr;
		    vaddr = (vaddr & LEVEL_MASK(l + 1)) + LEVEL_SIZE(l + 1)) {
			ASSERT(!IN_VA_HOLE(vaddr));
			/*
			 * find a pagetable that maps the current address
			 */
			ht = htable_lookup(hat, vaddr, l);
			if (ht == NULL)
				continue;
			if (ht->ht_flags & HTABLE_SHARED_PFN) {
				/*
				 * clear page count, set valid_cnt to 0,
				 * let htable_release() finish the job
				 */
				hat->hat_ism_pgcnt -= ht->ht_valid_cnt <<
				    (LEVEL_SHIFT(ht->ht_level) - MMU_PAGESHIFT);
				ht->ht_valid_cnt = 0;
				need_demaps = 1;
			}
			htable_release(ht);
		}
	}

	/*
	 * flush the TLBs - since we're probably dealing with MANY mappings
	 * we do just one CR3 reload.
	 */
	if (!(hat->hat_flags & HAT_FREEING) && need_demaps)
		hat_tlb_inval(hat, DEMAP_ALL_ADDR);

	/*
	 * Now go back and clean up any unaligned mappings that
	 * couldn't share pagetables.
	 */
	if (!is_it_dism(hat, addr))
		flags |= HAT_UNLOAD_UNLOCK;
	hat_unload(hat, addr, len, flags);
}


/*
 * hat_reserve() does nothing
 */
/*ARGSUSED*/
void
hat_reserve(struct as *as, caddr_t addr, size_t len)
{
}


/*
 * Called when all mappings to a page should have write permission removed.
 * Mostly stolen from hat_pagesync()
 */
static void
hati_page_clrwrt(struct page *pp)
{
	hment_t		*hm = NULL;
	htable_t	*ht;
	uint_t		entry;
	pte_t		old;
	pte_t		new;
	uint_t		pszc = 0;

next_size:
	/*
	 * walk thru the mapping list clearing write permission
	 */
	hm_enter(pp);
	while ((hm = hment_walk(pp, &ht, &entry, hm)) != NULL) {
		if (ht->ht_level < pszc)
			continue;
		old = pte_get(ht, entry);

		for (;;) {
			/*
			 * Is this mapping of interest?
			 */
			if (PTE2PFN(old, ht->ht_level) != pp->p_pagenum ||
			    PTE_GET(old, PTE_AP_RO))
				break;

			/*
			 * Clear ref/mod writable bits. This requires cross
			 * calls to ensure any executing TLBs see cleared bits.
			 */
			new = old;
			PTE_CLR(new, PTE_AF);
			PTE_SET(new, PTE_AP_RO);
			old = hati_update_pte(ht, entry, old, new);
			if (old != 0)
				continue;

			break;
		}
	}
	hm_exit(pp);
	while (pszc < pp->p_szc) {
		page_t *tpp;
		pszc++;
		tpp = PP_GROUPLEADER(pp, pszc);
		if (pp != tpp) {
			pp = tpp;
			goto next_size;
		}
	}
}

/*
 * void hat_page_setattr(pp, flag)
 * void hat_page_clrattr(pp, flag)
 *	used to set/clr ref/mod bits.
 */
void
hat_page_setattr(struct page *pp, uint_t flag)
{
	vnode_t		*vp = pp->p_vnode;
	kmutex_t	*vphm = NULL;
	page_t		**listp;
	int		noshuffle;

	noshuffle = flag & P_NSH;
	flag &= ~P_NSH;

	if (PP_GETRM(pp, flag) == flag)
		return;

	if ((flag & P_MOD) != 0 && vp != NULL && IS_VMODSORT(vp) &&
	    !noshuffle) {
		vphm = page_vnode_mutex(vp);
		mutex_enter(vphm);
	}

	PP_SETRM(pp, flag);

	if (vphm != NULL) {

		/*
		 * Some File Systems examine v_pages for NULL w/o
		 * grabbing the vphm mutex. Must not let it become NULL when
		 * pp is the only page on the list.
		 */
		if (pp->p_vpnext != pp) {
			page_vpsub(&vp->v_pages, pp);
			if (vp->v_pages != NULL)
				listp = &vp->v_pages->p_vpprev->p_vpnext;
			else
				listp = &vp->v_pages;
			page_vpadd(listp, pp);
		}
		mutex_exit(vphm);
	}
}

void
hat_page_clrattr(struct page *pp, uint_t flag)
{
	vnode_t		*vp = pp->p_vnode;
	ASSERT(!(flag & ~(P_MOD | P_REF | P_RO)));

	/*
	 * Caller is expected to hold page's io lock for VMODSORT to work
	 * correctly with pvn_vplist_dirty() and pvn_getdirty() when mod
	 * bit is cleared.
	 * We don't have assert to avoid tripping some existing third party
	 * code. The dirty page is moved back to top of the v_page list
	 * after IO is done in pvn_write_done().
	 */
	PP_CLRRM(pp, flag);

	if ((flag & P_MOD) != 0 && vp != NULL && IS_VMODSORT(vp)) {

		/*
		 * VMODSORT works by removing write permissions and getting
		 * a fault when a page is made dirty. At this point
		 * we need to remove write permission from all mappings
		 * to this page.
		 */
		hati_page_clrwrt(pp);
	}
}

/*
 *	If flag is specified, returns 0 if attribute is disabled
 *	and non zero if enabled.  If flag specifes multiple attributes
 *	then returns 0 if ALL attributes are disabled.  This is an advisory
 *	call.
 */
uint_t
hat_page_getattr(struct page *pp, uint_t flag)
{
	return (PP_GETRM(pp, flag));
}


/*
 * common code used by hat_pageunload() and hment_steal()
 */
hment_t *
hati_page_unmap(page_t *pp, htable_t *ht, uint_t entry)
{
	pte_t old_pte;
	pfn_t pfn = pp->p_pagenum;
	hment_t *hm;

	/*
	 * We need to acquire a hold on the htable in order to
	 * do the invalidate. We know the htable must exist, since
	 * unmap's don't release the htable until after removing any
	 * hment. Having hm_enter() keeps that from proceeding.
	 */
	htable_acquire(ht);

	/*
	 * Invalidate the PTE and remove the hment.
	 */
	old_pte = pte_inval(ht, entry, 0, NULL, B_TRUE);
	if (PTE2PFN(old_pte, ht->ht_level) != pfn) {
		panic("pte_inval() failure found PTE = " FMT_PTE
		    " pfn being unmapped is %lx ht=0x%lx entry=0x%x",
		    old_pte, pfn, (uintptr_t)ht, entry);
	}

	/*
	 * Clean up all the htable information for this mapping
	 */
	ASSERT(ht->ht_valid_cnt > 0);
	HTABLE_DEC(ht->ht_valid_cnt);
	PGCNT_DEC(ht->ht_hat, ht->ht_level);

	/*
	 * sync ref/mod bits to the page_t
	 */
	if (PTE_GET(old_pte, PTE_SOFTWARE) < PTE_NOSYNC)
		hati_sync_pte_to_page(pp, old_pte, ht->ht_level);

	/*
	 * Remove the mapping list entry for this page.
	 */
	hm = hment_remove(pp, ht, entry);

	/*
	 * drop the mapping list lock so that we might free the
	 * hment and htable.
	 */
	hm_exit(pp);
	htable_release(ht);
	return (hm);
}

extern int	vpm_enable;
/*
 * Unload all translations to a page. If the page is a subpage of a large
 * page, the large page mappings are also removed.
 *
 * The forceflags are unused.
 */

/*ARGSUSED*/
static int
hati_pageunload(struct page *pp, uint_t pg_szcd, uint_t forceflag)
{
	page_t		*cur_pp = pp;
	hment_t		*hm;
	hment_t		*prev;
	htable_t	*ht;
	uint_t		entry;
	level_t		level;

	/*
	 * prevent recursion due to kmem_free()
	 */
	++curthread->t_hatdepth;
	ASSERT(curthread->t_hatdepth < 16);

	/*
	 * clear the vpm ref.
	 */
	if (vpm_enable) {
		pp->p_vpmref = 0;
	}

	/*
	 * The loop with next_size handles pages with multiple pagesize mappings
	 */
next_size:
	for (;;) {

		/*
		 * Get a mapping list entry
		 */
		hm_enter(cur_pp);
		for (prev = NULL; ; prev = hm) {
			hm = hment_walk(cur_pp, &ht, &entry, prev);
			if (hm == NULL) {
				hm_exit(cur_pp);

				/*
				 * If not part of a larger page, we're done.
				 */
				if (cur_pp->p_szc <= pg_szcd) {
					ASSERT(curthread->t_hatdepth > 0);
					--curthread->t_hatdepth;
					return (0);
				}

				/*
				 * Else check the next larger page size.
				 * hat_page_demote() may decrease p_szc
				 * but that's ok we'll just take an extra
				 * trip discover there're no larger mappings
				 * and return.
				 */
				++pg_szcd;
				cur_pp = PP_GROUPLEADER(cur_pp, pg_szcd);
				goto next_size;
			}

			/*
			 * If this mapping size matches, remove it.
			 */
			level = ht->ht_level;
			if (level == pg_szcd)
				break;
		}

		/*
		 * Remove the mapping list entry for this page.
		 * Note this does the hm_exit() for us.
		 */
		hm = hati_page_unmap(cur_pp, ht, entry);
		if (hm != NULL)
			hment_free(hm);
	}
}

int
hat_pageunload(struct page *pp, uint_t forceflag)
{
	ASSERT(PAGE_EXCL(pp));
	return (hati_pageunload(pp, 0, forceflag));
}

/*
 * Unload all large mappings to pp and reduce by 1 p_szc field of every large
 * page level that included pp.
 *
 * pp must be locked EXCL. Even though no other constituent pages are locked
 * it's legal to unload large mappings to pp because all constituent pages of
 * large locked mappings have to be locked SHARED.  therefore if we have EXCL
 * lock on one of constituent pages none of the large mappings to pp are
 * locked.
 *
 * Change (always decrease) p_szc field starting from the last constituent
 * page and ending with root constituent page so that root's pszc always shows
 * the area where hat_page_demote() may be active.
 *
 * This mechanism is only used for file system pages where it's not always
 * possible to get EXCL locks on all constituent pages to demote the size code
 * (as is done for anonymous or kernel large pages).
 */
void
hat_page_demote(page_t *pp)
{
	uint_t		pszc;
	uint_t		rszc;
	uint_t		szc;
	page_t		*rootpp;
	page_t		*firstpp;
	page_t		*lastpp;
	pgcnt_t		pgcnt;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(!PP_ISFREE(pp));
	ASSERT(page_szc_lock_assert(pp));

	if (pp->p_szc == 0)
		return;

	rootpp = PP_GROUPLEADER(pp, 1);
	(void) hati_pageunload(rootpp, 1, HAT_FORCE_PGUNLOAD);

	/*
	 * all large mappings to pp are gone
	 * and no new can be setup since pp is locked exclusively.
	 *
	 * Lock the root to make sure there's only one hat_page_demote()
	 * outstanding within the area of this root's pszc.
	 *
	 * Second potential hat_page_demote() is already eliminated by upper
	 * VM layer via page_szc_lock() but we don't rely on it and use our
	 * own locking (so that upper layer locking can be changed without
	 * assumptions that hat depends on upper layer VM to prevent multiple
	 * hat_page_demote() to be issued simultaneously to the same large
	 * page).
	 */
again:
	pszc = pp->p_szc;
	if (pszc == 0)
		return;
	rootpp = PP_GROUPLEADER(pp, pszc);
	hm_enter(rootpp);
	/*
	 * If root's p_szc is different from pszc we raced with another
	 * hat_page_demote().  Drop the lock and try to find the root again.
	 * If root's p_szc is greater than pszc previous hat_page_demote() is
	 * not done yet.  Take and release mlist lock of root's root to wait
	 * for previous hat_page_demote() to complete.
	 */
	if ((rszc = rootpp->p_szc) != pszc) {
		hm_exit(rootpp);
		if (rszc > pszc) {
			/* p_szc of a locked non free page can't increase */
			ASSERT(pp != rootpp);

			rootpp = PP_GROUPLEADER(rootpp, rszc);
			hm_enter(rootpp);
			hm_exit(rootpp);
		}
		goto again;
	}
	ASSERT(pp->p_szc == pszc);

	/*
	 * Decrement by 1 p_szc of every constituent page of a region that
	 * covered pp. For example if original szc is 3 it gets changed to 2
	 * everywhere except in region 2 that covered pp. Region 2 that
	 * covered pp gets demoted to 1 everywhere except in region 1 that
	 * covered pp. The region 1 that covered pp is demoted to region
	 * 0. It's done this way because from region 3 we removed level 3
	 * mappings, from region 2 that covered pp we removed level 2 mappings
	 * and from region 1 that covered pp we removed level 1 mappings.  All
	 * changes are done from from high pfn's to low pfn's so that roots
	 * are changed last allowing one to know the largest region where
	 * hat_page_demote() is stil active by only looking at the root page.
	 *
	 * This algorithm is implemented in 2 while loops. First loop changes
	 * p_szc of pages to the right of pp's level 1 region and second
	 * loop changes p_szc of pages of level 1 region that covers pp
	 * and all pages to the left of level 1 region that covers pp.
	 * In the first loop p_szc keeps dropping with every iteration
	 * and in the second loop it keeps increasing with every iteration.
	 *
	 * First loop description: Demote pages to the right of pp outside of
	 * level 1 region that covers pp.  In every iteration of the while
	 * loop below find the last page of szc region and the first page of
	 * (szc - 1) region that is immediately to the right of (szc - 1)
	 * region that covers pp.  From last such page to first such page
	 * change every page's szc to szc - 1. Decrement szc and continue
	 * looping until szc is 1. If pp belongs to the last (szc - 1) region
	 * of szc region skip to the next iteration.
	 */
	szc = pszc;
	while (szc > 1) {
		lastpp = PP_GROUPLEADER(pp, szc);
		pgcnt = page_get_pagecnt(szc);
		lastpp += pgcnt - 1;
		firstpp = PP_GROUPLEADER(pp, (szc - 1));
		pgcnt = page_get_pagecnt(szc - 1);
		if (lastpp - firstpp < pgcnt) {
			szc--;
			continue;
		}
		firstpp += pgcnt;
		while (lastpp != firstpp) {
			ASSERT(lastpp->p_szc == pszc);
			lastpp->p_szc = szc - 1;
			lastpp--;
		}
		firstpp->p_szc = szc - 1;
		szc--;
	}

	/*
	 * Second loop description:
	 * First iteration changes p_szc to 0 of every
	 * page of level 1 region that covers pp.
	 * Subsequent iterations find last page of szc region
	 * immediately to the left of szc region that covered pp
	 * and first page of (szc + 1) region that covers pp.
	 * From last to first page change p_szc of every page to szc.
	 * Increment szc and continue looping until szc is pszc.
	 * If pp belongs to the fist szc region of (szc + 1) region
	 * skip to the next iteration.
	 *
	 */
	szc = 0;
	while (szc < pszc) {
		firstpp = PP_GROUPLEADER(pp, (szc + 1));
		if (szc == 0) {
			pgcnt = page_get_pagecnt(1);
			lastpp = firstpp + (pgcnt - 1);
		} else {
			lastpp = PP_GROUPLEADER(pp, szc);
			if (firstpp == lastpp) {
				szc++;
				continue;
			}
			lastpp--;
			pgcnt = page_get_pagecnt(szc);
		}
		while (lastpp != firstpp) {
			ASSERT(lastpp->p_szc == pszc);
			lastpp->p_szc = szc;
			lastpp--;
		}
		firstpp->p_szc = szc;
		if (firstpp == rootpp)
			break;
		szc++;
	}
	hm_exit(rootpp);
}

/*
 * get hw stats from hardware into page struct and reset hw stats
 * returns attributes of page
 * Flags for hat_pagesync, hat_getstat, hat_sync
 *
 * define	HAT_SYNC_ZERORM		0x01
 *
 * Additional flags for hat_pagesync
 *
 * define	HAT_SYNC_STOPON_REF	0x02
 * define	HAT_SYNC_STOPON_MOD	0x04
 * define	HAT_SYNC_STOPON_RM	0x06
 * define	HAT_SYNC_STOPON_SHARED	0x08
 */
uint_t
hat_pagesync(struct page *pp, uint_t flags)
{
	hment_t		*hm = NULL;
	htable_t	*ht;
	uint_t		entry;
	pte_t	old, save_old;
	pte_t	new;
	uchar_t		nrmbits = P_REF|P_MOD|P_RO;
	extern ulong_t	po_share;
	page_t		*save_pp = pp;
	uint_t		pszc = 0;

	ASSERT(PAGE_LOCKED(pp) || panicstr);

	if (PP_ISRO(pp) && (flags & HAT_SYNC_STOPON_MOD))
		return (pp->p_nrm & nrmbits);

	if ((flags & HAT_SYNC_ZERORM) == 0) {

		if ((flags & HAT_SYNC_STOPON_REF) != 0 && PP_ISREF(pp))
			return (pp->p_nrm & nrmbits);

		if ((flags & HAT_SYNC_STOPON_MOD) != 0 && PP_ISMOD(pp))
			return (pp->p_nrm & nrmbits);

		if ((flags & HAT_SYNC_STOPON_SHARED) != 0 &&
		    hat_page_getshare(pp) > po_share) {
			if (PP_ISRO(pp))
				PP_SETREF(pp);
			return (pp->p_nrm & nrmbits);
		}
	}

next_size:
	/*
	 * walk thru the mapping list syncing (and clearing) ref/mod bits.
	 */
	hm_enter(pp);
	while ((hm = hment_walk(pp, &ht, &entry, hm)) != NULL) {
		if (ht->ht_level < pszc)
			continue;
		old = pte_get(ht, entry);
try_again:

		ASSERT(PTE2PFN(old, ht->ht_level) == pp->p_pagenum);

		if (PTE_GET(old, PTE_AF) == 0)
			continue;

		save_old = old;
		if ((flags & HAT_SYNC_ZERORM) != 0) {

			/*
			 * Need to clear ref or mod bits. Need to demap
			 * to make sure any executing TLBs see cleared bits.
			 */
			new = old;
			PTE_CLR(new, PTE_AF);
			old = hati_update_pte(ht, entry, old, new);
			if (old != 0)
				goto try_again;

			old = save_old;
		}

		/*
		 * Sync the PTE
		 */
		if (!(flags & HAT_SYNC_ZERORM) &&
		    PTE_GET(old, PTE_SOFTWARE) <= PTE_NOSYNC)
			hati_sync_pte_to_page(pp, old, ht->ht_level);

		/*
		 * can stop short if we found a ref'd or mod'd page
		 */
		if ((flags & HAT_SYNC_STOPON_MOD) && PP_ISMOD(save_pp) ||
		    (flags & HAT_SYNC_STOPON_REF) && PP_ISREF(save_pp)) {
			hm_exit(pp);
			goto done;
		}
	}
	hm_exit(pp);
	while (pszc < pp->p_szc) {
		page_t *tpp;
		pszc++;
		tpp = PP_GROUPLEADER(pp, pszc);
		if (pp != tpp) {
			pp = tpp;
			goto next_size;
		}
	}
done:
	return (save_pp->p_nrm & nrmbits);
}

/*
 * returns approx number of mappings to this pp.  A return of 0 implies
 * there are no mappings to the page.
 */
ulong_t
hat_page_getshare(page_t *pp)
{
	uint_t cnt;
	cnt = hment_mapcnt(pp);
	if (vpm_enable && pp->p_vpmref) {
		cnt += 1;
	}
	return (cnt);
}

/*
 * Return 1 the number of mappings exceeds sh_thresh. Return 0
 * otherwise.
 */
int
hat_page_checkshare(page_t *pp, ulong_t sh_thresh)
{
	return (hat_page_getshare(pp) > sh_thresh);
}

/*
 * hat_softlock isn't supported anymore
 */
/*ARGSUSED*/
faultcode_t
hat_softlock(
	hat_t *hat,
	caddr_t addr,
	size_t *len,
	struct page **page_array,
	uint_t flags)
{
	return (FC_NOSUPPORT);
}



/*
 * Routine to expose supported HAT features to platform independent code.
 */
/*ARGSUSED*/
int
hat_supported(enum hat_features feature, void *arg)
{
	switch (feature) {

	case HAT_SHARED_PT:	/* this is really ISM */
		return (1);

	case HAT_DYNAMIC_ISM_UNMAP:
		return (0);

	case HAT_VMODSORT:
		return (1);

	case HAT_SHARED_REGIONS:
		return (0);

	default:
		panic("hat_supported() - unknown feature");
	}
	return (0);
}

/*
 * Called when a thread is exiting and has been switched to the kernel AS
 */
void
hat_thread_exit(kthread_t *thd)
{
	ASSERT(thd->t_procp->p_as == &kas);
	hat_switch(thd->t_procp->p_as->a_hat);
}

/*
 * Setup the given brand new hat structure as the new HAT on this cpu's mmu.
 */
/*ARGSUSED*/
void
hat_setup(hat_t *hat, int flags)
{
	kpreempt_disable();

	hat_switch(hat);

	kpreempt_enable();
}

/*
 * Hat locking functions
 * XXX - these two functions are currently being used by hatstats
 *	they can be removed by using a per-as mutex for hatstats.
 */
void
hat_enter(hat_t *hat)
{
	mutex_enter(&hat->hat_mutex);
}

void
hat_exit(hat_t *hat)
{
	mutex_exit(&hat->hat_mutex);
}

/*
 * Function called after all CPUs are brought online.
 * Used to remove low address boot mappings.
 */
void
clear_boot_mappings(uintptr_t low, uintptr_t high)
{
}

/*
 * Atomically update a new translation for a single page.  If the
 * currently installed PTE doesn't match the value we expect to find,
 * it's not updated and we return the PTE we found.
 *
 * If activating nosync or NOWRITE and the page was modified we need to sync
 * with the page_t. Also sync with page_t if clearing ref/mod bits.
 */
static pte_t
hati_update_pte(htable_t *ht, uint_t entry, pte_t expected, pte_t new)
{
	page_t		*pp;
	uint_t		rm = 0;
	pte_t		replaced;

	if (PTE_GET(expected, PTE_SOFTWARE) < PTE_NOSYNC &&
	    PTE_GET(expected, PTE_AF) &&
	    (PTE_GET(new, PTE_NOSYNC) || PTE_GET(new, PTE_AP_RO) ||
	    !PTE_GET(new, PTE_AF))) {

		pp = page_numtopp_nolock(PTE2PFN(expected, ht->ht_level));
		ASSERT(pp != NULL);

		switch (PTE_GET(expected, PTE_AF | PTE_AP_RO)) {
		case PTE_AF:
			rm |= (P_REF | P_MOD);
			break;
		case PTE_AF | PTE_AP_RO:
			rm |= P_REF;
			break;
		default:
			break;
		}
		PTE_CLR(new, PTE_AF);
	}

	replaced = pte_update(ht, entry, expected, new);
	if (replaced != expected)
		return (replaced);

	if (rm) {
		/*
		 * sync to all constituent pages of a large page
		 */
		pgcnt_t pgcnt = page_get_pagecnt(ht->ht_level);
		ASSERT(IS_P2ALIGNED(pp->p_pagenum, pgcnt));
		while (pgcnt-- > 0) {
			/*
			 * hat_page_demote() can't decrease
			 * pszc below this mapping size
			 * since large mapping existed after we
			 * took mlist lock.
			 */
			ASSERT(pp->p_szc >= ht->ht_level);
			hat_page_setattr(pp, rm);
			++pp;
		}
	}

	return (0);
}

/* ARGSUSED */
void
hat_join_srd(struct hat *hat, vnode_t *evp)
{
}

/* ARGSUSED */
hat_region_cookie_t
hat_join_region(struct hat *hat,
    caddr_t r_saddr,
    size_t r_size,
    void *r_obj,
    u_offset_t r_objoff,
    uchar_t r_perm,
    uchar_t r_pgszc,
    hat_rgn_cb_func_t r_cb_function,
    uint_t flags)
{
	panic("No shared region support on aarch64");
	return (HAT_INVALID_REGION_COOKIE);
}

/* ARGSUSED */
void
hat_leave_region(struct hat *hat, hat_region_cookie_t rcookie, uint_t flags)
{
	panic("No shared region support on aarch64");
}

/* ARGSUSED */
void
hat_dup_region(struct hat *hat, hat_region_cookie_t rcookie)
{
	panic("No shared region support on aarch64");
}


int
hat_page_fault(hat_t *hat, caddr_t vaddr)
{
	int rv = -1;
	vaddr = (caddr_t)((uintptr_t)vaddr & ~(MMU_PAGESIZE - 1));
	for (;;) {
		uint_t entry;
		pte_t oldpte;
		htable_t *ht = htable_getpte(hat, (uintptr_t)vaddr, &entry,
		    &oldpte, MAX_PAGE_LEVEL);
		if (ht == NULL)
			break;

		if (!PTE_ISVALID(oldpte)) {
			htable_release(ht);
			break;
		}
		if (PTE_GET(oldpte, PTE_SOFTWARE) >= PTE_NOSYNC) {
			htable_release(ht);
			break;
		}
		if (PTE_GET(oldpte, PTE_AF) == 0) {
			page_t *pp = page_numtopp_nolock(PTE2PFN(oldpte,
			    ht->ht_level));
			if (pp == NULL) {
				htable_release(ht);
				break;
			}

			hm_enter(pp);

			pte_t newpte = pte_get(ht, entry);

			if (newpte != oldpte) {
				hm_exit(pp);
				htable_release(ht);
				continue;
			}

			PTE_SET(newpte, PTE_AF);
			pte_update(ht, entry, oldpte, newpte);

			hm_exit(pp);
		}
		htable_release(ht);
		rv = 0;
		break;
	}

	return (rv);
}
