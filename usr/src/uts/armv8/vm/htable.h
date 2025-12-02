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
 * Copyright (c) 2014 by Delphix. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef _VM_HTABLE_H
#define	_VM_HTABLE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Each hardware page table has an htable_t describing it.
 *
 * We use a reference counter mechanism to detect when we can free an htable.
 * In the implmentation the reference count is split into 2 separate counters:
 *
 *	ht_busy is a traditional reference count of uses of the htable pointer
 *
 *	ht_valid_cnt is a count of how references are implied by valid PTE/PTP
 *	         entries in the pagetable
 *
 * ht_busy is only incremented by htable_lookup() or htable_create()
 * while holding the appropriate hash_table mutex. While installing a new
 * valid PTE or PTP, in order to increment ht_valid_cnt a thread must have
 * done an htable_lookup() or htable_create() but not the htable_release yet.
 *
 * htable_release(), while holding the mutex, can know that if
 * busy == 1 and valid_cnt == 0, the htable can be free'd.
 *
 * The fields have been ordered to make htable_lookup() fast. Hence,
 * ht_hat, ht_vaddr, ht_level and ht_next need to be clustered together.
 */
struct htable {
	struct htable	*ht_next;	/* forward link for hash table */
	struct hat	*ht_hat;	/* hat this mapping comes from */
	uintptr_t	ht_vaddr;	/* virt addr at start of this table */
	int8_t		ht_level;	/* page table level: 0=4K, 1=2M, ... */
	uint8_t		ht_flags;	/* see below */
	int16_t		ht_busy;	/* implements locking protocol */
	int16_t		ht_valid_cnt;	/* # of valid entries in this table */
	uint32_t	ht_lock_cnt;	/* # of locked entries in this table */
					/* never used for kernel hat */
	pfn_t		ht_pfn;
	struct htable	*ht_prev;	/* backward link for hash table */
	struct htable	*ht_parent;	/* htable that points to this htable */
	struct htable	*ht_shares;	/* for HTABLE_SHARED_PFN only */
};
typedef struct htable htable_t;

/*
 * Flags values for htable ht_flags field:
 *
 * HTABLE_SHARED_PFN - this htable had its PFN assigned from sharing another
 *	htable. Used by hat_share() for ISM.
 */
#define	HTABLE_SHARED_PFN	(0x01)

/*
 * The htable hash table hashing function.  The 28 is so that high
 * order bits are include in the hash index to skew the wrap
 * around of addresses. Even though the hash buckets are stored per
 * hat we include the value of hat pointer in the hash function so
 * that the secondary hash for the htable mutex winds up begin different in
 * every address space.
 */
#define	HTABLE_NUM_HASH	(MMU_PAGESIZE / sizeof (htable_t *))
#define	HTABLE_HASH(hat, va, lvl)					\
	((((va) >> LEVEL_SHIFT(1)) + ((va) >> 28) + (lvl) +		\
	((uintptr_t)(hat) >> 4)) & (HTABLE_NUM_HASH - 1))

/*
 * Compute the last page aligned VA mapped by an htable.
 *
 * Given a va and a level, compute the virtual address of the start of the
 * next page at that level.
 *
 * XX64 - The check for the VA hole needs to be better generalized.
 */
#define	HTABLE_NUM_PTES(ht)	NPTEPERPT

#define	HTABLE_LAST_PAGE(ht)			\
	((ht)->ht_vaddr - MMU_PAGESIZE +	\
	((uintptr_t)HTABLE_NUM_PTES(ht) * LEVEL_SIZE((ht)->ht_level)))

#define	NEXT_ENTRY_VA(va, l)	((va & LEVEL_MASK(l)) + LEVEL_SIZE(l))

#if defined(_KERNEL)

extern void htable_init(void);
extern htable_t *htable_lookup(struct hat *hat, uintptr_t vaddr, level_t level);
extern htable_t *htable_create(struct hat *hat, uintptr_t vaddr, level_t level,
    htable_t *shared);
extern void htable_acquire(htable_t *);
extern void htable_release(htable_t *ht);
extern void htable_destroy(htable_t *ht);
extern void htable_purge_hat(struct hat *hat);
extern htable_t *htable_getpte(struct hat *, uintptr_t, uint_t *, pte_t *,
    level_t);
extern htable_t *htable_getpage(struct hat *hat, uintptr_t va, uint_t *entry);
extern void htable_initial_reserve(uint_t);
extern void htable_reserve(uint_t);
extern void htable_adjust_reserve(void);
extern size_t htable_mapped(struct hat *);
extern void htable_attach(struct hat *, uintptr_t, level_t, struct htable *,
    pfn_t);
extern pte_t htable_walk(struct hat *hat, htable_t **ht, uintptr_t *va,
    uintptr_t eaddr);

#define	HTABLE_WALK_TO_END ((uintptr_t)-1)

extern uint_t htable_va2entry(uintptr_t va, htable_t *ht);
extern uintptr_t htable_e2va(htable_t *ht, uint_t entry);
extern pte_t pte_get(htable_t *, uint_t entry);

#define	LPAGE_ERROR (-(pte_t)1)
extern pte_t pte_set(htable_t *, uint_t entry, pte_t new, void *);
extern pte_t pte_inval(htable_t *ht, uint_t entry, pte_t old, pte_t *ptr,
    boolean_t tlb);
extern pte_t pte_update(htable_t *ht, uint_t entry, pte_t old, pte_t new);
extern void pte_copy(htable_t *src, htable_t *dest, uint_t entry, uint_t cnt);

#define	HTABLE_INC(x)		atomic_inc_16((uint16_t *)&x)
#define	HTABLE_DEC(x)		atomic_dec_16((uint16_t *)&x)
#define	HTABLE_LOCK_INC(ht)	atomic_inc_32(&(ht)->ht_lock_cnt)
#define	HTABLE_LOCK_DEC(ht)	atomic_dec_32(&(ht)->ht_lock_cnt)

#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HTABLE_H */
