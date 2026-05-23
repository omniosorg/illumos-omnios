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
 * Copyright 2025 Richard Lowe
 * Portions Copyright 2022 Oxide Computer Company
 */

/*
 * Commands dealing with the VMSAv8-64 compatible memory management unit
 */

#include <sys/controlregs.h>
#include <sys/debug.h>
#include <sys/machparam.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <vm/as.h>
#include <vm/hat_aarch64.h>

#include <stdbool.h>

#include <mdb/mdb_err.h>
#include <mdb/mdb_modapi.h>

#include "mmu.h"

struct hat_mmu_info mmu;

static inline uint64_t
takebits(uint64_t reg, uint_t high, uint_t low)
{
	uint64_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 64);
	ASSERT3U(low, <, 64);

	mask = ((1ULL << (high - low + 1)) - 1ULL) << low;
	return (reg & mask);
}

void
init_mmu(void)
{
	if (mmu.num_level != 0)
		return;

	if (mdb_readsym(&mmu, sizeof (mmu), "mmu") == -1)
		mdb_warn("Can't use HAT information before mmu_init()\n");
}

int
pte_table(uintptr_t addr, uint_t level)
{
	mdb_printf("pte=%lx table addr=%p level=%d", addr,
	    takebits(addr, 47, MMU_PAGESHIFT), level);

	if (addr & PTE_TABLE_NST)
		mdb_printf(", non-secure");

	if ((addr & PTE_TABLE_APT_RO) && (addr & PTE_TABLE_APT_NOUSER))
		mdb_printf(", ap=ro,nouser");
	else if (addr & PTE_TABLE_APT_RO)
		mdb_printf(", ap=ro");
	else if (addr & PTE_TABLE_APT_NOUSER)
		mdb_printf(", ap=nouser");

	if (addr & PTE_TABLE_UXNT)
		mdb_printf(", uxn");
	if (addr & PTE_TABLE_PXNT)
		mdb_printf(", pxn");
	if (addr & PTE_TABLE_PROTECTED)
		mdb_printf(", protected");
	if (addr & PTE_AF)
		mdb_printf(", af");

	mdb_printf("\n");
	return (DCMD_OK);
}

static int
pte_page_block(uintptr_t addr, uint_t level)
{
	const char *type = NULL;

	if (((addr & PTE_TYPE_MASK) == PTE_BLOCK)) {
		if (level == 0) {
			mdb_warn("block descriptors are invalid at level 0\n");
			/* Decode the rest of it anyway, in case it helps */
		}
		type = "block";
	} else {
		type = "page";
	}

	mdb_printf("pte=%lx %s addr=%p level=%d size=%H", addr, type,
	    takebits(addr, 47, MMU_PAGESHIFT), level, LEVEL_SIZE(level));

	if (addr & PTE_NOSYNC)
		mdb_printf(", nosync");
	if (addr & PTE_NOCONSIST)
		mdb_printf(", noconsist");
	if (addr & PTE_UXN)
		mdb_printf(", uxn");
	if (addr & PTE_PXN)
		mdb_printf(", pxn");
	if (addr & PTE_CONTIG_HINT)
		mdb_printf(", contig");
	if (addr & PTE_DBM)
		mdb_printf(", dbm");
	if (addr & PTE_GP)
		mdb_printf(", guarded");
	if ((addr & PTE_nT) && ((addr & PTE_TYPE_MASK) == PTE_BLOCK))
		mdb_printf(", nT");
	if (addr & PTE_NG)
		mdb_printf(", ng");
	if (addr & PTE_AF)
		mdb_printf(", af");

	switch (addr & PTE_SH_MASK) {
	case PTE_SH_INNER:
		mdb_printf(", sh=inner");
		break;
	case PTE_SH_OUTER:
		mdb_printf(", sh=outer");
		break;
	case PTE_SH_NONSHARE:
		mdb_printf(", sh=none");
		break;
	default:
		mdb_printf(", sh=0x%x", addr & PTE_SH_MASK);
		break;
	}

	if ((addr & PTE_AP_USER) && (addr & PTE_AP_RO))
		mdb_printf(", ap=ro,user");
	else if (addr & PTE_AP_USER)
		mdb_printf(", ap=user");
	else if (addr & PTE_AP_RO)
		mdb_printf(", ap=ro");

	switch (addr & PTE_ATTR_MASK) {
	case PTE_ATTR_STRONG:
		mdb_printf(", attr=strong");
		break;
	case PTE_ATTR_DEVICE:
		mdb_printf(", attr=device");
		break;
	case PTE_ATTR_NORMEM:
		mdb_printf(", attr=normem");
		break;
	case PTE_ATTR_NORMEM_WT:
		mdb_printf(", attr=writethru");
		break;
	case PTE_ATTR_NORMEM_UC:
		mdb_printf(", attr=uncached");
		break;
	case PTE_ATTR_UNORDERED:
		mdb_printf(", attr=unordered");
		break;
	default:
		mdb_warn("unknown pte attribute index\n");
		mdb_printf(", attr=%x",
		    (addr & PTE_ATTR_MASK) >> PTE_ATTR_SHIFT);
	}
	mdb_printf("\n");

	return (DCMD_OK);
}

/*
 * Note that level here is in the illumos sense, where level 0 is the deepest,
 * smallest, page size.  This is unfortunately the opposite to the order ARM
 * refer to things.
 *
 * Also, for future purposes, this won't work for VMSAv9-128, because mdb
 * lacks 128bit literals.
 */
int
pte_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t level = 0;

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'l', MDB_OPT_UINT64, &level, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (level > mmu.max_level) {
		mdb_warn("invalid level %lu, max is %lu\n", level,
		    mmu.max_level);
		return (DCMD_ERR);
	}

	/*
	 * Note the level check is necessary as page and table share the same
	 * encoding.  I'm sure there's a reason it's not page and block that
	 * share, given they share everything else.
	 */
	if (!PTE_ISVALID(addr)) {
		mdb_printf("invalid %p\n", addr);
		return (DCMD_OK);
	} else if (PTE_ISPAGE(addr, level)) {
		return (pte_page_block(addr, level));
	} else if (PTE_ISTABLE(addr, level)) {
		return (pte_table(addr, level));
	} else {
		mdb_warn("impossible pte type: %d\n", addr & PTE_TYPE_MASK);
		return (DCMD_ERR);
	}

	/* Unreachable */
	return (DCMD_ERR);
}

int
ptable_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t level = 0;
	bool opt_v = false;
	bool opt_r = false;
	bool opt_R = false;

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("missing page table (physical) address");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'l', MDB_OPT_UINT64, &level,
	    'v', MDB_OPT_SETBITS, 1, &opt_v,
	    'r', MDB_OPT_SETBITS, 1, &opt_r,
	    'R', MDB_OPT_SETBITS, 1, &opt_R,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (level > mmu.max_level) {
		mdb_warn("invalid level %lu, max is %lu\n", level,
		    mmu.max_level);
		return (DCMD_ERR);
	}

	/* We have as many PTEs as fit on a page in the current granule */
	for (int i = 0; i < MMU_PAGESIZE / sizeof (pte_t); i++) {
		uint64_t pte = 0;

		if (mdb_pread(&pte, sizeof (pte),
		    addr + (i * sizeof (pte))) != sizeof (pte)) {
			mdb_warn("failed to read page table entry");
			return (DCMD_ERR);
		}

		if ((pte == 0) && (opt_v == 0))
			continue;

		if (opt_r) {
			mdb_printf("[%x]\t%lx\n", i, pte);
		} else {
			mdb_arg_t v[] = {
				{ MDB_TYPE_STRING, { "-l" } },
				{ MDB_TYPE_IMMEDIATE, { .a_val = level } }
			};
			mdb_printf("[%x] ", i);
			mdb_call_dcmd("unix`pte", pte, DCMD_ADDRSPEC,
			    ARRAY_SIZE(v), v);

			if (opt_R && PTE_ISTABLE(pte, level)) {
				mdb_arg_t rv[] = {
					{ MDB_TYPE_STRING, { "-R" } },
					{ MDB_TYPE_STRING, { "-l" } },
					{ MDB_TYPE_IMMEDIATE,
					    { .a_val = level - 1} }
				};

				mdb_inc_indent(4);
				mdb_call_dcmd("unix`ptable",
				    takebits(pte, 47, MMU_PAGESHIFT),
				    DCMD_ADDRSPEC, ARRAY_SIZE(rv), rv);
				mdb_dec_indent(4);
			}
		}

	}

	return (DCMD_OK);
}

int
vatopa(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	struct as as;
	struct hat hat;
	struct htable htable;
	uintptr_t asaddr = 0;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_UINT64, &asaddr, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (asaddr == 0) {	/* Default is the kernel address space */
		if (mdb_readsym(&as, sizeof (struct as), "kas") !=
		    sizeof (struct as)) {
			mdb_warn("couldn't read kernel address space (kas)");
			return (DCMD_ERR);
		}
	} else {
		if (mdb_vread(&as, sizeof (as), asaddr) != sizeof (as)) {
			mdb_warn("couldn't read address space from %p", asaddr);
			return (DCMD_ERR);
		}
	}

	if (mdb_vread(&hat, sizeof (hat),
	    (uintptr_t)as.a_hat) != sizeof (hat)) {
		mdb_warn("failed to read hardware address translations");
		return (DCMD_ERR);
	}

	if (mdb_vread(&htable, sizeof (htable),
	    (uintptr_t)hat.hat_htable) != sizeof (htable)) {
		mdb_warn("failed to read hardware address translations");
		return (DCMD_ERR);
	}

	uintptr_t next_table = mmu_ptob(htable.ht_pfn);

	for (int i = mmu.max_level; i >= 0; i--) {
		uint_t idx = LEVEL_INDEX(addr, i);

		pte_t pte;
		if (mdb_pread(&pte, sizeof (pte),
		    next_table + (idx * sizeof (pte))) != sizeof (pte)) {
			mdb_warn("couldn't read page table entry at %p+%x",
			    next_table, idx);
			return (DCMD_ERR);
		}

		mdb_arg_t v[] = {
			{ MDB_TYPE_STRING, { "-l" } },
			{ MDB_TYPE_IMMEDIATE, { .a_val = i } }
		};

		if (!(flags & DCMD_PIPE_OUT)) {
			mdb_printf("[%p+%x] ", next_table, idx);
			mdb_call_dcmd("unix`pte", pte, DCMD_ADDRSPEC,
			    ARRAY_SIZE(v), v);
		}

		if (PTE_ISTABLE(pte, i)) {
			next_table = takebits(pte, 47, MMU_PAGESHIFT);
			continue;
		} else if (PTE_ISPAGE(pte, i)) {
			mdb_printf("%p\n",
			    takebits(pte, 47, LEVEL_SHIFT(i)) |
			    (addr & LEVEL_OFFSET(i)));
			break;
		} else {
			mdb_printf("not mapped");
			break;
		}
	}

	return (DCMD_OK);
}

/*
 * It is important that this interrogates the HAT and MMU, and not the entire
 * virtual memory subsystem (even though the reverse mappings in the VM make
 * it much faster and easier).  We are specifically looking for hardware
 * reality, not what the VM subsystem believes to be true.
 */
static int
patova_cb(uintptr_t addr, const void *data, void *cbdata)
{
	uintptr_t target = (uintptr_t)cbdata;
	htable_t htable;

	if (mdb_vread(&htable, sizeof (htable), addr) != sizeof (htable)) {
		mdb_warn("failed to read htable: %p", addr);
		return (WALK_ERR);
	}

	uintptr_t pfnpa = mmu_ptob(htable.ht_pfn);
	uintptr_t offset = target & ~LEVEL_MASK(htable.ht_level);

	for (int i = 0; i < MMU_PAGESIZE / sizeof (pte_t); i++) {
		uintptr_t pteaddr = (uintptr_t)PT_INDEX_PTR(pfnpa, i);
		pte_t pte;

		if (mdb_pread(&pte, sizeof (pte), pteaddr) != sizeof (pte_t)) {
			mdb_warn("failed to read pte: %lx", pteaddr);
			return (WALK_ERR);
		}

		if (!PTE_ISPAGE(pte, htable.ht_level)) {
			continue;
		}

		uintptr_t pfnmaps = pte & PTE_PFN_MASK;

		if ((target >= pfnmaps) &&
		    (target < (pfnmaps + LEVEL_SIZE(htable.ht_level)))) {
			mdb_printf("%p\n",
			    htable.ht_vaddr +
			    (i << LEVEL_SHIFT(htable.ht_level)) +
			    offset);
		}
	}

	return (WALK_NEXT);
}

int
patova(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("missing physical address\n");
		return (DCMD_USAGE);
	}

	struct as as;
	uintptr_t asaddr = 0;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_UINT64, &asaddr, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (asaddr == 0) {	/* Default is the kernel address space */
		if (mdb_readsym(&as, sizeof (as), "kas") != sizeof (as)) {
			mdb_warn("couldn't read kernel address space (kas)");
			return (DCMD_ERR);
		}
	} else {
		if (mdb_vread(&as, sizeof (as), asaddr) != sizeof (as)) {
			mdb_warn("couldn't read address space from %p", asaddr);
			return (DCMD_ERR);
		}
	}

	return (mdb_pwalk("htables", patova_cb, (void *)addr,
	    (uintptr_t)as.a_hat));
}
