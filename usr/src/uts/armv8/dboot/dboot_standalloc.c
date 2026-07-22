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
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/systm.h>
#include <sys/pte.h>
#include <sys/machparam.h>
#include <sys/memlist.h>
#include <sys/efi.h>
#include <sys/bootinfo.h>
#include <sys/controlregs.h>
#include <sys/cpuid.h>
#include <sys/sysmacros.h>
#include <sys/int_fmtio.h>
#include <sys/bootinfo.h>
#include <sys/framebuffer.h>
#include <sys/efifb.h>

#include <vm/hat_pte.h>
#include <vm/hat_aarch64.h>

#include "saio.h"
#include "dboot.h"
#include "dboot_printf.h"

extern void kmem_init(void);
extern void map_phys(pte_t pte_attr, uintptr_t vaddr,
    uint64_t paddr, size_t bytes);
extern uint64_t memlist_get(uint64_t size, int align, struct memlist **listp);

extern struct efi_map_header *efi_map_header;
extern struct memlist *pfreelistp;
extern caddr_t memlistpage;
extern caddr_t _BootScratch;
extern caddr_t _BootScratchEnd;

extern void init_physmem(void);

static caddr_t scratch_used_top;

static pte_t *ptbl_low;
static pte_t *ptbl_high;

static void init_pt(void);

#if 0
static void dump_tables(uint64_t tab, uint64_t va_offset);
#endif

void
init_memory(void)
{
	kmem_init();
	init_pt();
}

void
init_memlists(void)
{
	scratch_used_top = _BootScratch;
	memlistpage = scratch_used_top;
	scratch_used_top += MMU_PAGESIZE;

	init_physmem();
}

/* Page Table Initialization */
static void
init_pt(void)
{
	uint64_t fbaddr;
	uintptr_t paddr;
	struct memlist *ml;
	extern struct xboot_info *bi;

	fbaddr = 0;
	if (bi != NULL && bi->bi_framebuffer != 0) {
		boot_framebuffer_t *bfb =
		    (boot_framebuffer_t *)bi->bi_framebuffer;
		if (bfb->framebuffer != 0) {
			struct efi_fb *fb = (struct efi_fb *)bfb->framebuffer;
			fbaddr = RNDDN(fb->fb_addr, MMU_PAGESIZE);
		}
	}

	if ((paddr = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE, &pfreelistp)) == 0)
		panic("phy alloc error for lower top-level PT\n");
	memset((void *)paddr, 0, MMU_PAGESIZE);
	ptbl_low = (pte_t *)paddr;

	if ((paddr = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE, &pfreelistp)) == 0)
		panic("phy alloc error for upper top-level PT\n");
	memset((void *)paddr, 0, MMU_PAGESIZE);
	ptbl_high = (pte_t *)paddr;

	/*
	 * Memory that can be normally mapped. This is a subset of physical
	 * memory and removes the reserved, firmware code and firmware data
	 * spans.  Mapped executable at EL1 because we don't know the real
	 * needs.
	 */
	for (ml = pmappablep; ml != NULL; ml = ml->ml_next) {
		uint_t ng = 0;

		if (!IS_KERNEL_MAPPING(ml->ml_address))
			ng = PTE_NG;

		map_phys(PTE_UXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KRWUNA|PTE_ATTR_NORMEM|ng,
		    ml->ml_address,
		    ml->ml_address, ml->ml_size);
	}

	/*
	 * Memory reserved by UEFI is mapped as read-only.
	 *
	 * Under U-Boot this nominally includes the FDT, but loader copies
	 * the FDT to read/write memory to apply fixups, then passes the
	 * fixed FDT. Note that this memory is reclaimable, so `unix` creates
	 * another copy of the FDT once the kernel memory subsystem is up and
	 * before boot scratch memory is reclaimed.
	 */
	for (ml = prsvdlistp; ml != NULL; ml = ml->ml_next) {
		map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KROUNA|PTE_ATTR_NORMEM,
		    ml->ml_address,
		    ml->ml_address, ml->ml_size);
	}

	/*
	 * Firmware code is mapped to the lower address space as executable
	 * by privileged modes.
	 *
	 * This memory will be appropriately mapped in via an address space
	 * when calling UEFI runtime services.
	 */
	for (ml = pfwcodelistp; ml != NULL; ml = ml->ml_next) {
		map_phys(PTE_UXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KRWUNA|PTE_ATTR_NORMEM,
		    ml->ml_address,
		    ml->ml_address, ml->ml_size);
	}

	/*
	 * Firmware data is mapped to the lower address space as read/write.
	 *
	 * This memory will be appropriately mapped in via an address space
	 * when calling UEFI runtime services.
	 */
	for (ml = pfwdatalistp; ml != NULL; ml = ml->ml_next) {
		map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KRWUNA|PTE_ATTR_NORMEM,
		    ml->ml_address,
		    ml->ml_address, ml->ml_size);
	}

	for (ml = pldriolistp; ml != NULL; ml = ml->ml_next) {
		uint_t ng = 0;
		if (!IS_KERNEL_MAPPING(ml->ml_address))
			ng = PTE_NG;

		if (fbaddr != 0 && ml->ml_address == fbaddr) {
			/* XXXARM: we need a proper write-combining mapping */
			map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_SH_INNER|
			    PTE_AP_KRWUNA|PTE_ATTR_UNORDERED|ng,
			    ml->ml_address,
			    ml->ml_address, ml->ml_size);
		} else {
			map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_SH_INNER|
			    PTE_AP_KRWUNA|PTE_ATTR_DEVICE|ng,
			    ml->ml_address,
			    ml->ml_address, ml->ml_size);
		}
	}

	uint64_t mair = ((MAIR_ATTR_nGnRnE    << (MAIR_STRONG_ORDER * 8)) |
	    (MAIR_ATTR_nGnRE	<< (MAIR_DEVICE * 8)) |
	    (MAIR_ATTR_IWB_OWB	<< (MAIR_NORMAL_MEMORY * 8)) |
	    (MAIR_ATTR_IWT_OWT	<< (MAIR_NORMAL_MEMORY_WT * 8)) |
	    (MAIR_ATTR_INC_ONC	<< (MAIR_NORMAL_MEMORY_UC * 8)) |
	    (MAIR_ATTR_nGRE	<< (MAIR_UNORDERED * 8)));

	/*
	 * Enable 16-bit ASIDs if the hardware supports them.  This
	 * dramatically reduces the frequency of ASID epoch rollovers
	 * (65534 usable ASIDs vs 254 with 8-bit).
	 * ID_AA64MMFR0_EL1.ASIDBits == 0x2 means 16-bit ASIDs.
	 */
	uint64_t mmfr0 = read_id_aa64mmfr0();

	uint64_t tcr =
	    ((uint64_t)MMFR0_PARANGE(mmfr0) << TCR_IPS_SHIFT) |
	    TCR_TG1_4K | TCR_SH1_ISH | TCR_ORGN1_WBWA | TCR_IRGN1_WBWA |
	    TCR_T1SZ_256T | TCR_TG0_4K | TCR_SH0_ISH | TCR_ORGN0_WBWA |
	    TCR_IRGN0_WBWA | TCR_T0SZ_256T |
	    (MMFR0_ASIDBITS(mmfr0) >= 0x2 ? TCR_AS : 0);

	uint64_t sctlr = SCTLR_EL1_RES1 | SCTLR_EL1_UCI | SCTLR_EL1_UCT |
	    SCTLR_EL1_DZE | SCTLR_EL1_I | SCTLR_EL1_C | SCTLR_EL1_M;

	write_mair(mair);
	write_tcr(tcr);
	write_ttbr0((uint64_t)ptbl_low);
	write_ttbr1((uint64_t)ptbl_high);
	isb();

#if 0
	if (debug) {
		dboot_printf("Lower Memory Tables\n");
		dump_tables((uint64_t)ptbl_low, 0);
		dboot_printf("Upper Memory Tables\n");
		dump_tables((uint64_t)ptbl_high, HOLE_END);
	}
#endif

	tlbi_allis();
	dsb(ish);
	isb();

	dsb(ish);
	write_sctlr(sctlr);
	isb();
}

static paddr_t
alloc_pagetable_page(uint_t lvl)
{
	paddr_t pa;
	if ((pa = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE, &pfreelistp)) == 0)
		panic("page table alloc error for level %d\n", lvl);
	memset((void *)(uintptr_t)pa, 0, MMU_PAGESIZE);
	return (pa);
}

#define	DBOOT_ASSERT(EX) \
	((void)((EX) || (panic("%s:%d: %s: assertion failed: %s\n", \
	    __FILE__, __LINE__, __func__, #EX), 0)))

static void
map_pages(pte_t pte_attr, uintptr_t vaddr, uint64_t paddr, int level)
{
	DBOOT_ASSERT(IS_PAGEALIGNED(vaddr));
	DBOOT_ASSERT(IS_PAGEALIGNED(paddr));

	pte_t *ptbl = IS_KERNEL_MAPPING(vaddr) ? ptbl_high : ptbl_low;

	/* XXX: Needs to be dynamic, and match the choice in the kernel */
	for (int l = MMU_PAGE_LEVELS - 1; l > level; l--) {
		/* Need a new entry */
		if (!PTE_ISVALID(ptbl[LEVEL_INDEX(vaddr, l)])) {
			paddr_t pa = alloc_pagetable_page(l);

			/* XXX: MAKEPTE(...) */
			ptbl[LEVEL_INDEX(vaddr, l)] = pa |
			    PTE_TABLE_UXNT | PTE_TABLE_APT_NOUSER |
			    PTE_TABLE;
			dsb(ish);
			isb();
		} else if (!PTE_ISTABLE(ptbl[LEVEL_INDEX(vaddr, l)], l)) {
			panic("overlapping %s allocation for 0x%lx at "
			    "level %d (needed a table)\n", __func__, vaddr, l);
		}

		ptbl = (pte_t *)PTE2ADDR(ptbl[LEVEL_INDEX(vaddr, l)], l);
	}

	/* XXX: MAKEPTE */
	uint_t type = (level == 0) ? PTE_PAGE : PTE_BLOCK;
	pte_t newpte = paddr | pte_attr | type;

	if (PTE_ISVALID(ptbl[LEVEL_INDEX(vaddr, level)]) &&
	    !PTE_EQUIV(ptbl[LEVEL_INDEX(vaddr, level)], newpte)) {
		panic("overlapping %s allocation for 0x%lx at level %d\n"
		    "(old %lx new %lx), they are not equivalent\n",
		    __func__, vaddr, level,
		    ptbl[LEVEL_INDEX(vaddr, level)],
		    newpte);
	}

	ptbl[LEVEL_INDEX(vaddr, level)] = newpte;
	dsb(ish);
	isb();
}

void
map_phys(pte_t pte_attr, uintptr_t vaddr, uint64_t paddr, size_t bytes)
{
	if (!IS_P2ALIGNED(vaddr, MMU_PAGESIZE)) {
		panic("map_phys invalid vaddr\n");
	}

	if (!IS_P2ALIGNED(paddr, MMU_PAGESIZE)) {
		panic("map_phys invalid paddr\n");
	}

	if (!IS_P2ALIGNED(bytes, MMU_PAGESIZE)) {
		panic("map_phys invalid size\n");
	}

	while (bytes >= MMU_PAGESIZE) {
		int l = 0;

		/* find the largest page size */
		for (l = MMU_PAGE_LEVELS - 1; l > 0; l--) {
			if (((paddr & LEVEL_OFFSET(l)) == 0) &&
			    ((vaddr & LEVEL_OFFSET(l)) == 0) &&
			    bytes >= LEVEL_SIZE(l))
				break;
		}

		map_pages(pte_attr, vaddr, paddr, l);
		bytes -= LEVEL_SIZE(l);
		vaddr += LEVEL_SIZE(l);
		paddr += LEVEL_SIZE(l);
	}
	DBOOT_ASSERT(bytes == 0);
}

static caddr_t
get_low_vpage(size_t bytes)
{
	caddr_t v;

	if ((scratch_used_top + bytes) <= _BootScratchEnd) {
		v = scratch_used_top;
		scratch_used_top += bytes;
		return (v);
	}

	return (NULL);
}

caddr_t
resalloc(enum RESOURCES type, size_t bytes, caddr_t virthint, int align)
{
	caddr_t	vaddr = 0;
	uintptr_t paddr = 0;

	if (bytes != 0) {
		/* extend request to fill a page */
		bytes = roundup(bytes, MMU_PAGESIZE);
		dprintf("resalloc:  bytes = %lu\n", bytes);
		switch (type) {
		case RES_BOOTSCRATCH:
			vaddr = get_low_vpage(bytes);
			break;
		case RES_CHILDVIRT:
			vaddr = virthint;

			while (bytes >= MMU_PAGESIZE) {
				int l = 0;
				uintptr_t va = (uintptr_t)virthint;

				/*
				 * find the largest page size that fits the
				 * address and size, the physical address is
				 * constrained when we allocate it.
				 */
				for (l = MMU_PAGE_LEVELS - 1; l > 0; l--) {
					if (((paddr & LEVEL_OFFSET(l)) == 0) &&
					    ((va & LEVEL_OFFSET(l)) == 0) &&
					    bytes >= LEVEL_SIZE(l))
						break;
				}

				paddr = memlist_get(LEVEL_SIZE(l),
				    LEVEL_SIZE(l), &pfreelistp);
				if (paddr == 0) {
					panic("couldn't allocate %ld bytes "
					    "of physmem\n", LEVEL_SIZE(l));
				}

				map_pages(PTE_AF | PTE_SH_INNER | PTE_UXN |
				    PTE_AP_KRWUNA | PTE_ATTR_NORMEM, va, paddr,
				    l);
				bytes -= LEVEL_SIZE(l);
				virthint += LEVEL_SIZE(l);
			}
			DBOOT_ASSERT(bytes == 0);
			break;
		default:
			panic("Bad resource type\n");
			break;
		}
	}

	return (vaddr);
}

void
reset_alloc(void)
{
}

void
resfree(enum RESOURCES type, caddr_t virtaddr, size_t size)
{
}

#if 0
static void
dump_tables(uint64_t tab, uint64_t va_offset)
{
	uint_t shift_amt[] = {12, 21, 30, 39};
	uint_t save_index[4];   /* for recursion */
	char *save_table[4];    /* for recursion */
	uint_t top_level = 3;
	uint_t ptes_per_table = 512;
	uint_t  l;
	uint64_t va;
	uint64_t pgsize;
	int index;
	int i;
	pte_t pteval;
	char *table;
	static char *tablist = "\t\t\t";
	char *tabs = tablist + 3 - top_level;
	paddr_t pa, pa1;

	table = (char *)(uintptr_t)tab;
	l = top_level;
	va = va_offset;

	for (index = 0; index < ptes_per_table; ++index) {
		pgsize = 1ull << shift_amt[l];
		pteval = ((pte_t *)table)[index];
		if (!PTE_ISVALID(pteval))
			goto next_entry;

		dboot_printf("%s [L%u] 0x%p[%u] = 0x%" PRIx64 ", va=0x%" PRIx64,
		    tabs + l, l, (void *)table, index, (uint64_t)pteval, va);
		pa = pteval & PTE_PFN_MASK;
		if (PTE_ISPAGE(pteval, l)) {
			dboot_printf(" physaddr=0x%" PRIx64 "\n", pa);
		} else {
			dboot_printf(" => 0x%" PRIx64 "\n", pa);
		}

		if (PTE_ISTABLE(pteval, l)) {
			save_table[l] = table;
			save_index[l] = index;
			--l;
			index = -1;
			table = (char *)(uintptr_t)(pteval & PTE_PFN_MASK);
			goto recursion;
		}

		/*
		 * shorten dump for consecutive mappings
		 */
		for (i = 1; index + i < ptes_per_table; ++i) {
			pteval = ((pte_t *)table)[index + i];
			if (!PTE_ISVALID(pteval))
				break;
			pa1 = (pteval & PTE_PFN_MASK);
			if (pa1 != pa + (i * pgsize))
				break;
		}

		if (i > 2) {
			dboot_printf("%s...\n", tabs + l);
			va += pgsize * (i - 2);
			index += i - 2;
		}
next_entry:
		va += pgsize;
recursion:
		;
	}

	if (l < top_level) {
		++l;
		index = save_index[l];
		table = save_table[l];
		goto recursion;
	}
}
#endif
