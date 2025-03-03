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

#include "saio.h"
#include "dboot.h"
#include "dboot_printf.h"

extern void kmem_init(void);
extern void map_phys(pte_t pte_attr, caddr_t vaddr,
    uint64_t paddr, size_t bytes);
extern uint64_t memlist_get(uint64_t size, int align, struct memlist **listp);

#define	IS_KERNEL_MAPPING(__va)	(((uint64_t)(__va)) & (1UL << 55))

extern struct efi_map_header *efi_map_header;
extern struct memlist *pfreelistp;
extern caddr_t memlistpage;
extern caddr_t _BootScratch;
extern caddr_t _BootScratchEnd;

extern void init_physmem(void);

static caddr_t scratch_used_top;
static pte_t *l1_ptbl0;
static pte_t *l1_ptbl1;

static void init_pt(void);
static void dump_tables(uint64_t tab, uint64_t va_offset);

static inline int
l1_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT + 3 * NPTESHIFT)) &
	    ((1 << NPTESHIFT) - 1));
}

static inline int
l2_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT + 2 * NPTESHIFT)) &
	    ((1 << NPTESHIFT) - 1));
}

static inline int
l3_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT + 1 * NPTESHIFT)) &
	    ((1 << NPTESHIFT) - 1));
}

static inline int
l4_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT)) & ((1 << NPTESHIFT) - 1));
}


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
	uintptr_t pa;
	uintptr_t sz;
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
		panic("phy alloc error for L1 PT\n");
	memset((void *)paddr, 0, MMU_PAGESIZE);
	l1_ptbl0 = (pte_t *)paddr;

	if ((paddr = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE, &pfreelistp)) == 0)
		panic("phy alloc error for L1 PT\n");
	memset((void *)paddr, 0, MMU_PAGESIZE);
	l1_ptbl1 = (pte_t *)paddr;

	/*
	 * Memory that can be normally mapped. This is a subset of physical
	 * memory and removes the reserved, firmware code and firmware data
	 * spans.
	 *
	 * This memory is mapped to both the lower address space and the
	 * segkpm region. When in the lower region, it's marked as executable,
	 * since we just don't know at this point. When in segkpm it's simply
	 * marked as read/write.
	 */
	for (ml = pmappablep; ml != NULL; ml = ml->ml_next) {
		map_phys(PTE_UXN|PTE_AF|PTE_NG|PTE_SH_INNER|
		    PTE_AP_KRWUNA|PTE_ATTR_NORMEM,
		    (caddr_t)ml->ml_address,
		    ml->ml_address, ml->ml_size);
		map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_NG|PTE_SH_INNER|
		    PTE_AP_KRWUNA|PTE_ATTR_NORMEM,
		    (caddr_t)(ml->ml_address + SEGKPM_BASE),
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
		    (caddr_t)ml->ml_address,
		    ml->ml_address, ml->ml_size);
		map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KROUNA|PTE_ATTR_NORMEM,
		    (caddr_t)(ml->ml_address + SEGKPM_BASE),
		    ml->ml_address, ml->ml_size);
	}

	/*
	 * Firmware code is mapped to the lower address space as executable
	 * by privileged modes and to the segkpm region as read-only.
	 *
	 * This memory will be appropriately mapped in via an address space
	 * when calling UEFI runtime services.
	 */
	for (ml = pfwcodelistp; ml != NULL; ml = ml->ml_next) {
		map_phys(PTE_UXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KRWUNA|PTE_ATTR_NORMEM,
		    (caddr_t)ml->ml_address,
		    ml->ml_address, ml->ml_size);
		map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KROUNA|PTE_ATTR_NORMEM,
		    (caddr_t)(ml->ml_address + SEGKPM_BASE),
		    ml->ml_address, ml->ml_size);
	}

	/*
	 * Firmware data is mapped to the lower address space as read/write
	 * and to the segkpm region as read-only.
	 *
	 * This memory will be appropriately mapped in via an address space
	 * when calling UEFI runtime services.
	 */
	for (ml = pfwdatalistp; ml != NULL; ml = ml->ml_next) {
		map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KRWUNA|PTE_ATTR_NORMEM,
		    (caddr_t)ml->ml_address,
		    ml->ml_address, ml->ml_size);
		map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_SH_INNER|
		    PTE_AP_KROUNA|PTE_ATTR_NORMEM,
		    (caddr_t)(ml->ml_address + SEGKPM_BASE),
		    ml->ml_address, ml->ml_size);
	}

	/*
	 * We do not create device mappings in segkpm. That's for physical
	 * memory only.
	 */
	for (ml = pldriolistp; ml != NULL; ml = ml->ml_next) {
		if (fbaddr != 0 && ml->ml_address == fbaddr) {
			/* XXXARM: we need a proper write-combining mapping */
			map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_NG|PTE_SH_INNER|
			    PTE_AP_KRWUNA|PTE_ATTR_UNORDERED,
			    (caddr_t)ml->ml_address,
			    ml->ml_address, ml->ml_size);
			continue;
		}

		map_phys(PTE_UXN|PTE_PXN|PTE_AF|PTE_NG|PTE_SH_INNER|
		    PTE_AP_KRWUNA|PTE_ATTR_DEVICE,
		    (caddr_t)ml->ml_address,
		    ml->ml_address, ml->ml_size);
	}

	uint64_t mair = ((MAIR_ATTR_nGnRnE    << (MAIR_STRONG_ORDER * 8)) |
	    (MAIR_ATTR_nGnRE	<< (MAIR_DEVICE * 8)) |
	    (MAIR_ATTR_IWB_OWB	<< (MAIR_NORMAL_MEMORY * 8)) |
	    (MAIR_ATTR_IWT_OWT	<< (MAIR_NORMAL_MEMORY_WT * 8)) |
	    (MAIR_ATTR_INC_ONC	<< (MAIR_NORMAL_MEMORY_UC * 8)) |
	    (MAIR_ATTR_nGRE	<< (MAIR_UNORDERED * 8)));

	uint64_t tcr =
	    ((uint64_t)MMFR0_PARANGE(read_id_aa64mmfr0()) << TCR_IPS_SHIFT) |
	    TCR_TG1_4K | TCR_SH1_ISH | TCR_ORGN1_WBWA | TCR_IRGN1_WBWA |
	    TCR_T1SZ_256T | TCR_TG0_4K | TCR_SH0_ISH | TCR_ORGN0_WBWA |
	    TCR_IRGN0_WBWA | TCR_T0SZ_256T;

	uint64_t sctlr = SCTLR_EL1_RES1 | SCTLR_EL1_UCI | SCTLR_EL1_UCT |
	    SCTLR_EL1_DZE | SCTLR_EL1_I | SCTLR_EL1_C | SCTLR_EL1_M;

	write_mair(mair);
	write_tcr(tcr);
	write_ttbr0((uint64_t)l1_ptbl0);
	write_ttbr1((uint64_t)l1_ptbl1);
	isb();

#if 0
	if (debug) {
		dboot_printf("Lower Memory Tables\n");
		dump_tables((uint64_t)l1_ptbl0, 0);
		dboot_printf("Upper Memory Tables\n");
		dump_tables((uint64_t)l1_ptbl1, SEGKPM_BASE);
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
alloc_pagetable_page(const char *lvl)
{
	paddr_t pa;
	if ((pa = memlist_get(MMU_PAGESIZE, MMU_PAGESIZE, &pfreelistp)) == 0)
		panic("phy alloc error for %s PT\n", lvl);
	memset((void *)(uintptr_t)pa, 0, MMU_PAGESIZE);
	return (pa);
}

static void
map_pages(pte_t pte_attr, caddr_t vaddr, uint64_t paddr, size_t bytes)
{
	int l1_idx = l1_pteidx(vaddr);
	int l2_idx = l2_pteidx(vaddr);
	int l3_idx = l3_pteidx(vaddr);
	int l4_idx = l4_pteidx(vaddr);

	pte_t *l1_ptbl = IS_KERNEL_MAPPING(vaddr) ? l1_ptbl1 : l1_ptbl0;

	if ((l1_ptbl[l1_idx] & PTE_TYPE_MASK) == 0)
		l1_ptbl[l1_idx] = PTE_TABLE_APT_NOUSER|PTE_TABLE_UXNT|
		    PTE_TABLE|alloc_pagetable_page("L1");
	if ((l1_ptbl[l1_idx] & PTE_VALID) == 0)
		panic("invalid L1 PT\n");

	pte_t *l2_ptbl = (pte_t *)(uintptr_t)(l1_ptbl[l1_idx] & PTE_PFN_MASK);

	if (bytes == MMU_PAGESIZE1G) {
		if ((uintptr_t)vaddr & (MMU_PAGESIZE1G - 1))
			panic("invalid vaddr slignment (1G)\n");
		if (paddr & (MMU_PAGESIZE1G - 1))
			panic("invalid paddr slignment (1G)\n");
		if (l2_ptbl[l2_idx] & PTE_VALID)
			panic("invalid L2 PT\n");
		l2_ptbl[l2_idx] = paddr|pte_attr|PTE_BLOCK;
		dsb(ish);
		return;
	}

	if ((l2_ptbl[l2_idx] & PTE_TYPE_MASK) == 0)
		l2_ptbl[l2_idx] = PTE_TABLE_APT_NOUSER|PTE_TABLE_UXNT|
		    PTE_TABLE|alloc_pagetable_page("L2");
	if ((l2_ptbl[l2_idx] & PTE_TYPE_MASK) != PTE_TABLE)
		panic("invalid L2 PT\n");

	pte_t *l3_ptbl = (pte_t *)(uintptr_t)(l2_ptbl[l2_idx] & PTE_PFN_MASK);

	if (bytes == MMU_PAGESIZE2M) {
		if ((uintptr_t)vaddr & (MMU_PAGESIZE2M - 1))
			panic("invalid vaddr alignment (2M)\n");
		if (paddr & (MMU_PAGESIZE2M - 1))
			panic("invalid paddr alignment (2M)\n");
		if (l3_ptbl[l3_idx] & PTE_VALID)
			panic("invalid L3 PT\n");
		l3_ptbl[l3_idx] = paddr|pte_attr|PTE_BLOCK;
		dsb(ish);
		return;
	}

	if ((l3_ptbl[l3_idx] & PTE_TYPE_MASK) == 0)
		l3_ptbl[l3_idx] = PTE_TABLE_APT_NOUSER|PTE_TABLE_UXNT|
		    PTE_TABLE|alloc_pagetable_page("L3");
	if ((l3_ptbl[l3_idx] & PTE_TYPE_MASK) != PTE_TABLE)
		panic("invalid L3 PT\n");

	pte_t *l4_ptbl = (pte_t *)(uintptr_t)(l3_ptbl[l3_idx] & PTE_PFN_MASK);
	if (bytes == MMU_PAGESIZE) {
		if ((uintptr_t)vaddr & (MMU_PAGESIZE - 1))
			panic("invalid vaddr alignment (4K)\n");
		if (paddr & (MMU_PAGESIZE - 1))
			panic("invalid paddr alignment (4K)\n");
		if (l4_ptbl[l4_idx] & PTE_VALID)
			panic("invalid L4 PT\n");
		l4_ptbl[l4_idx] = paddr|pte_attr|PTE_PAGE;
		dsb(ish);
		return;
	}

	panic("invalid size\n");
}

void
map_phys(pte_t pte_attr, caddr_t vaddr, uint64_t paddr, size_t bytes)
{
	if (((uintptr_t)vaddr % MMU_PAGESIZE) != 0) {
		panic("map_phys invalid vaddr\n");
	}
	if ((paddr % MMU_PAGESIZE) != 0) {
		panic("map_phys invalid paddr\n");
	}
	if ((bytes % MMU_PAGESIZE) != 0) {
		panic("map_phys invalid size\n");
	}

	while (bytes) {
		uintptr_t va = (uintptr_t)vaddr;
		size_t maxalign = va & (-va);
		size_t mapsz;

		/*
		 * XXXARM: These calculations are terribly suspicious
		 */
		if (maxalign >= MMU_PAGESIZE1G && bytes >= MMU_PAGESIZE1G &&
		    paddr >= MMU_PAGESIZE1G) {
			mapsz = MMU_PAGESIZE1G;
		} else if (maxalign >= MMU_PAGESIZE2M &&
		    bytes >= MMU_PAGESIZE2M && paddr >= MMU_PAGESIZE2M) {
			mapsz = MMU_PAGESIZE2M;
		} else {
			mapsz = MMU_PAGESIZE;
		}

		map_pages(pte_attr, vaddr, paddr, mapsz);
		bytes -= mapsz;
		vaddr += mapsz;
		paddr += mapsz;
	}
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
			while (bytes) {
				uintptr_t va = (uintptr_t)virthint;
				size_t maxalign = va & (-va);
				size_t mapsz;
				if (maxalign >= MMU_PAGESIZE1G &&
				    bytes >= MMU_PAGESIZE1G) {
					mapsz = MMU_PAGESIZE1G;
				} else if (maxalign >= MMU_PAGESIZE2M &&
				    bytes >= MMU_PAGESIZE2M) {
					mapsz = MMU_PAGESIZE2M;
				} else {
					mapsz = MMU_PAGESIZE;
				}
				paddr = memlist_get(mapsz, mapsz, &pfreelistp);
				if (paddr == 0) {
					panic("phys mem allocate error\n");
				}
				map_phys(PTE_AF | PTE_SH_INNER | PTE_AP_KRWUNA |
				    PTE_ATTR_NORMEM, virthint, paddr, mapsz);
				bytes -= mapsz;
				virthint += mapsz;
			}
			break;
		default:
			dprintf("Bad resurce type\n");
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
		if (!(pteval & PTE_VALID))
			goto next_entry;

		dboot_printf("%s [L%u] 0x%p[%u] = 0x%" PRIx64 ", va=0x%" PRIx64,
		    tabs + l, l, (void *)table, index, (uint64_t)pteval, va);
		pa = pteval & PTE_PFN_MASK;
		if (l == 0 ||
		    (l != 0 && (pteval & PTE_TYPE_MASK) == PTE_BLOCK)) {
			dboot_printf(" physaddr=0x%" PRIx64 "\n", pa);
		} else {
			dboot_printf(" => 0x%" PRIx64 "\n", pa);
		}

		if (l > 0 && (pteval & PTE_TYPE_MASK) == PTE_TABLE) {
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
			if (!(pteval & PTE_TYPE_MASK))
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
