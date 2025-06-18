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
 * Copyright 2025 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cpu.h>
#include <sys/cpuid.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/note.h>
#include <sys/asm_linkage.h>
#include <sys/x_call.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/vtrace.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_dev.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/seg_kp.h>
#include <sys/kmem.h>
#include <sys/stack.h>
#include <sys/smp_impldefs.h>
#include <sys/machsystm.h>
#include <sys/clock.h>
#include <sys/cpc_impl.h>
#include <sys/pg.h>
#include <sys/cmt.h>
#include <sys/dtrace.h>
#include <sys/archsystm.h>
#include <sys/fp.h>
#include <sys/reboot.h>
#include <sys/kdi_machimpl.h>
#include <vm/vm_dep.h>
#include <sys/memnode.h>
#include <sys/sysmacros.h>
#include <sys/ontrap.h>
#include <sys/promif.h>
#include <sys/memlist_impl.h>
#include <sys/memlist_plat.h>
#include <sys/bootconf.h>
#include <sys/ddi_periodic.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/systeminfo.h>
#include <sys/rtc.h>
#include <sys/smbios.h>
#include <sys/clconf.h>
#include <sys/kdi.h>
#include <sys/vm_machparam.h>
#include <vm/hat_aarch64.h>
#include <sys/sysconf.h>
#include <sys/sunndi.h>
#include <sys/syspic.h>
#include <sys/syspic_impl.h>
#include <sys/psci.h>
#include <sys/controlregs.h>
#include <sys/arch_timer.h>
#include <sys/cpuinfo.h>
#include <sys/prom_debug.h>
#include <sys/bitext.h>
#include <sys/ramdisk.h>
#include <sys/bootinfo.h>

extern void brand_init(void);
extern void pcf_init(void);
extern void pg_init(void);
extern void mach_init(void);
#pragma weak set_platform_defaults
extern void set_platform_defaults(void);
extern time_t process_rtc_config_file(void);

static int32_t set_soft_hostid(void);
static char hostid_file[] = "/etc/hostid";

#define	TERABYTE		(1ul << 40)
#define	PHYSMEM_MAX64		mmu_btop(64 * TERABYTE)
#define	PHYSMEM			PHYSMEM_MAX64


caddr_t econtig;
pgcnt_t physmem = PHYSMEM;
pgcnt_t obp_pages;	/* Memory used by PROM for its text and data */
char bootblock_fstype[16];
int segzio_fromheap = 0;

char kern_bootargs[OBP_MAXPATHLEN];
char kern_bootfile[OBP_MAXPATHLEN];

int	l2cache_sz = 0x80000;
int	l2cache_linesz = 0x40;
int	l2cache_assoc = 1;
static size_t	textrepl_min_gb = 10;

uintptr_t	hole_start = HOLE_START;
uintptr_t	hole_end = HOLE_END;
caddr_t kpm_vbase;
size_t  kpm_size;
static uintptr_t segkpm_base = (uintptr_t)SEGKPM_BASE;
static page_t *rd_pages;

uintptr_t	kernelbase;
size_t		segmapsize;
uintptr_t	segmap_start;
int		segmapfreelists;
pgcnt_t		npages;
size_t		core_size;		/* size of "core" heap */
uintptr_t	core_base;		/* base address of "core" heap */

long page_hashsz;		/* Size of page hash table (power of two) */
unsigned int page_hashsz_shift;	/* log2(page_hashsz) */
struct page *pp_base;		/* Base of initial system page struct array */
struct page **page_hash;	/* Page hash table */
pad_mutex_t *pse_mutex;		/* Locks protecting pp->p_selock */
size_t pse_table_size;		/* Number of mutexes in pse_mutex[] */
int pse_shift;			/* log2(pse_table_size) */

struct seg ktextseg;		/* Segment used for kernel executable image */
struct seg kvalloc;		/* Segment used for "valloc" mapping */
struct seg kpseg;		/* Segment used for pageable kernel virt mem */
struct seg kmapseg;		/* Segment used for generic kernel mappings */
struct seg kdebugseg;		/* Segment used for the kernel debugger */

struct seg *segkmap = &kmapseg;	/* Kernel generic mapping segment */
static struct seg *segmap = &kmapseg;	/* easier to use name for in here */
struct seg *segkp = &kpseg;	/* Pageable kernel virtual memory segment */

struct seg kpmseg;		/* Segment used for physical mapping */
struct seg *segkpm = &kpmseg;	/* 64bit kernel physical mapping segment */

caddr_t segkp_base;		/* Base address of segkp */
caddr_t segzio_base;		/* Base address of segzio */
pgcnt_t segkpsize = btop(SEGKPDEFSIZE);	/* size of segkp segment in pages */
pgcnt_t segziosize = 0;		/* size of zio segment in pages */
const caddr_t kdi_segdebugbase = (const caddr_t)SEGDEBUGBASE;
const size_t kdi_segdebugsize = SEGDEBUGSIZE;

static page_t *bootpages;

struct memlist *memlist;

caddr_t s_text;		/* start of kernel text segment */
caddr_t e_text;		/* end of kernel text segment */
caddr_t s_data;		/* start of kernel data segment */
caddr_t e_data;		/* end of kernel data segment */

struct memlist *phys_install;	/* Total installed physical memory */
struct memlist *phys_avail;	/* Total available physical memory */
struct memlist *bios_rsvd;	/* Bios reserved memory */

struct bootops		*bootops = 0;
int physMemInit = 0;
struct memlist *boot_scratch;

uintptr_t	postbootkernelbase;	/* not set till boot loader is gone */
uintptr_t	eprom_kernelbase;
pgcnt_t		orig_npages;
struct memseg *memseg_base;

vmem_t		*device_arena;
uintptr_t	toxic_addr = (uintptr_t)NULL;
size_t		toxic_size = 1024 * 1024 * 1024; /* Sparc uses 1 gig too */

/*
 * Simple boot time debug facilities
 */
static char *prm_dbg_str[] = {
	"%s:%d: '%s' is 0x%x\n",
	"%s:%d: '%s' is 0x%llx\n"
};

int prom_debug = 0;

#define	ROUND_UP_PAGE(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), (uintptr_t)MMU_PAGESIZE))
#define	ROUND_UP_2MEG(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), (uintptr_t)(2 * 1024 * 1024)))
#define	ROUND_UP_LPAGE(x)	ROUND_UP_2MEG(x)

extern int size_pse_array(pgcnt_t, int);

/*
 * This structure is used to keep track of the intial allocations
 * done in startup_memlist(). The value of NUM_ALLOCATIONS needs to
 * be >= the number of ADD_TO_ALLOCATIONS() executed in the code.
 */
#define	NUM_ALLOCATIONS 8
int num_allocations = 0;
struct {
	void **al_ptr;
	size_t al_size;
} allocations[NUM_ALLOCATIONS];
size_t valloc_sz = 0;
uintptr_t valloc_base;

#define	ADD_TO_ALLOCATIONS(ptr, size) {					\
		size = ROUND_UP_PAGE(size);				\
		if (num_allocations == NUM_ALLOCATIONS)			\
			panic("too many ADD_TO_ALLOCATIONS()");		\
		allocations[num_allocations].al_ptr = (void**)&ptr;	\
		allocations[num_allocations].al_size = size;		\
		valloc_sz += size;					\
		++num_allocations;					\
	}
/*
 * Allocate all the initial memory needed by the page allocator.
 */
static void
perform_allocations(void)
{
	caddr_t mem;
	int i;
	int valloc_align;

	PRM_DEBUG(valloc_base);
	PRM_DEBUG(valloc_sz);
	valloc_align = MMU_PAGESIZE;
	mem = BOP_ALLOC(bootops, (caddr_t)valloc_base, valloc_sz, valloc_align);
	if (mem != (caddr_t)valloc_base)
		panic("BOP_ALLOC() failed");
	bzero(mem, valloc_sz);
	for (i = 0; i < num_allocations; ++i) {
		*allocations[i].al_ptr = (void *)mem;
		mem += allocations[i].al_size;
	}
}
static void startup_init(void);
static void startup_memlist(void);
static void startup_kmem(void);
static void startup_modules(void);
static void startup_vm(void);
static void startup_end(void);
static void layout_kernel_va(void);
extern void ssp_init(void);

static void
getl2cacheinfo(int *csz, int *lsz, int *assoc)
{
	uint64_t num_sets, ccsidr;

	write_csselr_el1(1u << 1); /* CCSIDR_EL1 should reflect L2$ */
	ccsidr = read_ccsidr_el1();
	PRM_DEBUG(ccsidr);

	/*
	 * We need ID_AA64MMFR2.CCIDX prior to cpu features being detected
	 * because the fields in CCSIDR change incompatibly.
	 */
	if (MMFR2_CCIDX(read_id_aa64mmfr2()) == 0) {
		num_sets = bitx64(ccsidr, 27, 13) + 1;
		l2cache_assoc = bitx64(ccsidr, 12, 3) + 1;
	} else {
		num_sets = bitx64(ccsidr, 55, 32) + 1;
		l2cache_assoc = bitx64(ccsidr, 23, 3) + 1;
	}

	PRM_DEBUG(num_sets);
	PRM_DEBUG(l2cache_assoc);

	l2cache_linesz = (1u << (4 + bitx64(ccsidr, 2, 0)));
	PRM_DEBUG(l2cache_linesz);
	l2cache_sz = l2cache_linesz * l2cache_assoc * num_sets;
	PRM_DEBUG(l2cache_sz);

	if (num_sets == 1 && l2cache_assoc == 1) {
		PRM_POINT("NOTICE: working around KVM cache size "
		    "discovery restrictions");
		l2cache_assoc = 0;
	}
}

void
kobj_vmem_init(vmem_t **text_arena, vmem_t **data_arena)
{
	/*
	 * XXXARM: x86 has reservations here, that it includes if it can
	 * SPARC does something similar.
	 *
	 * We don't have that facility (yet?) so we just create complete fresh
	 * arenas always.
	 */
	*text_arena = vmem_create("module_text", NULL, 0,
	    1, segkmem_alloc, segkmem_free, heaptext_arena, 0, VM_SLEEP);
	*data_arena = vmem_create("module_data", NULL, 0,
	    1, segkmem_alloc, segkmem_free, heap32_arena, 0, VM_SLEEP);
}

caddr_t
kobj_text_alloc(vmem_t *arena, size_t size)
{
	return (vmem_alloc(arena, size, VM_SLEEP | VM_BESTFIT));
}

/*ARGSUSED*/
caddr_t
kobj_texthole_alloc(caddr_t addr, size_t size)
{
	panic("unexpected call to kobj_texthole_alloc()");
	/*NOTREACHED*/
	return (0);
}

/*ARGSUSED*/
void
kobj_texthole_free(caddr_t addr, size_t size)
{
	panic("unexpected call to kobj_texthole_free()");
}

/*
 * claim a "setaside" boot page for use in the kernel
 */
page_t *
boot_claim_page(pfn_t pfn)
{
	page_t *pp;

	pp = page_numtopp_nolock(pfn);
	ASSERT(pp != NULL);

	if (PP_ISBOOTPAGES(pp)) {
		if (pp->p_next != NULL)
			pp->p_next->p_prev = pp->p_prev;
		if (pp->p_prev == NULL)
			bootpages = pp->p_next;
		else
			pp->p_prev->p_next = pp->p_next;
	} else {
		/*
		 * htable_attach() expects a base pagesize page
		 */
		if (pp->p_szc != 0)
			page_boot_demote(pp);
		pp = page_numtopp(pfn, SE_EXCL);
	}
	return (pp);
}


void
startup(void)
{
	extern cpuset_t cpu_ready_set;

	CPUSET_ONLY(cpu_ready_set, 0);	/* cpu 0 is boot cpu */

	ssp_init();
	startup_init();
	startup_memlist();
	startup_kmem();
	startup_vm();
	startup_modules();
	startup_end();
}

void
get_system_configuration(void)
{
	char	prop[32];
	u_longlong_t nodes_ll, cpus_pernode_ll, lvalue;

	if (BOP_GETPROPLEN(bootops, "segmapsize") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "segmapsize", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		segmapsize = SEGMAPDEFAULT;
	else
		segmapsize = (uintptr_t)lvalue;

	if (BOP_GETPROPLEN(bootops, "segmapfreelists") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "segmapfreelists", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		segmapfreelists = 0;	/* use segmap driver default */
	else
		segmapfreelists = (int)lvalue;

	/* physmem used to be here, but moved much earlier to fakebop.c */
}

static void
startup_init(void)
{
	PRM_POINT("startup_init() starting...");

	/*
	 * Complete the extraction of cpuid data
	 */
	(void) check_boot_version(BOP_GETVERSION(bootops));

	/*
	 * Check for prom_debug in boot environment
	 */
	if (BOP_GETPROPLEN(bootops, "prom_debug") >= 0) {
		++prom_debug;
		PRM_POINT("prom_debug found in boot enviroment");
	}

	/*
	 * Collect node, cpu and memory configuration information.
	 */
	get_system_configuration();

	PRM_POINT("startup_init() done");
}


static void
kpm_init(void)
{
	struct segkpm_crargs b;

	kpm_pgshft = MMU_PAGESHIFT;
	kpm_pgsz =  MMU_PAGESIZE;
	kpm_pgoff = MMU_PAGEOFFSET;
	kpmp2pshft = 0;
	kpmpnpgs = 1;
	ASSERT(((uintptr_t)kpm_vbase & (kpm_pgsz - 1)) == 0);

	PRM_POINT("about to create segkpm");
	rw_enter(&kas.a_lock, RW_WRITER);

	if (seg_attach(&kas, kpm_vbase, kpm_size, segkpm) < 0)
		panic("cannot attach segkpm");

	b.prot = PROT_READ | PROT_WRITE;
	b.nvcolors = 1;

	if (segkpm_create(segkpm, (caddr_t)&b) != 0)
		panic("segkpm_create segkpm");

	rw_exit(&kas.a_lock);
}

void
add_physmem_cb(page_t *pp, pfn_t pnum)
{
	pp->p_pagenum = pnum;
	pp->p_mapping = NULL;
	pp->p_embed = 0;
	pp->p_share = 0;
	pp->p_mlentry = 0;
}

static void
diff_memlists(struct memlist *proto, struct memlist *diff, void (*func)())
{
	uint64_t p_base, p_end, d_base, d_end;

	while (proto != NULL) {
		/*
		 * find diff item which may overlap with proto item
		 * if none, apply func to all of proto item
		 */
		while (diff != NULL &&
		    proto->ml_address >= diff->ml_address + diff->ml_size)
			diff = diff->ml_next;
		if (diff == NULL) {
			(*func)(proto->ml_address, proto->ml_size);
			proto = proto->ml_next;
			continue;
		}
		if (proto->ml_address == diff->ml_address &&
		    proto->ml_size == diff->ml_size) {
			proto = proto->ml_next;
			diff = diff->ml_next;
			continue;
		}

		p_base = proto->ml_address;
		p_end = p_base + proto->ml_size;
		d_base = diff->ml_address;
		d_end = d_base + diff->ml_size;
		/*
		 * here p_base < d_end
		 * there are 5 cases
		 */

		/*
		 *	d_end
		 *	d_base
		 *  p_end
		 *  p_base
		 *
		 * apply func to all of proto item
		 */
		if (p_end <= d_base) {
			(*func)(p_base, proto->ml_size);
			proto = proto->ml_next;
			continue;
		}

		/*
		 * ...
		 *	d_base
		 *  p_base
		 *
		 * normalize by applying func from p_base to d_base
		 */
		if (p_base < d_base)
			(*func)(p_base, d_base - p_base);

		if (p_end <= d_end) {
			/*
			 *	d_end
			 *  p_end
			 *	d_base
			 *  p_base
			 *
			 *	-or-
			 *
			 *	d_end
			 *  p_end
			 *  p_base
			 *	d_base
			 *
			 * any non-overlapping ranges applied above,
			 * so just continue
			 */
			proto = proto->ml_next;
			continue;
		}

		/*
		 *  p_end
		 *	d_end
		 *	d_base
		 *  p_base
		 *
		 *	-or-
		 *
		 *  p_end
		 *	d_end
		 *  p_base
		 *	d_base
		 *
		 * Find overlapping d_base..d_end ranges, and apply func
		 * where no overlap occurs.  Stop when d_base is above
		 * p_end
		 */
		for (p_base = d_end, diff = diff->ml_next; diff != NULL;
		    p_base = d_end, diff = diff->ml_next) {
			d_base = diff->ml_address;
			d_end = d_base + diff->ml_size;
			if (p_end <= d_base) {
				(*func)(p_base, p_end - p_base);
				break;
			} else
				(*func)(p_base, d_base - p_base);
		}
		if (diff == NULL)
			(*func)(p_base, p_end - p_base);
		proto = proto->ml_next;
	}
}

static struct memseg *
memseg_find(pfn_t base, pfn_t *next)
{
	struct memseg *seg;

	if (next != NULL)
		*next = LONG_MAX;
	for (seg = memsegs; seg != NULL; seg = seg->next) {
		if (base >= seg->pages_base && base < seg->pages_end)
			return (seg);
		if (next != NULL && seg->pages_base > base &&
		    seg->pages_base < *next)
			*next = seg->pages_base;
	}
	return (NULL);
}

static void
kphysm_erase(uint64_t addr, uint64_t len)
{
	pfn_t pfn = btop(addr);
	pgcnt_t num = btop(len);
	page_t *pp;
	while (num--) {
		int locked;

#ifdef DEBUG
		pp = page_numtopp_nolock(pfn);
		ASSERT(pp != NULL);
		ASSERT(PP_ISFREE(pp));
#endif
		pp = page_numtopp(pfn, SE_EXCL);
		ASSERT(pp != NULL);
		page_pp_lock(pp, 0, 1);
		ASSERT(pp != NULL);
		ASSERT(!PP_ISFREE(pp));
		ASSERT(pp->p_lckcnt == 1);
		ASSERT(PAGE_EXCL(pp));
		pfn++;
		availrmem_initial--;
		availrmem--;
	}
}

static void
kphysm_add(uint64_t addr, uint64_t len, int reclaim)
{
	struct page *pp;
	struct memseg *seg;
	pfn_t base = btop(addr);
	pgcnt_t num = btop(len);

	seg = memseg_find(base, NULL);
	ASSERT(seg != NULL);
	pp = seg->pages + (base - seg->pages_base);

	if (reclaim) {
		struct page *rpp = pp;
		struct page *lpp = pp + num;

		/*
		 * page should be locked on prom_ppages
		 * unhash and unlock it
		 */
		while (rpp < lpp) {
			ASSERT(PP_ISNORELOC(rpp));
			PP_CLRNORELOC(rpp);
			page_pp_unlock(rpp, 0, 1);
			page_hashout(rpp, NULL);
			page_unlock(rpp);
			rpp++;
		}
	}

	add_physmem(pp, num, base);
	availrmem_initial += num;
	availrmem += num;
}

static void
kphysm_init(page_t *pp)
{
	struct memlist	*pmem;
	struct memseg	*cur_memseg;
	pfn_t		base_pfn;
	pfn_t		end_pfn;
	pgcnt_t		num;
	uint64_t	addr;
	uint64_t	size;

	ASSERT(page_hash != NULL && page_hashsz != 0);
	/*
	 * Build the memsegs entry
	 */
	cur_memseg = memseg_base;
	for (pmem = phys_install; pmem; pmem = pmem->ml_next) {
		addr = pmem->ml_address;
		size = pmem->ml_size;

		num = mmu_btop(size);
		if (num == 0)
			continue;

		ASSERT((addr & MMU_PAGEOFFSET) == 0);
		base_pfn = mmu_btop(addr);

		if (prom_debug)
			prom_printf("MEMSEG addr=0x%" PRIx64
			    " pgs=0x%lx pfn 0x%lx-0x%lx\n",
			    addr, num, base_pfn, base_pfn + num);

		cur_memseg->pages = pp;
		cur_memseg->epages = pp + num;
		cur_memseg->pages_base = base_pfn;
		cur_memseg->pages_end = base_pfn + num;

		if (memsegs != NULL) {
			ASSERT(cur_memseg->pages_base >= memsegs->pages_end);
			cur_memseg->next = memsegs;
		}
		memsegs = cur_memseg;
		cur_memseg++;
		pp += num;
	}

	/*
	 * Free the avail list
	 */
	for (pmem = phys_install; pmem != NULL; pmem = pmem->ml_next)
		kphysm_add(pmem->ml_address, pmem->ml_size, 0);

	build_pfn_hash();

	/*
	 * Erase pages from free list
	 */
	diff_memlists(phys_install, phys_avail, kphysm_erase);

	physMemInit = 1;
}

static void
startup_memlist(void)
{
	size_t memlist_sz;
	size_t memseg_sz;
	size_t pagehash_sz;
	size_t pp_sz;
	uintptr_t va __unused;	/* XXXARM */
	size_t len;
	uint_t prot;
	pfn_t pfn;
	int memblocks;
	pfn_t rsvd_high_pfn;
	pgcnt_t rsvd_pgcnt;
	size_t rsvdmemlist_sz;
	int rsvdmemblocks;
	caddr_t pagecolor_mem;
	size_t pagecolor_memsz;
	caddr_t page_ctrs_mem;
	size_t page_ctrs_size;
	size_t pse_table_alloc_size;
	struct memlist *current;
	extern void startup_build_mem_nodes(struct memlist *);

	/* XX64 fix these - they should be in include files */
	extern size_t page_coloring_init(uint_t, int, int);
	extern void page_coloring_setup(caddr_t);

	PRM_POINT("startup_memlist() starting...");

	/*
	 * Use leftover large page nucleus text/data space for loadable modules.
	 * Use at most MODTEXT/MODDATA.
	 */
	len = MMU_PAGESIZE2M;
	ASSERT(len > MMU_PAGESIZE);

	econtig = (caddr_t)P2ROUNDUP((uintptr_t)e_data, (uintptr_t)len);

	PRM_DEBUG(econtig);

	/*
	 * Examine the boot loader physical memory map to find out:
	 * - total memory in system - physinstalled
	 * - the max physical address - physmax
	 * - the number of discontiguous segments of memory.
	 */
	installed_top_size_ex(phys_install, &physmax,
	    &physinstalled, &memblocks);
	PRM_DEBUG(physmax);
	PRM_DEBUG(physinstalled);
	PRM_DEBUG(memblocks);

	/*
	 * Initialize hat's mmu parameters.
	 * Check for enforce-prot-exec in boot environment. It's used to
	 * enable/disable support for the page table entry NX bit.
	 * The default is to enforce PROT_EXEC on processors that support NX.
	 * Boot seems to round up the "len", but 8 seems to be big enough.
	 */
	mmu_init();

	startup_build_mem_nodes(phys_install);

	/*
	 * We will need page_t's for every page in the system, except for
	 * memory mapped at or above above the start of the kernel text segment.
	 */
	npages = physinstalled;
	va = KERNEL_TEXT;
	PRM_DEBUG(npages);

	/*
	 * If physmem is patched to be non-zero, use it instead of the computed
	 * value unless it is larger than the actual amount of memory on hand.
	 */
	if (physmem == 0 || physmem > npages) {
		physmem = npages;
	} else if (physmem < npages) {
		orig_npages = npages;
		npages = physmem;
	}
	PRM_DEBUG(physmem);

	/*
	 * We now compute the sizes of all the  initial allocations for
	 * structures the kernel needs in order do kmem_alloc(). These
	 * include:
	 *	memsegs
	 *	memlists
	 *	page hash table
	 *	page_t's
	 *	page coloring data structs
	 */
	memseg_sz = sizeof (struct memseg) * memblocks;
	ADD_TO_ALLOCATIONS(memseg_base, memseg_sz);
	PRM_DEBUG(memseg_sz);

	/*
	 * The page structure hash table size is a power of 2
	 * such that the average hash chain length is PAGE_HASHAVELEN.
	 */
	page_hashsz = npages / PAGE_HASHAVELEN;
	page_hashsz_shift = highbit(page_hashsz);
	page_hashsz = 1 << page_hashsz_shift;
	pagehash_sz = sizeof (struct page *) * page_hashsz;
	ADD_TO_ALLOCATIONS(page_hash, pagehash_sz);
	PRM_DEBUG(pagehash_sz);

	/*
	 * Set aside room for the page structures themselves.
	 */
	PRM_DEBUG(npages);
	pp_sz = sizeof (struct page) * npages;
	ADD_TO_ALLOCATIONS(pp_base, pp_sz);
	PRM_DEBUG(pp_sz);

	/*
	 * determine l2 cache info and memory size for page coloring
	 */
	(void) getl2cacheinfo(&l2cache_sz, &l2cache_linesz, &l2cache_assoc);

	pagecolor_memsz =
	    page_coloring_init(l2cache_sz, l2cache_linesz, l2cache_assoc);
	ADD_TO_ALLOCATIONS(pagecolor_mem, pagecolor_memsz);
	PRM_DEBUG(pagecolor_memsz);

	page_ctrs_size = page_ctrs_sz();
	ADD_TO_ALLOCATIONS(page_ctrs_mem, page_ctrs_size);
	PRM_DEBUG(page_ctrs_size);

	/*
	 * Allocate the array that protects pp->p_selock.
	 */
	pse_shift = size_pse_array(physmem, max_ncpus);
	pse_table_size = 1 << pse_shift;
	pse_table_alloc_size = pse_table_size * sizeof (pad_mutex_t);
	ADD_TO_ALLOCATIONS(pse_mutex, pse_table_alloc_size);

	valloc_sz = ROUND_UP_LPAGE(valloc_sz);
	valloc_base = VALLOC_BASE;

	/*
	 * do all the initial allocations
	 */
	perform_allocations();

	/*
	 * setup page coloring
	 */
	page_coloring_setup(pagecolor_mem);
	page_lock_init();	/* currently a no-op */

	/*
	 * free page list counters
	 */
	(void) page_ctrs_alloc(page_ctrs_mem);

	/*
	 * Size the pcf array based on the number of cpus in the box at
	 * boot time.
	 */
	pcf_init();

	/*
	 * Initialize the page structures from the memory lists.
	 */
	availrmem_initial = availrmem = freemem = 0;
	PRM_POINT("Calling kphysm_init()...");
	kphysm_init(pp_base);
	PRM_POINT("kphysm_init() done");
	PRM_DEBUG(npages);
	PRM_DEBUG(availrmem_initial);
	PRM_DEBUG(availrmem);
	PRM_DEBUG(freemem);

	/*
	 * Now that page_t's have been initialized, remove all the
	 * initial allocation pages from the kernel free page lists.
	 */
	boot_reserve();
	PRM_POINT("startup_memlist() done");

	PRM_DEBUG(valloc_sz);

	if ((availrmem >> (30 - MMU_PAGESHIFT)) >=
	    textrepl_min_gb && l2cache_sz <= 2 << 20) {
		extern size_t textrepl_size_thresh;
		textrepl_size_thresh = (16 << 20) - 1;
	}
}

static void
load_tod_module(char *todmod)
{
	if (modload("tod", todmod) == -1)
		halt("Can't load TOD module");
}

/*
 * XXXARM: This enables more than just IRQs
 * Not a great name
 */
static inline void
enable_irq()
{
	__asm__ volatile("msr DAIFClr, %0"
	    :: "I" (DAIF_SETCLEAR_ALL)
	    : "memory");
}

static void
startup_end(void)
{
	int i;
	extern void cpu_event_init(void);

	PRM_POINT("startup_end() starting...");

	/*
	 * Perform tasks that get done after most of the VM
	 * initialization has been done but before the clock
	 * and other devices get started.
	 */
	kern_setup1();

	/*
	 * Perform CPC initialization for this CPU.
	 */
	kcpc_hw_init(CPU);

	/*
	 * Initialize cpu event framework.
	 */
	cpu_event_init();

	/*
	 * If needed, load TOD module now so that ddi_get_time(9F) etc. work
	 * (For now, "needed" is defined as set tod_module_name in /etc/system)
	 */
	if (tod_module_name != NULL) {
		PRM_POINT("load_tod_module()");
		load_tod_module(tod_module_name);
	}

	/*
	 * Configure the system.
	 */
	PRM_POINT("Calling configure()...");
	configure();		/* set up devices */
	PRM_POINT("configure() done");

	/*
	 * Set the isa_list string to the defined instruction sets we
	 * support.
	 */
	cpu_intr_alloc(CPU, NINTR_THREADS);

	mach_init();

	PRM_POINT("Enabling interrupts");
	set_base_spl();
	enable_irq();

	(void) add_avsoftintr((void *)&softlevel1_hdl, 1, softlevel1,
	    "softlevel1", NULL, NULL); /* XXX to be moved later */

	/*
	 * Register these software interrupts for ddi timer.
	 * Software interrupts up to the level 10 are supported.
	 */
	for (i = DDI_IPL_1; i <= DDI_IPL_10; i++) {
		(void) add_avsoftintr((void *)&softlevel_hdl[i-1], i,
		    (avfunc)(uintptr_t)ddi_periodic_softintr, "ddi_periodic",
		    (caddr_t)(uintptr_t)i, NULL);
	}
	PRM_POINT("startup_end() done");
}
static void
startup_kmem(void)
{
	extern void page_set_colorequiv_arr(void);

	PRM_POINT("startup_kmem() starting...");

	kernelbase = segkpm_base;
	PRM_DEBUG(kernelbase);

	ekernelheap = (char *)KERNEL_TEXT;
	PRM_DEBUG(ekernelheap);

	/*
	 * Now that we know the real value of kernelbase,
	 * update variables that were initialized with a value of
	 * KERNELBASE (in common/conf/param.c).
	 *
	 * XXX	The problem with this sort of hackery is that the
	 *	compiler just may feel like putting the const declarations
	 *	(in param.c) into the .text section.  Perhaps they should
	 *	just be declared as variables there?
	 */

	*(uintptr_t *)&_kernelbase = kernelbase;
	*(uintptr_t *)&_userlimit = USERLIMIT;
	PRM_DEBUG(_kernelbase);
	PRM_DEBUG(_userlimit);

	layout_kernel_va();

	/*
	 * Initialize the kernel heap. Note 3rd argument must be > 1st.
	 */
	kernelheap_init(kernelheap, ekernelheap,
	    kernelheap + MMU_PAGESIZE,
	    (void *)core_base, (void *)(core_base + core_size));

	/*
	 * Initialize kernel memory allocator.
	 */
	kmem_init();

	/*
	 * Factor in colorequiv to check additional 'equivalent' bins
	 */
	page_set_colorequiv_arr();

	/*
	 * Initialize bp_mapin().
	 */
	bp_init(MMU_PAGESIZE, HAT_STORECACHING_OK);

	/*
	 * orig_npages is non-zero if physmem has been configured for less
	 * than the available memory.
	 */
	if (orig_npages) {
		cmn_err(CE_WARN, "!%slimiting physmem to 0x%lx of 0x%lx pages",
		    (npages == PHYSMEM ? "Due to virtual address space " : ""),
		    npages, orig_npages);
	}

	PRM_POINT("startup_kmem() done");
}

/*
 * On platforms that do not have a hardware serial number, attempt
 * to set one based on the contents of /etc/hostid.  If this file does
 * not exist, assume that we are to generate a new hostid and set
 * it in the kernel, for subsequent saving by a userland process
 * once the system is up and the root filesystem is mounted r/w.
 *
 * In order to gracefully support upgrade on OpenSolaris, if
 * /etc/hostid does not exist, we will attempt to get a serial number
 * using the legacy method (/kernel/misc/sysinit).
 *
 * In an attempt to make the hostid less prone to abuse
 * (for license circumvention, etc), we store it in /etc/hostid
 * in rot47 format.
 */
static int atoi(char *);

static int32_t
set_soft_hostid(void)
{
	struct _buf *file;
	char tokbuf[MAXNAMELEN];
	token_t token;
	int done = 0;
	u_longlong_t tmp;
	int i;
	int32_t hostid = (int32_t)HW_INVALID_HOSTID;
	unsigned char *c;
	hrtime_t tsc;

	/*
	 * If /etc/hostid file not found, we'd like to get a pseudo
	 * random number to use at the hostid.  A nice way to do this
	 * is to read the real time clock.  To remain xen-compatible,
	 * we can't poke the real hardware, so we use tsc_read() to
	 * read the real time clock.  However, there is an ominous
	 * warning in tsc_read that says it can return zero, so we
	 * deal with that possibility by falling back to using the
	 * (hopefully random enough) value in tenmicrodata.
	 */

	if ((file = kobj_open_file(hostid_file)) == (struct _buf *)-1) {
		/*
		 * hostid file not found - try to load sysinit module
		 * and see if it has a nonzero hostid value...use that
		 * instead of generating a new hostid here if so.
		 */
		if ((i = modload("misc", "sysinit")) != -1) {
			if (strlen(hw_serial) > 0)
				hostid = (int32_t)atoi(hw_serial);
			(void) modunload(i);
		}
		if (hostid == HW_INVALID_HOSTID) {
			tsc = arch_timer_count();
			hostid = (int32_t)tsc & 0x0CFFFFF;
		}
	} else {
		/* hostid file found */
		while (!done) {
			token = kobj_lex(file, tokbuf, sizeof (tokbuf));

			switch (token) {
			case POUND:
				/*
				 * skip comments
				 */
				kobj_find_eol(file);
				break;
			case STRING:
				/*
				 * un-rot47 - obviously this
				 * nonsense is ascii-specific
				 */
				for (c = (unsigned char *)tokbuf;
				    *c != '\0'; c++) {
					*c += 47;
					if (*c > '~')
						*c -= 94;
					else if (*c < '!')
						*c += 94;
				}
				/*
				 * now we should have a real number
				 */

				if (kobj_getvalue(tokbuf, &tmp) != 0)
					kobj_file_err(CE_WARN, file,
					    "Bad value %s for hostid",
					    tokbuf);
				else
					hostid = (int32_t)tmp;

				break;
			case EOF:
				done = 1;
				/* FALLTHROUGH */
			case NEWLINE:
				kobj_newline(file);
				break;
			default:
				break;

			}
		}
		if (hostid == HW_INVALID_HOSTID) /* didn't find a hostid */
			kobj_file_err(CE_WARN, file,
			    "hostid missing or corrupt");

		kobj_close_file(file);
	}
	/*
	 * hostid is now the value read from /etc/hostid, or the
	 * new hostid we generated in this routine or HW_INVALID_HOSTID if not
	 * set.
	 */
	return (hostid);
}

static int
atoi(char *p)
{
	int i = 0;

	while (*p != '\0')
		i = 10 * i + (*p++ - '0');

	return (i);
}

static void
startup_modules(void)
{
	extern void prom_setup(void);
	extern void bop_relocate(void);
	int cnt;
	int32_t v, h;
	char d[11];
	char *cp;

	PRM_POINT("startup_modules() starting...");

	bop_relocate();

	if (&set_platform_defaults)
		set_platform_defaults();

	/*
	 * Read the GMT lag from /etc/rtc_config.
	 */
	sgmtl(process_rtc_config_file());

	/*
	 * Calculate default settings of system parameters based upon
	 * maxusers, yet allow to be overridden via the /etc/system file.
	 */
	param_calc(0);

	mod_setup();

	/*
	 * Initialize system parameters.
	 */
	param_init();

	/*
	 * Initialize the default brands
	 */
	brand_init();

	/*
	 * maxmem is the amount of physical memory we're playing with.
	 */
	maxmem = physmem;

	/*
	 * Initialize segment management stuff.
	 */
	seg_init();

	/*
	 * Gather CPU information
	 */
	if (cpuinfo_init() != 0)
		halt("Can't initialize CPU information");

	/*
	 * Initialise the system programmable interrupt controller
	 * functionality.
	 */
	if (syspic_init() != 0)
		halt("Can't initialize syspic");

	if (modload("fs", "specfs") == -1)
		halt("Can't load specfs");

	if (modload("fs", "devfs") == -1)
		halt("Can't load devfs");

	if (modload("fs", "dev") == -1)
		halt("Can't load dev");

	if (modload("fs", "procfs") == -1)
		halt("Can't load procfs");

	(void) modloadonly("sys", "lbl_edition");

	dispinit();

	/*
	 * This is needed here to initialize hw_serial[] for cluster booting.
	 */
	if ((h = set_soft_hostid()) == HW_INVALID_HOSTID) {
		cmn_err(CE_WARN, "Unable to set hostid");
	} else {
		for (v = h, cnt = 0; cnt < 10; cnt++) {
			d[cnt] = (char)(v % 10);
			v /= 10;
			if (v == 0)
				break;
		}
		for (cp = hw_serial; cnt >= 0; cnt--)
			*cp++ = d[cnt] + '0';
		*cp = 0;
	}

	/*
	 * Create a kernel device tree. First, create rootnex and
	 * then invoke bus specific code to probe devices.
	 */
	setup_ddi();

	{
		id_t smid;
		smbios_system_t smsys;
		smbios_info_t sminfo;
		char *mfg;

		/*
		 * Load the System Management BIOS into the global ksmbios
		 * handle, if an SMBIOS is present on this system.
		 * Also set "si-hw-provider" property, if not already set.
		 */
		ksmbios = smbios_open(NULL, SMB_VERSION, ksmbios_flags, NULL);
		if (ksmbios != NULL &&
		    ((smid = smbios_info_system(ksmbios, &smsys)) != SMB_ERR) &&
		    (smbios_info_common(ksmbios, smid, &sminfo)) != SMB_ERR) {
			mfg = (char *)sminfo.smbi_manufacturer;
			if (BOP_GETPROPLEN(bootops, "si-hw-provider") < 0) {
				extern char hw_provider[];
				int i;
				for (i = 0; i < SYS_NMLN; i++) {
					if (isprint(mfg[i]))
						hw_provider[i] = mfg[i];
					else {
						hw_provider[i] = '\0';
						break;
					}
				}
				hw_provider[SYS_NMLN - 1] = '\0';
			}
		}
	}

	/*
	 * Set up the CPU module subsystem for the boot cpu in the native
	 * case, and all physical cpu resource in the xpv dom0 case.
	 * Modifies the device tree, so this must be done after
	 * setup_ddi().
	 */
	/*
	 * Fake a prom tree such that /dev/openprom continues to work
	 */
	PRM_POINT("startup_modules: calling prom_setup...");
	prom_setup();

	PRM_POINT("startup_modules() done");
}

/*
 *
 */
static void
layout_kernel_va(void)
{
	PRM_POINT("layout_kernel_va() starting...");
	/*
	 * Establish the final size of the kernel's heap, size of segmap,
	 * segkp, etc.
	 */

	kpm_vbase = (caddr_t)segkpm_base;
	kpm_size = SEGKPM_SIZE;
	if ((uintptr_t)kpm_vbase + kpm_size > (uintptr_t)valloc_base)
		panic("not enough room for kpm!");
	PRM_DEBUG(kpm_size);
	PRM_DEBUG(kpm_vbase);

	size_t sz = mmu_ptob(segkpsize);
	segkp_base = (caddr_t)valloc_base + valloc_sz;
	/*
	 * determine size of segkp
	 */
	if (sz < SEGKPMINSIZE || sz > SEGKPMAXSIZE) {
		sz = SEGKPDEFSIZE;
		cmn_err(CE_WARN, "!Illegal value for segkpsize. "
		    "segkpsize has been reset to %ld pages",
		    mmu_btop(sz));
	}
	sz = MIN(sz, MAX(SEGKPMINSIZE, mmu_ptob(physmem)));

	segkpsize = mmu_btop(ROUND_UP_LPAGE(sz));
	PRM_DEBUG(segkp_base);
	PRM_DEBUG(segkpsize);

	/*
	 * segzio is used for ZFS cached data. It uses a distinct VA
	 * segment (from kernel heap) so that we can easily tell not to
	 * include it in kernel crash dumps on 64 bit kernels. The trick is
	 * to give it lots of VA, but not constrain the kernel heap.
	 * We scale the size of segzio linearly with physmem up to
	 * SEGZIOMAXSIZE. Above that amount it scales at 50% of physmem.
	 */
	segzio_base = segkp_base + mmu_ptob(segkpsize);
	if (segzio_fromheap) {
		segziosize = 0;
	} else {
		size_t physmem_size = mmu_ptob(physmem);
		size_t size = (segziosize == 0) ?
		    physmem_size : mmu_ptob(segziosize);

		if (size < SEGZIOMINSIZE)
			size = SEGZIOMINSIZE;
		if (size > SEGZIOMAXSIZE) {
			size = SEGZIOMAXSIZE;
			if (physmem_size > size)
				size += (physmem_size - size) / 2;
		}
		segziosize = mmu_btop(ROUND_UP_LPAGE(size));
	}
	PRM_DEBUG(segziosize);
	PRM_DEBUG(segzio_base);

	/*
	 * Put the range of VA for device mappings next, kmdb knows to not
	 * grep in this range of addresses.
	 */
	toxic_addr =
	    ROUND_UP_LPAGE((uintptr_t)segzio_base + mmu_ptob(segziosize));
	PRM_DEBUG(toxic_addr);
	segmap_start = ROUND_UP_LPAGE(toxic_addr + toxic_size);

	/*
	 * Users can change segmapsize through eeprom. If the variable
	 * is tuned through eeprom, there is no upper bound on the
	 * size of segmap.
	 */
	segmapsize = MAX(ROUND_UP_LPAGE(segmapsize), SEGMAPDEFAULT);

	PRM_DEBUG(segmap_start);
	PRM_DEBUG(segmapsize);
	kernelheap = (caddr_t)ROUND_UP_LPAGE(segmap_start + segmapsize);
	PRM_DEBUG(kernelheap);
	PRM_POINT("layout_kernel_va() done...");
}

static void
kvm_init(void)
{
	ASSERT((((uintptr_t)s_text) & MMU_PAGEOFFSET) == 0);

	/*
	 * Put the kernel segments in kernel address space.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	as_avlinit(&kas);

	caddr_t _text = (caddr_t)P2ALIGN((uintptr_t)s_text,
	    (uintptr_t)MMU_PAGESIZE);
	caddr_t _etext = (caddr_t)P2ROUNDUP((uintptr_t)e_text,
	    (uintptr_t)MMU_PAGESIZE);
	caddr_t _data = (caddr_t)P2ALIGN((uintptr_t)s_data,
	    (uintptr_t)MMU_PAGESIZE);
	caddr_t _edata = (caddr_t)P2ROUNDUP((uintptr_t)e_data,
	    (uintptr_t)MMU_PAGESIZE);

	(void) seg_attach(&kas, _text, _edata - _text, &ktextseg);
	(void) segkmem_create(&ktextseg);

	(void) seg_attach(&kas, (caddr_t)valloc_base, valloc_sz, &kvalloc);
	(void) segkmem_create(&kvalloc);

	(void) seg_attach(&kas, kernelheap,
	    ekernelheap - kernelheap, &kvseg);
	(void) segkmem_create(&kvseg);

	if (segziosize > 0) {
		PRM_POINT("attaching segzio");
		(void) seg_attach(&kas, segzio_base, mmu_ptob(segziosize),
		    &kzioseg);
		(void) segkmem_create(&kzioseg);

		/* create zio area covering new segment */
		segkmem_zio_init(segzio_base, mmu_ptob(segziosize));
	}

	(void) seg_attach(&kas, kdi_segdebugbase, kdi_segdebugsize, &kdebugseg);
	(void) segkmem_create(&kdebugseg);

	rw_exit(&kas.a_lock);

	(void) as_setprot(&kas, _text, _etext - _text, PROT_READ | PROT_EXEC);
	(void) as_setprot(&kas, _data, _edata - _data, PROT_READ | PROT_WRITE);
}

/*
 * Finish initializing the VM system, now that we are no longer
 * relying on the boot time memory allocators.
 */
static void
startup_vm(void)
{
	struct segmap_crargs a;

	extern int use_brk_lpg, use_stk_lpg;

	PRM_POINT("startup_vm() starting...");

	/*
	 * Initialize the hat layer.
	 */
	hat_init();

	/*
	 * Do final allocations of HAT data structures that need to
	 * be allocated before quiescing the boot loader.
	 */
	PRM_POINT("Calling hat_kern_alloc()...");
	hat_kern_alloc((caddr_t)segmap_start, segmapsize, ekernelheap);
	PRM_POINT("hat_kern_alloc() done");

	/*
	 * The next two loops are done in distinct steps in order
	 * to be sure that any page that is doubly mapped (both above
	 * KERNEL_TEXT and below kernelbase) is dealt with correctly.
	 * Note this may never happen, but it might someday.
	 */
	bootpages = NULL;
	PRM_POINT("Protecting boot pages");

	/*
	 * Switch to running on regular HAT (not boot_mmu)
	 */
	PRM_POINT("Calling hat_kern_setup()...");
	hat_kern_setup();

	/*
	 * It is no longer safe to call BOP_ALLOC(), so make sure we don't.
	 */
	bop_no_more_mem();

	PRM_POINT("hat_kern_setup() done");

	/*
	 * Initialize VM system
	 */
	PRM_POINT("Calling kvm_init()...");
	kvm_init();
	PRM_POINT("kvm_init() done");

	/*
	 * Tell kmdb that the VM system is now working
	 */
	if (boothowto & RB_DEBUG)
		kdi_dvec_vmready();


	device_arena = vmem_create("device", (void *)toxic_addr,
	    toxic_size, MMU_PAGESIZE, NULL, NULL, NULL, 0, VM_SLEEP);


	/*
	 * Now that we've got more VA, as well as the ability to allocate from
	 * it, tell the debugger.
	 */
	if (boothowto & RB_DEBUG)
		kdi_dvec_memavail();

	cmn_err(CE_CONT, "?mem = %luK (0x%lx)\n",
	    physinstalled << (MMU_PAGESHIFT - 10), ptob(physinstalled));

	/*
	 * disable automatic large pages for small memory systems or
	 * when the disable flag is set.
	 *
	 * Do not yet consider page sizes larger than 2m/4m.
	 */
	use_brk_lpg = 0;
	use_stk_lpg = 0;

	PRM_POINT("Calling hat_init_finish()...");
	hat_init_finish();
	PRM_POINT("hat_init_finish() done");

	/*
	 * Initialize the segkp segment type.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	PRM_POINT("Attaching segkp");
	if (seg_attach(&kas, (caddr_t)segkp_base, mmu_ptob(segkpsize),
	    segkp) < 0) {
		panic("startup: cannot attach segkp");
		/*NOTREACHED*/
	}
	PRM_POINT("Doing segkp_create()");
	if (segkp_create(segkp) != 0) {
		panic("startup: segkp_create failed");
		/*NOTREACHED*/
	}
	PRM_DEBUG(segkp);
	rw_exit(&kas.a_lock);

	/*
	 * kpm segment
	 */
	segmap_kpm = 0;
	kpm_init();

	/*
	 * Now create segmap segment.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	if (seg_attach(&kas, (caddr_t)segmap_start, segmapsize, segmap) < 0) {
		panic("cannot attach segmap");
		/*NOTREACHED*/
	}
	PRM_DEBUG(segmap);

	a.prot = PROT_READ | PROT_WRITE;
	a.shmsize = 0;
	a.nfreelist = segmapfreelists;

	if (segmap_create(segmap, (caddr_t)&a) != 0)
		panic("segmap_create segmap");
	rw_exit(&kas.a_lock);

	segdev_init();

	PRM_POINT("startup_vm() done");
}

void
post_startup(void)
{
	extern void cpu_event_init_cpu(cpu_t *);

	/*
	 * Perform forceloading tasks for /etc/system.
	 */
	(void) mod_sysctl(SYS_FORCELOAD, NULL);

	maxmem = freemem;

	cpu_event_init_cpu(CPU);

	pg_init();
}

static int
pp_in_range(page_t *pp, uint64_t low_addr, uint64_t high_addr)
{
	return ((pp->p_pagenum >= btop(low_addr)) &&
	    (pp->p_pagenum < btopr(high_addr)));
}

static int
pp_in_module(page_t *pp, const rd_existing_t *modranges)
{
	uint_t i;

	for (i = 0; modranges[i].phys != 0; i++) {
		if (pp_in_range(pp, modranges[i].phys,
		    modranges[i].phys + modranges[i].size))
			return (1);
	}

	return (0);
}

void
release_bootstrap(void)
{
	int root_is_ramdisk;
	page_t *pp;
	extern void kobj_boot_unmountroot(void);
	extern dev_t rootdev;
	rd_existing_t *modranges;
	char propname[32];

	/*
	 * Save the bootfs module ranges so that we can reserve them below
	 * for the real bootfs.
	 */
	modranges = kmem_alloc(sizeof (rd_existing_t) * MAX_BOOT_MODULES,
	    KM_SLEEP);
	for (int i = 0; ; i++) {
		uint64_t start, size;

		modranges[i].phys = 0;

		(void) snprintf(propname, sizeof (propname),
		    "module-addr-%u", i);
		if (do_bsys_getproplen(NULL, propname) <= 0)
			break;
		(void) do_bsys_getprop(NULL, propname, &start);

		(void) snprintf(propname, sizeof (propname),
		    "module-size-%u", i);
		if (do_bsys_getproplen(NULL, propname) <= 0)
			break;
		(void) do_bsys_getprop(NULL, propname, &size);

		modranges[i].phys = start;
		modranges[i].size = size;
	}

	/* unmount boot ramdisk and release kmem usage */
	kobj_boot_unmountroot();

	/*
	 * We're finished using the boot loader so free its pages.
	 */
	PRM_POINT("Unmapping lower boot pages");

	clear_boot_mappings(0, _userlimit);

	/*
	 * If root isn't on ramdisk, destroy the hardcoded
	 * ramdisk node now and release the memory. Else,
	 * ramdisk memory is kept in rd_pages.
	 */
	root_is_ramdisk = (getmajor(rootdev) == ddi_name_to_major("ramdisk"));
	if (!root_is_ramdisk) {
		dev_info_t *dip = ddi_find_devinfo("ramdisk", -1, 0);
		ASSERT(dip && ddi_get_parent(dip) == ddi_root_node());
		ndi_rele_devi(dip);	/* held from ddi_find_devinfo */
		(void) ddi_remove_child(dip, 0);
	}

	PRM_POINT("Releasing boot pages");

	for (struct memlist *scratch = boot_scratch; scratch != NULL;
	    scratch = scratch->ml_next) {
		uintptr_t pa = scratch->ml_address;
		uintptr_t sz = scratch->ml_size;
		uintptr_t pfn = mmu_btop(pa);

		for (uintptr_t i = 0; i < mmu_btop(sz); i++) {
			extern uint64_t ramdisk_start, ramdisk_end;
			page_t *pp = page_numtopp_nolock(pfn + i);
			ASSERT(pp);
			ASSERT(PAGE_LOCKED(pp));
			ASSERT(!PP_ISFREE(pp));
			if ((root_is_ramdisk && pp_in_range(pp, ramdisk_start,
			    ramdisk_end)) || pp_in_module(pp, modranges)) {
				pp->p_next = rd_pages;
				rd_pages = pp;
				continue;
			}
			pp->p_next = (struct page *)0;
			pp->p_prev = (struct page *)0;
			PP_CLRBOOTPAGES(pp);
			page_pp_unlock(pp, 0, 1);
			page_free(pp, 1);
			mutex_enter(&freemem_lock);
			availrmem_initial++;
			availrmem++;
			mutex_exit(&freemem_lock);
		}
	}

	PRM_POINT("Boot pages released");
	kmem_free(modranges, sizeof (rd_existing_t) * MAX_BOOT_MODULES);
}

void *
device_arena_alloc(size_t size, int vm_flag)
{
	return (vmem_alloc(device_arena, size, vm_flag));
}

void
device_arena_free(void *vaddr, size_t size)
{
	vmem_free(device_arena, vaddr, size);
}
