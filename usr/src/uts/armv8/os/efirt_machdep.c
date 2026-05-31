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
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * UEFI Runtime Services support for AArch64.
 *
 * This file implements the machine-dependent parts of UEFI Runtime
 * Services support:
 * - Building a 1:1 identity-mapped page table for EFI RT regions
 *   using hand-crafted page tables - necessary to not fall foul
 *   of as initialisation order and hat datastructure lifecycles
 * - Low-level enter/leave routines that switch TTBR0 to the EFI
 *   page table and save/restore FPU state.
 * - A fault-protected call wrapper that runs firmware on a
 *   dedicated stack via on_trap and an assembly trampoline
 * - Extracting RT function pointers from the EFI system table
 * - Easily callable function wrappers that protect callers from
 *   all of this complexity.
 *
 * Key design decisions:
 * * We identity-map RT regions (VA == PA) following the FreeBSD
 *   model. We still call SetVirtualAddressMap with the
 *   identity-mapped setup to ensure that we don't fall foul of
 *   well known firmware bugs.
 * * TTBR0 is switched directly (not via hat_switch()) to avoid
 *   side effects on cpu_current_hat.
 * * ASID 1 is permanently reserved for the UEFI page table to
 *   avoid unwanted interactions with user address spaces.
 * * A sleep mutex serializes all RT calls (UEFI RT is not
 *   reentrant - it is in some cases, but the rules are complex
 *   and it's simpler to just serialise calls).
 * * kernel_fpu_begin/end bracket RT calls because while the UEFI
 *   calling convention does not explicitly permit FP/SIMD register
 *   use there are implementations in the wild that use FP/SIMD.
 * * Firmware runs on a dedicated stack (DEFAULTSTKSZ = 20 KB)
 *   to avoid kernel stack overflow or corruption from greedy or
 *   buggy firmware.
 * * on_trap(OT_DATA_ACCESS) provides fault recovery for both
 *   data aborts and instruction aborts from EL1 (the trap
 *   handler dispatches both through the same on_trap check).
 *   Per-call recovery: a fault returns EFI_DEVICE_ERROR to the
 *   caller.  The faulting RT service is disabled, but other calls
 *   remain available.
 *
 * The EFI page table is constructed manually (not via the hat/as
 * layer) to avoid dependencies on htable lifecycle - the hat layer
 * may reap htable pages under memory pressure, but UEFI page tables
 * must be permanently pinned.  Page table pages are allocated via
 * kmem_zalloc and are never freed.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/mutex.h>
#include <sys/kfpu.h>
#include <sys/bootconf.h>
#include <sys/efi.h>
#include <sys/efirt.h>
#include <sys/ontrap.h>
#include <sys/machsystm.h>
#include <sys/machparam.h>
#include <sys/controlregs.h>
#include <asm/controlregs.h>
#include <asm/atomic.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/hat_aarch64.h>
#include <vm/hat_pte.h>
#include <vm/kpm.h>

/*
 * Convert a physical address to a KPM virtual address, preserving
 * the intra-page offset.  hat_kpm_pfn2va returns the VA for the
 * page boundary; we add back the offset within the page.
 */
static caddr_t
efirt_pa_to_va(uint64_t pa)
{
	return ((caddr_t)hat_kpm_pfn2va(mmu_btop(pa)) +
	    (pa & MMU_PAGEOFFSET));
}

/*
 * EFI Runtime Services state.
 *
 * These variables are set up at initialisation time.
 */
static pte_t		*efirt_pt;
static uint64_t		efirt_ttbr0;
static kmutex_t		efirt_lock;
static boolean_t	efirt_active = B_FALSE;

/*
 * Saved CPU state across an EFI RT call. Protected by efirt_lock.
 */
static uint64_t		efirt_saved_ttbr0;
static uint64_t		efirt_saved_tcr;

/*
 * Kernel FPU state for EFI RT calls.
 */
static struct kfpu_state	*efirt_kfpu;

/*
 * Dedicated stack for EFI runtime service calls.  Firmware runs on
 * this stack to avoid consuming the kernel thread's stack.  Sized at
 * DEFAULTSTKSZ (20 KB), which exceeds the UEFI specification's
 * typical requirements. Protected by efirt_lock.
 */
static caddr_t		efirt_stack;
static caddr_t		efirt_stack_top;

/*
 * Bitmask of runtime services that firmware advertises as functional
 * after ExitBootServices.  Initialised from EFI_RT_PROPERTIES_TABLE
 * if present, otherwise all bits are set (assume all available).
 *
 * Bits are cleared dynamically when a service returns EFI_UNSUPPORTED or
 * faults when called.
 */
static uint32_t		efirt_supported = EFI_RT_SUPPORTED_ALL;

/*
 * Assembly trampoline: switches to the UEFI dedicated stack, shuffles
 * arguments, calls the firmware function, and switches back.
 *
 * Implemented in armv8/ml/efirt_call.S.
 */
extern uint64_t efirt_call_asm(uint64_t func, uint64_t a0, uint64_t a1,
    uint64_t a2, uint64_t a3, uint64_t a4, uint64_t stack_top);

/*
 * UEFI Runtime Services function pointers (physical addresses).
 *
 * These are extracted from the EFI_RUNTIME_SERVICES64 table.
 */
uint64_t	efirt_get_time;
uint64_t	efirt_set_time;
uint64_t	efirt_get_wakeup_time;
uint64_t	efirt_set_wakeup_time;
uint64_t	efirt_get_variable;
uint64_t	efirt_get_next_variable_name;
uint64_t	efirt_set_variable;
uint64_t	efirt_get_next_high_mono_count;
uint64_t	efirt_reset_system;
uint64_t	efirt_update_capsule;
uint64_t	efirt_query_capsule_caps;
uint64_t	efirt_query_variable_info;

/*
 * Translate EFI memory descriptor attributes to AArch64 PTE bits.
 *
 * All EFI PTEs get:
 *   PTE_PAGE      - L0 page descriptor
 *   PTE_AF        - access flag pre-set (no fault on first touch)
 *   PTE_SH_INNER  - inner shareable
 *   PTE_NG        - non-global (tagged with ASID 1)
 *   PTE_UXN       - never user-executable
 *   PTE_AP_KRWUNA - kernel read/write, user no-access
 *
 * Code regions omit PTE_PXN so firmware can execute at EL1.
 * Data and MMIO regions set PTE_PXN.
 */
static pte_t
efirt_efi_to_pte_attr(uint32_t type, uint64_t attr)
{
	pte_t pte = PTE_PAGE | PTE_AF | PTE_SH_INNER | PTE_NG |
	    PTE_UXN | PTE_AP_KRWUNA;

	/* Caching attributes */
	if (type == EfiMemoryMappedIO ||
	    type == EfiMemoryMappedIOPortSpace) {
		pte |= PTE_ATTR_DEVICE;
	} else if (attr & EFI_MEMORY_WB) {
		pte |= PTE_ATTR_NORMEM;
	} else if (attr & EFI_MEMORY_WT) {
		pte |= PTE_ATTR_NORMEM_WT;
	} else if (attr & EFI_MEMORY_WC) {
		pte |= PTE_ATTR_NORMEM_UC;
	} else {
		pte |= PTE_ATTR_DEVICE;
	}

	/* Code regions: no PXN so firmware can execute at EL1 */
	if (type != EfiRuntimeServicesCode) {
		pte |= PTE_PXN;
	}

	return (pte);
}

/*
 * Allocate a zeroed page-table page.
 *
 * These are never freed - the UEFI page table must be permanently pinned.
 */
static pte_t *
efirt_alloc_ptpage(void)
{
	return ((pte_t *)kmem_zalloc(MMU_PAGESIZE, KM_SLEEP));
}

/*
 * Install a single page mapping in the UEFI page table.
 *
 * Allocates intermediate tables as needed.
 *
 * Level numbering follows the illumos convention.
 */
static void
efirt_map_page(pte_t *root, uint64_t pa, pte_t pte_attr)
{
	int level;
	pte_t *table = root;

	for (level = mmu.max_level; level > 0; level--) {
		uint_t idx = LEVEL_INDEX(pa, level);

		if (!PTE_ISVALID(table[idx])) {
			pte_t *next = efirt_alloc_ptpage();
			table[idx] = MAKEPTP(hat_getpfnum(
			    kas.a_hat, (caddr_t)next), level, 1);
			table = next;
		} else {
			table = (pte_t *)pfn_to_kseg(
			    PTE2PFN(table[idx], level));
		}
	}

	/* Leaf page entry */
	table[LEVEL_INDEX(pa, 0)] = (pa & PTE_PFN_MASK) | pte_attr;
}

/*
 * Walk the EFI configuration table to find EFI_RT_PROPERTIES_TABLE.
 *
 * If found, return the RuntimeServicesSupported bitmask.
 * If not found, return EFI_RT_SUPPORTED_ALL (assume all available).
 */
static uint32_t
efirt_get_rt_supported(EFI_SYSTEM_TABLE64 *systab)
{
	uint64_t		cfg_pa;
	uint64_t		count;
	EFI_CONFIGURATION_TABLE64	*cfg;
	static const efi_guid_t	rt_prop_guid =
	    EFI_RT_PROPERTIES_TABLE_GUID;

	count = systab->NumberOfTableEntries;
	cfg_pa = systab->ConfigurationTable;

	if (count == 0 || cfg_pa == 0) {
		return (EFI_RT_SUPPORTED_ALL);
	}

	cfg = (EFI_CONFIGURATION_TABLE64 *)efirt_pa_to_va(cfg_pa);

	for (uint64_t i = 0; i < count; i++) {
		if (bcmp(&cfg[i].VendorGuid, &rt_prop_guid,
		    sizeof (efi_guid_t)) == 0) {
			EFI_RT_PROPERTIES_TABLE	*prop;

			prop = (EFI_RT_PROPERTIES_TABLE *)
			    efirt_pa_to_va(cfg[i].VendorTable);

			if (prop->Version >=
			    EFI_RT_PROPERTIES_TABLE_VERSION) {
				return (prop->RuntimeServicesSupported &
				    EFI_RT_SUPPORTED_ALL);
			}

			/*
			 * Version mismatch - table is present but we
			 * don't understand it.  Assume all available.
			 */
			cmn_err(CE_NOTE,
			    "!EFI RT: RT properties table version %u "
			    "not supported (expected >= %u)",
			    prop->Version,
			    EFI_RT_PROPERTIES_TABLE_VERSION);
			return (EFI_RT_SUPPORTED_ALL);
		}
	}

	/* Table not found - assume all services available */
	cmn_err(CE_NOTE, "!EFI RT: RT properties table not found");
	return (EFI_RT_SUPPORTED_ALL);
}

/*
 * Clear one or more bits in the runtime services supported mask.
 *
 * Called by service wrappers when firmware returns EFI_UNSUPPORTED,
 * so that subsequent calls return EFI_UNSUPPORTED immediately without
 * entering firmware.  Safe to call without the RT lock - the only
 * transition is from set to clear, never back, so a race just means
 * one extra firmware round-trip.
 */
static void
efirt_clear_supported(uint32_t mask)
{
	atomic_and_32(&efirt_supported, ~mask);
}

/*
 * Check whether a set of runtime services are supported.
 *
 * Returns B_TRUE if all bits in the mask are set in efirt_supported.
 * Can be called without holding the RT lock (benign race at worst:
 * one extra call that returns EFI_UNSUPPORTED before the bit is cleared).
 */
static boolean_t
efirt_is_supported(uint32_t mask)
{
	return ((efirt_supported & mask) == mask);
}

/*
 * Call SetVirtualAddressMap with an identity mapping (VA == PA).
 *
 * Although we use a 1:1 identity map and could operate purely in
 * physical mode, calling SetVirtualAddressMap is necessary to work
 * around well-known firmware bugs - notably on Ampere eMAG platforms,
 * where firmware assumes the OS will always call SVAM and behaves
 * incorrectly if it is not called.
 *
 * This function is called once during efirt_init, after the UEFI
 * page table, dedicated stack, and FPU state are ready, but before
 * RT function pointers are extracted.  This ordering is important:
 * firmware may relocate its internal pointers during SVAM, so the
 * RT function pointer table must be read only after SVAM returns.
 *
 * Because efirt_active is not yet B_TRUE, we cannot use efirt_call_rt
 * (which asserts efirt_active).  Instead we inline the enter/call/leave
 * sequence.  This is safe because we are on a single CPU during early
 * boot with no contention.
 */
static void
efirt_set_virtual_address_map(struct efi_map_header *mhdr,
    EFI_RUNTIME_SERVICES64 *rt)
{
	EFI_MEMORY_DESCRIPTOR	*src, *dst;
	caddr_t			map_copy;
	on_trap_data_t		otd;
	uint64_t		svam_func;
	uint64_t		status;
	size_t			map_size;
	int			ndesc;

	ASSERT(!efirt_active);

	if (!(efirt_supported & EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP)) {
		return;
	}

	svam_func = rt->SetVirtualAddressMap;
	if (svam_func == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP);
		return;
	}

	/*
	 * Allocate a writable copy of the memory map.  Firmware reads
	 * VirtualStart from each descriptor to relocate its internal
	 * pointers.  The copy is a kernel VA (TTBR1 range) which
	 * firmware can access because TTBR1 remains active during
	 * EFI calls.
	 */
	map_size = mhdr->memory_size;
	ndesc = efi_mmap_ndesc(mhdr);
	map_copy = kmem_alloc(map_size, KM_SLEEP);

	src = efi_mmap_start(mhdr);
	dst = (EFI_MEMORY_DESCRIPTOR *)map_copy;
	for (int i = 0; i < ndesc; i++) {
		bcopy(src, dst, mhdr->descriptor_size);

		if (dst->Attribute & EFI_MEMORY_RUNTIME) {
			dst->VirtualStart = dst->PhysicalStart;
		} else {
			dst->VirtualStart = 0;
		}

		src = efi_mmap_next(src, mhdr->descriptor_size);
		dst = efi_mmap_next(dst, mhdr->descriptor_size);
	}

	/*
	 * Inline the EFI enter sequence.  No lock needed - single
	 * CPU during early boot.
	 */
	kpreempt_disable();
	kernel_fpu_begin(efirt_kfpu, 0);

	efirt_saved_tcr = read_tcr();
	efirt_saved_ttbr0 = read_ttbr0();
	write_ttbr0(efirt_ttbr0);
	write_tcr(efirt_saved_tcr & ~(TCR_EPD0));
	isb();

	if (on_trap(&otd, OT_DATA_ACCESS) != 0) {
		no_trap();
		status = EFI_DEVICE_ERROR;
		goto leave;
	}

	status = efirt_call_asm(svam_func,
	    (uint64_t)map_size,
	    (uint64_t)mhdr->descriptor_size,
	    (uint64_t)mhdr->descriptor_version,
	    (uint64_t)(uintptr_t)map_copy,
	    0,
	    (uint64_t)(uintptr_t)efirt_stack_top);

	no_trap();

leave:
	write_tcr(efirt_saved_tcr);
	write_ttbr0(efirt_saved_ttbr0);
	isb();

	kernel_fpu_end(efirt_kfpu, 0);
	kpreempt_enable();

	kmem_free(map_copy, map_size);

	if (status != EFI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!EFI RT: SetVirtualAddressMap failed: 0x%lx "
		    "(continuing with physical addresses)", status);
		efirt_clear_supported(EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP);
	}
}

/*
 * Initialize EFI Runtime Services support.
 *
 * Called from startup_efi, after startup_vm has made kmem,
 * the hat layer, and the ASID allocator available.  Boot scratch
 * memory (which holds the raw EFI memory map) is still intact -
 * release_bootstrap runs much later from main.c.
 */
void
efirt_init(void)
{
	uint64_t			systab_pa = 0;
	uint64_t			memmap_pa = 0;
	struct efi_map_header		*mhdr;
	EFI_MEMORY_DESCRIPTOR		*desc;
	EFI_SYSTEM_TABLE64		*systab;
	EFI_RUNTIME_SERVICES64		*rt;
	int				ndesc;
	int				nrt = 0;

	/*
	 * Read boot properties set by fakebop.c.
	 */
	if (do_bsys_getproplen(NULL, "efi-systab") > 0)
		(void) do_bsys_getprop(NULL, "efi-systab", &systab_pa);
	if (do_bsys_getproplen(NULL, "efi-memmap") > 0)
		(void) do_bsys_getprop(NULL, "efi-memmap", &memmap_pa);

	if (systab_pa == 0 || memmap_pa == 0) {
		cmn_err(CE_NOTE,
		    "!EFI RT: system table or memory map not available");
		return;
	}

	/*
	 * Validate the EFI system table and runtime services table
	 * before committing to any resource allocation.  These are
	 * accessed in-place via KPM from boot scratch memory.
	 */
	systab = (EFI_SYSTEM_TABLE64 *)efirt_pa_to_va(systab_pa);

	if (systab->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE) {
		cmn_err(CE_WARN,
		    "!EFI RT: invalid system table signature");
		return;
	}

	if (systab->RuntimeServices == 0) {
		cmn_err(CE_WARN,
		    "!EFI RT: no runtime services table pointer");
		return;
	}

	rt = (EFI_RUNTIME_SERVICES64 *)
	    efirt_pa_to_va(systab->RuntimeServices);

	if (rt->Hdr.Signature != EFI_RUNTIME_SERVICES_SIGNATURE) {
		cmn_err(CE_WARN,
		    "!EFI RT: invalid runtime services signature");
		return;
	}

	/*
	 * Check whether firmware advertises restricted RT service
	 * availability via the EFI_RT_PROPERTIES_TABLE.  If the table
	 * is not present we assume all services are available.
	 */
	efirt_supported = efirt_get_rt_supported(systab);

	/*
	 * Access the raw EFI memory map in-place via KPM.  The map
	 * lives in boot scratch memory (EfiLoaderData) which is still
	 * intact - release_bootstrap runs much later from main.c.
	 *
	 * We do not copy the map; it is only needed during init.
	 */
	mhdr = (struct efi_map_header *)efirt_pa_to_va(memmap_pa);

	/*
	 * Allocate the top-level page table and identity-map all
	 * EFI_MEMORY_RUNTIME regions.  Page table pages are allocated
	 * via kmem_zalloc and never freed, as runtime services are
	 * required all the way up to reboot.
	 */
	efirt_pt = efirt_alloc_ptpage();

	ndesc = efi_mmap_ndesc(mhdr);
	desc = efi_mmap_start(mhdr);

	for (int i = 0;
	    i < ndesc;
	    i++, desc = efi_mmap_next(desc, mhdr->descriptor_size)) {
		uint64_t	pa;
		uint64_t	npages;
		pte_t		pte_attr;

		if (!(desc->Attribute & EFI_MEMORY_RUNTIME)) {
			continue;
		}

		pa = desc->PhysicalStart;
		npages = desc->NumberOfPages;
		pte_attr = efirt_efi_to_pte_attr(desc->Type, desc->Attribute);

		for (uint64_t p = 0; p < npages; p++) {
			efirt_map_page(efirt_pt, pa + p * MMU_PAGESIZE,
			    pte_attr);
		}

		nrt++;
	}

	/*
	 * Ensure all page table stores are visible to the translation
	 * table walker before we switch TTBR0 for the first time.  The
	 * walker is coherent with the data cache on AArch64, so no cache
	 * maintenance is needed, but a DSB is required to guarantee that
	 * the stores have completed before the TTBR0 write in the SVAM
	 * call below.
	 */
	dsb(ish);

	/*
	 * Precompute the TTBR0 value for EFI context switches.
	 * ASID 1 is permanently reserved in the ASID bitmap allocator.
	 */
	efirt_ttbr0 = ((uint64_t)ASID_RESERVED_FOR_EFI << TTBR_ASID_SHIFT) |
	    pfn_to_pa(hat_getpfnum(kas.a_hat, (caddr_t)efirt_pt));

	/*
	 * Initialize the RT call serialization lock, FPU state, and
	 * the dedicated firmware call stack.
	 */
	mutex_init(&efirt_lock, NULL, MUTEX_DEFAULT, NULL);

	efirt_kfpu = kernel_fpu_alloc(KM_SLEEP);

	efirt_stack = kmem_zalloc(DEFAULTSTKSZ, KM_SLEEP);
	efirt_stack_top = efirt_stack + DEFAULTSTKSZ;

	/*
	 * Call SetVirtualAddressMap with our identity mapping before
	 * extracting function pointers.  SVAM may cause firmware to
	 * relocate its internal state and update the RT function
	 * pointer table entries.  By calling SVAM first, the function
	 * pointer extraction below picks up the post-SVAM values.
	 *
	 * If SVAM fails, we continue - the identity-mapped physical
	 * addresses are still valid.
	 */
	efirt_set_virtual_address_map(mhdr, rt);

	/*
	 * Extract RT function pointers from the (already validated)
	 * runtime services table.  Function pointers for services not
	 * advertised in the RT properties table are zeroed out - callers
	 * should check efi_rt_is_supported before calling efi_call_rt.
	 */
	efirt_get_time = (efirt_supported & EFI_RT_SUPPORTED_GET_TIME) ?
	    rt->GetTime : 0;
	efirt_set_time = (efirt_supported & EFI_RT_SUPPORTED_SET_TIME) ?
	    rt->SetTime : 0;
	efirt_get_wakeup_time =
	    (efirt_supported & EFI_RT_SUPPORTED_GET_WAKEUP_TIME) ?
	    rt->GetWakeupTime : 0;
	efirt_set_wakeup_time =
	    (efirt_supported & EFI_RT_SUPPORTED_SET_WAKEUP_TIME) ?
	    rt->SetWakeupTime : 0;
	efirt_get_variable =
	    (efirt_supported & EFI_RT_SUPPORTED_GET_VARIABLE) ?
	    rt->GetVariable : 0;
	efirt_get_next_variable_name =
	    (efirt_supported & EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME) ?
	    rt->GetNextVariableName : 0;
	efirt_set_variable =
	    (efirt_supported & EFI_RT_SUPPORTED_SET_VARIABLE) ?
	    rt->SetVariable : 0;
	efirt_get_next_high_mono_count =
	    (efirt_supported & EFI_RT_SUPPORTED_GET_NEXT_HIGH_MONO_COUNT) ?
	    rt->GetNextHighMonotonicCount : 0;
	efirt_reset_system =
	    (efirt_supported & EFI_RT_SUPPORTED_RESET_SYSTEM) ?
	    rt->ResetSystem : 0;
	efirt_update_capsule =
	    (efirt_supported & EFI_RT_SUPPORTED_UPDATE_CAPSULE) ?
	    rt->UpdateCapsule : 0;
	efirt_query_capsule_caps =
	    (efirt_supported & EFI_RT_SUPPORTED_QUERY_CAPSULE_CAPS) ?
	    rt->QueryCapsuleCapabilities : 0;
	efirt_query_variable_info =
	    (efirt_supported & EFI_RT_SUPPORTED_QUERY_VARIABLE_INFO) ?
	    rt->QueryVariableInfo : 0;

	/*
	 * Refine the supported services to remove services that have NULL
	 * pointers in the RuntimeServices structure (but may be otherwise
	 * considered available due to a default or buggy supported services
	 * bitmap).
	 */

	if (efirt_get_time == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_GET_TIME);
	}

	if (efirt_set_time == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_SET_TIME);
	}

	if (efirt_get_wakeup_time == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_GET_WAKEUP_TIME);
	}

	if (efirt_set_wakeup_time == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_SET_WAKEUP_TIME);
	}

	if (efirt_get_variable == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_GET_VARIABLE);
	}

	if (efirt_get_next_variable_name == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME);
	}

	if (efirt_set_variable == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_SET_VARIABLE);
	}

	if (efirt_get_next_high_mono_count == 0) {
		efirt_clear_supported(
		    EFI_RT_SUPPORTED_GET_NEXT_HIGH_MONO_COUNT);
	}

	if (efirt_reset_system == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_RESET_SYSTEM);
	}

	if (efirt_update_capsule == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_UPDATE_CAPSULE);
	}

	if (efirt_query_capsule_caps == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_QUERY_CAPSULE_CAPS);
	}

	if (efirt_query_variable_info == 0) {
		efirt_clear_supported(EFI_RT_SUPPORTED_QUERY_VARIABLE_INFO);
	}

	efirt_active = B_TRUE;

	cmn_err(CE_CONT,
	    "!EFI RT: %d regions mapped, services supported: 0x%x\n",
	    nrt, efirt_supported);
}

/*
 * Enter EFI runtime services context.
 *
 * Must be called with efirt_lock held.  Disables preemption, saves
 * FPU state, and switches TTBR0 to the UEFI 1:1 identity map.
 *
 * The previous TTBR0 and TCR values are saved in file-scope statics
 * (safe because the mutex serializes all RT calls).
 */
static void
efirt_arch_enter(void)
{
	ASSERT(MUTEX_HELD(&efirt_lock));

	kpreempt_disable();
	kernel_fpu_begin(efirt_kfpu, 0);

	/*
	 * Save TCR and TTBR0, then install the EFI page table.
	 * Order matters: install TTBR0 first (while walks may still
	 * be disabled via TCR_EPD0), then clear EPD0 to enable walks.
	 * This avoids a window where walks are enabled against a
	 * stale TTBR0.
	 */
	efirt_saved_tcr = read_tcr();
	efirt_saved_ttbr0 = read_ttbr0();
	write_ttbr0(efirt_ttbr0);
	write_tcr(efirt_saved_tcr & ~(TCR_EPD0));
	isb();
}

/*
 * Leave EFI runtime services context.
 *
 * Restores TCR and TTBR0, restores FPU state and re-enables preemption.
 */
static void
efirt_arch_leave(void)
{
	ASSERT(MUTEX_HELD(&efirt_lock));

	/*
	 * Restore TCR first (may re-set EPD0, disabling walks), then
	 * restore the previous TTBR0.  This avoids a window where
	 * walks are enabled against the UEFI page table after we've
	 * logically left UEFI context.
	 */
	write_tcr(efirt_saved_tcr);
	write_ttbr0(efirt_saved_ttbr0);
	isb();

	kernel_fpu_end(efirt_kfpu, 0);
	kpreempt_enable();
}

/*
 * Call an EFI runtime service with fault protection.
 *
 * Acquires the RT lock, enters UEFI context (TTBR0 switch, FPU save),
 * sets up on_trap fault recovery, calls the firmware function on a
 * dedicated stack via the assembly wrapper, then unwinds everything.
 *
 * Returns the UEFI status from firmware, or EFI_DEVICE_ERROR on fault.
 * Per-call recovery: a fault does not permanently disable RT services,
 * that is a decision made by individual runtime services call wrappers.
 */
uint64_t
efirt_call_rt(uint64_t func, uint64_t a0, uint64_t a1, uint64_t a2,
    uint64_t a3, uint64_t a4)
{
	on_trap_data_t	otd;
	uint64_t	status;

	ASSERT(efirt_active);

	mutex_enter(&efirt_lock);
	efirt_arch_enter();

	if (on_trap(&otd, OT_DATA_ACCESS) != 0) {
		/*
		 * A data abort or instruction abort occurred during the
		 * firmware call.  on_trap's longjmp has already restored
		 * SP to the kernel stack (from the setjmp buffer saved
		 * before we switched to the UEFI stack), so the dedicated
		 * UEFI stack is cleanly abandoned.
		 */
		no_trap();
		efirt_arch_leave();
		mutex_exit(&efirt_lock);
		cmn_err(CE_WARN,
		    "!EFI RT: firmware fault during runtime service call");
		return (EFI_DEVICE_ERROR);
	}

	status = efirt_call_asm(func, a0, a1, a2, a3, a4,
	    (uint64_t)(uintptr_t)efirt_stack_top);

	no_trap();
	efirt_arch_leave();
	mutex_exit(&efirt_lock);

	return (status);
}

/*
 * Return B_TRUE if EFI Runtime Services are available.
 */
boolean_t
efirt_is_active(void)
{
	return (efirt_active);
}

/*
 * EFI Runtime Service Wrappers
 *
 * Each wrapper follows the same pattern:
 * 1. Check efirt_is_active - bail if RT services never initialised.
 * 2. Check efirt_is_supported - bail if firmware advertised this
 *    service as unsupported, or a previous call returned EFI_UNSUPPORTED.
 * 3. Call firmware via efirt_call_rt.
 * 4. If firmware returns EFI_UNSUPPORTED, clear the supported bit so
 *    subsequent calls return immediately without entering firmware.
 */

/*
 * Reset or shut down the system (UEFI Specification 2.10, Section 8.5.1).
 *
 * ResetSystem does not return on success - the machine reboots or
 * powers off.  If we return from this function, the reset failed.
 *
 * The data_size/data arguments allow passing a reset reason string
 * to firmware (optional, may be NULL/0).
 */
void
efi_reset_system(EFI_RESET_TYPE type, uint64_t status,
    uint64_t data_size, void *data)
{
	if (!efirt_is_active()) {
		return;
	}

	if (!efirt_is_supported(EFI_RT_SUPPORTED_RESET_SYSTEM)) {
		return;
	}

	(void) efirt_call_rt(efirt_reset_system,
	    (uint64_t)type, status, data_size, (uint64_t)data, 0);

	/*
	 * If we get here, the reset failed.  Clear the supported bit
	 * so we don't try this path again.
	 */
	efirt_clear_supported(EFI_RT_SUPPORTED_RESET_SYSTEM);
}
