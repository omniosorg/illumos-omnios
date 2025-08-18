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
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/null.h>
#include <sys/bootinfo.h>
#include <sys/stdbool.h>
#include <sys/psci.h>
#include <sys/acpi/platform/acsolaris.h>
#include <sys/acpi/actypes.h>
#include <sys/acpi/actbl.h>
#include <sys/cpuinfo.h>
#include <sys/controlregs.h>
#include <sys/machparam.h>

#include "dboot.h"
#include "dboot_printf.h"

#if !defined(ACPI_MADT_ONLINE_CAPABLE)
#define	ACPI_MADT_ONLINE_CAPABLE	(1 << 3)
#endif

extern void boot_psci_init(struct xboot_info *);

static const ACPI_TABLE_XSDT *
get_acpi_xsdt(void)
{
	const ACPI_TABLE_RSDP *rsdp;
	const ACPI_TABLE_XSDT *xsdt;
	extern const void * dboot_uefi_get_acpi_rsdp(void);

	if ((rsdp = dboot_uefi_get_acpi_rsdp()) == NULL)
		return (NULL);

	xsdt = (const ACPI_TABLE_XSDT *)rsdp->XsdtPhysicalAddress;
	if (xsdt == NULL)
		return (NULL);

	if (strncmp(xsdt->Header.Signature, ACPI_SIG_XSDT,
	    strlen(ACPI_SIG_XSDT)) != 0)
		return (NULL);

	return (xsdt);
}

static const ACPI_TABLE_HEADER *
find_acpi_table(const char *sig)
{
	const ACPI_TABLE_XSDT *xsdt;
	ACPI_TABLE_HEADER *tab;
	const UINT64 *entries;
	UINT64 entry;
	UINT32 nentries;
	UINT32 i;
	size_t slen;

	if ((xsdt = get_acpi_xsdt()) == NULL)
		return (NULL);

	slen = strlen(sig);
	nentries = (xsdt->Header.Length -
	    sizeof (xsdt->Header)) / ACPI_XSDT_ENTRY_SIZE;
	entries = &xsdt->TableOffsetEntry[0];
	tab = NULL;

	for (i = 0; i < nentries; ++i) {
		/*
		 * This is disgusting, and exists to avoid alignment issues
		 * that crop up because we're running without the MMU at this
		 * point, so the SCTLR.A flag is ignored.
		 */
		memcpy(&entry, &entries[i], sizeof (entry));
		if (entry == 0)
			continue;
		tab = (ACPI_TABLE_HEADER *)entry;
		if (strncmp(tab->Signature, sig, slen) == 0)
			break;
		tab = NULL;
	}

	if (tab == NULL)
		return (NULL);

	return (tab);
}

static const ACPI_TABLE_FADT *
get_fadt(void)
{
	const ACPI_TABLE_HEADER *hdr;

	if ((hdr = find_acpi_table(ACPI_SIG_FADT)) == NULL)
		return (NULL);

	return ((const ACPI_TABLE_FADT *)hdr);
}

static const ACPI_TABLE_MADT *
get_madt(void)
{
	const ACPI_TABLE_HEADER *hdr;

	if ((hdr = find_acpi_table(ACPI_SIG_MADT)) == NULL)
		return (NULL);

	return ((const ACPI_TABLE_MADT *)hdr);
}

static int
fill_xcpuinfo(const ACPI_MADT_GENERIC_INTERRUPT *gicc,
    struct xboot_cpu_info *xci)
{
	xci->xci_flags = 0;
	if (gicc->Flags & ACPI_MADT_ENABLED)
		xci->xci_flags |= CPUINFO_ENABLED;
	if (gicc->Flags & ACPI_MADT_ONLINE_CAPABLE)
		xci->xci_flags |= CPUINFO_ONLINE_CAPABLE;

	xci->xci_mpidr = gicc->ArmMpidr;

	if (gicc->ParkingVersion != 0) {
		dboot_printf("dboot: PSCI is the only supported "
		    "CPU enable method for ACPI systems");
		return (-1);
	}

	xci->xci_ppver = CPUINFO_ENABLE_METHOD_PSCI;
	xci->xci_parked_addr = 0;
	xci->xci_cpuif = gicc->CpuInterfaceNumber;
	xci->xci_uid = gicc->Uid;

	return (0);
}

static int
dboot_configure_acpi_cpuinfo(struct xboot_info *bi)
{
	const ACPI_TABLE_MADT *madt;
	const ACPI_SUBTABLE_HEADER *item;
	const ACPI_SUBTABLE_HEADER *end;
	const ACPI_MADT_GENERIC_INTERRUPT *gicc;
	struct xboot_cpu_info *xci;
	uint64_t boot_cpu_affinity;

	bi->bi_cpuinfo_cnt = 0;
	if ((xci = (struct xboot_cpu_info *)bi->bi_cpuinfo) == NULL)
		return (-1);

	boot_cpu_affinity = (read_mpidr() & MPIDR_AFF_MASK);

	if ((madt = get_madt()) == NULL)
		return (-1);

	end = (const ACPI_SUBTABLE_HEADER *)
	    (madt->Header.Length + (uintptr_t)madt);

	/*
	 * We iterate the CPU list twice. On the first pass we match the
	 * CPU we're running on (the boot CPU) and record it at index 0.
	 *
	 * On the second pass we match all other CPUs, recording them as
	 * we discover them.
	 */

	item = (const ACPI_SUBTABLE_HEADER *)
	    ((uintptr_t)madt + sizeof (*madt));

	while (item < end) {
		if (item->Type != ACPI_MADT_TYPE_GENERIC_INTERRUPT) {
			item = (const ACPI_SUBTABLE_HEADER *)
			    ((uintptr_t)item + item->Length);
			continue;
		}

		gicc = (const ACPI_MADT_GENERIC_INTERRUPT *)item;
		if (gicc->ArmMpidr != boot_cpu_affinity) {
			item = (const ACPI_SUBTABLE_HEADER *)
			    ((uintptr_t)item + item->Length);
			continue;
		}

		if (fill_xcpuinfo(gicc, &xci[bi->bi_cpuinfo_cnt]) != 0) {
			dboot_printf("dboot: error filling boot CPU info\n");
			return (-1);
		}

		xci[bi->bi_cpuinfo_cnt].xci_id = bi->bi_cpuinfo_cnt;
		bi->bi_cpuinfo_cnt++;
		break;
	}

	if (bi->bi_cpuinfo_cnt != 1) {
		dboot_printf("dboot: could not match boot processor in MADT\n");
		return (-1);
	}

	/*
	 * Second pass, populate APs.
	 */

	item = (const ACPI_SUBTABLE_HEADER *)
	    ((uintptr_t)madt + sizeof (*madt));

	while (item < end) {
		if (item->Type != ACPI_MADT_TYPE_GENERIC_INTERRUPT) {
			item = (const ACPI_SUBTABLE_HEADER *)
			    ((uintptr_t)item + item->Length);
			continue;
		}

		gicc = (const ACPI_MADT_GENERIC_INTERRUPT *)item;
		if (gicc->ArmMpidr == boot_cpu_affinity) {
			item = (const ACPI_SUBTABLE_HEADER *)
			    ((uintptr_t)item + item->Length);
			continue;
		}

		if (bi->bi_cpuinfo_cnt >= NCPU) {
			dboot_printf("dboot: number of CPUs exceeds NCPU\n");
			break;
		}

		if (fill_xcpuinfo(gicc, &xci[bi->bi_cpuinfo_cnt]) != 0) {
			dboot_printf(
			    "dboot: error filling application CPU info\n");
			return (-1);
		}

		xci[bi->bi_cpuinfo_cnt].xci_id = bi->bi_cpuinfo_cnt;
		bi->bi_cpuinfo_cnt++;

		item = (const ACPI_SUBTABLE_HEADER *)
		    ((uintptr_t)item + item->Length);
	}

	return (0);
}

int
dboot_configure_acpi(void)
{
	const ACPI_TABLE_FADT *fadt;
	extern struct xboot_info *bi;
	UINT16 flags;

	if ((fadt = get_fadt()) == NULL)
		panic("dboot: ACPI FADT not found\n");

	/* again, alignment issues */
	memcpy(&flags, &fadt->ArmBootFlags, sizeof (flags));

	if (!(flags & ACPI_FADT_PSCI_COMPLIANT))
		panic("dboot: illumos requires PSCI");

	bi->bi_psci_conduit_hvc = (flags & ACPI_FADT_PSCI_USE_HVC) ? 1 : 0;

	boot_psci_init(bi);
	return (dboot_configure_acpi_cpuinfo(bi));
}
