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
#include <sys/efi.h>
#include <sys/psci.h>
#include <sys/acpi/platform/acsolaris.h>
#include <sys/acpi/actypes.h>
#include <sys/acpi/actbl.h>

#include "dboot.h"

extern void boot_psci_init(struct xboot_info *);

static efi_guid_t acpi2 = EFI_ACPI_TABLE_GUID;


static const EFI_SYSTEM_TABLE64 *
get_uefi_systab(void)
{
	EFI_SYSTEM_TABLE64 *st;
	extern struct xboot_info *bi;

	if (bi->bi_uefi_systab == 0)
		return (NULL);

	st = (EFI_SYSTEM_TABLE64 *)bi->bi_uefi_systab;

	if (st->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE)
		return (NULL);

	if (st->Hdr.Revision < EFI_REV(2, 5))
		return (NULL);

	return (st);
}

static bool
same_guids(efi_guid_t *g1, efi_guid_t *g2)
{
	size_t i;

	if (g1->time_low != g2->time_low)
		return (false);
	if (g1->time_mid != g2->time_mid)
		return (false);
	if (g1->time_hi_and_version != g2->time_hi_and_version)
		return (false);
	if (g1->clock_seq_hi_and_reserved != g2->clock_seq_hi_and_reserved)
		return (false);
	if (g1->clock_seq_low != g2->clock_seq_low)
		return (false);
	for (i = 0; i < 6; i++)
		if (g1->node_addr[i] != g2->node_addr[i])
			return (false);

	return (true);
}

static const ACPI_TABLE_RSDP *
get_acpi_rsdp(void)
{
	efi_guid_t vguid;
	const EFI_SYSTEM_TABLE64 *st;
	const EFI_CONFIGURATION_TABLE64 *cf;
	const ACPI_TABLE_RSDP *rsdp;
	UINT32 i;

	if ((st = get_uefi_systab()) == NULL)
		return (NULL);

	cf = (const EFI_CONFIGURATION_TABLE64 *)st->ConfigurationTable;
	if (cf == NULL)
		return (NULL);

	rsdp = NULL;

	for (i = 0; i < st->NumberOfTableEntries; ++i) {
		memcpy(&vguid, &cf[i].VendorGuid, sizeof (vguid));
		if (same_guids(&vguid, &acpi2)) {
			rsdp = (const ACPI_TABLE_RSDP *)cf[i].VendorTable;
			break;
		}
	}

	if (rsdp == NULL)
		return (NULL);

	if (strncmp(rsdp->Signature, ACPI_SIG_RSDP, strlen(ACPI_SIG_RSDP)) != 0)
		return (NULL);

	if (rsdp->Revision < 2)
		return (NULL);

	return (rsdp);
}

static const ACPI_TABLE_XSDT *
get_acpi_xsdt(void)
{
	const ACPI_TABLE_RSDP *rsdp;
	const ACPI_TABLE_XSDT *xsdt;

	if ((rsdp = get_acpi_rsdp()) == NULL)
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
	return (0);
}
