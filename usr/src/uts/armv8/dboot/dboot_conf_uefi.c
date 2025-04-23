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

const void *
dboot_uefi_get_acpi_rsdp(void)
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
