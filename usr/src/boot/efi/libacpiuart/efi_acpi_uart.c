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

/*
 * Validate that the system is running with ACPI configuration tables.
 *
 * Once validated, initialise ACPICA and discover MMIO UARTs from ACPI.
 */

#include <efi.h>
#include <efilib.h>
#include <Guid/Acpi.h>

#include <acpi_efi.h>

extern void acpiuart_discover_uarts(void);

void
acpiuart_ini(void)
{
	if (efi_get_table(&gEfiAcpi20TableGuid) == NULL)
		return;

	if (acpi_efi_init())
		acpiuart_discover_uarts();

	acpi_efi_fini();
}
