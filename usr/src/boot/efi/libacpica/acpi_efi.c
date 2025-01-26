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
 * ACPICA initialisation for UEFI in the illumos loader
 */

#include <acpi.h>
#include <aclocal.h>
#include <acobject.h>
#include <acstruct.h>
#include <acnamesp.h>
#include <acutils.h>
#include <acmacros.h>
#include <acevents.h>
#include <actbl.h>
#include <actbl1.h>
#include <actbl3.h>

#include "acpi_efi.h"

typedef enum {
	ACPI_EFI_UNINITIALISED,
	ACPI_EFI_INIT_FAILED,
	ACPI_EFI_INIT_SUCCESS
} acpi_efi_init_status_t;

static acpi_efi_init_status_t acpica_init_status = ACPI_EFI_UNINITIALISED;

bool
acpi_efi_init(void)
{
	ACPI_STATUS status;

	switch (acpica_init_status) {
	case ACPI_EFI_UNINITIALISED:
		break;
	case ACPI_EFI_INIT_FAILED:
		return (false);
	case ACPI_EFI_INIT_SUCCESS:
		return (true);
	}

	acpica_init_status = ACPI_EFI_INIT_FAILED;

	status = AcpiInitializeSubsystem();
	if (ACPI_FAILURE(status))
		return (false);

	status = AcpiInitializeTables(NULL, 16, TRUE);
	if (ACPI_FAILURE(status))
		return (false);

	status = AcpiLoadTables();
	if (ACPI_FAILURE(status))
		return (false);

	status = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
	if (ACPI_FAILURE(status))
		return (false);

	status = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
	if (ACPI_FAILURE(status))
		return (false);

	acpica_init_status = ACPI_EFI_INIT_SUCCESS;
	return (true);
}

bool
acpi_efi_fini(void)
{
	ACPI_STATUS status;

	if (acpica_init_status == ACPI_EFI_UNINITIALISED)
		return (true);

	status = AcpiTerminate();
	if (ACPI_FAILURE(status)) {
		acpica_init_status = ACPI_EFI_INIT_FAILED;
		return (false);
	}

	acpica_init_status = ACPI_EFI_UNINITIALISED;
	return (true);
}
