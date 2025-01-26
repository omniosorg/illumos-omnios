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
 * OS Layer stub functions for ACPI in the aarch64 illumos loader.
 */
#include <acpi.h>
#include <stdio.h>

ACPI_STATUS
AcpiOsPhysicalTableOverride(ACPI_TABLE_HEADER *ExistingTable,
    ACPI_PHYSICAL_ADDRESS *NewAddress, UINT32 *NewTableLength)
{
	return (AE_SUPPORT);
}

ACPI_STATUS
AcpiOsWritePort(ACPI_IO_ADDRESS Address, UINT32 Value, UINT32 Width)
{
	return (AE_SUPPORT);
}

ACPI_STATUS
AcpiOsReadPort(ACPI_IO_ADDRESS Address, UINT32 *Value, UINT32 Width)
{
	return (AE_SUPPORT);
}

#define	OSL_RW(ptr, val, type, rw) \
	{ if (rw) *((type *)(ptr)) = *((type *) val); \
	else *((type *) val) = *((type *)(ptr)); }

static void
osl_rw_memory(ACPI_PHYSICAL_ADDRESS Address, UINT64 *Value,
    UINT32 Width, int write)
{
	char *ptr = (char *)Address;

	switch (Width / 8) {
	case 1:
		OSL_RW(ptr, Value, uint8_t, write);
		break;
	case 2:
		OSL_RW(ptr, Value, uint16_t, write);
		break;
	case 4:
		OSL_RW(ptr, Value, uint32_t, write);
		break;
	case 8:
		OSL_RW(ptr, Value, uint64_t, write);
		break;
	default:
		break;
	}
}

ACPI_STATUS
AcpiOsReadMemory(ACPI_PHYSICAL_ADDRESS Address, UINT64 *Value, UINT32 Width)
{
	osl_rw_memory(Address, Value, Width, 0);
	return (AE_OK);
}

ACPI_STATUS
AcpiOsWriteMemory(ACPI_PHYSICAL_ADDRESS Address, UINT64 Value, UINT32 Width)
{
	osl_rw_memory(Address, &Value, Width, 1);
	return (AE_OK);
}

ACPI_STATUS
AcpiOsTableOverride(ACPI_TABLE_HEADER *ExistingTable,
    ACPI_TABLE_HEADER **NewTable)
{
	if (!ExistingTable || !NewTable) {
		return (AE_BAD_PARAMETER);
	}

	*NewTable = NULL;
	return (AE_NO_ACPI_TABLES);
}
