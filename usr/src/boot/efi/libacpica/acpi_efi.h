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

#ifndef _ACPI_EFI_H
#define	_ACPI_EFI_H

/*
 * Loader-specific functions to initialise ACPI.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool acpi_efi_init(void);
extern bool acpi_efi_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* _ACPI_EFI_H */
