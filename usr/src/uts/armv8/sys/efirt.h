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

#ifndef _SYS_EFIRT_H
#define	_SYS_EFIRT_H

/*
 * UEFI Runtime Services types and declarations.
 */

#include <sys/efi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * EFI reset types (UEFI Specification 2.10, Section 8.5.1).
 */
typedef enum {
	EfiResetCold,
	EfiResetWarm,
	EfiResetShutdown,
	EfiResetPlatformSpecific
} EFI_RESET_TYPE;

extern void efi_reset_system(EFI_RESET_TYPE, uint64_t, uint64_t, void *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_EFIRT_H */
