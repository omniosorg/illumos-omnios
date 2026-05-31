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

/*
 * EFI time representation (UEFI Specification 2.10, Section 8.3).
 *
 * Packed to match the UEFI wire format (16 bytes).  The Pad1 and Pad2
 * fields are required by the specification and must be zero.
 */
typedef struct {
	uint16_t	Year;		/* 1900-9999 */
	uint8_t		Month;		/* 1-12 */
	uint8_t		Day;		/* 1-31 */
	uint8_t		Hour;		/* 0-23 */
	uint8_t		Minute;		/* 0-59 */
	uint8_t		Second;		/* 0-59 */
	uint8_t		Pad1;
	uint32_t	Nanosecond;	/* 0-999999999 */
	int16_t		TimeZone;	/* -1440 to 1440, or 2047 */
	uint8_t		Daylight;
	uint8_t		Pad2;
} __packed EFI_TIME;

/* Daylight Savings Time field bits */
#define	EFI_TIME_ADJUST_DAYLIGHT	0x01
#define	EFI_TIME_IN_DAYLIGHT		0x02

/* Unspecified timezone sentinel */
#define	EFI_UNSPECIFIED_TIMEZONE	0x07FF

/*
 * EFI time capabilities (UEFI Specification 2.10, Section 8.3).
 *
 * Returned by GetTime() to describe the hardware clock's properties.
 * SetsToZero is a UEFI BOOLEAN (uint8_t), not an illumos boolean_t,
 * to match the specification's structure layout.
 */
typedef struct {
	uint32_t	Resolution;	/* counts per second */
	uint32_t	Accuracy;	/* error rate in ppm */
	uint8_t		SetsToZero;	/* TRUE = time resets on hw reset */
} EFI_TIME_CAPABILITIES;

extern void efi_reset_system(EFI_RESET_TYPE, uint64_t, uint64_t, void *);
extern uint64_t efi_get_time(EFI_TIME *, EFI_TIME_CAPABILITIES *);
extern uint64_t efi_set_time(EFI_TIME *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_EFIRT_H */
