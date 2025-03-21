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

#ifndef _BOOT_EARLY_UART_H
#define	_BOOT_EARLY_UART_H

/*
 * Debug-only fixed UART definitions for platform bringup and troubleshooting.
 *
 * Checked in copies of this files must always have:
 *   _EARLY_DBG_UART = 0
 *   EARLY_UART_PA = 0x0ULL
 *   EARLY_UART_TYPE = 0x0ULL
 */

#if !defined(_EARLY_DBG_UART)
#define	_EARLY_DBG_UART	0
#endif

#if defined(_EARLY_DBG_UART) && _EARLY_DBG_UART > 0
/*
 *    qemu sbsa-ref is: 0x60000000ULL, 0x000eULL
 *        qemu virt is: 0x09000000ULL, 0x000eULL
 *   Raspberry Pi 4 is: 0xfe201000ULL, 0x000eULL
 * Ampere Altra Max is: 0x100002620000ULL, 0x0003ULL
 */
#define	EARLY_UART_PA	0x0ULL
#define	EARLY_UART_TYPE	0x0ULL
#else	/* defined(_EARLY_DBG_UART) && _EARLY_DBG_UART > 0 */
#define	EARLY_UART_PA	0x0ULL
#define	EARLY_UART_TYPE	0x0ULL
#endif	/* !(defined(_EARLY_DBG_UART) && _EARLY_DBG_UART > 0) */

#endif /* _BOOT_EARLY_UART_H */
