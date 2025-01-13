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
 * Helper utilities for MMIO UARTs and discovery libraries.
 */

#include <efi.h>
#include <efilib.h>

#include "mmio_uart.h"

/*
 * Print a string using the UEFI console output device.
 *
 * Used in debugging.
 */
void
mmio_uart_puts(const char *s)
{
	while (*s) {
		CHAR16 buf[2];
		EFI_STATUS status;

		buf[0] = *s;
		buf[1] = 0;

		status = ST->ConOut->TestString(ST->ConOut, buf);
		if (EFI_ERROR(status))
			buf[0] = '?';
		if (buf[0] == '\n')
			mmio_uart_puts("\r");
		ST->ConOut->OutputString(ST->ConOut, buf);
		++s;
	}
}

/*
 * Print an unsigned integer n in base b using the UEFI console output device.
 *
 * Used in debugging.
 */
void
mmio_uart_putn(unsigned long n, int b)
{
	unsigned long a;
	char buf[2];

	if ((a = n/b))
		mmio_uart_putn(a, b);
	buf[0] = "0123456789abcdef"[n % b];
	buf[1] = '\0';
	mmio_uart_puts(buf);
}

/*
 * Allocate a physical memory page below the 4GiB mark.
 *
 * Allows for a 64KiB page size.
 *
 * WARNING: This is not a portable function, and will only succeed for systems
 * that have available physical memory below 4GiB (such as rpi4).
 */
void *
mmio_uart_alloc_low_page(void)
{
	EFI_PHYSICAL_ADDRESS pa = 0xFFFEFFFF;
	if (BS->AllocatePages(AllocateMaxAddress,
	    EfiLoaderData, 1, &pa) != EFI_SUCCESS)
		return (NULL);
	return ((void *)pa);
}

/*
 * Free a memory page allocated by 'mmio_uart_alloc_low_page`.
 */
void
mmio_uart_free_low_page(void *addr)
{
	EFI_PHYSICAL_ADDRESS pa = (EFI_PHYSICAL_ADDRESS)addr;
	if (pa == 0)
		return;
	BS->FreePages(pa, 1);
}
