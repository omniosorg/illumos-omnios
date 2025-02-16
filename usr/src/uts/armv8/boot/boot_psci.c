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
 * Boot "syscalls" for system reset.
 */

#include <sys/types.h>
#include <sys/null.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>
#include <sys/psci.h>

extern boolean_t psci_initialized;

/*
 * PSCI implementation.
 *
 * illumos has a hard dependency on PSCI.
 */

void __NORETURN
boot_psci_reset(bool poff)
{
	if (psci_initialized) {
		if (poff)
			psci_system_off();
		else
			psci_system_reset();
	}

	/*
	 * Turn off SError, debug, IRQ and FIQ, sync the
	 * world, then wait for an event. Rinse, repeat.
	 */
	for (;;) {
		__asm__ volatile("msr DAIFSet, #15":::"memory");
		__asm__ volatile("dsb sy":::"memory");
		__asm__ volatile("isb sy":::"memory");
		__asm__ volatile("wfe":::"memory");
	}

	/* UNREACHABLE */
}

void __NORETURN
_reset(bool poff)
{
	boot_psci_reset(poff);
	/* UNREACHABLE */
}

/*
 * Boot services initialisation
 */
void
boot_psci_init(struct xboot_info *xbp)
{
	static const char no_psci_str[] = "boot: Unable to initialize PSCI";
	int rv;
	extern void boot_uart_putchar(int c);

	if (xbp == NULL || psci_initialized == B_TRUE)
		return;

	rv = psci_init(xbp);

	/*
	 * If PSCI init fails we end up calling the PROM when we try to call
	 * PSCI, which is not what we want in boot, so do an early check to
	 * catch problems.
	 */
	if (rv != 0 || psci_initialized == B_FALSE) {
		const char *no_psci = no_psci_str;
		psci_initialized = B_FALSE;
		do {
			boot_uart_putchar(*no_psci);
		} while (*no_psci++);
		boot_uart_putchar('\n');
		boot_psci_reset(true);
		/* UNREACHABLE */
	}
}
