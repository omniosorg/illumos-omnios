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
 * Boot "syscalls" for platform bringup
 */

#include <sys/types.h>
#include <sys/null.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>

extern void boot_uart_init(struct xboot_info *);
extern void boot_psci_init(struct xboot_info *);

extern int boot_uart_ischar(void);
extern int boot_uart_getchar(void);
extern void boot_uart_putchar(int);
extern void __NORETURN boot_psci_reset(bool);

static struct boot_syscalls boot_syscalls = {
	.bsvc_ischar = boot_uart_ischar,
	.bsvc_getchar = boot_uart_getchar,
	.bsvc_putchar = boot_uart_putchar,
	.bsvc_reset = boot_psci_reset,
};

struct boot_syscalls *sysp = &boot_syscalls;

/*
 * Boot services initialisation
 */
void
bsvc_init(struct xboot_info *xbp)
{
	boot_uart_init(xbp);
	boot_psci_init(xbp);
}
