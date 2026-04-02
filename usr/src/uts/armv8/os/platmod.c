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

#include <sys/systm.h>
#include <sys/machclock.h>
#include <sys/efi.h>
#include <sys/efirt.h>

/*
 * All platmod functions are weak and are only present when required.
 * The function calls have been converted to use methods
 *	if (&plat_func)
 *		plat_func(args);
 */

/*
 * Platform power management drivers list - empty by default
 */
char *platform_module_list[] = {
	NULL
};

void
plat_tod_fault(enum tod_fault_type tod_bad __unused)
{
}

void
set_platform_defaults(void)
{
	EFI_TIME t;
	EFI_TIME_CAPABILITIES tc;

	if (efi_get_time(&t, &tc) == EFI_SUCCESS) {
		tod_module_name = "efitod";
	}
}
