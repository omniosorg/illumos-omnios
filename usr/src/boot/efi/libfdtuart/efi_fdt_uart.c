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
 * Obtain the FDT pointer and, if present, discover supported MMIO UARTs in
 * the devicetree.
 */

#include <libfdtutil.h>

extern void fdtuart_discover_uarts(const void *fdtp);

void
fdtuart_ini(void)
{
	const void	*fdtp;

	if (!(fdtp = efi_get_fdtp()))
		return;

	fdtuart_discover_uarts(fdtp);
}
