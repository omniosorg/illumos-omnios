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
 * Support for fixed-clock FDT clocks.
 */

#include <sys/types.h>

#include "fdtuart.h"

uint64_t
fdtuart_fixed_clock_get_clock_rate(const void *fdtp,
    int clkoff, const uint32_t *spec)
{
	switch (fdtuart_get_clock_cells(fdtp, clkoff)) {
	case 0:
		break;
	default:
		return (0);
	}

	return (fdtuart_get_clock_frequency(fdtp, clkoff));
}
