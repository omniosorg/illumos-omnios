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
 * Rough-and-ready FDT clock reading support for supported UARTs/boards.
 *
 * This file wraps up clock drivers behind a consistent interface, walking
 * the clocks cells array and calling the relevant driver.
 */

#include <libfdt.h>

#include "fdtuart.h"

uint64_t fdtuart_bcm2835_cprman_get_clock_rate(
    const void *fdtp, int clkoff, const uint32_t *spec);
uint64_t fdtuart_fixed_clock_get_clock_rate(
    const void *fdtp, int clkoff, const uint32_t *spec);

typedef uint64_t (*clock_resolver_func_t)(const void *, int, const uint32_t *);

typedef struct {
	const char		*cr_compat;
	clock_resolver_func_t	cr_func;
} clock_resolver_t;

static const clock_resolver_t fdtuart_clock_resolvers[] = {
	{
		.cr_compat = "fixed-clock",
		.cr_func = fdtuart_fixed_clock_get_clock_rate,
	},
	{
		.cr_compat = "brcm,bcm2711-cprman",
		.cr_func = fdtuart_bcm2835_cprman_get_clock_rate,
	},
	{
		.cr_compat = "brcm,bcm2835-cprman",
		.cr_func = fdtuart_bcm2835_cprman_get_clock_rate,
	},
};
static const size_t fdtuart_clock_resolvers_num =
    sizeof (fdtuart_clock_resolvers) / sizeof (fdtuart_clock_resolvers[0]);

uint32_t
fdtuart_get_clock_cells(const void *fdtp, int nodeoff)
{
	const void *clock_cells_prop;
	int clock_cells_proplen;

	clock_cells_prop = fdt_getprop(fdtp, nodeoff,
	    "#clock-cells", &clock_cells_proplen);
	if (clock_cells_prop == NULL)
		return (FDTUART_BAD_CLOCK_CELLS);
	if (clock_cells_proplen != (sizeof (uint32_t)))
		return (FDTUART_BAD_CLOCK_CELLS);

	return (fdt32_to_cpu(*((const uint32_t *)clock_cells_prop)));
}

/*
 * Return the value of the clock-frequency property on this node.
 *
 * On error, or if no such property is present, return 0.
 */
uint64_t
fdtuart_get_clock_frequency(const void *fdtp, int nodeoff)
{
	const void *clock_frequency_prop;
	int clock_frequency_proplen;

	clock_frequency_prop = fdt_getprop(fdtp, nodeoff,
	    "clock-frequency", &clock_frequency_proplen);
	if (clock_frequency_prop == NULL)
		return (0);

	switch (clock_frequency_proplen) {
	case sizeof (uint32_t):
		return (fdt32_to_cpu(
		    *((const uint32_t *)clock_frequency_prop)));
	case sizeof (uint64_t):
		return (fdt64_to_cpu(
		    *((const uint64_t *)clock_frequency_prop)));
	default:
		break;
	}

	return (0);
}

static uint64_t
fdtuart_get_clock_rate_inner(const void *fdtp, const uint32_t *spec)
{
	size_t n;
	int clkoff = fdt_node_offset_by_phandle(fdtp, fdt32_to_cpu(spec[0]));

	for (n = 0; n < fdtuart_clock_resolvers_num; ++n) {
		if (fdtuart_clock_resolvers[n].cr_compat == NULL ||
		    fdtuart_clock_resolvers[n].cr_func == NULL)
			continue;

		if (fdt_node_check_compatible(fdtp, clkoff,
		    fdtuart_clock_resolvers[n].cr_compat) == 0)
			return (fdtuart_clock_resolvers[n].cr_func(
			    fdtp, clkoff, spec + 1));
	}

	return (0);
}

/*
 * Return the rate (frequency) of the requested clock.
 *
 * If unsupported, or not present, or on error, return 0.
 */
uint64_t
fdtuart_get_clock_rate(const void *fdtp, int nodeoff, int which)
{
	const uint32_t *clocks_prop;
	uint32_t clock_cells;
	int clocks_proplen;
	int idx;
	int clkidx;

	clocks_prop = fdt_getprop(fdtp, nodeoff, "clocks", &clocks_proplen);
	if (clocks_prop == NULL)
		return (0);
	if (clocks_proplen % (sizeof (uint32_t)))
		return (0);
	clocks_proplen /= (sizeof (uint32_t));

	/*
	 * Walk the clocks property, which is an array of cells. There is no
	 * consistent stride, but each clock index starts with a phandle to
	 * a clock driver and is followed by zero or more cells containing
	 * driver-specific data. We read the clock cells from the phandle
	 * to determine the stride to the next clock phandle.
	 */
	idx = clkidx = 0;
	while (idx < clocks_proplen) {
		if (clkidx == which)
			return (fdtuart_get_clock_rate_inner(
			    fdtp, &clocks_prop[idx]));

		clock_cells = fdtuart_get_clock_cells(fdtp,
		    fdt32_to_cpu(clocks_prop[idx]));
		if (clock_cells == FDTUART_BAD_CLOCK_CELLS)
			return (0);

		idx += (clock_cells + 1);
		clkidx++;
	}

	return (0);
}
