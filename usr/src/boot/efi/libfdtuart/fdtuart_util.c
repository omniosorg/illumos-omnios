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
 * Utility functions used in devicetree traversal and interrogation.
 */

#include <mmio_uart.h>
#include <libfdt.h>

#include "fdtuart.h"

int
fdtuart_phandle_from_prop(const void *fdtp, int nodeoff, const char *propname)
{
	const void *prop;
	int proplen;

	if ((prop = fdt_getprop(fdtp, nodeoff, propname, &proplen)) == NULL)
		return (-1);

	if (proplen < (sizeof (uint32_t)))
		return (-1);

	return (fdt_node_offset_by_phandle(fdtp,
	    fdt32_to_cpu(*((const uint32_t *)prop))));
}

/*
 * Look up the #address-cells property on the passed node. If not
 * found, continue looking up the tree.
 *
 * If we get to the root node, return the default #address-cells value,
 * which is 2.
 *
 * Returns <0 if any errors occur, the number of address cells otherwise.
 */
static int
fdtuart_address_cells(const void *fdtp, int nodeoff)
{
	int poff;

	if (fdt_getprop(fdtp, nodeoff, "#address-cells", NULL) != NULL)
		return (fdt_address_cells(fdtp, nodeoff));

	if (nodeoff == 0)
		return (2);

	if ((poff = fdt_parent_offset(fdtp, nodeoff)) < 0)
		return (-1);

	return (fdtuart_address_cells(fdtp, poff));
}

/*
 * Look up the #size-cells property on the passed node's parent. If not
 * found, continue looking up the tree.
 *
 * If we get to the root node as the passed node's parent return the default
 * #size-cells value, which is 1.
 *
 * Returns <0 if any errors occur, the number of size cells otherwise.
 */
static int
fdtuart_size_cells(const void *fdtp, int nodeoff)
{
	int poff;

	if (fdt_getprop(fdtp, nodeoff, "#size-cells", NULL) != NULL)
		return (fdt_size_cells(fdtp, nodeoff));

	if (nodeoff == 0)
		return (1);

	if ((poff = fdt_parent_offset(fdtp, nodeoff)) < 0)
		return (-1);

	return (fdtuart_size_cells(fdtp, poff));
}

static bool
fdtuart_get_reg(const void *fdtp, int nodeoff, int frame,
    uint64_t *reg, uint64_t *reglen)
{
	const uint32_t *regprop;
	int regprop_len;
	int regprop_ncells;
	int address_cells;
	int size_cells;
	int n;
	int m;

	if ((address_cells = fdtuart_address_cells(fdtp, nodeoff)) <= 0)
		return (false);

	if ((size_cells = fdtuart_size_cells(fdtp, nodeoff)) <= 0)
		return (false);

	if ((regprop = fdt_getprop(fdtp, nodeoff, "reg", &regprop_len)) == NULL)
		return (false);

	if (regprop_len % (sizeof (uint32_t)))
		return (false);
	regprop_ncells = regprop_len / (sizeof (uint32_t));

	n = frame * (address_cells + size_cells);
	m = n + address_cells + size_cells;

	if (m > regprop_ncells)
		return (false);

	for (*reg = 0; n < (m - size_cells); ++n) {
		*reg <<= 32;
		*reg = *reg | fdt32_to_cpu(regprop[n]);
	}

	for (*reglen = 0; n < m; ++n) {
		*reglen <<= 32;
		*reglen = *reglen | fdt32_to_cpu(regprop[n]);
	}

	return (true);
}

static bool
fdtuart_apply_ranges_(const void *fdtp, const char *propname,
    int busoff, int buspoff, uint64_t *reg, uint64_t reg_len, int bottom_up)
{
	const struct fdt_property *prop;
	const uint32_t *rngprop;
	int rngprop_len;
	int stride;
	int nrng;
	int cac;
	int pac;
	int csc;
	int poff;
	int idx;

	/*
	 * In the bottom-up case we recurse up the tree prior to applying our
	 * ranges. This allows dma-ranges translation from CPU physical
	 * addresses to bus-visible addresses.
	 */
	if (bottom_up) {
		/*
		 * If our parent is the root we have no need to recurse, as
		 * the root nexus can't have ranges.
		 */
		if (buspoff != 0) {
			/* apply parent ranges before applying child ranges */
			if ((poff = fdt_parent_offset(fdtp, buspoff)) < 0)
				return (false);

			if (fdtuart_apply_ranges_(fdtp, propname, buspoff,
			    poff, reg, reg_len, bottom_up) != 0)
				return (false);
		}
	}

	/*
	 * We must have the requested property (ranges or dma-ranges). Absence
	 * implies that no translation is possible.
	 */
	if ((prop = fdt_get_property(fdtp,
	    busoff, propname, &rngprop_len)) == NULL)
		return (false);

	/*
	 * When we have an empty property (indicating identity mapping) and
	 * we're applying ranges bottom-up, then we're done at this level.
	 */
	if (bottom_up && rngprop_len == 0)
		return (true);

	/*
	 * When we have an empty property (indicating identity mapping) and
	 * we're applying ranges top-down, then we have no ranges to apply
	 * at this level and we should now recurse to the parent bus, unless
	 * that parent is the tree root, in which case we're just done.
	 */
	if (!bottom_up && rngprop_len == 0) {
		if (buspoff == 0)
			return (true);	/* root has no ranges */
		if ((poff = fdt_parent_offset(fdtp, buspoff)) < 0)
			return (false);
		return (fdtuart_apply_ranges_(
		    fdtp, propname, buspoff, poff, reg, reg_len, bottom_up));
	}

	/*
	 * We have ranges to apply at this level. Working these out is the
	 * same in the top-down and bottom-up cases, it's just how we apply
	 * them that very slightly differs.
	 */

	rngprop = (const uint32_t *)prop->data;

	if ((cac = fdtuart_address_cells(fdtp, busoff)) <= 0)
		return (false);

	if ((pac = fdtuart_address_cells(fdtp, buspoff)) <= 0)
		return (false);

	if ((csc = fdtuart_size_cells(fdtp, busoff)) <= 0)
		return (false);

	stride = cac + pac + csc;

	if (rngprop_len % (sizeof (uint32_t)))
		return (false);
	rngprop_len /= (sizeof (uint32_t));

	if (rngprop_len % stride)
		return (false);
	nrng = rngprop_len / stride;

	for (idx = 0; idx < nrng; ++idx) {
		uint64_t rng_coffset;
		uint64_t rng_offset;
		uint64_t rng_size;
		uint64_t suboff;
		uint64_t addoff;
		int n;
		int m;

		n = (idx * stride);
		m = n + stride;

		for (rng_coffset = 0; n < (m - pac - csc); ++n) {
			rng_coffset <<= 32;
			rng_coffset |= fdt32_to_cpu(rngprop[n]);
		}

		for (rng_offset = 0; n < (m - csc); ++n) {
			rng_offset <<= 32;
			rng_offset |= fdt32_to_cpu(rngprop[n]);
		}

		for (rng_size = 0; n < m; ++n) {
			rng_size <<= 32;
			rng_size |= fdt32_to_cpu(rngprop[n]);
		}

		/*
		 * Here's the core of the difference in how we apply the ranges
		 * differently between top-down and bottom-up.
		 *
		 * In the top down case we check against the child offset for
		 * a fit, then subtract the child offset and add the parent
		 * offset.
		 *
		 * The bottom-up case is the opposite. We check against the
		 * parent offset for a fit, then subtract the parent offset
		 * and all the child offset.
		 */
		if (bottom_up) {
			suboff = rng_offset;
			addoff = rng_coffset;
		} else {
			suboff = rng_coffset;
			addoff = rng_offset;
		}

		/*
		 * If it fits, apply it
		 */
		if (*reg < suboff)
			continue;

		if (rng_size == 0 ||
		    (*reg + reg_len - 1) <= (suboff + rng_size - 1)) {
			*reg = (*reg - suboff) + addoff;
			break;
		}
	}

	/*
	 * If we did not match a declared range then translation has failed.
	 */
	if (idx == nrng)
		return (false);	/* if no range was applied it's an error */

	/*
	 * In the bottom-up case we've already recursed at the head of the
	 * function, so we're done.
	 */
	if (bottom_up)
		return (true);

	/*
	 * In the top-down case we need to recurse at the tail of the
	 * function, but if our current parent is the root we're done (since
	 * the root cannot have ranges).
	 */
	if (buspoff == 0)
		return (true);

	/*
	 * Find the bus grandparent and recurse, passing the parent and
	 * grandparent to identify the next level.
	 */

	if ((poff = fdt_parent_offset(fdtp, buspoff)) < 0)
		return (false);

	return (fdtuart_apply_ranges_(fdtp, propname,
	    buspoff, poff, reg, reg_len, bottom_up));
}

static bool
fdtuart_apply_ranges_impl(const void *fdtp, const char *propname, int nodeoff,
    uint64_t *reg, uint64_t reg_len, int bottom_up)
{
	int busoff;
	int buspoff;

	/* resolve the bus */
	busoff = fdt_parent_offset(fdtp, nodeoff);
	if (busoff < 0)
		return (false);	/* error */
	if (busoff == 0)
		return (true);	/* root node has no ranges */

	/* resolve the bus parent */
	if ((buspoff = fdt_parent_offset(fdtp, busoff)) < 0)
		return (false);

	return (fdtuart_apply_ranges_(fdtp, propname,
	    busoff, buspoff, reg, reg_len, bottom_up));
}

static bool
fdtuart_apply_ranges(const void *fdtp, int nodeoff,
    uint64_t *reg, uint64_t reg_len)
{
	return (fdtuart_apply_ranges_impl(
	    fdtp, "ranges", nodeoff, reg, reg_len, 0));
}

bool
fdtuart_bus_to_phys(const void *fdtp, int nodeoff,
    uint64_t *addr, uint64_t addr_len)
{
	return (fdtuart_apply_ranges_impl(
	    fdtp, "dma-ranges", nodeoff, addr, addr_len, 0));
}

bool
fdtuart_phys_to_bus(const void *fdtp, int nodeoff,
    uint64_t *addr, uint64_t addr_len)
{
	return (fdtuart_apply_ranges_impl(
	    fdtp, "dma-ranges", nodeoff, addr, addr_len, 1));
}

bool
fdtuart_resolve_reg(const void *fdtp, int nodeoff, int frame,
    uint64_t *reg, uint64_t *reg_len)
{
	/*
	 * Get the raw register value.
	 */
	if (!fdtuart_get_reg(fdtp, nodeoff, frame, reg, reg_len))
		return (false);

	/*
	 * Now apply ranges to resolve the CPU-visible register address.
	 */
	return (fdtuart_apply_ranges(fdtp, nodeoff, reg, *reg_len));
}

/*
 * Returns true if the node status property indicates that the node is usable.
 *
 * Usable is defined as:
 * - The status property does not exist
 * - The status property exists and has the value "okay" or the value "ok"
 *
 * Returns false on error or when the above conditions are not met.
 */
bool
fdtuart_node_status_okay(const void *fdtp, int nodeoff)
{
	const char *prop;
	int proplen;

	if ((prop = fdt_getprop(fdtp, nodeoff, "status", &proplen)) == NULL)
		return (true);

	if (proplen == 0)
		return (false);

	if (strcmp(prop, "ok") == 0 || strcmp(prop, "okay") == 0)
		return (true);

	return (false);
}
