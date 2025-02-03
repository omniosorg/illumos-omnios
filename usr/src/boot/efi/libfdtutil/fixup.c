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
 * FDT fixups, to make things more predictable for the kernel.
 *
 * The illumos device tree prom integration relies on all FDT nodes having
 * a phandle, which becomes the DDI node ID, allowing easy translation between
 * device tree nodes and FDT nodes. In the FDT world a phandle is only needed
 * when a node is referenced from another node. To make this all hang together
 * we assign a phandle to all nodes in the FDT.
 *
 * The illumos kernel expects a set of common top-level nodes which are not
 * always present (/chosen, /options and /alias). We ensure that these nodes
 * are created and have phandles.
 *
 * This editing of the FDT is the last time the tree is mutated. Once we
 * hand off to the kernel via dboot the tree is treated as read-only.
 */

#include <stand.h>
#include <libfdt.h>
#include <fdt.h>

#define	FDT_FIX_PHANDLE_SUCCESS	0
#define	FDT_FIX_PHANDLE_AGAIN	1
#define	FDT_FIX_PHANDLE_FAILURE	2


static int
i_fix_phandle(void *fdtp, int node)
{
	int err;
	uint32_t phandle;

	phandle = fdt_get_phandle(fdtp, node);
	if (phandle > 0)
		return (FDT_FIX_PHANDLE_SUCCESS);

	err = fdt_generate_phandle(fdtp, &phandle);
	if (err != 0)
		return (FDT_FIX_PHANDLE_FAILURE);

	err = fdt_setprop_u32(fdtp, node, "phandle", phandle);
	if (err != 0)
		return (FDT_FIX_PHANDLE_FAILURE);

	return (FDT_FIX_PHANDLE_AGAIN);
}

static int
fix_phandle(void *fdtp, int node)
{
	int err;
	int offset;

	err = i_fix_phandle(fdtp, node);
	if (err != FDT_FIX_PHANDLE_SUCCESS)
		return (err);

	fdt_for_each_subnode(offset, fdtp, node) {
		err = fix_phandle(fdtp, offset);
		if (err != FDT_FIX_PHANDLE_SUCCESS)
			return (err);
	}

	return (FDT_FIX_PHANDLE_SUCCESS);
}

static void
fix_phandles(void *fdtp)
{
	int err;
	int offset;

	switch (i_fix_phandle(fdtp, 0)) {
	case FDT_FIX_PHANDLE_AGAIN:	/* fallthrough */
	case FDT_FIX_PHANDLE_SUCCESS:
		break;
	default:
		panic("fdtutil: failed to fix devicetree phandles\n");
	}

again:
	fdt_for_each_subnode(offset, fdtp, 0) {
		err = fix_phandle(fdtp, offset);
		if (err == FDT_FIX_PHANDLE_AGAIN)
			goto again;
		else if (err != FDT_FIX_PHANDLE_SUCCESS)
			panic("fdtutil: failed to fix devicetree phandles\n");
	}
}

static void
ensure_toplevel_node(void *fdtp, const char *name)
{
	int offset;

	fdt_for_each_subnode(offset, fdtp, 0) {
		const char *n = fdt_get_name(fdtp, offset, NULL);
		if (n && strcmp(n, name) == 0)
			return;
	}

	fdt_add_subnode(fdtp, 0, name);
}

void
fdtutil_fdt_fixup(void *fdtp)
{
	ensure_toplevel_node(fdtp, "chosen");
	ensure_toplevel_node(fdtp, "options");
	ensure_toplevel_node(fdtp, "alias");
	fix_phandles(fdtp);
}
