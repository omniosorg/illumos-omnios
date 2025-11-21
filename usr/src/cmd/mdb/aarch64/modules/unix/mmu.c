/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>

#include <vm/page.h>

#include <mdb/mdb_modapi.h>

/*
 * ::memseg_list dcmd and walker to implement it.
 */
/*ARGSUSED*/
int
memseg_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct memseg ms;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_pwalk_dcmd("memseg", "memseg_list",
		    0, NULL, 0) == -1) {
			mdb_warn("can't walk memseg");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %?s %?s %?s %?s%</u>\n", "ADDR",
		    "PAGES", "EPAGES", "BASE", "END");

	if (mdb_vread(&ms, sizeof (struct memseg), addr) == -1) {
		mdb_warn("can't read memseg at %#lx", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?lx %0?lx %0?lx %0?lx %0?lx\n", addr,
	    ms.pages, ms.epages, ms.pages_base, ms.pages_end);

	return (DCMD_OK);
}

/*
 * walk the memseg structures
 */
int
memseg_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		mdb_warn("memseg only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&wsp->walk_addr, "memsegs") == -1) {
		mdb_warn("symbol 'memsegs' not found");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (struct memseg), UM_SLEEP);
	return (WALK_NEXT);

}

int
memseg_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (struct memseg),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct memseg at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((struct memseg *)wsp->walk_data)->next);

	return (status);
}

void
memseg_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct memseg));
}
