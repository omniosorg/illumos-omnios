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

#include <vm/hat_aarch64.h>

#include <mdb/mdb_modapi.h>

#include "mmu.h"

typedef struct {
	hat_t htw_hat;
	uint_t htw_bucket;
} htables_walk_data_t;

int
htables_walk_init(mdb_walk_state_t *wsp)
{
	init_mmu();

	if (mmu.num_level == 0)
		return (WALK_ERR);

	if (wsp->walk_addr == 0) {
		mdb_warn("missing hat address\n");
		return (WALK_ERR);
	}

	htables_walk_data_t *htw = mdb_zalloc(sizeof (htables_walk_data_t),
	    UM_SLEEP);

	if (mdb_vread(&htw->htw_hat, sizeof (hat_t), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read struct hat");
		mdb_free(htw, sizeof (htables_walk_data_t));
		return (WALK_ERR);
	}

	wsp->walk_addr = 0;
	wsp->walk_data = htw;

	while (wsp->walk_addr == 0) {
		uintptr_t baddr = (uintptr_t)(htw->htw_hat.hat_ht_hash +
		    htw->htw_bucket);

		if (mdb_vread(&wsp->walk_addr, sizeof (htable_t *),
		    baddr) == -1) {
			mdb_warn("couldn't read htable ptr %p", baddr);
			mdb_free(wsp->walk_data, sizeof (htables_walk_data_t));
			wsp->walk_data = NULL;
			return (WALK_ERR);
		}

		if (wsp->walk_addr != 0)
			break;

		htw->htw_bucket += 1;
		if (htw->htw_bucket >= mmu.hash_cnt) {
			mdb_free(wsp->walk_data, sizeof (htables_walk_data_t));
			wsp->walk_data = NULL;
			return (WALK_DONE);
		}
	}

	return (WALK_NEXT);
}

int
htables_walk_step(mdb_walk_state_t *wsp)
{
	htables_walk_data_t *htw = wsp->walk_data;
	int status;

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	if (status != WALK_NEXT) {
		return (status);
	}

	htable_t ht;
	if (mdb_vread(&ht, sizeof (ht), wsp->walk_addr) == -1) {
		mdb_warn("failed to read htable %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (ht.ht_next != NULL) {	/* Continue down the chain */
		wsp->walk_addr = (uintptr_t)ht.ht_next;
		return (WALK_NEXT);
	} else { /* Go to the next bucket */
		uintptr_t next = 0;

		while ((next == 0) && (htw->htw_bucket < (mmu.hash_cnt - 1))) {
			htw->htw_bucket += 1;

			uintptr_t baddr = (uintptr_t)(htw->htw_hat.hat_ht_hash +
			    htw->htw_bucket);

			if (mdb_vread(&next, sizeof (htable_t *),
			    baddr) == -1) {
				mdb_warn("couldn't read htable ptr %p", baddr);
				return (WALK_ERR);
			}
		}
		wsp->walk_addr = next;

		return ((next == 0) ? WALK_DONE : WALK_NEXT);
	}
}

void
htables_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (htables_walk_data_t));
}
