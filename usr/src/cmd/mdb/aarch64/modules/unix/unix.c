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

/* Copyright 2023 Richard Lowe */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/arm_features.h>
#include <sys/bitmap.h>
#include <sys/gic.h>
#include <sys/gic_reg.h>
#include <sys/syspic.h>
#include <sys/syspic_impl.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>

#include "mmu.h"

static int
arm_features_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	void *fset;
	GElf_Sym sym;
	uintptr_t nptr;
	char name[128];
	int ii;

	size_t sz = sizeof (uchar_t) * BT_SIZEOFMAP(NUM_ARM_FEATURES);

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_lookup_by_name("arm_feature_names", &sym) == -1) {
		mdb_warn("couldn't find x86_feature_names");
		return (DCMD_ERR);
	}

	fset = mdb_zalloc(sz, UM_NOSLEEP);
	if (fset == NULL) {
		mdb_warn("failed to allocate memory for arm_features");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(fset, sz, addr) != sz) {
			mdb_warn("failed to read arm_features from %p", addr);
			mdb_free(fset, sz);
			return (DCMD_ERR);
		}
	} else {
		if (mdb_readvar(fset, "arm_features") != sz) {
			mdb_warn("failed to read arm_features");
			mdb_free(fset, sz);
			return (DCMD_ERR);
		}
	}

	for (ii = 0; ii < NUM_ARM_FEATURES; ii++) {
		if (!BT_TEST((ulong_t *)fset, ii))
			continue;

		if (mdb_vread(&nptr, sizeof (char *), sym.st_value +
		    sizeof (void *) * ii) != sizeof (char *)) {
			mdb_warn("failed to read feature array %d", ii);
			mdb_free(fset, sz);
			return (DCMD_ERR);
		}

		if (mdb_readstr(name, sizeof (name), nptr) == -1) {
			mdb_printf("unknown feature 0x%x\n", ii);
		} else {
			mdb_printf("%s\n", name);
		}
	}

	mdb_free(fset, sz);
	return (DCMD_OK);
}

static const char *
gic_vec_to_type(uint_t vec)
{
	if (GIC_INTID_IS_SGI(vec)) {
		return ("SGI");
	} else if (GIC_INTID_IS_ANY_PPI(vec)) {
		return ("PPI");
	} else if (GIC_INTID_IS_ANY_SPI(vec)) {
		return ("SPI");
	} else if (GIC_INTID_IS_LPI(vec)) {
		return ("LPI");
	} else {
		return ("???");
	}
}


static int
gic_print_vec(uintptr_t state_addr, const void *aw_buff, void *arg)
{
	syspic_intr_state_t state;
	struct av_head *avec_tbl = arg;
	struct autovec av;

	if (mdb_vread(&state, sizeof (state), state_addr) != sizeof (state)) {
		return (WALK_ERR);
	}

	uintptr_t av_addr = (uintptr_t)avec_tbl[state.si_vector].avh_link;

	while (av_addr != 0x0) {
		if (mdb_vread(&av, sizeof (struct autovec), av_addr) == -1) {
			mdb_warn("Failed to read autovec %p for vec %d",
			    av_addr, state.si_vector);
			break;
		}

		if (av.av_vector == NULL) {
			av_addr = (uintptr_t)av.av_link;
			continue;
		}

		/*
		 * NB: Should match the format header in `gic_interrupts_dcmd`
		 */
		mdb_printf("%-8d  %-8s  %-8s  %-8d  ", state.si_vector,
		    gic_vec_to_type(state.si_vector),
		    state.si_edge_triggered ? "edge" : "level",
		    state.si_prio);

		if (av.av_dip != 0) {
			char driv[MODMAXNAMELEN + 1];
			struct dev_info di;

			if (mdb_devinfo2driver((uintptr_t)av.av_dip, driv,
			    sizeof (driv)) == 0) {
				(void) mdb_vread(&di,
				    sizeof (struct dev_info),
				    (uintptr_t)av.av_dip);

				mdb_printf("%-28a  %s#%d\n",
				    av.av_vector, driv,
				    di.devi_instance);
			} else {
				mdb_printf("%-28a  - \n",
				    av.av_vector);
			}
		} else {
			mdb_printf("%-28a  - \n", av.av_vector);
		}

		av_addr = (uintptr_t)av.av_link;
	}

	return (WALK_NEXT);
}

static int
gic_interrupts_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	/*
	 * XXXARM: This is the true size of the avec tbl, which in general
	 * needs to be larger on ARM.
	 */
	struct av_head avec_tbl[MAX_VECT] = {0};

	if (mdb_readvar(&avec_tbl, "autovect") == -1) {
		mdb_warn("failed to read autovect");
		return (DCMD_ERR);
	}

	GElf_Sym sym;
	if (mdb_lookup_by_name("syspic_intrs", &sym) == -1) {
		mdb_warn("failed to lookup up syspic_intrs");
		return (DCMD_ERR);
	}

	mdb_printf("%<u>%-8s  %-8s  %-8s  %-8s  %-28s  %s%</u>\n",
	    "Vector",  "Type", "Trigger", "Priority", "ISR", "Instance");

	if (mdb_pwalk("avl", gic_print_vec, avec_tbl, sym.st_value) == -1)
		return (DCMD_ERR);

	return (DCMD_OK);
}


static const mdb_dcmd_t dcmds[] = {
	{ "arm_features", ":", "dump the arm_features vector",
	    arm_features_dcmd },
	{ "interrupts", "", "print interrupts", gic_interrupts_dcmd },
	{ "memseg_list", ":", "show memseg list", memseg_list },
	{ NULL },
};

static const mdb_walker_t walkers[] = {
	{ "memseg", "walk the memseg structures",
	    memseg_walk_init, memseg_walk_step, memseg_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
