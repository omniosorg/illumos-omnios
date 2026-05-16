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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * Processor Group platform support for FDT-based aarch64 systems.
 *
 * Topology is derived from two DT mechanisms:
 *
 *   next-level-cache (DTSpec s3.9)
 *     Each cpu node may contain a "next-level-cache" phandle pointing to a
 *     cache node.  Cache nodes may themselves chain via next-level-cache.
 *     We follow each chain to its terminal node; two CPUs whose chains
 *     converge at the same terminal node share an LLC (PGHW_CACHE).
 *
 *   cpu-map (DTSpec cpu-topology binding)
 *     The cpu-map node, when present, describes a socket/cluster/core/thread
 *     hierarchy.  The full walk classifies nodes by their DTSpec-mandated
 *     name prefixes ("socketN", "clusterN", "coreN", "threadN"):
 *       - socketN  -> PGHW_CHIP   (package)
 *       - clusterN -> PGHW_PROCNODE (AMD CCX/CCD analogue)
 *       - coreN    -> PGHW_IPIPE  (threads sharing a pipeline, i.e. SMT)
 *       - threadN  -> leaf CPU
 *     Socket is optional (clusters may appear directly under cpu-map).
 *     Clusters may nest; the innermost cluster determines PROCNODE identity.
 *     When cpu-map is absent or structurally invalid, a flat fallback is
 *     applied: all CPUs in socket 0, cluster 0, one core per CPU, no SMT.
 *
 * MPIDR is NOT used - its encoding is implementation-defined and unreliable
 * for topology inference without a-priori platform knowledge.
 *
 * Initialisation:
 *   pg_plat_set_fw is called from mlsetup after cpuinfo_bootstrap
 *   and before pg_cpu_bootstrap.  On some platforms this could receive a
 *   firmware table physical address.  On FDT platforms the argument is unused
 *   and we perform the FDT walk here instead.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cpuvar.h>
#include <sys/cmt.h>
#include <sys/pghw.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/cpuinfo.h>

/*
 * Per-CPU topology information derived from the FDT.
 */
typedef struct fdt_cpu_info {
	id_t		fci_chip_id;	/* socket from cpu-map */
	id_t		fci_cluster_id;	/* cluster from cpu-map */
	id_t		fci_llc_id;	/* LLC group from next-level-cache */
	id_t		fci_core_id;	/* core group from cpu-map */
	boolean_t	fci_valid;	/* entry populated */
} fdt_cpu_info_t;

static fdt_cpu_info_t fdt_info[NCPU];
static boolean_t fdt_parsed = B_FALSE;

/*
 * Parse the FDT and populate fdt_info.
 */
static void
fdt_parse_topology(void)
{
	prom_fdt_cpu_topo_t raw_topo[NCPU];
	int ncpus;
	int i;

	ncpus = prom_fdt_get_cpu_topology(raw_topo, NCPU);
	if (ncpus <= 0) {
		/*
		 * No FDT or no cpu nodes found.  Leave fdt_parsed false;
		 * all lookups will use the flat fallback.
		 */
		return;
	}

	for (i = 0; i < ncpus; i++) {
		processorid_t cpu_id;

		cpu_id = cpuinfo_id_for_mpidr(raw_topo[i].pft_mpidr);
		if (cpu_id == (processorid_t)-1) {
			continue;
		}

		ASSERT3S(cpu_id, >=, 0);
		ASSERT3S(cpu_id, <, NCPU);

		fdt_info[cpu_id].fci_chip_id = raw_topo[i].pft_chip_id;
		fdt_info[cpu_id].fci_cluster_id = raw_topo[i].pft_cluster_id;
		fdt_info[cpu_id].fci_llc_id = raw_topo[i].pft_llc_id;
		fdt_info[cpu_id].fci_core_id = raw_topo[i].pft_core_id;
		fdt_info[cpu_id].fci_valid = B_TRUE;
	}

	/*
	 * Normalise LLC IDs.  If a CPU has no next-level-cache
	 * (llc_id == -1), give it a unique llc_id based on cpu_id so
	 * it forms a singleton cache group rather than false-sharing
	 * with other CPUs that also lack cache data.
	 *
	 * Use a negative offset from -1 so synthetic IDs can never
	 * collide with real phandle values (which are positive).
	 */
	for (i = 0; i < NCPU; i++) {
		if (!fdt_info[i].fci_valid) {
			continue;
		}

		if (fdt_info[i].fci_llc_id == -1) {
			fdt_info[i].fci_llc_id = -(i + 2);
		}
	}

	fdt_parsed = B_TRUE;
}

static id_t
fdt_instance_id(processorid_t id, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_IPIPE:
		return (fdt_info[id].fci_core_id);
	case PGHW_CACHE:
		return (fdt_info[id].fci_llc_id);
	case PGHW_PROCNODE:
		return (fdt_info[id].fci_cluster_id);
	case PGHW_CHIP:
		return (fdt_info[id].fci_chip_id);
	default:
		return ((id_t)-1);
	}
}

int
pg_plat_hw_shared(cpu_t *cp, pghw_type_t hw)
{
	id_t my_id;
	int i;
	processorid_t id = cp->cpu_id;

	if (!fdt_parsed || id < 0 || id >= NCPU || !fdt_info[id].fci_valid) {
		return (0);
	}

	if ((my_id = fdt_instance_id(id, hw)) == (id_t)-1) {
		return (0);
	}

	for (i = 0; i < NCPU; i++) {
		if (i == id || !fdt_info[i].fci_valid) {
			continue;
		}

		if (fdt_instance_id(i, hw) == my_id) {
			return (1);
		}
	}

	return (0);
}

/*
 * Compare two CPUs and see if they have a pghw_type_t sharing relationship.
 *
 * If pghw_type_t is an unsupported hardware type, then return -1.
 */
int
pg_plat_cpus_share(cpu_t *cpu_a, cpu_t *cpu_b, pghw_type_t hw)
{
	id_t pgp_a, pgp_b;

	pgp_a = pg_plat_hw_instance_id(cpu_a, hw);
	pgp_b = pg_plat_hw_instance_id(cpu_b, hw);

	if (pgp_a == -1 || pgp_b == -1) {
		return (-1);
	}

	return (pgp_a == pgp_b);
}

/*
 * Return a physical instance identifier for known hardware sharing
 * relationships.
 */
id_t
pg_plat_hw_instance_id(cpu_t *cpu, pghw_type_t hw)
{
	processorid_t id = cpu->cpu_id;

	if (!fdt_parsed || id < 0 || id >= NCPU || !fdt_info[id].fci_valid) {
		/*
		 * Flat fallback: unique core, single cluster, single chip.
		 */
		switch (hw) {
		case PGHW_IPIPE:
			return (id);
		case PGHW_CACHE:
			return (id);
		case PGHW_PROCNODE:
			return (0);
		case PGHW_CHIP:
			return (0);
		default:
			return (-1);
		}
	}

	switch (hw) {
	case PGHW_IPIPE:
		return (fdt_info[id].fci_core_id);
	case PGHW_CACHE:
		return (fdt_info[id].fci_llc_id);
	case PGHW_PROCNODE:
		return (fdt_info[id].fci_cluster_id);
	case PGHW_CHIP:
		return (fdt_info[id].fci_chip_id);
	default:
		return (-1);
	}
}

/*
 * Override the default CMT dispatcher policy for the specified
 * hardware sharing relationship.
 *
 * This follows the i86pc implementation, with the exception being that we
 * don't recognise FPU sharing (nothing in FDT can provide this information).
 */
pg_cmt_policy_t
pg_plat_cmt_policy(pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CACHE:
		return (CMT_BALANCE|CMT_AFFINITY);
	case PGHW_IPIPE:
	case PGHW_PROCNODE:
	default:
		return (CMT_NO_POLICY);
	}
}

id_t
pg_plat_get_core_id(cpu_t *cpu)
{
	processorid_t id = cpu->cpu_id;

	if (fdt_parsed && id >= 0 && id < NCPU && fdt_info[id].fci_valid) {
		return (fdt_info[id].fci_core_id);
	}

	return ((id_t)id);
}

pghw_type_t
pg_plat_hw_rank(pghw_type_t hw1, pghw_type_t hw2)
{
	int i;
	int rank1 = 0;
	int rank2 = 0;

	static pghw_type_t hw_hier[] = {
		PGHW_IPIPE,
		PGHW_CACHE,
		PGHW_PROCNODE,
		PGHW_CHIP,
		PGHW_NUM_COMPONENTS
	};

	for (i = 0; hw_hier[i] != PGHW_NUM_COMPONENTS; i++) {
		if (hw_hier[i] == hw1) {
			rank1 = i;
		}

		if (hw_hier[i] == hw2) {
			rank2 = i;
		}
	}

	if (rank1 > rank2) {
		return (hw1);
	} else {
		return (hw2);
	}
}

/*
 * Called from mlsetup after cpuinfo_bootstrap and before pg_cpu_bootstrap.
 */
void
pg_plat_set_fw(uint64_t arg0 __unused)
{
	fdt_parse_topology();
}
