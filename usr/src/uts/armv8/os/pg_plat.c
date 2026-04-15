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
 * Processor Group platform support for aarch64.
 *
 * This is the base (FDT) implementation.  It derives processor topology
 * (badly) from MPIDR affinity fields, which is a rough heuristic -- MPIDR
 * encoding is implementation-defined and may not accurately reflect cache
 * sharing or physical package boundaries.
 */

#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/cmt.h>
#include <sys/pghw.h>
#include <sys/controlregs.h>

int
pg_plat_hw_shared(cpu_t *cp, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CHIP:
		return (1);
	case PGHW_CACHE:
		return (1);
	default:
		return (0);
	}
}

/*
 * Compare two CPUs and see if they have a pghw_type_t sharing relationship.
 * If pghw_type_t is an unsupported hardware type, then return -1.
 */
int
pg_plat_cpus_share(cpu_t *cpu_a, cpu_t *cpu_b, pghw_type_t hw)
{
	id_t pgp_a, pgp_b;

	pgp_a = pg_plat_hw_instance_id(cpu_a, hw);
	pgp_b = pg_plat_hw_instance_id(cpu_b, hw);

	if (pgp_a == -1 || pgp_b == -1)
		return (-1);

	return (pgp_a == pgp_b);
}

/*
 * Return a physical instance identifier for known hardware sharing
 * relationships.
 *
 * NOTE: This MPIDR-based implementation reads the *current* CPU's MPIDR
 * rather than the target cpu's.  It serves as a placeholder until PPTT-based
 * topology is available on ACPI platforms.
 */
id_t
pg_plat_hw_instance_id(cpu_t *cpu, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CACHE:
		return (read_mpidr() & 0xFF);
	case PGHW_CHIP:
		return (((read_mpidr() >> 16) |
		    (read_mpidr() >> 8)) & 0xFFFFFF);
	default:
		return (-1);
	}
}

/*
 * Override the default CMT dispatcher policy for the specified
 * hardware sharing relationship.
 */
pg_cmt_policy_t
pg_plat_cmt_policy(pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CACHE:
		return (CMT_BALANCE|CMT_AFFINITY);
	default:
		return (CMT_NO_POLICY);
	}
}

id_t
pg_plat_get_core_id(cpu_t *cpu)
{
	return (read_mpidr() & 0xFF);
}

pghw_type_t
pg_plat_hw_rank(pghw_type_t hw1, pghw_type_t hw2)
{
	int i, rank1, rank2;

	static pghw_type_t hw_hier[] = {
		PGHW_CACHE,
		PGHW_CHIP,
		PGHW_NUM_COMPONENTS
	};

	for (i = 0; hw_hier[i] != PGHW_NUM_COMPONENTS; i++) {
		if (hw_hier[i] == hw1)
			rank1 = i;
		if (hw_hier[i] == hw2)
			rank2 = i;
	}

	if (rank1 > rank2)
		return (hw1);
	else
		return (hw2);
}
