/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1994-1996,1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
/*
 * Copyright 2026 Michael van der Westhuizen
 */

#ifndef	_SYS_PROM_PLAT_H
#define	_SYS_PROM_PLAT_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * FDT-specific
 */
struct prom_hwclock {
	pnode_t node;
	uint32_t id;
};

extern int prom_fdt_get_reg(pnode_t node, int index, uint64_t *base);
extern int prom_fdt_get_clock_by_name(pnode_t node, const char *name,
    struct prom_hwclock *clock);
extern boolean_t prom_fdt_is_compatible(pnode_t node, const char *name);
extern pnode_t prom_fdt_find_compatible(pnode_t node, const char *compatible);
extern void prom_fdt_walk(void(*func)(pnode_t, void*), void *arg);
extern int prom_fdt_get_reg_address(pnode_t node, int index, uint64_t *reg);
extern int prom_fdt_get_reg_size(pnode_t node, int index, uint64_t *regsize);

/*
 * Per-CPU topology extracted from the FDT by prom_fdt_get_cpu_topology.
 *
 * pft_mpidr       MPIDR affinity value from the cpu node's reg property.
 * pft_llc_id      Last-level cache group identity, derived by following the
 *                 next-level-cache phandle chain to its terminal node.  Two
 *                 CPUs with the same pft_llc_id share an LLC.  Set to -1 if
 *                 the cpu node has no next-level-cache property.
 * pft_chip_id     Socket/package identity from the cpu-map node.  Set to 0
 *                 (single socket) if cpu-map is absent or has no socket
 *                 nodes.
 * pft_cluster_id  Cluster identity from the cpu-map node.  Set to 0 (single
 *                 cluster) if cpu-map is absent or has no cluster nodes.
 * pft_core_id     Core identity from the cpu-map node.  Set to the CPU's
 *                 ordinal index if cpu-map is absent or lacks a core/thread
 *                 hierarchy (one core per CPU, no SMT).
 */
typedef struct prom_fdt_cpu_topo {
	uint64_t	pft_mpidr;
	id_t		pft_llc_id;
	id_t		pft_chip_id;
	id_t		pft_cluster_id;
	id_t		pft_core_id;
} prom_fdt_cpu_topo_t;

extern int prom_fdt_get_cpu_topology(prom_fdt_cpu_topo_t *topo, int max_cpus);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PROM_PLAT_H */
