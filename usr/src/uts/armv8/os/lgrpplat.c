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
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * Locality Group (lgroup) platform support for aarch64/FDT platforms
 *
 * This module determines the NUMA topology by reading FDT (devicetree)
 * properties:
 * - numa-node-id (u32) on CPU nodes, memory nodes, and device nodes
 *   identifies the NUMA domain each resource belongs to.
 * - /distance-map (compatible = "numa-distance-map-v1") with a
 *   distance-matrix property provides inter-node latency data as
 *   (from, to, distance) triples.  Local distance is 10, remote > 10.
 *
 * The distance-matrix is the primary authority for which nodes exist.
 * A full tree walk catches any additional numa-node-id values not
 * referenced by the distance-matrix (e.g. I/O-only nodes such as PCIe
 * root complexes in their own NUMA domain).  Orphan nodes are warned
 * about and synthesised with self-distance 10 and max-observed-distance
 * to all other nodes.
 *
 * If no numa-node-id property appears anywhere in the tree, the system
 * is treated as UMA (single locality group).
 *
 * CPU identification uses the MPIDR value from the cpu node's reg
 * property, mapped to a processorid_t via cpuinfo_id_for_mpidr.
 *
 * UEFI+FDT interaction: /memory node reg values define NUMA domain
 * boundaries while the actual usable memory map comes from EFI.  EFI
 * memory outside any /memory node is assigned to node 0 as orphan
 * memnodes.
 */

#include <sys/archsystm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/cpupart.h>
#include <sys/cpuvar.h>
#include <sys/lgrp.h>
#include <sys/machsystm.h>
#include <sys/memlist.h>
#include <sys/memnode.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/types.h>
#include <sys/cpuinfo.h>
#include <sys/sysmacros.h>
#include <vm/vm_dep.h>

#define	MAX_NODES		MAX_MEM_NODES
#define	NLGRP			(MAX_NODES * (MAX_NODES - 1) + 1)

/*
 * Default distances when no distance-map is available.
 */
#define	FDT_LOCAL_DISTANCE	10
#define	FDT_REMOTE_DISTANCE	20

/*
 * Node ID to internal node index mapping.
 *
 * FDT numa-node-id values serve as proximity domain identifiers.
 */
typedef struct node_domain_map {
	int		exists;
	uint32_t	prox_domain;	/* numa-node-id value */
} node_domain_map_t;

/*
 * CPU to node mapping, keyed by processorid_t.
 */
typedef struct cpu_node_map {
	uint64_t	mpidr;
	uint32_t	prox_domain;
	int		node;
	boolean_t	exists;
} cpu_node_map_t;

/*
 * Physical address range for a memory node.
 */
typedef struct memnode_phys_addr_map {
	pfn_t		start;		/* start PFN (inclusive) */
	pfn_t		end;		/* end PFN (exclusive) */
	int		exists;
	uint32_t	prox_domain;
	int		lgrphand;
	boolean_t	orphan;		/* EFI memory not in FDT /memory */
} memnode_phys_addr_map_t;

/*
 * Latency statistics from distance-map.
 */
typedef struct lgrp_plat_latency_stats {
	int	latencies[MAX_NODES][MAX_NODES];
	int	latency_min;
	int	latency_max;
} lgrp_plat_latency_stats_t;

/*
 * Static lgrp allocation.
 */
static lgrp_t		lgrp_space[NLGRP];
static int		nlgrps_alloc;
struct lgrp_stats	lgrp_stats[NLGRP];

/*
 * CPU to node mapping table, indexed by processorid_t.
 *
 * Static array sized to NCPU.
 */
static cpu_node_map_t		lgrp_plat_cpu_node[NCPU];

/*
 * Latency statistics from distance-map.
 */
static lgrp_plat_latency_stats_t	lgrp_plat_lat_stats;

/*
 * Node to proximity domain mapping.
 */
static node_domain_map_t	lgrp_plat_node_domain[MAX_NODES];

/*
 * Physical address ranges per memory node.
 */
static memnode_phys_addr_map_t	lgrp_plat_memnode_info[MAX_MEM_NODES];

/*
 * Maximum memnode index in use.
 */
static uint_t			lgrp_plat_max_mem_node;

/*
 * Tunables and counters.
 */
uint_t		lgrp_plat_node_cnt = 1;
int		lgrp_plat_node_sort_enable = 1;

/*
 * Forward declarations.
 */
static int	lgrp_plat_domain_to_node(node_domain_map_t *node_domain,
		    int node_cnt, uint32_t domain);
static int	lgrp_plat_node_domain_update(node_domain_map_t *node_domain,
		    int node_cnt, uint32_t domain);
static int	lgrp_plat_cpu_node_update(node_domain_map_t *node_domain,
		    int node_cnt, cpu_node_map_t *cpu_node, int nentries,
		    uint64_t mpidr, uint32_t domain);
static int	lgrp_plat_memnode_info_update(node_domain_map_t *node_domain,
		    int node_cnt, memnode_phys_addr_map_t *memnode_info,
		    int memnode_cnt, uint64_t base, uint64_t length,
		    uint32_t domain);
static void	lgrp_plat_node_sort(node_domain_map_t *node_domain,
		    int node_cnt, cpu_node_map_t *cpu_node, int cpu_count,
		    memnode_phys_addr_map_t *memnode_info);
static void	fdt_get_numa_config(void);
static boolean_t lgrp_plat_memnode_validate(node_domain_map_t *node_domain,
		    int node_cnt, memnode_phys_addr_map_t *memnode_info,
		    uint_t max_mem_node);
static void	lgrp_plat_orphan_memnode(pfn_t start, pfn_t end);

/*
 * Look up the internal node index for a given numa-node-id.
 *
 * Returns -1 if not found.
 */
static int
lgrp_plat_domain_to_node(node_domain_map_t *node_domain, int node_cnt,
    uint32_t domain)
{
	int i;

	for (i = 0; i < node_cnt; i++) {
		if (node_domain[i].exists &&
		    node_domain[i].prox_domain == domain) {
			return (i);
		}
	}

	return (-1);
}

/*
 * Add or update a node-to-numa-node-id mapping.
 *
 * Returns the internal node index for the domain.
 */
static int
lgrp_plat_node_domain_update(node_domain_map_t *node_domain, int node_cnt,
    uint32_t domain)
{
	int i, node;

	/*
	 * See if this domain is already known.
	 */
	node = lgrp_plat_domain_to_node(node_domain, node_cnt, domain);
	if (node >= 0) {
		return (node);
	}

	/*
	 * Find the first unused slot and assign this domain.
	 */
	for (i = 0; i < node_cnt; i++) {
		if (!node_domain[i].exists) {
			node_domain[i].prox_domain = domain;
			node_domain[i].exists = 1;
			return (i);
		}
	}

	return (-1);
}

/*
 * Update the CPU-to-node mapping for a CPU identified by its MPIDR.
 *
 * Returns 0 on success, -1 if the CPU couldn't be found or mapped.
 */
static int
lgrp_plat_cpu_node_update(node_domain_map_t *node_domain, int node_cnt,
    cpu_node_map_t *cpu_node, int nentries, uint64_t mpidr, uint32_t domain)
{
	processorid_t	id;
	int		node;

	id = cpuinfo_id_for_mpidr(mpidr);
	if (id < 0 || id >= nentries) {
		return (-1);
	}

	node = lgrp_plat_node_domain_update(node_domain, node_cnt, domain);
	if (node < 0) {
		return (-1);
	}

	cpu_node[id].mpidr = mpidr;
	cpu_node[id].prox_domain = domain;
	cpu_node[id].node = node;
	cpu_node[id].exists = B_TRUE;

	return (0);
}

/*
 * Update the memnode info for a memory range.
 *
 * Multiple ranges in the same numa-node-id may share a memnode if
 * they are contiguous, or they may use separate memnodes.
 *
 * Returns the memnode ID on success, -1 on failure.
 */
static int
lgrp_plat_memnode_info_update(node_domain_map_t *node_domain, int node_cnt,
    memnode_phys_addr_map_t *memnode_info, int memnode_cnt,
    uint64_t base, uint64_t length, uint32_t domain)
{
	int	node;
	int	mnode;
	pfn_t	start_pfn;
	pfn_t	end_pfn;

	if (length == 0) {
		return (-1);
	}

	node = lgrp_plat_node_domain_update(node_domain, node_cnt, domain);
	if (node < 0) {
		return (-1);
	}

	start_pfn = btop(base);
	end_pfn = btop(base + length);

	/*
	 * See if this extends an existing memnode for the same domain.
	 */
	for (mnode = 0; mnode < memnode_cnt; mnode++) {
		if (!memnode_info[mnode].exists) {
			continue;
		}

		if (memnode_info[mnode].prox_domain != domain) {
			continue;
		}

		if (memnode_info[mnode].end == start_pfn) {
			memnode_info[mnode].end = end_pfn;
			return (mnode);
		}

		if (end_pfn == memnode_info[mnode].start) {
			memnode_info[mnode].start = start_pfn;
			return (mnode);
		}
	}

	/*
	 * Allocate a new memnode.
	 */
	for (mnode = 0; mnode < memnode_cnt; mnode++) {
		if (!memnode_info[mnode].exists) {
			memnode_info[mnode].start = start_pfn;
			memnode_info[mnode].end = end_pfn;
			memnode_info[mnode].exists = 1;
			memnode_info[mnode].prox_domain = domain;
			memnode_info[mnode].lgrphand =
			    (lgrp_handle_t)node;

			if ((uint_t)mnode >= lgrp_plat_max_mem_node) {
				lgrp_plat_max_mem_node = mnode + 1;
			}

			return (mnode);
		}
	}

	return (-1);
}

/*
 * Sort nodes by numa-node-id for deterministic ordering.
 * Uses a simple insertion sort since MAX_NODES is small.
 *
 * After sorting, CPU and memnode mappings are rebuilt to reflect
 * the new node numbering.
 */
static void
lgrp_plat_node_sort(node_domain_map_t *node_domain, int node_cnt,
    cpu_node_map_t *cpu_node, int cpu_count,
    memnode_phys_addr_map_t *memnode_info)
{
	int			i, j, n;
	node_domain_map_t	tmp;
	int			new_node;

	if (!lgrp_plat_node_sort_enable || node_cnt <= 1) {
		return;
	}

	/*
	 * Compact: move all existing entries to the front so the
	 * insertion sort operates on a contiguous range.
	 */
	n = 0;
	for (i = 0; i < node_cnt; i++) {
		if (node_domain[i].exists) {
			if (i != n) {
				node_domain[n] = node_domain[i];
			}

			n++;
		}
	}
	for (i = n; i < node_cnt; i++) {
		node_domain[i].exists = 0;
		node_domain[i].prox_domain = 0;
	}

	/*
	 * Insertion sort by numa-node-id value.
	 */
	for (i = 1; i < n; i++) {
		tmp = node_domain[i];
		j = i - 1;

		while (j >= 0 &&
		    node_domain[j].prox_domain > tmp.prox_domain) {
			node_domain[j + 1] = node_domain[j];
			j--;
		}

		node_domain[j + 1] = tmp;
	}

	/*
	 * Rebuild CPU and memnode mappings to match new node order.
	 */
	for (i = 0; i < cpu_count; i++) {
		if (!cpu_node[i].exists) {
			continue;
		}

		new_node = lgrp_plat_domain_to_node(node_domain, node_cnt,
		    cpu_node[i].prox_domain);

		if (new_node >= 0) {
			cpu_node[i].node = new_node;
		}
	}

	for (i = 0; i < MAX_MEM_NODES; i++) {
		if (!memnode_info[i].exists) {
			continue;
		}

		new_node = lgrp_plat_domain_to_node(node_domain, node_cnt,
		    memnode_info[i].prox_domain);

		if (new_node >= 0) {
			memnode_info[i].lgrphand = (lgrp_handle_t)new_node;
		}
	}
}

/*
 * Validate the memnode configuration.
 *
 * Detects interleaved domains and memnode overflow.
 *
 * Returns B_TRUE if the configuration is valid, B_FALSE if UMA fallback
 * is required.
 */
static boolean_t
lgrp_plat_memnode_validate(node_domain_map_t *node_domain,
    int node_cnt, memnode_phys_addr_map_t *memnode_info,
    uint_t max_mem_node)
{
	pfn_t	domain_min[MAX_NODES];
	pfn_t	domain_max[MAX_NODES];
	int	i, j;

	/*
	 * Check for boot memnode overflow.
	 */
	if (max_mem_node +
	    (MAX_MEM_NODES_PER_LGROUP * node_cnt) > MAX_MEM_NODES) {
		cmn_err(CE_NOTE, "?lgrp: MPO disabled because FDT "
		    "memory ranges exceed memnode capacity "
		    "(%u ranges, %ld max)",
		    max_mem_node, MAX_MEM_NODES);
		return (B_FALSE);
	}

	/*
	 * Compute per-domain bounding boxes.
	 */
	for (i = 0; i < MAX_NODES; i++) {
		domain_min[i] = PFN_INVALID;
		domain_max[i] = 0;
	}

	for (i = 0; i < (int)max_mem_node; i++) {
		int	node;

		if (!memnode_info[i].exists) {
			continue;
		}

		node = lgrp_plat_domain_to_node(node_domain,
		    node_cnt, memnode_info[i].prox_domain);
		if (node < 0 || node >= MAX_NODES) {
			continue;
		}

		if (memnode_info[i].start < domain_min[node]) {
			domain_min[node] = memnode_info[i].start;
		}

		if (memnode_info[i].end > domain_max[node]) {
			domain_max[node] = memnode_info[i].end;
		}
	}

	/*
	 * Check for interleaved domains.
	 */
	for (i = 0; i < node_cnt; i++) {
		if (domain_max[i] == 0) {
			continue;
		}

		for (j = i + 1; j < node_cnt; j++) {
			if (domain_max[j] == 0) {
				continue;
			}

			if (domain_min[i] < domain_max[j] &&
			    domain_min[j] < domain_max[i]) {
				cmn_err(CE_NOTE, "?lgrp: MPO disabled "
				    "because memory is interleaved "
				    "across NUMA domains");
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

/*
 * Determine NUMA configuration from FDT properties.
 *
 * Called from lgrp_plat_init(LGRP_INIT_STAGE1).
 */
static void
fdt_get_numa_config(void)
{
	prom_fdt_numa_topo_t	topo;
	uint_t			i, j;
	int			node_cnt;

	prom_fdt_get_numa_topo(&topo);

	if (!topo.pfnt_has_numa) {
		return;
	}

	/*
	 * Pre-populate node_domain_map from all discovered node IDs.
	 * This ensures I/O-only nodes (from distance-matrix or device
	 * tree nodes) get slots before we process CPUs and memory.
	 */
	node_cnt = MAX_NODES;

	for (i = 0; i < topo.pfnt_nnode_ids; i++) {
		if (lgrp_plat_node_domain_update(lgrp_plat_node_domain,
		    node_cnt, topo.pfnt_node_ids[i]) < 0) {
			cmn_err(CE_WARN, "!lgrp: numa-node-id %u exceeds "
			    "maximum of %ld nodes, ignoring",
			    topo.pfnt_node_ids[i], MAX_NODES);
		}
	}

	/*
	 * Map CPUs to nodes via MPIDR.
	 */
	for (i = 0; i < topo.pfnt_ncpus; i++) {
		if (lgrp_plat_cpu_node_update(lgrp_plat_node_domain,
		    node_cnt, lgrp_plat_cpu_node, NCPU,
		    topo.pfnt_cpus[i].pfnc_mpidr,
		    topo.pfnt_cpus[i].pfnc_node_id) < 0) {
			cmn_err(CE_WARN, "!lgrp: CPU MPIDR %llx in "
			    "numa-node-id %u could not be mapped to "
			    "a NUMA node",
			    (unsigned long long)
			    topo.pfnt_cpus[i].pfnc_mpidr,
			    topo.pfnt_cpus[i].pfnc_node_id);
		}
	}

	/*
	 * Map memory ranges to nodes.
	 */
	for (i = 0; i < topo.pfnt_nmem; i++) {
		if (lgrp_plat_memnode_info_update(lgrp_plat_node_domain,
		    node_cnt, lgrp_plat_memnode_info, MAX_MEM_NODES,
		    topo.pfnt_mem[i].pfnm_base,
		    topo.pfnt_mem[i].pfnm_size,
		    topo.pfnt_mem[i].pfnm_node_id) < 0 &&
		    topo.pfnt_mem[i].pfnm_size > 0) {
			cmn_err(CE_WARN, "!lgrp: memory range "
			    "[%llx, %llx) in numa-node-id %u could "
			    "not be mapped to a NUMA node",
			    (unsigned long long)topo.pfnt_mem[i].pfnm_base,
			    (unsigned long long)(topo.pfnt_mem[i].pfnm_base +
			    topo.pfnt_mem[i].pfnm_size),
			    topo.pfnt_mem[i].pfnm_node_id);
		}
	}

	/*
	 * Find the extent of populated node slots.
	 */
	lgrp_plat_node_cnt = 0;
	for (i = 0; i < MAX_NODES; i++) {
		if (lgrp_plat_node_domain[i].exists) {
			lgrp_plat_node_cnt = i + 1;
		}
	}

	if (lgrp_plat_node_cnt <= 1) {
		max_mem_nodes = 1;
		return;
	}

	/*
	 * Validate the per-range memnode configuration.
	 */
	if (!lgrp_plat_memnode_validate(lgrp_plat_node_domain,
	    lgrp_plat_node_cnt, lgrp_plat_memnode_info,
	    lgrp_plat_max_mem_node)) {
		lgrp_plat_node_cnt = max_mem_nodes = 1;
		(void) lgrp_topo_ht_limit_set(1);
		return;
	}

	/*
	 * Tune scheduler for NUMA.
	 */
	lgrp_expand_proc_thresh = LGRP_LOADAVG_THREAD_MAX / 2;
	lgrp_expand_proc_diff = 0;

	/*
	 * Set up memory nodes with DR headroom.
	 */
	max_mem_nodes = lgrp_plat_max_mem_node +
	    (MAX_MEM_NODES_PER_LGROUP * lgrp_plat_node_cnt);
	if (max_mem_nodes > MAX_MEM_NODES) {
		max_mem_nodes = MAX_MEM_NODES;
	}

	/*
	 * Sort nodes by numa-node-id for deterministic ordering.
	 *
	 * This must happen before distance processing so that the
	 * latency matrix indices match the final node numbering.
	 */
	lgrp_plat_node_sort(lgrp_plat_node_domain, lgrp_plat_node_cnt,
	    lgrp_plat_cpu_node, NCPU, lgrp_plat_memnode_info);

	/*
	 * Initialize latency stats.
	 */
	lgrp_plat_lat_stats.latency_min = -1;
	lgrp_plat_lat_stats.latency_max = 0;

	/*
	 * Process distance-matrix if available.
	 */
	if (topo.pfnt_has_distance_map) {
		/*
		 * Track which internal node indices appear in the
		 * distance-matrix so we can detect orphans.
		 */
		boolean_t node_in_dmap[MAX_NODES];

		bzero(node_in_dmap, sizeof (node_in_dmap));

		/*
		 * First pass: populate latency matrix from triples.
		 */
		for (i = 0; i < topo.pfnt_ndist; i++) {
			int from_node, to_node;

			from_node = lgrp_plat_domain_to_node(
			    lgrp_plat_node_domain, lgrp_plat_node_cnt,
			    topo.pfnt_dist[i].pfnd_from);
			to_node = lgrp_plat_domain_to_node(
			    lgrp_plat_node_domain, lgrp_plat_node_cnt,
			    topo.pfnt_dist[i].pfnd_to);

			if (from_node < 0 || to_node < 0) {
				continue;
			}

			lgrp_plat_lat_stats.latencies[from_node][to_node] =
			    topo.pfnt_dist[i].pfnd_distance;

			node_in_dmap[from_node] = B_TRUE;
			node_in_dmap[to_node] = B_TRUE;
		}

		/*
		 * Second pass: fill symmetric entries (A->B = B->A)
		 * where only one direction was specified.
		 */
		for (i = 0; i < lgrp_plat_node_cnt; i++) {
			if (!lgrp_plat_node_domain[i].exists) {
				continue;
			}

			for (j = i + 1; j < lgrp_plat_node_cnt; j++) {
				if (!lgrp_plat_node_domain[j].exists) {
					continue;
				}

				if (lgrp_plat_lat_stats.latencies[i][j] != 0 &&
				    lgrp_plat_lat_stats.latencies[j][i] == 0) {
					lgrp_plat_lat_stats.latencies[j][i] =
					    lgrp_plat_lat_stats.latencies[i][j];
				} else if (
				    lgrp_plat_lat_stats.latencies[j][i] != 0 &&
				    lgrp_plat_lat_stats.latencies[i][j] == 0) {
					lgrp_plat_lat_stats.latencies[i][j] =
					    lgrp_plat_lat_stats.latencies[j][i];
				}
			}
		}

		/*
		 * Compute min/max latencies for cross-node pairs.
		 */
		for (i = 0; i < lgrp_plat_node_cnt; i++) {
			if (!lgrp_plat_node_domain[i].exists) {
				continue;
			}
			for (j = 0; j < lgrp_plat_node_cnt; j++) {
				int lat;

				if (!lgrp_plat_node_domain[j].exists) {
					continue;
				}

				if (i == j) {
					continue;
				}

				lat = lgrp_plat_lat_stats.latencies[i][j];
				if (lat <= 0) {
					continue;
				}

				if (lat < lgrp_plat_lat_stats.latency_min ||
				    lgrp_plat_lat_stats.latency_min == -1) {
					lgrp_plat_lat_stats.latency_min = lat;
				}

				if (lat > lgrp_plat_lat_stats.latency_max) {
					lgrp_plat_lat_stats.latency_max = lat;
				}
			}
		}

		/*
		 * Third pass: synthesise entries for orphan nodes
		 * (nodes found via tree walk but not in distance-matrix).
		 */
		for (i = 0; i < lgrp_plat_node_cnt; i++) {
			int max_dist;

			if (!lgrp_plat_node_domain[i].exists) {
				continue;
			}

			if (node_in_dmap[i]) {
				continue;
			}

			cmn_err(CE_WARN, "!lgrp: numa-node-id %u not "
			    "in distance-matrix, synthesising distances",
			    lgrp_plat_node_domain[i].prox_domain);

			max_dist = lgrp_plat_lat_stats.latency_max;
			if (max_dist <= 0) {
				max_dist = FDT_REMOTE_DISTANCE;
			}

			lgrp_plat_lat_stats.latencies[i][i] =
			    FDT_LOCAL_DISTANCE;

			for (j = 0; j < lgrp_plat_node_cnt; j++) {
				if (!lgrp_plat_node_domain[j].exists) {
					continue;
				}

				if (i == j) {
					continue;
				}

				lgrp_plat_lat_stats.latencies[i][j] =
				    max_dist;
				lgrp_plat_lat_stats.latencies[j][i] =
				    max_dist;
			}

			if (max_dist > lgrp_plat_lat_stats.latency_max) {
				lgrp_plat_lat_stats.latency_max = max_dist;
			}

			if (max_dist < lgrp_plat_lat_stats.latency_min ||
			    lgrp_plat_lat_stats.latency_min == -1) {
				lgrp_plat_lat_stats.latency_min = max_dist;
			}
		}
	} else {
		/*
		 * No distance-map: use default flat latencies.
		 */
		lgrp_plat_lat_stats.latency_min = FDT_REMOTE_DISTANCE;
		lgrp_plat_lat_stats.latency_max = FDT_REMOTE_DISTANCE;
		for (i = 0; i < lgrp_plat_node_cnt; i++) {
			for (j = 0; j < lgrp_plat_node_cnt; j++) {
				lgrp_plat_lat_stats.latencies[i][j] =
				    (i == j) ? FDT_LOCAL_DISTANCE :
				    FDT_REMOTE_DISTANCE;
			}
		}
	}
}

/*
 * Public lgrp_plat interface
 */

void
lgrp_plat_init(lgrp_init_stages_t stage)
{
	switch (stage) {
	case LGRP_INIT_STAGE1:
		fdt_get_numa_config();
		break;

	case LGRP_INIT_STAGE3:
		/* No hardware probing on FDT ARM platforms */
		break;

	case LGRP_INIT_STAGE4:
		/* No BOP_ALLOC replacement needed; arrays are static */
		break;

	default:
		break;
	}
}

void
lgrp_plat_set_fw_tables(uint64_t srat __unused, uint64_t slit __unused,
    uint64_t msct __unused, uint64_t pptt __unused)
{
	/*
	 * FDT platform: nothing to do.
	 */
}

void
lgrp_plat_probe(void)
{
	/* No hardware probing on FDT ARM platforms. */
}

lgrp_t *
lgrp_plat_alloc(lgrp_id_t lgrpid)
{
	if (lgrpid >= NLGRP || nlgrps_alloc >= NLGRP) {
		return (NULL);
	}

	return (&lgrp_space[nlgrps_alloc++]);
}

void
lgrp_plat_config(lgrp_config_flag_t flag __unused, uintptr_t arg __unused)
{
	/*
	 * CPU and memory DR notifications.  No-op for now since we
	 * don't support DR on FDT Arm platforms.
	 */
}

lgrp_handle_t
lgrp_plat_cpu_to_hand(processorid_t id)
{
	if (lgrp_plat_node_cnt <= 1) {
		return (LGRP_DEFAULT_HANDLE);
	}

	if (id < 0 || id >= NCPU || !lgrp_plat_cpu_node[id].exists) {
		return (LGRP_DEFAULT_HANDLE);
	}

	return ((lgrp_handle_t)lgrp_plat_cpu_node[id].node);
}

lgrp_handle_t
lgrp_plat_pfn_to_hand(pfn_t pfn)
{
	int	i;

	if (max_mem_nodes == 1) {
		return (LGRP_DEFAULT_HANDLE);
	}

	for (i = 0; i < (int)lgrp_plat_max_mem_node; i++) {
		if (!lgrp_plat_memnode_info[i].exists) {
			continue;
		}

		if (pfn >= lgrp_plat_memnode_info[i].start &&
		    pfn < lgrp_plat_memnode_info[i].end) {
			return ((lgrp_handle_t)
			    lgrp_plat_memnode_info[i].lgrphand);
		}
	}

	return (LGRP_DEFAULT_HANDLE);
}

int
lgrp_plat_latency(lgrp_handle_t from, lgrp_handle_t to)
{
	/*
	 * Return max latency for root lgroup (LGRP_DEFAULT_HANDLE).
	 */
	if (from == LGRP_DEFAULT_HANDLE || to == LGRP_DEFAULT_HANDLE) {
		return (lgrp_plat_lat_stats.latency_max);
	}

	if ((uint_t)from >= lgrp_plat_node_cnt ||
	    (uint_t)to >= lgrp_plat_node_cnt) {
		return (0);
	}

	return (lgrp_plat_lat_stats.latencies[from][to]);
}

int
lgrp_plat_max_lgrps(void)
{
	int n = lgrp_plat_node_cnt;

	/*
	 * The quadratic formula accounts for intermediate lgroup levels in
	 * multi-node topologies but underestimates for the single-node case
	 * (returns 1, but the framework needs root + node = 2).  Ensure the
	 * minimum is always node_cnt + 1 (one lgroup per node plus the root).
	 */
	return (MAX(n * (n - 1) + 1, n + 1));
}

pgcnt_t
lgrp_plat_mem_size(lgrp_handle_t plathand, lgrp_mem_query_t query)
{
	int		mnode;
	pgcnt_t		npgs = 0;
	extern struct memlist *phys_avail;
	extern struct memlist *phys_install;

	if (plathand == LGRP_NULL_HANDLE) {
		return (0);
	}

	if (plathand == LGRP_DEFAULT_HANDLE) {
		struct memlist *mlist;

		switch (query) {
		case LGRP_MEM_SIZE_FREE:
			if (lgrp_plat_node_cnt == 1) {
				return ((pgcnt_t)freemem);
			}

			/*
			 * Multi-node: sum free pages across all memnodes.
			 */
			for (mnode = 0;
			    mnode < (int)lgrp_plat_max_mem_node; mnode++) {
				if (!lgrp_plat_memnode_info[mnode].exists) {
					continue;
				}

				npgs += MNODE_PGCNT(mnode);
			}

			return (npgs);

		case LGRP_MEM_SIZE_AVAIL:
			memlist_read_lock();
			for (mlist = phys_avail; mlist;
			    mlist = mlist->ml_next) {
				npgs += btop(mlist->ml_size);
			}
			memlist_read_unlock();

			return (npgs);

		case LGRP_MEM_SIZE_INSTALL:
			memlist_read_lock();
			for (mlist = phys_install; mlist;
			    mlist = mlist->ml_next) {
				npgs += btop(mlist->ml_size);
			}
			memlist_read_unlock();

			return (npgs);

		default:
			return (0);
		}
	}

	/*
	 * Walk memnodes that belong to this lgrp handle and sum
	 * their installed/available pages.
	 */
	for (mnode = 0; mnode < (int)lgrp_plat_max_mem_node; mnode++) {
		if (!lgrp_plat_memnode_info[mnode].exists) {
			continue;
		}

		if (lgrp_plat_memnode_info[mnode].lgrphand != (int)plathand) {
			continue;
		}

		switch (query) {
		case LGRP_MEM_SIZE_FREE:
			npgs += MNODE_PGCNT(mnode);
			break;

		case LGRP_MEM_SIZE_AVAIL:
		case LGRP_MEM_SIZE_INSTALL: {
			struct memlist *mlist;
			pfn_t start = lgrp_plat_memnode_info[mnode].start;
			pfn_t end = lgrp_plat_memnode_info[mnode].end;

			memlist_read_lock();
			mlist = (query == LGRP_MEM_SIZE_INSTALL) ?
			    phys_install : phys_avail;
			for (; mlist; mlist = mlist->ml_next) {
				pfn_t ms = btop(mlist->ml_address);
				pfn_t me = btop(mlist->ml_address +
				    mlist->ml_size);
				pfn_t os, oe;

				/* Compute overlap with this memnode */
				os = MAX(ms, start);
				oe = MIN(me, end);
				if (os < oe) {
					npgs += (oe - os);
				}
			}
			memlist_read_unlock();
			break;
		}
		default:
			break;
		}
	}

	return (npgs);
}

lgrp_handle_t
lgrp_plat_root_hand(void)
{
	return (LGRP_DEFAULT_HANDLE);
}

/*
 * VM integration: plat_* functions
 *
 * These are called from the memnode layer via #pragma weak.
 */

/*
 * Allocate an orphan memnode for EFI memory not described by any
 * FDT /memory node.  The range is attributed to memnode 0's
 * numa-node-id.
 *
 * start and end are inclusive PFNs.
 */
static void
lgrp_plat_orphan_memnode(pfn_t start, pfn_t end)
{
	int	omn;

	for (omn = 0; omn < MAX_MEM_NODES; omn++) {
		if (!lgrp_plat_memnode_info[omn].exists) {
			break;
		}
	}

	if (omn >= MAX_MEM_NODES) {
		cmn_err(CE_PANIC, "lgrp: no memnode slot "
		    "for orphan memory [%lx, %lx]",
		    start, end);
	}

	lgrp_plat_memnode_info[omn].start = start;
	lgrp_plat_memnode_info[omn].end = end + 1;
	lgrp_plat_memnode_info[omn].exists = 1;
	lgrp_plat_memnode_info[omn].prox_domain =
	    lgrp_plat_memnode_info[0].prox_domain;
	lgrp_plat_memnode_info[omn].lgrphand =
	    lgrp_plat_memnode_info[0].lgrphand;
	lgrp_plat_memnode_info[omn].orphan = B_TRUE;

	if ((uint_t)(omn + 1) > lgrp_plat_max_mem_node) {
		lgrp_plat_max_mem_node = omn + 1;
	}

	if (omn + 1 > max_mem_nodes) {
		max_mem_nodes = omn + 1;
	}

	cmn_err(CE_WARN, "!lgrp: memory [%lx, %lx] not "
	    "described in FDT /memory, assigned to memnode %d "
	    "(numa-node-id %u)",
	    start, end, omn,
	    lgrp_plat_memnode_info[0].prox_domain);

	mem_node_add_slice(start, end);
}

/*
 * Build memory nodes from the physical memlist.
 *
 * Each memory range is assigned to the appropriate memnode based on
 * the FDT memory node NUMA data.
 */
void
plat_build_mem_nodes(struct memlist *list)
{
	struct memlist	*ml;
	pfn_t		start, end;

	for (ml = list; ml != NULL; ml = ml->ml_next) {
		start = btop(ml->ml_address);
		if (start > physmax) {
			continue;
		}

		end = btop(ml->ml_address + ml->ml_size) - 1;
		if (end > physmax) {
			end = physmax;
		}

		if (max_mem_nodes == 1 || lgrp_plat_node_cnt <= 1) {
			/*
			 * UMA system or single NUMA node: all memory
			 * belongs to memnode 0.
			 */
			mem_node_add_range(start, end);
			continue;
		}

		/*
		 * Walk the range memnode-by-memnode, splitting at
		 * boundaries.  Sub-ranges that fall outside all FDT
		 * memnodes are assigned to orphan memnodes.
		 */
		pfn_t cur = start;
		do {
			pfn_t	cur_end = end;
			int	found = -1;
			int	mnode;

			for (mnode = 0;
			    mnode < (int)lgrp_plat_max_mem_node;
			    mnode++) {
				pfn_t ms, me;

				if (!lgrp_plat_memnode_info[mnode].exists) {
					continue;
				}

				ms = lgrp_plat_memnode_info[mnode].start;
				me = lgrp_plat_memnode_info[mnode].end - 1;

				if (cur >= ms && cur <= me) {
					found = mnode;
					if (cur_end > me) {
						cur_end = me;
					}

					break;
				}

				/*
				 * Tighten orphan upper bound.
				 */
				if (ms > cur && ms - 1 < cur_end) {
					cur_end = ms - 1;
				}
			}

			if (found >= 0) {
				mem_node_add_slice(cur, cur_end);
			} else {
				lgrp_plat_orphan_memnode(cur, cur_end);
			}

			cur = cur_end + 1;
		} while (cur <= end);
	}
}

/*
 * Given a PFN, return the memnode it belongs to.
 */
int
plat_pfn_to_mem_node(pfn_t pfn)
{
	int	i;

	for (i = 0; i < (int)lgrp_plat_max_mem_node; i++) {
		if (!lgrp_plat_memnode_info[i].exists) {
			continue;
		}

		if (pfn >= lgrp_plat_memnode_info[i].start &&
		    pfn < lgrp_plat_memnode_info[i].end) {
			return (i);
		}
	}

	/*
	 * Didn't find memnode where this PFN lives.
	 */
#if defined(DEBUG)
	panic("no memnode for pfn 0x%lx", (uint64_t)pfn);
#endif
	return (0);
}

/*
 * Given a memnode, return the lgrp handle it belongs to.
 */
lgrp_handle_t
plat_mem_node_to_lgrphand(int mnode)
{
	if (mnode < 0 || mnode >= MAX_MEM_NODES ||
	    !lgrp_plat_memnode_info[mnode].exists) {
		return (LGRP_DEFAULT_HANDLE);
	}

	return ((lgrp_handle_t)lgrp_plat_memnode_info[mnode].lgrphand);
}

/*
 * Given an lgrp handle, return the first memnode for it.
 */
int
plat_lgrphand_to_mem_node(lgrp_handle_t hand)
{
	int	i;

	for (i = 0; i < (int)lgrp_plat_max_mem_node; i++) {
		if (lgrp_plat_memnode_info[i].exists &&
		    lgrp_plat_memnode_info[i].lgrphand == (int)hand) {
			return (i);
		}
	}

	return (-1);
}

/*
 * Assign an lgrp handle to a memnode.
 */
void
plat_assign_lgrphand_to_mem_node(lgrp_handle_t hand, int mnode)
{
	if (mnode >= 0 && mnode < MAX_MEM_NODES) {
		lgrp_plat_memnode_info[mnode].lgrphand = (int)hand;
	}
}
