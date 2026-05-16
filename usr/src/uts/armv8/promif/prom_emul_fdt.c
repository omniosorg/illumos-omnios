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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2026 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/byteorder.h>
#include <sys/ccompile.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/param.h>
#include <sys/prom_plat.h>
#include <sys/cmn_err.h>
#include <libfdt.h>

static const struct fdt_header *fdtp = NULL;

/*
 * This exists to keep us from trying to check for over-long property names
 * before the system can support us doing it.
 *
 * Can be tuned _to 0_ to prevent any warnings.  Tuning to 1 is absolutely
 * fatal.
 */
#ifdef DEBUG
int prom_propname_warn = -1;
#else
int prom_propname_warn = 0;
#endif

static phandle_t
get_phandle(int offset)
{
	int len;
	fdt32_t v;
	const void *prop = fdt_getprop(fdtp, offset, "phandle", &len);

	VERIFY3P(prop, !=, NULL);
	VERIFY3U(len, ==, sizeof (fdt32_t));

	memcpy(&v, prop, sizeof (fdt32_t));
	return (fdt32_to_cpu(v));
}

static void
check_overlong_property(pnode_t nodeid, const char *name)
{
	/*
	 * We are called very early in boot, in limited circumstances.  So
	 * early we can't actually tell anyone we've failed.  Bail out if
	 * we're unready, or have been tuned off.
	 */
	if (prom_propname_warn <= 0)
		return;

	if ((strlen(name) + 1) > OBP_STANDARD_MAXPROPNAME) {
		int offset = fdt_node_offset_by_phandle(fdtp, nodeid);
		const char *nodename = NULL;
		int len;

		if (offset < 0)
			goto no_name;

		nodename = fdt_get_name(fdtp, offset, &len);
		if ((nodename == NULL) || nodename[0] == '\0')
			goto no_name;

		cmn_err(CE_WARN,
		    "PROM node '%s' request for over long property '%s'",
		    nodename, name);
		return;

no_name:
		cmn_err(CE_WARN,
		    "PROM node %u request for over long property '%s'",
		    nodeid, name);
	}
}

static pnode_t
get_parent(pnode_t nodeid)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return (OBP_NONODE);

	int parent_offset = fdt_parent_offset(fdtp, offset);
	if (parent_offset < 0)
		return (OBP_NONODE);
	phandle_t phandle = get_phandle(parent_offset);
	if (phandle < 0)
		return (OBP_NONODE);
	return ((pnode_t)phandle);
}

static pnode_t
find_by_phandle(phandle_t phandle)
{
	int offset = fdt_node_offset_by_phandle(fdtp, phandle);
	if (offset < 0)
		return (-1);
	return ((pnode_t)phandle);
}

/*
 * Node-specific
 */

pnode_t
promif_finddevice(const char *device)
{
	int offset = fdt_path_offset(fdtp, device);
	if (offset < 0)
		return (OBP_BADNODE);

	phandle_t phandle = get_phandle(offset);
	if (phandle < 0)
		return (OBP_BADNODE);

	return ((pnode_t)phandle);
}

pnode_t
promif_rootnode(void)
{
	pnode_t root = promif_finddevice("/");
	if (root < 0) {
		return (OBP_NONODE);
	}
	return (root);
}

pnode_t
promif_nextnode(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return (promif_rootnode());

	int offset = fdt_node_offset_by_phandle(fdtp, (phandle_t)nodeid);
	if (offset < 0)
		return (OBP_BADNODE);

	int child = fdt_next_subnode(fdtp, offset);
	if (child == -FDT_ERR_NOTFOUND) {
		return (OBP_NONODE);
	} else if (child < 0) {
		return (OBP_BADNODE);
	}

	phandle_t phandle = get_phandle(child);
	if (phandle < 0)
		return (OBP_NONODE);

	return ((pnode_t)phandle);
}

pnode_t
promif_childnode(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return (promif_rootnode());

	int offset = fdt_node_offset_by_phandle(fdtp, (phandle_t)nodeid);
	if (offset < 0)
		return (OBP_NONODE);

	int child = fdt_first_subnode(fdtp, offset);
	if (child == -FDT_ERR_NOTFOUND) {
		return (OBP_NONODE);
	} else if (child < 0) {
		return (OBP_BADNODE);
	}

	phandle_t phandle = get_phandle(child);
	if (phandle < 0)
		return (OBP_NONODE);
	return ((pnode_t)phandle);
}

pnode_t
promif_optionsnode(void)
{
	pnode_t node = promif_finddevice("/options");
	if (node != OBP_BADNODE)
		return (node);
	return (OBP_NONODE);
}

pnode_t
promif_chosennode(void)
{
	pnode_t node = promif_finddevice("/chosen");
	if (node != OBP_BADNODE)
		return (node);
	return (OBP_NONODE);
}

/*
 * Node-specific, platform-specific
 */

pnode_t
prom_fdt_find_compatible(pnode_t node, const char *compatible)
{
	pnode_t child;

	if (prom_fdt_is_compatible(node, compatible))
		return (node);

	child = promif_childnode(node);

	while (child > 0) {
		node = prom_fdt_find_compatible(child, compatible);
		if (node > 0)
			return (node);

		child = promif_nextnode(child);
	}

	return (OBP_NONODE);
}

static void
promif_walk_dev(pnode_t nodeid, void(*func)(pnode_t, void*), void *arg)
{
	func(nodeid, arg);

	pnode_t child = promif_childnode(nodeid);
	while (child > 0) {
		promif_walk_dev(child, func, arg);
		child = promif_nextnode(child);
	}
}

void
prom_fdt_walk(void(*func)(pnode_t, void*), void *arg)
{
	promif_walk_dev(promif_rootnode(), func, arg);
}

/*
 * Property-specific
 */

int
promif_getproplen(pnode_t nodeid, const char *name)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);

	if (offset < 0)
		return (-1);

	check_overlong_property(nodeid, name);

	int len;
	const struct fdt_property *prop = fdt_get_property(fdtp, offset, name,
	    &len);

	if (prop == NULL) {
		if (strcmp(name, OBP_NAME) == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			if (!name_ptr)
				return (-1);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				len = p - name_ptr;
			} else {
				len = strlen(name_ptr);
			}

			return (len + 1);
		}
		if (strcmp(name, OBP_UNIT_ADDRESS) == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			if (!name_ptr)
				return (-1);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				p++;
				len = strlen(p);
			} else {
				return (-1);
			}
			if (len == 0)
				return (-1);
			return (len + 1);
		}

		return (-1);
	}

	return (len);
}

int
promif_getprop(pnode_t nodeid, const char *name, void *value)
{
	int offset = fdt_node_offset_by_phandle(fdtp, nodeid);

	check_overlong_property(nodeid, name);

	if (offset < 0)
		return (-1);

	int len;
	const void *prop = fdt_getprop(fdtp, offset, name, &len);

	if (prop == NULL) {
		if (strcmp(name, OBP_NAME) == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');

			if (!name_ptr)
				return (-1);

			if (p) {
				len = p - name_ptr;
			} else {
				len = strlen(name_ptr);
			}
			memcpy(value, name_ptr, len);
			((char *)value)[len] = '\0';

			return (len + 1);
		}
		if (strcmp(name, OBP_UNIT_ADDRESS) == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				p++;
				len = strlen(p);
			} else {
				return (-1);
			}
			if (len == 0)
				return (-1);

			memcpy(value, p, len);
			((char *)value)[len] = '\0';
			return (len + 1);
		}

		return (-1);
	}

	memcpy(value, prop, len);
	return (len);
}

/*
 * Returning NULL means something went wrong, returning '\0' means no more
 * properties.
 */
char *
promif_nextprop(pnode_t nodeid, const char *name, char *next)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return (NULL);

	/*
	 * The first time we're called, present the "name" pseudo-property
	 */
	if (name[0] == '\0') {
		strlcpy(next, OBP_NAME, OBP_MAXPROPNAME);
		return (next);
	}

	/*
	 * The second time we're called, present the "unit-address"
	 * pseudo-property, if appropriate
	 */
	if (strcmp(name, OBP_NAME) == 0) {
		int len;
		const char *fullname = fdt_get_name(fdtp, offset, &len);

		if (strchr(fullname, '@') != NULL) {
			strlcpy(next, OBP_UNIT_ADDRESS, OBP_MAXPROPNAME);
			return (next);
		}

		/* Fall through to get real properties */
	}

	*next = '\0';
	offset = fdt_first_property_offset(fdtp, offset);
	if (offset < 0) {
		return (next);
	}

	const struct fdt_property *data;
	for (;;) {
		data = fdt_get_property_by_offset(fdtp, offset, NULL);
		const char *name0 = fdt_string(fdtp,
		    fdt32_to_cpu(data->nameoff));
		if (name0) {
			/*
			 * If we reach here with name equal to one of our
			 * pseudo-properties, give the first real property.
			 */
			if ((strcmp(name, OBP_NAME) == 0) ||
			    (strcmp(name, OBP_UNIT_ADDRESS) == 0)) {
				strlcpy(next, name0, OBP_MAXPROPNAME);
				return (next);
			}
			if (strcmp(name, name0) == 0)
				break;
		}
		offset = fdt_next_property_offset(fdtp, offset);
		if (offset < 0) {
			return (next);
		}
	}
	offset = fdt_next_property_offset(fdtp, offset);
	if (offset < 0) {
		return (next);
	}
	data = fdt_get_property_by_offset(fdtp, offset, NULL);
	strlcpy(next, (char *)fdt_string(fdtp, fdt32_to_cpu(data->nameoff)),
	    OBP_MAXPROPNAME);
	return (next);
}

int
promif_bounded_getprop(pnode_t nodeid, char *name, void *value, int len)
{
	int prop_len = promif_getproplen(nodeid, name);
	if (prop_len < 0 || len < prop_len) {
		return (-1);
	}

	return (promif_getprop(nodeid, name, value));
}

/*
 * Property-specific, platform-specific
 */

static int
get_prop_int(pnode_t node, const char *name, int def)
{
	int value = def;

	while (node > 0) {
		int len = promif_getproplen(node, name);
		if (len == sizeof (int)) {
			int prop;
			promif_getprop(node, name, (caddr_t)&prop);
			value = ntohl(prop);
			break;
		}
		if (len > 0) {
			break;
		}
		node = get_parent(node);
	}
	return (value);
}

/*
 * Look up a single-int property on exactly this node, with no ancestor walk.
 *
 * Per DTSpec §2.3.5, #address-cells and #size-cells are NOT inherited from
 * ancestors in the devicetree and shall be explicitly defined.  Use this
 * function (not get_prop_int) when looking up cell-count properties.
 */
static int
get_prop_int_local(pnode_t node, const char *name, int def)
{
	int len = promif_getproplen(node, name);
	if (len == sizeof (int)) {
		int prop;
		promif_getprop(node, name, (caddr_t)&prop);
		return (ntohl(prop));
	}
	return (def);
}

static int
get_address_cells(pnode_t node)
{
	return (get_prop_int_local(get_parent(node), OBP_ADDRESS_CELLS,
	    OBP_DEFAULT_ADDRESS_CELLS));
}

static int
get_size_cells(pnode_t node)
{
	return (get_prop_int_local(get_parent(node), OBP_SIZE_CELLS,
	    OBP_DEFAULT_SIZE_CELLS));
}

static int
get_prop_index(pnode_t node, const char *prop_name, const char *name)
{
	int len;
	len = promif_getproplen(node, prop_name);
	if (len > 0) {
		char *prop = __builtin_alloca(len);
		promif_getprop(node, prop_name, prop);
		int offset = 0;
		int index = 0;
		while (offset < len) {
			if (strcmp(name, prop + offset) == 0)
				return (index);
			offset += strlen(prop + offset) + 1;
			index++;
		}
	}
	return (-1);
}

static int
get_reg_bounds(pnode_t node, int index, uint64_t *base, uint64_t *size)
{
	size_t off;
	int len = promif_getproplen(node, OBP_REG);
	if (len <= 0)
		return (-1);

	uint32_t *regs = __builtin_alloca(len);
	promif_getprop(node, OBP_REG, (caddr_t)regs);

	int address_cells = get_address_cells(node);
	int size_cells = get_size_cells(node);

	if (CELLS_1275_TO_BYTES((address_cells + size_cells) *
	    index + address_cells + size_cells) > len) {
		return (-1);
	}

	if (address_cells < 1 || address_cells > 2 ||
	    size_cells < 1 || size_cells > 2)
		return (-1);

	off = (address_cells + size_cells) * index;
	switch (address_cells) {
	case 1:
		*base = ntohl(regs[off]);
		break;
	case 2:
		*base = ntohl(regs[off]);
		*base <<= 32;
		*base |= ntohl(regs[off + 1]);
		break;
	default:
		return (-1);
	}

	off += address_cells;
	switch (size_cells) {
	case 1:
		*size = ntohl(regs[off]);
		break;
	case 2:
		*size = ntohl(regs[off]);
		*size <<= 32;
		*size |= ntohl(regs[off + 1]);
		break;
	default:
		return (-1);
	}

	return (0);
}

static int
promif_get_clock(pnode_t node, int index, struct prom_hwclock *clock)
{
	int len = promif_getproplen(node, "clocks");
	if (len <= 0)
		return (-1);

	uint32_t *clocks = __builtin_alloca(len);
	promif_getprop(node, "clocks", (caddr_t)clocks);

	pnode_t clock_node;
	clock_node = find_by_phandle(ntohl(clocks[0]));
	if (clock_node < 0)
		return (-1);

	int clock_cells = get_prop_int(clock_node, "#clock-cells", 1);
	if (clock_cells != 0 && clock_cells != 1)
		return (-1);

	if (len % (CELLS_1275_TO_BYTES(clock_cells + 1)) != 0)
		return (-1);
	if (len <= index * CELLS_1275_TO_BYTES(clock_cells + 1))
		return (-1);

	clock_node = find_by_phandle(
	    ntohl(clocks[index * (clock_cells + 1)]));
	if (clock_node < 0)
		return (-1);
	clock->node = clock_node;
	clock->id = (clock_cells == 0 ? 0:
	    ntohl(clocks[index * (clock_cells + 1) + 1]));

	return (0);
}

boolean_t
prom_fdt_is_compatible(pnode_t node, const char *name)
{
	int len;
	char *prop_name = OBP_COMPATIBLE;
	len = promif_getproplen(node, prop_name);
	if (len <= 0)
		return (B_FALSE);

	char *prop = __builtin_alloca(len);
	promif_getprop(node, prop_name, prop);

	int offset = 0;
	while (offset < len) {
		if (strcmp(name, prop + offset) == 0)
			return (B_TRUE);
		offset += strlen(prop + offset) + 1;
	}
	return (B_FALSE);
}

int
prom_fdt_get_reg(pnode_t node, int index, uint64_t *base)
{
	uint64_t size;
	return (get_reg_bounds(node, index, base, &size));
}

int
prom_fdt_get_reg_size(pnode_t node, int index, uint64_t *size)
{
	uint64_t base;
	return (get_reg_bounds(node, index, &base, size));
}

int
prom_fdt_get_reg_address(pnode_t node, int index, uint64_t *reg)
{
	uint64_t addr;
	if (prom_fdt_get_reg(node, index, &addr) != 0)
		return (-1);

	pnode_t parent = get_parent(node);
	while (parent > 0) {
		if (!prom_fdt_is_compatible(parent, "simple-bus")) {
			parent = get_parent(parent);
			continue;
		}

		int len = promif_getproplen(parent, OBP_RANGES);
		if (len <= 0) {
			parent = get_parent(parent);
			continue;
		}

		int address_cells = get_prop_int_local(parent,
		    OBP_ADDRESS_CELLS, OBP_DEFAULT_ADDRESS_CELLS);
		int size_cells = get_prop_int_local(parent,
		    OBP_SIZE_CELLS, OBP_DEFAULT_SIZE_CELLS);
		int parent_address_cells = get_prop_int_local(
		    get_parent(parent), OBP_ADDRESS_CELLS,
		    OBP_DEFAULT_ADDRESS_CELLS);

		if ((len % CELLS_1275_TO_BYTES(address_cells +
		    parent_address_cells + size_cells)) != 0) {
			parent = get_parent(parent);
			continue;
		}

		uint32_t *ranges = __builtin_alloca(len);
		promif_getprop(parent, OBP_RANGES, (caddr_t)ranges);
		int ranges_cells =
		    (address_cells + parent_address_cells + size_cells);

		for (int i = 0;
		    i < len / CELLS_1275_TO_BYTES(ranges_cells); i++) {
			uint64_t base = 0;
			uint64_t target = 0;
			uint64_t size = 0;
			for (int j = 0; j < address_cells; j++) {
				base <<= 32;
				base += ntohl(ranges[ranges_cells * i + j]);
			}
			for (int j = 0; j < parent_address_cells; j++) {
				target <<= 32;
				target += ntohl(ranges[
				    ranges_cells * i + address_cells + j]);
			}
			for (int j = 0; j < size_cells; j++) {
				size <<= 32;
				size += ntohl(ranges[
				    ranges_cells * i + address_cells +
				    parent_address_cells + j]);
			}

			if (base <= addr && addr <= base + size - 1) {
				addr = (addr - base) + target;
				break;
			}
		}

		parent = get_parent(parent);
	}

	*reg = addr;
	return (0);
}

int
prom_fdt_get_clock_by_name(pnode_t node,
    const char *name, struct prom_hwclock *clock)
{
	int index = get_prop_index(node, "clock-names", name);
	if (index >= 0)
		return (promif_get_clock(node, index, clock));
	return (-1);
}

/*
 * FDT-specific
 */
const struct fdt_header *
prom_get_fdtp(void)
{
	return (fdtp);
}

/*
 * Platform-specific implementations
 */

void
promif_init(char *pgmname __unused, void *cookie)
{
	fdtp = NULL;
	if (fdt_check_header((struct fdt_header *)cookie) == 0)
		fdtp = (const struct fdt_header *)cookie;
}

void
promif_setup(void)
{
	if (prom_propname_warn == -1)
		prom_propname_warn = 1;
}

/*
 * Classification of cpu-map node types per DTSpec cpu-topology binding.
 *
 * Node names must be "socketN", "clusterN", "coreN", or "threadN".
 */
typedef enum cpumap_level {
	CML_SOCKET,
	CML_CLUSTER,
	CML_CORE,
	CML_THREAD,
	CML_UNKNOWN
} cpumap_level_t;

static cpumap_level_t
cpumap_classify(const char *name)
{
	if (name == NULL) {
		return (CML_UNKNOWN);
	} else if (strncmp(name, "socket", 6) == 0) {
		return (CML_SOCKET);
	} else if (strncmp(name, "cluster", 7) == 0) {
		return (CML_CLUSTER);
	} else if (strncmp(name, "core", 4) == 0) {
		return (CML_CORE);
	} else if (strncmp(name, "thread", 6) == 0) {
		return (CML_THREAD);
	}

	return (CML_UNKNOWN);
}

/*
 * Check that all children of a cpu-map container node share a single
 * classification.  Returns the common type, or CML_UNKNOWN if the node
 * has no children, any child has an unrecognised name, or children have
 * mixed types.
 */
static cpumap_level_t
cpumap_children_type(int parent_off)
{
	cpumap_level_t common = CML_UNKNOWN;
	int child;

	fdt_for_each_subnode(child, fdtp, parent_off) {
		const char *name = fdt_get_name(fdtp, child, NULL);
		cpumap_level_t t = cpumap_classify(name);

		if (t == CML_UNKNOWN) {
			return (CML_UNKNOWN);
		}

		if (common == CML_UNKNOWN) {
			common = t;
		} else if (t != common) {
			return (CML_UNKNOWN);
		}
	}

	return (common);
}

/*
 * Walk the /cpus node of the FDT and extract per-CPU topology information.
 *
 * For each cpu node (device_type = "cpu"):
 * - Read the MPIDR affinity value from the reg property.
 * - Follow the next-level-cache phandle chain to its terminal node.
 *   The terminal node's phandle becomes the LLC group identity. CPUs
 *   sharing the same terminal cache phandle share an LLC.
 * - If /cpus/cpu-map exists, walk its full hierarchy per the DTSpec
 *   cpu-topology binding:
 *     cpu-map -> socketN -> clusterN [-> clusterN] -> coreN [-> threadN]
 *   Socket is optional: clusters may appear directly under cpu-map.
 *   Clusters may nest.  Cores are leaves (no SMT) or contain threads.
 *   Node names are validated against "socketN", "clusterN", "coreN",
 *   "threadN" conventions.
 *
 * When cpu-map is absent or structurally invalid, the flat fallback is
 * applied: all CPUs in socket 0, cluster 0, one core per CPU, no SMT.
 *
 * Returns the number of CPUs found (written to topo[0..n-1]), or -1
 * on error.  max_cpus limits the output array size.
 */
int
prom_fdt_get_cpu_topology(prom_fdt_cpu_topo_t *topo, int max_cpus)
{
	int cpus_off;
	int cpu_off;
	int count = 0;
	int ac;

	if (fdtp == NULL) {
		return (-1);
	}

	cpus_off = fdt_path_offset(fdtp, "/cpus");
	if (cpus_off < 0) {
		return (-1);
	}

	ac = fdt_address_cells(fdtp, cpus_off);
	if (ac != 1 && ac != 2) {
		return (-1);
	}

	/*
	 * We need to match cpu-map leaf "cpu" phandles back to the
	 * enumerated cpu nodes.  Store phandles alongside the topo
	 * entries.  Static because this runs exactly once at boot and
	 * NCPU may be large enough to stress early boot stacks.
	 */
	static uint32_t cpu_phandles[NCPU];

	fdt_for_each_subnode(cpu_off, fdtp, cpus_off) {
		const char *devtype;
		const void *prop;
		int plen;

		devtype = fdt_getprop(fdtp, cpu_off, "device_type", &plen);
		if (devtype == NULL || strcmp(devtype, "cpu") != 0) {
			continue;
		}

		if (count >= max_cpus) {
			break;
		}

		/* MPIDR from reg property */
		prop = fdt_getprop(fdtp, cpu_off, "reg", &plen);
		if (prop == NULL) {
			continue;
		}

		uint64_t mpidr = 0;
		if (ac == 1 && plen >= (int)sizeof (uint32_t)) {
			uint32_t v;
			memcpy(&v, prop, sizeof (v));
			mpidr = fdt32_to_cpu(v);
		} else if (ac == 2 && plen >= (int)(sizeof (uint32_t) * 2)) {
			uint32_t parts[2];
			memcpy(parts, prop, sizeof (parts));
			mpidr = ((uint64_t)fdt32_to_cpu(parts[0]) << 32) |
			    fdt32_to_cpu(parts[1]);
		} else {
			continue;
		}

		topo[count].pft_mpidr = mpidr;

		/*
		 * Follow next-level-cache phandle chain to the terminal
		 * cache node (the one without its own next-level-cache).
		 */
		id_t llc_id = -1;
		int cur_off = cpu_off;
		int depth = 0;
#define	MAX_CACHE_DEPTH	8
		for (;;) {
			if (++depth > MAX_CACHE_DEPTH) {
				cmn_err(CE_WARN, "prom_fdt: invalid "
				    "next-level-cache chain");
				return (-1);
			}

			prop = fdt_getprop(fdtp, cur_off,
			    "next-level-cache", &plen);
			if (prop == NULL || plen != (int)sizeof (uint32_t)) {
				break;
			}

			uint32_t ph;
			memcpy(&ph, prop, sizeof (ph));
			ph = fdt32_to_cpu(ph);
			llc_id = (id_t)ph;
			int cache_off =
			    fdt_node_offset_by_phandle(fdtp, ph);
			if (cache_off < 0) {
				break;
			}

			cur_off = cache_off;
		}
		topo[count].pft_llc_id = llc_id;

		/* Default: single socket, single cluster, unique core */
		topo[count].pft_chip_id = 0;
		topo[count].pft_cluster_id = 0;
		topo[count].pft_core_id = (id_t)count;

		/* Record cpu node phandle for cpu-map matching */
		prop = fdt_getprop(fdtp, cpu_off, "phandle", &plen);
		if (prop != NULL && plen == (int)sizeof (uint32_t)) {
			uint32_t ph;
			memcpy(&ph, prop, sizeof (ph));
			cpu_phandles[count] = fdt32_to_cpu(ph);
		} else {
			cpu_phandles[count] = 0;
		}

		count++;
	}

	/*
	 * Parse cpu-map if present.
	 *
	 * The DTSpec cpu-topology binding defines a strict hierarchy:
	 *   cpu-map -> socketN -> clusterN [-> clusterN] -> coreN [-> threadN]
	 *
	 * Socket is optional (clusters may appear directly under cpu-map).
	 * Clusters may nest (inner clusters group cores within outer ones).
	 * Cores are leaves when there is no SMT, or contain thread nodes.
	 * Node names are mandated: "socketN", "clusterN", "coreN", "threadN".
	 *
	 * We walk depth-first with an explicit stack, classifying each node
	 * by name prefix and validating children at each container level.
	 * Any structural violation causes a bail to the flat fallback
	 * (chip=0, cluster=0, core=cpu ordinal).
	 */
	int cpumap_off = fdt_subnode_offset(fdtp, cpus_off, "cpu-map");
	if (cpumap_off < 0) {
		goto done;
	}

	cpumap_level_t top_type = cpumap_children_type(cpumap_off);
	if (top_type != CML_SOCKET && top_type != CML_CLUSTER) {
		cmn_err(CE_WARN, "prom_fdt: invalid cpu-map structure, "
		    "ignoring");
		goto done;
	}

	id_t next_chip = 0, next_cluster = 0, next_core = 0;
	id_t cur_chip = 0, cur_cluster = 0, cur_core = 0;

#define	CPUMAP_MAX_DEPTH	8
	int wstack[CPUMAP_MAX_DEPTH];
	int wsp = 0;
	int wnode;

	wnode = fdt_first_subnode(fdtp, cpumap_off);
	if (wnode < 0) {
		goto done;
	}

	for (;;) {
		const char *nname;
		cpumap_level_t level;
		boolean_t is_leaf = B_FALSE;

		nname = fdt_get_name(fdtp, wnode, NULL);
		level = cpumap_classify(nname);

		if (level == CML_UNKNOWN) {
			cmn_err(CE_WARN, "prom_fdt: unrecognised cpu-map "
			    "node '%s', ignoring cpu-map",
			    nname != NULL ? nname : "<null>");
			goto cpumap_bail;
		}

		/* Update hierarchy context */
		switch (level) {
		case CML_SOCKET:
			cur_chip = next_chip++;
			break;
		case CML_CLUSTER:
			cur_cluster = next_cluster++;
			break;
		case CML_CORE:
			cur_core = next_core++;
			break;
		default:
			break;
		}

		/* Validate structure and handle leaves */
		switch (level) {
		case CML_SOCKET: {
			cpumap_level_t ct = cpumap_children_type(wnode);
			if (ct != CML_CLUSTER) {
				cmn_err(CE_WARN, "prom_fdt: socket children "
				    "must be clusters, ignoring cpu-map");
				goto cpumap_bail;
			}
			break;
		}
		case CML_CLUSTER: {
			cpumap_level_t ct = cpumap_children_type(wnode);
			if (ct != CML_CLUSTER && ct != CML_CORE) {
				cmn_err(CE_WARN, "prom_fdt: cluster children "
				    "must be clusters or cores, ignoring "
				    "cpu-map");
				goto cpumap_bail;
			}
			break;
		}
		case CML_CORE: {
			int fc = fdt_first_subnode(fdtp, wnode);
			if (fc >= 0) {
				cpumap_level_t ct =
				    cpumap_children_type(wnode);
				if (ct != CML_THREAD) {
					cmn_err(CE_WARN, "prom_fdt: core "
					    "children must be threads, "
					    "ignoring cpu-map");
					goto cpumap_bail;
				}
			} else {
				is_leaf = B_TRUE;
			}
			break;
		}
		case CML_THREAD:
			if (fdt_first_subnode(fdtp, wnode) >= 0) {
				cmn_err(CE_WARN, "prom_fdt: thread node "
				    "must be a leaf, ignoring cpu-map");
				goto cpumap_bail;
			}
			is_leaf = B_TRUE;
			break;
		default:
			goto cpumap_bail;
		}

		/* Match cpu phandle at leaf nodes */
		if (is_leaf) {
			const void *cpuprop;
			int cpulen;

			cpuprop = fdt_getprop(fdtp, wnode, "cpu", &cpulen);
			if (cpuprop == NULL ||
			    cpulen != (int)sizeof (uint32_t)) {
				cmn_err(CE_WARN, "prom_fdt: cpu-map leaf "
				    "'%s' missing cpu phandle, ignoring "
				    "cpu-map",
				    nname != NULL ? nname : "<null>");
				goto cpumap_bail;
			}

			uint32_t cpu_ph;
			memcpy(&cpu_ph, cpuprop, sizeof (cpu_ph));
			cpu_ph = fdt32_to_cpu(cpu_ph);

			for (int i = 0; i < count; i++) {
				if (cpu_phandles[i] == cpu_ph) {
					topo[i].pft_chip_id = cur_chip;
					topo[i].pft_cluster_id = cur_cluster;
					topo[i].pft_core_id = cur_core;
					break;
				}
			}
		}

		/* Descend to first child for container nodes */
		if (!is_leaf) {
			int child = fdt_first_subnode(fdtp, wnode);
			if (child >= 0 && wsp < CPUMAP_MAX_DEPTH) {
				wstack[wsp++] = wnode;
				wnode = child;
				continue;
			}

			if (wsp >= CPUMAP_MAX_DEPTH) {
				cmn_err(CE_WARN,
				    "prom_fdt: cpu-map hierarchy too deep");
				goto cpumap_bail;
			}
		}

		/* Move to next sibling or pop up */
		for (;;) {
			int sib = fdt_next_subnode(fdtp, wnode);
			if (sib >= 0) {
				wnode = sib;
				break;
			}
			if (wsp == 0) {
				goto done;
			}
			wnode = wstack[--wsp];
		}
	}

cpumap_bail:
	for (int i = 0; i < count; i++) {
		topo[i].pft_chip_id = 0;
		topo[i].pft_cluster_id = 0;
		topo[i].pft_core_id = (id_t)i;
	}

done:
	return (count);
}

/*
 * NUMA topology extraction from FDT.
 *
 * Parses numa-node-id properties on CPU and memory nodes, the
 * distance-map node's distance-matrix property, and performs a full
 * tree walk to catch any additional numa-node-id values on device
 * nodes (e.g. PCIe root complexes in their own NUMA domain).
 *
 * All data is returned in static storage valid until the next call.
 */

#define	FDT_NUMA_MAX_NODES	64
#define	FDT_NUMA_MAX_MEM	128
#define	FDT_NUMA_MAX_DIST	(FDT_NUMA_MAX_NODES * FDT_NUMA_MAX_NODES)

static prom_fdt_numa_cpu_t	fdt_numa_cpus[NCPU];
static prom_fdt_numa_mem_t	fdt_numa_mem[FDT_NUMA_MAX_MEM];
static prom_fdt_numa_dist_t	fdt_numa_dist[FDT_NUMA_MAX_DIST];
static uint32_t			fdt_numa_node_ids[FDT_NUMA_MAX_NODES];

/*
 * Add a node ID to the unique set.  Returns B_TRUE if added (new),
 * B_FALSE if already present or the set is full.
 */
static boolean_t
fdt_numa_add_node_id(uint32_t *ids, uint_t *count, uint_t max, uint32_t nid)
{
	uint_t i;

	for (i = 0; i < *count; i++) {
		if (ids[i] == nid) {
			return (B_FALSE);
		}
	}

	if (*count >= max) {
		return (B_FALSE);
	}

	ids[*count] = nid;
	(*count)++;
	return (B_TRUE);
}

/*
 * Read a big-endian u32 cell from an FDT property value at the given
 * byte offset.
 */
static uint32_t
fdt_numa_read_cell32(const void *prop, int byte_off)
{
	fdt32_t v;

	memcpy(&v, (const char *)prop + byte_off, sizeof (fdt32_t));
	return (fdt32_to_cpu(v));
}

/*
 * Read a 64-bit value from 1 or 2 big-endian u32 cells at the given
 * cell index within a property value.
 */
static uint64_t
fdt_numa_read_cells(const void *prop, int cell_index, int ncells)
{
	uint64_t val = 0;
	int i;

	for (i = 0; i < ncells; i++) {
		val <<= 32;
		val |= fdt_numa_read_cell32(prop,
		    (cell_index + i) * sizeof (fdt32_t));
	}

	return (val);
}

/*
 * Record a memory range.  If an entry with the same (base, size) already
 * exists - as happens when the bootloader consolidates multiple /memory
 * nodes' ranges into one node's reg - overwrite its node ID.  A later,
 * more specific /memory node is authoritative for its address range.
 *
 * This odd logic works around what appears to be a bug in qemu virt.
 */
static int
fdt_numa_add_mem(uint_t *nmem, uint64_t base, uint64_t size, uint32_t nid)
{
	uint_t i;

	for (i = 0; i < *nmem; i++) {
		if (fdt_numa_mem[i].pfnm_base == base &&
		    fdt_numa_mem[i].pfnm_size == size) {
			fdt_numa_mem[i].pfnm_node_id = nid;
			return (0);
		}
	}

	if (*nmem >= FDT_NUMA_MAX_MEM) {
		cmn_err(CE_WARN, "prom_fdt: too many NUMA memory nodes");
		return (-1);
	}

	fdt_numa_mem[*nmem].pfnm_base = base;
	fdt_numa_mem[*nmem].pfnm_size = size;
	fdt_numa_mem[*nmem].pfnm_node_id = nid;
	(*nmem)++;
	return (0);
}

void
prom_fdt_get_numa_topo(prom_fdt_numa_topo_t *topo)
{
	int		cpus_off, cpu_off, mem_off, dmap_off, node_off;
	int		addr_cells, size_cells, cpu_addr_cells;
	int		len, depth;
	const void	*prop;
	uint_t		ncpus = 0, nmem = 0, ndist = 0, nnids = 0;
	boolean_t	has_numa = B_FALSE;
	boolean_t	has_dmap = B_FALSE;

	bzero(topo, sizeof (*topo));
	bzero(fdt_numa_cpus, sizeof (fdt_numa_cpus));
	bzero(fdt_numa_mem, sizeof (fdt_numa_mem));
	bzero(fdt_numa_dist, sizeof (fdt_numa_dist));
	bzero(fdt_numa_node_ids, sizeof (fdt_numa_node_ids));

	/*
	 * Step 1: Walk /cpus children for MPIDR and numa-node-id.
	 */
	cpus_off = fdt_path_offset(fdtp, "/cpus");
	if (cpus_off >= 0) {
		/*
		 * CPU reg property uses #address-cells from /cpus.
		 */
		cpu_addr_cells = fdt_address_cells(fdtp, cpus_off);
		if (cpu_addr_cells < 1 || cpu_addr_cells > 2) {
			cmn_err(CE_WARN, "!prom_fdt: /cpus missing or invalid "
			    "#address-cells, NUMA disabled");
			return;
		}

		fdt_for_each_subnode(cpu_off, fdtp, cpus_off) {
			const void *dt_prop;
			int dt_len;
			uint32_t nid;
			uint64_t mpidr;

			/*
			 * Only process nodes with device_type = "cpu".
			 */
			dt_prop = fdt_getprop(fdtp, cpu_off,
			    "device_type", &dt_len);
			if (dt_prop == NULL || dt_len < 4 ||
			    strcmp(dt_prop, "cpu") != 0)
				continue;

			/*
			 * Read MPIDR from reg property.
			 */
			prop = fdt_getprop(fdtp, cpu_off, "reg", &len);
			if (prop == NULL ||
			    len < (int)(cpu_addr_cells * sizeof (fdt32_t)))
				continue;

			mpidr = fdt_numa_read_cells(prop, 0, cpu_addr_cells);

			/*
			 * Read numa-node-id if present.
			 */
			prop = fdt_getprop(fdtp, cpu_off,
			    "numa-node-id", &len);
			if (prop == NULL || len != (int)sizeof (fdt32_t))
				continue;

			nid = fdt_numa_read_cell32(prop, 0);
			has_numa = B_TRUE;

			if (ncpus < NCPU) {
				fdt_numa_cpus[ncpus].pfnc_mpidr = mpidr;
				fdt_numa_cpus[ncpus].pfnc_node_id = nid;
				ncpus++;
			}
			fdt_numa_add_node_id(fdt_numa_node_ids, &nnids,
			    FDT_NUMA_MAX_NODES, nid);
		}
	}

	/*
	 * Step 2: Walk /memory nodes for address ranges and numa-node-id.
	 * Use fdt_node_offset_by_prop_value to find all nodes with
	 * device_type = "memory".
	 */
	addr_cells = fdt_address_cells(fdtp, 0);
	if (addr_cells < 1 || addr_cells > 2) {
		cmn_err(CE_WARN, "!prom_fdt: / missing or invalid "
		    "#address-cells, NUMA disabled");
		return;
	}

	size_cells = fdt_size_cells(fdtp, 0);
	if (size_cells < 1 || size_cells > 2) {
		cmn_err(CE_WARN, "!prom_fdt: / missing or invalid "
		    "#size-cells, NUMA disabled");
		return;
	}

	mem_off = fdt_node_offset_by_prop_value(fdtp, -1,
	    "device_type", "memory", sizeof ("memory"));
	while (mem_off >= 0) {
		uint32_t nid;
		int tuple_size, ntuples, t;

		/*
		 * Read numa-node-id if present.
		 */
		prop = fdt_getprop(fdtp, mem_off, "numa-node-id", &len);
		if (prop != NULL && len == (int)sizeof (fdt32_t)) {
			nid = fdt_numa_read_cell32(prop, 0);
			has_numa = B_TRUE;

			fdt_numa_add_node_id(fdt_numa_node_ids, &nnids,
			    FDT_NUMA_MAX_NODES, nid);

			/*
			 * Parse reg property: may contain multiple
			 * (base, size) tuples, each using the root's
			 * #address-cells and #size-cells.
			 */
			prop = fdt_getprop(fdtp, mem_off, "reg", &len);
			if (prop != NULL) {
				tuple_size = (addr_cells + size_cells) *
				    (int)sizeof (fdt32_t);
				ntuples = len / tuple_size;

				for (t = 0; t < ntuples && nmem <
				    FDT_NUMA_MAX_MEM; t++) {
					uint64_t base, size;
					int cell_idx;

					cell_idx = t *
					    (addr_cells + size_cells);
					base = fdt_numa_read_cells(prop,
					    cell_idx, addr_cells);
					size = fdt_numa_read_cells(prop,
					    cell_idx + addr_cells,
					    size_cells);

					if (size == 0) {
						continue;
					}

					if (fdt_numa_add_mem(
					    &nmem, base, size, nid) != 0) {
						return;
					}
				}
			}
		}

		mem_off = fdt_node_offset_by_prop_value(fdtp, mem_off,
		    "device_type", "memory", sizeof ("memory"));
	}

	/*
	 * Step 3: Parse /distance-map node.
	 */
	dmap_off = fdt_node_offset_by_compatible(fdtp, -1,
	    "numa-distance-map-v1");
	if (dmap_off >= 0) {
		prop = fdt_getprop(fdtp, dmap_off, "distance-matrix", &len);
		if (prop != NULL && len > 0) {
			if (len % sizeof (fdt32_t) != 0 ||
			    (len / sizeof (fdt32_t)) % 3 != 0) {
				cmn_err(CE_WARN, "!prom_fdt: invalid "
				    "distance-matrix, NUMA disabled");
				return;
			}

			int entry_count = len / (int)sizeof (fdt32_t);
			int i;

			has_dmap = B_TRUE;
			if (has_numa == B_FALSE && entry_count >= 3) {
				has_numa = B_TRUE;
			}

			for (i = 0; i + 2 < entry_count &&
			    ndist < FDT_NUMA_MAX_DIST; i += 3) {
				uint32_t from, to, dist;

				from = fdt_numa_read_cell32(prop,
				    i * (int)sizeof (fdt32_t));
				to = fdt_numa_read_cell32(prop,
				    (i + 1) * (int)sizeof (fdt32_t));
				dist = fdt_numa_read_cell32(prop,
				    (i + 2) * (int)sizeof (fdt32_t));

				fdt_numa_dist[ndist].pfnd_from = from;
				fdt_numa_dist[ndist].pfnd_to = to;
				fdt_numa_dist[ndist].pfnd_distance = dist;
				ndist++;

				fdt_numa_add_node_id(fdt_numa_node_ids,
				    &nnids, FDT_NUMA_MAX_NODES, from);
				fdt_numa_add_node_id(fdt_numa_node_ids,
				    &nnids, FDT_NUMA_MAX_NODES, to);
			}
		}
	}

	/*
	 * Step 4: Full tree walk for any remaining numa-node-id
	 * properties on device nodes (e.g. PCIe root complexes).
	 */
	depth = 0;
	node_off = fdt_next_node(fdtp, -1, &depth);
	while (node_off >= 0 && depth >= 0) {
		prop = fdt_getprop(fdtp, node_off, "numa-node-id", &len);
		if (prop != NULL && len == (int)sizeof (fdt32_t)) {
			uint32_t nid = fdt_numa_read_cell32(prop, 0);

			has_numa = B_TRUE;
			fdt_numa_add_node_id(fdt_numa_node_ids, &nnids,
			    FDT_NUMA_MAX_NODES, nid);
		}
		node_off = fdt_next_node(fdtp, node_off, &depth);
	}

	/*
	 * Fill in the result structure.
	 */
	topo->pfnt_cpus = fdt_numa_cpus;
	topo->pfnt_ncpus = ncpus;
	topo->pfnt_mem = fdt_numa_mem;
	topo->pfnt_nmem = nmem;
	topo->pfnt_dist = fdt_numa_dist;
	topo->pfnt_ndist = ndist;
	topo->pfnt_node_ids = fdt_numa_node_ids;
	topo->pfnt_nnode_ids = nnids;
	topo->pfnt_has_numa = has_numa;
	topo->pfnt_has_distance_map = has_dmap;
}
