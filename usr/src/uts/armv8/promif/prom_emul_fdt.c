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
 * Copyright 2025 Michael van der Westhuizen
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
		if (strcmp(name, "name") == 0) {
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
		if (strcmp(name, "unit-address") == 0) {
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
		if (strcmp(name, "name") == 0) {
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
		if (strcmp(name, "unit-address") == 0) {
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
		strlcpy(next, "name", OBP_MAXPROPNAME);
		return (next);
	}

	/*
	 * The second time we're called, present the "unit-address"
	 * pseudo-property, if appropriate
	 */
	if (strcmp(name, "name") == 0) {
		int len;
		const char *fullname = fdt_get_name(fdtp, offset, &len);

		if (strchr(fullname, '@') != NULL) {
			strlcpy(next, "unit-address", OBP_MAXPROPNAME);
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
			if ((strcmp(name, "name") == 0) ||
			    (strcmp(name, "unit-address") == 0)) {
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

static int
get_address_cells(pnode_t node)
{
	return (get_prop_int(get_parent(node), "#address-cells", 2));
}

static int
get_size_cells(pnode_t node)
{
	return (get_prop_int(get_parent(node), "#size-cells", 2));
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
	int len = promif_getproplen(node, "reg");
	if (len <= 0)
		return (-1);

	uint32_t *regs = __builtin_alloca(len);
	promif_getprop(node, "reg", (caddr_t)regs);

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
	char *prop_name = "compatible";
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

		int len = promif_getproplen(parent, "ranges");
		if (len <= 0) {
			parent = get_parent(parent);
			continue;
		}

		int address_cells = get_prop_int(parent, "#address-cells", 2);
		int size_cells = get_prop_int(parent, "#size-cells", 2);
		int parent_address_cells = get_prop_int(
		    get_parent(parent), "#address-cells", 2);

		if ((len % CELLS_1275_TO_BYTES(address_cells +
		    parent_address_cells + size_cells)) != 0) {
			parent = get_parent(parent);
			continue;
		}

		uint32_t *ranges = __builtin_alloca(len);
		promif_getprop(parent, "ranges", (caddr_t)ranges);
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
