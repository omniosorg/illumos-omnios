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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2019 Western Digital Corporation
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * PCI bus enumeration and device programming are done in several passes. The
 * following is a high level overview of this process.
 *
 * pci_enumerate()
 *				The main entry point to PCI bus enumeration is
 *				pci_enumerate(). This function is invoked
 *				twice, once to set up the PCI portion of the
 *				device tree, and then a second time to
 *				reprogram devices.
 *   pci_setup_tree()
 *	enumerate_bus_devs(CONFIG_INFO)
 *	    <foreach bus>
 *	        process_devfunc(CONFIG_INFO)
 *	            <set up most device properties>
 *				The next stage is to enumerate the bus and set
 *				up the bulk of the properties for each device.
 *				This is where the generic properties such as
 *				'device-id' are created.
 *		    <if PPB device>
 *			add_ppb_props()
 *				For a PCI-to-PCI bridge (ppb) device, any
 *				memory ranges for IO, memory or pre-fetchable
 *				memory that have been programmed by the system
 *				firmware (BIOS/EFI) are retrieved and stored in
 *				bus-specific lists (pci_bus_res[bus].io_avail,
 *				mem_avail and pmem_avail). The contents of
 *				these lists are used to set the initial 'ranges'
 *				property on the ppb device. Later, as children
 *				are found for this bridge, resources will be
 *				removed from these avail lists as necessary.
 *
 *				If the IO or memory ranges have not been
 *				programmed by this point, indicated by the
 *				appropriate bit in the control register being
 *				unset or, in the memory case only, by the base
 *				address being 0, then the range is explicitly
 *				disabled here by setting base > limit for
 *				the resource. Since a zero address is
 *				technically valid for the IO case, the base
 *				address is not checked for IO.
 *
 *				This is an initial pass so the ppb devices will
 *				still be reprogrammed later in fix_ppb_res().
 *		    <else>
 *			<add to list of non-PPB devices for the bus>
 *				Any non-PPB device on the bus is recorded in a
 *				bus-specific list, to be set up later.
 *		    add_reg_props(CONFIG_INFO)
 *				The final step in this phase is to add the
 *				initial 'reg' and 'assigned-addresses'
 *				properties to all devices. At the same time,
 *				any IO or memory ranges which have been
 *				assigned to the bus are moved from the avail
 *				list to the corresponding used one.
 * ...
 *				The second bus enumeration pass is to take care
 *				of any devices that were not set up by the
 *				system firmware. These devices were flagged
 *				during the first pass. This pass is bracketed
 *				by the same pci fix application and removal as
 *				the first.
 *   pci_reprogram()
 *	pci_prd_root_complex_iter()
 *				The platform is asked to tell us of all root
 *				complexes that it knows about (e.g. using the
 *				_BBN method via ACPI). This will include buses
 *				that we've already discovered and those that we
 *				potentially haven't. Anything that has not been
 *				previously discovered (or inferred to exist) is
 *				then added to the system.
 *	<foreach ROOT bus>
 *	    populate_bus_res()
 *				Find resources associated with this root bus
 *				based on what the platform provides through the
 *				pci platform interfaces defined in
 *				sys/plat/pci_prd.h. On i86pc this is driven by
 *				ACPI and BIOS tables.
 *	<foreach bus>
 *	    fix_ppb_res()
 *				Reprogram pci(e) bridges.
 *	    enumerate_bus_devs(CONFIG_NEW)
 *		<foreach non-PPB device on the bus>
 *		    add_reg_props(CONFIG_NEW)
 *				Using the list of non-PPB devices on the bus
 *				which was assembled during the first pass, add
 *				or update the 'reg' and 'assigned-address'
 *				properties for these devices. Assign and program
 *				resources into the device. This can result in
 *				these properties changing from their previous
 *				values.
 *	<foreach bus>
 *	    add_bus_available_prop()
 *				Finally, the 'available' properties is set on
 *				each device, representing that device's final
 *				unallocated (available) IO and memory ranges.
 */

#include <sys/ddi.h>
#include <sys/memlist.h>
#include <sys/obpdefs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>

#include <sys/pci.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_impl.h>
#include <sys/pci_memlist.h>
#include <sys/pci_props.h>
#include <sys/pcie_impl.h>
#include <sys/plat/pci_prd.h>

#define	dcmn_err	if (pci_boot_debug != 0) cmn_err
#define	bus_debug(bus)	(pci_boot_debug != 0 && pci_debug_bus_start != -1 && \
	    pci_debug_bus_end != -1 && (bus) >= pci_debug_bus_start && \
	    (bus) <= pci_debug_bus_end)
#define	dump_memlists(pbr, tag, bus)				\
	if (bus_debug((bus))) dump_memlists_impl(pbr, (tag), (bus))
#define	MSGHDR		"!pci_boot: %s[%02x/%02x/%x]: "

typedef enum {
	CONFIG_INFO,
	CONFIG_UPDATE,
	CONFIG_NEW,
} config_phase_t;

#define	PPB_IO_ALIGNMENT	0x1000		/* 4K aligned */
#define	PPB_MEM_ALIGNMENT	0x100000	/* 1M aligned */

/* round down _at least once_ to nearest power of two */
static inline uint_t
lowerp2(uint_t align)
{
	uint_t i = 0;

	while (align >>= 1) {
		i++;
	}

	return (1 << i);
}

/*
 * Determining the size of a PCI BAR is done by writing all 1s to the base
 * register and then reading the value back. The retrieved value will either
 * be zero, indicating that the BAR is unimplemented, or a mask in which
 * the significant bits for the required memory space are 0.
 * For example, a 32-bit BAR could return 0xfff00000 which equates to a
 * length of 0x100000 (1MiB). The following macro does that conversion.
 * The input value must have already had the lower encoding bits cleared.
 */
#define	BARMASKTOLEN(value) ((((value) ^ ((value) - 1)) + 1) >> 1)

typedef enum {
	RES_IO,
	RES_MEM,
	RES_PMEM
} mem_res_t;

/*
 * In order to disable an IO or memory range on a bridge, the range's base must
 * be set to a value greater than its limit. The following values are used for
 * this purpose.
 */
#define	PPB_DISABLE_IORANGE_BASE	0x9fff
#define	PPB_DISABLE_IORANGE_LIMIT	0x1000
#define	PPB_DISABLE_MEMRANGE_BASE	0x9ff00000
#define	PPB_DISABLE_MEMRANGE_LIMIT	0x100fffff

/*
 * Value used to indicate that a bus hasn't yet been set.
 *
 * It being the maximum valid bus number seems like a problem but is not,
 * because we're caring about the parent side of bridges.  If the parent is
 * bus 255, there's no room for a child.
 */
#define	NO_PAR_BUS	(uchar_t)-1

struct pci_devfunc {
	struct pci_devfunc *next;
	dev_info_t *dip;
	uchar_t dev;
	uchar_t func;
};

static uchar_t max_dev_pci = PCI_MAX_DEVICES;
int pci_boot_maxbus;

int pci_boot_debug = 0;
int pci_debug_bus_start = 0;
int pci_debug_bus_end = PCI_MAX_BUS_NUM - 1;

extern dev_info_t *pcie_get_rc_dip(dev_info_t *);

/*
 * Module prototypes
 */
static void enumerate_bus_devs(dev_info_t *, uchar_t,
    struct pci_bus_resource *, config_phase_t);
static void process_devfunc(dev_info_t *, struct pci_bus_resource *,
    uchar_t, uchar_t, uchar_t, config_phase_t);
static void add_reg_props(dev_info_t *, dev_info_t *,
    struct pci_bus_resource *, uchar_t, uchar_t, uchar_t, config_phase_t);
static void add_ppb_props(dev_info_t *, dev_info_t *, struct pci_bus_resource *,
    uchar_t, uchar_t, uchar_t, boolean_t, boolean_t);
static void add_bus_range_prop(struct pci_bus_resource *, int);
static void add_ranges_prop(struct pci_bus_resource *, int, boolean_t);
static void add_bus_available_prop(struct pci_bus_resource *, int);
static void alloc_res_array(struct pci_bus_resource **, size_t);
static void pci_memlist_remove_list(struct memlist **, struct memlist *);
static void populate_bus_res(dev_info_t *, struct pci_bus_resource *,
    uchar_t);
static void pci_reprogram(dev_info_t *, struct pci_bus_resource *);
static void dip_bus_range(dev_info_t *, int *);

static void
dump_memlists_impl(struct pci_bus_resource *pci_bus_res, const char *tag,
    int bus)
{
	printf("Memlist dump at %s - bus %x\n", tag, bus);
	if (pci_bus_res[bus].io_used != NULL) {
		printf("    io_used ");
		pci_memlist_dump(pci_bus_res[bus].io_used);
	}
	if (pci_bus_res[bus].io_avail != NULL) {
		printf("    io_avail ");
		pci_memlist_dump(pci_bus_res[bus].io_avail);
	}
	if (pci_bus_res[bus].mem_used != NULL) {
		printf("    mem_used ");
		pci_memlist_dump(pci_bus_res[bus].mem_used);
	}
	if (pci_bus_res[bus].mem_avail != NULL) {
		printf("    mem_avail ");
		pci_memlist_dump(pci_bus_res[bus].mem_avail);
	}
	if (pci_bus_res[bus].pmem_used != NULL) {
		printf("    pmem_used ");
		pci_memlist_dump(pci_bus_res[bus].pmem_used);
	}
	if (pci_bus_res[bus].pmem_avail != NULL) {
		printf("    pmem_avail ");
		pci_memlist_dump(pci_bus_res[bus].pmem_avail);
	}
}

/*
 * Enumerate all PCI devices
 */
static void
pci_setup_tree(dev_info_t *dip, struct pci_bus_resource *pci_bus_res)
{
	for (uint_t i = 0; i <= pci_boot_maxbus; i++) {
		pci_bus_res[i].par_bus = NO_PAR_BUS;
		pci_bus_res[i].sub_bus = i;
	}

	int busrng[2];

	dip_bus_range(dip, busrng);

	VERIFY3P(pci_bus_res[busrng[0]].dip, ==, NULL);

	/*
	 * The first bus is _our_ bus, others in the range
	 * are available to subordinate bridges.
	 */
	pci_bus_res[busrng[0]].dip = dip;

	for (int i = busrng[0]; i <= busrng[1]; i++) {
		enumerate_bus_devs(dip, i, pci_bus_res, CONFIG_INFO);
	}
}

void
pci_enumerate(dev_info_t *dip)
{
	struct pci_bus_resource *pci_bus_res;

	pci_boot_maxbus = pci_prd_max_bus();

	alloc_res_array(&pci_bus_res, pci_boot_maxbus);
	pci_setup_tree(dip, pci_bus_res);
	pci_reprogram(dip, pci_bus_res);
}

/*
 * Retrieve, or default, the "bus-range" property.
 */
void
dip_bus_range(dev_info_t *dip, int *busrng)
{
	int *bus_prop;
	uint_t bus_prop_sz;

	busrng[0] = 0;
	busrng[1] = pci_prd_max_bus();

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_BUS_RANGE,
	    &bus_prop, &bus_prop_sz) == DDI_SUCCESS) {
		VERIFY3U(bus_prop_sz, ==, 2);
		busrng[0] = bus_prop[0];
		busrng[1] = bus_prop[1];
		ddi_prop_free(bus_prop);
	}
}

/*
 * Remove the resources which are already used by devices under a subtractive
 * bridge from the bus's resources lists, because they're not available, and
 * shouldn't be allocated to other buses.  This is necessary because tracking
 * resources for subtractive bridges is not complete.  (Subtractive bridges only
 * track some of their claimed resources, not "the rest of the address space" as
 * they should, so that allocation to peer non-subtractive PPBs is easier.  We
 * need a fully-capable global resource allocator).
 */
static void
remove_subtractive_res(struct pci_bus_resource *pci_bus_res)
{
	int i, j;
	struct memlist *list;

	for (i = 0; i <= pci_boot_maxbus; i++) {
		if (pci_bus_res[i].subtractive) {
			/* remove used io ports */
			list = pci_bus_res[i].io_used;
			while (list) {
				for (j = 0; j <= pci_boot_maxbus; j++)
					(void) pci_memlist_remove(
					    &pci_bus_res[j].io_avail,
					    list->ml_address, list->ml_size);
				list = list->ml_next;
			}
			/* remove used mem resource */
			list = pci_bus_res[i].mem_used;
			while (list) {
				for (j = 0; j <= pci_boot_maxbus; j++) {
					(void) pci_memlist_remove(
					    &pci_bus_res[j].mem_avail,
					    list->ml_address, list->ml_size);
					(void) pci_memlist_remove(
					    &pci_bus_res[j].pmem_avail,
					    list->ml_address, list->ml_size);
				}
				list = list->ml_next;
			}
			/* remove used prefetchable mem resource */
			list = pci_bus_res[i].pmem_used;
			while (list) {
				for (j = 0; j <= pci_boot_maxbus; j++) {
					(void) pci_memlist_remove(
					    &pci_bus_res[j].pmem_avail,
					    list->ml_address, list->ml_size);
					(void) pci_memlist_remove(
					    &pci_bus_res[j].mem_avail,
					    list->ml_address, list->ml_size);
				}
				list = list->ml_next;
			}
		}
	}
}

/*
 * Set up (or complete the setup of) the bus_avail resource list
 */
static void
setup_bus_res(struct pci_bus_resource *pci_bus_res, int bus)
{
	uchar_t par_bus;

	if (pci_bus_res[bus].dip == NULL)	/* unused bus */
		return;

	/*
	 * Set up bus_avail if not already filled in by populate_bus_res()
	 */
	if (pci_bus_res[bus].bus_avail == NULL) {
		ASSERT(pci_bus_res[bus].sub_bus >= bus);
		pci_memlist_insert(&pci_bus_res[bus].bus_avail, bus,
		    pci_bus_res[bus].sub_bus - bus + 1);
	}

	ASSERT(pci_bus_res[bus].bus_avail != NULL);

	/*
	 * Remove resources from parent bus node if this is not a
	 * root bus.
	 */
	par_bus = pci_bus_res[bus].par_bus;
	if (par_bus != NO_PAR_BUS) {
		ASSERT(pci_bus_res[par_bus].bus_avail != NULL);
		pci_memlist_remove_list(&pci_bus_res[par_bus].bus_avail,
		    pci_bus_res[bus].bus_avail);
	}

	/* remove self from bus_avail */;
	(void) pci_memlist_remove(&pci_bus_res[bus].bus_avail, bus, 1);
}

/*
 * Return the bus from which resources should be allocated. A device under a
 * subtractive PPB can allocate resources from its parent bus if there are no
 * resources available on its own bus, so iterate up the chain until resources
 * are found or the root is reached.
 */
static uchar_t
resolve_alloc_bus(struct pci_bus_resource *pci_bus_res, uchar_t bus,
    mem_res_t type)
{
	while (pci_bus_res[bus].subtractive) {
		if (type == RES_IO && pci_bus_res[bus].io_avail != NULL)
			break;
		if (type == RES_MEM && pci_bus_res[bus].mem_avail != NULL)
			break;
		if (type == RES_PMEM && pci_bus_res[bus].pmem_avail != NULL)
			break;
		/* Has the root bus been reached? */
		if (pci_bus_res[bus].par_bus == NO_PAR_BUS)
			break;
		bus = pci_bus_res[bus].par_bus;
	}

	return (bus);
}

/*
 * Each root port has a record of the number of PCIe bridges that is under it
 * and the amount of memory that is has available which is not otherwise
 * required for BARs.
 *
 * This function finds the root port for a given bus and returns the amount of
 * spare memory that is available for allocation to any one of its bridges.
 */
static uint64_t
get_per_bridge_avail(struct pci_bus_resource *pci_bus_res, uchar_t bus)
{
	uchar_t par_bus;

	par_bus = pci_bus_res[bus].par_bus;
	while (par_bus != NO_PAR_BUS) {
		bus = par_bus;
		par_bus = pci_bus_res[par_bus].par_bus;
	}

	if (pci_bus_res[bus].mem_buffer == 0 ||
	    pci_bus_res[bus].num_bridge == 0) {
		return (0);
	}

	return (pci_bus_res[bus].mem_buffer / pci_bus_res[bus].num_bridge);
}

static uint64_t
lookup_parbus_res(struct pci_bus_resource *pci_bus_res, uchar_t parbus,
    uint64_t size, uint64_t align, mem_res_t type)
{
	struct memlist **list;
	uint64_t addr;

	parbus = resolve_alloc_bus(pci_bus_res, parbus, type);

	switch (type) {
	case RES_IO:
		list = &pci_bus_res[parbus].io_avail;
		break;
	case RES_MEM:
		list = &pci_bus_res[parbus].mem_avail;
		break;
	case RES_PMEM:
		list = &pci_bus_res[parbus].pmem_avail;
		break;
	default:
		panic("Invalid resource type %d", type);
	}

	if (*list == NULL)
		return (0);

	addr = pci_memlist_find(list, size, align);

	return (addr);
}

/*
 * Allocate a resource from the parent bus
 */
static uint64_t
get_parbus_res(struct pci_bus_resource *pci_bus_res, uchar_t parbus,
    uchar_t bus, uint64_t size, uint64_t align, mem_res_t type)
{
	struct memlist **par_avail, **par_used, **avail, **used;
	uint64_t addr;

	parbus = resolve_alloc_bus(pci_bus_res, parbus, type);

	switch (type) {
	case RES_IO:
		par_avail = &pci_bus_res[parbus].io_avail;
		par_used = &pci_bus_res[parbus].io_used;
		avail = &pci_bus_res[bus].io_avail;
		used = &pci_bus_res[bus].io_used;
		break;
	case RES_MEM:
		par_avail = &pci_bus_res[parbus].mem_avail;
		par_used = &pci_bus_res[parbus].mem_used;
		avail = &pci_bus_res[bus].mem_avail;
		used = &pci_bus_res[bus].mem_used;
		break;
	case RES_PMEM:
		par_avail = &pci_bus_res[parbus].pmem_avail;
		par_used = &pci_bus_res[parbus].pmem_used;
		avail = &pci_bus_res[bus].pmem_avail;
		used = &pci_bus_res[bus].pmem_used;
		break;
	default:
		panic("Invalid resource type %d", type);
	}

	/* Return any existing resources to the parent bus */
	pci_memlist_subsume(used, avail);
	for (struct memlist *m = *avail; m != NULL; m = m->ml_next) {
		(void) pci_memlist_remove(par_used, m->ml_address, m->ml_size);
		pci_memlist_insert(par_avail, m->ml_address, m->ml_size);
	}
	pci_memlist_free_all(avail);

	addr = lookup_parbus_res(pci_bus_res, parbus, size, align, type);

	/*
	 * The system may have provided a 64-bit non-PF memory region to the
	 * parent bus, but we cannot use that for programming a bridge. Since
	 * the memlists are kept sorted by base address and searched in order,
	 * then if we received a 64-bit address here we know that the request
	 * is unsatisfiable from the available 32-bit ranges.
	 */
	if (type == RES_MEM &&
	    (addr >= UINT32_MAX || addr >= UINT32_MAX - size)) {
		return (0);
	}

	if (addr != 0) {
		pci_memlist_insert(par_used, addr, size);
		(void) pci_memlist_remove(par_avail, addr, size);
		pci_memlist_insert(avail, addr, size);
	}

	return (addr);
}

/*
 * given a cap_id, return its cap_id location in config space
 */
static int
get_pci_cap(dev_info_t *rcdip, uchar_t bus, uchar_t dev, uchar_t func,
    uint8_t cap_id)
{
	uint8_t curcap, cap_id_loc;
	uint16_t status;
	int location = -1;

	/*
	 * Need to check the Status register for ECP support first.
	 * Also please note that for type 1 devices, the
	 * offset could change. Should support type 1 next.
	 */
	status = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP)) {
		return (-1);
	}
	cap_id_loc = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_CAP_PTR);

	/* Walk the list of capabilities */
	while (cap_id_loc && cap_id_loc != (uint8_t)-1) {
		curcap = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    cap_id_loc);

		if (curcap == cap_id) {
			location = cap_id_loc;
			break;
		}
		cap_id_loc = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    cap_id_loc + 1);
	}
	return (location);
}

static void
set_ppb_res(dev_info_t *rcdip, dev_info_t *dip, uchar_t bus, uchar_t dev,
    uchar_t func, mem_res_t type, uint64_t base, uint64_t limit)
{
	char *tag;

	switch (type) {
	case RES_IO: {
		VERIFY0(base >> 32);
		VERIFY0(limit >> 32);

		pci_cfgacc_put8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_BASE_LOW,
		    (uint8_t)((base >> PCI_BCNF_IO_SHIFT) & PCI_BCNF_IO_MASK));
		pci_cfgacc_put8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_LIMIT_LOW,
		    (uint8_t)((limit >> PCI_BCNF_IO_SHIFT) & PCI_BCNF_IO_MASK));

		uint8_t val = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_BASE_LOW);
		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_IO_32BIT) {
			pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
			    PCI_BCNF_IO_BASE_HI, base >> 16);
			pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
			    PCI_BCNF_IO_LIMIT_HI, limit >> 16);
		} else {
			VERIFY0(base >> 16);
			VERIFY0(limit >> 16);
		}

		tag = "I/O";
		break;
	}

	case RES_MEM:
		VERIFY0(base >> 32);
		VERIFY0(limit >> 32);

		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_MEM_BASE, (uint16_t)((base >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_MEM_LIMIT,
		    (uint16_t)((limit >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));

		tag = "MEM";
		break;

	case RES_PMEM: {
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_PF_BASE_LOW,
		    (uint16_t)((base >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_PF_LIMIT_LOW,
		    (uint16_t)((limit >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));

		uint16_t val = pci_cfgacc_get16(rcdip,
		    PCI_GETBDF(bus, dev, func), PCI_BCNF_PF_BASE_LOW);
		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_PF_MEM_64BIT) {
			pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
			    PCI_BCNF_PF_BASE_HIGH, base >> 32);
			pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
			    PCI_BCNF_PF_LIMIT_HIGH, limit >> 32);
		} else {
			VERIFY0(base >> 32);
			VERIFY0(limit >> 32);
		}

		tag = "PMEM";
		break;
	}

	default:
		panic("Invalid resource type %d", type);
	}

	if (base > limit) {
		cmn_err(CE_NOTE, MSGHDR "DISABLE %4s range",
		    ddi_node_name(dip), bus, dev, func, tag);
	} else {
		cmn_err(CE_NOTE,
		    MSGHDR "PROGRAM %4s range 0x%lx ~ 0x%lx",
		    ddi_node_name(dip), bus, dev, func, tag, base, limit);
	}
}

static void
fetch_ppb_res(dev_info_t *rcdip, uchar_t bus, uchar_t dev, uchar_t func,
    mem_res_t type, uint64_t *basep, uint64_t *limitp)
{
	uint64_t val, base, limit;

	switch (type) {
	case RES_IO:
		val = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_LIMIT_LOW);
		limit = ((val & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT) |
		    PCI_BCNF_IO_LIMIT_BITS;
		val = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_IO_BASE_LOW);
		base = ((val & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT);

		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_IO_32BIT) {
			val = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_BCNF_IO_BASE_HI);
			base |= val << 16;
			val = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_BCNF_IO_LIMIT_HI);
			limit |= val << 16;
		}
		VERIFY0(base >> 32);
		break;

	case RES_MEM:
		val = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_MEM_LIMIT);
		limit = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT) |
		    PCI_BCNF_MEM_LIMIT_BITS;
		val = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_MEM_BASE);
		base = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT);
		VERIFY0(base >> 32);
		break;

	case RES_PMEM:
		val = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_PF_LIMIT_LOW);
		limit = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT) |
		    PCI_BCNF_MEM_LIMIT_BITS;
		val = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_BCNF_PF_BASE_LOW);
		base = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT);

		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_PF_MEM_64BIT) {
			val = pci_cfgacc_get32(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_BCNF_PF_BASE_HIGH);
			base |= val << 32;
			val = pci_cfgacc_get32(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_BCNF_PF_LIMIT_HIGH);
			limit |= val << 32;
		}
		break;
	default:
		panic("Invalid resource type %d", type);
	}

	*basep = base;
	*limitp = limit;
}

/*
 * Assign valid resources to PCI(e) bridges.
 */
static void
fix_ppb_res(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res,
    uchar_t secbus, boolean_t prog_sub)
{
	uchar_t bus, dev, func;
	uchar_t parbus, subbus;
	struct {
		uint64_t base;
		uint64_t limit;
		uint64_t size;
		uint64_t align;
	} io, mem, pmem;
	uint64_t addr = 0;
	int *regp = NULL;
	uint_t reglen, buscount;
	int rv, cap_ptr, physhi;
	dev_info_t *dip;
	uint16_t cmd_reg;

	/* skip root (peer) PCI busses */
	if (pci_bus_res[secbus].par_bus == NO_PAR_BUS)
		return;

	/* skip subtractive PPB when prog_sub is not TRUE */
	if (pci_bus_res[secbus].subtractive && !prog_sub)
		return;

	/* some entries may be empty due to discontiguous bus numbering */
	dip = pci_bus_res[secbus].dip;
	if (dip == NULL)
		return;

	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_REG, &regp, &reglen);
	if (rv != DDI_PROP_SUCCESS || reglen == 0)
		return;
	physhi = regp[0];
	ddi_prop_free(regp);

	func = (uchar_t)PCI_REG_FUNC_G(physhi);
	dev = (uchar_t)PCI_REG_DEV_G(physhi);
	bus = (uchar_t)PCI_REG_BUS_G(physhi);

	dump_memlists(pci_bus_res, "fix_ppb_res start bus", bus);
	dump_memlists(pci_bus_res, "fix_ppb_res start secbus", secbus);

	/*
	 * If pcie bridge, check to see if link is enabled
	 */
	cap_ptr = get_pci_cap(rcdip, bus, dev, func, PCI_CAP_ID_PCI_E);
	if (cap_ptr != -1) {
		uint16_t reg = pci_cfgacc_get16(rcdip,
		    PCI_GETBDF(bus, dev, func),
		    (uint16_t)cap_ptr + PCIE_LINKCTL);
		if ((reg & PCIE_LINKCTL_LINK_DISABLE) != 0) {
			dcmn_err(CE_NOTE, MSGHDR "link is disabled",
			    ddi_node_name(dip), bus, dev, func);
			return;
		}
	}

	subbus = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_BCNF_SUBBUS);
	parbus = pci_bus_res[secbus].par_bus;
	ASSERT(parbus == bus);
	cmd_reg = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_COMM);

	buscount = subbus - secbus + 1;

	dcmn_err(CE_NOTE, MSGHDR
	    "secbus 0x%x existing sizes I/O 0x%x, MEM 0x%lx, PMEM 0x%lx",
	    ddi_node_name(dip), bus, dev, func, secbus,
	    pci_bus_res[secbus].io_size, pci_bus_res[secbus].mem_size,
	    pci_bus_res[secbus].pmem_size);

	/*
	 * The bridge is going to be allocated the greater of:
	 *  - 512 bytes per downstream bus;
	 *  - the amount required by its current children.
	 * rounded up to the next 4K.
	 */
	io.size = MAX(pci_bus_res[secbus].io_size, buscount * 0x200);

	/*
	 * We'd like to assign some extra memory to the bridge in case there
	 * is anything hotplugged underneath later.
	 *
	 * We use the information gathered earlier relating to the number of
	 * bridges that must share the resource of this bus' root port, and how
	 * much memory is available that isn't already accounted for to
	 * determine how much to use.
	 *
	 * At least the existing `mem_size` must be allocated as that has been
	 * gleaned from enumeration.
	 */
	uint64_t avail = get_per_bridge_avail(pci_bus_res, bus);

	mem.size = 0;
	if (avail > 0) {
		/* Try 32MiB first, then adjust down until it fits */
		for (uint_t i = 32; i > 0; i >>= 1) {
			if (avail >= buscount * PPB_MEM_ALIGNMENT * i) {
				mem.size = buscount * PPB_MEM_ALIGNMENT * i;
				dcmn_err(CE_NOTE, MSGHDR
				    "Allocating %uMiB",
				    ddi_node_name(dip), bus, dev, func, i);
				break;
			}
		}
	}
	mem.size = MAX(pci_bus_res[secbus].mem_size, mem.size);

	/*
	 * For the PF memory range, illumos has not historically handed out
	 * any additional memory to bridges. However there are some
	 * hotpluggable devices which need 64-bit PF space and so we now always
	 * attempt to allocate at least 32 MiB. If there is enough space
	 * available from a parent then we will increase this to 512MiB.
	 * If we're later unable to find memory to satisfy this, we just move
	 * on and are no worse off than before.
	 */
	pmem.size = MAX(pci_bus_res[secbus].pmem_size,
	    buscount * PPB_MEM_ALIGNMENT * 32);

	/*
	 * Check if the parent bus could allocate a 64-bit sized PF
	 * range and bump the minimum pmem.size to 512MB if so.
	 */
	if (lookup_parbus_res(pci_bus_res, parbus, 1ULL << 32,
	    PPB_MEM_ALIGNMENT, RES_PMEM) > 0) {
		pmem.size = MAX(pci_bus_res[secbus].pmem_size,
		    buscount * PPB_MEM_ALIGNMENT * 512);
	}

	/*
	 * I/O space needs to be 4KiB aligned, Memory space needs to be 1MiB
	 * aligned.
	 *
	 * We calculate alignment as the largest power of two less than the
	 * the sum of all children's size requirements, because this will
	 * align to the size of the largest child request within that size
	 * (which is always a power of two).
	 */
	io.size = P2ROUNDUP(io.size, PPB_IO_ALIGNMENT);
	mem.size = P2ROUNDUP(mem.size, PPB_MEM_ALIGNMENT);
	pmem.size = P2ROUNDUP(pmem.size, PPB_MEM_ALIGNMENT);

	io.align = lowerp2(io.size);
	mem.align = lowerp2(mem.size);
	pmem.align = lowerp2(pmem.size);

	/* Subtractive bridge */
	if (pci_bus_res[secbus].subtractive && prog_sub) {
		/*
		 * We program an arbitrary amount of I/O and memory resource
		 * for the subtractive bridge so that child dynamic-resource-
		 * allocating devices (such as Cardbus bridges) have a chance
		 * of success.  Until we have full-tree resource rebalancing,
		 * dynamic resource allocation (thru busra) only looks at the
		 * parent bridge, so all PPBs must have some allocatable
		 * resource.  For non-subtractive bridges, the resources come
		 * from the base/limit register "windows", but subtractive
		 * bridges often don't program those (since they don't need to).
		 * If we put all the remaining resources on the subtractive
		 * bridge, then peer non-subtractive bridges can't allocate
		 * more space (even though this is probably most correct).
		 * If we put the resources only on the parent, then allocations
		 * from children of subtractive bridges will fail without
		 * special-case code for bypassing the subtractive bridge.
		 * This solution is the middle-ground temporary solution until
		 * we have fully-capable resource allocation.
		 */

		/*
		 * Add an arbitrary I/O resource to the subtractive PPB
		 */
		if (pci_bus_res[secbus].io_avail == NULL) {
			addr = get_parbus_res(pci_bus_res, parbus, secbus,
			    io.size, io.align, RES_IO);
			if (addr != 0) {
				add_ranges_prop(pci_bus_res, secbus, B_TRUE);

				cmn_err(CE_NOTE,
				    MSGHDR "PROGRAM  I/O range 0x%lx ~ 0x%lx "
				    "(subtractive bridge)",
				    ddi_node_name(dip), bus, dev, func,
				    addr, addr + io.size - 1);
			}
		}
		/*
		 * Add an arbitrary memory resource to the subtractive PPB
		 */
		if (pci_bus_res[secbus].mem_avail == NULL) {
			addr = get_parbus_res(pci_bus_res, parbus, secbus,
			    mem.size, mem.align, RES_MEM);
			if (addr != 0) {
				add_ranges_prop(pci_bus_res, secbus, B_TRUE);

				cmn_err(CE_NOTE,
				    MSGHDR "PROGRAM  MEM range 0x%lx ~ 0x%lx "
				    "(subtractive bridge)",
				    ddi_node_name(dip), bus, dev, func,
				    addr, addr + mem.size - 1);
			}
		}

		goto cmd_enable;
	}

	/*
	 * Retrieve the various configured ranges from the bridge.
	 */

	fetch_ppb_res(rcdip, bus, dev, func, RES_IO, &io.base, &io.limit);
	fetch_ppb_res(rcdip, bus, dev, func, RES_MEM, &mem.base, &mem.limit);
	fetch_ppb_res(rcdip, bus, dev, func, RES_PMEM, &pmem.base, &pmem.limit);

	/*
	 * Reprogram IO:
	 */
	if (pci_bus_res[secbus].io_used != NULL) {
		pci_memlist_subsume(&pci_bus_res[secbus].io_used,
		    &pci_bus_res[secbus].io_avail);
	}

	/* get new io ports from parent bus */
	addr = get_parbus_res(pci_bus_res, parbus, secbus,
	    io.size, io.align, RES_IO);
	if (addr != 0) {
		io.base = addr;
		io.limit = addr + io.size - 1;
	}

	/* reprogram PPB regs */
	set_ppb_res(rcdip, pci_bus_res[bus].dip, bus, dev, func,
	    RES_IO, io.base, io.limit);
	add_ranges_prop(pci_bus_res, secbus, B_TRUE);

	/*
	 * Reprogram memory
	 */
	/* Mem range */
	if (pci_bus_res[secbus].mem_used != NULL) {
		pci_memlist_subsume(&pci_bus_res[secbus].mem_used,
		    &pci_bus_res[secbus].mem_avail);
	}

	/* get new mem resource from parent bus */
	addr = get_parbus_res(pci_bus_res, parbus, secbus,
	    mem.size, mem.align, RES_MEM);
	if (addr != 0) {
		mem.base = addr;
		mem.limit = addr + mem.size - 1;
	}

	/* Prefetch mem */
	if (pci_bus_res[secbus].pmem_used != NULL) {
		pci_memlist_subsume(&pci_bus_res[secbus].pmem_used,
		    &pci_bus_res[secbus].pmem_avail);
	}

	/* get new mem resource from parent bus */
	addr = get_parbus_res(pci_bus_res, parbus, secbus,
	    pmem.size, pmem.align, RES_PMEM);
	if (addr != 0) {
		pmem.base = addr;
		pmem.limit = addr + pmem.size - 1;
	}

	set_ppb_res(rcdip, pci_bus_res[bus].dip,
	    bus, dev, func,
	    RES_MEM, mem.base, mem.limit);
	set_ppb_res(rcdip, pci_bus_res[bus].dip,
	    bus, dev, func,
	    RES_PMEM, pmem.base, pmem.limit);
	add_ranges_prop(pci_bus_res, secbus, B_TRUE);

cmd_enable:
	dump_memlists(pci_bus_res, "fix_ppb_res end bus", bus);
	dump_memlists(pci_bus_res, "fix_ppb_res end secbus", secbus);

	if (pci_bus_res[secbus].io_avail != NULL)
		cmd_reg |= PCI_COMM_IO | PCI_COMM_ME;
	if (pci_bus_res[secbus].mem_avail != NULL ||
	    pci_bus_res[secbus].pmem_avail != NULL) {
		cmd_reg |= PCI_COMM_MAE | PCI_COMM_ME;
	}
	pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_COMM, cmd_reg);
}

void
pci_reprogram(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res)
{
	int i;
	int bus;

	/*
	 * Do root-bus resource discovery
	 */
	for (bus = 0; bus <= pci_boot_maxbus; bus++) {
		/* skip non-root (peer) PCI busses */
		if (pci_bus_res[bus].par_bus != NO_PAR_BUS)
			continue;

		/*
		 * 1. find resources associated with this root bus
		 */
		populate_bus_res(rcdip, pci_bus_res, bus);

		/*
		 * 2. Exclude <1M address range here in case below reserved
		 * ranges for BIOS data area, ROM area etc are wrongly reported
		 * in ACPI resource producer entries for PCI root bus.
		 *	00000000 - 000003FF	RAM
		 *	00000400 - 000004FF	BIOS data area
		 *	00000500 - 0009FFFF	RAM
		 *	000A0000 - 000BFFFF	VGA RAM
		 *	000C0000 - 000FFFFF	ROM area
		 *
		 * NB: This justification does not make sense on ARM, however
		 * the PCI codebase contains assumptions that address 0, at
		 * least, is invalid.  This is as good a place as any to make
		 * it true.  We also remove I/O 0x0 for the same reason
		 */
		(void) pci_memlist_remove(&pci_bus_res[bus].mem_avail,
		    0x0, 0x100000);
		(void) pci_memlist_remove(&pci_bus_res[bus].pmem_avail,
		    0x0, 0x100000);
		(void) pci_memlist_remove(&pci_bus_res[bus].io_avail,
		    0x0, 0x1);

		/*
		 * 3. Calculate the amount of "spare" 32-bit memory so that we
		 * can use that later to determine how much additional memory
		 * to allocate to bridges in order that they have a better
		 * chance of supporting a device being hotplugged under them.
		 *
		 * This is a root bus and the previous CONFIG_INFO pass has
		 * populated `mem_size` with the sum of all of the BAR sizes
		 * for all devices underneath, possibly adjusted up to allow
		 * for alignment when it is later allocated. This pass has also
		 * recorded the number of child bridges found under this bus in
		 * `num_bridge`. To calculate the memory which can be used for
		 * additional bridge allocations we sum up the contents of the
		 * `mem_avail` list and subtract `mem_size`.
		 *
		 * When programming child bridges later in fix_ppb_res(), the
		 * bridge count and spare memory values cached against the
		 * relevant root port are used to determine how much memory to
		 * be allocated.
		 */
		if (pci_bus_res[bus].num_bridge > 0) {
			uint64_t mem = 0;

			for (struct memlist *ml = pci_bus_res[bus].mem_avail;
			    ml != NULL; ml = ml->ml_next) {
				if (ml->ml_address < UINT32_MAX)
					mem += ml->ml_size;
			}

			if (mem > pci_bus_res[bus].mem_size)
				mem -= pci_bus_res[bus].mem_size;
			else
				mem = 0;

			pci_bus_res[bus].mem_buffer = mem;

			dcmn_err(CE_NOTE,
			    "Bus 0x%02x, bridges 0x%x, buffer mem 0x%lx",
			    bus, pci_bus_res[bus].num_bridge, mem);
		}

		/*
		 * 4. Remove used PCI and ISA resources from bus resource map
		 */

		pci_memlist_remove_list(&pci_bus_res[bus].io_avail,
		    pci_bus_res[bus].io_used);
		pci_memlist_remove_list(&pci_bus_res[bus].mem_avail,
		    pci_bus_res[bus].mem_used);
		pci_memlist_remove_list(&pci_bus_res[bus].pmem_avail,
		    pci_bus_res[bus].pmem_used);
		pci_memlist_remove_list(&pci_bus_res[bus].mem_avail,
		    pci_bus_res[bus].pmem_used);
		pci_memlist_remove_list(&pci_bus_res[bus].pmem_avail,
		    pci_bus_res[bus].mem_used);
	}

	/* add bus-range property for root/peer bus nodes */
	for (i = 0; i <= pci_boot_maxbus; i++) {
		/* create bus-range property on root/peer buses */
		if (pci_bus_res[i].par_bus == NO_PAR_BUS)
			add_bus_range_prop(pci_bus_res, i);

		/* setup bus range resource on each bus */
		setup_bus_res(pci_bus_res, i);
	}

	remove_subtractive_res(pci_bus_res);

	/* reprogram the non-subtractive PPB */
	for (i = 0; i <= pci_boot_maxbus; i++) {
		fix_ppb_res(rcdip, pci_bus_res, i, B_FALSE);
	}

	for (i = 0; i <= pci_boot_maxbus; i++) {
		/*
		 * Reprogram the subtractive PPB. At this time, all its
		 * siblings should have got their resources already.
		 */
		if (pci_bus_res[i].subtractive)
			fix_ppb_res(rcdip, pci_bus_res, i, B_TRUE);
		enumerate_bus_devs(rcdip, i, pci_bus_res, CONFIG_NEW);
	}

	/* All dev programmed, so we can create available prop */
	for (i = 0; i <= pci_boot_maxbus; i++)
		add_bus_available_prop(pci_bus_res, i);
}

static struct memlist *
find_resource(dev_info_t *rcdip, pci_prd_rsrc_t rsrc)
{
	struct memlist *mlp = NULL;

	/*
	 * Take _BUS from "bus-range", anything else can be derived from
	 * "ranges"
	 */
	if (rsrc == PCI_PRD_R_BUS) {
		int busrng[2];

		dip_bus_range(rcdip, busrng);
		pci_memlist_insert(&mlp, busrng[0], busrng[1] - busrng[0]);
		return (mlp);
	}

	pci_ranges_t *rngs;
	uint_t rnglen;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rcdip,
	    DDI_PROP_DONTPASS,  OBP_RANGES,
	    (int **)&rngs, &rnglen) != DDI_PROP_SUCCESS) {
		dev_err(rcdip, CE_PANIC, "No ranges property");
		return (NULL);
	}

	rnglen = CELLS_1275_TO_BYTES(rnglen);
	rnglen /= sizeof (pci_ranges_t);

	int i;

	for (i = 0; i < rnglen; i++) {
		if ((rsrc == PCI_PRD_R_IO) &&
		    (rngs[i].child_high & PCI_ADDR_MASK) == PCI_ADDR_IO) {
			break;
		} else if ((rsrc == PCI_PRD_R_PREFETCH) &&
		    (((rngs[i].child_high & PCI_ADDR_MASK) == PCI_ADDR_MEM32) ||
		    ((rngs[i].child_high & PCI_ADDR_MASK) == PCI_ADDR_MEM64)) &&
		    ((rngs[i].child_high & PCI_PREFETCH_B) != 0)) {
			break;
		} else if ((rsrc == PCI_PRD_R_MMIO) &&
		    (((rngs[i].child_high & PCI_ADDR_MASK) == PCI_ADDR_MEM32) ||
		    ((rngs[i].child_high & PCI_ADDR_MASK) == PCI_ADDR_MEM64)) &&
		    ((rngs[i].child_high & PCI_PREFETCH_B) == 0)) {
			break;
		}
	}

	if (i == rnglen)
		return (NULL);

	pci_memlist_insert(&mlp,
	    ((uint64_t)rngs[i].child_mid << 32) | rngs[i].child_low,
	    ((uint64_t)rngs[i].size_high << 32) | rngs[i].size_low);

	ddi_prop_free(rngs);

	return (mlp);
}

/*
 * populate bus resources
 */
static void
populate_bus_res(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res,
    uchar_t bus)
{
	pci_bus_res[bus].pmem_avail = find_resource(rcdip, PCI_PRD_R_PREFETCH);
	pci_bus_res[bus].mem_avail = find_resource(rcdip, PCI_PRD_R_MMIO);
	pci_bus_res[bus].io_avail = find_resource(rcdip, PCI_PRD_R_IO);
	pci_bus_res[bus].bus_avail = find_resource(rcdip, PCI_PRD_R_BUS);

	dump_memlists(pci_bus_res, "populate_bus_res", bus);

	/*
	 * attempt to initialize sub_bus from the largest range-end
	 * in the bus_avail list
	 */
	if (pci_bus_res[bus].bus_avail != NULL) {
		struct memlist *entry;
		int current;

		entry = pci_bus_res[bus].bus_avail;
		while (entry != NULL) {
			current = entry->ml_address + entry->ml_size - 1;
			if (current > pci_bus_res[bus].sub_bus)
				pci_bus_res[bus].sub_bus = current;
			entry = entry->ml_next;
		}
	}
}

/*
 * For any fixed configuration (often compatability) pci devices
 * and those with their own expansion rom, create device nodes
 * to hold the already configured device details.
 */
void
enumerate_bus_devs(dev_info_t *rcdip, uchar_t bus,
    struct pci_bus_resource *pci_bus_res, config_phase_t config_op)
{
	uchar_t dev, func, nfunc, header;
	struct pci_devfunc *devlist = NULL, *entry;

	if (bus_debug(bus)) {
		if (config_op == CONFIG_NEW) {
			dcmn_err(CE_NOTE, "configuring pci bus 0x%x", bus);
		} else {
			dcmn_err(CE_NOTE, "enumerating pci bus 0x%x", bus);
		}
	}

	if (config_op == CONFIG_NEW) {
		devlist = (struct pci_devfunc *)pci_bus_res[bus].privdata;
		while (devlist) {
			entry = devlist;
			devlist = entry->next;
			/* reprogram device(s) */
			add_reg_props(rcdip, entry->dip,
			    pci_bus_res, bus, entry->dev, entry->func,
			    CONFIG_NEW);
			kmem_free(entry, sizeof (*entry));
		}
		pci_bus_res[bus].privdata = NULL;
		return;
	}

	for (dev = 0; dev < max_dev_pci; dev++) {
		nfunc = 1;
		for (func = 0; func < nfunc; func++) {
			ushort_t venid = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_CONF_VENID);
			ushort_t devid = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_CONF_DEVID);
			if ((venid != 0xffff) && (venid != 0x0))
				dcmn_err(CE_CONT, "pci%x,%x at %x:%x:%x\n",
				    venid, devid, bus, dev, func);
			if ((venid == 0xffff) || (venid == 0)) {
				/* no function at this address */
				continue;
			}

			header = pci_cfgacc_get8(rcdip,
			    PCI_GETBDF(bus, dev, func), PCI_CONF_HEADER);
			if (header == 0xff) {
				dcmn_err(CE_CONT, "%x:%x:%x has no header\n",
				    bus, dev, func);
				continue; /* illegal value */
			}

			/*
			 * according to some mail from Microsoft posted
			 * to the pci-drivers alias, their only requirement
			 * for a multifunction device is for the 1st
			 * function to have to PCI_HEADER_MULTI bit set.
			 */
			if ((func == 0) && (header & PCI_HEADER_MULTI)) {
				nfunc = 8;
			}

			if (config_op == CONFIG_INFO) {
				/*
				 * Create the node, unconditionally, on the
				 * first pass only.  It may still need
				 * resource assignment, which will be
				 * done on the second, CONFIG_NEW, pass.
				 */
				process_devfunc(rcdip, pci_bus_res, bus, dev,
				    func, config_op);

			}
		}
	}

	/* percolate bus used resources up through parents to root */
	if (config_op == CONFIG_INFO) {
		int	par_bus;

		par_bus = pci_bus_res[bus].par_bus;
		while (par_bus != NO_PAR_BUS) {
			pci_bus_res[par_bus].io_size +=
			    pci_bus_res[bus].io_size;
			pci_bus_res[par_bus].mem_size +=
			    pci_bus_res[bus].mem_size;
			pci_bus_res[par_bus].pmem_size +=
			    pci_bus_res[bus].pmem_size;

			if (pci_bus_res[bus].io_used != NULL) {
				pci_memlist_merge(&pci_bus_res[bus].io_used,
				    &pci_bus_res[par_bus].io_used);
			}

			if (pci_bus_res[bus].mem_used != NULL) {
				pci_memlist_merge(&pci_bus_res[bus].mem_used,
				    &pci_bus_res[par_bus].mem_used);
			}

			if (pci_bus_res[bus].pmem_used != NULL) {
				pci_memlist_merge(&pci_bus_res[bus].pmem_used,
				    &pci_bus_res[par_bus].pmem_used);
			}

			pci_bus_res[par_bus].num_bridge +=
			    pci_bus_res[bus].num_bridge;

			bus = par_bus;
			par_bus = pci_bus_res[par_bus].par_bus;
		}
	}
}

static void
set_devpm_d0(dev_info_t *rcdip, uchar_t bus, uchar_t dev, uchar_t func)
{
	uint16_t status;
	uint8_t header;
	uint8_t cap_ptr;
	uint8_t cap_id;
	uint16_t pmcsr;

	status = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP))
		return;	/* No capabilities list */

	header = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;
	if (header == PCI_HEADER_CARDBUS) {
		cap_ptr = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CBUS_CAP_PTR);
	} else {
		cap_ptr = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CONF_CAP_PTR);
	}
	/*
	 * Walk the capabilities list searching for a PM entry.
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL && cap_ptr >= PCI_CAP_PTR_OFF) {
		cap_ptr &= PCI_CAP_PTR_MASK;
		cap_id = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    cap_ptr + PCI_CAP_ID);
		if (cap_id == PCI_CAP_ID_PM) {
			pmcsr = pci_cfgacc_get16(rcdip,
			    PCI_GETBDF(bus, dev, func), cap_ptr + PCI_PMCSR);
			pmcsr &= ~(PCI_PMCSR_STATE_MASK);
			pmcsr |= PCI_PMCSR_D0; /* D0 state */
			pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
			    cap_ptr + PCI_PMCSR, pmcsr);
			break;
		}
		cap_ptr = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
		    cap_ptr + PCI_CAP_NEXT_PTR);
	}

}

static void
process_devfunc(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res,
    uchar_t bus, uchar_t dev, uchar_t func, config_phase_t config_op)
{
	pci_prop_data_t prop_data;
	pci_prop_failure_t prop_ret;
	dev_info_t *dip = NULL;
	struct pci_devfunc *devlist = NULL, *entry = NULL;
	int power[2] = {1, 1};
	pcie_req_id_t bdf;

	prop_ret = pci_prop_data_fill(rcdip, NULL, bus, dev, func, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		cmn_err(CE_WARN, MSGHDR "failed to get basic PCI data: 0x%x",
		    ddi_node_name(rcdip), bus, dev, func, prop_ret);
		return;
	}

	VERIFY3P(pci_bus_res[bus].dip, !=, NULL);

	/*
	 * There may be be nodes below the root complex in the device tree
	 * already, passed to us from firmware.  However, these nodes are not
	 * necessarily complete, we are expected to merge information from the
	 * bus with the information from firmware.
	 *
	 * We do this matching based on PCI unit address, matching device and
	 * function (we search below the parent dip, so we know bus must
	 * match).
	 */
	ndi_devi_enter(pci_bus_res[bus].dip);
	for (dev_info_t *firmdip = ddi_get_child(pci_bus_res[bus].dip);
	    firmdip != NULL;
	    firmdip = ddi_get_next_sibling(firmdip)) {
		pci_regspec_t *regs;
		uint_t regsz;
		uint16_t child_dev = 0;
		uint16_t child_func = 0;

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, firmdip,
		    DDI_PROP_DONTPASS, OBP_REG,
		    (int **)&regs, &regsz) == DDI_SUCCESS) {
			child_dev = (regs->pci_phys_hi & PCI_REG_DEV_M) >>
			    PCI_REG_DEV_SHIFT;
			child_func = (regs->pci_phys_hi & PCI_REG_FUNC_M) >>
			    PCI_REG_FUNC_SHIFT;

			ddi_prop_free(regs);
		}

		if ((child_dev == dev) && (child_func == func)) {
			dip = firmdip;
		}
	}
	ndi_devi_exit(pci_bus_res[bus].dip);

	if (dip == NULL) {
		ndi_devi_alloc_sleep(pci_bus_res[bus].dip, DEVI_PSEUDO_NEXNAME,
		    DEVI_SID_NODEID, &dip);
		prop_ret = pci_prop_name_node(dip, &prop_data);
		if (prop_ret != PCI_PROP_OK) {
			cmn_err(CE_WARN, MSGHDR "failed to set node "
			    "name: 0x%x; devinfo node not created",
			    ddi_node_name(rcdip), bus, dev, func, prop_ret);
			(void) ndi_devi_free(dip);
			return;
		}
	}




	bdf = PCI_GETBDF(bus, dev, func);

	/*
	 * Only populate bus_t if this device is sitting under a PCIE root
	 * complex.  Some particular machines have both a PCIE root complex and
	 * a PCI hostbridge, in which case only devices under the PCIE root
	 * complex will have their bus_t populated.
	 */
	if (pcie_get_rc_dip(dip) != NULL) {
		(void) pcie_init_bus(dip, bdf, PCIE_BUS_INITIAL);
	}

	/*
	 * Go through and set all of the devinfo proprties on this function.
	 */
	prop_ret = pci_prop_set_common_props(dip, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		cmn_err(CE_WARN, MSGHDR "failed to set properties: 0x%x; "
		    "devinfo node not created", ddi_node_name(rcdip), bus, dev,
		    func, prop_ret);
		if (pcie_get_rc_dip(dip) != NULL) {
			pcie_fini_bus(dip, PCIE_BUS_FINAL);
		}
		(void) ndi_devi_free(dip);
		return;
	}

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "power-consumption", power, 2);

	/* Set the device PM state to D0 */
	set_devpm_d0(rcdip, bus, dev, func);

	if (pci_prop_class_is_pcibridge(&prop_data)) {
		boolean_t pciex = (prop_data.ppd_flags & PCI_PROP_F_PCIE) != 0;
		boolean_t is_pci_bridge = pciex &&
		    prop_data.ppd_pcie_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI;
		add_ppb_props(rcdip, dip, pci_bus_res, bus, dev, func, pciex,
		    is_pci_bridge);
	} else {
		/*
		 * Record the non-PPB devices on the bus for possible
		 * reprogramming at 2nd bus enumeration.
		 * Note: PPB reprogramming is done in fix_ppb_res()
		 */
		devlist = (struct pci_devfunc *)pci_bus_res[bus].privdata;
		entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
		entry->dip = dip;
		entry->dev = dev;
		entry->func = func;
		entry->next = devlist;
		pci_bus_res[bus].privdata = entry;
	}

	prop_ret = pci_prop_set_compatible(dip, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		cmn_err(CE_WARN, MSGHDR "failed to set compatible property: "
		    "0x%x;  device may not bind to a driver",
		    ddi_node_name(rcdip), bus, dev, func, prop_ret);
	}

	DEVI_SET_PCI(dip);
	add_reg_props(rcdip, dip, pci_bus_res, bus, dev, func,
	    config_op);
	(void) ndi_devi_bind_driver(dip, 0);
}

/*
 * Where op is one of:
 *   CONFIG_INFO	- first pass, gather what is there.
 *   CONFIG_UPDATE	- second pass, adjust/allocate regions.
 *   CONFIG_NEW		- third pass, allocate regions.
 * Returns:
 *	-1	Skip this BAR
 *	 1	Properties have been assigned, reprogramming required
 */
static int
add_bar_reg_props(dev_info_t *rcdip, struct pci_bus_resource *pci_bus_res,
    config_phase_t op, uchar_t bus, uchar_t dev, uchar_t func, uint_t bar,
    ushort_t offset, pci_regspec_t *regs, pci_regspec_t *assigned,
    ushort_t *bar_sz)
{
	uint8_t baseclass;
	uint32_t base, devloc;
	uint16_t command = 0;
	uint64_t value;

	devloc = PCI_REG_MAKE_BDFR(bus, dev, func, 0);
	baseclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_BASCLASS);

	/*
	 * Determine the size of the BAR by writing 0xffffffff to the base
	 * register and reading the value back before restoring the original.
	 *
	 * For non-bridges, disable I/O and Memory access while doing this to
	 * avoid difficulty with USB emulation (see OHCI spec1.0a appendix B
	 * "Host Controller Mapping"). Doing this for bridges would have the
	 * side-effect of making the bridge transparent to secondary-bus
	 * activity (see sections 4.1-4.3 of the PCI-PCI Bridge Spec V1.2).
	 */
	base = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func), offset);

	if (baseclass != PCI_CLASS_BRIDGE) {
		command = pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CONF_COMM);
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CONF_COMM, command & ~(PCI_COMM_MAE | PCI_COMM_IO));
	}

	pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func), offset, 0xffffffff);
	value = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func), offset);
	pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func), offset, base);

	if (baseclass != PCI_CLASS_BRIDGE) {
		pci_cfgacc_put16(rcdip, PCI_GETBDF(bus, dev, func),
		    PCI_CONF_COMM, command);
	}

	/* I/O Space */
	if ((base & PCI_BASE_SPACE_IO) != 0) {
		struct memlist **io_avail = &pci_bus_res[bus].io_avail;
		struct memlist **io_used = &pci_bus_res[bus].io_used;
		boolean_t hard_decode = B_FALSE;
		uint_t type, len;

		*bar_sz = PCI_BAR_SZ_32;
		value &= PCI_BASE_IO_ADDR_M;
		len = BARMASKTOLEN(value);

		if (value == 0) {
			/* skip base regs with size of 0 */
			return (-1);
		}

		regs->pci_phys_hi = PCI_ADDR_IO | devloc;
		if (hard_decode) {
			regs->pci_phys_hi |= PCI_RELOCAT_B;
			regs->pci_phys_low = base & PCI_BASE_IO_ADDR_M;
		} else {
			regs->pci_phys_hi |= offset;
			regs->pci_phys_low = 0;
		}
		assigned->pci_phys_hi = PCI_RELOCAT_B | regs->pci_phys_hi;
		regs->pci_size_low = assigned->pci_size_low = len;

		/*
		 * 'type' holds the non-address part of the base to be re-added
		 * to any new address in the programming step below.
		 */
		type = base & ~PCI_BASE_IO_ADDR_M;
		base &= PCI_BASE_IO_ADDR_M;

		/*
		 * A device under a subtractive PPB can allocate resources from
		 * its parent bus if there is no resource available on its own
		 * bus.
		 */
		if (op == CONFIG_NEW && pci_bus_res[bus].subtractive &&
		    *io_avail == NULL) {
			uchar_t res_bus;

			res_bus = resolve_alloc_bus(pci_bus_res, bus, RES_IO);
			io_avail = &pci_bus_res[res_bus].io_avail;
		}

		if (op == CONFIG_INFO) {	/* first pass */
			dcmn_err(CE_NOTE,
			    MSGHDR "BAR%u I/O FWINIT 0x%x ~ 0x%x "
			    "(ignored)", ddi_node_name(rcdip),
			    bus, dev, func, bar, base, len);
			pci_bus_res[bus].io_size += len;
		} else {
			base = pci_memlist_find(io_avail, len, len);
			if (base == 0) {
				cmn_err(CE_WARN, MSGHDR "BAR%u I/O "
				    "failed to find length 0x%x",
				    ddi_node_name(rcdip), bus, dev, func, bar,
				    len);
			} else {
				uint32_t nbase;

				cmn_err(CE_NOTE, MSGHDR "BAR%u  "
				    "I/O REPROG 0x%x ~ 0x%x",
				    ddi_node_name(rcdip), bus, dev, func,
				    bar, base, len);
				pci_cfgacc_put32(rcdip,
				    PCI_GETBDF(bus, dev, func),
				    offset, base | type);
				nbase = pci_cfgacc_get32(rcdip,
				    PCI_GETBDF(bus, dev, func), offset);
				nbase &= PCI_BASE_IO_ADDR_M;

				if (base != nbase) {
					cmn_err(CE_NOTE, MSGHDR "BAR%u  "
					    "I/O REPROG 0x%x ~ 0x%x "
					    "FAILED READBACK 0x%x",
					    ddi_node_name(rcdip), bus, dev,
					    func, bar, base, len, nbase);
					pci_cfgacc_put32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset, 0);
					if (baseclass != PCI_CLASS_BRIDGE) {
						/* Disable PCI_COMM_IO bit */
						command =
						    pci_cfgacc_get16(rcdip,
						    PCI_GETBDF(bus, dev, func),
						    PCI_CONF_COMM);
						command &= ~PCI_COMM_IO;
						pci_cfgacc_put16(rcdip,
						    PCI_GETBDF(bus, dev, func),
						    PCI_CONF_COMM, command);
					}
					pci_memlist_insert(io_avail, base, len);
					base = 0;
				} else {
					pci_memlist_insert(io_used, base, len);
				}
			}
		}
		assigned->pci_phys_low = base;

	} else {	/* Memory space */
		struct memlist **mem_avail = &pci_bus_res[bus].mem_avail;
		struct memlist **mem_used = &pci_bus_res[bus].mem_used;
		struct memlist **pmem_avail = &pci_bus_res[bus].pmem_avail;
		struct memlist **pmem_used = &pci_bus_res[bus].pmem_used;
		uint_t type, base_hi, phys_hi;
		uint64_t len, fbase;

		if ((base & PCI_BASE_TYPE_M) == PCI_BASE_TYPE_ALL) {
			*bar_sz = PCI_BAR_SZ_64;
			base_hi = pci_cfgacc_get32(rcdip,
			    PCI_GETBDF(bus, dev, func), offset + 4);
			pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
			    offset + 4, 0xffffffff);
			value |= (uint64_t)pci_cfgacc_get32(rcdip,
			    PCI_GETBDF(bus, dev, func), offset + 4) << 32;
			pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
			    offset + 4, base_hi);
			phys_hi = PCI_ADDR_MEM64;
			value &= PCI_BASE_M_ADDR64_M;
		} else {
			*bar_sz = PCI_BAR_SZ_32;
			base_hi = 0;
			phys_hi = PCI_ADDR_MEM32;
			value &= PCI_BASE_M_ADDR_M;
		}

		/* skip base regs with size of 0 */
		if (value == 0)
			return (-1);

		len = BARMASKTOLEN(value);
		regs->pci_size_low = assigned->pci_size_low = len & 0xffffffff;
		regs->pci_size_hi = assigned->pci_size_hi = len >> 32;

		phys_hi |= devloc | offset;
		if (base & PCI_BASE_PREF_M)
			phys_hi |= PCI_PREFETCH_B;


		/*
		 * A device under a subtractive PPB can allocate resources from
		 * its parent bus if there is no resource available on its own
		 * bus.
		 */
		if (op == CONFIG_NEW && pci_bus_res[bus].subtractive) {
			uchar_t res_bus = bus;

			if ((phys_hi & PCI_PREFETCH_B) != 0 &&
			    *pmem_avail == NULL) {
				res_bus = resolve_alloc_bus(pci_bus_res, bus,
				    RES_PMEM);
				pmem_avail = &pci_bus_res[res_bus].pmem_avail;
				mem_avail = &pci_bus_res[res_bus].mem_avail;
			} else if (*mem_avail == NULL) {
				res_bus = resolve_alloc_bus(pci_bus_res, bus,
				    RES_MEM);
				pmem_avail = &pci_bus_res[res_bus].pmem_avail;
				mem_avail = &pci_bus_res[res_bus].mem_avail;
			}
		}

		regs->pci_phys_hi = assigned->pci_phys_hi = phys_hi;
		assigned->pci_phys_hi |= PCI_RELOCAT_B;

		/*
		 * 'type' holds the non-address part of the base to be re-added
		 * to any new address in the programming step below.
		 */
		type = base & ~PCI_BASE_M_ADDR_M;
		base &= PCI_BASE_M_ADDR_M;

		fbase = (((uint64_t)base_hi) << 32) | base;
		if (op == CONFIG_INFO) {
			dcmn_err(CE_NOTE,
			    MSGHDR "BAR%u %sMEM FWINIT 0x%lx ~ 0x%lx%s "
			    "(ignored)",
			    ddi_node_name(rcdip), bus, dev, func, bar,
			    (phys_hi & PCI_PREFETCH_B) ? "P" : " ",
			    fbase, len,
			    *bar_sz == PCI_BAR_SZ_64 ? " (64-bit)" : "");

			/*
			 * We need to actually increase the amount of memory
			 * that we request to take into account alignment.
			 * This is a bit gross, but by doubling the request
			 * size we are more likely to get the size that we
			 * need. A more involved fix would require a smarter
			 * and more involved allocator (something we will need
			 * eventually).
			 */
			len *= 2;

			if (phys_hi & PCI_PREFETCH_B)
				pci_bus_res[bus].pmem_size += len;
			else
				pci_bus_res[bus].mem_size += len;
		} else {
			boolean_t pf = B_FALSE;
			fbase = 0;

			/*
			 * When desired, attempt a prefetchable allocation first
			 */
			if ((phys_hi & PCI_PREFETCH_B) != 0 &&
			    *pmem_avail != NULL) {
				fbase = pci_memlist_find(pmem_avail, len, len);
				if (fbase != 0)
					pf = B_TRUE;
			}
			/*
			 * If prefetchable allocation was not desired, or
			 * failed, attempt ordinary memory allocation.
			 */
			if (fbase == 0 && *mem_avail != NULL)
				fbase = pci_memlist_find(mem_avail, len, len);

			base_hi = fbase >> 32;
			base = fbase & 0xffffffff;

			if (fbase == 0) {
				cmn_err(CE_WARN, MSGHDR "BAR%u MEM "
				    "failed to find length 0x%lx",
				    ddi_node_name(rcdip), bus, dev, func,
				    bar, len);
			} else {
				uint64_t nbase, nbase_hi = 0;

				cmn_err(CE_NOTE, MSGHDR "BAR%u "
				    "%s%s REPROG 0x%lx ~ 0x%lx",
				    ddi_node_name(rcdip), bus, dev, func, bar,
				    pf ? "PMEM" : "MEM",
				    *bar_sz == PCI_BAR_SZ_64 ? "64" : "",
				    fbase, len);
				pci_cfgacc_put32(rcdip,
				    PCI_GETBDF(bus, dev, func),
				    offset, base | type);
				nbase = pci_cfgacc_get32(rcdip,
				    PCI_GETBDF(bus, dev, func), offset);

				if (*bar_sz == PCI_BAR_SZ_64) {
					pci_cfgacc_put32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset + 4, base_hi);
					nbase_hi = pci_cfgacc_get32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset + 4);
				}

				nbase &= PCI_BASE_M_ADDR_M;

				if (base != nbase || base_hi != nbase_hi) {
					cmn_err(CE_NOTE, MSGHDR "BAR%u "
					    "%s%s REPROG 0x%lx ~ 0x%lx "
					    "FAILED READBACK 0x%lx",
					    ddi_node_name(rcdip), bus, dev,
					    func, bar, pf ? "PMEM" : "MEM",
					    *bar_sz == PCI_BAR_SZ_64 ?
					    "64" : "",
					    fbase, len,
					    nbase_hi << 32 | nbase);

					pci_cfgacc_put32(rcdip,
					    PCI_GETBDF(bus, dev, func),
					    offset, 0);
					if (*bar_sz == PCI_BAR_SZ_64) {
						pci_cfgacc_put32(rcdip,
						    PCI_GETBDF(bus, dev, func),
						    offset + 4, 0);
					}

					if (baseclass != PCI_CLASS_BRIDGE) {
						/* Disable PCI_COMM_MAE bit */
						command =
						    pci_cfgacc_get16(rcdip,
						    PCI_GETBDF(bus, dev,
						    func), PCI_CONF_COMM);
						command &= ~PCI_COMM_MAE;
						pci_cfgacc_put16(rcdip,
						    PCI_GETBDF(bus, dev, func),
						    PCI_CONF_COMM, command);
					}

					pci_memlist_insert(
					    pf ? pmem_avail : mem_avail,
					    base, len);
					base = base_hi = 0;
				} else {
					if (pf) {
						pci_memlist_insert(pmem_used,
						    fbase, len);
						(void) pci_memlist_remove(
						    pmem_avail, fbase, len);
					} else {
						pci_memlist_insert(mem_used,
						    fbase, len);
						(void) pci_memlist_remove(
						    mem_avail, fbase, len);
					}
				}
			}
		}

		assigned->pci_phys_mid = base_hi;
		assigned->pci_phys_low = base;
	}

	dcmn_err(CE_NOTE, MSGHDR "BAR%u ---- %08x.%x.%x.%x.%x",
	    ddi_node_name(rcdip), bus, dev, func, bar,
	    assigned->pci_phys_hi,
	    assigned->pci_phys_mid,
	    assigned->pci_phys_low,
	    assigned->pci_size_hi,
	    assigned->pci_size_low);

	return (1);
}

/*
 * Add the "reg" and "assigned-addresses" property
 */
static void
add_reg_props(dev_info_t *rcdip, dev_info_t *dip,
    struct pci_bus_resource *pci_bus_res, uchar_t bus, uchar_t dev,
    uchar_t func, config_phase_t op)
{
	uchar_t baseclass, subclass, progclass, header;
	uint_t bar, value, devloc, base;
	ushort_t bar_sz, offset, end;
	int max_basereg;

	struct memlist **mem_avail, **mem_used;

	pci_regspec_t regs[16] = {{0}};
	pci_regspec_t assigned[15] = {{0}};
	int nreg, nasgn;

	mem_avail = &pci_bus_res[bus].mem_avail;
	mem_used = &pci_bus_res[bus].mem_used;

	dump_memlists(pci_bus_res, "add_reg_props start", bus);

	devloc = PCI_REG_MAKE_BDFR(bus, dev, func, 0);
	regs[0].pci_phys_hi = devloc;
	nreg = 1;	/* rest of regs[0] is all zero */
	nasgn = 0;

	baseclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_BASCLASS);
	subclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_SUBCLASS);
	progclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_PROGCLASS);
	header = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;

	switch (header) {
	case PCI_HEADER_ZERO:
		max_basereg = PCI_BASE_NUM;
		break;
	case PCI_HEADER_PPB:
		max_basereg = PCI_BCNF_BASE_NUM;
		break;
	default:
		max_basereg = 0;
		break;
	}

	end = PCI_CONF_BASE0 + max_basereg * sizeof (uint_t);
	for (bar = 0, offset = PCI_CONF_BASE0; offset < end;
	    bar++, offset += bar_sz) {
		int ret;

		ret = add_bar_reg_props(rcdip, pci_bus_res, op, bus, dev, func,
		    bar, offset, &regs[nreg], &assigned[nasgn], &bar_sz);

		if (bar_sz == PCI_BAR_SZ_64)
			bar++;

		if (ret == -1)		/* Skip BAR */
			continue;

		nreg++;
		nasgn++;
	}

	switch (header) {
	case PCI_HEADER_ZERO:
		offset = PCI_CONF_ROM;
		break;
	case PCI_HEADER_PPB:
		offset = PCI_BCNF_ROM;
		break;
	default: /* including PCI_HEADER_CARDBUS */
		goto done;
	}

	/*
	 * Add the expansion rom memory space
	 * Determine the size of the ROM base reg; don't write reserved bits
	 * ROM isn't in the PCI memory space.
	 */
	base = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func), offset);
	pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func),
	    offset, PCI_BASE_ROM_ADDR_M);
	value = pci_cfgacc_get32(rcdip, PCI_GETBDF(bus, dev, func), offset);
	pci_cfgacc_put32(rcdip, PCI_GETBDF(bus, dev, func), offset, base);
	if (value & PCI_BASE_ROM_ENABLE)
		value &= PCI_BASE_ROM_ADDR_M;
	else
		value = 0;

	if (value != 0) {
		uint_t len;

		regs[nreg].pci_phys_hi = (PCI_ADDR_MEM32 | devloc) + offset;
		assigned[nasgn].pci_phys_hi = (PCI_RELOCAT_B |
		    PCI_ADDR_MEM32 | devloc) + offset;
		base &= PCI_BASE_ROM_ADDR_M;
		assigned[nasgn].pci_phys_low = base;
		len = BARMASKTOLEN(value);
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = len;
		nreg++, nasgn++;
		/* take it out of the memory resource */
		if (base != 0) {
			(void) pci_memlist_remove(mem_avail, base, len);
			pci_memlist_insert(mem_used, base, len);
			pci_bus_res[bus].mem_size += len;
		}
	}

	/*
	 * Account for "legacy" (alias) video adapter resources
	 */

	/* add the three hard-decode, aliased address spaces for VGA */
	if ((baseclass == PCI_CLASS_DISPLAY && subclass == PCI_DISPLAY_VGA) ||
	    (baseclass == PCI_CLASS_NONE && subclass == PCI_NONE_VGA)) {
		dev_err(dip, CE_PANIC, "ARM PCI does not support legacy VGA");
	}

	/* add the hard-decode, aliased address spaces for 8514 */
	if ((baseclass == PCI_CLASS_DISPLAY) &&
	    (subclass == PCI_DISPLAY_VGA) &&
	    (progclass & PCI_DISPLAY_IF_8514)) {
		dev_err(dip, CE_PANIC, "ARM PCI does not support legacy VGA");
	}

done:
	dump_memlists(pci_bus_res, "add_reg_props end", bus);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, OBP_REG,
	    (int *)regs, nreg * sizeof (pci_regspec_t) / sizeof (int));
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "assigned-addresses",
	    (int *)assigned, nasgn * sizeof (pci_regspec_t) / sizeof (int));
}

static void
add_ppb_props(dev_info_t *rcdip, dev_info_t *dip,
    struct pci_bus_resource *pci_bus_res, uchar_t bus, uchar_t dev,
    uchar_t func, boolean_t pciex, boolean_t is_pci_bridge)
{
	char *dev_type;
	int i;
	struct {
		uint64_t base;
		uint64_t limit;
	} io, mem, pmem;
	uchar_t secbus, subbus;
	uchar_t progclass;

	secbus = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_BCNF_SECBUS);
	subbus = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_BCNF_SUBBUS);

	ASSERT3U(secbus, <=, subbus);
	ASSERT3P(pci_bus_res[secbus].dip, ==, NULL);
	pci_bus_res[secbus].dip = dip;
	pci_bus_res[secbus].par_bus = bus;

	dump_memlists(pci_bus_res, "add_ppb_props start bus", bus);
	dump_memlists(pci_bus_res, "add_ppb_props start secbus", secbus);

	/*
	 * Check if it's a subtractive PPB.
	 */
	progclass = pci_cfgacc_get8(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_CONF_PROGCLASS);
	if (progclass == PCI_BRIDGE_PCI_IF_SUBDECODE)
		pci_bus_res[secbus].subtractive = B_TRUE;

	dev_type = (pciex && !is_pci_bridge) ? "pciex" : "pci";

	/* set up bus number hierarchy */
	pci_bus_res[secbus].sub_bus = subbus;
	/*
	 * Keep track of the largest subordinate bus number (this is essential
	 * for peer buses because there is no other way of determining its
	 * subordinate bus number).
	 */
	if (subbus > pci_bus_res[bus].sub_bus)
		pci_bus_res[bus].sub_bus = subbus;
	/*
	 * Loop through subordinate buses, initializing their parent bus
	 * field to this bridge's parent.  The subordinate buses' parent
	 * fields may very well be further refined later, as child bridges
	 * are enumerated.  (The value is to note that the subordinate buses
	 * are not peer buses by changing their par_bus fields to anything
	 * other than -1.)
	 */
	for (i = secbus + 1; i <= subbus; i++)
		pci_bus_res[i].par_bus = bus;

	/*
	 * Update the number of bridges on the bus.
	 */
	if (!is_pci_bridge)
		pci_bus_res[bus].num_bridge++;

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    OBP_DEVICETYPE, dev_type);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    OBP_ADDRESS_CELLS, 3);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    OBP_SIZE_CELLS, 2);

	/*
	 * Collect bridge window specifications, and use them to populate
	 * the "avail" resources for the bus.  Not all of those resources will
	 * end up being available; this is done top-down, and so the initial
	 * collection of windows populates the 'ranges' property for the
	 * bus node.  Later, as children are found, resources are removed from
	 * the 'avail' list, so that it becomes the freelist for
	 * this point in the tree.  ranges will be set again after bridge
	 * reprogramming in fix_ppb_res(), in which case it's set from
	 * used + avail.
	 *
	 * According to PPB spec, the base register should be programmed
	 * with a value bigger than the limit register when there are
	 * no resources available. This applies to io, memory, and
	 * prefetchable memory.
	 */

	fetch_ppb_res(rcdip, bus, dev, func, RES_IO, &io.base, &io.limit);
	fetch_ppb_res(rcdip, bus, dev, func, RES_MEM, &mem.base, &mem.limit);
	fetch_ppb_res(rcdip, bus, dev, func, RES_PMEM, &pmem.base, &pmem.limit);

	if (pci_boot_debug != 0) {
		dcmn_err(CE_NOTE, MSGHDR " I/O FWINIT 0x%lx ~ 0x%lx%s "
		    "(ignored)",
		    ddi_node_name(dip), bus, dev, func, io.base, io.limit,
		    io.base > io.limit ? " (disabled)" : "");
		dcmn_err(CE_NOTE, MSGHDR " MEM FWINIT 0x%lx ~ 0x%lx%s "
		    "(ignored)",
		    ddi_node_name(dip), bus, dev, func, mem.base, mem.limit,
		    mem.base > mem.limit ? " (disabled)" : "");
		dcmn_err(CE_NOTE, MSGHDR "PMEM FWINIT 0x%lx ~ 0x%lx%s "
		    "(ignored)",
		    ddi_node_name(dip), bus, dev, func, pmem.base, pmem.limit,
		    pmem.base > pmem.limit ? " (disabled)" : "");
	}

	io.base = PPB_DISABLE_IORANGE_BASE;
	io.limit = PPB_DISABLE_IORANGE_LIMIT;
	set_ppb_res(rcdip, dip, bus, dev, func, RES_IO, io.base, io.limit);

	mem.base = PPB_DISABLE_MEMRANGE_BASE;
	mem.limit = PPB_DISABLE_MEMRANGE_LIMIT;
	set_ppb_res(rcdip, dip, bus, dev, func, RES_MEM, mem.base,
	    mem.limit);

	pmem.base = PPB_DISABLE_MEMRANGE_BASE;
	pmem.limit = PPB_DISABLE_MEMRANGE_LIMIT;
	set_ppb_res(rcdip, dip, bus, dev, func, RES_PMEM, pmem.base,
	    pmem.limit);

	if (pci_cfgacc_get16(rcdip, PCI_GETBDF(bus, dev, func),
	    PCI_BCNF_BCNTRL) & PCI_BCNF_BCNTRL_VGA_ENABLE) {
		dev_err(dip, CE_PANIC, "ARM PCI does not support legacy VGA");
	}

	add_bus_range_prop(pci_bus_res, secbus);
	add_ranges_prop(pci_bus_res, secbus, B_TRUE);

	dump_memlists(pci_bus_res, "add_ppb_props end bus", bus);
	dump_memlists(pci_bus_res, "add_ppb_props end secbus", secbus);
}

/*
 *
 * Insert the "bus-range" property, indicating the buses this node is
 * responsible for.
 */
static void
add_bus_range_prop(struct pci_bus_resource *pci_bus_res, int bus)
{
	int bus_range[2];

	if (pci_bus_res[bus].dip == NULL)
		return;
	bus_range[0] = bus;
	bus_range[1] = pci_bus_res[bus].sub_bus;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    "bus-range", (int *)bus_range, 2);
}

/*
 * Handle both PCI root and PCI-PCI bridge range properties;
 * the 'ppb' argument selects PCI-PCI bridges versus root.
 */
static void
memlist_to_ranges(void **rp, struct memlist *list, const int bus,
    const uint32_t type, boolean_t ppb)
{
	ppb_ranges_t *ppb_rp = *rp;
	pci_ranges_t *pci_rp = *rp;

	while (list != NULL) {
		uint32_t newtype = type;

		/*
		 * If this is in fact a 64-bit address, adjust the address
		 * type code to match.
		 */
		if (list->ml_address + (list->ml_size - 1) > UINT32_MAX) {
			if ((type & PCI_ADDR_MASK) == PCI_ADDR_IO) {
				cmn_err(CE_WARN, "Found invalid 64-bit I/O "
				    "space address 0x%lx+0x%lx on bus %x",
				    list->ml_address, list->ml_size, bus);
				list = list->ml_next;
				continue;
			}
			newtype &= ~PCI_ADDR_MASK;
			newtype |= PCI_ADDR_MEM64;
		}

		if (ppb) {
			ppb_rp->child_high = ppb_rp->parent_high = newtype;
			ppb_rp->child_mid = ppb_rp->parent_mid =
			    (uint32_t)(list->ml_address >> 32);
			ppb_rp->child_low = ppb_rp->parent_low =
			    (uint32_t)list->ml_address;
			ppb_rp->size_high = (uint32_t)(list->ml_size >> 32);
			ppb_rp->size_low = (uint32_t)list->ml_size;
			*rp = ++ppb_rp;
		} else {
			pci_rp->child_high = newtype;
			pci_rp->child_mid = pci_rp->parent_high =
			    (uint32_t)(list->ml_address >> 32);
			pci_rp->child_low = pci_rp->parent_low =
			    (uint32_t)list->ml_address;
			pci_rp->size_high = (uint32_t)(list->ml_size >> 32);
			pci_rp->size_low = (uint32_t)list->ml_size;
			*rp = ++pci_rp;
		}
		list = list->ml_next;
	}
}

static void
add_ranges_prop(struct pci_bus_resource *pci_bus_res, int bus, boolean_t ppb)
{
	int total, alloc_size;
	void	*rp, *next_rp;
	struct memlist *iolist, *memlist, *pmemlist;

	/* no devinfo node - unused bus, return */
	if (pci_bus_res[bus].dip == NULL)
		return;

	dump_memlists(pci_bus_res, "add_ranges_prop", bus);

	iolist = memlist = pmemlist = (struct memlist *)NULL;

	pci_memlist_merge(&pci_bus_res[bus].io_avail, &iolist);
	pci_memlist_merge(&pci_bus_res[bus].io_used, &iolist);
	pci_memlist_merge(&pci_bus_res[bus].mem_avail, &memlist);
	pci_memlist_merge(&pci_bus_res[bus].mem_used, &memlist);
	pci_memlist_merge(&pci_bus_res[bus].pmem_avail, &pmemlist);
	pci_memlist_merge(&pci_bus_res[bus].pmem_used, &pmemlist);

	total = pci_memlist_count(iolist);
	total += pci_memlist_count(memlist);
	total += pci_memlist_count(pmemlist);

	/* no property is created if no ranges are present */
	if (total == 0)
		return;

	alloc_size = total *
	    (ppb ? sizeof (ppb_ranges_t) : sizeof (pci_ranges_t));

	next_rp = rp = kmem_alloc(alloc_size, KM_SLEEP);

	memlist_to_ranges(&next_rp, iolist, bus,
	    PCI_ADDR_IO | PCI_RELOCAT_B, ppb);
	memlist_to_ranges(&next_rp, memlist, bus,
	    PCI_ADDR_MEM32 | PCI_RELOCAT_B, ppb);
	memlist_to_ranges(&next_rp, pmemlist, bus,
	    PCI_ADDR_MEM32 | PCI_RELOCAT_B | PCI_PREFETCH_B, ppb);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    OBP_RANGES, (int *)rp, alloc_size / sizeof (int));

	kmem_free(rp, alloc_size);
	pci_memlist_free_all(&iolist);
	pci_memlist_free_all(&memlist);
	pci_memlist_free_all(&pmemlist);
}

static void
pci_memlist_remove_list(struct memlist **list, struct memlist *remove_list)
{
	while (list && *list && remove_list) {
		(void) pci_memlist_remove(list, remove_list->ml_address,
		    remove_list->ml_size);
		remove_list = remove_list->ml_next;
	}
}


static int
memlist_to_spec(struct pci_phys_spec *sp, const int bus, struct memlist *list,
    const uint32_t type)
{
	uint_t i = 0;

	while (list != NULL) {
		uint32_t newtype = type;

		/*
		 * If this is in fact a 64-bit address, adjust the address
		 * type code to match.
		 */
		if (list->ml_address + (list->ml_size - 1) > UINT32_MAX) {
			if ((type & PCI_ADDR_MASK) == PCI_ADDR_IO) {
				cmn_err(CE_WARN, "Found invalid 64-bit I/O "
				    "space address 0x%lx+0x%lx on bus %x",
				    list->ml_address, list->ml_size, bus);
				list = list->ml_next;
				continue;
			}
			newtype &= ~PCI_ADDR_MASK;
			newtype |= PCI_ADDR_MEM64;
		}

		sp->pci_phys_hi = newtype;
		sp->pci_phys_mid = (uint32_t)(list->ml_address >> 32);
		sp->pci_phys_low = (uint32_t)list->ml_address;
		sp->pci_size_hi = (uint32_t)(list->ml_size >> 32);
		sp->pci_size_low = (uint32_t)list->ml_size;

		list = list->ml_next;
		sp++, i++;
	}
	return (i);
}

static void
add_bus_available_prop(struct pci_bus_resource *pci_bus_res, int bus)
{
	int i, count;
	struct pci_phys_spec *sp;

	/* no devinfo node - unused bus, return */
	if (pci_bus_res[bus].dip == NULL)
		return;

	count = pci_memlist_count(pci_bus_res[bus].io_avail) +
	    pci_memlist_count(pci_bus_res[bus].mem_avail) +
	    pci_memlist_count(pci_bus_res[bus].pmem_avail);

	if (count == 0)		/* nothing available */
		return;

	sp = kmem_alloc(count * sizeof (*sp), KM_SLEEP);
	i = memlist_to_spec(&sp[0], bus, pci_bus_res[bus].io_avail,
	    PCI_ADDR_IO | PCI_RELOCAT_B);
	i += memlist_to_spec(&sp[i], bus, pci_bus_res[bus].mem_avail,
	    PCI_ADDR_MEM32 | PCI_RELOCAT_B);
	i += memlist_to_spec(&sp[i], bus, pci_bus_res[bus].pmem_avail,
	    PCI_ADDR_MEM32 | PCI_RELOCAT_B | PCI_PREFETCH_B);
	ASSERT(i == count);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    "available", (int *)sp,
	    i * sizeof (struct pci_phys_spec) / sizeof (int));
	kmem_free(sp, count * sizeof (*sp));
}

static void
alloc_res_array(struct pci_bus_resource **pci_bus_res, size_t maxbus)
{
	*pci_bus_res = kmem_zalloc((maxbus + 1) *
	    sizeof (struct pci_bus_resource), KM_SLEEP);
}
