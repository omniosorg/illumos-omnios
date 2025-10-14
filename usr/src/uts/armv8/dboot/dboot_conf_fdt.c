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
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/null.h>
#include <sys/bootinfo.h>
#include <sys/psci.h>
#include <sys/obpdefs.h>
#include <sys/cpuinfo.h>
#include <sys/controlregs.h>
#include <sys/machparam.h>
#include <libfdt.h>

#include "dboot.h"
#include "dboot_printf.h"

extern void boot_psci_init(struct xboot_info *);

typedef enum {
	CPUNODE_STATUS_OKAY	= 0,
	CPUNODE_STATUS_DISABLED	= 1,
	CPUNODE_STATUS_FAILED	= 2,
	CPUNODE_STATUS_UNKNOWN	= 3,
	CPUNODE_STATUS_OTHER	= 4,
	CPUNODE_STATUS_ERROR	= 5,
} cpunode_status_t;

#define	CPUNODE_BAD_AFFINITY		0xffffffffffffffffull

#define	CPUNODE_BAD_ENABLE_METHOD	-1

#define	CPUNODE_BAD_PARKED_ADDRESS	0xffffffffffffffffull

static const void *
get_fdtp(void)
{
	static const void *fdtp;
	extern struct xboot_info *bi;

	if (fdtp != NULL)
		return (fdtp);

	if (bi == NULL)
		return (NULL);

	if (bi->bi_fdt == 0)
		return (NULL);

	if (fdt_check_header((const void *)bi->bi_fdt) != 0)
		return (NULL);

	fdtp = (const void *)bi->bi_fdt;
	return (fdtp);
}

static cpunode_status_t
get_cpu_status(const void *fdtp, int nodeoff)
{
	const struct fdt_property *prop;
	int plen;

	plen = 0;
	if ((prop = fdt_get_property(fdtp, nodeoff, OBP_STATUS, &plen)) == NULL)
		return (CPUNODE_STATUS_UNKNOWN);
	if (plen == 0)
		return (CPUNODE_STATUS_ERROR);

	if (strcmp(prop->data, "okay") == 0 || strcmp(prop->data, "ok") == 0)
		return (CPUNODE_STATUS_OKAY);
	else if (strcmp(prop->data, "disabled") == 0)
		return (CPUNODE_STATUS_DISABLED);
	else if (strncmp(prop->data, "fail", 4) == 0)
		return (CPUNODE_STATUS_FAILED);

	return (CPUNODE_STATUS_OTHER);
}

/*
 * Extract the MPIDR of the target CPU object, or CPUNODE_BAD_AFFINITY on error.
 */
static uint64_t
get_cpu_mpidr(const void *fdtp, int nodeoff)
{
	const void	*prop;
	int		plen;
	int		cv;
	int		ac;
	int		poff;
	uint64_t	affinity = CPUNODE_BAD_AFFINITY;
	uint32_t	parts[2] = {0, 0};

	if ((poff = fdt_parent_offset(fdtp, nodeoff)) < 0)
		return (affinity);

	cv = fdt_size_cells(fdtp, poff);
	if (cv != 0)
		return (affinity);

	ac = fdt_address_cells(fdtp, poff);
	if (ac != 1 && ac != 2)
		return (affinity);

	plen = 0;
	if ((prop = fdt_getprop(fdtp, nodeoff, OBP_REG, &plen)) == NULL)
		return (affinity);
	if ((ac == 1 && plen != sizeof (uint32_t)) ||
	    (ac == 2 && plen != (sizeof (uint32_t) * 2)))
		return (affinity);
	memcpy(&parts[0], prop, plen);

	switch (ac) {
	case 1:
		affinity = (uint64_t)fdt32_to_cpu(parts[0]);
		break;
	case 2:
		affinity = (uint64_t)fdt32_to_cpu(parts[0]);
		affinity <<= 32;
		affinity |= (uint64_t)fdt32_to_cpu(parts[1]);
		break;
	default:
		break;
	}

	return (affinity);
}

static int
get_enable_method(const void *fdtp, int nodeoff)
{
	/* enable-method: psci|spin-table */
	const char	*prop;
	int		plen;

	plen = 0;
	/*
	 * When booting on a single CPU host (e.g. qemu) there may not be a
	 * per-CPU enable-method, so go looking in the root.
	 */
	if ((prop = fdt_getprop(fdtp, nodeoff, "enable-method", &plen)) ==
	    NULL) {
		if (fdt_path_offset(fdtp, "/psci") >= 0)
			return (CPUINFO_ENABLE_METHOD_PSCI);
		return (CPUNODE_BAD_ENABLE_METHOD);
	}
	if (plen == 0)
		return (CPUNODE_BAD_ENABLE_METHOD);

	if (strcmp(prop, "psci") == 0)
		return (CPUINFO_ENABLE_METHOD_PSCI);
	else if (strcmp(prop, "spin-table") == 0)
		return (CPUINFO_ENABLE_METHOD_SPINTABLE_SIMPLE);

	return (CPUNODE_BAD_ENABLE_METHOD);
}

static uint64_t
get_parked_address(const void *fdtp, int nodeoff)
{
	const void	*prop;
	int		plen;
	int		cv;
	int		ac;
	int		poff;
	uint64_t	parked_addr = CPUNODE_BAD_PARKED_ADDRESS;
	uint32_t	parts[2] = {0, 0};

	if ((poff = fdt_parent_offset(fdtp, nodeoff)) < 0)
		return (parked_addr);

	cv = fdt_size_cells(fdtp, poff);
	if (cv != 0)
		return (parked_addr);

	ac = fdt_address_cells(fdtp, poff);
	if (ac != 1 && ac != 2)
		return (parked_addr);

	plen = 0;
	if ((prop = fdt_getprop(fdtp, nodeoff, "cpu-release-addr", &plen)) ==
	    NULL)
		return (parked_addr);
	if ((ac == 1 && plen != sizeof (uint32_t)) ||
	    (ac == 2 && plen != (sizeof (uint32_t) * 2)))
		return (parked_addr);
	memcpy(&parts[0], prop, plen);

	switch (ac) {
	case 1:
		parked_addr = (uint64_t)fdt32_to_cpu(parts[0]);
		break;
	case 2:
		parked_addr = (uint64_t)fdt32_to_cpu(parts[0]);
		parked_addr <<= 32;
		parked_addr |= (uint64_t)fdt32_to_cpu(parts[1]);
		break;
	default:
		break;
	}

	return (parked_addr);
}

static bool
is_gicv3(const void *fdtp)
{
	return (fdt_node_offset_by_compatible(fdtp, 0, "arm,gic-v3") > 0);
}

/*
 * In the FDT case we have to infer the CPU Interface Number.
 *
 * This seems a bit sketchy, but looking at edk2 sources (as
 * DynamicTablesPkg/Library/FdtHwInfoParserLib/Gic/ArmGicCParser.c) and at
 * u-boot sources (arch/arm/cpu/armv8/spin_table.c, arch/arm/cpu/armv8/start.S
 * and arch/arm/cpu/armv8/spin_table_v8.S) makes this palatable.
 *
 * Specifically, this comment from edk2 sums up the situation nicely:
 *
 * To fit the Affinity [0-3] a 32bits value, place the Aff3 on bits
 * [31:24] instead of their original place ([39:32]).
 *
 * Furthermore, the CPU Interface Number is only poopulated for GICv2, as GICv3
 * in legacy mode is unsupported by edk2.
 *
 * ARM Trusted Firmware updates the board device tree to use PSCI.
 */
static int
fill_xcpuinfo(const void *fdtp, int nodeoff, struct xboot_cpu_info *xci)
{
	xci->xci_flags = 0;

	/*
	 * Translate FDT CPU node status to ACPI-like "Enabled" and
	 * "Online Capable" flags.
	 */
	switch (get_cpu_status(fdtp, nodeoff)) {
	case CPUNODE_STATUS_UNKNOWN:	/* fallthrough */
	case CPUNODE_STATUS_OKAY:
		xci->xci_flags |= CPUINFO_ENABLED;
		break;
	default:
		break;
	}

	/*
	 * There isn't really a notion of "Online Capable" in the FDT CPU node,
	 * so no hot-pluggable CPUs for embedded devices (which makes sense).
	 *
	 * If there were such a notion we'd set the CPUINFO_ONLINE_CAPABLE bit
	 * here if the CPU were not enabled but capable of coming online.
	 *
	 * Other flags we're not yet setting are the interrupt mode bits for
	 * the performance and VGIC maintenance interrupts.
	 */

	if ((xci->xci_mpidr = get_cpu_mpidr(fdtp, nodeoff)) ==
	    CPUNODE_BAD_AFFINITY)
		return (-1);

	if ((xci->xci_ppver = get_enable_method(fdtp, nodeoff)) ==
	    CPUNODE_BAD_ENABLE_METHOD)
		return (-1);

	xci->xci_parked_addr = 0;
	if (xci->xci_ppver == CPUINFO_ENABLE_METHOD_SPINTABLE_SIMPLE) {
		if ((xci->xci_parked_addr = get_parked_address(fdtp, nodeoff))
		    == CPUNODE_BAD_PARKED_ADDRESS)
			return (-1);
	}

	/* the Uid field is ACPI-specific */
	xci->xci_uid = 0;

	xci->xci_cpuif = 0;
	if (!is_gicv3(fdtp)) {
		/*
		 * Assume GICv2, since we don't support anything else.
		 *
		 * GICv4.x has the same driver as GICv3.
		 */
		xci->xci_cpuif = (xci->xci_mpidr & 0x00ffffff) |
		    ((xci->xci_mpidr >> 8) & 0xff000000);
	}

	return (0);
}

static int
dboot_configure_fdt_cpuinfo(const void *fdtp, struct xboot_info *bi)
{
	uint64_t boot_cpu_affinity;
	int cpus;
	int child;
	const char *device_type;
	int device_type_len;
	struct xboot_cpu_info *xci;

	bi->bi_cpuinfo_cnt = 0;
	if ((xci = (struct xboot_cpu_info *)bi->bi_cpuinfo) == NULL)
		return (-1);

	boot_cpu_affinity = (read_mpidr() & MPIDR_AFF_MASK);

	if ((cpus = fdt_path_offset(fdtp, "/cpus")) < 0) {
		dboot_printf("dboot: no /cpus node in FDT\n");
		return (-1);
	}

	/*
	 * We iterate the CPU list twice. On the first pass we match the
	 * CPU we're running on (the boot CPU) and record it at index 0.
	 *
	 * On the second pass we match all other CPUs, recording them as
	 * we discover them.
	 */

	if ((child = fdt_first_subnode(fdtp, cpus)) < 0) {
		dboot_printf("dboot: no /cpus node children in FDT\n");
		return (-1);
	}

	do {
		device_type_len = 0;
		if ((device_type = fdt_getprop(fdtp, child, OBP_DEVICETYPE,
		    &device_type_len)) == NULL || device_type_len == 0)
			continue;
		if (strcmp(device_type, OBP_CPU) != 0)
			continue;

		if (get_cpu_mpidr(fdtp, child) != boot_cpu_affinity)
			continue;

		if (fill_xcpuinfo(fdtp, child, &xci[bi->bi_cpuinfo_cnt]) != 0) {
			dboot_printf("dboot: error filling boot CPU info\n");
			return (-1);
		}

		xci[bi->bi_cpuinfo_cnt].xci_id = bi->bi_cpuinfo_cnt;
		bi->bi_cpuinfo_cnt++;
		break;
	} while ((child = fdt_next_subnode(fdtp, child)) >= 0);

	if (bi->bi_cpuinfo_cnt != 1) {
		dboot_printf("dboot: could not match boot processor in FDT\n");
		return (-1);
	}

	/*
	 * Second pass, all APs.
	 */

	if ((child = fdt_first_subnode(fdtp, cpus)) < 0) {
		dboot_printf("dboot: no /cpus node children in FDT\n");
		return (-1);
	}

	do {
		if (bi->bi_cpuinfo_cnt >= NCPU) {
			dboot_printf("dboot: number of CPUs exceeds NCPU\n");
			break;
		}

		device_type_len = 0;
		if ((device_type = fdt_getprop(fdtp, child, OBP_DEVICETYPE,
		    &device_type_len)) == NULL || device_type_len == 0)
			continue;
		if (strcmp(device_type, OBP_CPU) != 0)
			continue;

		/* CPUNODE_BAD_AFFINITY is checked in fill_xcpuinfo */
		if (get_cpu_mpidr(fdtp, child) == boot_cpu_affinity)
			continue;

		if (fill_xcpuinfo(fdtp, child, &xci[bi->bi_cpuinfo_cnt]) != 0) {
			dboot_printf(
			    "dboot: error filling application CPU info\n");
			return (-1);
		}

		xci[bi->bi_cpuinfo_cnt].xci_id = bi->bi_cpuinfo_cnt;
		bi->bi_cpuinfo_cnt++;
	} while ((child = fdt_next_subnode(fdtp, child)) >= 0);

	return (0);
}

static void
dboot_count_pcierc_compat(const void *fdtp, struct xboot_info *bi,
    const char *compat)
{
	int off = fdt_node_offset_by_compatible(fdtp, -1, compat);

	while (off != -FDT_ERR_NOTFOUND) {
		bi->bi_pcierc_cnt++;
		off = fdt_node_offset_by_compatible(fdtp, off, compat);
	}
}

static void
dboot_count_pcierc(const void *fdtp, struct xboot_info *bi)
{
	static const char *ecam = "pci-host-ecam-generic";
	static const char *rpi4 = "brcm,bcm2711-pcie";

	bi->bi_pcierc_cnt = 0;
	dboot_count_pcierc_compat(fdtp, bi, ecam);
	dboot_count_pcierc_compat(fdtp, bi, rpi4);
}

int
dboot_configure_fdt(void)
{
	const void *fdtp;
	int nodeoff;
	const char *method;
	const uint32_t *pval;
	int plen;
	extern struct xboot_info *bi;

	if (bi == NULL)
		return (-1);

	if ((fdtp = get_fdtp()) == NULL)
		return (-1);

	/*
	 * Extract PSCI configuration from the FDT.
	 *
	 * The mandatory configuration here is the PSCI conduit (HVC or SMC),
	 * while the legacy function identifiers are optional.
	 */

	nodeoff = fdt_node_offset_by_compatible(fdtp, -1, "arm,psci");
	if (nodeoff < 0)
		return (-1);

	if ((method = fdt_getprop(fdtp, nodeoff, "method", &plen)) == NULL ||
	    plen == 0) {
		return (-1);
	}

	bi->bi_psci_conduit_hvc = strcmp(method, "hvc") == 0 ? 1 : 0;

	if ((pval = fdt_getprop(fdtp, nodeoff, "cpu_suspend", &plen)) != NULL) {
		bi->bi_psci_cpu_suspend_id =
		    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	if ((pval = fdt_getprop(fdtp, nodeoff, "cpu_off", &plen)) != NULL) {
		bi->bi_psci_cpu_off_id =
		    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	if ((pval = fdt_getprop(fdtp, nodeoff, "cpu_on", &plen)) != NULL) {
		bi->bi_psci_cpu_on_id =
		    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	if ((pval = fdt_getprop(fdtp, nodeoff, "migrate", &plen)) != NULL) {
		bi->bi_psci_migrate_id =
		    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	boot_psci_init(bi);

	/*
	 * Extract architected timer configuration from the FDT.
	 *
	 * On FDT systems this might not not programmed into cntfrq, so we
	 * try to read it from FDT first. If it's there we use that value.
	 *
	 * If not present in firmware, the caller sets the value from cntfrq
	 * and claims success if that value is non-zero.
	 */

	nodeoff = fdt_node_offset_by_compatible(fdtp, -1, "arm,armv8-timer");
	if (nodeoff >= 0) {
		if ((pval = fdt_getprop(fdtp, nodeoff,
		    "clock-frequency", &plen)) != NULL)
			bi->bi_arch_timer_freq =
			    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	dboot_count_pcierc(fdtp, bi);
	return (dboot_configure_fdt_cpuinfo(fdtp, bi));
}
