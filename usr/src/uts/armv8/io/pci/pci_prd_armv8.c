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
 * Copyright 2023 Oxide Computer Company
 * Copyright 2024 Richard Lowe
 */

/*
 * PCI Resource Discovery on armv8.  We just ask the PROM device tree.
 *
 * XXXARM: Architecturally, I'm assuming that this module `pci_prd_armv8` is
 * devicetree based, and an acpi-based `pci_prd_sbsa` would exist.
 */

#include <sys/esunddi.h>
#include <sys/memlist.h>
#include <sys/promif.h>
#include <sys/types.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/plat/pci_prd.h>
#include <sys/obpdefs.h>

/*
 * We always just tell the system to scan all PCI buses.
 */
uint32_t
pci_prd_max_bus(void)
{
	return (PCI_MAX_BUS_NUM - 1);
}

boolean_t
pci_prd_multi_root_ok(void)
{
	return (B_TRUE);
}

pci_prd_compat_flags_t
pci_prd_compat_flags(void)
{
	/*
	 * On systems using devicetree, we need IEEE 1275 compatible naming.
	 */
	return (PCI_PRD_COMPAT_1275);
}



static struct modlmisc pci_prd_modlmisc_armv8 = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "armv8 PCI Resource Discovery"
};

static struct modlinkage pci_prd_modlinkage_armv8 = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &pci_prd_modlmisc_armv8, NULL }
};

int
_init(void)
{
	return (mod_install(&pci_prd_modlinkage_armv8));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pci_prd_modlinkage_armv8, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&pci_prd_modlinkage_armv8));
}
