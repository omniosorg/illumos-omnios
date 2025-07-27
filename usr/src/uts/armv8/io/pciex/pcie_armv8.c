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
 * Copyright 2024 Richard Lowe
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/plat/pci_prd.h>

void
pcie_init_plat(dev_info_t *dip)
{
}

void
pcie_fini_plat(dev_info_t *dip)
{
}

int
pcie_plat_pwr_setup(dev_info_t *dip __unused)
{
	return (DDI_SUCCESS);
}

/*
 * Undo whatever is done in pcie_plat_pwr_setup
 */
void
pcie_plat_pwr_teardown(dev_info_t *dip __unused)
{
}
