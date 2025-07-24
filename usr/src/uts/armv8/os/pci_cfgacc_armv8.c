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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include <sys/pci.h>
#include <sys/pci_cfgacc.h>
#include <sys/pcie_impl.h>

void
pci_cfgacc_acc(pci_cfgacc_req_t *req)
{
	VERIFY3P(req, !=, NULL);
	VERIFY3P(req->rcdip, !=, NULL);

	VERIFY(ndi_port_type(req->rcdip, B_TRUE, DEVI_PORT_TYPE_PCIRC));

	pcie_rc_data_t *rcdata = ndi_get_bus_private(req->rcdip, B_TRUE);

	if ((rcdata == NULL) || (rcdata->pcie_rc_cfgspace_acc == NULL)) {
		dev_err(req->rcdip, CE_PANIC, "not registered as a "
		    "PCIe root complex");
		if (!req->write) {
			VAL64(req) = PCI_EINVAL64;
		}
		return;
	}

	rcdata->pcie_rc_cfgspace_acc(req);
}
