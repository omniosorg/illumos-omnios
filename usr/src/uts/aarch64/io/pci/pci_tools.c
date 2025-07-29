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
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This file is the backend for the pcieadm and pcitool(8) tools.  In this
 * case only the small amount of config space access needed by pcieadm is
 * supported.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <vm/seg_kmem.h>
#include <sys/sunndi.h>
#include <sys/ontrap.h>
#include <sys/pcie.h>
#include <sys/pci_tools.h>
#include <io/pci/pci_tools_ext.h>
#include <sys/pci_impl.h>
#include <sys/promif.h>
#include <sys/cpuvar.h>
#include <sys/pci_cfgacc.h>

#define	PCIEX_BDF_OFFSET_DELTA	4
#define	PCIEX_REG_FUNC_SHIFT	(PCI_REG_FUNC_SHIFT + PCIEX_BDF_OFFSET_DELTA)
#define	PCIEX_REG_DEV_SHIFT	(PCI_REG_DEV_SHIFT + PCIEX_BDF_OFFSET_DELTA)
#define	PCIEX_REG_BUS_SHIFT	(PCI_REG_BUS_SHIFT + PCIEX_BDF_OFFSET_DELTA)

#define	SUCCESS	0

extern dev_info_t *pcie_get_rc_dip(dev_info_t *);

int pcitool_debug = 0;

/*
 * Offsets of BARS in config space.  First entry of 0 means config space.
 * Entries here correlate to pcitool_bars_t enumerated type.
 */
static uint8_t pci_bars[] = {
	0x0,
	PCI_CONF_BASE0,
	PCI_CONF_BASE1,
	PCI_CONF_BASE2,
	PCI_CONF_BASE3,
	PCI_CONF_BASE4,
	PCI_CONF_BASE5,
	PCI_CONF_ROM
};

/* Max offset allowed into config space for a particular device. */
static uint64_t max_cfg_size = PCI_CONF_HDR_SIZE;

static uint64_t pcitool_swap_endian(uint64_t, int);
static int pcitool_cfg_access(dev_info_t *, pcitool_reg_t *, boolean_t);

int
pcitool_init(dev_info_t *dip, boolean_t is_pciex)
{
	int instance = ddi_get_instance(dip);

	/* Create pcitool nodes for register access and interrupt routing. */

	if (ddi_create_minor_node(dip, PCI_MINOR_REG, S_IFCHR,
	    PCI_MINOR_NUM(instance, PCI_TOOL_REG_MINOR_NUM),
	    DDI_NT_REGACC, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, PCI_MINOR_INTR, S_IFCHR,
	    PCI_MINOR_NUM(instance, PCI_TOOL_INTR_MINOR_NUM),
	    DDI_NT_INTRCTL, 0) != DDI_SUCCESS) {
		ddi_remove_minor_node(dip, PCI_MINOR_REG);
		return (DDI_FAILURE);
	}

	if (is_pciex)
		max_cfg_size = PCIE_CONF_HDR_SIZE;

	return (DDI_SUCCESS);
}

void
pcitool_uninit(dev_info_t *dip)
{
	ddi_remove_minor_node(dip, PCI_MINOR_INTR);
	ddi_remove_minor_node(dip, PCI_MINOR_REG);
}

static int
pcitool_set_intr(dev_info_t *dip, void *arg, int mode)
{
	return (ENOTSUP);
}

static int
pcitool_get_intr(dev_info_t *dip, void *arg, int mode)
{
	return (ENOTSUP);
}

static int
pcitool_intr_info(dev_info_t *dip, void *arg, int mode)
{
	return (ENOTSUP);
}

/*
 * Main function for handling interrupt CPU binding requests and queries.
 * Need to implement later
 */
int
pcitool_intr_admn(dev_info_t *dip, void *arg, int cmd, int mode)
{
	int rval;

	switch (cmd) {

	/* Associate a new CPU with a given vector */
	case PCITOOL_DEVICE_SET_INTR:
		rval = pcitool_set_intr(dip, arg, mode);
		break;

	case PCITOOL_DEVICE_GET_INTR:
		rval = pcitool_get_intr(dip, arg, mode);
		break;

	case PCITOOL_SYSTEM_INTR_INFO:
		rval = pcitool_intr_info(dip, arg, mode);
		break;

	default:
		rval = ENOTSUP;
	}

	return (rval);
}

int
pcitool_bus_reg_ops(dev_info_t *dip, void *arg, int cmd, int mode)
{
	return (ENOTSUP);
}

/* Swap endianness. */
static uint64_t
pcitool_swap_endian(uint64_t data, int size)
{
	typedef union {
		uint64_t data64;
		uint8_t data8[8];
	} data_split_t;

	data_split_t orig_data;
	data_split_t returned_data;
	int i;

	orig_data.data64 = data;
	returned_data.data64 = 0;

	for (i = 0; i < size; i++) {
		returned_data.data8[i] = orig_data.data8[size - 1 - i];
	}

	return (returned_data.data64);
}

/* Access device.  prg is modified. */
static int
pcitool_cfg_access(dev_info_t *dip, pcitool_reg_t *prg, boolean_t write_flag)
{
	int size = PCITOOL_ACC_ATTR_SIZE(prg->acc_attr);
	boolean_t big_endian = PCITOOL_ACC_IS_BIG_ENDIAN(prg->acc_attr);
	int rval = SUCCESS;
	uint64_t local_data;
	pci_cfgacc_req_t req;
	uint32_t max_offset;

	if ((size <= 0) || (size > 8) || !ISP2(size)) {
		prg->status = PCITOOL_INVALID_SIZE;
		return (ENOTSUP);
	}

	/*
	 * NOTE: there is no way to verify whether or not the address is
	 * valid other than that it is within the maximum offset.  The
	 * put functions return void and the get functions return -1 on error.
	 */
	max_offset = 0xFFF;

	if (prg->offset + size - 1 > max_offset) {
		prg->status = PCITOOL_INVALID_ADDRESS;
		return (ENOTSUP);
	}

	prg->status = PCITOOL_SUCCESS;

	req.rcdip = pcie_get_rc_dip(dip);
	req.bdf = PCI_GETBDF(prg->bus_no, prg->dev_no, prg->func_no);
	req.offset = prg->offset;
	req.size = size;
	req.write = write_flag;
	req.ioacc = B_FALSE;

	if (write_flag) {
		if (big_endian) {
			local_data = pcitool_swap_endian(prg->data, size);
		} else {
			local_data = prg->data;
		}
		VAL64(&req) = local_data;
		pci_cfgacc_acc(&req);
	} else {
		pci_cfgacc_acc(&req);
		switch (size) {
		case 1:
			local_data = VAL8(&req);
			break;
		case 2:
			local_data = VAL16(&req);
			break;
		case 4:
			local_data = VAL32(&req);
			break;
		case 8:
			local_data = VAL64(&req);
			break;
		default:
			prg->status = PCITOOL_INVALID_ADDRESS;
			return (ENOTSUP);
		}
		if (big_endian) {
			prg->data =
			    pcitool_swap_endian(local_data, size);
		} else {
			prg->data = local_data;
		}
	}

	/* There's no reliable physical address on this platform */
	prg->phys_addr = 0;

	return (rval);
}

int
pcitool_dev_reg_ops(dev_info_t *dip, void *arg, int cmd, int mode)
{
	boolean_t	write_flag = B_FALSE;
	int		rval = 0;
	pcitool_reg_t	prg;

	switch (cmd) {
	case (PCITOOL_DEVICE_SET_REG):
		write_flag = B_TRUE;

	/*FALLTHRU*/
	case (PCITOOL_DEVICE_GET_REG):
		if (pcitool_debug)
			prom_printf("pci_dev_reg_ops set/get reg\n");
		if (ddi_copyin(arg, &prg, sizeof (pcitool_reg_t), mode) !=
		    DDI_SUCCESS) {
			if (pcitool_debug)
				prom_printf("Error reading arguments\n");
			return (EFAULT);
		}

		if (prg.barnum >= (sizeof (pci_bars) / sizeof (pci_bars[0]))) {
			prg.status = PCITOOL_OUT_OF_RANGE;
			rval = EINVAL;
			goto done_reg;
		}

		if (pcitool_debug)
			prom_printf("raw bus:0x%x, dev:0x%x, func:0x%x\n",
			    prg.bus_no, prg.dev_no, prg.func_no);
		/* Validate address arguments of bus / dev / func */
		if (((prg.bus_no &
		    (PCI_REG_BUS_M >> PCI_REG_BUS_SHIFT)) !=
		    prg.bus_no) ||
		    ((prg.dev_no &
		    (PCI_REG_DEV_M >> PCI_REG_DEV_SHIFT)) !=
		    prg.dev_no) ||
		    ((prg.func_no &
		    (PCI_REG_FUNC_M >> PCI_REG_FUNC_SHIFT)) !=
		    prg.func_no)) {
			prg.status = PCITOOL_INVALID_ADDRESS;
			rval = EINVAL;
			goto done_reg;
		}

		/* Proper config space desired. */
		if (prg.barnum == 0) {
			if (pcitool_debug)
				prom_printf(
				    "config access: offset:0x%" PRIx64 ", "
				    "phys_addr:0x%" PRIx64 "\n",
				    prg.offset, prg.phys_addr);

			if (prg.offset >= max_cfg_size) {
				prg.status = PCITOOL_OUT_OF_RANGE;
				rval = EINVAL;
				goto done_reg;
			}

			rval = pcitool_cfg_access(dip, &prg, write_flag);
			if (pcitool_debug)
				prom_printf(
				    "config access: data:0x%" PRIx64 "\n",
				    prg.data);

		/* IO/ MEM/ MEM64 space. */
		} else {
			prg.status = PCITOOL_OUT_OF_RANGE;
		}
done_reg:
		prg.drvr_version = PCITOOL_VERSION;
		if (ddi_copyout(&prg, arg, sizeof (pcitool_reg_t), mode) !=
		    DDI_SUCCESS) {
			if (pcitool_debug)
				prom_printf("Error returning arguments.\n");
			rval = EFAULT;
		}
		break;
	default:
		rval = ENOTTY;
		break;
	}
	return (rval);
}
