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
 * Copyright 2026 Michael van der Westhuizen
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
#include <sys/sunndi.h>
#include <vm/seg_kmem.h>
#include <sys/ontrap.h>
#include <sys/pcie.h>
#include <sys/pci_tools.h>
#include <io/pci/pci_tools_ext.h>
#include <sys/pci_impl.h>
#include <sys/promif.h>
#include <sys/cpuvar.h>
#include <sys/pci_cfgacc.h>
#include <sys/ddi_intr_impl.h>
#include <sys/avintr.h>

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

/*
 * Fill in a pcitool_intr_dev_t from a dev_info_t.
 */
static void
pcitool_get_intr_dev_info(dev_info_t *dip, pcitool_intr_dev_t *devs)
{
	if (dip == NULL) {
		(void) strlcpy(devs->driver_name,
		    "(unknown)", sizeof (devs->driver_name));
		devs->path[0] = '/';
		devs->path[1] = '\0';
		devs->dev_inst = 0;
		return;
	}

	(void) strlcpy(devs->driver_name,
	    ddi_driver_name(dip), sizeof (devs->driver_name));
	(void) ddi_pathname(dip, devs->path);
	devs->dev_inst = ddi_get_instance(dip);
}

/*
 * PCITOOL_DEVICE_SET_INTR: retarget an interrupt to a different CPU.
 */
static int
pcitool_set_intr(dev_info_t *dip, void *arg, int mode)
{
	pcitool_intr_set_t iset;
	ddi_intr_handle_impl_t *hdlp = NULL;
	processorid_t old_cpu;
	processorid_t new_cpu;
	int rval = SUCCESS;
	size_t copyinout_size = sizeof (pcitool_intr_set_t);

	if (ddi_copyin(arg, &iset, copyinout_size, mode) != DDI_SUCCESS) {
		return (EFAULT);
	}

	switch (iset.user_version) {
	case PCITOOL_V2:
		break;

	default:
		iset.status = PCITOOL_OUT_OF_RANGE;
		rval = ENOTSUP;
		goto done_set_intr;
	}

	/*
	 * i86pc only retargets MSI/MSI-X, but we can retarget FIXED as well.
	 */

	ndi_devi_enter(dip);

	/* Look up the autovect chain for a representative handle */
	if (av_get_vector_info(iset.ino, &hdlp, NULL, 0) == 0 ||
	    hdlp == NULL) {
		ndi_devi_exit(dip);
		iset.status = PCITOOL_INVALID_INO;
		rval = EINVAL;
		goto done_set_intr;
	}

	/* Read current CPU assignment */
	if (hdlp->ih_dip == NULL) {
		old_cpu = (processorid_t)-1;
	} else {
		if (get_intr_affinity(
		    (ddi_intr_handle_t)hdlp, &old_cpu) != DDI_SUCCESS) {
			ndi_devi_exit(dip);
			iset.status = PCITOOL_IO_ERROR;
			rval = EIO;
			goto done_set_intr;
		}
	}

	/* Validate target CPU. */
	if (iset.cpu_id >= (uint32_t)ncpus) {
		ndi_devi_exit(dip);
		rval = EINVAL;
		iset.status = PCITOOL_INVALID_CPUID;
		goto done_set_intr;
	}

	iset.status = PCITOOL_SUCCESS;

	/* Retarget the interrupt via the GIC driver. */
	new_cpu = (processorid_t)iset.cpu_id;
	if (set_intr_affinity(
	    (ddi_intr_handle_t)hdlp, new_cpu) != DDI_SUCCESS) {
		rval = EIO;
		iset.status = PCITOOL_IO_ERROR;
	}

	ndi_devi_exit(dip);

	/* Return original CPU */
	iset.cpu_id = (uint32_t)old_cpu;

done_set_intr:
	iset.drvr_version = PCITOOL_VERSION;
	if (ddi_copyout(&iset, arg, copyinout_size, mode) != DDI_SUCCESS) {
		rval = EFAULT;
	}

	return (rval);
}

/*
 * PCITOOL_DEVICE_GET_INTR: return device and CPU information for a
 * given interrupt vector.
 */
static int
pcitool_get_intr(dev_info_t *dip, void *arg, int mode)
{
	pcitool_intr_get_t partial_iget;
	pcitool_intr_get_t *iget = &partial_iget;
	size_t iget_kmem_alloc_size = 0;
	uint8_t num_devs_ret = 0;
	int copyout_rval;
	int rval = SUCCESS;
	uint_t i;
	ddi_intr_handle_impl_t *hdlp = NULL;
	uint_t num_devs;
	processorid_t cpu_id;
	dev_info_t **dip_list = NULL;
	uint32_t saved_ino;

	/* Read in just the header part, no variable-length array section. */
	if (ddi_copyin(arg, &partial_iget, PCITOOL_IGET_SIZE(0), mode) !=
	    DDI_SUCCESS) {
		return (EFAULT);
	}

	num_devs_ret = partial_iget.num_devs_ret;

	/*
	 * If caller wants device information, allocate the full response
	 * buffer and the dip collection array.
	 *
	 * NOTE: we are allocating memory based on user-supplied values here,
	 * both via PCITOOL_IGET_SIZE and directly for the dip list.  This
	 * is not an attack vector, as both num_devs_ret and the user-supplied
	 * iget.num_devs_ret are uint8_t.  For the dip list the maximum
	 * allocation size is 2040 bytes, and for iget the maximum allocation
	 * size is 327447 bytes (modulo struct padding).  This is nowhere near
	 * integer overflow territory.
	 */
	if (num_devs_ret > 0) {
		iget_kmem_alloc_size = PCITOOL_IGET_SIZE(num_devs_ret);
		iget = kmem_zalloc(iget_kmem_alloc_size, KM_SLEEP);

		/* Read in whole structure to verify there's room. */
		if (ddi_copyin(arg, iget, iget_kmem_alloc_size, mode) !=
		    SUCCESS) {
			kmem_free(iget, iget_kmem_alloc_size);
			return (EFAULT);
		}

		dip_list = kmem_zalloc(
		    num_devs_ret * sizeof (dev_info_t *), KM_SLEEP);
	}

	/*
	 * Hold the device tree to stabilise dip pointers returned by
	 * av_get_vector_info() while we extract device information.
	 */
	if (num_devs_ret > 0) {
		ndi_devi_enter(dip);
	}

	/*
	 * Walk the autovect chain.  Returns total handler count and
	 * fills dip_list up to num_devs_ret entries.  hdlp receives a
	 * representative handle for GETTARGET.
	 */
	num_devs = av_get_vector_info(partial_iget.ino, &hdlp,
	    dip_list, num_devs_ret);

	/* Get current CPU via the interrupt controller driver */
	if (num_devs != 0 && hdlp != NULL && hdlp->ih_dip != NULL) {
		if (get_intr_affinity(
		    (ddi_intr_handle_t)hdlp, &cpu_id) != DDI_SUCCESS) {
			cpu_id = (processorid_t)-1;
		}
	} else {
		cpu_id = (processorid_t)-1;
	}

	saved_ino = partial_iget.ino;
	bzero(iget, PCITOOL_IGET_SIZE(num_devs_ret));
	iget->ino = saved_ino;
	iget->cpu_id = (uint32_t)cpu_id;
	iget->num_devs = (uint8_t)num_devs;
	iget->num_devs_ret = (uint8_t)MIN(num_devs_ret, num_devs);

	/* Fill in device information for each handler */
	for (i = 0; i < iget->num_devs_ret; i++) {
		pcitool_get_intr_dev_info(dip_list[i], &iget->dev[i]);
	}

	if (num_devs_ret > 0) {
		ndi_devi_exit(dip);
	}

	if (dip_list != NULL) {
		kmem_free(dip_list, num_devs_ret * sizeof (dev_info_t *));
	}

	iget->drvr_version = PCITOOL_VERSION;
	copyout_rval = ddi_copyout(iget, arg,
	    PCITOOL_IGET_SIZE(num_devs_ret), mode);

	if (iget_kmem_alloc_size > 0) {
		kmem_free(iget, iget_kmem_alloc_size);
	}

	if (copyout_rval != DDI_SUCCESS) {
		rval = EFAULT;
	}

	return (rval);
}

/*
 * PCITOOL_SYSTEM_INTR_INFO: return interrupt controller type and
 * configuration.
 *
 * num_intr is set to MAX_VECT, the autovect hash table size.  This
 * bounds pcitool's brute-force 0..num_intr-1 iteration.  A future
 * ioctl will provide proper active-vector enumeration.
 */
static int
pcitool_intr_info(dev_info_t *dip, void *arg, int mode)
{
	pcitool_intr_info_t intr_info;
	int rval = SUCCESS;

	if (ddi_copyin(arg, &intr_info, sizeof (pcitool_intr_info_t),
	    mode) != DDI_SUCCESS) {
		return (EFAULT);
	}

	intr_info.ctlr_type = PCITOOL_CTLR_TYPE_GIC;
	intr_info.ctlr_version = 0;
	intr_info.num_intr = 1020;	/* maximum SPI, for now */
	intr_info.num_cpu = ncpus;
	intr_info.drvr_version = PCITOOL_VERSION;

	if (ddi_copyout(&intr_info, arg, sizeof (pcitool_intr_info_t),
	    mode) != DDI_SUCCESS) {
		rval = EFAULT;
	}

	return (rval);
}

/*
 * Main function for handling interrupt CPU binding requests and queries
 * from pcitool(8) and intrd(8).
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
