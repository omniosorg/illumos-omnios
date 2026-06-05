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
 * Copyright 2022 Oxide Computer Company
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 *	File that has code which is common between pci(4D) and pcierc(4D)
 *	It shares the following:
 *	- interrupt code
 *	- pci_tools ioctl code
 *	- name_child code
 *	- set_parent_private_data code
 */

#include <sys/conf.h>
#include <sys/pci.h>
#include <sys/sunndi.h>
#include <sys/pci_intr_lib.h>
#include <sys/policy.h>
#include <sys/sysmacros.h>
#include <sys/pci_tools.h>
#include <io/pci/pci_tools_ext.h>
#include <io/pci/pci_common.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_impl.h>
#include <sys/pci_cap.h>
#include <sys/obpdefs.h>
#include <sys/plat/pci_prd.h>
#include <sys/ddi_subrdefs.h>
#include <sys/avintr.h>
#include <sys/mach_intr.h>

/*
 * Function prototypes
 */
static uint8_t	pci_config_rd8(ddi_acc_impl_t *hdlp, uint8_t *addr);
static uint16_t	pci_config_rd16(ddi_acc_impl_t *hdlp, uint16_t *addr);
static uint32_t	pci_config_rd32(ddi_acc_impl_t *hdlp, uint32_t *addr);
static uint64_t	pci_config_rd64(ddi_acc_impl_t *hdlp, uint64_t *addr);

static void	pci_config_wr8(ddi_acc_impl_t *hdlp, uint8_t *addr,
		    uint8_t value);
static void	pci_config_wr16(ddi_acc_impl_t *hdlp, uint16_t *addr,
		    uint16_t value);
static void	pci_config_wr32(ddi_acc_impl_t *hdlp, uint32_t *addr,
		    uint32_t value);
static void	pci_config_wr64(ddi_acc_impl_t *hdlp, uint64_t *addr,
		    uint64_t value);

static void	pci_config_rep_wr8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
		    uint8_t *dev_addr, size_t repcount, uint_t flags);
static void	pci_config_rep_wr16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
		    uint16_t *dev_addr, size_t repcount, uint_t flags);
static void	pci_config_rep_wr32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
		    uint32_t *dev_addr, size_t repcount, uint_t flags);
static void	pci_config_rep_wr64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
		    uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * pci_name_child:
 *
 *	Assign the address portion of the node name
 */
int
pci_common_name_child(dev_info_t *child, char *name, int namelen)
{
	int		dev, func, length;
	char		**unit_addr;
	uint_t		n;
	pci_regspec_t	*pci_rp;
	pci_prd_compat_flags_t flags = pci_prd_compat_flags();

	if (ndi_dev_is_persistent_node(child) == 0) {
		/*
		 * For .conf node, use "unit-address" property
		 */
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, OBP_UNIT_ADDRESS, &unit_addr, &n) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "cannot find unit-address in %s.conf",
			    ddi_get_name(child));
			return (DDI_FAILURE);
		}
		if (n != 1 || *unit_addr == NULL || **unit_addr == 0) {
			cmn_err(CE_WARN, "unit-address property in %s.conf"
			    " not well-formed", ddi_get_name(child));
			ddi_prop_free(unit_addr);
			return (DDI_FAILURE);
		}
		(void) snprintf(name, namelen, "%s", *unit_addr);
		ddi_prop_free(unit_addr);
		return (DDI_SUCCESS);
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    OBP_REG, (int **)&pci_rp, (uint_t *)&length) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "cannot find reg property in %s",
		    ddi_get_name(child));
		return (DDI_FAILURE);
	}

	/* copy the device identifications */
	dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);

	if ((func != 0) || (flags & PCI_PRD_COMPAT_1275)) {
		(void) snprintf(name, namelen, "%x,%x", dev, func);
	} else {
		(void) snprintf(name, namelen, "%x", dev);
	}

	return (DDI_SUCCESS);
}

/*
 * Interrupt related code:
 *
 * The following busop is common to pcierc and pci drivers
 *	bus_introp
 */

/*
 * Create the ddi_parent_private_data for a pseudo child.
 */
void
pci_common_set_parent_private_data(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;

	pdptr = (struct ddi_parent_private_data *)kmem_zalloc(
	    (sizeof (struct ddi_parent_private_data)), KM_SLEEP);
	ddi_set_parent_data(dip, pdptr);
}

#if XXXARM			/* Used only for MSIs */
static int pcieb_intr_pri_counter = 0;
#endif

/*
 * Configure a device for FIXED interrupts.
 *
 * When firmware leaves a device configured for MSI/MSI-X but the driver
 * requests FIXED, we need to clear the MSI/MSI-X enable bits in the PCI
 * capability structures so that FIXED interrupts will flow.
 */
static int
pci_fixed_enable_mode(dev_info_t *rdip, ddi_intr_handle_impl_t *hdlp)
{
	ddi_acc_handle_t	handle;
	ushort_t		cap_ctrl;
	uint16_t		cap_base;
	int			ret;

	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	if ((ret = pci_config_setup(rdip, &handle)) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT,
		    "?pci_fixed_enable_mode: %s%d: "
		    "pci_config_setup failed: %d\n",
		    ddi_driver_name(rdip),
		    ddi_get_instance(rdip),
		    ret));
		return (ret);
	}

	if (PCI_CAP_LOCATE(handle, PCI_CAP_ID_MSI, &cap_base) == DDI_SUCCESS) {
		cap_ctrl = PCI_CAP_GET16(handle, 0, cap_base, PCI_MSI_CTRL);
		if (cap_ctrl == PCI_CAP_EINVAL16) {
			ret = DDI_FAILURE;
			goto out;
		}

		if (cap_ctrl & PCI_MSI_ENABLE_BIT) {
			DDI_INTR_NEXDBG((CE_CONT,
			    "?pci_fixed_enable_mode: %s%d: "
			    "clearing MSI enable\n",
			    ddi_driver_name(rdip),
			    ddi_get_instance(rdip)));
			cap_ctrl &= ~PCI_MSI_ENABLE_BIT;
			PCI_CAP_PUT16(handle, 0, cap_base,
			    PCI_MSI_CTRL, cap_ctrl);
		}
	}

	if (PCI_CAP_LOCATE(handle, PCI_CAP_ID_MSI_X, &cap_base)
	    == DDI_SUCCESS) {
		cap_ctrl = PCI_CAP_GET16(handle, 0, cap_base, PCI_MSIX_CTRL);
		if (cap_ctrl == PCI_CAP_EINVAL16) {
			ret = DDI_FAILURE;
			goto out;
		}

		if (cap_ctrl & PCI_MSIX_ENABLE_BIT) {
			DDI_INTR_NEXDBG((CE_CONT,
			    "?pci_fixed_enable_mode: %s%d: "
			    "clearing MSIX enable\n",
			    ddi_driver_name(rdip),
			    ddi_get_instance(rdip)));
			cap_ctrl &= ~PCI_MSIX_ENABLE_BIT;
			PCI_CAP_PUT16(handle, 0, cap_base,
			    PCI_MSIX_CTRL, cap_ctrl);
		}
	}

out:
	pci_config_teardown(&handle);
	return (ret);
}

/*
 * Per-operation helper functions for pci_common_intr_ops.
 */

static int
pci_intr_supported_types(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	int			device_caps;
	int			platform_types;
	uint16_t		msi_cap_base;
	uint16_t		msix_cap_base;
	uint16_t		cap_ctrl;
	ddi_acc_handle_t	handle;

	/*
	 * Step 1: Determine what the PCI device supports by examining its
	 * config space capabilities and device tree properties.
	 *
	 * Only include FIXED if the device has both a non-zero interrupt
	 * pin in config space (PCI_CONF_IPIN) and an "interrupts" property
	 * in the device tree.  The pin register tells us the hardware
	 * supports INTx; the property tells us firmware has described the
	 * routing.  Without both, the FIXED path through map_interrupt
	 * cannot succeed.
	 */
	device_caps = 0;

	if (pci_config_setup(rdip, &handle) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (pci_config_get8(handle, PCI_CONF_IPIN) != 0 &&
	    ddi_prop_exists(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, OBP_INTERRUPTS)) {
		device_caps |= DDI_INTR_TYPE_FIXED;
	}

	if (PCI_CAP_LOCATE(handle, PCI_CAP_ID_MSI, &msi_cap_base) ==
	    DDI_SUCCESS) {
		cap_ctrl = PCI_CAP_GET16(handle, 0, msi_cap_base, PCI_MSI_CTRL);
		if (cap_ctrl != PCI_CAP_EINVAL16) {
			device_caps |= DDI_INTR_TYPE_MSI;
		}
	}

	if (PCI_CAP_LOCATE(handle, PCI_CAP_ID_MSI_X,
	    &msix_cap_base) == DDI_SUCCESS) {
		cap_ctrl = PCI_CAP_GET16(handle, 0, msix_cap_base,
		    PCI_MSIX_CTRL);
		if (cap_ctrl != PCI_CAP_EINVAL16) {
			device_caps |= DDI_INTR_TYPE_MSIX;
		}
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_supported_types: "
	    "rdip: 0x%p device caps: 0x%x\n", (void *)rdip,
	    device_caps));

	/* Export MSI/MSI-X cap locations via properties */
	if (device_caps & DDI_INTR_TYPE_MSI) {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
		    "pci-msi-capid-pointer", (int)msi_cap_base) !=
		    DDI_PROP_SUCCESS) {
			pci_config_teardown(&handle);
			return (DDI_FAILURE);
		}
	}

	if (device_caps & DDI_INTR_TYPE_MSIX) {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, rdip,
		    "pci-msix-capid-pointer", (int)msix_cap_base) !=
		    DDI_PROP_SUCCESS) {
			pci_config_teardown(&handle);
			return (DDI_FAILURE);
		}
	}

	pci_config_teardown(&handle);

	/*
	 * Step 2: Ask the tree what the platform supports.
	 *
	 * This should always return DDI_INTR_TYPE_FIXED.
	 */
	platform_types = 0;
	(void) i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, &platform_types);

	/*
	 * Step 3: If the device has MSI/MSI-X caps, ask the MSI controller
	 * what it supports and augment the platform capabilities accordingly.
	 */
	if (device_caps & (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX)) {
		int msi_types = 0;
		if (i_ddi_msi_supported_types(pdip, rdip, hdlp,
		    &msi_types) == DDI_SUCCESS) {
			platform_types |= msi_types;
		}
	}

	/*
	 * Step 4: Intersect device capabilities with platform support to
	 * produce the final supported set.
	 */
	*(int *)result = device_caps & platform_types;

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_supported_types: "
	    "rdip: 0x%p supported types: 0x%x\n", (void *)rdip,
	    *(int *)result));

	return (DDI_SUCCESS);
}

static int
pci_intr_navail_nintrs(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	int nintrs;

	if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type)) {
		/*
		 * NINTRS: the device's PCI capability count.
		 * NAVAIL: min(device capability, controller free count).
		 *
		 * For MSI, NAVAIL is an upper bound: MSI vectors require
		 * a power-of-2 aligned contiguous block in the SPI/LPI
		 * space, so a fragmented arena may not be able to satisfy
		 * the full count even if enough total free IDs exist.
		 * ddi_intr_alloc handles partial allocation.
		 *
		 * For MSI-X, vectors are individually allocated so the
		 * free count is accurate (though racy - these sorts of
		 * checks are fraught with TOCTOU behaviour by design).
		 */
		if (pci_msi_get_nintrs(hdlp->ih_dip, hdlp->ih_type,
		    &nintrs) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		if (intr_op == DDI_INTROP_NAVAIL) {
			int navail;

			if (i_ddi_intr_ops(pdip, rdip, DDI_INTROP_NAVAIL,
			    hdlp, &navail) == DDI_SUCCESS) {
				nintrs = MIN(nintrs, navail);
			}
		}

		*(int *)result = nintrs;
		return (DDI_SUCCESS);
	} else {
		/* FIXED: just go up the tree */
		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	}
}

static int
pci_intr_alloc_msi(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int			cap_ptr;
	ddi_acc_handle_t	handle;
	int			rv;
	boolean_t		did_alloc_phdl = B_FALSE;

	if (i_ddi_get_pci_config_handle(rdip) == NULL) {
		if (pci_config_setup(rdip, &handle) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		i_ddi_set_pci_config_handle(rdip, handle);
	}

	cap_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "pci-msi-capid-pointer", 0);
	if (cap_ptr == 0) {
		DDI_INTR_NEXDBG((CE_CONT,
		    "pci_intr_alloc_msi: rdip: 0x%p "
		    "attempted MSI alloc without "
		    "cap property\n", (void *)rdip));
		return (DDI_FAILURE);
	}
	i_ddi_set_msi_msix_cap_ptr(rdip, cap_ptr);

	/*
	 * Hand off the rest of the allocation work to the interrupt controller.
	 */
	if (hdlp->ih_private == NULL) {
		i_ddi_alloc_intr_phdl(hdlp);
		did_alloc_phdl = B_TRUE;
	}

	rv = i_ddi_intr_ops(pdip, rdip, DDI_INTROP_ALLOC, hdlp, result);

	if (did_alloc_phdl) {
		i_ddi_free_intr_phdl(hdlp);
		hdlp->ih_private = NULL;
	}

	return (rv);
}

static int
pci_intr_alloc_msix(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int			cap_ptr;
	ddi_acc_handle_t	handle;
	ddi_intr_msix_t		*msix_p;
	int			rv;
	boolean_t		did_alloc_phdl = B_FALSE;

	if (i_ddi_get_pci_config_handle(rdip) == NULL) {
		if (pci_config_setup(rdip, &handle) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		i_ddi_set_pci_config_handle(rdip, handle);
	}

	cap_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "pci-msix-capid-pointer", 0);
	if (cap_ptr == 0) {
		DDI_INTR_NEXDBG((CE_CONT,
		    "pci_intr_alloc_msix: rdip: 0x%p "
		    "attempted MSI-X alloc without "
		    "cap property\n", (void *)rdip));
		return (DDI_FAILURE);
	}
	i_ddi_set_msi_msix_cap_ptr(rdip, cap_ptr);

	if (i_ddi_get_msix(hdlp->ih_dip) == NULL) {
		msix_p = pci_msix_init(hdlp->ih_dip);
		if (msix_p != NULL) {
			i_ddi_set_msix(hdlp->ih_dip, msix_p);
		} else {
			DDI_INTR_NEXDBG((CE_CONT,
			    "pci_intr_alloc_msix: MSI-X "
			    "table init failed, "
			    "rdip 0x%p\n", (void *)rdip));
			return (DDI_FAILURE);
		}
	}

	/*
	 * Hand off the rest of the allocation work to the interrupt controller.
	 */
	if (hdlp->ih_private == NULL) {
		i_ddi_alloc_intr_phdl(hdlp);
		did_alloc_phdl = B_TRUE;
	}

	rv = i_ddi_intr_ops(pdip, rdip, DDI_INTROP_ALLOC, hdlp, result);

	if (did_alloc_phdl) {
		i_ddi_free_intr_phdl(hdlp);
		hdlp->ih_private = NULL;
	}

	return (rv);
}

static int
pci_intr_alloc(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
		return (pci_intr_alloc_msi(pdip, rdip, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSIX) {
		return (pci_intr_alloc_msix(pdip, rdip, hdlp, result));
	}

	return (DDI_FAILURE);
}

static int
pci_intr_free(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	ddi_acc_handle_t	handle;
	ddi_intr_msix_t		*msix_p;

	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
		/*
		 * Tear down config handle on the last free.
		 */
		if (i_ddi_intr_get_current_nintrs(hdlp->ih_dip) - 1 == 0) {
			if ((handle = i_ddi_get_pci_config_handle(
			    rdip)) != NULL) {
				(void) pci_config_teardown(&handle);
				i_ddi_set_pci_config_handle(rdip, NULL);
			}
			i_ddi_set_msi_msix_cap_ptr(rdip, 0);
		}

		/* Route to MSI controller */
		return (i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_FREE, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSIX) {
		/*
		 * Tear down config handle and MSI-X table on
		 * the last free.
		 */
		if (i_ddi_intr_get_current_nintrs(hdlp->ih_dip)
		    - 1 == 0) {
			if ((handle = i_ddi_get_pci_config_handle(
			    rdip)) != NULL) {
				(void) pci_config_teardown(&handle);
				i_ddi_set_pci_config_handle(rdip, NULL);
			}
			i_ddi_set_msi_msix_cap_ptr(rdip, 0);

			msix_p = i_ddi_get_msix(hdlp->ih_dip);
			if (msix_p != NULL) {
				pci_msix_fini(msix_p);
				i_ddi_set_msix(hdlp->ih_dip, NULL);
			}
		}

		/* Route to MSI controller */
		return (i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_FREE, hdlp, result));
	}

	return (DDI_FAILURE);
}

static int
pci_intr_enable_msi(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	ihdl_plat_t	*ihdl_p = (ihdl_plat_t *)hdlp->ih_private;
	int		nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_enable_msi: "
	    "ENABLE MSI type = 0x%x, inum = 0x%x, "
	    "nintrs = %d for %s%d\n",
	    hdlp->ih_type, hdlp->ih_inum, nintrs,
	    ddi_driver_name(rdip), ddi_get_instance(rdip)));

	/*
	 * First, enable the interrupt in the MSI controller.  This sets
	 * ip_msi_addr and ip_msi_data on the handle.
	 */
	if (i_ddi_intr_ops(pdip, rdip,
	    DDI_INTROP_ENABLE, hdlp, result) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_enable_msi: "
	    "ENABLE: calling pci_msi_configure with "
	    "addr = 0x%" PRIx64 ", data = 0x%" PRIx32
	    ", count = %d, inum = 0x%x\n",
	    ihdl_p->ip_msi_addr, ihdl_p->ip_msi_data,
	    nintrs, hdlp->ih_inum));

	/*
	 * Program PCI MSI registers with the address and data
	 * values provided by the MSI controller.
	 */
	if (pci_msi_configure(rdip, hdlp->ih_type, nintrs, hdlp->ih_inum,
	    ihdl_p->ip_msi_addr, ihdl_p->ip_msi_data) != DDI_SUCCESS) {
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_DISABLE, hdlp, result);
		return (DDI_FAILURE);
	}

	/* Enable MSI in PCI config space */
	if (pci_msi_enable_mode(rdip, hdlp->ih_type) != DDI_SUCCESS) {
		(void) pci_msi_set_mask(rdip, hdlp->ih_type, hdlp->ih_inum);
		(void) pci_msi_unconfigure(rdip, hdlp->ih_type, hdlp->ih_inum);
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_DISABLE, hdlp, result);
		return (DDI_FAILURE);
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_enable_msi: "
	    "ENABLE: MSI fully enabled for %s%d inum 0x%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    hdlp->ih_inum));

	return (DDI_SUCCESS);
}

static int
pci_intr_enable_msix(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	ihdl_plat_t	*ihdl_p = (ihdl_plat_t *)hdlp->ih_private;
	int		nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_enable_msix: "
	    "ENABLE MSI-X type = 0x%x, inum = 0x%x, "
	    "nintrs = %d for %s%d\n",
	    hdlp->ih_type, hdlp->ih_inum, nintrs,
	    ddi_driver_name(rdip), ddi_get_instance(rdip)));

	/*
	 * First, enable the interrupt in the MSI
	 * controller.  This sets ip_msi_addr and
	 * ip_msi_data on the handle.
	 */
	if (i_ddi_intr_ops(pdip, rdip, DDI_INTROP_ENABLE,
	    hdlp, result) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_enable_msix: "
	    "ENABLE: calling pci_msi_configure with "
	    "addr = 0x%" PRIx64 ", data = 0x%" PRIx32
	    ", count = %d, inum = 0x%x\n",
	    ihdl_p->ip_msi_addr, ihdl_p->ip_msi_data,
	    nintrs, hdlp->ih_inum));

	/*
	 * Program PCI MSI-X registers with the address and data values
	 * provided by the MSI controller.
	 */
	if (pci_msi_configure(rdip, hdlp->ih_type, nintrs, hdlp->ih_inum,
	    ihdl_p->ip_msi_addr, ihdl_p->ip_msi_data) != DDI_SUCCESS) {
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_DISABLE, hdlp, result);
		return (DDI_FAILURE);
	}

	/* For MSI-X, clear the mask bit for this entry */
	pci_msi_clr_mask(rdip, hdlp->ih_type, hdlp->ih_inum);

	/* Enable MSI-X in PCI config space */
	if (pci_msi_enable_mode(rdip, hdlp->ih_type) != DDI_SUCCESS) {
		(void) pci_msi_set_mask(rdip, hdlp->ih_type, hdlp->ih_inum);
		(void) pci_msi_unconfigure(rdip, hdlp->ih_type, hdlp->ih_inum);
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_DISABLE, hdlp, result);
		return (DDI_FAILURE);
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_enable_msix: "
	    "ENABLE: MSI-X fully enabled for %s%d inum 0x%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    hdlp->ih_inum));

	return (DDI_SUCCESS);
}

static int
pci_intr_enable(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		if (pci_fixed_enable_mode(rdip, hdlp) != DDI_SUCCESS) {
			dev_err(rdip, CE_WARN,
			    "failed to configure interrupt type");
			return (DDI_FAILURE);
		}

		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
		return (pci_intr_enable_msi(pdip, rdip, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSIX) {
		return (pci_intr_enable_msix(pdip, rdip, hdlp, result));
	}

	return (DDI_FAILURE);
}

static int
pci_intr_blockenable_msi(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int		nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);
	ihdl_plat_t	*ihdl_p;

	/*
	 * Block enable: let the MSI controller enable all vectors, then
	 * program PCI registers and enable MSI mode.
	 *
	 * MSI: there is a single shared capability register set
	 * (addr/data/MME), so we program it once after all vectors are enabled
	 * using vector 0's addr/data.
	 */
	if (i_ddi_intr_ops(pdip, rdip, DDI_INTROP_BLOCKENABLE,
	    hdlp, result) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Program the shared PCI MSI capability registers once using vector 0's
	 * address and base data value.
	 *
	 * hdlp is h_array[0], so ih_private has vector 0's plat data.
	 */
	ihdl_p = (ihdl_plat_t *)hdlp->ih_private;

	if (pci_msi_configure(rdip, hdlp->ih_type, nintrs, 0,
	    ihdl_p->ip_msi_addr, ihdl_p->ip_msi_data) != DDI_SUCCESS) {
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_BLOCKDISABLE, hdlp, result);
		return (DDI_FAILURE);
	}

	if (pci_msi_enable_mode(rdip, hdlp->ih_type) != DDI_SUCCESS) {
		(void) pci_msi_unconfigure(rdip, hdlp->ih_type, 0);
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_BLOCKDISABLE, hdlp, result);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
pci_intr_blockenable_msix(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int			nintrs;
	ddi_intr_handle_impl_t	**h_array;

	nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);
	h_array = (ddi_intr_handle_impl_t **)hdlp->ih_scratch2;

	/*
	 * Block enable: let the MSI controller enable all vectors, then
	 * program PCI registers and enable MSI-X mode.
	 *
	 * MSI-X: each vector has its own table entry, so we configure and
	 * unmask per-vector after the controller has populated the
	 * address/data for each handle.
	 */
	if (i_ddi_intr_ops(pdip, rdip, DDI_INTROP_BLOCKENABLE,
	    hdlp, result) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Program PCI MSI-X table entries per-vector.  Each handle in the
	 * array has its ip_msi_addr/ip_msi_data populated by the MSI
	 * controller's BLOCKENABLE.
	 */
	for (int i = 0; i < nintrs; i++) {
		ihdl_plat_t *ihdl_p = (ihdl_plat_t *)h_array[i]->ih_private;

		if (pci_msi_configure(rdip, hdlp->ih_type, nintrs, i,
		    ihdl_p->ip_msi_addr, ihdl_p->ip_msi_data) != DDI_SUCCESS) {
			for (int j = i - 1; j >= 0; j--) {
				(void) pci_msi_unconfigure(rdip,
				    hdlp->ih_type, j);
			}
			(void) i_ddi_intr_ops(pdip, rdip,
			    DDI_INTROP_BLOCKDISABLE, hdlp, result);
			return (DDI_FAILURE);
		}
		pci_msi_clr_mask(rdip, hdlp->ih_type, i);
	}

	if (pci_msi_enable_mode(rdip, hdlp->ih_type) != DDI_SUCCESS) {
		for (int j = nintrs - 1; j >= 0; j--) {
			(void) pci_msi_unconfigure(rdip,
			    hdlp->ih_type, j);
		}
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_BLOCKDISABLE, hdlp, result);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
pci_intr_blockenable(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		return (DDI_ENOTSUP);
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
		return (pci_intr_blockenable_msi(pdip, rdip, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSIX) {
		return (pci_intr_blockenable_msix(pdip, rdip, hdlp, result));
	}

	return (DDI_FAILURE);
}

static int
pci_intr_disable(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
		/* Disable in MSI controller first */
		if (i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_DISABLE, hdlp, result) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		/*
		 * For MSI, the address and data registers are shared across
		 * all vectors.  Only unconfigure and disable MSI mode when
		 * this is the last enabled vector.  We check nenables (not
		 * nintrs) because vectors may be allocated but not all enabled.
		 *
		 * The caller decrements nenables after we return success, so
		 * a value of 1 here means this is the last one.
		 */
		if (i_ddi_intr_get_current_nenables(hdlp->ih_dip) - 1 == 0) {
			(void) pci_msi_unconfigure(rdip,
			    hdlp->ih_type, hdlp->ih_inum);
			(void) pci_msi_disable_mode(rdip, hdlp->ih_type);
		}

		return (DDI_SUCCESS);
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSIX) {
		/* Disable in MSI controller first */
		if (i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_DISABLE, hdlp, result) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		/* For MSI-X, set the mask bit */
		pci_msi_set_mask(rdip, hdlp->ih_type, hdlp->ih_inum);

		/*
		 * For MSI-X, each vector has its own table entry and can be
		 * unconfigured independently.
		 */
		(void) pci_msi_unconfigure(rdip, hdlp->ih_type, hdlp->ih_inum);

		/*
		 * Disable MSI-X mode if this is the last enabled interrupt.
		 */
		if (i_ddi_intr_get_current_nenables(hdlp->ih_dip) - 1 == 0) {
			(void) pci_msi_disable_mode(rdip, hdlp->ih_type);
		}

		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
pci_intr_blockdisable(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		return (DDI_ENOTSUP);
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
		int nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);

		/*
		 * Disable MSI mode first so the device stops generating
		 * interrupts, then let the MSI controller disable all vectors,
		 * and unconfigure PCI registers.
		 */
		(void) pci_msi_disable_mode(rdip, hdlp->ih_type);
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_BLOCKDISABLE, hdlp, result);

		for (int i = 0; i < nintrs; i++) {
			(void) pci_msi_unconfigure(rdip, hdlp->ih_type, i);
		}

		return (DDI_SUCCESS);
	} else if (hdlp->ih_type == DDI_INTR_TYPE_MSIX) {
		int nintrs = i_ddi_intr_get_current_nintrs(hdlp->ih_dip);

		/*
		 * Disable MSI-X mode first so the device stops generating
		 * interrupts, then let the MSI controller disable all vectors.
		 * Mask and unconfigure each PCI MSI-X table entry.
		 */
		(void) pci_msi_disable_mode(rdip, hdlp->ih_type);
		(void) i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_BLOCKDISABLE, hdlp, result);

		for (int i = 0; i < nintrs; i++) {
			pci_msi_set_mask(rdip, hdlp->ih_type, i);
			(void) pci_msi_unconfigure(rdip, hdlp->ih_type, i);
		}

		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*
 * GETPRI for FIXED
 *
 * If the FIXED interrupt is shared, then just return the priority of the
 * existing shared interrupt (all sharers must use the same priority).
 *
 * Grab the controller priority via the tree - if this is a non-default
 * priority, use it.  This allows driver.conf overrides of interrupt priorities
 * to work for PCI/PCIe devices.
 *
 * PCI has a better set of defaults than FIXED (class-based), so if the
 * controller returned a default priority, then use the class-based priority.
 */
static int
pci_intr_fixed_getpri(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	uint_t ctlr_pri;
	uint_t shared_pri;
	int class_pri;
	int rv;

	if (av_get_shared(hdlp->ih_vector, &shared_pri) > 0) {
		hdlp->ih_pri = shared_pri;
		*(uint_t *)result = shared_pri;

		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_fixed_getpri: "
		    "shared, hdlp = 0x%p, vector = 0x%x, priority = 0x%x\n",
		    hdlp, hdlp->ih_vector, shared_pri));
		return (DDI_SUCCESS);
	}

	if ((rv = i_ddi_intr_ops(pdip, rdip, DDI_INTROP_GETPRI,
	    hdlp, &ctlr_pri)) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_fixed_getpri: "
		    "hdlp = 0x%p, vector = 0x%x, upcall failed, rv = 0x%x\n",
		    hdlp, hdlp->ih_vector, rv));
		return (rv);
	}

	if (ctlr_pri != 5) {
		hdlp->ih_pri = ctlr_pri;
		*(uint_t *)result = ctlr_pri;

		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_fixed_getpri: "
		    "unshared, hdlp = 0x%p, vector = 0x%x, priority = 0x%x\n",
		    hdlp, hdlp->ih_vector, ctlr_pri));
		return (DDI_SUCCESS);
	}

	if ((class_pri = pci_class_to_pil(rdip)) <= 0) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_fixed_getpri: "
		    "unshared, hdlp = 0x%p, vector = 0x%x, "
		    "pci_class_to_pil failed, using controller "
		    "priority = 0x%x\n",
		    hdlp, hdlp->ih_vector, ctlr_pri));
		class_pri = (int)ctlr_pri;
	}

	hdlp->ih_pri = (uint_t)class_pri;
	*(uint_t *)result = (uint_t)class_pri;

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_fixed_getpri: "
	    "unshared, hdlp = 0x%p, vector = 0x%x, priority = 0x%x\n",
	    hdlp, hdlp->ih_vector, class_pri));
	return (DDI_SUCCESS);
}

static int
pci_intr_getpri(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int class_pri;
	uint_t shared_pri;

	if (!DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type)) {
		return (pci_intr_fixed_getpri(pdip, rdip, hdlp, result));
	}

	if ((class_pri = pci_class_to_pil(rdip)) <= 0) {
		class_pri = 5;
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_getpri: hdlp = 0x%p, "
		    "vector = 0x%x, failed to get pil from class, "
		    "default = 0x%x\n",
		    hdlp, hdlp->ih_vector, class_pri));
	}

	if (av_get_shared(hdlp->ih_vector, &shared_pri) > 0) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_getpri: hdlp = 0x%p, "
		    "vector = 0x%x, MSI/MSI-X is shared, using existing "
		    "priority = 0x%x\n",
		    hdlp, hdlp->ih_vector, shared_pri));
		class_pri = (int)shared_pri;
	}

	if (class_pri < 1 || class_pri >= 15) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_getpri: hdlp = 0x%p, "
		    "vector = 0x%x, class priority 0x%x out of range, "
		    "default = 0x%x\n",
		    hdlp, hdlp->ih_vector, class_pri, 5));
		class_pri = 5;
	}

	hdlp->ih_pri = (uint_t)class_pri;
	*(uint_t *)result = (uint_t)class_pri;

	DDI_INTR_NEXDBG((CE_CONT, "pci_intr_getpri: hdlp = 0x%p, "
	    "vector = 0x%x, priority = 0x%x\n",
	    hdlp, hdlp->ih_vector, class_pri));
	return (DDI_SUCCESS);
}

static int
pci_intr_addisr(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	ihdl_plat_t *ihdl_plat_datap;

	ASSERT3P(hdlp->ih_private, !=, NULL);
	ihdl_plat_datap = (ihdl_plat_t *)hdlp->ih_private;
	pci_kstat_create(&ihdl_plat_datap->ip_ksp, pdip, hdlp);
	return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
}

static int
pci_intr_remisr(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	ihdl_plat_t *ihdl_plat_datap;
	int ret;

	ret = i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result);

	ASSERT3P(hdlp->ih_private, !=, NULL);
	ihdl_plat_datap = (ihdl_plat_t *)hdlp->ih_private;

	if (ihdl_plat_datap->ip_ksp != NULL) {
		pci_kstat_delete(ihdl_plat_datap->ip_ksp);
	}

	return (ret);
}

static int
pci_intr_getcap(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	int rv;

	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		/*
		 * Get PCI-side capabilities from config space.
		 *
		 * pci_intx_get_cap returns LEVEL always, plus MASKABLE and
		 * PENDING if the device supports PCI v2.3+ INTx disable.
		 */
		if ((rv = pci_intx_get_cap(
		    rdip, (int *)result)) != DDI_SUCCESS) {
			return (rv);
		}

		/*
		 * Chain to the interrupt controller so it can add its own
		 * capabilities (PENDING, trigger modes) and clear any it
		 * does not support.
		 */
		if ((rv = i_ddi_intr_ops(pdip, rdip,
		    intr_op, hdlp, result)) != DDI_SUCCESS) {
			return (rv);
		}

		/*
		 * PCI INTx is always level-triggered.  The controller may
		 * honestly report EDGE|LEVEL, but EDGE is not valid
		 * for INTx, so clear it.
		 */
		*(int *)result &= ~DDI_INTR_FLAG_EDGE;
		return (DDI_SUCCESS);
	} else if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type)) {
		if ((rv = pci_msi_get_cap(rdip, hdlp->ih_type, (int *)result))
		    != DDI_SUCCESS) {
			return (rv);
		}

		/* Let the MSI controller filter/augment */
		return (i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_GETCAP, hdlp, result));
	}

	return (DDI_FAILURE);
}

static int
pci_intr_setmask_clrmask(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp)
{
	int	pci_status;

	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		int caps = 0;

		/*
		 * Try PCI config space first (PCI 2.3+ Command Register
		 * bit 10 INTx disable).
		 */
		if (intr_op == DDI_INTROP_SETMASK) {
			pci_status = pci_intx_set_mask(rdip);
		} else {
			pci_status = pci_intx_clr_mask(rdip);
		}

		if (pci_status == DDI_SUCCESS) {
			return (DDI_SUCCESS);
		}

		/*
		 * Device doesn't support PCI-level masking.
		 *
		 * Fall back to the interrupt controller iff it advertises
		 * masking capability.
		 */
		if (i_ddi_intr_ops(pdip, rdip, DDI_INTROP_GETCAP,
		    hdlp, (void *)&caps) == DDI_SUCCESS &&
		    (caps & DDI_INTR_FLAG_MASKABLE)) {
			return (i_ddi_intr_ops(pdip, rdip,
			    intr_op, hdlp, NULL));
		}

		return (DDI_FAILURE);
	} else if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type)) {
		if (intr_op == DDI_INTROP_SETMASK) {
			pci_status = pci_msi_set_mask(rdip,
			    hdlp->ih_type, hdlp->ih_inum);
		} else {
			pci_status = pci_msi_clr_mask(rdip,
			    hdlp->ih_type, hdlp->ih_inum);
		}

		return (pci_status);
	}

	return (DDI_FAILURE);
}

static int
pci_intr_getpending(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int	pci_rval;
	int	pci_status = 0;
	int	ctrl_status = 0;

	if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type)) {
		/*
		 * For MSI/MSI-X, query the MSI controller.
		 *
		 * The controller reads the hardware pending state.
		 */
		return (i_ddi_intr_ops(pdip, rdip,
		    DDI_INTROP_GETPENDING, hdlp, result));
	}

	if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
		/*
		 * Belt-and-braces: check both the PCI device and the
		 * interrupt controller.  PCI config space (Status register
		 * Interrupt Status bit) tells us whether the device is
		 * asserting INTx.  The GIC's ISPENDR tells us whether the
		 * SPI is pending at the controller.  Either source means
		 * the interrupt is pending.
		 *
		 * Both reads are inherently racy - the device can
		 * assert/deassert at any time, so this is a best-effort
		 * snapshot.
		 */
		pci_rval = pci_intx_get_pending(rdip, &pci_status);
		if (pci_rval != DDI_SUCCESS) {
			pci_status = 0;
		}

		(void) i_ddi_intr_ops(pdip, rdip, DDI_INTROP_GETPENDING,
		    hdlp, (void *)&ctrl_status);

		*(int *)result = pci_status | ctrl_status;
		DDI_INTR_NEXDBG((CE_CONT, "pci: GETPENDING returned = %x "
		    "(pci %x, ctlr %x)\n",
		    *(int *)result, pci_status, ctrl_status));
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*
 * pci_common_intr_ops: bus_intr_op() function for interrupt support
 *
 * This switch gets very large when implementations are embedded into the
 * case handlers - prefer to dispatch to discrete processing functions for
 * readability.
 */
int
pci_common_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	DDI_INTR_NEXDBG((CE_CONT,
	    "pci_common_intr_ops: pdip 0x%p (%s), rdip 0x%p (%s), "
	    "op %x handle 0x%p\n",
	    (void *)pdip, ddi_node_name(pdip), (void *)rdip,
	    ddi_node_name(rdip), intr_op, (void *)hdlp));

	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	/* Process the request */
	switch (intr_op) {
	case DDI_INTROP_SUPPORTED_TYPES:
		return (pci_intr_supported_types(pdip, rdip, intr_op,
		    hdlp, result));
	case DDI_INTROP_NAVAIL:	/* fallthrough */
	case DDI_INTROP_NINTRS:
		return (pci_intr_navail_nintrs(pdip, rdip, intr_op,
		    hdlp, result));
	case DDI_INTROP_ALLOC:
		return (pci_intr_alloc(pdip, rdip, intr_op, hdlp, result));
	case DDI_INTROP_FREE:
		return (pci_intr_free(pdip, rdip, intr_op, hdlp, result));
	case DDI_INTROP_ENABLE:
		return (pci_intr_enable(pdip, rdip, intr_op, hdlp, result));
	case DDI_INTROP_BLOCKENABLE:
		return (pci_intr_blockenable(pdip, rdip, intr_op,
		    hdlp, result));
	case DDI_INTROP_DISABLE:
		return (pci_intr_disable(pdip, rdip, intr_op, hdlp, result));
	case DDI_INTROP_BLOCKDISABLE:
		return (pci_intr_blockdisable(pdip, rdip, intr_op,
		    hdlp, result));
	case DDI_INTROP_GETPRI:
		return (pci_intr_getpri(pdip, rdip, hdlp, result));
	case DDI_INTROP_ADDISR:
		return (pci_intr_addisr(pdip, rdip, intr_op, hdlp, result));
	case DDI_INTROP_REMISR:
		return (pci_intr_remisr(pdip, rdip, intr_op, hdlp, result));
	case DDI_INTROP_GETCAP:
		return (pci_intr_getcap(pdip, rdip, intr_op, hdlp, result));
	case DDI_INTROP_SETMASK:	/* fallthrough */
	case DDI_INTROP_CLRMASK:
		return (pci_intr_setmask_clrmask(pdip, rdip, intr_op, hdlp));
	case DDI_INTROP_GETPENDING:
		return (pci_intr_getpending(pdip, rdip, hdlp, result));
	case DDI_INTROP_GETPOOL:
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
			return (DDI_ENOTSUP);
		}

		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	case DDI_INTROP_DUPVEC:
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED ||
		    hdlp->ih_type == DDI_INTR_TYPE_MSI) {
			return (DDI_ENOTSUP);
		}

		return (pci_msix_dup(hdlp->ih_dip, hdlp->ih_inum,
		    hdlp->ih_scratch1));
	default:
		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	}
}

/*
 * Miscellaneous library function
 */
int
pci_common_get_reg_prop(dev_info_t *dip, pci_regspec_t *pci_rp)
{
	int		i;
	int		number;
	int		assigned_addr_len;
	uint_t		phys_hi = pci_rp->pci_phys_hi;
	pci_regspec_t	*assigned_addr;

	if (((phys_hi & PCI_REG_ADDR_M) == PCI_ADDR_CONFIG) ||
	    (phys_hi & PCI_RELOCAT_B))
		return (DDI_SUCCESS);

	/*
	 * the "reg" property specifies relocatable, get and interpret the
	 * "assigned-addresses" property.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (int **)&assigned_addr,
	    (uint_t *)&assigned_addr_len) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Scan the "assigned-addresses" for one that matches the specified
	 * "reg" property entry.
	 */
	phys_hi &= PCI_CONF_ADDR_MASK;
	number = assigned_addr_len / (sizeof (pci_regspec_t) / sizeof (int));
	for (i = 0; i < number; i++) {
		if ((assigned_addr[i].pci_phys_hi & PCI_CONF_ADDR_MASK) ==
		    phys_hi) {
			/*
			 * When the system does not manage to allocate PCI
			 * resources for a device, then the value that is stored
			 * in assigned addresses ends up being the hardware
			 * default reset value of '0'. On currently supported
			 * platforms, physical address zero is associated with
			 * memory; however, on other platforms this may be the
			 * exception vector table (ARM), etc. and so we opt to
			 * generally keep the idea in PCI that the reset value
			 * will not be used for actual MMIO allocations. If such
			 * a platform comes around where it is worth using that
			 * bit of MMIO for PCI then we should make this check
			 * platform-specific.
			 *
			 * Note, the +1 in the print statement is because a
			 * given regs[0] describes B/D/F information for the
			 * device.
			 */
			if (assigned_addr[i].pci_phys_mid == 0 &&
			    assigned_addr[i].pci_phys_low == 0) {
				dev_err(dip, CE_WARN, "regs[%u] does not have "
				    "a valid MMIO address", i + 1);
				goto err;
			}

			pci_rp->pci_phys_mid = assigned_addr[i].pci_phys_mid;
			pci_rp->pci_phys_low = assigned_addr[i].pci_phys_low;
			ddi_prop_free(assigned_addr);
			return (DDI_SUCCESS);
		}
	}

err:
	ddi_prop_free(assigned_addr);
	return (DDI_FAILURE);
}


/*
 * To handle PCI tool ioctls
 */

/*ARGSUSED*/
int
pci_common_ioctl(dev_info_t *dip, dev_t dev, int cmd, intptr_t arg,
    int mode, cred_t *credp, int *rvalp)
{
	minor_t	minor = getminor(dev);
	int	rv = ENOTTY;

	switch (PCI_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:
		switch (cmd) {
		case PCITOOL_DEVICE_SET_REG:
		case PCITOOL_DEVICE_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pcitool_dev_reg_ops(dip, (void *)arg,
				    cmd, mode);
			break;

		case PCITOOL_NEXUS_SET_REG:
		case PCITOOL_NEXUS_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pcitool_bus_reg_ops(dip, (void *)arg,
				    cmd, mode);
			break;
		}
		break;

	case PCI_TOOL_INTR_MINOR_NUM:
		switch (cmd) {
		case PCITOOL_DEVICE_SET_INTR:

			/* Require PRIV_SYS_RES_CONFIG, same as psradm */
			if (secpolicy_ponline(credp)) {
				rv = EPERM;
				break;
			}

		/*FALLTHRU*/
		/* These require no special privileges. */
		case PCITOOL_DEVICE_GET_INTR:
		case PCITOOL_SYSTEM_INTR_INFO:
			rv = pcitool_intr_admn(dip, (void *)arg, cmd, mode);
			break;
		}
		break;

	default:
		break;
	}

	return (rv);
}


int
pci_common_ctlops_poke(peekpoke_ctlops_t *in_args)
{
	size_t size = in_args->size;
	uintptr_t dev_addr = in_args->dev_addr;
	uintptr_t host_addr = in_args->host_addr;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;
	ddi_acc_hdl_t *hdlp = (ddi_acc_hdl_t *)in_args->handle;
	size_t repcount = in_args->repcount;
	uint_t flags = in_args->flags;
	int err = DDI_SUCCESS;

	/*
	 * if no handle then this is a poke. We have to return failure here
	 * as we have no way of knowing whether this is a MEM or IO space access
	 */
	if (in_args->handle == NULL)
		return (DDI_FAILURE);

	/*
	 * rest of this function is actually for cautious puts
	 */
	for (; repcount; repcount--) {
		if (hp->ahi_acc_attr == DDI_ACCATTR_CONFIG_SPACE) {
			switch (size) {
			case sizeof (uint8_t):
				pci_config_wr8(hp, (uint8_t *)dev_addr,
				    *(uint8_t *)host_addr);
				break;
			case sizeof (uint16_t):
				pci_config_wr16(hp, (uint16_t *)dev_addr,
				    *(uint16_t *)host_addr);
				break;
			case sizeof (uint32_t):
				pci_config_wr32(hp, (uint32_t *)dev_addr,
				    *(uint32_t *)host_addr);
				break;
			case sizeof (uint64_t):
				pci_config_wr64(hp, (uint64_t *)dev_addr,
				    *(uint64_t *)host_addr);
				break;
			default:
				err = DDI_FAILURE;
				break;
			}
		} else if (hp->ahi_acc_attr & DDI_ACCATTR_IO_SPACE) {
			if (hdlp->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {
				switch (size) {
				case sizeof (uint8_t):
					i_ddi_io_put8(hp,
					    (uint8_t *)dev_addr,
					    *(uint8_t *)host_addr);
					break;
				case sizeof (uint16_t):
					i_ddi_io_swap_put16(hp,
					    (uint16_t *)dev_addr,
					    *(uint16_t *)host_addr);
					break;
				case sizeof (uint32_t):
					i_ddi_io_swap_put32(hp,
					    (uint32_t *)dev_addr,
					    *(uint32_t *)host_addr);
					break;
				/*
				 * note the 64-bit case is a dummy
				 * function - so no need to swap
				 */
				case sizeof (uint64_t):
					i_ddi_io_put64(hp,
					    (uint64_t *)dev_addr,
					    *(uint64_t *)host_addr);
					break;
				default:
					err = DDI_FAILURE;
					break;
				}
			} else {
				switch (size) {
				case sizeof (uint8_t):
					i_ddi_io_put8(hp,
					    (uint8_t *)dev_addr,
					    *(uint8_t *)host_addr);
					break;
				case sizeof (uint16_t):
					i_ddi_io_put16(hp,
					    (uint16_t *)dev_addr,
					    *(uint16_t *)host_addr);
					break;
				case sizeof (uint32_t):
					i_ddi_io_put32(hp,
					    (uint32_t *)dev_addr,
					    *(uint32_t *)host_addr);
					break;
				case sizeof (uint64_t):
					i_ddi_io_put64(hp,
					    (uint64_t *)dev_addr,
					    *(uint64_t *)host_addr);
					break;
				default:
					err = DDI_FAILURE;
					break;
				}
			}
		} else {
			if (hdlp->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {
				switch (size) {
				case sizeof (uint8_t):
					*(uint8_t *)dev_addr =
					    *(uint8_t *)host_addr;
					break;
				case sizeof (uint16_t):
					*(uint16_t *)dev_addr =
					    ddi_swap16(*(uint16_t *)host_addr);
					break;
				case sizeof (uint32_t):
					*(uint32_t *)dev_addr =
					    ddi_swap32(*(uint32_t *)host_addr);
					break;
				case sizeof (uint64_t):
					*(uint64_t *)dev_addr =
					    ddi_swap64(*(uint64_t *)host_addr);
					break;
				default:
					err = DDI_FAILURE;
					break;
				}
			} else {
				switch (size) {
				case sizeof (uint8_t):
					*(uint8_t *)dev_addr =
					    *(uint8_t *)host_addr;
					break;
				case sizeof (uint16_t):
					*(uint16_t *)dev_addr =
					    *(uint16_t *)host_addr;
					break;
				case sizeof (uint32_t):
					*(uint32_t *)dev_addr =
					    *(uint32_t *)host_addr;
					break;
				case sizeof (uint64_t):
					*(uint64_t *)dev_addr =
					    *(uint64_t *)host_addr;
					break;
				default:
					err = DDI_FAILURE;
					break;
				}
			}
		}
		host_addr += size;
		if (flags == DDI_DEV_AUTOINCR)
			dev_addr += size;
	}
	return (err);
}


int
pci_fm_acc_setup(ddi_acc_hdl_t *hp, off_t offset, off_t len)
{
	ddi_acc_impl_t	*ap = (ddi_acc_impl_t *)hp->ah_platform_private;

	/* endian-ness check */
	if (hp->ah_acc.devacc_attr_endian_flags == DDI_STRUCTURE_BE_ACC)
		return (DDI_FAILURE);

	/*
	 * range check
	 */
	if ((offset >= PCI_CONF_HDR_SIZE) ||
	    (len > PCI_CONF_HDR_SIZE) ||
	    (offset + len > PCI_CONF_HDR_SIZE))
		return (DDI_FAILURE);

	ap->ahi_acc_attr |= DDI_ACCATTR_CONFIG_SPACE;
	/*
	 * always use cautious mechanism for config space gets
	 */
	ap->ahi_get8 = i_ddi_caut_get8;
	ap->ahi_get16 = i_ddi_caut_get16;
	ap->ahi_get32 = i_ddi_caut_get32;
	ap->ahi_get64 = i_ddi_caut_get64;
	ap->ahi_rep_get8 = i_ddi_caut_rep_get8;
	ap->ahi_rep_get16 = i_ddi_caut_rep_get16;
	ap->ahi_rep_get32 = i_ddi_caut_rep_get32;
	ap->ahi_rep_get64 = i_ddi_caut_rep_get64;
	if (hp->ah_acc.devacc_attr_access == DDI_CAUTIOUS_ACC) {
		ap->ahi_put8 = i_ddi_caut_put8;
		ap->ahi_put16 = i_ddi_caut_put16;
		ap->ahi_put32 = i_ddi_caut_put32;
		ap->ahi_put64 = i_ddi_caut_put64;
		ap->ahi_rep_put8 = i_ddi_caut_rep_put8;
		ap->ahi_rep_put16 = i_ddi_caut_rep_put16;
		ap->ahi_rep_put32 = i_ddi_caut_rep_put32;
		ap->ahi_rep_put64 = i_ddi_caut_rep_put64;
	} else {
		ap->ahi_put8 = pci_config_wr8;
		ap->ahi_put16 = pci_config_wr16;
		ap->ahi_put32 = pci_config_wr32;
		ap->ahi_put64 = pci_config_wr64;
		ap->ahi_rep_put8 = pci_config_rep_wr8;
		ap->ahi_rep_put16 = pci_config_rep_wr16;
		ap->ahi_rep_put32 = pci_config_rep_wr32;
		ap->ahi_rep_put64 = pci_config_rep_wr64;
	}

	/* Initialize to default check/notify functions */
	ap->ahi_fault_check = i_ddi_acc_fault_check;
	ap->ahi_fault_notify = i_ddi_acc_fault_notify;
	ap->ahi_fault = 0;
	impl_acc_err_init(hp);
	return (DDI_SUCCESS);
}


int
pci_common_ctlops_peek(peekpoke_ctlops_t *in_args)
{
	size_t size = in_args->size;
	uintptr_t dev_addr = in_args->dev_addr;
	uintptr_t host_addr = in_args->host_addr;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;
	ddi_acc_hdl_t *hdlp = (ddi_acc_hdl_t *)in_args->handle;
	size_t repcount = in_args->repcount;
	uint_t flags = in_args->flags;
	int err = DDI_SUCCESS;

	/*
	 * if no handle then this is a peek. We have to return failure here
	 * as we have no way of knowing whether this is a MEM or IO space access
	 */
	if (in_args->handle == NULL)
		return (DDI_FAILURE);

	for (; repcount; repcount--) {
		if (hp->ahi_acc_attr == DDI_ACCATTR_CONFIG_SPACE) {
			switch (size) {
			case sizeof (uint8_t):
				*(uint8_t *)host_addr = pci_config_rd8(hp,
				    (uint8_t *)dev_addr);
				break;
			case sizeof (uint16_t):
				*(uint16_t *)host_addr = pci_config_rd16(hp,
				    (uint16_t *)dev_addr);
				break;
			case sizeof (uint32_t):
				*(uint32_t *)host_addr = pci_config_rd32(hp,
				    (uint32_t *)dev_addr);
				break;
			case sizeof (uint64_t):
				*(uint64_t *)host_addr = pci_config_rd64(hp,
				    (uint64_t *)dev_addr);
				break;
			default:
				err = DDI_FAILURE;
				break;
			}
		} else if (hp->ahi_acc_attr & DDI_ACCATTR_IO_SPACE) {
			if (hdlp->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {
				switch (size) {
				case sizeof (uint8_t):
					*(uint8_t *)host_addr =
					    i_ddi_io_get8(hp,
					    (uint8_t *)dev_addr);
					break;
				case sizeof (uint16_t):
					*(uint16_t *)host_addr =
					    i_ddi_io_swap_get16(hp,
					    (uint16_t *)dev_addr);
					break;
				case sizeof (uint32_t):
					*(uint32_t *)host_addr =
					    i_ddi_io_swap_get32(hp,
					    (uint32_t *)dev_addr);
					break;
				/*
				 * note the 64-bit case is a dummy
				 * function - so no need to swap
				 */
				case sizeof (uint64_t):
					*(uint64_t *)host_addr =
					    i_ddi_io_get64(hp,
					    (uint64_t *)dev_addr);
					break;
				default:
					err = DDI_FAILURE;
					break;
				}
			} else {
				switch (size) {
				case sizeof (uint8_t):
					*(uint8_t *)host_addr =
					    i_ddi_io_get8(hp,
					    (uint8_t *)dev_addr);
					break;
				case sizeof (uint16_t):
					*(uint16_t *)host_addr =
					    i_ddi_io_get16(hp,
					    (uint16_t *)dev_addr);
					break;
				case sizeof (uint32_t):
					*(uint32_t *)host_addr =
					    i_ddi_io_get32(hp,
					    (uint32_t *)dev_addr);
					break;
				case sizeof (uint64_t):
					*(uint64_t *)host_addr =
					    i_ddi_io_get64(hp,
					    (uint64_t *)dev_addr);
					break;
				default:
					err = DDI_FAILURE;
					break;
				}
			}
		} else {
			if (hdlp->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {
				switch (in_args->size) {
				case sizeof (uint8_t):
					*(uint8_t *)host_addr =
					    *(uint8_t *)dev_addr;
					break;
				case sizeof (uint16_t):
					*(uint16_t *)host_addr =
					    ddi_swap16(*(uint16_t *)dev_addr);
					break;
				case sizeof (uint32_t):
					*(uint32_t *)host_addr =
					    ddi_swap32(*(uint32_t *)dev_addr);
					break;
				case sizeof (uint64_t):
					*(uint64_t *)host_addr =
					    ddi_swap64(*(uint64_t *)dev_addr);
					break;
				default:
					err = DDI_FAILURE;
					break;
				}
			} else {
				switch (in_args->size) {
				case sizeof (uint8_t):
					*(uint8_t *)host_addr =
					    *(uint8_t *)dev_addr;
					break;
				case sizeof (uint16_t):
					*(uint16_t *)host_addr =
					    *(uint16_t *)dev_addr;
					break;
				case sizeof (uint32_t):
					*(uint32_t *)host_addr =
					    *(uint32_t *)dev_addr;
					break;
				case sizeof (uint64_t):
					*(uint64_t *)host_addr =
					    *(uint64_t *)dev_addr;
					break;
				default:
					err = DDI_FAILURE;
					break;
				}
			}
		}
		host_addr += size;
		if (flags == DDI_DEV_AUTOINCR)
			dev_addr += size;
	}
	return (err);
}

/*ARGSUSED*/
int
pci_common_peekpoke(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	if (ctlop == DDI_CTLOPS_PEEK)
		return (pci_common_ctlops_peek((peekpoke_ctlops_t *)arg));
	else
		return (pci_common_ctlops_poke((peekpoke_ctlops_t *)arg));
}

/*
 * These are the get and put functions to be shared with drivers. The
 * mutex locking is done inside the functions referenced, rather than
 * here, and is thus shared across PCI child drivers and any other
 * consumers of PCI config space (such as the ACPI subsystem).
 *
 * The configuration space addresses come in as pointers.  This is fine on
 * a 32-bit system, where the VM space and configuration space are the same
 * size.  It's not such a good idea on a 64-bit system, where memory
 * addresses are twice as large as configuration space addresses.  At some
 * point in the call tree we need to take a stand and say "you are 32-bit
 * from this time forth", and this seems like a nice self-contained place.
 */

static uint8_t
pci_config_rd8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	pci_acc_cfblk_t *cfp;
	uint8_t	rval;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)hdlp->ahi_common.ah_bus_private;

	rval = pci_cfgacc_get8(cfp->c_rootdip,
	    PCI_GETBDF(cfp->c_busnum, cfp->c_devnum, cfp->c_funcnum),
	    reg);

	return (rval);
}

static uint16_t
pci_config_rd16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	pci_acc_cfblk_t *cfp;
	uint16_t rval;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)hdlp->ahi_common.ah_bus_private;

	rval = pci_cfgacc_get16(cfp->c_rootdip,
	    PCI_GETBDF(cfp->c_busnum, cfp->c_devnum, cfp->c_funcnum),
	    reg);

	return (rval);
}

static uint32_t
pci_config_rd32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	pci_acc_cfblk_t *cfp;
	uint32_t rval;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)hdlp->ahi_common.ah_bus_private;

	rval = pci_cfgacc_get32(cfp->c_rootdip,
	    PCI_GETBDF(cfp->c_busnum, cfp->c_devnum, cfp->c_funcnum),
	    reg);

	return (rval);
}

static void
pci_config_wr8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	pci_acc_cfblk_t *cfp;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)hdlp->ahi_common.ah_bus_private;

	pci_cfgacc_put8(cfp->c_rootdip,
	    PCI_GETBDF(cfp->c_busnum, cfp->c_devnum, cfp->c_funcnum),
	    reg, value);
}

static void
pci_config_rep_wr8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			pci_config_wr8(hdlp, d++, *h++);
	else
		for (; repcount; repcount--)
			pci_config_wr8(hdlp, d, *h++);
}

static void
pci_config_wr16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	pci_acc_cfblk_t *cfp;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)hdlp->ahi_common.ah_bus_private;

	pci_cfgacc_put16(cfp->c_rootdip,
	    PCI_GETBDF(cfp->c_busnum, cfp->c_devnum, cfp->c_funcnum),
	    reg, value);
}

static void
pci_config_rep_wr16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			pci_config_wr16(hdlp, d++, *h++);
	else
		for (; repcount; repcount--)
			pci_config_wr16(hdlp, d, *h++);
}

static void
pci_config_wr32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	pci_acc_cfblk_t *cfp;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)hdlp->ahi_common.ah_bus_private;

	pci_cfgacc_put32(cfp->c_rootdip,
	    PCI_GETBDF(cfp->c_busnum, cfp->c_devnum, cfp->c_funcnum),
	    reg, value);
}

void
pci_config_rep_wr32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			pci_config_wr32(hdlp, d++, *h++);
	else
		for (; repcount; repcount--)
			pci_config_wr32(hdlp, d, *h++);
}

static uint64_t
pci_config_rd64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint32_t lw_val;
	uint32_t hi_val;
	uint32_t *dp;
	uint64_t val;

	dp = (uint32_t *)addr;
	lw_val = pci_config_rd32(hdlp, dp);
	dp++;
	hi_val = pci_config_rd32(hdlp, dp);
	val = ((uint64_t)hi_val << 32) | lw_val;
	return (val);
}

static void
pci_config_wr64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	uint32_t lw_val;
	uint32_t hi_val;
	uint32_t *dp;

	dp = (uint32_t *)addr;
	lw_val = (uint32_t)(value & 0xffffffff);
	hi_val = (uint32_t)(value >> 32);
	pci_config_wr32(hdlp, dp, lw_val);
	dp++;
	pci_config_wr32(hdlp, dp, hi_val);
}

static void
pci_config_rep_wr64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			pci_config_wr64(hdlp, host_addr++, *dev_addr++);
	} else {
		for (; repcount; repcount--)
			pci_config_wr64(hdlp, host_addr++, *dev_addr);
	}
}
