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
 * Copyright 2024 Michael van der Westhuizen
 */

/*
 * Virtio MMIO Nexus
 *
 * This nexus provides hardware discovery functionality for VirtIO MMIO devices
 * as presented by FDT systems with a compatible attribute of `virtio,mmio' and
 * ACPI systems with a _HID attribute of `LNRO0005'.  The nexus uses properties
 * from the corresponding driver.conf(5) to map VirtIO device IDs to a driver
 * and compatible string, then creates a child node per that information,
 * allowing the kernel to attach the correct driver.
 *
 * The nexus unconditionally sets the `virtio-is-mmio' property, instructing
 * the virtio library module to use the MMIO transport.
 */

#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/ddi_implfuncs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>
#include "virtio.h"
#include "virtio_impl.h"

static int viommionex_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result);
static int viommionex_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int viommionex_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static int viommionex_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg);

static struct bus_ops viommionex_bus_ops = {
	.busops_rev		= BUSO_REV,
	.bus_map		= i_ddi_bus_map,
	.bus_get_intrspec	= NULL, /* obsolete */
	.bus_add_intrspec	= NULL, /* obsolete */
	.bus_remove_intrspec	= NULL, /* obsolete */
	.bus_map_fault		= i_ddi_map_fault,
	.bus_dma_map		= NULL,
	.bus_dma_allochdl	= ddi_dma_allochdl,
	.bus_dma_freehdl	= ddi_dma_freehdl,
	.bus_dma_bindhdl	= ddi_dma_bindhdl,
	.bus_dma_unbindhdl	= ddi_dma_unbindhdl,
	.bus_dma_flush		= ddi_dma_flush,
	.bus_dma_win		= ddi_dma_win,
	.bus_dma_ctl		= ddi_dma_mctl,
	.bus_ctl		= viommionex_ctlops,
	.bus_prop_op		= ddi_bus_prop_op,
	.bus_get_eventcookie	= NULL,
	.bus_add_eventcall	= NULL,
	.bus_remove_eventcall	= NULL,
	.bus_post_event		= NULL,
	.bus_intr_ctl		= NULL,
	.bus_config		= viommionex_bus_config,
	.bus_unconfig		= viommionex_bus_unconfig,
	.bus_fm_init		= NULL,
	.bus_fm_fini		= NULL,
	.bus_fm_access_enter	= NULL,
	.bus_fm_access_exit	= NULL,
	.bus_power		= NULL,
	.bus_intr_op		= i_ddi_intr_ops,
	.bus_hp_op		= NULL
};

static struct dev_ops viommionex_ops = {
	.devo_rev		= DEVO_REV,
	.devo_refcnt		= 0,
	.devo_getinfo		= ddi_no_info,
	.devo_identify		= nulldev,
	.devo_probe		= nulldev,
	.devo_attach		= viommionex_attach,
	.devo_detach		= nulldev,
	.devo_reset		= nodev,
	.devo_cb_ops		= NULL,
	.devo_bus_ops		= &viommionex_bus_ops,
	.devo_power		= NULL,
	.devo_quiesce		= ddi_quiesce_not_needed,
};

static struct modldrv viommionex_modldrv = {
	.drv_modops		= &mod_driverops,
	.drv_linkinfo		= "VIRTIO MMIO nexus driver",
	.drv_dev_ops		= &viommionex_ops
};

static struct modlinkage modlinkage = {
	.ml_rev			= MODREV_1,
	.ml_linkage		= { &viommionex_modldrv, NULL }
};

int
_init(void)
{
	int	err;

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);

	return (0);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Nexus implementation
 */

static int
viommionex_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	int	ret;

	switch (ctlop) {
	case DDI_CTLOPS_INITCHILD:
		ret = impl_ddi_sunbus_initchild((dev_info_t *)arg);
		break;
	case DDI_CTLOPS_UNINITCHILD:
		impl_ddi_sunbus_removechild((dev_info_t *)arg);
		ret = DDI_SUCCESS;
		break;
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?%s%d at %s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ret = DDI_SUCCESS;
		break;
	default:
		ret = ddi_ctlops(dip, rdip, ctlop, arg, result);
		break;
	}

	return (ret);
}

static int
viommionex_probe_driver(dev_info_t *dip, char **driver, char **compat)
{
	virtio_t	*vio;
	uint32_t	devid;
	char		propname[32];

	if ((vio = virtio_init(dip, 0, B_FALSE)) == NULL)
		return (DDI_FAILURE);

	/*
	 * virtio_init asserts that the VMM has presented a v1 device to us and
	 * that the magic value is correct, so no need to check that here.
	 */
	devid = virtio_get32(vio, VIRTIO_MMIO_DEVICE_ID);
	virtio_fini(vio, B_FALSE);

	if (devid == 0)
		return (DDI_FAILURE);

	(void) snprintf(propname, sizeof (propname) - 1,
	    "device-%u-name", devid);
	propname[sizeof (propname) - 1] = '\0';
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    propname, driver) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);
	if (strlen(*driver) == 0) {
		ddi_prop_free(*driver);
		return (DDI_FAILURE);
	}

	(void) snprintf(propname, sizeof (propname) - 1,
	    "device-%u-compat", devid);
	propname[sizeof (propname) - 1] = '\0';
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    propname, compat) != DDI_PROP_SUCCESS) {
		ddi_prop_free(*driver);
		return (DDI_FAILURE);
	}
	if (strlen(*compat) == 0) {
		ddi_prop_free(*compat);
		ddi_prop_free(*driver);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
viommionex_bus_config(dev_info_t *dip, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	dev_info_t	*rdip;
	char		*driver;
	char		*compat;
	char		*compatible[1];

	rdip = NULL;

	/*
	 * We can only ever have one child, so CONFIG_ALL, CONFIG_DRIVER, and
	 * CONFIG_ONE are all the same operation.
	 */
	if (((op != BUS_CONFIG_ALL) && (op != BUS_CONFIG_DRIVER) &&
	    (op != BUS_CONFIG_ONE)) || ddi_get_child(dip) != NULL) {
		return (ndi_busop_bus_config(dip, flags, op, arg, childp, 0));
	}

	if (viommionex_probe_driver(dip, &driver, &compat) != DDI_SUCCESS)
		return (DDI_FAILURE);

	ndi_devi_enter(dip);
	ndi_devi_alloc_sleep(dip, driver, (pnode_t)DEVI_SID_NODEID, &rdip);
	ddi_prop_free(driver);

	compatible[0] = (char *)compat;
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, rdip,
	    "compatible", compatible, 1) != DDI_PROP_SUCCESS) {
		ddi_prop_free(compat);
		(void) ndi_devi_offline(rdip, NDI_DEVI_REMOVE);
		ndi_devi_exit(dip);
		return (DDI_FAILURE);
	}
	ddi_prop_free(compat);

	/*
	 * Copy the "reg" and "interrupts" properties, so we appear as a
	 * sufficiently normal device for the 1275 interrupt mapping
	 * algorithm.
	 */
	int *reg;
	uint_t reg_cells;
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_REG, &reg, &reg_cells) == DDI_SUCCESS) {
		if (ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip,
		    OBP_REG, reg, reg_cells) != DDI_PROP_SUCCESS) {
			(void) ndi_devi_offline(rdip, NDI_DEVI_REMOVE);
			ddi_prop_free(reg);
			ndi_devi_exit(dip);
			return (DDI_FAILURE);
		}
	}
	ddi_prop_free(reg);

	int *intr;
	uint_t intr_cells;
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_INTERRUPTS, &intr, &intr_cells) == DDI_SUCCESS) {
		if (ndi_prop_update_int_array(DDI_DEV_T_NONE, rdip,
		    OBP_INTERRUPTS, intr, intr_cells) != DDI_PROP_SUCCESS) {
			(void) ndi_devi_offline(rdip, NDI_DEVI_REMOVE);
			ddi_prop_free(intr);
			ndi_devi_exit(dip);
			return (DDI_FAILURE);
		}
	}
	ddi_prop_free(intr);

	if (ndi_devi_bind_driver(rdip, 0) != NDI_SUCCESS) {
		(void) ndi_devi_offline(rdip, NDI_DEVI_REMOVE);
		ndi_devi_exit(dip);
		return (DDI_FAILURE);
	}

	ndi_devi_exit(dip);
	return (ndi_busop_bus_config(dip,
	    flags | NDI_ONLINE_ATTACH, op, arg, childp, 0));
}

static int
viommionex_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	/*
	 * The NDI_UNCONFIG flag allows the reference count on this nexus to be
	 * decremented when children's drivers are unloaded, enabling the nexus
	 * itself to be unloaded.
	 */
	return (ndi_busop_bus_unconfig(parent, flags | NDI_UNCONFIG, op, arg));
}

static int
viommionex_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    VIRTIO_MMIO_PROPERTY_NAME, 1) != DDI_PROP_SUCCESS) {
		dev_err(dip, CE_WARN, "?failed to set the '%s' property",
		    VIRTIO_MMIO_PROPERTY_NAME);
		return (DDI_FAILURE);
	}

	if (cmd == DDI_ATTACH)
		ddi_report_dev(dip);

	return (DDI_SUCCESS);
}
