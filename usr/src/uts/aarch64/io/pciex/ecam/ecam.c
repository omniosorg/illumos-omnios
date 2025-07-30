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
 * Copyright 2025 Richard Lowe
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/pci_cfgacc.h>
#include <sys/pcie.h>
#include <sys/pcie_impl.h>

#include <pcierc.h>

typedef struct {
	dev_info_t *ec_dip;
	ddi_acc_handle_t ec_handle;
	caddr_t ec_base;
} ecam_softc_t;

static void *ecam_soft_state;

static void
ecam_cfgspace_acc(pci_cfgacc_req_t *req)
{
	ecam_softc_t *softc;
	int bus, dev, func, reg;

	bus = PCI_CFGACC_BUS(req);
	dev = PCI_CFGACC_DEV(req);
	func = PCI_CFGACC_FUNC(req);
	reg = req->offset;

	softc = ddi_get_soft_state(ecam_soft_state,
	    ddi_get_instance(req->rcdip));

	VERIFY3P(softc, !=, NULL);

	if (!pcie_cfgspace_access_check(bus, dev, func, reg, req->size)) {
		if (!req->write)
			VAL64(req) = PCI_EINVAL64;
		return;
	}

	caddr_t addr = softc->ec_base + PCIE_CADDR_ECAM(bus, dev, func, reg);

	switch (req->size) {
	case PCI_CFG_SIZE_BYTE:
		if (req->write) {
			ddi_put8(softc->ec_handle, (uint8_t *)addr, VAL8(req));
		} else {
			VAL16(req) = ddi_get8(softc->ec_handle,
			    (uint8_t *)addr);
		}
		break;
	case PCI_CFG_SIZE_WORD:
		if (req->write) {
			ddi_put16(softc->ec_handle, (uint16_t *)addr,
			    VAL16(req));
		} else {
			VAL16(req) = ddi_get16(softc->ec_handle,
			    (uint16_t *)addr);
		}
		break;
	case PCI_CFG_SIZE_DWORD:
		if (req->write) {
			ddi_put32(softc->ec_handle, (uint32_t *)addr,
			    VAL32(req));
		} else {
			VAL32(req) = ddi_get32(softc->ec_handle,
			    (uint32_t *)addr);
		}
		break;
	case PCI_CFG_SIZE_QWORD:
		if (req->write) {
			ddi_put64(softc->ec_handle, (uint64_t *)addr,
			    VAL64(req));
		} else {
			VAL64(req) = ddi_get64(softc->ec_handle,
			    (uint64_t *)addr);
		}
		break;
	default:
		dev_err(softc->ec_dip, CE_PANIC,
		    "weird %d bit config space access", req->size * NBBY);
	}
}

pcie_rc_data_t ecam_pcie_rc_data = {
	.pcie_rc_cfgspace_acc = ecam_cfgspace_acc,
};

static int
ecam_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ecam_softc_t *softc = NULL;
	int ret;

	if (cmd == DDI_RESUME)
		return (DDI_SUCCESS);

	int instance = ddi_get_instance(dip);

	if ((ret = ddi_soft_state_zalloc(ecam_soft_state, instance)) !=
	    DDI_SUCCESS) {
		return (ret);
	}

	softc = ddi_get_soft_state(ecam_soft_state, instance);
	VERIFY3P(softc, !=, NULL);

	const ddi_device_acc_attr_t attr = {
		.devacc_attr_version = DDI_DEVICE_ATTR_V1,
		.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder = DDI_STRICTORDER_ACC,
		.devacc_attr_access = DDI_DEFAULT_ACC,
	};

	if ((ret = ddi_regs_map_setup(dip, 0, &softc->ec_base,
	    0, 0, &attr, &softc->ec_handle)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to map configuration space: %d",
		    ret);
		return (ret);
	}

	ndi_set_bus_private(dip, B_TRUE, DEVI_PORT_TYPE_PCIRC,
	    &ecam_pcie_rc_data);

	VERIFY3U(softc->ec_base, !=, 0);

	softc->ec_dip = dip;

	if ((ret = pcierc_attach(dip, cmd)) != DDI_SUCCESS) {
		return (ret);
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
ecam_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int ret;

	if (cmd != DDI_DETACH)
		return (DDI_SUCCESS);

	ecam_softc_t *softc = ddi_get_soft_state(ecam_soft_state,
	    ddi_get_instance(dip));

	VERIFY3P(softc, !=, NULL);

	if ((ret = pcierc_detach(dip, cmd)) != DDI_SUCCESS) {
		return (ret);
	}

	ddi_regs_map_free(&softc->ec_handle);
	ddi_soft_state_free(ecam_soft_state,
	    ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

static int
ecam_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int instance = ddi_get_instance(dip);
	ecam_softc_t *softc = ddi_get_soft_state(ecam_soft_state,
	    instance);

	VERIFY3P(softc, !=, NULL);

	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2DEVINFO:
		if (softc == NULL) {
			return (DDI_FAILURE);
		}
		*result = softc->ec_dip;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static struct bus_ops ecam_bus_ops = {
	.busops_rev = BUSO_REV,
	.bus_map = pcierc_bus_map,
	.bus_map_fault = i_ddi_map_fault,
	.bus_dma_allochdl = ddi_dma_allochdl,
	.bus_dma_freehdl = ddi_dma_freehdl,
	.bus_dma_bindhdl = ddi_dma_bindhdl,
	.bus_dma_unbindhdl = ddi_dma_unbindhdl,
	.bus_dma_flush = ddi_dma_flush,
	.bus_dma_win = ddi_dma_win,
	.bus_dma_ctl = ddi_dma_mctl,
	.bus_ctl = pcierc_ctlops,
	.bus_prop_op = ddi_bus_prop_op,
	.bus_get_eventcookie = pcierc_bus_get_eventcookie,
	.bus_add_eventcall = pcierc_bus_add_eventcall,
	.bus_remove_eventcall = pcierc_bus_remove_eventcall,
	.bus_post_event = pcierc_bus_post_event,
	.bus_config = pcierc_bus_config,
	.bus_fm_init = pcierc_fm_init,
	.bus_intr_op = pcierc_intr_ops,
	.bus_hp_op = pcie_hp_common_ops,
};

static struct cb_ops ecam_cb_ops = {
	.cb_open = pcierc_open,
	.cb_close = pcierc_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = pcierc_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = pcie_prop_op,
	.cb_flag = D_NEW | D_MP | D_HOTPLUG,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev,
};

static struct dev_ops ecam_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = ecam_info,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ecam_attach,
	.devo_detach = ecam_detach,
	.devo_reset = nodev,
	.devo_cb_ops = &ecam_cb_ops,
	.devo_bus_ops = &ecam_bus_ops,
	.devo_quiesce = ddi_quiesce_not_needed,
};

static struct modldrv ecam_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Generic ECAM PCIe",
	.drv_dev_ops = &ecam_ops,
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ecam_modldrv, NULL }
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&ecam_soft_state,
	    sizeof (ecam_softc_t), 1)) != DDI_SUCCESS) {
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ecam_soft_state);
		return (err);
	}

	return (DDI_SUCCESS);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != DDI_SUCCESS) {
		return (err);
	}

	ddi_soft_state_fini(&ecam_soft_state);
	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
