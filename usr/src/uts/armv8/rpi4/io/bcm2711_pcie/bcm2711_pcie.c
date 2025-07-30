/*
 * Derived from:
 * $OpenBSD: bcm2711_pcie.c,v 1.13 2024/03/27 15:15:00 patrick Exp $
 *
 * Copyright (c) 2020 Mark Kettenis <kettenis@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2020 Dr Robert Harvey Crowston <crowston@protonmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */

/*
 * Copyright 2025 Richard Lowe
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
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

#define	BCM2711_REG_CONTROLLER_HW_REV	0x406c
#define	BCM2711_REG_BRIDGE_CTRL		0x9210
#define	BCM2711_BRIDGE_DISABLE_FLAG	0x1
#define	BCM2711_BRIDGE_RESET_FLAG	0x2
#define	BCM2711_REG_PCIE_HARD_DEBUG	0x4204
#define	BCM2711_REG_BRIDGE_STATE	0x4068
#define	BCM2711_REG_BRIDGE_LINK_STATE	0x00bc

/* (read/write) config space data */
#define	BCM2711_DEV_CFG_DATA		0x8000
/* (write) config space index  */
#define	BCM2711_DEV_CFG_INDEX		0x9000

#define	BCM2711_MAX_BUS			1

typedef struct {
	dev_info_t *bc_dip;
	ddi_acc_handle_t bc_handle;
	caddr_t bc_base;
	kmutex_t bc_lock;
} bcm2711_pcie_softc_t;

static void *bcm2711_pcie_soft_state;

static uint64_t
bcm2711_cfg_read_root(bcm2711_pcie_softc_t *softc, int bus, int dev, int func,
    int reg, size_t size)
{
	/*
	 * Requests to bus 0, the root complex, must also have device 0, per
	 * the BSD driver
	 */
	if (dev != 0)
		return (PCI_EINVAL64);

	switch (size) {
	case PCI_CFG_SIZE_BYTE:
		return (ddi_get8(softc->bc_handle,
		    (uint8_t *)(softc->bc_base + PCIE_CADDR_ECAM(bus, dev, func,
		    reg))));
	case PCI_CFG_SIZE_WORD:
		return (ddi_get16(softc->bc_handle,
		    (uint16_t *)(softc->bc_base + PCIE_CADDR_ECAM(bus, dev,
		    func, reg))));
	case PCI_CFG_SIZE_DWORD:
		return (ddi_get32(softc->bc_handle,
		    (uint32_t *)(softc->bc_base + PCIE_CADDR_ECAM(bus, dev,
		    func, reg))));
	case PCI_CFG_SIZE_QWORD:
		return (ddi_get64(softc->bc_handle,
		    (uint64_t *)(softc->bc_base + PCIE_CADDR_ECAM(bus, dev,
		    func, reg))));

	}

	dev_err(softc->bc_dip, CE_PANIC, "weird %ld bit config space access",
	    size * NBBY);
	/* Unreachable */
	return (PCI_EINVAL64);
}

static uint64_t
bcm2711_cfg_read_dev(bcm2711_pcie_softc_t *softc, int bus, int dev, int func,
    int reg, size_t size)
{
	VERIFY3S(bus, !=, 0);

	if (bus > BCM2711_MAX_BUS || dev != 0 || func != 0)
		return (PCI_EINVAL64);

	ddi_put32(softc->bc_handle,
	    (uint32_t *)(softc->bc_base + BCM2711_DEV_CFG_INDEX),
	    PCIE_CADDR_ECAM(bus, dev, func, 0));

	switch (size) {
	case PCI_CFG_SIZE_BYTE:
		return (ddi_get8(softc->bc_handle,
		    (uint8_t *)(softc->bc_base + BCM2711_DEV_CFG_DATA + reg)));
	case PCI_CFG_SIZE_WORD:
		return (ddi_get16(softc->bc_handle,
		    (uint16_t *)(softc->bc_base + BCM2711_DEV_CFG_DATA + reg)));
	case PCI_CFG_SIZE_DWORD:
		return (ddi_get32(softc->bc_handle,
		    (uint32_t *)(softc->bc_base + BCM2711_DEV_CFG_DATA + reg)));
	case PCI_CFG_SIZE_QWORD:
		return (ddi_get64(softc->bc_handle,
		    (uint64_t *)(softc->bc_base + BCM2711_DEV_CFG_DATA + reg)));
	}

	dev_err(softc->bc_dip, CE_PANIC, "weird %ld bit config space access",
	    size * NBBY);
	/* Unreachable */
	return (PCI_EINVAL64);
}

static uint64_t
bcm2711_cfg_read(dev_info_t *dip, int bus, int dev, int func, int reg,
    size_t size)
{
	bcm2711_pcie_softc_t *softc =
	    ddi_get_soft_state(bcm2711_pcie_soft_state, ddi_get_instance(dip));
	uint64_t ret = 0;

	mutex_enter(&softc->bc_lock);

	if (bus == 0) {
		ret = bcm2711_cfg_read_root(softc, bus, dev, func, reg, size);
	} else {
		ret = bcm2711_cfg_read_dev(softc, bus, dev, func, reg, size);
	}

	mutex_exit(&softc->bc_lock);

	return (ret);
}

static void
bcm2711_cfg_write_root(bcm2711_pcie_softc_t *softc, int bus, int dev, int func,
    int reg, size_t size, uint64_t val)
{
	/*
	 * Requests to bus 0, the root complex, must also have device 0, per
	 * the BSD driver
	 */
	if (dev != 0)
		return;

	switch (size) {
	case PCI_CFG_SIZE_BYTE:
		ddi_put8(softc->bc_handle, (uint8_t *)(softc->bc_base +
		    PCIE_CADDR_ECAM(bus, dev, func, reg)), val);
		break;
	case PCI_CFG_SIZE_WORD:
		ddi_put16(softc->bc_handle, (uint16_t *)(softc->bc_base +
		    PCIE_CADDR_ECAM(bus, dev, func, reg)), val);
		break;
	case PCI_CFG_SIZE_DWORD:
		ddi_put32(softc->bc_handle, (uint32_t *)(softc->bc_base +
		    PCIE_CADDR_ECAM(bus, dev, func, reg)), val);
		break;
	case PCI_CFG_SIZE_QWORD:
		ddi_put64(softc->bc_handle, (uint64_t *)(softc->bc_base +
		    PCIE_CADDR_ECAM(bus, dev, func, reg)), val);
		break;
	default:
		dev_err(softc->bc_dip, CE_PANIC,
		    "weird %ld bit config space access", size * NBBY);
	}
}

static void
bcm2711_cfg_write_dev(bcm2711_pcie_softc_t *softc, int bus, int dev, int func,
    int reg, size_t size, uint64_t val)
{
	VERIFY3S(bus, !=, 0);

	if (bus > BCM2711_MAX_BUS || dev != 0 || func != 0)
		return;

	ddi_put32(softc->bc_handle,
	    (uint32_t *)(softc->bc_base + BCM2711_DEV_CFG_INDEX),
	    PCIE_CADDR_ECAM(bus, dev, func, 0));

	switch (size) {
	case PCI_CFG_SIZE_BYTE:
		ddi_put8(softc->bc_handle,
		    (uint8_t *)(softc->bc_base + BCM2711_DEV_CFG_DATA + reg),
		    val);
		break;
	case PCI_CFG_SIZE_WORD:
		ddi_put16(softc->bc_handle,
		    (uint16_t *)(softc->bc_base + BCM2711_DEV_CFG_DATA + reg),
		    val);
		break;
	case PCI_CFG_SIZE_DWORD:
		ddi_put32(softc->bc_handle,
		    (uint32_t *)(softc->bc_base + BCM2711_DEV_CFG_DATA + reg),
		    val);
		break;
	case PCI_CFG_SIZE_QWORD:
		ddi_put64(softc->bc_handle,
		    (uint64_t *)(softc->bc_base + BCM2711_DEV_CFG_DATA + reg),
		    val);
		break;
	default:
		dev_err(softc->bc_dip, CE_PANIC,
		    "weird %ld bit config space access", size * NBBY);
	}
}

static void
bcm2711_cfg_write(dev_info_t *dip, int bus, int dev, int func, int reg,
    size_t size, uint64_t val)
{
	bcm2711_pcie_softc_t *softc =
	    ddi_get_soft_state(bcm2711_pcie_soft_state, ddi_get_instance(dip));

	mutex_enter(&softc->bc_lock);

	if (bus == 0) {
		bcm2711_cfg_write_root(softc, bus, dev, func, reg, size, val);
	} else {
		bcm2711_cfg_write_dev(softc, bus, dev, func, reg, size, val);
	}

	mutex_exit(&softc->bc_lock);
}

void
bcm2711_cfgspace_acc(pci_cfgacc_req_t *req)
{
	int bus, dev, func, reg;

	bus = PCI_CFGACC_BUS(req);
	dev = PCI_CFGACC_DEV(req);
	func = PCI_CFGACC_FUNC(req);
	reg = req->offset;

	if (!pcie_cfgspace_access_check(bus, dev, func, reg, req->size)) {
		if (!req->write)
			VAL64(req) = PCI_EINVAL64;
		return;
	}

	if (req->write) {
		bcm2711_cfg_write(req->rcdip, bus, dev, func, reg,
		    req->size, VAL64(req));
	} else {
		VAL64(req) = bcm2711_cfg_read(req->rcdip, bus, dev, func, reg,
		    req->size);
	}
}

static uint32_t
bcm2711_pcie_read_reg(const bcm2711_pcie_softc_t *softc, uint32_t reg)
{
	uint32_t val =
	    ddi_get32(softc->bc_handle, (uint32_t *)(softc->bc_base + reg));

	return (val);
}

static void
bcm2711_pcie_write_reg(const bcm2711_pcie_softc_t *softc, uint32_t reg,
    uint32_t val)
{
	ddi_put32(softc->bc_handle, (uint32_t *)(softc->bc_base + reg), val);
}

static void
bcm2711_pcie_reset_controller(const bcm2711_pcie_softc_t *softc)
{
	uint32_t val;

	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_BRIDGE_CTRL);
	val |= BCM2711_BRIDGE_DISABLE_FLAG | BCM2711_BRIDGE_RESET_FLAG;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_BRIDGE_CTRL, val);

	drv_usecwait(100);

	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_BRIDGE_CTRL);
	val &= ~BCM2711_BRIDGE_RESET_FLAG;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_BRIDGE_CTRL, val);

	drv_usecwait(100);

	bcm2711_pcie_write_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG, 0);

	drv_usecwait(100);
}

static void
bcm2711_pcie_enable_controller(const bcm2711_pcie_softc_t *softc)
{
	uint32_t val;

	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_BRIDGE_CTRL);
	val &= ~BCM2711_BRIDGE_DISABLE_FLAG;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_BRIDGE_CTRL, val);

	drv_usecwait(100);
}

pcie_rc_data_t bcm2711_pcie_rc_data = {
	.pcie_rc_cfgspace_acc = bcm2711_cfgspace_acc,
};

int
bcm2711_pcie_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	bcm2711_pcie_softc_t *softc = NULL;
	int ret;

	if (cmd == DDI_RESUME)
		return (DDI_SUCCESS);

	int instance = ddi_get_instance(dip);

	if ((ret = ddi_soft_state_zalloc(bcm2711_pcie_soft_state, instance)) !=
	    DDI_SUCCESS) {
		return (ret);
	}

	softc = ddi_get_soft_state(bcm2711_pcie_soft_state, instance);
	VERIFY3P(softc, !=, NULL);

	const ddi_device_acc_attr_t attr = {
		.devacc_attr_version = DDI_DEVICE_ATTR_V1,
		.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder = DDI_STRICTORDER_ACC,
		.devacc_attr_access = DDI_DEFAULT_ACC,
	};

	softc->bc_dip = dip;

	if ((ret = ddi_regs_map_setup(dip, 0, &softc->bc_base,
	    0, 0, &attr, &softc->bc_handle)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to map configuration space: %d",
		    ret);
		return (ret);
	}

	ndi_set_bus_private(dip, B_TRUE, DEVI_PORT_TYPE_PCIRC,
	    &bcm2711_pcie_rc_data);

	VERIFY3U(softc->bc_base, !=, 0);

	bcm2711_pcie_reset_controller(softc);

	uint32_t hw_rev = bcm2711_pcie_read_reg(softc,
	    BCM2711_REG_CONTROLLER_HW_REV) & 0xffff;

	dev_err(dip, CE_NOTE, "hardware revision: 0x%x.", hw_rev);

	bcm2711_pcie_enable_controller(softc);

	/*
	 * wait for controller startup
	 */
	for (uint_t i = 0; ; i++) {
		uint32_t bstate =
		    bcm2711_pcie_read_reg(softc, BCM2711_REG_BRIDGE_STATE);

		if ((bstate & 0x30) == 0x30)
			break;

		/*
		 * The controller failed to start in 100 ms
		 */
		if (i >= 100) {
			dev_err(dip, CE_WARN, "controller failed to start");
			return (DDI_FAILURE);
		}

		drv_usecwait(1000);
	}

	uint32_t link_state =
	    bcm2711_pcie_read_reg(softc, BCM2711_REG_BRIDGE_LINK_STATE) >> 0x10;

	if (link_state == 0) {
		dev_err(dip, CE_WARN, "controller started but link is not up");
		return (DDI_FAILURE);
	}

	/*
	 * XXXARM: do we need to set the CPU->PCI memory window?
	 */

	if ((ret = pcierc_attach(dip, cmd)) != DDI_SUCCESS) {
		return (ret);
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
bcm2711_pcie_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int ret;

	if (cmd != DDI_DETACH)
		return (DDI_SUCCESS);

	bcm2711_pcie_softc_t *softc =
	    ddi_get_soft_state(bcm2711_pcie_soft_state, ddi_get_instance(dip));

	VERIFY3P(softc, !=, NULL);

	if ((ret = pcierc_detach(dip, cmd)) != DDI_SUCCESS) {
		return (ret);
	}

	ddi_regs_map_free(&softc->bc_handle);
	ddi_soft_state_free(bcm2711_pcie_soft_state,
	    ddi_get_instance(dip));

	return (DDI_SUCCESS);
}


static int
bcm2711_pcie_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int instance = ddi_get_instance(dip);
	bcm2711_pcie_softc_t *softc =
	    ddi_get_soft_state(bcm2711_pcie_soft_state, instance);

	VERIFY3P(softc, !=, NULL);

	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2DEVINFO:
		if (softc == NULL) {
			return (DDI_FAILURE);
		}
		*result = softc->bc_dip;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static struct bus_ops bcm2711_pcie_bus_ops = {
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


static struct cb_ops bcm2711_pcie_cb_ops = {
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

static struct dev_ops bcm2711_pcie_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = bcm2711_pcie_info,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = bcm2711_pcie_attach,
	.devo_detach = bcm2711_pcie_detach,
	.devo_reset = nodev,
	.devo_cb_ops = &bcm2711_pcie_cb_ops,
	.devo_bus_ops = &bcm2711_pcie_bus_ops,
	.devo_quiesce = ddi_quiesce_not_needed,
};

static struct modldrv bcm2711_pcie_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Broadcom 2711 PCIe",
	.drv_dev_ops = &bcm2711_pcie_ops,
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &bcm2711_pcie_modldrv, NULL }
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&bcm2711_pcie_soft_state,
	    sizeof (bcm2711_pcie_softc_t), 1)) != DDI_SUCCESS) {
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&bcm2711_pcie_soft_state);
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

	ddi_soft_state_fini(&bcm2711_pcie_soft_state);
	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
