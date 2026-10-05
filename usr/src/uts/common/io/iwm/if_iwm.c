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
 * Copyright 2026 lex0de <lex0de@tuta.com>
 */

/*
 * Native resource boundaries for the Intel 8260 transport.
 *
 * Hardware definitions come from the pinned OpenBSD iwm donor described in
 * the accompanying headers.  This file contains native illumos integration,
 * not an implementation of OpenBSD kernel interfaces.
 *
 * Passive attach by default. The iwm-init-nvm property opts into one bounded
 * INIT firmware/NVM cycle; iwm-full-init additionally calibrates and restarts
 * REGULAR. The iwm-public-scan opt-in publishes only passive scanning;
 * its attach-time INIT bootstrap stops before public registration.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/pci.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/firmload.h>
#include <sys/mac_provider.h>
#include <sys/atomic.h>
#include <sys/strsun.h>
#include <sys/policy.h>
#include <sys/stat.h>
#include <sys/disp.h>
#include <inet/wifi_ioctl.h>
#include "if_iwmvar.h"

/* The only hardware identity admitted by the resource mapping helper. */
static const struct iwm_cfg iwm_8260 = {
	.vendor = 0x8086,
	.device = 0x24f3,
	.subvendor = 0x8086,
	.subdevice = 0x1130,
	.revision = 0x3a,
	.family = IWM_DEVICE_FAMILY_8000,
	.fw_dma_size = IWM_FWDMASEGSZ_8000,
	.nvm_section_size = 32768,
	.nvm_external = B_TRUE,
	.fwname = "iwm-8000C-36"
};

#define	IWM_BAR_SIZE	0x2000
#define	IWM_DMA_MAX	0xfffffffffULL	/* 36-bit transport addresses */
#define	IWM_FW_FILE_MAX	(4 * 1024 * 1024)

static void *iwm_state;
static uint32_t iwm_retained;

static int iwm_cleanup(struct iwm_softc *);
static int iwm_public_unregister(struct iwm_softc *);

/* Only recognised causes may be acknowledged by the dormant handler. */
#define	IWM_PASSIVE_INT_CAUSES	(IWM_CSR_INT_BIT_FH_RX | \
	IWM_CSR_INT_BIT_HW_ERR | IWM_CSR_INT_BIT_RX_PERIODIC | \
	IWM_CSR_INT_BIT_FH_TX | IWM_CSR_INT_BIT_SCD | IWM_CSR_INT_BIT_SW_ERR | \
	IWM_CSR_INT_BIT_RF_KILL | IWM_CSR_INT_BIT_CT_KILL | \
	IWM_CSR_INT_BIT_SW_RX | IWM_CSR_INT_BIT_WAKEUP | IWM_CSR_INT_BIT_ALIVE)
#define	IWM_PASSIVE_FH_CAUSES	(IWM_CSR_FH_INT_BIT_ERR | \
	IWM_CSR_FH_INT_BIT_HI_PRIOR | IWM_CSR_FH_INT_BIT_RX_CHNL1 | \
	IWM_CSR_FH_INT_BIT_RX_CHNL0 | IWM_CSR_FH_INT_BIT_TX_CHNL1 | \
	IWM_CSR_FH_INT_BIT_TX_CHNL0)

/* Passive control allocations; INIT may publish keep-warm and RX state. */
static const struct {
	const char *name;
	size_t size;
	uint_t align;
} iwm_passive_dma[IWM_PASSIVE_DMA_COUNT] = {
	{ "keep-warm", 4096, 4096 },
	{ "tx-descriptors", IWM_TX_RING_COUNT * sizeof (struct iwm_tfd), 256 },
	{ "rx-descriptors", IWM_RX_RING_COUNT * sizeof (uint32_t), 256 },
	{ "rx-status", sizeof (struct iwm_rb_status), 16 }
};

int
iwm_base_dma_alloc(struct iwm_softc *sc)
{
	uint_t i;

	for (i = 0; i < IWM_PASSIVE_DMA_COUNT; i++) {
		if (sc->dma[i].bound)
			continue;
		if (iwm_dma_alloc(sc, &sc->dma[i], iwm_passive_dma[i].size,
		    iwm_passive_dma[i].align, DDI_DMA_RDWR) != 0)
			return (ENOMEM);
	}
	return (0);
}

static const ddi_device_acc_attr_t iwm_reg_attr = {
	DDI_DEVICE_ATTR_V0, DDI_STRUCTURE_LE_ACC, DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/* Wire fields are explicitly little endian; do not swap payload bytes. */
static const ddi_device_acc_attr_t iwm_dma_attr = {
	DDI_DEVICE_ATTR_V0, DDI_NEVERSWAP_ACC, DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/* Inject test failure after a successful ownership transition. */
int
iwm_checkpoint(struct iwm_softc *sc, const char *name)
{
	if (++sc->attach_step != sc->fail_step)
		return (0);
	dev_err(sc->dip, CE_NOTE, "!iwm injected failure %d (%s)",
	    sc->attach_step, name);
	return (EIO);
}

/* A bounded conventional PCI capability walk, including cycle detection. */
static int
iwm_pci_caps(struct iwm_softc *sc)
{
	uint64_t seen = 0;
	uint8_t ptr, id;
	uint16_t pmcsr, msi;

	if (!(pci_config_get16(sc->pcih, PCI_CONF_STAT) & PCI_STAT_CAP))
		return (ENOTSUP);
	ptr = pci_config_get8(sc->pcih, PCI_CONF_CAP_PTR);
	while (ptr != 0) {
		if (ptr < 0x40 || (ptr & 3) != 0 ||
		    (seen & (1ULL << (ptr / 4))) != 0)
			return (EIO);
		seen |= 1ULL << (ptr / 4);
		id = pci_config_get8(sc->pcih, ptr);
		switch (id) {
		case PCI_CAP_ID_PCI_E:
			sc->pcie_cap = ptr;
			break;
		case PCI_CAP_ID_MSI:
			sc->msi_cap = ptr;
			break;
		case PCI_CAP_ID_PM:
			if (ptr > 0xf8)
				return (EIO);
			sc->pm_cap = ptr;
			break;
		case 0xff:
			return (EIO);
		default:
			break;
		}
		ptr = pci_config_get8(sc->pcih, ptr + PCI_CAP_NEXT_PTR);
	}
	if (sc->pcie_cap == 0 || sc->msi_cap == 0 || sc->pm_cap == 0)
		return (ENOTSUP);
	pmcsr = pci_config_get16(sc->pcih, sc->pm_cap + PCI_PMCSR);
	msi = pci_config_get16(sc->pcih, sc->msi_cap + PCI_MSI_CTRL);
	dev_err(sc->dip, CE_NOTE, "!iwm caps PCIe=%02x MSI=%02x PM=%02x "
	    "PMCSR=%04x MSI-control=%04x", sc->pcie_cap, sc->msi_cap,
	    sc->pm_cap, pmcsr, msi);
	if ((pmcsr & PCI_PMCSR_STATE_MASK) != PCI_PMCSR_D0 ||
	    (msi & PCI_MSI_ENABLE_BIT) != 0)
		return (EBUSY);
	return (0);
}

/*
 * Thread context, exclusive lifecycle ownership.  This does not enable bus
 * mastering, alter PCI command bits, or read/write the mapped device BAR.
 * BAR0 is reg tuple 1 on the target; require its observed 8 KiB extent.
 */
int
iwm_pci_map(struct iwm_softc *sc)
{
	const struct iwm_cfg *cfg = &iwm_8260;
	uint16_t vendor, device, subvendor, subdevice;
	uint8_t revision;

	if (sc->pcih != NULL || sc->regh != NULL)
		return (EBUSY);
	if (pci_config_setup(sc->dip, &sc->pcih) != DDI_SUCCESS)
		return (EIO);
	if (iwm_checkpoint(sc, "pci-config") != 0)
		return (EIO);
	vendor = pci_config_get16(sc->pcih, PCI_CONF_VENID);
	device = pci_config_get16(sc->pcih, PCI_CONF_DEVID);
	subvendor = pci_config_get16(sc->pcih, PCI_CONF_SUBVENID);
	subdevice = pci_config_get16(sc->pcih, PCI_CONF_SUBSYSID);
	revision = pci_config_get8(sc->pcih, PCI_CONF_REVID);
	dev_err(sc->dip, CE_NOTE, "!iwm PCI %04x:%04x subsystem %04x:%04x "
	    "revision %02x", vendor, device, subvendor, subdevice, revision);
	if (vendor != cfg->vendor || device != cfg->device ||
	    subvendor != cfg->subvendor || subdevice != cfg->subdevice ||
	    revision != cfg->revision)
		return (ENODEV);
	sc->pci_command = pci_config_get16(sc->pcih, PCI_CONF_COMM);
	dev_err(sc->dip, CE_NOTE, "!iwm PCI command before=%04x",
	    sc->pci_command);
	/* Preserve power, memory decoding, retry timeout and bus mastering. */
	if (!(sc->pci_command & PCI_COMM_MAE) || iwm_pci_caps(sc) != 0)
		return (ENOTSUP);
	if (ddi_dev_regsize(sc->dip, 1, &sc->regsize) != DDI_SUCCESS ||
	    sc->regsize != IWM_BAR_SIZE ||
	    ddi_regs_map_setup(sc->dip, 1, &sc->regs, 0, sc->regsize,
	    &iwm_reg_attr, &sc->regh) != DDI_SUCCESS)
		return (EIO);
	sc->cfg = cfg;
	return (iwm_checkpoint(sc, "bar"));
}

void
iwm_pci_unmap(struct iwm_softc *sc)
{
	if (sc->regh != NULL)
		ddi_regs_map_free(&sc->regh);
	sc->regs = NULL;
	sc->regsize = 0;
	if (sc->pcih != NULL)
		pci_config_teardown(&sc->pcih);
	sc->cfg = NULL;
}

/* Direct CSR access only; these do not acquire peripheral/NIC ownership. */
int
iwm_reg_read(struct iwm_softc *sc, uint_t reg, uint32_t *value)
{
	if (sc->regh == NULL || value == NULL || (reg & 3) != 0 ||
	    sc->regsize < sizeof (*value) ||
	    reg > sc->regsize - sizeof (*value))
		return (EINVAL);
	*value = ddi_get32(sc->regh, (uint32_t *)(sc->regs + reg));
	return (0);
}

int
iwm_reg_write(struct iwm_softc *sc, uint_t reg, uint32_t value)
{
	if (sc->regh == NULL || (reg & 3) != 0 ||
	    sc->regsize < sizeof (value) ||
	    reg > sc->regsize - sizeof (value))
		return (EINVAL);
	ddi_put32(sc->regh, (uint32_t *)(sc->regs + reg), value);
	return (0);
}

/*
 * Allocate one contiguous device-visible region.  Alignment is specified by
 * the ring/firmware owner, never inferred from a kernel virtual address.
 * This helper is for consistent control/ring memory, not streaming mblks.
 * No address is published to hardware here.  A later publisher must perform
 * ddi_dma_sync(FORDEV); a consumer must perform ddi_dma_sync(FORCPU).
 */
int
iwm_dma_alloc(struct iwm_softc *sc, struct iwm_dma_info *dma, size_t size,
    uint_t align, uint_t direction)
{
	ddi_dma_attr_t attr = {
		DMA_ATTR_V0, 0, IWM_DMA_MAX, IWM_DMA_MAX, 1, 0x7ff, 1,
		IWM_DMA_MAX, IWM_DMA_MAX, 1, 1, 0
	};
	uint_t count;

	if (dma->allocated || dma->memory || dma->bound)
		return (EBUSY);
	if (size == 0 || size > IWM_DMA_MAX || align == 0 ||
	    (align & (align - 1)) != 0 ||
	    (direction != DDI_DMA_READ && direction != DDI_DMA_WRITE &&
	    direction != DDI_DMA_RDWR))
		return (EINVAL);
	attr.dma_attr_align = align;
	if (ddi_dma_alloc_handle(sc->dip, &attr, DDI_DMA_SLEEP, NULL,
	    &dma->dma_hdl) != DDI_SUCCESS)
		return (ENOMEM);
	dma->allocated = B_TRUE;
	if (iwm_checkpoint(sc, "dma-handle") != 0)
		goto fail;
	if (ddi_dma_mem_alloc(dma->dma_hdl, size, &iwm_dma_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &dma->vaddr,
	    &dma->length, &dma->acc_hdl) != DDI_SUCCESS)
		goto fail;
	dma->memory = B_TRUE;
	if (iwm_checkpoint(sc, "dma-memory") != 0)
		goto fail;
	if (dma->length < size)
		goto fail;
	if (ddi_dma_addr_bind_handle(dma->dma_hdl, NULL, dma->vaddr, size,
	    direction | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &dma->cookie, &count) != DDI_DMA_MAPPED)
		goto fail;
	dma->bound = B_TRUE;
	if (iwm_checkpoint(sc, "dma-bind") != 0)
		goto fail;
	if (count != 1 || dma->cookie.dmac_size < size ||
	    dma->cookie.dmac_laddress > IWM_DMA_MAX ||
	    size - 1 > IWM_DMA_MAX - dma->cookie.dmac_laddress ||
	    (dma->cookie.dmac_laddress & (align - 1)) != 0)
		goto fail;
	dma->size = size;
	bzero(dma->vaddr, size);
	/* Exercise both sync directions without publishing the cookie. */
	if (ddi_dma_sync(dma->dma_hdl, 0, size, DDI_DMA_SYNC_FORDEV) !=
	    DDI_SUCCESS || ddi_dma_sync(dma->dma_hdl, 0, size,
	    DDI_DMA_SYNC_FORCPU) != DDI_SUCCESS ||
	    iwm_checkpoint(sc, "dma-sync") != 0)
		goto fail;
	return (0);

fail:
	/* If unbinding fails, the object retains ownership for its caller. */
	(void) iwm_dma_free(dma);
	return (EIO);
}

/* Device must be stopped; retain resources rather than free a live mapping. */
int
iwm_dma_free(struct iwm_dma_info *dma)
{
	if (dma->bound) {
		if (ddi_dma_unbind_handle(dma->dma_hdl) != DDI_SUCCESS)
			return (EIO);
		dma->bound = B_FALSE;
	}
	if (dma->memory)
		ddi_dma_mem_free(&dma->acc_hdl);
	if (dma->allocated)
		ddi_dma_free_handle(&dma->dma_hdl);
	bzero(dma, sizeof (*dma));
	return (0);
}

/*
 * Read raw bytes in thread context with exclusive ownership of fw.  Success
 * means file I/O only.  TLV parsing, version/capability validation and device
 * transfer require successful validation by iwm_fw_parse().
 * The filename resolves to kernel/firmware/iwm/iwm-8000C-36 through firmload.
 */
int
iwm_fw_read(struct iwm_softc *sc)
{
	struct iwm_fw_info *fw = &sc->fw;
	firmware_handle_t handle;
	off_t size;
	int error;

	if (fw->data != NULL)
		return (EBUSY);
	error = firmware_open("iwm", iwm_8260.fwname, &handle);
	if (error != 0)
		return (error);
	if (iwm_checkpoint(sc, "firmware-open") != 0) {
		(void) firmware_close(handle);
		return (EIO);
	}
	size = firmware_get_size(handle);
	if (size < sizeof (struct iwm_tlv_ucode_header) ||
	    size > IWM_FW_FILE_MAX) {
		(void) firmware_close(handle);
		return (EINVAL);
	}
	fw->size = (size_t)size;
	fw->data = kmem_zalloc(fw->size, KM_SLEEP);
	error = iwm_checkpoint(sc, "firmware-memory");
	if (error == 0)
		error = firmware_read(handle, 0, fw->data, fw->size);
	(void) firmware_close(handle);
	if (error != 0) {
		iwm_fw_free(fw);
		return (EIO);
	}
	return (0);
}

void
iwm_fw_free(struct iwm_fw_info *fw)
{
	if (fw->data != NULL)
		kmem_free(fw->data, fw->size);
	bzero(fw, sizeof (*fw));
}

/* A read after the mask write flushes posted MMIO before host enable. */
static int
iwm_mask(struct iwm_softc *sc)
{
	uint32_t mask;

	if (iwm_reg_write(sc, IWM_CSR_INT_MASK, 0) != 0 ||
	    iwm_reg_read(sc, IWM_CSR_INT_MASK, &mask) != 0 || mask != 0)
		return (EIO);
	return (0);
}

static boolean_t
iwm_csr_unavailable(uint32_t value)
{
	return (value == 0xffffffff || (value & 0xfffffff0) == 0xa5a5a5a0);
}

static int
iwm_passive_csr(struct iwm_softc *sc)
{
	uint32_t causes, fh, mask;

	if (iwm_reg_read(sc, IWM_CSR_HW_REV, &sc->hw_rev) != 0 ||
	    iwm_reg_read(sc, IWM_CSR_GP_CNTRL, &sc->gp_cntrl) != 0 ||
	    iwm_reg_read(sc, IWM_CSR_INT_MASK, &mask) != 0 ||
	    iwm_csr_unavailable(sc->hw_rev) ||
	    iwm_csr_unavailable(sc->gp_cntrl) || iwm_csr_unavailable(mask))
		return (EIO);
	sc->csr_valid = B_TRUE;
	dev_err(sc->dip, CE_NOTE, "!iwm BAR size=%ld HW_REV=%08x "
	    "GP_CNTRL=%08x rfkill=%s initial-mask=%08x", (long)sc->regsize,
	    sc->hw_rev, sc->gp_cntrl,
	    (sc->gp_cntrl & IWM_CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW) ?
	    "off" : "on", mask);
	if (iwm_mask(sc) != 0 ||
	    iwm_reg_read(sc, IWM_CSR_INT, &causes) != 0 ||
	    iwm_reg_read(sc, IWM_CSR_FH_INT_STATUS, &fh) != 0)
		return (EIO);
	dev_err(sc->dip, CE_NOTE, "!iwm stale causes=%08x fh=%08x",
	    causes, fh);
	if ((causes & ~IWM_PASSIVE_INT_CAUSES) != 0 ||
	    (fh & ~IWM_PASSIVE_FH_CAUSES) != 0)
		return (EIO);
	/* Write-one-to-clear only the recognised causes actually observed. */
	(void) iwm_reg_write(sc, IWM_CSR_INT, causes);
	(void) iwm_reg_write(sc, IWM_CSR_FH_INT_STATUS, fh);
	return (iwm_checkpoint(sc, "csr-mask"));
}

static uint_t
iwm_intr(caddr_t arg, caddr_t unused)
{
	struct iwm_softc *sc = (void *)arg;
	uint32_t causes = 0, fh = 0;
	uint32_t ack, fh_ack;
	uint_t result = DDI_INTR_UNCLAIMED;

	_NOTE(ARGUNUSED(unused));
	mutex_enter(&sc->lock);
	sc->intr_calls++;
	if (sc->run != NULL) {
		(void) iwm_mask(sc);
		(void) iwm_reg_read(sc, IWM_CSR_INT, &causes);
		(void) iwm_reg_read(sc, IWM_CSR_FH_INT_STATUS, &fh);
		result = iwm_active_intr(sc, causes, fh);
		mutex_exit(&sc->lock);
		return (result);
	}
	(void) iwm_mask(sc);
	if (iwm_reg_read(sc, IWM_CSR_INT, &causes) == 0 &&
	    iwm_reg_read(sc, IWM_CSR_FH_INT_STATUS, &fh) == 0 &&
	    !iwm_csr_unavailable(causes) && !iwm_csr_unavailable(fh)) {
		ack = causes & IWM_PASSIVE_INT_CAUSES;
		fh_ack = fh & IWM_PASSIVE_FH_CAUSES;
		if (ack != 0 || fh_ack != 0) {
			(void) iwm_reg_write(sc, IWM_CSR_INT, ack);
			(void) iwm_reg_write(sc, IWM_CSR_FH_INT_STATUS, fh_ack);
			result = DDI_INTR_CLAIMED;
		}
	}
	/* Any callback is unexpected with device sources masked.  Log once. */
	if (!sc->intr_fault)
		dev_err(sc->dip, CE_WARN, "!iwm unexpected passive interrupt "
		    "causes=%08x fh=%08x; sources remain masked", causes, fh);
	sc->intr_fault = B_TRUE;
	mutex_exit(&sc->lock);
	return (result);
}

static int
iwm_intr_open(struct iwm_softc *sc)
{
	int count, available, actual;

	if (ddi_intr_get_supported_types(sc->dip, &sc->intr_types) !=
	    DDI_SUCCESS || !(sc->intr_types & DDI_INTR_TYPE_MSI))
		return (ENOTSUP);
	/* MSI uses the donor's single-vector CSR path, with no ICT routing. */
	if (ddi_intr_get_nintrs(sc->dip, DDI_INTR_TYPE_MSI, &count) !=
	    DDI_SUCCESS || count < 1 ||
	    ddi_intr_get_navail(sc->dip, DDI_INTR_TYPE_MSI, &available) !=
	    DDI_SUCCESS || available < 1)
		return (ENOSPC);
	if (ddi_intr_alloc(sc->dip, &sc->intr, DDI_INTR_TYPE_MSI, 0, 1,
	    &actual, DDI_INTR_ALLOC_STRICT) != DDI_SUCCESS)
		return (EIO);
	sc->intr_allocated = B_TRUE;
	if (actual != 1 || iwm_checkpoint(sc, "interrupt-handle") != 0 ||
	    ddi_intr_get_pri(sc->intr, &sc->intr_pri) != DDI_SUCCESS ||
	    sc->intr_pri >= ddi_intr_get_hilevel_pri() ||
	    ddi_intr_get_cap(sc->intr, &sc->intr_cap) != DDI_SUCCESS)
		return (EIO);
	mutex_init(&sc->lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(sc->intr_pri));
	sc->lock_initialized = B_TRUE;
	if (iwm_checkpoint(sc, "interrupt-lock") != 0)
		return (EIO);
	if (ddi_intr_add_handler(sc->intr, iwm_intr, sc, NULL) != DDI_SUCCESS)
		return (EIO);
	sc->intr_added = B_TRUE;
	dev_err(sc->dip, CE_NOTE, "!iwm interrupt supported=%x selected=MSI "
	    "count=1 priority=%u capabilities=%x", sc->intr_types,
	    sc->intr_pri, sc->intr_cap);
	return (iwm_checkpoint(sc, "interrupt-handler"));
}

int
iwm_intr_disable(struct iwm_softc *sc)
{
	int error;

	if (!sc->intr_enabled)
		return (0);
	if (sc->intr_cap & DDI_INTR_FLAG_BLOCK)
		error = ddi_intr_block_disable(&sc->intr, 1);
	else
		error = ddi_intr_disable(sc->intr);
	if (error != DDI_SUCCESS)
		return (EIO);
	sc->intr_enabled = B_FALSE;
	return (0);
}

static int
iwm_intr_test(struct iwm_softc *sc)
{
	int error;
	boolean_t fault;

	if (iwm_mask(sc) != 0)
		return (EIO);
	if (sc->intr_cap & DDI_INTR_FLAG_BLOCK)
		error = ddi_intr_block_enable(&sc->intr, 1);
	else
		error = ddi_intr_enable(sc->intr);
	if (error != DDI_SUCCESS)
		return (EIO);
	sc->intr_enabled = B_TRUE;
	if (iwm_checkpoint(sc, "interrupt-enabled") != 0)
		return (EIO);
	/* Observe for one tick, without holding a lock while asleep. */
	delay(1);
	if (iwm_intr_disable(sc) != 0)
		return (EIO);
	mutex_enter(&sc->lock);
	fault = sc->intr_fault;
	mutex_exit(&sc->lock);
	if (fault || iwm_mask(sc) != 0)
		return (EIO);
	dev_err(sc->dip, CE_NOTE, "!iwm host MSI enable/disable passed; "
	    "device mask=0 callbacks=%u", sc->intr_calls);
	return (iwm_checkpoint(sc, "interrupt-disabled"));
}

/*
 * Stop the runtime transport before releasing passive resources. Keep any
 * resource whose release fails, and prevent module removal while its
 * soft state remains.  A cleanup failure requires operator investigation;
 * it must never become a use-after-free or a forced removal.
 */
static int
iwm_cleanup(struct iwm_softc *sc)
{
	int i;
	int mask_error = 0;
	uint16_t command;

	if (sc->public_enabled && sc->lock_initialized &&
	    iwm_public_unregister(sc) != 0)
		return (EIO);
	if (iwm_run_free(sc) != 0)
		return (EIO);
	if (sc->net_attached && iwm_scan_detach(sc) != 0)
		return (EIO);
	iwm_fw_free(&sc->fw);
	bzero(&sc->identity, sizeof (sc->identity));
	if (sc->csr_valid && iwm_mask(sc) != 0)
		mask_error = EIO;
	if (iwm_intr_disable(sc) != 0)
		return (EIO);
	if (mask_error != 0)
		return (mask_error);
	for (i = IWM_PASSIVE_DMA_COUNT - 1; i >= 0; i--) {
		if (iwm_dma_free(&sc->dma[i]) != 0)
			return (EIO);
	}
	if (sc->intr_added) {
		if (ddi_intr_remove_handler(sc->intr) != DDI_SUCCESS)
			return (EIO);
		sc->intr_added = B_FALSE;
	}
	if (sc->lock_initialized) {
		mutex_destroy(&sc->lock);
		sc->lock_initialized = B_FALSE;
	}
	if (sc->intr_allocated) {
		if (ddi_intr_free(sc->intr) != DDI_SUCCESS)
			return (EIO);
		sc->intr_allocated = B_FALSE;
		sc->intr = NULL;
	}
	if (sc->cfg != NULL && sc->pcih != NULL) {
		command = pci_config_get16(sc->pcih, PCI_CONF_COMM);
		dev_err(sc->dip, CE_NOTE, "!iwm PCI command after=%04x "
		    "before=%04x", command, sc->pci_command);
		if ((command ^ sc->pci_command) & PCI_COMM_ME)
			dev_err(sc->dip, CE_WARN,
			    "!iwm bus-master state changed");
	}
	iwm_pci_unmap(sc);
	sc->csr_valid = B_FALSE;
	if (sc->operation_initialized) {
		mutex_destroy(&sc->connection.crypto_lock);
		cv_destroy(&sc->connection.cv);
		cv_destroy(&sc->operation_cv);
		mutex_destroy(&sc->operation_lock);
		sc->operation_initialized = B_FALSE;
	}
	return (0);
}

/*
 * Public operation ownership is separate from the MSI/command mutex. Owners
 * drop operation_lock before hardware or framework calls. STOP signals the
 * scan owner under lock, then waits; it never runs a second scan drain.
 */
int
iwm_operation_enter(struct iwm_softc *sc, enum iwm_operation operation)
{
	clock_t end = ddi_get_lbolt() + drv_usectohz(30000000);
	int error = 0;

	mutex_enter(&sc->operation_lock);
	if (operation == IWM_OP_STOP) {
		sc->stop_requested = B_TRUE;
		if (sc->operation == IWM_OP_SCAN)
			iwm_scan_stop_request(sc);
	}
	for (;;) {
		if (sc->detach_requested && operation != IWM_OP_STOP &&
		    operation != IWM_OP_DETACH &&
		    operation != IWM_OP_DISCONNECT) {
			error = ENXIO;
			break;
		}
		if (sc->operation == IWM_OP_NONE) {
			if (sc->stop_requested && operation != IWM_OP_STOP &&
			    operation != IWM_OP_DETACH &&
			    operation != IWM_OP_DISCONNECT) {
				error = EBUSY;
				break;
			}
			sc->operation = operation;
			break;
		}
		if (operation == IWM_OP_SCAN || operation == IWM_OP_SELECT ||
		    operation == IWM_OP_CONNECT) {
			error = EBUSY;
			break;
		}
		if (cv_timedwait(&sc->operation_cv, &sc->operation_lock,
		    end) == -1) {
			error = ETIMEDOUT;
			break;
		}
	}
	mutex_exit(&sc->operation_lock);
	return (error);
}

void
iwm_operation_exit(struct iwm_softc *sc)
{
	mutex_enter(&sc->operation_lock);
	ASSERT(sc->operation != IWM_OP_NONE);
	if (sc->operation == IWM_OP_STOP)
		sc->stop_requested = B_FALSE;
	sc->operation = IWM_OP_NONE;
	cv_broadcast(&sc->operation_cv);
	mutex_exit(&sc->operation_lock);
}

/*
 * The caller owns a public operation, but holds neither driver mutex. Owner
 * bits represent lifetime claims, not MAC framework or association state.
 * Publish a new claim only after startup succeeds. A failed final stop leaves
 * the claim and runtime intact for diagnosis; it cannot permit a new startup.
 */
int
iwm_runtime_acquire(struct iwm_softc *sc, enum iwm_runtime_owner owner)
{
	int error;

	ASSERT(sc->operation != IWM_OP_NONE);
	ASSERT(owner == IWM_RUNTIME_PROVIDER || owner == IWM_RUNTIME_CONNECT);
	if (sc->detach_requested || !sc->mac_registered || !sc->net_attached ||
	    !sc->identity.valid || !sc->minor_created)
		return (ENXIO);
	if (sc->runtime_stop_error != 0)
		return (sc->runtime_stop_error);
	if (sc->runtime_started && (error = iwm_runtime_status(sc)) != 0)
		return (error);
	if (sc->runtime_owners & owner)
		return (0);
	if (sc->runtime_started) {
		ASSERT(sc->runtime_owners != 0 && sc->run != NULL);
		sc->runtime_owners |= owner;
		return (0);
	}
	ASSERT(sc->runtime_owners == 0);
	error = iwm_runtime_start(sc);
	if (error != 0)
		return (error);
	sc->runtime_started = B_TRUE;
	if (iwm_checkpoint(sc, "runtime-started") != 0) {
		sc->runtime_stop_error = iwm_runtime_stop(sc);
		if (sc->runtime_stop_error == 0)
			sc->runtime_started = B_FALSE;
		else
			dev_err(sc->dip, CE_WARN,
			    "!iwm start rollback error=%d",
			    sc->runtime_stop_error);
		return (EIO);
	}
	sc->runtime_owners |= owner;
	return (0);
}

int
iwm_runtime_release(struct iwm_softc *sc, enum iwm_runtime_owner owner)
{
	int error;

	ASSERT(sc->operation != IWM_OP_NONE);
	ASSERT(owner == IWM_RUNTIME_PROVIDER || owner == IWM_RUNTIME_CONNECT);
	if (sc->runtime_stop_error != 0)
		return (sc->runtime_stop_error);
	if (!(sc->runtime_owners & owner))
		return (0);
	if (sc->runtime_owners & ~owner) {
		sc->runtime_owners &= ~owner;
		return (0);
	}
	error = iwm_runtime_stop(sc);
	sc->runtime_stop_error = error;
	if (error == 0) {
		sc->runtime_started = B_FALSE;
		sc->runtime_owners &= ~owner;
	}
	return (error);
}

static int
iwm_m_start(void *arg)
{
	struct iwm_softc *sc = arg;
	int error;

	if ((error = iwm_operation_enter(sc, IWM_OP_START)) != 0)
		return (error);
	error = iwm_runtime_acquire(sc, IWM_RUNTIME_PROVIDER);
	iwm_operation_exit(sc);
	return (error);
}

static void
iwm_m_stop(void *arg)
{
	struct iwm_softc *sc = arg;
	int error;

	error = iwm_operation_enter(sc, IWM_OP_STOP);
	if (error != 0) {
		dev_err(sc->dip, CE_WARN, "!iwm public stop owner error=%d",
		    error);
		return;
	}
	error = iwm_runtime_release(sc, IWM_RUNTIME_PROVIDER);
	if (error != 0)
		dev_err(sc->dip, CE_WARN, "!iwm runtime stop error=%d", error);
	iwm_operation_exit(sc);
}

static mblk_t *
iwm_m_tx(void *arg, mblk_t *mp)
{
	struct iwm_softc *sc = arg;

	return (iwm_connection_tx(sc, mp));
}

static int
iwm_m_unicst(void *arg, const uint8_t *address)
{
	struct iwm_softc *sc = arg;

	return (bcmp(address, sc->identity.mac, IEEE80211_ADDR_LEN) == 0 ?
	    0 : ENOTSUP);
}

static int
iwm_m_multicst(void *arg, boolean_t add, const uint8_t *address)
{
	struct iwm_softc *sc = arg;

	_NOTE(ARGUNUSED(add, address))
	atomic_inc_32(&sc->multicast_calls);
	return (0);
}

static int
iwm_m_promisc(void *arg, boolean_t on)
{
	_NOTE(ARGUNUSED(arg, on))
	return (ENOTSUP);
}

static int
iwm_m_stat(void *arg, uint_t stat, uint64_t *value)
{
	_NOTE(ARGUNUSED(arg))
	switch (stat) {
	case MAC_STAT_IFSPEED:
	case MAC_STAT_IPACKETS:
	case MAC_STAT_OPACKETS:
	case MAC_STAT_RBYTES:
	case MAC_STAT_OBYTES:
	case MAC_STAT_IERRORS:
	case MAC_STAT_OERRORS:
		*value = 0;
		return (0);
	default:
		return (ENOTSUP);
	}
}

/* The private snapshot contains native ABI values, never node pointers. */
struct iwm_ess_snapshot {
	struct iwm_softc *sc;
	wl_ess_list_t *list;
	size_t size;
	int error;
};

static void
iwm_ess_node(void *arg, struct ieee80211_node *node)
{
	struct iwm_ess_snapshot *snapshot = arg;
	struct iwm_softc *sc = snapshot->sc;
	wl_ess_list_t *list = snapshot->list;
	wl_ess_conf_t *entry;
	wl_erp_t *erp;
	size_t count = list->wl_ess_list_num;
	uint_t channel, i, nrates, rssi;
	static const uint8_t rates[] =
	    { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };

	if (snapshot->error != 0 ||
	    IEEE80211_ADDR_EQ(node->in_macaddr, sc->identity.mac))
		return;
	if (node->in_esslen > IEEE80211_NWID_LEN ||
	    node->in_rates.ir_nrates > sizeof (node->in_rates.ir_rates)) {
		snapshot->error = EPROTO;
		return;
	}
	for (channel = 1; channel <= 13; channel++) {
		if (node->in_chan == &sc->ic.ic_sup_channels[channel])
			break;
	}
	if (channel > 13 ||
	    !(sc->identity.channels[channel - 1] & 1)) {
		snapshot->error = EPROTO;
		return;
	}
	for (i = 0; i < node->in_rates.ir_nrates; i++) {
		uint_t j;
		uint8_t rate = node->in_rates.ir_rates[i] & IEEE80211_RATE_VAL;

		for (j = 0; j < sizeof (rates); j++) {
			if (rates[j] == rate)
				break;
		}
		if (j == sizeof (rates)) {
			snapshot->error = EPROTO;
			return;
		}
	}
	if (snapshot->size < offsetof(wl_ess_list_t, wl_ess_list_ess) ||
	    count >= (snapshot->size -
	    offsetof(wl_ess_list_t, wl_ess_list_ess)) / sizeof (*entry)) {
		snapshot->error = ENOSPC;
		return;
	}
	entry = &list->wl_ess_list_ess[count];
	entry->wl_ess_conf_length = sizeof (*entry);
	entry->wl_ess_conf_essid.wl_essid_length = node->in_esslen;
	bcopy(node->in_essid, entry->wl_ess_conf_essid.wl_essid_essid,
	    node->in_esslen);
	bcopy(node->in_bssid, entry->wl_ess_conf_bssid, IEEE80211_ADDR_LEN);
	entry->wl_ess_conf_wepenabled =
	    node->in_capinfo & IEEE80211_CAPINFO_PRIVACY ? WL_ENC_WEP :
	    WL_NOENCRYPTION;
	entry->wl_ess_conf_bsstype = node->in_capinfo & IEEE80211_CAPINFO_ESS ?
	    WL_BSS_BSS : WL_BSS_IBSS;
	entry->wl_ess_conf_reserved[0] = node->in_wpa_ie != NULL;
	rssi = MIN(node->in_rssi, 100);
	entry->wl_ess_conf_sl = rssi == 0 ? 0 : rssi == 100 ? MAX_RSSI :
	    rssi * MAX_RSSI / 100 + 1;
	erp = &entry->wl_phy_conf.wl_phy_erp_conf;
	erp->wl_erp_subtype = WL_ERP;
	erp->wl_erp_channel = channel;
	erp->wl_erp_have_short_preamble =
	    !!(node->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE);
	erp->wl_erp_sst_enabled =
	    !!(node->in_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME);
	nrates = MIN(node->in_rates.ir_nrates, MAX_SCAN_SUPPORT_RATES);
	for (i = 0; i < nrates; i++)
		entry->wl_supported_rates[i] =
		    node->in_rates.ir_rates[node->in_rates.ir_nrates - i - 1];
	list->wl_ess_list_num++;
}

/* crypto_lock serializes the accumulated native configuration. */
static boolean_t
iwm_open_ready(struct iwm_softc *sc)
{
	struct iwm_connection *c = &sc->connection;
	uint_t required = IWM_CONFIG_COMMON | IWM_CONFIG_OPEN;

	return (!c->resetting && (c->configuration & required) == required &&
	    !c->wpa &&
	    !(sc->ic.ic_flags & IEEE80211_F_WPA) && sc->desired_bssid_valid);
}

static boolean_t
iwm_wpa_ready(struct iwm_softc *sc)
{
	struct iwm_connection *c = &sc->connection;

	return (!c->resetting &&
	    (c->configuration & IWM_CONFIG_COMMON) == IWM_CONFIG_COMMON &&
	    c->wpa && (sc->ic.ic_flags & IEEE80211_F_WPA) != 0 &&
	    iwm_rsn_check((const uint8_t *)sc->ic.ic_opt_ie,
	    sc->ic.ic_opt_ie_len) == 0);
}

/* Reserve only; the worker performs native join and firmware waits. */
static int
iwm_connect_request(struct iwm_softc *sc, const uint8_t *bssid)
{
	struct iwm_connection *c = &sc->connection;
	ieee80211_node_t *node = NULL;
	uint8_t previous[IEEE80211_ADDR_LEN];
	boolean_t valid;
	int error;

	if ((error = iwm_operation_enter(sc, IWM_OP_CONNECT)) != 0)
		return (error);
	mutex_enter(&sc->lock);
	if (c->pending || c->resetting || c->taskq == NULL ||
	    sc->ic.ic_state != IEEE80211_S_INIT) {
		error = EBUSY;
		mutex_exit(&sc->lock);
		goto out;
	}
	valid = sc->desired_bssid_valid;
	bcopy(sc->desired_bssid, previous, sizeof (previous));
	if (bssid != NULL) {
		bcopy(bssid, sc->desired_bssid, IEEE80211_ADDR_LEN);
		sc->desired_bssid_valid = B_TRUE;
	}
	mutex_exit(&sc->lock);
	/* Reference the exact WPA node before scheduling anything. */
	if (bssid != NULL && (error = iwm_select_bss(sc, c->essid,
	    c->esslen, c->channel, &node)) != 0)
		goto restore;
	mutex_enter(&sc->lock);
	c->node = node;
	c->error = c->cleanup_error = 0;
	c->cancel = c->mlme_cancel = B_FALSE;
	c->clear_ie = c->disable_wpa = B_FALSE;
	c->finished = B_FALSE;
	c->pending = B_TRUE;
	if (taskq_dispatch(c->taskq, iwm_connection_task, sc,
	    TQ_NOSLEEP) == TASKQID_INVALID) {
		c->pending = B_FALSE;
		error = ENOMEM;
	}
	mutex_exit(&sc->lock);
	if (error == 0)
		return (0);
restore:
	mutex_enter(&sc->lock);
	c->node = NULL;
	bcopy(previous, sc->desired_bssid, sizeof (previous));
	sc->desired_bssid_valid = valid;
	mutex_exit(&sc->lock);
	if (node != NULL)
		ieee80211_free_node(node);
out:
	if (error != 0)
		iwm_operation_exit(sc);
	return (error);
}

/*
 * Native key slots and set_tx semantics are preserved. Serialize key property
 * calls against retirement without holding a MAC callback across firmware
 * work. Reinstalling an identical live key must never reset its PN or RSC.
 */
static int
iwm_wpa_key(struct iwm_softc *sc, const char *name, mac_prop_id_t id,
    uint_t size, const void *value)
{
	ieee80211com_t *ic = &sc->ic;
	wl_key_t key;
	wl_del_key_t deletion;
	struct ieee80211_key *live;
	boolean_t duplicate = B_FALSE, allowed;
	uint_t flags;
	int error = 0;

	if (id == MAC_PROP_WL_KEY) {
		if (size != sizeof (key))
			return (EINVAL);
		bcopy(value, &key, sizeof (key));
		flags = IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV |
		    IEEE80211_KEY_DEFAULT;
		if (key.ik_type != IEEE80211_CIPHER_AES_CCM ||
		    key.ik_keylen != IEEE80211_KEYBUF_SIZE ||
		    key.ik_keyix >= IEEE80211_WEP_NKID ||
		    key.ik_keyrsc > 0xffffffffffffULL ||
		    (key.ik_flags != IEEE80211_KEY_RECV &&
		    key.ik_flags != flags)) {
			error = ENOTSUP;
			goto out;
		}
	} else {
		if (size != sizeof (deletion))
			return (EINVAL);
		bcopy(value, &deletion, sizeof (deletion));
		if (deletion.idk_keyix >= IEEE80211_WEP_NKID)
			return (EINVAL);
	}
	mutex_enter(&sc->connection.crypto_lock);
	mutex_enter(&sc->lock);
	allowed = sc->net_attached &&
	    (id == MAC_PROP_WL_DELKEY || (sc->connection.wpa &&
	    sc->connection.running && !sc->connection.cancel));
	if (allowed && id == MAC_PROP_WL_KEY) {
		if (key.ik_flags & IEEE80211_KEY_DEFAULT) {
			allowed = key.ik_keyix == 0 &&
			    bcmp(key.ik_macaddr, sc->associated_bssid, 6) == 0;
		} else {
			static const uint8_t zero[6] = { 0 };

			/* Native receive-only GTK uses a zero address. */
			allowed = key.ik_keyix != 0 &&
			    bcmp(key.ik_macaddr, zero, sizeof (zero)) == 0;
		}
	}
	mutex_exit(&sc->lock);
	if (!allowed) {
		error = EBUSY;
		goto unlock;
	}
	if (id == MAC_PROP_WL_KEY) {
		mutex_enter(&ic->ic_genlock);
		live = &ic->ic_nw_keys[key.ik_keyix];
		duplicate = live->wk_cipher->ic_cipher ==
		    IEEE80211_CIPHER_AES_CCM &&
		    live->wk_keylen == key.ik_keylen &&
		    (live->wk_flags & IEEE80211_KEY_COMMON) ==
		    (key.ik_flags & IEEE80211_KEY_COMMON) &&
		    bcmp(live->wk_key, key.ik_keydata, key.ik_keylen) == 0;
		if (duplicate) {
			live->wk_keyrsc = MAX(live->wk_keyrsc, key.ik_keyrsc);
			if (key.ik_flags & IEEE80211_KEY_DEFAULT)
				ic->ic_def_txkey = key.ik_keyix;
		}
		mutex_exit(&ic->ic_genlock);
	}
	if (!duplicate)
		error = ieee80211_setprop(ic, name, id, size, value);
unlock:
	mutex_exit(&sc->connection.crypto_lock);
out:
	/* This stack copy is never retained as diagnostic evidence. */
	bzero(&key, sizeof (key));
	return (error);
}

static int
iwm_m_setprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, const void *value)
{
	struct iwm_softc *sc = arg;
	const uint8_t *address = value;
	uint8_t nonzero = 0;
	uint_t i;
	int error;
	struct iwm_connection *c = &sc->connection;
	const wl_essid_t *essid = value;
	const wl_phy_conf_t *phy = value;
	uint32_t scalar = 0;

	if (value == NULL)
		return (EINVAL);
	if (id == MAC_PROP_WL_KEY || id == MAC_PROP_WL_DELKEY)
		return (iwm_wpa_key(sc, name, id, size, value));
	if (id == MAC_PROP_WL_MLME) {
		wl_mlme_t mlme;

		if (size != sizeof (mlme))
			return (EINVAL);
		bcopy(value, &mlme, sizeof (mlme));
		if (mlme.im_op == IEEE80211_MLME_DISASSOC ||
		    mlme.im_op == IEEE80211_MLME_DEAUTH) {
			mutex_enter(&sc->lock);
			if (c->pending) {
				c->mlme_cancel = B_TRUE;
				c->tx_admission = c->rx_admission = B_FALSE;
			}
			mutex_exit(&sc->lock);
			iwm_connection_cancel(sc);
			return (0);
		}
		for (i = 0; i < IEEE80211_ADDR_LEN; i++)
			nonzero |= mlme.im_macaddr[i];
		mutex_enter(&c->crypto_lock);
		if (mlme.im_op != IEEE80211_MLME_ASSOC ||
		    nonzero == 0 || (mlme.im_macaddr[0] & 1) != 0 ||
		    !iwm_wpa_ready(sc))
			error = EINVAL;
		else
			error = iwm_connect_request(sc, mlme.im_macaddr);
		mutex_exit(&c->crypto_lock);
		return (error);
	}
	if (id == MAC_PROP_WL_WPA || id == MAC_PROP_WL_SETOPTIE) {
		const wl_wpa_ie_t *ie = value;
		wl_wpa_t wpa = { 0 };

		if (id == MAC_PROP_WL_WPA) {
			if (size != sizeof (wpa))
				return (EINVAL);
			bcopy(value, &wpa, sizeof (wpa));
			if (wpa.wpa_flag > 1)
				return (ENOTSUP);
		} else if (size < sizeof (*ie) ||
		    ie->wpa_ie_len > IEEE80211_MAX_OPT_IE ||
		    ie->wpa_ie_len > size - offsetof(wl_wpa_ie_t, wpa_ie) ||
		    (ie->wpa_ie_len != 0 && iwm_rsn_check(
		    (const uint8_t *)ie->wpa_ie, ie->wpa_ie_len) != 0)) {
			return (EINVAL);
		}
		mutex_enter(&c->crypto_lock);
		mutex_enter(&sc->lock);
		if (c->pending && id == MAC_PROP_WL_SETOPTIE &&
		    ie->wpa_ie_len == 0 && c->cancel) {
			/* A management builder may still read the old IE. */
			c->clear_ie = B_TRUE;
			error = 0;
		} else if (c->pending && id == MAC_PROP_WL_WPA &&
		    wpa.wpa_flag == 0 && c->cancel) {
			c->disable_wpa = B_TRUE;
			error = 0;
		} else if (c->pending || c->resetting) {
			error = EBUSY;
		} else {
			error = 0;
		}
		mutex_exit(&sc->lock);
		if (error == 0 && !c->pending) {
			error = ieee80211_setprop(&sc->ic, name, id,
			    size, value);
			if (error == 0 && id == MAC_PROP_WL_WPA) {
				c->wpa = wpa.wpa_flag != 0;
				c->configuration &= ~IWM_CONFIG_OPEN;
				if (!c->wpa) {
					c->clear_ie = c->disable_wpa = B_TRUE;
					iwm_connection_config_clear(sc);
				}
			}
		}
		mutex_exit(&c->crypto_lock);
		return (error);
	}
	if (id == MAC_PROP_WL_ESSID) {
		if (size != sizeof (*essid) || essid->wl_essid_length == 0 ||
		    essid->wl_essid_length > IEEE80211_NWID_LEN)
			return (EINVAL);
		mutex_enter(&c->crypto_lock);
		if ((error = iwm_operation_enter(sc, IWM_OP_SELECT)) != 0) {
			mutex_exit(&c->crypto_lock);
			return (error);
		}
		if (c->pending || c->resetting) {
			error = EBUSY;
		} else {
			mutex_enter(&sc->ic.ic_genlock);
			bcopy(essid->wl_essid_essid, sc->ic.ic_des_essid,
			    essid->wl_essid_length);
			sc->ic.ic_des_esslen = essid->wl_essid_length;
			mutex_exit(&sc->ic.ic_genlock);
			mutex_enter(&sc->lock);
			bcopy(essid->wl_essid_essid, c->essid,
			    essid->wl_essid_length);
			c->esslen = essid->wl_essid_length;
			c->configuration |= IWM_CONFIG_ESSID;
			mutex_exit(&sc->lock);
		}
		iwm_operation_exit(sc);
		/* WPA ESSID precedes wpad; only a pinned open path commits. */
		if (error == 0 && iwm_open_ready(sc))
			error = iwm_connect_request(sc, NULL);
		mutex_exit(&c->crypto_lock);
		return (error);
	}
	if (id == MAC_PROP_WL_ENCRYPTION || id == MAC_PROP_WL_AUTH_MODE ||
	    id == MAC_PROP_WL_BSSTYPE || id == MAC_PROP_WL_PHY_CONFIG) {
		if (id == MAC_PROP_WL_PHY_CONFIG) {
			size_t offset = offsetof(wl_dsss_t, wl_dsss_channel);

			if (size != sizeof (*phy) ||
			    phy->wl_phy_dsss_conf.wl_dsss_channel == 0 ||
			    phy->wl_phy_dsss_conf.wl_dsss_channel > 13)
				return (EINVAL);
			/* libdladm leaves non-channel fields unset. */
			for (i = 0; i < sizeof (*phy); i++) {
				if (i >= offset &&
				    i < offset + sizeof (uint32_t))
					continue;
				if (address[i] != 0xff)
					return (ENOTSUP);
			}
		} else {
			if (size != sizeof (scalar))
				return (EINVAL);
			bcopy(value, &scalar, sizeof (scalar));
			if ((id == MAC_PROP_WL_ENCRYPTION &&
			    scalar != WL_NOENCRYPTION) ||
			    (id == MAC_PROP_WL_AUTH_MODE &&
			    scalar != WL_OPENSYSTEM) ||
			    (id == MAC_PROP_WL_BSSTYPE && scalar != WL_BSS_BSS))
				return (ENOTSUP);
		}
		mutex_enter(&c->crypto_lock);
		if ((error = iwm_operation_enter(sc, IWM_OP_SELECT)) != 0) {
			mutex_exit(&c->crypto_lock);
			return (error);
		}
		mutex_enter(&sc->lock);
		if (c->pending || c->resetting || !sc->net_attached)
			error = EBUSY;
		else if (id == MAC_PROP_WL_PHY_CONFIG) {
			c->channel = phy->wl_phy_dsss_conf.wl_dsss_channel;
			c->configuration |= IWM_CONFIG_CHANNEL;
		} else if (id == MAC_PROP_WL_ENCRYPTION) {
			if (c->wpa)
				error = EBUSY;
			else
				c->configuration |= IWM_CONFIG_OPEN;
		} else if (id == MAC_PROP_WL_AUTH_MODE)
			c->configuration |= IWM_CONFIG_AUTH;
		else
			c->configuration |= IWM_CONFIG_BSSTYPE;
		mutex_exit(&sc->lock);
		iwm_operation_exit(sc);
		mutex_exit(&c->crypto_lock);
		return (error);
	}
	if (id != MAC_PROP_WL_BSSID)
		return (ENOTSUP);
	if (size != sizeof (wl_bssid_t) || value == NULL)
		return (EINVAL);
	for (i = 0; i < IEEE80211_ADDR_LEN; i++)
		nonzero |= address[i];
	if (nonzero == 0 || (address[0] & 1) != 0)
		return (EINVAL);
	mutex_enter(&c->crypto_lock);
	if ((error = iwm_operation_enter(sc, IWM_OP_SELECT)) != 0) {
		mutex_exit(&c->crypto_lock);
		return (error);
	}
	mutex_enter(&sc->lock);
	if (!sc->net_attached || !sc->mac_registered)
		error = ENXIO;
	else if (c->pending || c->resetting || sc->associated_bssid_valid ||
	    (sc->runtime_owners & IWM_RUNTIME_CONNECT) != 0)
		error = EBUSY;
	else {
		bcopy(address, sc->desired_bssid, IEEE80211_ADDR_LEN);
		sc->desired_bssid_valid = B_TRUE;
	}
	mutex_exit(&sc->lock);
	iwm_operation_exit(sc);
	mutex_exit(&c->crypto_lock);
	return (error);
}

static int
iwm_m_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, void *value)
{
	struct iwm_softc *sc = arg;
	struct iwm_ess_snapshot snapshot;
	struct ieee80211_node *node;
	size_t used;
	int error;

	if (id == MAC_PROP_WL_BSSID) {
		if (size < sizeof (wl_bssid_t))
			return (ENOSPC);
		mutex_enter(&sc->lock);
		if (sc->associated_bssid_valid)
			bcopy(sc->associated_bssid, value, sizeof (wl_bssid_t));
		else if (sc->connection.wpa && sc->connection.pending &&
		    sc->connection.node != NULL && !sc->connection.cancel &&
		    sc->connection.tx_admission &&
		    sc->ic.ic_state == IEEE80211_S_RUN)
			/* Native RUN can queue EVENT_ASSOC before returning. */
			bcopy(sc->connection.node->in_bssid, value,
			    sizeof (wl_bssid_t));
		else
			bzero(value, sizeof (wl_bssid_t));
		mutex_exit(&sc->lock);
		return (0);
	}
	if (id == MAC_PROP_WL_LINKSTATUS) {
		if (size < sizeof (wl_linkstatus_t))
			return (ENOSPC);
		if (sc->connection.wpa)
			return (ieee80211_getprop(&sc->ic, name, id,
			    size, value));
		mutex_enter(&sc->lock);
		*(wl_linkstatus_t *)value = sc->connection.running ?
		    WL_CONNECTED : WL_NOTCONNECTED;
		mutex_exit(&sc->lock);
		return (0);
	}
	if (id == MAC_PROP_WL_ESSID) {
		wl_essid_t *essid = value;

		if (size < sizeof (*essid))
			return (ENOSPC);
		bzero(essid, sizeof (*essid));
		mutex_enter(&sc->lock);
		if (sc->connection.configuration & IWM_CONFIG_ESSID) {
			essid->wl_essid_length = sc->connection.esslen;
			bcopy(sc->connection.essid, essid->wl_essid_essid,
			    sc->connection.esslen);
		}
		mutex_exit(&sc->lock);
		return (0);
	}
	if (id == MAC_PROP_WL_ENCRYPTION) {
		if (size < sizeof (wl_encryption_t))
			return (ENOSPC);
		*(wl_encryption_t *)value = sc->connection.wpa ?
		    WL_ENC_WPA : WL_NOENCRYPTION;
		return (0);
	}
	if (id == MAC_PROP_WL_CAPABILITY || id == MAC_PROP_WL_WPA ||
	    id == MAC_PROP_WL_RSSI) {
		if (size < sizeof (uint32_t))
			return (ENOSPC);
		return (ieee80211_getprop(&sc->ic, name, id,
			    size, value));
	}
	if (id == MAC_PROP_WL_SCANRESULTS) {
		wl_wpa_ess_t *results = value;
		struct wpa_ess *entry;
		size_t count = 0, capacity;

		if (size < offsetof(wl_wpa_ess_t, ess))
			return (ENOSPC);
		capacity = (size - offsetof(wl_wpa_ess_t, ess)) /
		    sizeof (*entry);
		results->count = 0;
		mutex_enter(&sc->ic.ic_scan.nt_nodelock);
		for (node = list_head(&sc->ic.ic_scan.nt_node); node != NULL;
		    node = list_next(&sc->ic.ic_scan.nt_node, node)) {
			if (node->in_chan == IEEE80211_CHAN_ANYC ||
			    node->in_wpa_ie == NULL ||
			    node->in_esslen > sizeof (entry->ssid) ||
			    iwm_rsn_check(node->in_wpa_ie,
			    node->in_wpa_ie[1] + 2) != 0)
				continue;
			if (count == capacity) {
				mutex_exit(&sc->ic.ic_scan.nt_nodelock);
				return (ENOSPC);
			}
			entry = &results->ess[count++];
			bzero(entry, sizeof (*entry));
			bcopy(node->in_bssid, entry->bssid,
			    sizeof (entry->bssid));
			entry->ssid_len = node->in_esslen;
			bcopy(node->in_essid, entry->ssid, entry->ssid_len);
			entry->freq = node->in_chan->ich_freq;
			entry->wpa_ie_len = node->in_wpa_ie[1] + 2;
			bcopy(node->in_wpa_ie, entry->wpa_ie,
			    entry->wpa_ie_len);
		}
		mutex_exit(&sc->ic.ic_scan.nt_nodelock);
		results->count = count;
		return (0);
	}
	if (id != MAC_PROP_WL_ESS_LIST)
		return (ENOTSUP);
	if (size < offsetof(wl_ess_list_t, wl_ess_list_ess))
		return (ENOSPC);
	if ((error = iwm_operation_enter(sc, IWM_OP_READ)) != 0)
		return (error);
	if (!sc->net_attached) {
		iwm_operation_exit(sc);
		return (ENXIO);
	}
	if (sc->connection.pending) {
		iwm_operation_exit(sc);
		return (EBUSY);
	}
	snapshot.sc = sc;
	snapshot.size = MAX_BUF_LEN;
	snapshot.list = kmem_zalloc(snapshot.size, KM_SLEEP);
	snapshot.error = 0;
	mutex_enter(&sc->ic.ic_scan.nt_nodelock);
	for (node = list_head(&sc->ic.ic_scan.nt_node); node != NULL;
	    node = list_next(&sc->ic.ic_scan.nt_node, node)) {
		if (node->in_chan != IEEE80211_CHAN_ANYC)
			iwm_ess_node(&snapshot, node);
	}
	mutex_exit(&sc->ic.ic_scan.nt_nodelock);
	error = snapshot.error;
	used = offsetof(wl_ess_list_t, wl_ess_list_ess) +
	    snapshot.list->wl_ess_list_num * sizeof (wl_ess_conf_t);
	if (error == 0 && used > size)
		error = ENOSPC;
	if (error == 0 && iwm_checkpoint(sc, "esslist-snapshot") != 0)
		error = EIO;
	if (error == 0)
		bcopy(snapshot.list, value, used);
	kmem_free(snapshot.list, snapshot.size);
	iwm_operation_exit(sc);
	return (error);
}

static void
iwm_m_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t handle)
{
	_NOTE(ARGUNUSED(arg, name))
	if (id == MAC_PROP_WL_BSSID || id == MAC_PROP_WL_ESSID ||
	    id == MAC_PROP_WL_ENCRYPTION || id == MAC_PROP_WL_AUTH_MODE ||
	    id == MAC_PROP_WL_BSSTYPE || id == MAC_PROP_WL_PHY_CONFIG ||
	    id == MAC_PROP_WL_WPA || id == MAC_PROP_WL_KEY ||
	    id == MAC_PROP_WL_DELKEY || id == MAC_PROP_WL_SETOPTIE ||
	    id == MAC_PROP_WL_MLME) {
		mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
		return;
	}
	mac_prop_info_set_perm(handle,
	    id == MAC_PROP_WL_LINKSTATUS || id == MAC_PROP_WL_ESS_LIST ||
	    id == MAC_PROP_WL_CAPABILITY || id == MAC_PROP_WL_SCANRESULTS ||
	    id == MAC_PROP_WL_RSSI ?
	    MAC_PROP_PERM_READ : 0);
}

static int
iwm_scan_ioctl_check(const struct iocblk *ioc, const wldp_t *request,
    size_t size, boolean_t chained)
{
	if (ioc->ioc_cmd != WLAN_COMMAND)
		return (ENOTSUP);
	if (chained || size < sizeof (*request) ||
	    ioc->ioc_count < sizeof (*request) || ioc->ioc_count > size)
		return (EINVAL);
	if (request->wldp_type != NET_802_11 ||
	    (request->wldp_id != WL_SCAN &&
	    request->wldp_id != WL_DISASSOCIATE))
		return (ENOTSUP);
	if (request->wldp_length < WIFI_BUF_OFFSET ||
	    request->wldp_length > MAX_BUF_LEN)
		return (EINVAL);
	return (0);
}

static void
iwm_m_ioctl(void *arg, queue_t *queue, mblk_t *mp)
{
	struct iwm_softc *sc = arg;
	struct iocblk *ioc;
	wldp_t *request;
	int error;

	if (MBLKL(mp) < sizeof (*ioc)) {
		merror(queue, mp, EINVAL);
		return;
	}
	if (mp->b_cont == NULL) {
		miocnak(queue, mp, 0, EINVAL);
		return;
	}
	ioc = (void *)mp->b_rptr;
	request = (void *)mp->b_cont->b_rptr;
	error = iwm_scan_ioctl_check(ioc, request, MBLKL(mp->b_cont),
	    mp->b_cont->b_cont != NULL);
	if (error == 0)
		error = secpolicy_dl_config(ioc->ioc_cr);
	if (error != 0) {
		miocnak(queue, mp, 0, error);
		return;
	}
	if (request->wldp_id == WL_DISASSOCIATE) {
		/* DLD's ioctl task holds no MAC perimeter across this wait. */
		error = iwm_connection_disconnect(sc);
	} else if ((error = iwm_operation_enter(sc, IWM_OP_SCAN)) == 0) {
		if (sc->connection.pending)
			error = EBUSY;
		else if (!sc->runtime_started || !sc->net_attached)
			error = ENXIO;
		else
			error = iwm_public_scan(sc);
		iwm_operation_exit(sc);
		if (error == 0 && (sc->ic.ic_flags & IEEE80211_F_WPA))
			/* Publish only after releasing SCAN serialization. */
			ieee80211_end_scan(&sc->ic);
	}
	if (error != 0) {
		miocnak(queue, mp, 0, error);
		return;
	}
	request->wldp_length = WIFI_BUF_OFFSET;
	request->wldp_result = WL_SUCCESS;
	mp->b_cont->b_wptr = mp->b_cont->b_rptr + WIFI_BUF_OFFSET;
	miocack(queue, mp, WIFI_BUF_OFFSET, 0);
}

static mac_callbacks_t iwm_m_callbacks = {
	.mc_callbacks = MC_IOCTL | MC_GETPROP | MC_PROPINFO | MC_SETPROP,
	.mc_getstat = iwm_m_stat,
	.mc_start = iwm_m_start,
	.mc_stop = iwm_m_stop,
	.mc_setpromisc = iwm_m_promisc,
	.mc_multicst = iwm_m_multicst,
	.mc_unicst = iwm_m_unicst,
	.mc_tx = iwm_m_tx,
	.mc_ioctl = iwm_m_ioctl,
	.mc_getprop = iwm_m_getprop,
	.mc_setprop = iwm_m_setprop,
	.mc_propinfo = iwm_m_propinfo
};

static int
iwm_public_register(struct iwm_softc *sc)
{
	mac_register_t *registration;
	char name[32];
	int error, instance = ddi_get_instance(sc->dip);

	if ((error = iwm_preinit(sc)) != 0 ||
	    (error = iwm_scan_attach(sc)) != 0)
		return (error);
	sc->connection.taskq = taskq_create("iwm_connection", 1, minclsyspri,
	    1, 1, TASKQ_PREPOPULATE);
	if (sc->connection.taskq == NULL)
		return (ENOMEM);
	sc->wifi.wd_opmode = IEEE80211_M_STA;
	sc->wifi.wd_secalloc = WIFI_SEC_NONE;
	bcopy(sc->identity.mac, sc->wifi.wd_bssid, IEEE80211_ADDR_LEN);
	registration = mac_alloc(MAC_VERSION);
	if (registration == NULL)
		return (ENOMEM);
	registration->m_type_ident = MAC_PLUGIN_IDENT_WIFI;
	registration->m_driver = sc;
	registration->m_dip = sc->dip;
	registration->m_src_addr = sc->identity.mac;
	registration->m_callbacks = &iwm_m_callbacks;
	registration->m_min_sdu = 0;
	registration->m_max_sdu = IEEE80211_MTU;
	registration->m_pdata = &sc->wifi;
	registration->m_pdata_size = sizeof (sc->wifi);
	error = mac_register(registration, &sc->ic.ic_mach);
	mac_free(registration);
	if (error != 0)
		return (error);
	sc->mac_registered = B_TRUE;
	mac_link_update(sc->ic.ic_mach, LINK_STATE_DOWN);
	if (iwm_checkpoint(sc, "public-mac-registered") != 0)
		return (EIO);
	(void) snprintf(name, sizeof (name), "iwm%d", instance);
	if (ddi_create_minor_node(sc->dip, name, S_IFCHR, instance + 1,
	    DDI_NT_NET_WIFI, 0) != DDI_SUCCESS)
		return (EIO);
	sc->minor_created = B_TRUE;
	return (0);
}

/* Framework calls are made with neither driver mutex held. */
static int
iwm_public_unregister(struct iwm_softc *sc)
{
	int error;

	mutex_enter(&sc->operation_lock);
	sc->detach_requested = B_TRUE;
	mutex_exit(&sc->operation_lock);
	if (sc->mac_registered && (error = mac_disable(sc->ic.ic_mach)) != 0) {
		mutex_enter(&sc->operation_lock);
		sc->detach_requested = B_FALSE;
		mutex_exit(&sc->operation_lock);
		return (error);
	}
	if (sc->connection.taskq != NULL &&
	    (error = iwm_connection_disconnect(sc)) != 0)
		return (error);
	if (sc->connection.taskq != NULL)
		taskq_wait(sc->connection.taskq);
	iwm_m_stop(sc);
	if ((error = iwm_operation_enter(sc, IWM_OP_DETACH)) != 0)
		return (error);
	if (sc->run != NULL || sc->runtime_stop_error != 0) {
		error = EIO;
		goto out;
	}
	if (sc->net_attached && (error = ieee80211_wpa_quiesce(&sc->ic,
	    ddi_get_lbolt() + drv_usectohz(5000000))) != 0)
		goto out;
	if (sc->minor_created) {
		ddi_remove_minor_node(sc->dip, NULL);
		sc->minor_created = B_FALSE;
	}
	if (sc->mac_registered) {
		if ((error = mac_unregister(sc->ic.ic_mach)) != 0)
			goto out;
		sc->mac_registered = B_FALSE;
		sc->ic.ic_mach = NULL;
	}
	error = iwm_scan_detach(sc);
	if (error == 0 && sc->connection.taskq != NULL) {
		taskq_destroy(sc->connection.taskq);
		sc->connection.taskq = NULL;
	}
out:
	iwm_operation_exit(sc);
	return (error);
}

static int
iwm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct iwm_softc *sc;
	int instance = ddi_get_instance(dip);
	uint16_t command;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if (ddi_soft_state_zalloc(iwm_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	sc = ddi_get_soft_state(iwm_state, instance);
	sc->dip = dip;
	mutex_init(&sc->operation_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sc->operation_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->connection.cv, NULL, CV_DRIVER, NULL);
	mutex_init(&sc->connection.crypto_lock, NULL, MUTEX_DRIVER, NULL);
	sc->operation_initialized = B_TRUE;
	sc->public_enabled = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "iwm-public-scan", 0) != 0;
	ddi_set_driver_private(dip, sc);
	sc->fail_step = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "iwm-attach-fail", 0);
	if (sc->fail_step < 0 || sc->fail_step > 4096 ||
	    iwm_checkpoint(sc, "soft-state") != 0 ||
	    iwm_pci_map(sc) != 0 || iwm_passive_csr(sc) != 0 ||
	    iwm_intr_open(sc) != 0)
		goto fail;
	if (iwm_base_dma_alloc(sc) != 0)
		goto fail;
	if (iwm_intr_test(sc) != 0)
		goto fail;
	command = pci_config_get16(sc->pcih, PCI_CONF_COMM);
	if ((command ^ sc->pci_command) & PCI_COMM_ME)
		goto fail;
	if (sc->public_enabled) {
		if (iwm_public_register(sc) != 0)
			goto fail;
	} else if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "iwm-init-nvm", 0) != 0 && iwm_init_nvm(sc) != 0)
		goto fail;
	sc->attached = B_TRUE;
	dev_err(dip, CE_NOTE, "!iwm attach complete, %d checkpoints; "
	    "PCI command=%04x; public=%u",
	    sc->attach_step, command, sc->mac_registered);
	return (DDI_SUCCESS);

fail:
	dev_err(dip, CE_WARN, "!iwm attach failed at step %d",
	    sc->attach_step);
	if (iwm_cleanup(sc) != 0) {
		/* Pin the retained handler's devinfo until recovery reboot. */
		ndi_hold_devi(dip);
		atomic_inc_32(&iwm_retained);
		dev_err(dip, CE_WARN, "!iwm cleanup failed; resources retained;"
		    " module removal prohibited");
		return (DDI_FAILURE);
	}
	ddi_set_driver_private(dip, NULL);
	ddi_soft_state_free(iwm_state, instance);
	dev_err(dip, CE_NOTE, "!iwm failed attach fully unwound");
	return (DDI_FAILURE);
}

/* Suspend/resume remain unsupported; a full detach releases every resource. */
static int
iwm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct iwm_softc *sc = ddi_get_driver_private(dip);

	if (cmd != DDI_DETACH || sc == NULL || !sc->attached)
		return (DDI_FAILURE);
	if (iwm_cleanup(sc) != 0) {
		dev_err(dip, CE_WARN, "!iwm detach cleanup failed; retained");
		return (DDI_FAILURE);
	}
	ddi_set_driver_private(dip, NULL);
	ddi_soft_state_free(iwm_state, ddi_get_instance(dip));
	dev_err(dip, CE_NOTE, "!iwm detach complete");
	return (DDI_SUCCESS);
}

static int
iwm_quiesce(dev_info_t *dip)
{
	struct iwm_softc *sc = ddi_get_driver_private(dip);

	/* No locks, sleeping, interrupt teardown or mapping teardown here. */
	if (sc == NULL || !sc->csr_valid ||
	    iwm_mask(sc) != 0)
		return (DDI_FAILURE);
	return (iwm_run_quiesce(sc) == 0 ? DDI_SUCCESS : DDI_FAILURE);
}

DDI_DEFINE_STREAM_OPS(iwm_devops, nulldev, nulldev, iwm_attach,
    iwm_detach, nodev, NULL, D_MP, NULL, iwm_quiesce);

static struct modldrv iwm_modldrv = {
	&mod_driverops,
	"Intel 8260 INIT transport",
	&iwm_devops
};

static struct modlinkage iwm_modlinkage = {
	MODREV_1, { &iwm_modldrv, NULL }
};

int
_init(void)
{
	int error;

	error = ddi_soft_state_init(&iwm_state, sizeof (struct iwm_softc), 1);
	if (error != 0)
		return (error);
	mac_init_ops(&iwm_devops, "iwm");
	if (iwm_devops.devo_cb_ops->cb_str == NULL) {
		ddi_soft_state_fini(&iwm_state);
		return (ENXIO);
	}
	error = mod_install(&iwm_modlinkage);
	if (error != 0) {
		mac_fini_ops(&iwm_devops);
		ddi_soft_state_fini(&iwm_state);
	}
	return (error);
}

int
_fini(void)
{
	int error;

	/* Also covers retained ownership after a failed attach or cleanup. */
	if (iwm_retained != 0)
		return (EBUSY);
	error = mod_remove(&iwm_modlinkage);

	if (error == 0) {
		mac_fini_ops(&iwm_devops);
		ddi_soft_state_fini(&iwm_state);
	}
	return (error);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&iwm_modlinkage, mip));
}
