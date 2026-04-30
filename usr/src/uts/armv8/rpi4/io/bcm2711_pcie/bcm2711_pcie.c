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
 * Derived from:
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
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * PCIe root complex driver for the BCM2711 SoC, as used in the Raspberry Pi 4.
 *
 * The BCM2711 contains a single PCIe Gen 2 x1 root complex integrated into the
 * SoC.  The PCIe controller is a custom Broadcom design that interfaces
 * upstream to the SoC's AXI interconnect and downstream to a single PCIe lane
 * connected to the VL805 USB 3.0 xHCI controller on the RPi4.  The controller
 * also contains a built-in MSI controller that converts MSI writes from
 * downstream devices into a single GIC SPI as well as the usual legacy INTx
 * lines.  The controller's firmware lives externally (in the RPi4's SPI flash)
 * and must be loaded by an external actor (the VideoCore GPU via a mailbox
 * property tag write) before the controller is usable.
 *
 * The driver departs fairly significantly from the standard pcierc
 * implementation.  In order to work around hardware quirks and limitations, it
 * must interpose on config space accesses to redirect indices, check link
 * status (avoid CPU aborts), and handle the VL805 firmware load.  It also
 * needs to manage the controller's MSI and legacy interrupt masking to ensure
 * that interrupts flow when enabled.
 *
 * The driver only supports a single downstream device (the VL805) and does not
 * attempt to support hotplug or power management features beyond what can be
 * automatically handled by the hardware.
 *
 * The built-in MSI controller is quite simple and supports up to 32 MSI
 * vectors with a fixed target address and a configurable mask/match pattern
 * for vector extraction from the data value.  The MSI write address is
 * intercepted by the controller and cannot overlap with the ranges used for
 * DMA.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include <sys/ddi_intr.h>
#include <sys/ddi_intr_impl.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>

#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/pci_cfgacc.h>
#include <sys/pcie.h>

#include <sys/bcm2835_mbox.h>
#include <sys/bcm2835_vcprop.h>
#include <sys/pcie_impl.h>

#include <sys/mach_intr.h>

#include <pcierc.h>

#define	BCM2711_CLASS_CODE_BRIDGE_PCI	0x060400
/*
 * RGR1_SW_INIT_1 register - controls bridge software init and PERST#.
 * Bit 0 (PERST#): 1 = assert, 0 = deassert.
 * Bit 1 (SW_INIT): 1 = bridge in reset, 0 = bridge out of reset.
 */
#define	BCM2711_REG_RGR1_SW_INIT_1	0x9210
#define	BCM2711_RGR1_PERST_MASK		0x1
#define	BCM2711_RGR1_SW_INIT_MASK	0x2

/*
 * MDIO interface registers
 */
#define	BCM2711_REG_MDIO_ADDR		0x1100
#define	BCM2711_MDIO_PORT_MASK		(0xf << 16)
#define	BCM2711_MDIO_PORT_SHIFT		16
#define	BCM2711_MDIO_REGAD_MASK		(0xffff << 0)
#define	BCM2711_MDIO_REGAD_SHIFT	0
#define	BCM2711_MDIO_CMD_READ		(1 << 20)
#define	BCM2711_MDIO_CMD_WRITE		(0 << 20)
#define	BCM2711_REG_MDIO_WR_DATA	0x1104
#define	BCM2711_REG_MDIO_RD_DATA	0x1108
#define	BCM2711_MDIO_DATA_DONE		(1U << 31)
#define	BCM2711_MDIO_DATA_MASK		(0x7fffffff << 0)

/*
 * MDIO registers
 */
#define	MDIO_SET_ADDR			0x1f
#define	MDIO_SSC_REGS_ADDR		0x1100

#define	MDIO_SSC_STATUS			0x01
#define	MDIO_SSC_STATUS_SSC		(1 << 10)
#define	MDIO_SSC_STATUS_PLL_LOCK	(1 << 11)
#define	MDIO_SSC_CNTL			0x02
#define	MDIO_SSC_CNTL_OVRD_EN		(1 << 15)
#define	MDIO_SSC_CNTL_OVRD_VAL		(1 << 14)

/*
 * MISC_CTRL register - burst size, SCB access, read completion boundary.
 */
#define	BCM2711_REG_MISC_CTRL		0x4008
#define	BCM2711_MISC_CTRL_RCB_64B_MODE	(1 << 7)
#define	BCM2711_MISC_CTRL_RCB_MPS_MODE	(1 << 10)
#define	BCM2711_MISC_CTRL_SCB_ACCESS_EN	(1 << 12)
#define	BCM2711_MISC_CTRL_CFG_READ_UR	(1 << 13)
#define	BCM2711_MISC_CTRL_MAX_BURST_MASK 0x300000
#define	BCM2711_MISC_CTRL_MAX_BURST_128	(0 << 20)
#define	BCM2711_MISC_CTRL_MAX_BURST_256	(1 << 20)
#define	BCM2711_MISC_CTRL_MAX_BURST_512	(2 << 20)
#define	BCM2711_MISC_CTRL_SCB0_SIZE_MASK 0xf8000000
#define	BCM2711_MISC_CTRL_SCB0_SIZE_SHIFT 27

/*
 * HARD_DEBUG register - SerDes power and debug controls.
 */
#define	BCM2711_REG_PCIE_HARD_DEBUG	0x4204
#define	BCM2711_HARD_DEBUG_CLKREQ_DEBUG_ENABLE	(1 << 0)
#define	BCM2711_HARD_DEBUG_REFCLK_OVRD_ENABLE	(1 << 16)
#define	BCM2711_HARD_DEBUG_REFCLK_OVRD_OUT	(1 << 20)
#define	BCM2711_HARD_DEBUG_L1SS_ENABLE		(1 << 21)
#define	BCM2711_HARD_DEBUG_SERDES_IDDQ		(1 << 27)
#define	BCM2711_HARD_DEBUG_CLKREQ_MASK		( \
	BCM2711_HARD_DEBUG_CLKREQ_DEBUG_ENABLE | \
	BCM2711_HARD_DEBUG_REFCLK_OVRD_ENABLE | \
	BCM2711_HARD_DEBUG_REFCLK_OVRD_OUT | \
	BCM2711_HARD_DEBUG_L1SS_ENABLE)

/*
 * PCIE_STATUS register - link status bits.
 */
#define	BCM2711_REG_PCIE_STATUS		0x4068
#define	BCM2711_STATUS_PHYLINKUP	(1 << 4)
#define	BCM2711_STATUS_DL_ACTIVE	(1 << 5)

/*
 * Private config space register for bridge class code identification.
 */
#define	BCM2711_REG_PRIV1_ID_VAL3	0x043c
#define	BCM2711_ID_VAL3_CLASS_CODE_MASK	0xffffff

/*
 * PCIe link status in config space.
 */
#define	BCM2711_REG_BRIDGE_LINK_STATE	0x00bc

/*
 * Hardware revision register.
 */
#define	BCM2711_REG_CONTROLLER_HW_REV	0x406c

/*
 * Root complex private control registers.
 */
#define	BCM2711_REG_RC_CFG_PRIV1_LINK_CAP	0x04dc
#define	BCM2711_RC_CFG_PRIV1_LINK_CAP_MAX_LINK_WIDTH_MASK	(0x1f << 4)
#define	BCM2711_RC_CFG_PRIV1_LINK_CAP_ASPM_SUPPORT_MASK		(0x3 << 10)
#define	BCM2711_REG_RC_CFG_PRIV1_ROOT_CAP	0x04f8
#define	BCM2711_RC_CFG_PRIV1_ROOT_CAP_L1SS_MODE_MASK		(0x1f << 3)
#define	BCM2711_RC_CFG_PRIV1_ROOT_CAP_L1SS_MODE_SHIFT		3

/*
 * Outbound window registers (CPU->PCI MMIO translation).
 * Programs the address translation from CPU physical addresses to
 * PCIe bus addresses for MMIO access to downstream devices.
 */
#define	BCM2711_REG_MEM_WIN0_LO(win) \
	(0x400c + ((win) * 8))
#define	BCM2711_REG_MEM_WIN0_HI(win) \
	(0x4010 + ((win) * 8))
#define	BCM2711_REG_MEM_WIN0_BASE_LIMIT(win) \
	(0x4070 + ((win) * 4))
#define	BCM2711_REG_MEM_WIN0_BASE_HI(win) \
	(0x4080 + ((win) * 8))
#define	BCM2711_REG_MEM_WIN0_LIMIT_HI(win) \
	(0x4084 + ((win) * 8))

#define	BCM2711_MEM_WIN0_BASE_LIMIT_BASE_MASK	0xfff0
#define	BCM2711_MEM_WIN0_BASE_LIMIT_BASE_SHIFT	4
#define	BCM2711_MEM_WIN0_BASE_LIMIT_LIMIT_MASK	0xfff00000
#define	BCM2711_MEM_WIN0_BASE_LIMIT_LIMIT_SHIFT	20
#define	BCM2711_MEM_WIN0_BASE_HI_MASK		0xff
#define	BCM2711_MEM_WIN0_LIMIT_HI_MASK		0xff

/*
 * Number of low-order bits in the BASE_LIMIT register's base field.
 * The upper bits of the MB address go into the separate BASE_HI register.
 * HWEIGHT32(0xfff0) = 12.
 */
#define	BCM2711_MEM_WIN0_BASE_LIMIT_NBITS	12

/*
 * Inbound window (PCI->CPU DMA) BAR configuration.
 * Programs the BAR registers that control the address translation
 * from PCIe bus addresses (used by devices for DMA) to CPU physical
 * addresses.
 */
#define	BCM2711_REG_RC_BAR1_CONFIG_LO	0x402c
#define	BCM2711_REG_RC_BAR2_CONFIG_LO	0x4034
#define	BCM2711_REG_RC_BAR2_CONFIG_HI	0x4038
#define	BCM2711_REG_RC_BAR3_CONFIG_LO	0x403c
#define	BCM2711_RC_BAR_CONFIG_LO_SIZE_MASK 0x1f

/*
 * Endian mode for inbound window.
 */
#define	BCM2711_REG_VENDOR_SPECIFIC_REG1 0x0188
#define	BCM2711_VENDOR_REG1_ENDIAN_MODE_BAR2_MASK 0xc
#define	BCM2711_VENDOR_REG1_LITTLE_ENDIAN 0x0

/* Config space access aperture for non-root devices. */
#define	BCM2711_DEV_CFG_DATA		0x8000
#define	BCM2711_DEV_CFG_INDEX		0x9000

#define	BCM2711_MAX_BUS			1

/*
 * VL805 USB 3.0 xHCI controller - always at bus 1, dev 0, func 0 on
 * the RPi4's single PCIe lane.  Its firmware lives in SPI flash and
 * must be loaded by the VideoCore GPU via a mailbox property tag
 * before the controller is usable.
 */
#define	VL805_VENDOR_ID			0x1106
#define	VL805_DEVICE_ID			0x3483

/*
 * Built-in MSI controller registers.
 *
 * The BCM2711 PCIe wrapper contains a dedicated MSI controller that
 * intercepts MSI writes from downstream devices and converts them into
 * a single GIC SPI.  Software demultiplexes via a 32-bit status register.
 *
 * MSI_BAR_CONFIG_LO/HI program the bus address that devices write to
 * when generating MSIs.  Bit 0 of LO is the enable bit.
 * MSI_DATA_CONFIG encodes the mask/match pattern used to extract the
 * vector number from the data value written by the device.
 */
#define	BCM2711_MSI_BAR_CONFIG_LO	0x4044
#define	BCM2711_MSI_BAR_CONFIG_HI	0x4048
#define	BCM2711_MSI_DATA_CONFIG		0x404c

#define	BCM2711_INTR2_BASE		0x4300
#define	BCM2711_INTR2_STATUS		(BCM2711_INTR2_BASE + 0x00)
#define	BCM2711_INTR2_SET		(BCM2711_INTR2_BASE + 0x04)
#define	BCM2711_INTR2_CLR		(BCM2711_INTR2_BASE + 0x08)
#define	BCM2711_INTR2_MASK_STATUS	(BCM2711_INTR2_BASE + 0x0c)
#define	BCM2711_INTR2_MASK_SET		(BCM2711_INTR2_BASE + 0x10)
#define	BCM2711_INTR2_MASK_CLR		(BCM2711_INTR2_BASE + 0x14)

#define	BCM2711_MSI_INTR2_BASE		0x4500
#define	BCM2711_MSI_INT_STATUS		(BCM2711_MSI_INTR2_BASE + 0x00)
#define	BCM2711_MSI_INT_CLR		(BCM2711_MSI_INTR2_BASE + 0x08)
#define	BCM2711_MSI_INT_MASK_SET	(BCM2711_MSI_INTR2_BASE + 0x10)
#define	BCM2711_MSI_INT_MASK_CLR	(BCM2711_MSI_INTR2_BASE + 0x14)

/*
 * MSI EOI register.  A write of 1 strobes the controller to re-latch
 * the status register and re-assert the legacy interrupt if any vectors
 * are still pending.  Must be written after each BCM2711_MSI_INT_CLR
 * acknowledgement.
 */
#define	BCM2711_MSI_EOI			0x4060

#define	BCM2711_MSI_DATA_CONFIG_VAL_32	0xffe06540
#define	BCM2711_MSI_DATA_CONFIG_VAL_8	0xfff86540

#define	BCM2711_MSI_TARGET_ADDR		0x0fffffffcULL
#define	BCM2711_MSI_TARGET_ADDR_HI	0xffffffffcULL

#define	BCM2711_MSI_MAX_VECTORS		32
#define	BCM2711_MSI_IRQ_SHIFT		0
#define	BCM2711_MSI_LEGACY_VECTORS	8
#define	BCM2711_MSI_LEGACY_IRQ_SHIFT	24
#define	BCM2711_MSI_HW_REV_33		0x0303

/*
 * PCI ranges phys.hi type field (bits 25:24).
 */
#define	PCI_PHYS_HI_SPACE_MEM		0x02000000

/*
 * Megabyte constant used for outbound window address calculations.
 */
#define	SZ_1M				0x100000ULL

/*
 * Maximum number of outbound (CPU->PCIe) memory windows supported
 * by the BCM2711 hardware.
 */
#define	BCM2711_NUM_OUTBOUND_WINS	4

#define	BCM2711_PCIE_IRQ	0
#define	BCM2711_MSI_IRQ		1
#define	BCM2711_NUM_IRQ		2

typedef struct bcm2711_pcie_softc {
	dev_info_t		*bc_dip;
	ddi_acc_handle_t	bc_handle;
	caddr_t			bc_base;
	kmutex_t		bc_lock;
} bcm2711_pcie_softc_t;

static void *bcm2711_pcie_soft_state;

/*
 * Register access
 */

static uint32_t
bcm2711_pcie_read_reg(const bcm2711_pcie_softc_t *softc, uint32_t reg)
{
	return (ddi_get32(
	    softc->bc_handle, (uint32_t *)(softc->bc_base + reg)));
}

static void
bcm2711_pcie_write_reg(bcm2711_pcie_softc_t *softc, uint32_t reg,
    uint32_t val)
{
	ddi_put32(softc->bc_handle, (uint32_t *)(softc->bc_base + reg), val);
}

/*
 * Configuration space access
 */

static uint64_t
bcm2711_cfg_read_root(bcm2711_pcie_softc_t *softc, int bus, int dev, int func,
    int reg, size_t size)
{
	/*
	 * Requests to bus 0, the root complex, must also have device 0.
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
	uint32_t status;

	VERIFY3S(bus, !=, 0);

	/* we only support reads from bus 1 and device 0 */
	if (bus > BCM2711_MAX_BUS || dev != 0)
		return (PCI_EINVAL64);

	/*
	 * A config space access with the link down causes a CPU abort
	 * on this hardware.  Check link status before proceeding.
	 */
	status = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_STATUS);
	if (!(status & BCM2711_STATUS_DL_ACTIVE) ||
	    !(status & BCM2711_STATUS_PHYLINKUP))
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
	 * Requests to bus 0, the root complex, must also have device 0.
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
	uint32_t status;

	VERIFY3S(bus, !=, 0);

	/* we only support writes to bus 1 and device 0 */
	if (bus > BCM2711_MAX_BUS || dev != 0)
		return;

	/*
	 * A config space access with the link down causes a CPU abort
	 * on this hardware.  Check link status before proceeding.
	 */
	status = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_STATUS);
	if (!(status & BCM2711_STATUS_DL_ACTIVE) ||
	    !(status & BCM2711_STATUS_PHYLINKUP))
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

static void
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

static pcie_rc_data_t bcm2711_pcie_rc_data = {
	.pcie_rc_cfgspace_acc = bcm2711_cfgspace_acc,
};

/*
 * MDIO access
 */

static int
bcm2711_pcie_mdio_read(bcm2711_pcie_softc_t *sc, uint8_t port, uint16_t addr,
    uint32_t *data)
{
	uint32_t reg;
	int timo;

	ASSERT3U(port, <, 16);
	reg = BCM2711_MDIO_CMD_READ;
	reg |= ((uint32_t)port << BCM2711_MDIO_PORT_SHIFT);
	reg |= ((uint32_t)addr << BCM2711_MDIO_REGAD_SHIFT);
	bcm2711_pcie_write_reg(sc, BCM2711_REG_MDIO_ADDR, reg);
	(void) bcm2711_pcie_read_reg(sc, BCM2711_REG_MDIO_ADDR);

	for (timo = 10; timo > 0; timo--) {
		reg = bcm2711_pcie_read_reg(sc, BCM2711_REG_MDIO_RD_DATA);
		if (reg & BCM2711_MDIO_DATA_DONE)
			break;
		drv_usecwait(10);
	}
	if (timo == 0) {
		dev_err(sc->bc_dip, CE_WARN,
		    "timeout reading MDIO port %d reg %d", port, addr);
		return (DDI_FAILURE);
	}

	*data = reg & BCM2711_MDIO_DATA_MASK;
	return (DDI_SUCCESS);
}

static int
bcm2711_pcie_mdio_write(bcm2711_pcie_softc_t *sc, uint8_t port, uint16_t addr,
    uint32_t data)
{
	uint32_t reg;
	int timo;

	ASSERT3U(port, <, 16);
	reg = BCM2711_MDIO_CMD_WRITE;
	reg |= ((uint32_t)port << BCM2711_MDIO_PORT_SHIFT);
	reg |= ((uint32_t)addr << BCM2711_MDIO_REGAD_SHIFT);
	bcm2711_pcie_write_reg(sc, BCM2711_REG_MDIO_ADDR, reg);
	(void) bcm2711_pcie_read_reg(sc, BCM2711_REG_MDIO_ADDR);

	bcm2711_pcie_write_reg(sc, BCM2711_REG_MDIO_WR_DATA,
	    (data & BCM2711_MDIO_DATA_MASK) | BCM2711_MDIO_DATA_DONE);
	for (timo = 10; timo > 0; timo--) {
		reg = bcm2711_pcie_read_reg(sc, BCM2711_REG_MDIO_WR_DATA);
		if ((reg & BCM2711_MDIO_DATA_DONE) == 0)
			break;
		drv_usecwait(10);
	}
	if (timo == 0) {
		dev_err(sc->bc_dip, CE_WARN,
		    "timeout writing MDIO port %d reg %d", port, addr);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Augment SETMASK/CLRMASK and ENABLE/DISABLE operations for fixed interrupts
 * to also enable/disable the corresponding interrupt in the BCM2711's interrupt
 * built-in controller.  Without doing this additional work interrupts won't
 * flow.
 *
 * Somehow this doesn't seem to be necessary in other open-source operating
 * systems running on the same hardware, but it certainly is necessary here.
 *
 * hdlp->ih_inum is the interrupt number within the controller, which
 * for fixed interrupts is the same as the index into the controller's
 * interrupt status/mask registers.  For our purposes this means that
 * the mapping is:
 *   0: INTA
 *   1: INTB
 *   2: INTC
 *   3: INTD
 *
 * While we don't actively manage these legacy INTx interrupts, we
 * do need to interpose on masking/unmasking and enable/disable
 * operations so that we can be sure that interrupts do flow.
 *
 * There are a number of other bits that can be set and masked in these
 * registers, but those are undocumented and probably apply to the primary
 * PCIe interrupt vector - since we have no documentation we simply leave
 * them masked.
 */
static int
bcm2711_pcie_intr_ops(dev_info_t *pdip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	bcm2711_pcie_softc_t *softc;
	int ret;

	ret = pcierc_intr_ops(pdip, rdip, intr_op, hdlp, result);
	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	if (hdlp->ih_type != DDI_INTR_TYPE_FIXED) {
		return (ret);
	}

	VERIFY3S(hdlp->ih_inum, <=, 3);

	softc =
	    ddi_get_soft_state(bcm2711_pcie_soft_state, ddi_get_instance(pdip));
	VERIFY3P(softc, !=, NULL);

	switch (intr_op) {
	case DDI_INTROP_SETMASK:	/* fallthrough */
	case DDI_INTROP_DISABLE:
		DDI_INTR_NEXDBG((CE_CONT, "bcm2711_pcie_intr_ops: "
		    "masking fixed interrupt %d (vector %d)\n",
		    hdlp->ih_inum, hdlp->ih_vector));
		bcm2711_pcie_write_reg(softc,
		    BCM2711_INTR2_MASK_SET, 1U << hdlp->ih_inum);
		break;
	case DDI_INTROP_CLRMASK:	/* fallthrough */
	case DDI_INTROP_ENABLE:
		DDI_INTR_NEXDBG((CE_CONT, "bcm2711_pcie_intr_ops: "
		    "unmasking fixed interrupt %d (vector %d)\n",
		    hdlp->ih_inum, hdlp->ih_vector));
		bcm2711_pcie_write_reg(softc,
		    BCM2711_INTR2_MASK_CLR, 1U << hdlp->ih_inum);
		break;
	default:
		return (ret);
	}

	return (DDI_SUCCESS);
}

/*
 * Check whether the device behind the PCIe link is a VL805 xHCI controller
 * and, if so, ask the VideoCore firmware to load its firmware from SPI flash.
 *
 * The VL805 on the RPi4 has no non-volatile storage of its own; the firmware
 * image is stored in the Pi's SPI flash alongside the GPU firmware.  The GPU
 * loads it into the VL805 on request via mailbox property tag
 * VCPROPTAG_NOTIFY_XHCI_RESET (0x00030058).  Without this step the
 * controller's USB ports are non-functional.
 *
 * The device address passed to the firmware is encoded as:
 *   (bus << 20) | (dev << 15) | (func << 12)
 * which is the standard PCI B/D/F encoding used by the VideoCore firmware.
 *
 * This must be called after link-up and before pcierc_attach() enumerates
 * child devices, so that the xHCI driver (when it exists) finds the
 * controller in a usable state.
 */
static void
bcm2711_pcie_vl805_reset(bcm2711_pcie_softc_t *softc)
{
	uint32_t vendor_device;
	uint16_t vendor_id, device_id;
	uint32_t pci_dev_addr;
	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_notifyxhcireset xhci_reset;
		struct vcprop_tag		end;
	} req;

	/*
	 * Read the vendor/device ID of the device at bus 1, dev 0, func 0.
	 * On the RPi4 this is the only possible downstream device - the
	 * BCM2711 has a single PCIe Gen 2 x1 lane.
	 */
	mutex_enter(&softc->bc_lock);
	vendor_device = (uint32_t)bcm2711_cfg_read_dev(softc,
	    1, 0, 0, PCI_CONF_VENID, PCI_CFG_SIZE_DWORD);
	mutex_exit(&softc->bc_lock);

	vendor_id = vendor_device & 0xffff;
	device_id = (vendor_device >> 16) & 0xffff;

	if (vendor_id != VL805_VENDOR_ID || device_id != VL805_DEVICE_ID) {
		dev_err(softc->bc_dip, CE_CONT,
		    "?downstream device %04x:%04x is not a VL805, "
		    "skipping firmware load\n",
		    vendor_id, device_id);
		return;
	}

	/*
	 * Encode the PCI device address in the format the VideoCore
	 * firmware expects.
	 */
	pci_dev_addr = (1 << 20) | (0 << 15) | (0 << 12);

	VCPROP_INIT_REQUEST(req);
	VCPROP_INIT_TAG(req.xhci_reset, VCPROPTAG_NOTIFY_XHCI_RESET);
	req.xhci_reset.deviceaddress = pci_dev_addr;

	bcm2835_mbox_prop_send(&req, sizeof (req));

	if (!vcprop_buffer_success_p(&req.vb_hdr)) {
		dev_err(softc->bc_dip, CE_WARN,
		    "VL805 firmware load: mailbox request failed "
		    "(rcode 0x%x)", req.vb_hdr.vpb_rcode);
		return;
	}

	if (!vcprop_tag_success_p(&req.xhci_reset.tag)) {
		dev_err(softc->bc_dip, CE_WARN,
		    "VL805 firmware load: tag response failed "
		    "(rcode 0x%x)", req.xhci_reset.tag.vpt_rcode);
		return;
	}

	dev_err(softc->bc_dip, CE_CONT, "?VL805 xHCI firmware loaded");

	/*
	 * Allow the controller time to initialise after firmware load.
	 *
	 * There is no documentation about what is actually required, so
	 * this value comes from OpenBSD's sys/dev/fdt/bcm2711_pcie.c.
	 */
	drv_usecwait(200);
}

/*
 * Helpers used during attach, link setup, reset and detach.
 */

static void
bcm2711_pcie_perst_set(bcm2711_pcie_softc_t *softc, uint32_t assert)
{
	uint32_t val;

	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_RGR1_SW_INIT_1);
	if (assert)
		val |= BCM2711_RGR1_PERST_MASK;
	else
		val &= ~BCM2711_RGR1_PERST_MASK;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_RGR1_SW_INIT_1, val);
}

static void
bcm2711_pcie_bridge_sw_init_set(bcm2711_pcie_softc_t *softc,
    uint32_t assert)
{
	uint32_t val;

	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_RGR1_SW_INIT_1);
	if (assert)
		val |= BCM2711_RGR1_SW_INIT_MASK;
	else
		val &= ~BCM2711_RGR1_SW_INIT_MASK;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_RGR1_SW_INIT_1, val);
}

static int
bcm2711_pcie_setup_ssc(bcm2711_pcie_softc_t *sc)
{
	uint32_t reg;
	int ret;

	ret = bcm2711_pcie_mdio_write(sc, 0, MDIO_SET_ADDR, MDIO_SSC_REGS_ADDR);
	if (ret)
		return (ret);

	ret = bcm2711_pcie_mdio_read(sc, 0, MDIO_SSC_CNTL, &reg);
	if (ret)
		return (ret);
	reg |= (MDIO_SSC_CNTL_OVRD_VAL | MDIO_SSC_CNTL_OVRD_EN);
	ret = bcm2711_pcie_mdio_write(sc, 0, MDIO_SSC_CNTL, reg);
	if (ret)
		return (ret);
	delay(drv_usectohz(1000));

	ret = bcm2711_pcie_mdio_read(sc, 0, MDIO_SSC_STATUS, &reg);
	if (ret)
		return (ret);

	if ((reg & MDIO_SSC_STATUS_SSC) && (reg & MDIO_SSC_STATUS_PLL_LOCK))
		return (DDI_SUCCESS);

	return (DDI_FAILURE);
}

/*
 * Encode inbound BAR size to the non-linear 5-bit SIZE field used by
 * PCIE_MISC_RC_BAR[123]_CONFIG_LO.  Ported from the Linux pcie-brcmstb
 * driver's brcm_pcie_encode_ibar_size().
 *
 * The encoding is:
 *   4KB  - 32KB  (ilog2 12-15): value = (ilog2 - 12) + 0x1c
 *   64KB - 64GB  (ilog2 16-36): value = ilog2 - 15
 *   anything else:               0 (disabled)
 */
static uint32_t
bcm2711_pcie_encode_ibar_size(uint64_t size)
{
	int log2_in;

	if (size == 0)
		return (0);

	/* highbit64 returns 1-indexed position; subtract 1 for ilog2 */
	log2_in = highbit64(size) - 1;

	if (log2_in >= 12 && log2_in <= 15)
		return ((log2_in - 12) + 0x1c);
	else if (log2_in >= 16 && log2_in <= 36)
		return (log2_in - 15);

	return (0);
}

/*
 * Program one outbound (CPU->PCIe) memory window.
 *
 * Ported from the Linux pcie-brcmstb driver's brcm_pcie_set_outbound_win().
 * Addresses in the BASE_LIMIT register are expressed in megabytes.
 */
static void
bcm2711_pcie_set_outbound_win(bcm2711_pcie_softc_t *softc, uint8_t win,
    uint64_t cpu_addr, uint64_t pcie_addr, uint64_t size)
{
	uint64_t cpu_addr_mb, limit_addr_mb;
	uint32_t tmp;

	/* Set the base of the PCIe address window. */
	bcm2711_pcie_write_reg(softc, BCM2711_REG_MEM_WIN0_LO(win),
	    (uint32_t)(pcie_addr & 0xffffffffU));
	bcm2711_pcie_write_reg(softc, BCM2711_REG_MEM_WIN0_HI(win),
	    (uint32_t)(pcie_addr >> 32));

	/* Write the base & limit lower bits (in MBs). */
	cpu_addr_mb = cpu_addr / SZ_1M;
	limit_addr_mb = (cpu_addr + size - 1) / SZ_1M;

	tmp = bcm2711_pcie_read_reg(softc,
	    BCM2711_REG_MEM_WIN0_BASE_LIMIT(win));
	tmp &= ~(BCM2711_MEM_WIN0_BASE_LIMIT_BASE_MASK |
	    BCM2711_MEM_WIN0_BASE_LIMIT_LIMIT_MASK);
	tmp |= ((uint32_t)cpu_addr_mb <<
	    BCM2711_MEM_WIN0_BASE_LIMIT_BASE_SHIFT) &
	    BCM2711_MEM_WIN0_BASE_LIMIT_BASE_MASK;
	tmp |= ((uint32_t)limit_addr_mb <<
	    BCM2711_MEM_WIN0_BASE_LIMIT_LIMIT_SHIFT) &
	    BCM2711_MEM_WIN0_BASE_LIMIT_LIMIT_MASK;
	bcm2711_pcie_write_reg(softc,
	    BCM2711_REG_MEM_WIN0_BASE_LIMIT(win), tmp);

	/* Write the upper bits of base and limit addresses. */
	tmp = bcm2711_pcie_read_reg(softc,
	    BCM2711_REG_MEM_WIN0_BASE_HI(win));
	tmp &= ~BCM2711_MEM_WIN0_BASE_HI_MASK;
	tmp |= ((uint32_t)(cpu_addr_mb >>
	    BCM2711_MEM_WIN0_BASE_LIMIT_NBITS)) &
	    BCM2711_MEM_WIN0_BASE_HI_MASK;
	bcm2711_pcie_write_reg(softc,
	    BCM2711_REG_MEM_WIN0_BASE_HI(win), tmp);

	tmp = bcm2711_pcie_read_reg(softc,
	    BCM2711_REG_MEM_WIN0_LIMIT_HI(win));
	tmp &= ~BCM2711_MEM_WIN0_LIMIT_HI_MASK;
	tmp |= ((uint32_t)(limit_addr_mb >>
	    BCM2711_MEM_WIN0_BASE_LIMIT_NBITS)) &
	    BCM2711_MEM_WIN0_LIMIT_HI_MASK;
	bcm2711_pcie_write_reg(softc,
	    BCM2711_REG_MEM_WIN0_LIMIT_HI(win), tmp);
}

/*
 * Parse the "ranges" property on the PCIe node and program the outbound
 * (CPU->PCI) memory window registers.
 *
 * The PCIe node has #address-cells=3, its parent has #address-cells=2,
 * and #size-cells=2.  Each entry is therefore 7 cells:
 *   phys.hi phys.mid phys.lo  parent.hi parent.lo  size.hi size.lo
 *
 * We only program MEM-type entries (phys.hi & 0x03000000 == 0x02000000).
 */
static int
bcm2711_pcie_setup_outbound(bcm2711_pcie_softc_t *softc)
{
	dev_info_t *dip = softc->bc_dip;
	int *rng_prop;
	uint_t rng_len;
	uint32_t *cells;
	int n;
	uint_t i;
	uint8_t num_wins = 0;

	n = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_RANGES, &rng_prop, &rng_len);
	if (n != DDI_PROP_SUCCESS) {
		dev_err(dip, CE_WARN,
		    "failed to read ranges property: %d", n);
		return (DDI_FAILURE);
	}

	/*
	 * Each entry: 3 (child addr) + 2 (parent addr) + 2 (size) = 7 cells.
	 */
	if ((rng_len % 7) != 0) {
		dev_err(dip, CE_WARN,
		    "ranges property length %d not a multiple of 7", rng_len);
		ddi_prop_free(rng_prop);
		return (DDI_FAILURE);
	}

	cells = (uint32_t *)rng_prop;
	for (i = 0; i < rng_len; i += 7) {
		uint32_t phys_hi = cells[i];
		uint64_t pci_addr;
		uint64_t cpu_addr;
		uint64_t size;

		/* Only program memory (non-prefetchable) windows. */
		if ((phys_hi & 0x03000000) != PCI_PHYS_HI_SPACE_MEM) {
			continue;
		}

		pci_addr = ((uint64_t)cells[i + 1] << 32) | cells[i + 2];
		cpu_addr = ((uint64_t)cells[i + 3] << 32) | cells[i + 4];
		size = ((uint64_t)cells[i + 5] << 32) | cells[i + 6];

#ifdef	DEBUG
		dev_err(dip, CE_CONT,
		    "!outbound win %d: cpu 0x%llx -> pci 0x%llx size 0x%llx\n",
		    num_wins, (unsigned long long)cpu_addr,
		    (unsigned long long)pci_addr,
		    (unsigned long long)size);
#endif

		bcm2711_pcie_set_outbound_win(softc, num_wins,
		    cpu_addr, pci_addr, size);
		num_wins++;

		if (num_wins >= BCM2711_NUM_OUTBOUND_WINS) {
			dev_err(dip, CE_WARN,
			    "outbound window limit reached (%d), "
			    "ignoring remaining ranges",
			    BCM2711_NUM_OUTBOUND_WINS);
			break;
		}
	}

	ddi_prop_free(rng_prop);

	if (num_wins == 0) {
		dev_err(dip, CE_WARN,
		    "no memory ranges found in ranges property");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Parse the "dma-ranges" property on the PCIe node and program the
 * inbound (PCI->CPU DMA) BAR registers.
 *
 * For the BCM2711:
 *   - BAR1 is disabled (size 0).
 *   - BAR2 is the main inbound window, covering all DMA-accessible memory.
 *     Its size must be a power of two.
 *   - BAR3 is disabled (size 0).
 *   - SCB0_SIZE in MISC_CTRL is set to ilog2(size) - 15.
 *   - The endian mode is set to little-endian via VENDOR_SPECIFIC_REG1.
 *
 * The "dma-ranges" property format matches "ranges": 7 cells per entry
 * with #address-cells=3, parent #address-cells=2, #size-cells=2.
 */
static int
bcm2711_pcie_setup_inbound(bcm2711_pcie_softc_t *softc)
{
	dev_info_t *dip = softc->bc_dip;
	int *rng_prop;
	uint_t rng_len;
	uint32_t *cells;
	int n;
	uint_t i;
	uint64_t pci_offset = 0;
	/*
	 * BAR2's cpu_addr is hardwired to the start of system memory on
	 * BCM2711 (and all STB chips), so it is always 0.
	 */
	uint64_t cpu_addr = 0;
	uint64_t tot_size = 0;
	uint64_t size;
	int log2_size;
	uint32_t tmp;
	boolean_t found = B_FALSE;

	n = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_DMA_RANGES, &rng_prop, &rng_len);
	if (n != DDI_PROP_SUCCESS) {
		dev_err(dip, CE_WARN,
		    "failed to read dma-ranges property: %d", n);
		return (DDI_FAILURE);
	}

	if ((rng_len % 7) != 0) {
		dev_err(dip, CE_WARN,
		    "dma-ranges property length %d not a multiple of 7",
		    rng_len);
		ddi_prop_free(rng_prop);
		return (DDI_FAILURE);
	}

	/*
	 * Walk all DMA range entries.  Accumulate total size and track
	 * the lowest PCIe address as the BAR2 base offset.
	 */
	cells = (uint32_t *)rng_prop;
	for (i = 0; i < rng_len; i += 7) {
		uint64_t entry_pci;
		uint64_t entry_size;

		entry_pci = ((uint64_t)cells[i + 1] << 32) | cells[i + 2];
		entry_size = ((uint64_t)cells[i + 5] << 32) | cells[i + 6];

		if (!found || entry_pci < pci_offset)
			pci_offset = entry_pci;

		tot_size += entry_size;
		found = B_TRUE;
	}

	ddi_prop_free(rng_prop);

	if (!found) {
		dev_err(dip, CE_WARN, "no entries in dma-ranges property");
		return (DDI_FAILURE);
	}

	/*
	 * The hardware mandates that the inbound window size must be a
	 * power of two.  Round up if necessary.
	 */
	if (!ISP2(tot_size))
		size = 1ULL << highbit64(tot_size);
	else
		size = tot_size;

#ifdef	DEBUG
	dev_err(dip, CE_CONT,
	    "!inbound win: pci 0x%llx -> cpu 0x%llx size 0x%llx\n",
	    (unsigned long long)pci_offset,
	    (unsigned long long)cpu_addr,
	    (unsigned long long)size);
#endif

	/* Step 1: Disable BAR1. */
	bcm2711_pcie_write_reg(softc, BCM2711_REG_RC_BAR1_CONFIG_LO, 0);

	/* Step 2: Program BAR2 with the encoded size and PCI offset. */
	tmp = (uint32_t)(pci_offset & 0xffffffffU);
	tmp &= ~BCM2711_RC_BAR_CONFIG_LO_SIZE_MASK;
	tmp |= bcm2711_pcie_encode_ibar_size(size) &
	    BCM2711_RC_BAR_CONFIG_LO_SIZE_MASK;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_RC_BAR2_CONFIG_LO, tmp);
	bcm2711_pcie_write_reg(softc, BCM2711_REG_RC_BAR2_CONFIG_HI,
	    (uint32_t)(pci_offset >> 32));

	/* Step 3: Disable BAR3. */
	bcm2711_pcie_write_reg(softc, BCM2711_REG_RC_BAR3_CONFIG_LO, 0);

	/* Step 4: Program SCB0_SIZE in MISC_CTRL. */
	log2_size = highbit64(size) - 1;
	if (log2_size < 15 || log2_size > 36) {
		dev_err(dip, CE_WARN,
		    "inbound window size 0x%llx out of encodable range "
		    "(log2=%d, need 15-36)",
		    (unsigned long long)size, log2_size);
		return (DDI_FAILURE);
	}
	tmp = bcm2711_pcie_read_reg(softc, BCM2711_REG_MISC_CTRL);
	tmp &= ~BCM2711_MISC_CTRL_SCB0_SIZE_MASK;
	tmp |= ((uint32_t)(log2_size - 15) <<
	    BCM2711_MISC_CTRL_SCB0_SIZE_SHIFT) &
	    BCM2711_MISC_CTRL_SCB0_SIZE_MASK;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_MISC_CTRL, tmp);

	/* Step 5: Set little-endian mode for inbound BAR2 window. */
	tmp = bcm2711_pcie_read_reg(softc,
	    BCM2711_REG_VENDOR_SPECIFIC_REG1);
	tmp &= ~BCM2711_VENDOR_REG1_ENDIAN_MODE_BAR2_MASK;
	tmp |= BCM2711_VENDOR_REG1_LITTLE_ENDIAN;
	bcm2711_pcie_write_reg(softc,
	    BCM2711_REG_VENDOR_SPECIFIC_REG1, tmp);

	return (DDI_SUCCESS);
}

/*
 * Perform the full PCIe controller setup sequence.  This follows a similar
 * initialisation order to the OpenBSD bcmpcie driver.
 */
static int
bcm2711_pcie_setup(bcm2711_pcie_softc_t *softc)
{
	uint32_t val;
	int ret;
	int i;
	char *strprop;

	/*
	 * Assert PERST# and place the bridge into SW init (reset).
	 */
	bcm2711_pcie_perst_set(softc, 1);
	bcm2711_pcie_bridge_sw_init_set(softc, 1);
	drv_usecwait(200);

	/*
	 * Take the bridge out of reset and deassert SERDES IDDQ to
	 * wake up the SerDes, then give it some time to stabilise.
	 */
	bcm2711_pcie_bridge_sw_init_set(softc, 0);
	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG);
	val &= ~BCM2711_HARD_DEBUG_SERDES_IDDQ;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG, val);
	drv_usecwait(200);

	/*
	 * Set SCB_MAX_BURST_SIZE to 128 bytes, enable SCB access, set UR
	 * mode for config reads, and enable RCB MPS and 64-byte RCB modes.
	 */
	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_MISC_CTRL);
	val &= ~BCM2711_MISC_CTRL_MAX_BURST_MASK;
	val |= BCM2711_MISC_CTRL_MAX_BURST_128;
	val |= BCM2711_MISC_CTRL_SCB_ACCESS_EN;
	val |= BCM2711_MISC_CTRL_CFG_READ_UR;
	val |= BCM2711_MISC_CTRL_RCB_64B_MODE;
	val |= BCM2711_MISC_CTRL_RCB_MPS_MODE;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_MISC_CTRL, val);

	/*
	 * Set the bridge class code to PCI-PCI bridge.  The
	 * hardware defaults to endpoint mode.
	 */
	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_PRIV1_ID_VAL3);
	val = (val & ~BCM2711_ID_VAL3_CLASS_CODE_MASK) |
	    BCM2711_CLASS_CODE_BRIDGE_PCI;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_PRIV1_ID_VAL3, val);

	/*
	 * Configure outbound (CPU->PCI) memory windows from the device
	 * tree "ranges" property.
	 */
	ret = bcm2711_pcie_setup_outbound(softc);
	if (ret != DDI_SUCCESS) {
		dev_err(softc->bc_dip, CE_WARN,
		    "failed to configure outbound windows");
		goto fail_setup;
	}

	/*
	 * Configure inbound (PCI->CPU DMA) BAR windows from the device
	 * tree "dma-ranges" property.
	 */
	ret = bcm2711_pcie_setup_inbound(softc);
	if (ret != DDI_SUCCESS) {
		dev_err(softc->bc_dip, CE_WARN,
		    "failed to configure inbound windows");
		goto fail_setup;
	}

	/*
	 * Mask and clear all MSI.
	 */
	bcm2711_pcie_write_reg(softc, BCM2711_MSI_INT_MASK_SET, 0xffffffffU);
	bcm2711_pcie_write_reg(softc, BCM2711_MSI_INT_CLR, 0xffffffffU);
	bcm2711_pcie_write_reg(softc, BCM2711_MSI_EOI, 1U);

	/*
	 * Mask and clear all legacy INTx interrupts.
	 *
	 * Note that this is very coarse, and also masks/acks all other
	 * bits in these registers that are undocumented and may relate to the
	 * primary PCIe interrupt vector (which is unused).
	 */
	bcm2711_pcie_write_reg(softc, BCM2711_INTR2_MASK_SET, 0xffffffffU);
	bcm2711_pcie_write_reg(softc, BCM2711_INTR2_CLR, 0xffffffffU);

	/*
	 * Check for "brcm,clkreq-mode" property to determine whether to
	 * enable CLKREQ# L1.1 power management or use it for link debugging.
	 */
	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG);
	val &= ~BCM2711_HARD_DEBUG_CLKREQ_MASK;
	val |= BCM2711_HARD_DEBUG_L1SS_ENABLE;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, softc->bc_dip,
	    DDI_PROP_DONTPASS, "brcm,clkreq-mode", &strprop) == DDI_SUCCESS) {
		if (strcmp(strprop, "no-l1ss") == 0) {
			val &= ~BCM2711_HARD_DEBUG_L1SS_ENABLE;
			val |= BCM2711_HARD_DEBUG_CLKREQ_DEBUG_ENABLE;
		}

		ddi_prop_free(strprop);
	}

	bcm2711_pcie_write_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG, val);

	/* brcm,clkreq-mode == no-l1ss */
	if (val & BCM2711_HARD_DEBUG_CLKREQ_DEBUG_ENABLE) {
		val = bcm2711_pcie_read_reg(softc,
		    BCM2711_REG_RC_CFG_PRIV1_ROOT_CAP);
		val &= ~BCM2711_RC_CFG_PRIV1_ROOT_CAP_L1SS_MODE_MASK;
		val |= (1U << BCM2711_RC_CFG_PRIV1_ROOT_CAP_L1SS_MODE_SHIFT);
		bcm2711_pcie_write_reg(softc,
		    BCM2711_REG_RC_CFG_PRIV1_ROOT_CAP, val);
	}

	/*
	 * Deassert PERST# to bring up the link.
	 */
	bcm2711_pcie_perst_set(softc, 0);

	/*
	 * Poll for link-up.  The PCIe CEM spec (r5.0 §2.9.2) requires
	 * at least 100ms after PERST# deassertion before sending
	 * configuration requests.  We wait that first, then poll every 5ms
	 * for up to an additional 900ms (1s total) to allow slower devices
	 * to complete link training.
	 */
	delay(drv_usectohz(100000));

	for (i = 0; i < 900; i += 5) {
		val = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_STATUS);
		if ((val & BCM2711_STATUS_DL_ACTIVE) &&
		    (val & BCM2711_STATUS_PHYLINKUP)) {
			break;
		}

		delay(drv_usectohz(5000));
	}

	if (i >= 900) {
		val = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_STATUS);
		dev_err(softc->bc_dip, CE_WARN,
		    "link-up timeout: PCIE_STATUS=0x%x "
		    "(phylinkup=%d dl_active=%d)",
		    val,
		    !!(val & BCM2711_STATUS_PHYLINKUP),
		    !!(val & BCM2711_STATUS_DL_ACTIVE));
		goto fail_setup;
	}

	if (ddi_prop_exists(DDI_DEV_T_ANY, softc->bc_dip,
	    DDI_PROP_DONTPASS, "brcm,enable-ssc")) {
		if (bcm2711_pcie_setup_ssc(softc) != DDI_SUCCESS) {
			dev_err(softc->bc_dip, CE_WARN,
			    "failed to enable spread-spectrum clocking");
			goto fail_setup;
		}
	}

	return (DDI_SUCCESS);

fail_setup:
	/*
	 * Re-assert PERST#, take down SerDes and re-assert and
	 * bridge SW_INIT to leave the hardware in a known-safe
	 * state after a setup failure.
	 */
	bcm2711_pcie_perst_set(softc, 1);
	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG);
	val |= BCM2711_HARD_DEBUG_SERDES_IDDQ;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG, val);
	bcm2711_pcie_bridge_sw_init_set(softc, 1);
	return (DDI_FAILURE);
}

/*
 * Standard driver entry points, integration structures and module linkage.
 */

static int
bcm2711_pcie_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	bcm2711_pcie_softc_t *softc = NULL;
	int ret;
	int instance;
	uint32_t val;
	uint16_t cmdval;
	const ddi_device_acc_attr_t attr = {
		.devacc_attr_version = DDI_DEVICE_ATTR_V1,
		.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder = DDI_STRICTORDER_ACC,
		.devacc_attr_access = DDI_DEFAULT_ACC,
	};

	if (cmd == DDI_RESUME)
		return (DDI_SUCCESS);

	/*
	 * If we don't have a bus-range property, create one that describes
	 * what is typically found on the rpi4: a single downstream bus
	 * numbered 1.
	 *
	 * This is needed for the PCIe enumeration code to know where to look
	 * for devices.
	 */
	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_BUS_RANGE)) {
		int busrange[2] = { 0, 1 };
		if (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		    OBP_BUS_RANGE, busrange, 2) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN,
			    "failed to create bus-range property");
			return (DDI_FAILURE);
		}
	}

	instance = ddi_get_instance(dip);

	if ((ret = ddi_soft_state_zalloc(bcm2711_pcie_soft_state, instance)) !=
	    DDI_SUCCESS) {
		return (ret);
	}

	softc = ddi_get_soft_state(bcm2711_pcie_soft_state, instance);
	VERIFY3P(softc, !=, NULL);

	softc->bc_dip = dip;
	mutex_init(&softc->bc_lock, NULL, MUTEX_DRIVER, NULL);

	if ((ret = ddi_regs_map_setup(dip, 0, &softc->bc_base,
	    0, 0, &attr, &softc->bc_handle)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to map configuration space: %d",
		    ret);
		goto fail_regs;
	}

	ndi_set_bus_private(dip, B_TRUE, DEVI_PORT_TYPE_PCIRC,
	    &bcm2711_pcie_rc_data);

	VERIFY3U(softc->bc_base, !=, 0);

	if ((ret = bcm2711_pcie_setup(softc)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "controller setup failed, link not up");
		goto fail_setup;
	}

	/*
	 * If the downstream device is a VL805 xHCI controller, load its
	 * firmware via the VideoCore mailbox before enumeration begins.
	 */
	bcm2711_pcie_vl805_reset(softc);

	/*
	 * Defensively remove any reference to an MSI capability until we're
	 * ready for that.
	 */
	(void) ddi_prop_undefine(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP, "msi-controller");
	(void) ddi_prop_undefine(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP, "msi-parent");
	(void) ddi_prop_undefine(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP, "msi-map");

	if ((ret = pcierc_attach(dip, cmd)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "pcierc_attach failed: %d", ret);
		goto fail_pcierc;
	}

	/*
	 * Enable bus mastering and memory space access on the root port.
	 * pcie_initchild() handles this for downstream devices, but the
	 * root port itself is not a child — we must program it directly.
	 *
	 * Without BME, upstream DMA from the VL805 is silently dropped.
	 */
	cmdval = (uint16_t)bcm2711_cfg_read(dip, 0, 0, 0,
	    PCI_CONF_COMM, PCI_CFG_SIZE_WORD);
	cmdval |= (PCI_COMM_ME | PCI_COMM_MAE);
	bcm2711_cfg_write(dip, 0, 0, 0,
	    PCI_CONF_COMM, PCI_CFG_SIZE_WORD, cmdval);

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

fail_pcierc:
	/*
	 * Place the hardware into a known-safe state.
	 */
	bcm2711_pcie_perst_set(softc, 1);
	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG);
	val |= BCM2711_HARD_DEBUG_SERDES_IDDQ;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG, val);
	bcm2711_pcie_bridge_sw_init_set(softc, 1);

fail_setup:
	ddi_regs_map_free(&softc->bc_handle);

fail_regs:
	mutex_destroy(&softc->bc_lock);
	ddi_soft_state_free(bcm2711_pcie_soft_state, instance);
	return (ret);
}

static int
bcm2711_pcie_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	bcm2711_pcie_softc_t *softc;
	int ret;
	uint32_t val;

	if (cmd != DDI_DETACH)
		return (DDI_SUCCESS);

	softc = ddi_get_soft_state(bcm2711_pcie_soft_state,
	    ddi_get_instance(dip));

	VERIFY3P(softc, !=, NULL);

	if ((ret = pcierc_detach(dip, cmd)) != DDI_SUCCESS) {
		return (ret);
	}

	bcm2711_pcie_perst_set(softc, 1);
	val = bcm2711_pcie_read_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG);
	val |= BCM2711_HARD_DEBUG_SERDES_IDDQ;
	bcm2711_pcie_write_reg(softc, BCM2711_REG_PCIE_HARD_DEBUG, val);
	bcm2711_pcie_bridge_sw_init_set(softc, 1);

	ddi_regs_map_free(&softc->bc_handle);
	mutex_destroy(&softc->bc_lock);
	ddi_soft_state_free(bcm2711_pcie_soft_state, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

static int
bcm2711_pcie_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result)
{
	int instance = ddi_get_instance(dip);
	bcm2711_pcie_softc_t *softc =
	    ddi_get_soft_state(bcm2711_pcie_soft_state, instance);

	ASSERT3P(softc, !=, NULL);

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
	.bus_intr_op = bcm2711_pcie_intr_ops,
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
