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
 * Copyright 2017 Hayashi Naoyuki
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <sys/byteorder.h>
#include <sys/sysmacros.h>
#include <sys/controlregs.h>
#include <sys/arch_timer.h>
#include <sys/platmod.h>
#include <sys/platform.h>
#include <sys/miiregs.h>
#include <sys/ethernet.h>
#include "prom_dev.h"
#include "genet.h"
#include <sys/bcm2711_genetreg.h>
#include "boot_plat.h"

#define ENET_ALIGN  DCACHE_LINE
#define BUFFER_SIZE 1536

struct genet_sc
{
	uint64_t base;
	uint8_t mac_addr[6];
	int phy_id;
	int phy_speed;
	int phy_fullduplex;

	int tx_index;
	int rx_index;
	int rx_c_index;
	caddr_t tx_buffer;
	caddr_t rx_buffer;
	paddr_t tx_buffer_phys;
	paddr_t rx_buffer_phys;
};

static struct genet_sc *genet_dev[3];

static void
genet_usecwait(int usec)
{
	arch_timer_udelay(usec);
}

static void
genet_cache_flush(void *addr, size_t len)
{
	for (uintptr_t v = P2ALIGN((uintptr_t)addr, DCACHE_LINE); v < (uintptr_t)addr + len; v += DCACHE_LINE) {
		flush_data_cache(v);
	}
	dsb(sy);
}

static int
genet_alloc_buffer(struct genet_sc *sc)
{
	size_t size = 0;
	size += BUFFER_SIZE; // for tx
	size = roundup(size, ENET_ALIGN);
	size += BUFFER_SIZE * GENET_DMA_DESC_COUNT; // for rx

	size_t alloc_size = size + 2 * MMU_PAGESIZE;
	uintptr_t orig_addr = (uintptr_t)kmem_alloc(alloc_size, 0);
	if (orig_addr == 0)
		return -1;
	uintptr_t buf_addr = roundup(orig_addr, MMU_PAGESIZE);
	size_t buf_size = roundup(size, MMU_PAGESIZE);
	uintptr_t buf_vaddr = memlist_get(buf_size, MMU_PAGESIZE, &ptmplistp);

	map_phys(PTE_UXN | PTE_PXN | PTE_AF | PTE_SH_INNER | PTE_AP_KRWUNA | PTE_ATTR_NORMEM_UC, (caddr_t)buf_vaddr, buf_addr, buf_size);
	memset((caddr_t)orig_addr, 0, alloc_size);
	genet_cache_flush((caddr_t)orig_addr, alloc_size);
	size_t offset = 0;

	sc->tx_buffer_phys = (paddr_t)(buf_addr + offset);
	sc->tx_buffer = (caddr_t)(buf_vaddr + offset);
	offset += BUFFER_SIZE;

	offset = roundup(offset, ENET_ALIGN);
	sc->rx_buffer_phys = (paddr_t)(buf_addr + offset);
	sc->rx_buffer = (caddr_t)(buf_vaddr + offset);
	offset += BUFFER_SIZE * GENET_DMA_DESC_COUNT;

	return 0;
}


static void
genet_reg_write(struct genet_sc *sc, size_t offset, uint32_t val)
{
	*(volatile uint32_t *)(sc->base + offset) = val;
}

static uint32_t
genet_reg_read(struct genet_sc *sc, size_t offset)
{
	return *(volatile uint32_t *)(sc->base + offset);
}

#define	MII_BUSY_RETRY		1000

static int
genet_mii_write(struct genet_sc *sc, int offset, uint16_t val)
{
	if (genet_reg_read(sc, GENET_MDIO_CMD) & GENET_MDIO_START_BUSY)
		return -1;

	genet_reg_write(sc, GENET_MDIO_CMD, GENET_MDIO_WRITE | (sc->phy_id << GENET_MDIO_ADDR_SHIFT) | (offset << GENET_MDIO_REG_SHIFT) | (val & GENET_MDIO_VAL_MASK));
	genet_reg_write(sc, GENET_MDIO_CMD, genet_reg_read(sc, GENET_MDIO_CMD) | GENET_MDIO_START_BUSY);

	for (int retry = MII_BUSY_RETRY; retry > 0; retry--) {
		if ((genet_reg_read(sc, GENET_MDIO_CMD) & GENET_MDIO_START_BUSY) == 0)
			return 0;
		genet_usecwait(10);
	}
	prom_printf("%s timeout\n",__func__);
	return -1;
}

static int
genet_mii_read(struct genet_sc *sc, int offset)
{
	if (genet_reg_read(sc, GENET_MDIO_CMD) & GENET_MDIO_START_BUSY)
		return -1;

	genet_reg_write(sc, GENET_MDIO_CMD, GENET_MDIO_READ | (sc->phy_id << GENET_MDIO_ADDR_SHIFT) | (offset << GENET_MDIO_REG_SHIFT));
	genet_reg_write(sc, GENET_MDIO_CMD, genet_reg_read(sc, GENET_MDIO_CMD) | GENET_MDIO_START_BUSY);

	for (int retry = MII_BUSY_RETRY; retry > 0; retry--) {
		uint32_t val = genet_reg_read(sc, GENET_MDIO_CMD);
		if ((val & GENET_MDIO_START_BUSY) == 0) {
			if (val & GENET_MDIO_READ_FAILED)
				return -1;
			return val & GENET_MDIO_VAL_MASK;
		}
		genet_usecwait(10);
	}
	prom_printf("%s timeout\n",__func__);
	return -1;
}

static int
genet_phy_reset(struct genet_sc *sc)
{
	int reg;

	reg = genet_mii_read(sc, MII_AN_ADVERT);
	if (reg < 0)
		return -1;

	uint16_t advert = reg & 0x1F;
	advert |= MII_ABILITY_100BASE_TX_FD;
	advert |= MII_ABILITY_100BASE_TX;
	advert |= MII_ABILITY_10BASE_T_FD;
	advert |= MII_ABILITY_10BASE_T;
	uint16_t gigctrl =  MII_MSCONTROL_1000T_FD | MII_MSCONTROL_1000T;

	if (genet_mii_write(sc, MII_AN_ADVERT, advert))
		return -1;
	if (genet_mii_write(sc, MII_MSCONTROL, gigctrl))
		return -1;

	uint16_t bmcr = MII_CONTROL_ANE | MII_CONTROL_RSAN | MII_CONTROL_1GB | MII_CONTROL_FDUPLEX;
	if (genet_mii_write(sc, MII_CONTROL, bmcr))
		return -1;

	uint16_t bmsr = 0;
	for (int i = 0; i < 20000; i++) {
		genet_usecwait(1000);
		reg = genet_mii_read(sc, MII_STATUS);
		if (reg < 0)
			return -1;
		bmsr = reg;
		if (bmsr & MII_STATUS_LINKUP)
			break;
	}
	if (!(bmsr & MII_STATUS_LINKUP)) {
		prom_printf("%s linkup timeout\n",__func__);
		return -1;
	}

	reg = genet_mii_read(sc, MII_AN_LPABLE);
	if (reg < 0)
		return -1;
	uint16_t lpar = reg;
	reg = genet_mii_read(sc, MII_MSSTATUS);
	if (reg < 0)
		return -1;
	uint16_t msstat = reg;
	if (msstat & MII_MSSTATUS_LP1000T_FD) {
		sc->phy_speed = 1000;
		sc->phy_fullduplex = 1;
	} else if (msstat & MII_MSSTATUS_LP1000T) {
		sc->phy_speed = 1000;
		sc->phy_fullduplex = 0;
	} else if (lpar & MII_ABILITY_100BASE_TX_FD) {
		sc->phy_speed = 100;
		sc->phy_fullduplex = 1;
	} else if (lpar & MII_ABILITY_100BASE_TX) {
		sc->phy_speed = 100;
		sc->phy_fullduplex = 0;
	} else if (lpar & MII_ABILITY_10BASE_T_FD) {
		sc->phy_speed = 10;
		sc->phy_fullduplex = 1;
	} else if (lpar & MII_ABILITY_10BASE_T) {
		sc->phy_speed = 10;
		sc->phy_fullduplex = 0;
	} else {
		sc->phy_speed = 0;
		sc->phy_fullduplex = 0;
	}

	return 0;
}

static void
genet_write_hwaddr(struct genet_sc *sc)
{
	uint8_t *addr = sc->mac_addr;
	genet_reg_write(sc, GENET_UMAC_MAC0, addr[0] << 24 | addr[1] << 16 | addr[2] << 8 | addr[3]);
	genet_reg_write(sc, GENET_UMAC_MAC1, addr[4] << 8 | addr[5]);
}

static int
genet_get_macaddr(struct genet_sc *sc, pnode_t node)
{
	int len = prom_getproplen(node, "local-mac-address");
	if (len != sizeof(sc->mac_addr))
		return -1;

	prom_getprop(node, "local-mac-address", (caddr_t)sc->mac_addr);
	return 0;
}

static int
genet_match(const char *name)
{
	pnode_t node = prom_finddevice(name);
	if (node <= 0)
		return 0;
	if (prom_is_compatible(node, "brcm,bcm2711-genet-v5"))
		return 1;
	return 0;
}

static bool
is_rgmii(pnode_t node)
{
	int len = prom_getproplen(node, "phy-mode");
	if (len > 0) {
		caddr_t mode = __builtin_alloca(len);
		prom_getprop(node, "phy-mode", mode);
		if (strncmp(mode, "rgmii", strlen("rgmii")) == 0)
		    return true;
	}
	return false;
}

static pnode_t
get_phynode(pnode_t node)
{
	int len = prom_getproplen(node, "phy-handle");
	if (len <= 0)
		return -1;
	phandle_t phandle;
	prom_getprop(node, "phy-handle", (caddr_t)&phandle);
	return prom_findnode_by_phandle(ntohl(phandle));
}

static void
genet_reset(struct genet_sc *sc, pnode_t node)
{
	if (is_rgmii(node))
		genet_reg_write(sc, GENET_SYS_PORT_CTRL, GENET_SYS_PORT_MODE_EXT_GPHY);

	genet_reg_write(sc, GENET_SYS_RBUF_FLUSH_CTRL, 0);
	genet_usecwait(10);

	genet_reg_write(sc, GENET_UMAC_CMD, 0);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_UMAC_CMD, GENET_UMAC_CMD_LCL_LOOP_EN | GENET_UMAC_CMD_SW_RESET);
	genet_usecwait(10);

	genet_reg_write(sc, GENET_SYS_RBUF_FLUSH_CTRL, GENET_SYS_RBUF_FLUSH_RESET);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_SYS_RBUF_FLUSH_CTRL, 0);

	genet_reg_write(sc, GENET_UMAC_CMD, 0);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_UMAC_CMD, GENET_UMAC_CMD_LCL_LOOP_EN | GENET_UMAC_CMD_SW_RESET);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_UMAC_CMD, 0);

	genet_reg_write(sc, GENET_UMAC_MIB_CTRL, GENET_UMAC_MIB_RESET_RUNT | GENET_UMAC_MIB_RESET_RX | GENET_UMAC_MIB_RESET_TX);
	genet_reg_write(sc, GENET_UMAC_MIB_CTRL, 0);

	genet_reg_write(sc, GENET_UMAC_MAX_FRAME_LEN, 1536);
	genet_reg_write(sc, GENET_RBUF_CTRL, genet_reg_read(sc, GENET_RBUF_CTRL) | GENET_RBUF_ALIGN_2B);
	genet_reg_write(sc, GENET_RBUF_TBUF_SIZE_CTRL, 1);
}

static void
genet_enable(struct genet_sc *sc)
{
	genet_reg_write(sc, GENET_TX_DMA_CTRL, GENET_TX_DMA_CTRL_RBUF_EN(GENET_DMA_DEFAULT_QUEUE) | GENET_TX_DMA_CTRL_EN);
	genet_reg_write(sc, GENET_RX_DMA_CTRL, GENET_RX_DMA_CTRL_RBUF_EN(GENET_DMA_DEFAULT_QUEUE) | GENET_RX_DMA_CTRL_EN);
	genet_reg_write(sc, GENET_UMAC_CMD, genet_reg_read(sc, GENET_UMAC_CMD) | GENET_UMAC_CMD_TXEN | GENET_UMAC_CMD_RXEN);
}

static void
genet_disable(struct genet_sc *sc)
{
	// stop rx
	genet_reg_write(sc, GENET_UMAC_CMD, genet_reg_read(sc, GENET_UMAC_CMD) & ~GENET_UMAC_CMD_RXEN);
	// stop rx dma
	genet_reg_write(sc, GENET_RX_DMA_CTRL, genet_reg_read(sc, GENET_RX_DMA_CTRL) & ~GENET_RX_DMA_CTRL_EN);
	// stop tx dma
	genet_reg_write(sc, GENET_TX_DMA_CTRL, genet_reg_read(sc, GENET_TX_DMA_CTRL) & ~GENET_TX_DMA_CTRL_EN);
	// stop tx
	genet_reg_write(sc, GENET_UMAC_CMD, genet_reg_read(sc, GENET_UMAC_CMD) & ~GENET_UMAC_CMD_TXEN);
	// flush tx fifo
	genet_reg_write(sc, GENET_UMAC_TX_FLUSH, 1);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_UMAC_TX_FLUSH, 0);
}

static void
genet_rx_init(struct genet_sc *sc)
{
	genet_reg_write(sc, GENET_RX_DMA_RING_CFG, 0);
	genet_reg_write(sc, GENET_RX_SCB_BURST_SIZE, 0x08);
	genet_reg_write(sc, GENET_RX_DMA_START_ADDR_LO(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_RX_DMA_START_ADDR_HI(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_RX_DMA_READ_PTR_LO(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_RX_DMA_READ_PTR_HI(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_RX_DMA_WRITE_PTR_LO(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_RX_DMA_WRITE_PTR_HI(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_RX_DMA_END_ADDR_LO(GENET_DMA_DEFAULT_QUEUE),
	    GENET_DMA_DESC_COUNT * GENET_DMA_DESC_SIZE / 4 - 1);
	genet_reg_write(sc, GENET_RX_DMA_END_ADDR_HI(GENET_DMA_DEFAULT_QUEUE), 0);

	sc->rx_c_index = genet_reg_read(sc, GENET_RX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE));
	genet_reg_write(sc, GENET_RX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE), sc->rx_c_index);
	sc->rx_index = sc->rx_c_index & (GENET_DMA_DESC_COUNT - 1);

	genet_reg_write(sc, GENET_RX_DMA_RING_BUF_SIZE(GENET_DMA_DEFAULT_QUEUE),
	    (GENET_DMA_DESC_COUNT << GENET_RX_DMA_RING_BUF_SIZE_DESC_SHIFT) |
	    (BUFFER_SIZE & GENET_RX_DMA_RING_BUF_SIZE_BUF_LEN_MASK));
	genet_reg_write(sc, GENET_RX_DMA_XON_XOFF_THRES(GENET_DMA_DEFAULT_QUEUE),
	    (5 << GENET_RX_DMA_XON_XOFF_THRES_LO_SHIFT) | (GENET_DMA_DESC_COUNT >> 4));

	genet_reg_write(sc, GENET_RX_DMA_RING_CFG, __BIT(GENET_DMA_DEFAULT_QUEUE));

	for (int i = 0; i < GENET_DMA_DESC_COUNT; i++) {
		paddr_t addr = (sc->rx_buffer_phys + BUFFER_SIZE * i);
		genet_reg_write(sc, GENET_RX_DESC_ADDRESS_LO(i), (uint32_t)addr);
		genet_reg_write(sc, GENET_RX_DESC_ADDRESS_HI(i), (uint32_t)(addr >> 32));
	}
}

static void
genet_tx_init(struct genet_sc *sc)
{
	genet_reg_write(sc, GENET_TX_DMA_RING_CFG, 0);
	genet_reg_write(sc, GENET_TX_SCB_BURST_SIZE, 0x08);
	genet_reg_write(sc, GENET_TX_DMA_START_ADDR_LO(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_TX_DMA_START_ADDR_HI(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_TX_DMA_READ_PTR_LO(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_TX_DMA_READ_PTR_HI(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_TX_DMA_WRITE_PTR_LO(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_TX_DMA_WRITE_PTR_HI(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_TX_DMA_END_ADDR_LO(GENET_DMA_DEFAULT_QUEUE),
	    GENET_DMA_DESC_COUNT * GENET_DMA_DESC_SIZE / 4 - 1);
	genet_reg_write(sc, GENET_TX_DMA_END_ADDR_HI(GENET_DMA_DEFAULT_QUEUE), 0);

	genet_reg_write(sc, GENET_TX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE), genet_reg_read(sc, GENET_TX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE)));
	sc->tx_index = genet_reg_read(sc, GENET_TX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE)) & (GENET_DMA_DESC_COUNT - 1);
	genet_reg_write(sc, GENET_TX_DMA_MBUF_DONE_THRES(GENET_DMA_DEFAULT_QUEUE), 1);
	genet_reg_write(sc, GENET_TX_DMA_FLOW_PERIOD(GENET_DMA_DEFAULT_QUEUE), 0);
	genet_reg_write(sc, GENET_TX_DMA_RING_BUF_SIZE(GENET_DMA_DEFAULT_QUEUE),
	    (GENET_DMA_DESC_COUNT << GENET_TX_DMA_RING_BUF_SIZE_DESC_SHIFT) |
	    (BUFFER_SIZE & GENET_TX_DMA_RING_BUF_SIZE_BUF_LEN_MASK));

	genet_reg_write(sc, GENET_TX_DMA_RING_CFG, __BIT(GENET_DMA_DEFAULT_QUEUE));

	for (int i = 0; i < GENET_DMA_DESC_COUNT; i++) {
		paddr_t addr = sc->tx_buffer_phys;
		genet_reg_write(sc, GENET_TX_DESC_ADDRESS_LO(i), (uint32_t)addr);
		genet_reg_write(sc, GENET_TX_DESC_ADDRESS_HI(i), (uint32_t)(addr >> 32));
	}
}

static void
genet_update_link(struct genet_sc *sc)
{
	uint32_t speed = 0;
	switch (sc->phy_speed) {
	case 10: speed = GENET_UMAC_CMD_SPEED_10; break;
	case 100: speed = GENET_UMAC_CMD_SPEED_100; break;
	case 1000: speed = GENET_UMAC_CMD_SPEED_1000; break;
	}

	uint32_t val;
	val = genet_reg_read(sc, GENET_EXT_RGMII_OOB_CTRL);
	val &= ~GENET_EXT_RGMII_OOB_OOB_DISABLE;
	val |= GENET_EXT_RGMII_OOB_RGMII_LINK;
	val |= GENET_EXT_RGMII_OOB_RGMII_MODE_EN;
	val |= GENET_EXT_RGMII_OOB_ID_MODE_DISABLE;
	genet_reg_write(sc, GENET_EXT_RGMII_OOB_CTRL, val);

	val = genet_reg_read(sc, GENET_UMAC_CMD);
	val &= ~GENET_UMAC_CMD_SPEED;
	val |= speed;
	genet_reg_write(sc, GENET_UMAC_CMD, val);
}

static int
genet_open(const char *name)
{
	pnode_t node = prom_finddevice(name);
	if (node <= 0)
		return -1;
	if (!prom_is_compatible(node, "brcm,bcm2711-genet-v5"))
		return -1;

	int fd;

	for (fd = 0; fd < sizeof(genet_dev) / sizeof(genet_dev[0]); fd++) {
		if (genet_dev[fd] == NULL)
			break;
	}
	if (fd == sizeof(genet_dev) / sizeof(genet_dev[0]))
		return -1;
	struct genet_sc *sc = kmem_alloc(sizeof(struct genet_sc), 0);

	if (genet_get_macaddr(sc, node))
		return -1;

	if (prom_get_reg_address(node, 0, &sc->base) != 0)
		return -1;

	if (genet_alloc_buffer(sc))
		return -1;

	// get phy id
	pnode_t phy_node = get_phynode(node);
	if (phy_node < 0)
		return -1;
	{
		uint32_t phy_id;
		if (prom_getproplen(phy_node, "reg") != sizeof(phy_id))
			return -1;
		prom_getprop(phy_node, "reg", (caddr_t)&phy_id);
		sc->phy_id = ntohl(phy_id);
	}

	genet_reset(sc, node);
	genet_write_hwaddr(sc);
	genet_disable(sc);
	genet_rx_init(sc);
	genet_tx_init(sc);

	if (genet_phy_reset(sc) < 0)
		return -1;
	genet_update_link(sc);

	genet_enable(sc);

	char *str;
	str = "bootp";
	prom_setprop(prom_chosennode(), "net-config-strategy", (caddr_t)str, strlen(str) + 1);
	str = "ethernet,100,rj45,full";
	prom_setprop(prom_chosennode(), "network-interface-type", (caddr_t)str, strlen(str) + 1);
	str = "Ethernet controller";
	prom_setprop(node, "model", (caddr_t)str, strlen(str) + 1);

	genet_dev[fd] = sc;
	return fd;
}

static ssize_t
genet_send(int dev, caddr_t data, size_t packet_length, uint_t startblk)
{
	if (!(0 <= dev && dev < sizeof(genet_dev) / sizeof(genet_dev[0])))
		return -1;

	struct genet_sc *sc = genet_dev[dev];
	if (!sc)
		return -1;

	if (packet_length > BUFFER_SIZE)
		return -1;

	uint32_t prod = genet_reg_read(sc, GENET_TX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE));
	while ((genet_reg_read(sc, GENET_TX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE)) & GENET_TX_DMA_PROD_CONS_MASK) != prod) {}

	memcpy(sc->tx_buffer, data, packet_length);

	prod = (prod + 1) & GENET_TX_DMA_PROD_CONS_MASK;
	uint32_t length_status = GENET_TX_DESC_STATUS_QTAG_MASK;
	length_status |= GENET_TX_DESC_STATUS_SOP | GENET_TX_DESC_STATUS_EOP | GENET_TX_DESC_STATUS_CRC;
	length_status |= packet_length << GENET_TX_DESC_STATUS_BUFLEN_SHIFT;

	genet_reg_write(sc, GENET_TX_DESC_STATUS(sc->tx_index), length_status);
	genet_reg_write(sc, GENET_TX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE), prod);

	sc->tx_index = (sc->tx_index + 1) & (GENET_DMA_DESC_COUNT - 1);
	return packet_length;
}

static ssize_t
genet_recv(int dev, caddr_t buf, size_t buf_len, uint_t startblk)
{
	if (!(0 <= dev && dev < sizeof(genet_dev) / sizeof(genet_dev[0])))
		return -1;

	struct genet_sc *sc = genet_dev[dev];
	if (!sc)
		return -1;

	uint32_t prod = genet_reg_read(sc, GENET_RX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE));
	if (prod == sc->rx_c_index)
		return -1;
	uint32_t status = genet_reg_read(sc, GENET_RX_DESC_STATUS(sc->rx_index));

	size_t len = 0;
	if ((status &
		    (GENET_RX_DESC_STATUS_SOP | GENET_RX_DESC_STATUS_EOP |
		    GENET_RX_DESC_STATUS_RX_ERROR)) ==
		    (GENET_RX_DESC_STATUS_SOP | GENET_RX_DESC_STATUS_EOP)) {

		len = (status & GENET_RX_DESC_STATUS_BUFLEN_MASK) >>
		    GENET_RX_DESC_STATUS_BUFLEN_SHIFT;

			len -= 2;
			caddr_t buffer = sc->rx_buffer + BUFFER_SIZE * sc->rx_index + 2;
			memcpy(buf, buffer, len);
	}
	sc->rx_c_index = (sc->rx_c_index + 1) & GENET_RX_DMA_PROD_CONS_MASK;
	sc->rx_index = (sc->rx_index + 1) & (GENET_DMA_DESC_COUNT - 1);
	genet_reg_write(sc, GENET_RX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE), sc->rx_c_index);

	return len;
}

static int
genet_getmacaddr(ihandle_t dev, caddr_t ea)
{
	if (!(0 <= dev && dev < sizeof(genet_dev) / sizeof(genet_dev[0])))
		return -1;

	struct genet_sc *sc = genet_dev[dev];
	if (!sc)
		return -1;
	memcpy(ea, sc->mac_addr, 6);
	return 0;
}

static int
genet_close(int dev)
{
	if (!(0 <= dev && dev < sizeof(genet_dev) / sizeof(genet_dev[0])))
		return -1;
	struct genet_sc *sc = genet_dev[dev];
	if (!sc)
		return -1;

	genet_disable(sc);

	genet_dev[dev] = NULL;
	return 0;
}

static struct prom_dev genet_prom_dev =
{
	.match = genet_match,
	.open = genet_open,
	.write = genet_send,
	.read = genet_recv,
	.close = genet_close,
	.getmacaddr = genet_getmacaddr,
};

void init_genet(void)
{
	prom_register(&genet_prom_dev);
}
