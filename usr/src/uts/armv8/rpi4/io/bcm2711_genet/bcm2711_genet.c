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
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/promif.h>
#include <sys/miiregs.h>
#include <sys/ethernet.h>
#include <sys/byteorder.h>
#include <sys/controlregs.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/vlan.h>
#include <sys/platform.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/mii.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/crc32.h>
#include <sys/sysmacros.h>
#include <sys/platmod.h>
#include <sys/controlregs.h>
#include <sys/obpdefs.h>
#include <sys/bcm2711_genetreg.h>

#define	GENET_DMA_BUFFER_SIZE	1536

struct genet_reg {
	ddi_acc_handle_t handle;
	caddr_t addr;
};

struct genet_dma {
	caddr_t addr;
	size_t size;
	uint64_t dmac_addr;
	ddi_dma_handle_t dma_handle;
	ddi_acc_handle_t mem_handle;
};

struct genet_sc;
struct genet_packet {
	struct genet_packet *next;
	struct genet_dma dma;
	mblk_t *mp;
	frtn_t free_rtn;
	struct genet_sc *sc;
};

struct genet_mcast {
	list_node_t		node;
	uint8_t			addr[ETHERADDRL];
};

#define RX_PKT_NUM_MAX	GENET_DMA_DESC_COUNT

struct genet_desc_tx_ring {
	struct genet_dma desc;
	struct genet_packet *pkt[GENET_DMA_DESC_COUNT];

	mblk_t *mp[GENET_DMA_DESC_COUNT];

	int p_index;
	int c_index;
};

struct genet_desc_rx_ring {
	struct genet_dma desc;
	struct genet_packet *pkt[GENET_DMA_DESC_COUNT];
	int c_index;
};

struct genet_sc {
	dev_info_t *dip;
	kmutex_t intrlock;
	kmutex_t rx_pkt_lock;
	int rx_pkt_num;

	mac_handle_t mac_handle;
	mii_handle_t mii_handle;
	ddi_intr_handle_t intr_handle;
	link_duplex_t phy_duplex;

	mac_register_t *macp;
	struct genet_reg reg;
	struct genet_desc_tx_ring tx_ring;
	struct genet_desc_rx_ring rx_ring;
	int running;
	int phy_speed;
	int phy_id;
	uint8_t dev_addr[ETHERADDRL];
	struct genet_packet *rx_pkt_free;
	list_t mcast;
	uint32_t default_mtu;
	uint32_t pkt_size;
	boolean_t promisc;
};

static const ddi_device_acc_attr_t mem_acc_attr = {
	.devacc_attr_version = DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder = DDI_STORECACHING_OK_ACC,
};

static const ddi_device_acc_attr_t reg_acc_attr = {
	.devacc_attr_version = DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder = DDI_STRICTORDER_ACC,
};

static const ddi_dma_attr_t dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	.dma_attr_addr_lo = 0x0000000000000000ull,
	.dma_attr_addr_hi = 0x00000000FFFFFFFFull,
	.dma_attr_count_max = 0x00000000FFFFFFFFull,
	.dma_attr_align = DCACHE_LINE,
	.dma_attr_burstsizes = 0x00000FFF,
	.dma_attr_minxfer = 0x00000001,
	.dma_attr_maxxfer = 0x00000000FFFFFFFFull,
	.dma_attr_seg = 0x00000000FFFFFFFFull,
	.dma_attr_sgllen = 1,
	.dma_attr_granular = 0x00000001,
	.dma_attr_flags = DDI_DMA_FLAGERR,
};

static void genet_destroy(struct genet_sc *sc);
static void genet_m_stop(void *arg);

static void
genet_reg_write(struct genet_sc *sc, uint32_t offset, uint32_t val)
{
	void *addr = sc->reg.addr + offset;
	ddi_put32(sc->reg.handle, addr, val);
}

static uint32_t
genet_reg_read(struct genet_sc *sc, uint32_t offset)
{
	void *addr = sc->reg.addr + offset;
	return (ddi_get32(sc->reg.handle, addr));
}

static void
genet_usecwait(int usec)
{
	drv_usecwait(usec);
}

static void
genet_mutex_enter(struct genet_sc *sc)
{
	mutex_enter(&sc->intrlock);
}

static void
genet_mutex_exit(struct genet_sc *sc)
{
	mutex_exit(&sc->intrlock);
}

static boolean_t
is_rgmii(dev_info_t *dip)
{
	char *mode;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    "phy-mode", &mode) != DDI_SUCCESS) {
		return (B_FALSE);
	}

	/* only check whether we match the rgmii prefix */
	if (strncmp(mode, "rgmii", strlen("rgmii")) == 0) {
		ddi_prop_free(mode);
		return (B_TRUE);
	}

	ddi_prop_free(mode);
	return (B_FALSE);
}

static void
genet_gmac_reset(struct genet_sc *sc)
{
	if (is_rgmii(sc->dip)) {
		genet_reg_write(sc, GENET_SYS_PORT_CTRL,
		    GENET_SYS_PORT_MODE_EXT_GPHY);
	}

	genet_reg_write(sc, GENET_SYS_RBUF_FLUSH_CTRL, 0);
	genet_usecwait(10);

	genet_reg_write(sc, GENET_UMAC_CMD, 0);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_UMAC_CMD,
	    GENET_UMAC_CMD_LCL_LOOP_EN | GENET_UMAC_CMD_SW_RESET);
	genet_usecwait(10);

	genet_reg_write(sc, GENET_SYS_RBUF_FLUSH_CTRL,
	    GENET_SYS_RBUF_FLUSH_RESET);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_SYS_RBUF_FLUSH_CTRL, 0);

	genet_reg_write(sc, GENET_UMAC_CMD, 0);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_UMAC_CMD,
	    GENET_UMAC_CMD_LCL_LOOP_EN | GENET_UMAC_CMD_SW_RESET);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_UMAC_CMD, 0);

	genet_reg_write(sc, GENET_UMAC_MIB_CTRL,
	    GENET_UMAC_MIB_RESET_RUNT | GENET_UMAC_MIB_RESET_RX |
	    GENET_UMAC_MIB_RESET_TX);
	genet_reg_write(sc, GENET_UMAC_MIB_CTRL, 0);

	genet_reg_write(sc, GENET_UMAC_MAX_FRAME_LEN, GENET_DMA_BUFFER_SIZE);
	genet_reg_write(sc, GENET_RBUF_CTRL,
	    genet_reg_read(sc, GENET_RBUF_CTRL) | GENET_RBUF_ALIGN_2B);
	genet_reg_write(sc, GENET_RBUF_TBUF_SIZE_CTRL, 1);
}

static void
genet_gmac_init(struct genet_sc *sc)
{
	// interrupt disable
	genet_reg_write(sc, GENET_INTRL2_CPU_SET_MASK, 0xffffffff);

	// interrupt clear
	genet_reg_write(sc, GENET_INTRL2_CPU_CLEAR, 0xffffffff);

	// setup tx
	genet_reg_write(sc, GENET_TX_DMA_RING_CFG, 0);
	genet_reg_write(sc, GENET_TX_SCB_BURST_SIZE, 0x08);
	genet_reg_write(sc, GENET_TX_DMA_START_ADDR_LO(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_TX_DMA_START_ADDR_HI(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_TX_DMA_READ_PTR_LO(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_TX_DMA_READ_PTR_HI(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_TX_DMA_WRITE_PTR_LO(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_TX_DMA_WRITE_PTR_HI(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_TX_DMA_END_ADDR_LO(GENET_DMA_DEFAULT_QUEUE),
	    GENET_DMA_DESC_COUNT * GENET_DMA_DESC_SIZE / 4 - 1);
	genet_reg_write(sc, GENET_TX_DMA_END_ADDR_HI(GENET_DMA_DEFAULT_QUEUE),
	    0);
	sc->tx_ring.c_index = sc->tx_ring.p_index = genet_reg_read(sc,
	    GENET_TX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE)) &
	    GENET_TX_DMA_PROD_CONS_MASK;
	genet_reg_write(sc, GENET_TX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE),
	    sc->tx_ring.c_index);
	genet_reg_write(sc,
	    GENET_TX_DMA_MBUF_DONE_THRES(GENET_DMA_DEFAULT_QUEUE), 1);
	genet_reg_write(sc, GENET_TX_DMA_FLOW_PERIOD(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_TX_DMA_RING_BUF_SIZE(GENET_DMA_DEFAULT_QUEUE),
	    (GENET_DMA_DESC_COUNT << GENET_TX_DMA_RING_BUF_SIZE_DESC_SHIFT) |
	    (GENET_DMA_BUFFER_SIZE & GENET_TX_DMA_RING_BUF_SIZE_BUF_LEN_MASK));

	genet_reg_write(sc, GENET_TX_DMA_RING_CFG,
	    __BIT(GENET_DMA_DEFAULT_QUEUE));

	// setup rx
	genet_reg_write(sc, GENET_RX_DMA_RING_CFG, 0);
	genet_reg_write(sc, GENET_RX_SCB_BURST_SIZE, 0x08);
	genet_reg_write(sc, GENET_RX_DMA_START_ADDR_LO(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_RX_DMA_START_ADDR_HI(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_RX_DMA_READ_PTR_LO(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_RX_DMA_READ_PTR_HI(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_RX_DMA_WRITE_PTR_LO(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_RX_DMA_WRITE_PTR_HI(GENET_DMA_DEFAULT_QUEUE),
	    0);
	genet_reg_write(sc, GENET_RX_DMA_END_ADDR_LO(GENET_DMA_DEFAULT_QUEUE),
	    GENET_DMA_DESC_COUNT * GENET_DMA_DESC_SIZE / 4 - 1);
	genet_reg_write(sc, GENET_RX_DMA_END_ADDR_HI(GENET_DMA_DEFAULT_QUEUE),
	    0);
	sc->rx_ring.c_index = genet_reg_read(sc,
	    GENET_RX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE)) &
	    GENET_RX_DMA_PROD_CONS_MASK;
	genet_reg_write(sc, GENET_RX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE),
	    sc->rx_ring.c_index);
	genet_reg_write(sc, GENET_RX_DMA_RING_BUF_SIZE(GENET_DMA_DEFAULT_QUEUE),
	    (GENET_DMA_DESC_COUNT << GENET_RX_DMA_RING_BUF_SIZE_DESC_SHIFT) |
	    (GENET_DMA_BUFFER_SIZE & GENET_RX_DMA_RING_BUF_SIZE_BUF_LEN_MASK));
	genet_reg_write(sc,
	    GENET_RX_DMA_XON_XOFF_THRES(GENET_DMA_DEFAULT_QUEUE),
	    (5 << GENET_RX_DMA_XON_XOFF_THRES_LO_SHIFT) |
	    (GENET_DMA_DESC_COUNT >> 4));

	genet_reg_write(sc, GENET_RX_DMA_RING_CFG,
	    __BIT(GENET_DMA_DEFAULT_QUEUE));

	// interrupt enable
	genet_reg_write(sc, GENET_INTRL2_CPU_CLEAR_MASK,
	    GENET_IRQ_TXDMA_DONE | GENET_IRQ_RXDMA_DONE);
}

static void
genet_gmac_update(struct genet_sc *sc)
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

static void
genet_gmac_enable(struct genet_sc *sc)
{
	genet_reg_write(sc, GENET_TX_DMA_CTRL,
	    GENET_TX_DMA_CTRL_RBUF_EN(GENET_DMA_DEFAULT_QUEUE) |
	    GENET_TX_DMA_CTRL_EN);
	genet_reg_write(sc, GENET_RX_DMA_CTRL,
	    GENET_RX_DMA_CTRL_RBUF_EN(GENET_DMA_DEFAULT_QUEUE) |
	    GENET_RX_DMA_CTRL_EN);

	genet_reg_write(sc, GENET_UMAC_CMD,
	    genet_reg_read(sc, GENET_UMAC_CMD) | GENET_UMAC_CMD_TXEN |
	    GENET_UMAC_CMD_RXEN);
}

static void
genet_gmac_disable(struct genet_sc *sc)
{
	// stop rx
	genet_reg_write(sc, GENET_UMAC_CMD,
	    genet_reg_read(sc, GENET_UMAC_CMD) & ~GENET_UMAC_CMD_RXEN);
	// stop rx dma
	genet_reg_write(sc, GENET_RX_DMA_CTRL,
	    genet_reg_read(sc, GENET_RX_DMA_CTRL) & ~GENET_RX_DMA_CTRL_EN);
	// stop tx dma
	genet_reg_write(sc, GENET_TX_DMA_CTRL,
	    genet_reg_read(sc, GENET_TX_DMA_CTRL) & ~GENET_TX_DMA_CTRL_EN);
	// stop tx
	genet_reg_write(sc, GENET_UMAC_CMD,
	    genet_reg_read(sc, GENET_UMAC_CMD) & ~GENET_UMAC_CMD_TXEN);
	// flush tx fifo
	genet_reg_write(sc, GENET_UMAC_TX_FLUSH, 1);
	genet_usecwait(10);
	genet_reg_write(sc, GENET_UMAC_TX_FLUSH, 0);
}

static void
genet_free_tx(struct genet_sc *sc, int idx)
{
	if (sc->tx_ring.mp[idx]) {
		freemsg(sc->tx_ring.mp[idx]);
		sc->tx_ring.mp[idx] = NULL;
	}
}

static void
genet_free_packet(struct genet_packet *pkt)
{
	struct genet_sc *sc = pkt->sc;
	if (sc->running && sc->rx_pkt_num < RX_PKT_NUM_MAX) {
		pkt->mp = desballoc((unsigned char *)pkt->dma.addr,
		    GENET_DMA_BUFFER_SIZE, BPRI_MED, &pkt->free_rtn);
	} else {
		pkt->mp = NULL;
	}
	if (pkt->mp == NULL) {
		ddi_dma_unbind_handle(pkt->dma.dma_handle);
		ddi_dma_mem_free(&pkt->dma.mem_handle);
		ddi_dma_free_handle(&pkt->dma.dma_handle);
		kmem_free(pkt, sizeof (struct genet_packet));
	} else {
		ddi_dma_sync(pkt->dma.dma_handle, 0, pkt->dma.size,
		    DDI_DMA_SYNC_FORDEV);

		mutex_enter(&sc->rx_pkt_lock);
		pkt->next = sc->rx_pkt_free;
		sc->rx_pkt_free = pkt;
		sc->rx_pkt_num++;
		mutex_exit(&sc->rx_pkt_lock);
	}
}

static struct genet_packet *
genet_alloc_packet(struct genet_sc *sc)
{
	struct genet_packet *pkt;

	mutex_enter(&sc->rx_pkt_lock);
	pkt = sc->rx_pkt_free;
	if (pkt) {
		sc->rx_pkt_free = pkt->next;
		sc->rx_pkt_num--;
	}
	mutex_exit(&sc->rx_pkt_lock);

	if (pkt == NULL) {
		pkt = kmem_zalloc(sizeof (struct genet_packet), KM_NOSLEEP);
		if (pkt) {
			if (ddi_dma_alloc_handle(sc->dip, &dma_attr,
			    DDI_DMA_SLEEP, 0,
			    &pkt->dma.dma_handle) != DDI_SUCCESS) {
				kmem_free(pkt, sizeof (struct genet_packet));
				pkt = NULL;
			}
		}

		if (pkt) {
			if (ddi_dma_mem_alloc(pkt->dma.dma_handle,
			    GENET_DMA_BUFFER_SIZE, &mem_acc_attr,
			    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
			    &pkt->dma.addr, &pkt->dma.size,
			    &pkt->dma.mem_handle)) {
				ddi_dma_free_handle(&pkt->dma.dma_handle);
				kmem_free(pkt, sizeof (struct genet_packet));
				pkt = NULL;
			} else {
				ASSERT3U(pkt->dma.size, >=, GENET_DMA_BUFFER_SIZE);
			}
		}

		if (pkt) {
			ddi_dma_cookie_t cookie;
			uint_t ccount;
			int result;

			result = ddi_dma_addr_bind_handle(pkt->dma.dma_handle,
			    NULL, pkt->dma.addr, pkt->dma.size,
			    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
			    DDI_DMA_SLEEP, NULL, &cookie, &ccount);

			if (result == DDI_DMA_MAPPED) {
				ASSERT3U(ccount, ==, 1);
				pkt->dma.dmac_addr = cookie.dmac_laddress;
				ASSERT3U((cookie.dmac_laddress &
				    (DCACHE_LINE - 1)), ==, 0);
				ASSERT3U(cookie.dmac_size, <=,
				    GENET_DMA_BUFFER_SIZE);
				pkt->sc = sc;
				pkt->free_rtn.free_func = genet_free_packet;
				pkt->free_rtn.free_arg = (char *)pkt;

				pkt->mp = desballoc((uint8_t *)pkt->dma.addr,
				    GENET_DMA_BUFFER_SIZE, BPRI_MED,
				    &pkt->free_rtn);
				if (pkt->mp == NULL) {
					ddi_dma_unbind_handle(pkt->dma.dma_handle);
					ddi_dma_mem_free(&pkt->dma.mem_handle);
					ddi_dma_free_handle(&pkt->dma.dma_handle);
					kmem_free(pkt,
					    sizeof (struct genet_packet));
					pkt = NULL;
				}
			} else {
				ddi_dma_mem_free(&pkt->dma.mem_handle);
				ddi_dma_free_handle(&pkt->dma.dma_handle);
				kmem_free(pkt, sizeof (struct genet_packet));
				pkt = NULL;
			}
		}
	}

	return (pkt);
}

static boolean_t
genet_alloc_buffer(struct genet_sc *sc)
{
	for (int index = 0; index < GENET_DMA_DESC_COUNT; index++) {
		struct genet_packet *pkt = genet_alloc_packet(sc);
		if (!pkt)
			return (B_FALSE);
		sc->rx_ring.pkt[index] = pkt;

		genet_reg_write(sc, GENET_RX_DESC_ADDRESS_LO(index),
		    (uint32_t)pkt->dma.dmac_addr);
		genet_reg_write(sc, GENET_RX_DESC_ADDRESS_HI(index),
		    (uint32_t)(pkt->dma.dmac_addr >> 32));
	}

	for (int index = 0; index < GENET_DMA_DESC_COUNT; index++) {
		struct genet_packet *pkt = genet_alloc_packet(sc);
		if (!pkt)
			return (B_FALSE);
		sc->tx_ring.pkt[index] = pkt;

		genet_reg_write(sc, GENET_TX_DESC_ADDRESS_LO(index),
		    (uint32_t)pkt->dma.dmac_addr);
		genet_reg_write(sc, GENET_TX_DESC_ADDRESS_HI(index),
		    (uint32_t)(pkt->dma.dmac_addr >> 32));
	}

	return (B_TRUE);
}

static void
genet_free_buffer(struct genet_sc *sc)
{
	for (int i = 0; i < GENET_DMA_DESC_COUNT; i++) {
		struct genet_packet *pkt = sc->tx_ring.pkt[i];
		if (pkt) {
			freemsg(pkt->mp);
			sc->tx_ring.pkt[i] = NULL;
		}
		genet_free_tx(sc, i);
	}

	for (int i = 0; i < GENET_DMA_DESC_COUNT; i++) {
		struct genet_packet *pkt = sc->rx_ring.pkt[i];
		if (pkt != NULL) {
			freemsg(pkt->mp);
			sc->rx_ring.pkt[i] = NULL;
		}
	}

	mutex_enter(&sc->rx_pkt_lock);
	for (;;) {
		struct genet_packet *pkt = sc->rx_pkt_free;
		if (pkt == NULL)
			break;
		sc->rx_pkt_free = pkt->next;
		sc->rx_pkt_num--;
		mutex_exit(&sc->rx_pkt_lock);
		freemsg(pkt->mp);
		mutex_enter(&sc->rx_pkt_lock);
	}
	mutex_exit(&sc->rx_pkt_lock);
}

static boolean_t
genet_get_macaddr(struct genet_sc *sc)
{
	uchar_t *buf;
	uint_t len;

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, sc->dip, 0,
	    "local-mac-address", &buf, &len) != DDI_PROP_SUCCESS) {
		return (B_FALSE);
	}

	if (len != sizeof (sc->dev_addr)) {
		ddi_prop_free(buf);
		return (B_FALSE);
	}

	bcopy(buf, sc->dev_addr, sizeof (sc->dev_addr));
	ddi_prop_free(buf);
	return (B_TRUE);
}

static void
genet_destroy(struct genet_sc *sc)
{
	if (sc->intr_handle) {
		ddi_intr_disable(sc->intr_handle);
		ddi_intr_remove_handler(sc->intr_handle);
		ddi_intr_free(sc->intr_handle);
	}
	sc->intr_handle = 0;

	if (sc->mii_handle)
		mii_free(sc->mii_handle);
	sc->mii_handle = 0;

	if (sc->mac_handle) {
		mac_unregister(sc->mac_handle);
		mac_free(sc->macp);
	}
	sc->mac_handle = 0;

	genet_free_buffer(sc);

	if (sc->reg.handle)
		ddi_regs_map_free(&sc->reg.handle);
	sc->reg.handle = 0;

	ddi_set_driver_private(sc->dip, NULL);
	struct genet_mcast *mc;
	while ((mc = list_head(&sc->mcast)) != NULL) {
		list_remove(&sc->mcast, mc);
		kmem_free(mc, sizeof (*mc));
	}
	list_destroy(&sc->mcast);
	mutex_destroy(&sc->intrlock);
	mutex_destroy(&sc->rx_pkt_lock);
	kmem_free(sc, sizeof (*sc));
}

static boolean_t
genet_init(struct genet_sc *sc)
{
	if (!genet_get_macaddr(sc))
		return (B_FALSE);

	genet_gmac_reset(sc);

	return (B_TRUE);
}

#define	MII_BUSY_RETRY		1000

static void
genet_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t value)
{
	struct genet_sc *sc = arg;

	genet_mutex_enter(sc);
	if ((genet_reg_read(sc, GENET_MDIO_CMD) & GENET_MDIO_START_BUSY) == 0) {
		genet_reg_write(sc, GENET_MDIO_CMD,
		    GENET_MDIO_WRITE | (phy << GENET_MDIO_ADDR_SHIFT) |
		    (reg << GENET_MDIO_REG_SHIFT) |
		    (value & GENET_MDIO_VAL_MASK));
		genet_reg_write(sc, GENET_MDIO_CMD,
		    genet_reg_read(sc, GENET_MDIO_CMD) | GENET_MDIO_START_BUSY);

		int retry;
		for (retry = MII_BUSY_RETRY; retry > 0; retry--) {
			if ((genet_reg_read(sc, GENET_MDIO_CMD) &
			    GENET_MDIO_START_BUSY) == 0) {
				break;
			}
			genet_usecwait(10);
		}
		if (retry == 0)
			cmn_err(CE_WARN, "%s%d: MII write failed (timeout)",
			    ddi_driver_name(sc->dip),
			    ddi_get_instance(sc->dip));
	} else {
		cmn_err(CE_WARN, "%s%d: MII write failed (busy)",
		    ddi_driver_name(sc->dip), ddi_get_instance(sc->dip));
	}
	genet_mutex_exit(sc);
}

static uint16_t
genet_mii_read(void *arg, uint8_t phy, uint8_t reg)
{
	struct genet_sc *sc = arg;

	uint16_t data = 0xffff;

	genet_mutex_enter(sc);

	if ((genet_reg_read(sc, GENET_MDIO_CMD) & GENET_MDIO_START_BUSY) == 0) {
		genet_reg_write(sc, GENET_MDIO_CMD, GENET_MDIO_READ |
		    (phy << GENET_MDIO_ADDR_SHIFT) |
		    (reg << GENET_MDIO_REG_SHIFT));
		genet_reg_write(sc, GENET_MDIO_CMD,
		    genet_reg_read(sc, GENET_MDIO_CMD) | GENET_MDIO_START_BUSY);

		int retry;
		for (retry = MII_BUSY_RETRY; retry > 0; retry--) {
			uint32_t val = genet_reg_read(sc, GENET_MDIO_CMD);
			if ((val & GENET_MDIO_START_BUSY) == 0) {
				if ((val & GENET_MDIO_READ_FAILED) == 0) {
					data = (val & GENET_MDIO_VAL_MASK);
				}
				break;
			}
			genet_usecwait(10);
		}
		if (retry == 0)
			cmn_err(CE_WARN, "%s%d: MII read failed (timeout)",
			    ddi_driver_name(sc->dip),
			    ddi_get_instance(sc->dip));
	} else {
		cmn_err(CE_WARN, "%s%d: MII read failed (busy)",
		    ddi_driver_name(sc->dip), ddi_get_instance(sc->dip));
	}

	genet_mutex_exit(sc);

	return (data);
}

static int
genet_probe(dev_info_t *dip)
{
	char *buf;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    OBP_STATUS, &buf) != DDI_SUCCESS) {
		return (DDI_PROBE_SUCCESS);
	}

	if (strcmp(buf, "ok") != 0 && strcmp(buf, "okay") != 0) {
		ddi_prop_free(buf);
		return (DDI_PROBE_FAILURE);
	}

	ddi_prop_free(buf);
	return (DDI_PROBE_SUCCESS);
}

static void
genet_mii_notify(void *arg, link_state_t link)
{
	struct genet_sc *sc = arg;
	link_flowctrl_t fc __unused; /* XXXARM */
	link_duplex_t duplex;
	int speed;

	fc = mii_get_flowctrl(sc->mii_handle);
	duplex = mii_get_duplex(sc->mii_handle);
	speed = mii_get_speed(sc->mii_handle);

	genet_mutex_enter(sc);

	if (link == LINK_STATE_UP) {
		sc->phy_speed = speed;
		sc->phy_duplex = duplex;
		genet_gmac_update(sc);
	} else {
		sc->phy_speed = -1;
		sc->phy_duplex = LINK_DUPLEX_UNKNOWN;
	}

	genet_mutex_exit(sc);

	mac_link_update(sc->mac_handle, link);
}

static void
genet_mii_reset(void *arg)
{
	struct genet_sc *sc = arg;
	int phy = mii_get_addr(sc->mii_handle);

	genet_mii_write(sc, phy, 0x0d, 0x7);
	genet_mii_write(sc, phy, 0x0e, 0x3c);
	genet_mii_write(sc, phy, 0x0d, 0x4007);
	genet_mii_write(sc, phy, 0x0e, 0);

	uint16_t v = genet_mii_read(sc, phy, 9);
	genet_mii_write(sc, phy, 9, v & ~(1u << 9));
}

static mii_ops_t genet_mii_ops = {
	MII_OPS_VERSION,
	genet_mii_read,
	genet_mii_write,
	genet_mii_notify,
	genet_mii_reset	/* reset */
};

static int
genet_phy_install(struct genet_sc *sc)
{
	sc->mii_handle = mii_alloc(sc, sc->dip, &genet_mii_ops);
	if (sc->mii_handle == NULL) {
		return (DDI_FAILURE);
	}
	// mii_set_pauseable(sc->mii_handle, B_FALSE, B_FALSE);

	return (DDI_SUCCESS);
}

static mblk_t *
genet_send(struct genet_sc *sc, mblk_t *mp)
{
	if (((sc->tx_ring.p_index - sc->tx_ring.c_index +
	    GENET_DMA_DESC_COUNT) % GENET_DMA_DESC_COUNT) ==
	    (GENET_DMA_DESC_COUNT - 8)) {
		return (mp);
	}

	int index = sc->tx_ring.p_index % GENET_DMA_DESC_COUNT;
	size_t mblen = 0;
	sc->tx_ring.mp[index] = mp;
	struct genet_packet *pkt = sc->tx_ring.pkt[index];

	caddr_t addr = pkt->dma.addr;
	for (mblk_t *bp = mp; bp != NULL; bp = bp->b_cont) {
		size_t frag_len = MBLKL(bp);
		if (frag_len == 0)
			continue;
		memcpy(addr, bp->b_rptr, frag_len);
		addr += frag_len;
		mblen += frag_len;
	}
	if (mblen < 0x40)
		mblen = 0x40;

	ddi_dma_sync(pkt->dma.dma_handle, 0, mblen, DDI_DMA_SYNC_FORDEV);

	uint32_t length_status = GENET_TX_DESC_STATUS_QTAG_MASK;
	length_status |= GENET_TX_DESC_STATUS_SOP |
	    GENET_TX_DESC_STATUS_EOP | GENET_TX_DESC_STATUS_CRC;
	length_status |= mblen << GENET_TX_DESC_STATUS_BUFLEN_SHIFT;
	genet_reg_write(sc, GENET_TX_DESC_STATUS(index), length_status);

	uint32_t prod = sc->tx_ring.p_index;
	prod = (prod + 1) & GENET_TX_DMA_PROD_CONS_MASK;
	genet_reg_write(sc, GENET_TX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE),
	    prod);

	sc->tx_ring.p_index = prod;

	return (NULL);
}

static mblk_t *
genet_m_tx(void *arg, mblk_t *mp)
{
	struct genet_sc *sc = arg;
	mblk_t *nmp;

	genet_mutex_enter(sc);

	int count = 0;
	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;
		if ((mp = genet_send(sc, mp)) != NULL) {
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
		count++;
	}

	genet_mutex_exit(sc);

	return (mp);
}


static mblk_t *
genet_rx_intr(struct genet_sc *sc)
{

	mblk_t *mblk_head = NULL;
	mblk_t **mblk_tail = &mblk_head;

	uint32_t prod = genet_reg_read(sc,
	    GENET_RX_DMA_PROD_INDEX(GENET_DMA_DEFAULT_QUEUE)) &
	    GENET_RX_DMA_PROD_CONS_MASK;
	int index = sc->rx_ring.c_index % GENET_DMA_DESC_COUNT;
	uint32_t num = (prod - sc->rx_ring.c_index) &
	    GENET_RX_DMA_PROD_CONS_MASK;

	for (int i = 0; i < num; i++) {
		int len = 0;
		uint32_t status = genet_reg_read(sc,
		    GENET_RX_DESC_STATUS(index));

		if ((status & (GENET_RX_DESC_STATUS_SOP |
		    GENET_RX_DESC_STATUS_EOP |
		    GENET_RX_DESC_STATUS_RX_ERROR)) ==
		    (GENET_RX_DESC_STATUS_SOP | GENET_RX_DESC_STATUS_EOP)) {
			len = (status & GENET_RX_DESC_STATUS_BUFLEN_MASK) >>
			    GENET_RX_DESC_STATUS_BUFLEN_SHIFT;
		}

		if (len > 2) {
			struct genet_packet *pkt = genet_alloc_packet(sc);
			if (pkt) {
				mblk_t *mp = sc->rx_ring.pkt[index]->mp;
				*mblk_tail = mp;
				mblk_tail = &mp->b_next;
				ddi_dma_sync(sc->rx_ring.pkt[index]->dma.dma_handle,
				    0, len, DDI_DMA_SYNC_FORKERNEL);
				mp->b_rptr += 2;
				mp->b_wptr += len;
				sc->rx_ring.pkt[index] = pkt;
			}
		}

		{
			struct genet_packet *pkt = sc->rx_ring.pkt[index];
			genet_reg_write(sc, GENET_RX_DESC_ADDRESS_LO(index),
			    (uint32_t)pkt->dma.dmac_addr);
			genet_reg_write(sc, GENET_RX_DESC_ADDRESS_HI(index),
			    (uint32_t)(pkt->dma.dmac_addr >> 32));
		}

		index = ((index + 1) % GENET_DMA_DESC_COUNT);
	}

	if (num > 0) {
		sc->rx_ring.c_index = prod;
		genet_reg_write(sc,
		    GENET_RX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE),
		    sc->rx_ring.c_index);
	}

	return (mblk_head);
}


static int
genet_tx_intr(struct genet_sc *sc)
{
	int cons = genet_reg_read(sc,
	    GENET_TX_DMA_CONS_INDEX(GENET_DMA_DEFAULT_QUEUE)) &
	    GENET_TX_DMA_PROD_CONS_MASK;
	int num = (cons - sc->tx_ring.c_index) & GENET_TX_DMA_PROD_CONS_MASK;

	int index = sc->tx_ring.c_index % GENET_DMA_DESC_COUNT;
	for (int i = 0; i < num; i++) {
		genet_free_tx(sc, index);
		index = (index + 1) % GENET_DMA_DESC_COUNT;
	}
	sc->tx_ring.c_index = cons;
	return (num);
}

static uint_t
genet_intr(caddr_t arg, caddr_t unused)
{
	struct genet_sc *sc = (struct genet_sc *)arg;

	genet_mutex_enter(sc);

	for (;;) {
		uint32_t status = genet_reg_read(sc, GENET_INTRL2_CPU_STAT);
		status &= ~genet_reg_read(sc, GENET_INTRL2_CPU_STAT_MASK);
		genet_reg_write(sc, GENET_INTRL2_CPU_CLEAR, status);

		if ((status & (GENET_IRQ_RXDMA_DONE |
		    GENET_IRQ_TXDMA_DONE)) == 0) {
			break;
		}

		if (sc->running == 0)
			break;

		if (status & GENET_IRQ_RXDMA_DONE) {
			mblk_t *mp = genet_rx_intr(sc);
			if (mp) {
				genet_mutex_exit(sc);
				mac_rx(sc->mac_handle, NULL, mp);
				genet_mutex_enter(sc);

				if (sc->running == 0)
					break;
			}
		}


		if (status & GENET_IRQ_TXDMA_DONE) {
			int tx = 0;

			tx = genet_tx_intr(sc);

			if (tx) {
				genet_mutex_exit(sc);
				mac_tx_update(sc->mac_handle);
				genet_mutex_enter(sc);

				if (sc->running == 0)
					break;
			}
		}
	}

	genet_mutex_exit(sc);

	return (DDI_INTR_CLAIMED);
}


static int genet_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int
genet_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}
	struct genet_sc *sc = ddi_get_driver_private(dip);

	genet_m_stop(sc);

	if (mac_disable(sc->mac_handle) != 0)
		return (DDI_FAILURE);

	genet_destroy(sc);

	return (DDI_SUCCESS);
}

static int
genet_quiesce(dev_info_t *dip)
{
	cmn_err(CE_WARN, "%s%d: genet_quiesce is not implemented",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	return (DDI_FAILURE);
}

static void
genet_set_mdf(struct genet_sc *sc, int index, const uint8_t *addr)
{
	genet_reg_write(sc, GENET_UMAC_MDF_ADDR0(index),
	    addr[0] << 8 | addr[1]);
	genet_reg_write(sc, GENET_UMAC_MDF_ADDR1(index), addr[2] << 24 |
	    addr[3] << 16 | addr[4] << 8 | addr[5]);
}

static void
genet_update_filter(struct genet_sc *sc)
{
	int num = 2;
	uint32_t cmd = genet_reg_read(sc, GENET_UMAC_CMD);
	uint32_t mdf_ctrl = 0;

	for (struct genet_mcast *mc = list_head(&sc->mcast); mc != NULL;
	    mc = list_next(&sc->mcast, mc)) {
		num++;
	}

	if (num > GENET_MAX_MDF_FILTER || sc->promisc) {
		cmd |= GENET_UMAC_CMD_PROMISC;
		mdf_ctrl = 0;
	} else {
		cmd &= ~GENET_UMAC_CMD_PROMISC;
		int index = 0;
		const uint8_t ba[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		genet_set_mdf(sc, index++, ba);
		genet_set_mdf(sc, index++, sc->dev_addr);

		for (struct genet_mcast *mc = list_head(&sc->mcast); mc != NULL;
		    mc = list_next(&sc->mcast, mc)) {
			genet_set_mdf(sc, index++, mc->addr);
		}
		mdf_ctrl = __BITS(GENET_MAX_MDF_FILTER - 1,
		    GENET_MAX_MDF_FILTER - index);
	}
	genet_reg_write(sc, GENET_UMAC_CMD, cmd);
	genet_reg_write(sc, GENET_UMAC_MDF_CTRL, mdf_ctrl);
}

static int
genet_m_setpromisc(void *a, boolean_t b)
{
	struct genet_sc *sc = a;
	genet_mutex_enter(sc);

	if (b)
		sc->promisc = (B_TRUE);
	else
		sc->promisc = (B_FALSE);

	genet_update_filter(sc);

	genet_mutex_exit(sc);

	return (0);
}

static int
genet_m_multicst(void *a, boolean_t b, const uint8_t *c)
{
	struct genet_sc *sc = a;
	struct genet_mcast *mc;

	genet_mutex_enter(sc);

	if (b) {
		mc = kmem_alloc(sizeof (*mc), KM_NOSLEEP);
		if (!mc) {
			genet_mutex_exit(sc);
			return (ENOMEM);
		}

		memcpy(mc->addr, c, sizeof (mc->addr));
		list_insert_head(&sc->mcast, mc);
	} else {
		for (mc = list_head(&sc->mcast); mc != NULL;
		    mc = list_next(&sc->mcast, mc)) {
			if (memcmp(mc->addr, c, sizeof (mc->addr)) == 0) {
				list_remove(&sc->mcast, mc);
				kmem_free(mc, sizeof (*mc));
				break;
			}
		}
	}

	genet_update_filter(sc);

	genet_mutex_exit(sc);
	return (0);
}

static void
genet_write_hwaddr(struct genet_sc *sc)
{
	uint8_t *addr = sc->dev_addr;
	genet_reg_write(sc, GENET_UMAC_MAC0, addr[0] << 24 | addr[1] << 16 |
	    addr[2] << 8 | addr[3]);
	genet_reg_write(sc, GENET_UMAC_MAC1, addr[4] << 8 | addr[5]);
}

static int
genet_m_unicst(void *arg, const uint8_t *dev_addr)
{
	struct genet_sc *sc = arg;

	genet_mutex_enter(sc);

	memcpy(sc->dev_addr, dev_addr, sizeof (sc->dev_addr));

	genet_write_hwaddr(sc);
	genet_update_filter(sc);

	genet_mutex_exit(sc);

	return (0);
}

static int
genet_m_start(void *arg)
{
	struct genet_sc *sc = arg;

	genet_mutex_enter(sc);

	if (!genet_alloc_buffer(sc)) {
		genet_mutex_exit(sc);
		return (ENOMEM);
	}
	genet_gmac_init(sc);
	genet_write_hwaddr(sc);
	genet_update_filter(sc);
	genet_gmac_enable(sc);

	sc->running = 1;

	if (ddi_intr_enable(sc->intr_handle) != DDI_SUCCESS) {
		sc->running = 0;
		genet_gmac_disable(sc);
		genet_free_buffer(sc);
		genet_mutex_exit(sc);
		return (EIO);
	}

	genet_mutex_exit(sc);

	mii_start(sc->mii_handle);

	return (0);
}

static void
genet_m_stop(void *arg)
{
	struct genet_sc *sc = arg;

	mii_stop(sc->mii_handle);

	genet_mutex_enter(sc);

	ddi_intr_disable(sc->intr_handle);

	sc->running = 0;
	genet_gmac_disable(sc);
	genet_free_buffer(sc);

	genet_mutex_exit(sc);
}

static int
genet_m_getstat(void *arg, uint_t stat, uint64_t *val)
{
	struct genet_sc *sc = arg;
	return (mii_m_getstat(sc->mii_handle, stat, val));
}

static int
genet_m_setprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    const void *val)
{
	struct genet_sc *sc = arg;
	return (mii_m_setprop(sc->mii_handle, name, num, sz, val));
}

static int
genet_m_getprop(void *arg, const char *name, mac_prop_id_t num,
    uint_t sz, void *val)
{
	struct genet_sc *sc = arg;
	return (mii_m_getprop(sc->mii_handle, name, num, sz, val));
}

static void
genet_m_propinfo(void *arg, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	struct genet_sc *sc = arg;
	mii_m_propinfo(sc->mii_handle, name, num, prh);
}

static void
genet_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct genet_sc *sc = arg;
	if (mii_m_loop_ioctl(sc->mii_handle, wq, mp))
		return;

	miocnak(wq, mp, 0, EINVAL);
}

extern struct mod_ops mod_driverops;

DDI_DEFINE_STREAM_OPS(genet_devops, nulldev, genet_probe, genet_attach,
    genet_detach, nodev, NULL, D_MP, NULL, genet_quiesce);

static struct modldrv genet_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Amlogic gmac",		/* short description */
	&genet_devops		/* driver specific ops */
};

static struct modlinkage genet_modlinkage = {
	MODREV_1,		/* ml_rev */
	{ &genet_modldrv, NULL }	/* ml_linkage */
};

static mac_callbacks_t genet_m_callbacks = {
	MC_SETPROP | MC_GETPROP | MC_PROPINFO,	/* mc_callbacks */
	genet_m_getstat,	/* mc_getstat */
	genet_m_start,		/* mc_start */
	genet_m_stop,		/* mc_stop */
	genet_m_setpromisc,	/* mc_setpromisc */
	genet_m_multicst,	/* mc_multicst */
	genet_m_unicst,		/* mc_unicst */
	genet_m_tx,		/* mc_tx */
	NULL,
	genet_m_ioctl,		/* mc_ioctl */
	NULL,			/* mc_getcapab */
	NULL,			/* mc_open */
	NULL,			/* mc_close */
	genet_m_setprop,
	genet_m_getprop,
	genet_m_propinfo
};

static int
genet_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	struct genet_sc *sc = kmem_zalloc(sizeof (struct genet_sc), KM_SLEEP);
	ddi_set_driver_private(dip, sc);
	sc->dip = dip;

	mutex_init(&sc->intrlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->rx_pkt_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&sc->mcast, sizeof (struct genet_mcast),
	    offsetof(struct genet_mcast, node));

	if (ddi_regs_map_setup(sc->dip, 0, &sc->reg.addr, 0, 0,
	    &reg_acc_attr, &sc->reg.handle) != DDI_SUCCESS) {
		goto err_exit;
	}

	genet_mutex_enter(sc);
	if (!genet_init(sc)) {
		genet_mutex_exit(sc);
		goto err_exit;
	}
	genet_mutex_exit(sc);

	mac_register_t *macp;
	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		goto err_exit;
	}
	sc->macp = macp;

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = sc;
	macp->m_dip = dip;
	macp->m_src_addr = sc->dev_addr;
	macp->m_callbacks = &genet_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;

	if (mac_register(macp, &sc->mac_handle) != 0) {
		mac_free(sc->macp);
		sc->mac_handle = 0;
		goto err_exit;
	}

	if (genet_phy_install(sc) != DDI_SUCCESS) {
		goto err_exit;
	}

	int actual;
	if (ddi_intr_alloc(dip, &sc->intr_handle, DDI_INTR_TYPE_FIXED, 0, 1,
	    &actual, DDI_INTR_ALLOC_STRICT) != DDI_SUCCESS) {
		goto err_exit;
	}

	if (ddi_intr_add_handler(sc->intr_handle,
	    genet_intr, sc, NULL) != DDI_SUCCESS) {
		ddi_intr_free(sc->intr_handle);
		sc->intr_handle = 0;
		goto err_exit;
	}

	return (DDI_SUCCESS);
err_exit:
	genet_destroy(sc);
	return (DDI_FAILURE);
}

int
_init(void)
{
	int i;

	mac_init_ops(&genet_devops, "bcm2711_genet");

	if ((i = mod_install(&genet_modlinkage)) != 0) {
		mac_fini_ops(&genet_devops);
	}
	return (i);
}

int
_fini(void)
{
	int i;

	if ((i = mod_remove(&genet_modlinkage)) == 0) {
		mac_fini_ops(&genet_devops);
	}
	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&genet_modlinkage, modinfop));
}
