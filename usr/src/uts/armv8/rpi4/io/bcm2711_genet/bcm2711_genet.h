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

#ifndef _IO_GENET_H
#define _IO_GENET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/platform.h>
#include <sys/mac.h>
#include <sys/mii.h>
#include <sys/ethernet.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/bcm2711_genetreg.h>

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

#ifdef __cplusplus
}
#endif

#endif	/* _IO_GENET_H */
