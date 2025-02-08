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
 * Copyright 2021 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/stdbool.h>
#include <sys/promif.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/smp_impldefs.h>
#include <sys/bcm2835_mbox.h>
#include <sys/bcm2835_mboxreg.h>
#include <sys/bcm2835_vcprop.h>
#include <sys/bcm2835_vcio.h>

static bool mbox_initialized = false;
static kmutex_t mbox_lock;

static ddi_dma_attr_t dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	.dma_attr_addr_lo = 0x0000000000000000ull,
	.dma_attr_addr_hi = 0x000000003FFFFFFFull,
	.dma_attr_count_max = 0x000000003FFFFFFFull,
	.dma_attr_align = 0x0000000000000001ull,
	.dma_attr_burstsizes = 0x00000FFF,
	.dma_attr_minxfer = 0x00000001,
	.dma_attr_maxxfer = 0x000000000FFFFFFFull,
	.dma_attr_seg = 0x000000000FFFFFFFull,
	.dma_attr_sgllen = 1,
	.dma_attr_granular = 0x00000001,
	.dma_attr_flags = DDI_DMA_FLAGERR
};
static ddi_dma_attr_t dma_mem_attr;

static caddr_t mbox_buffer;
static paddr_t mbox_buffer_phys;

typedef struct {
	void	*mbox_base;
	size_t	mbox_size;
} mbox_conf_t;

static mbox_conf_t mbox_conf;

static int
bcm2835_find_mbox(dev_info_t *dip, void *arg)
{
	pnode_t node = ddi_get_nodeid(dip);
	if (node > 0) {
		if (prom_is_compatible(node, "brcm,bcm2835-mbox")) {
			*(dev_info_t **)arg = dip;
			return (DDI_WALK_TERMINATE);
		}
	}
	return (DDI_WALK_CONTINUE);
}

static void
bcm2835_mbox_init(void)
{
	int err;

	ASSERT(MUTEX_HELD(&mbox_lock));

	ASSERT3P(mbox_conf.mbox_base, ==, NULL);

	dev_info_t *dip = NULL;
	ddi_walk_devs(ddi_root_node(), bcm2835_find_mbox, &dip);

	if (dip == NULL)
		cmn_err(CE_PANIC, "mbox register is not found");

	pnode_t node = ddi_get_nodeid(dip);
	ASSERT(node > 0);

	uint64_t mbox_base, mbox_size;
	if (prom_get_reg_address(node, 0, &mbox_base) != 0) {
		cmn_err(CE_PANIC,
		    "prom_get_reg_address failed for mbox register");
	}

	if (prom_get_reg_size(node, 0, &mbox_size) != 0) {
		cmn_err(CE_PANIC,
		    "prom_get_reg_size failed for mbox register");
	}

	caddr_t addr = psm_map_phys(mbox_base, mbox_size, PROT_READ|PROT_WRITE);
	if (addr == NULL)
		cmn_err(CE_PANIC, "failed to map mbox");

	mbox_conf.mbox_base = addr;
	mbox_conf.mbox_size = mbox_size;

	int rv;
	rv = i_ddi_update_dma_attr(dip, &dma_attr);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "i_ddi_update_dma_attr failed (%d)!", rv);
	}
	dma_attr.dma_attr_count_max = dma_attr.dma_attr_addr_hi -
	    dma_attr.dma_attr_addr_lo;

	rv = i_ddi_convert_dma_attr(&dma_mem_attr, dip, &dma_attr);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "i_ddi_convert_dma_attr failed (%d)!", rv);
	}

	err = i_ddi_mem_alloc(NULL, &dma_mem_attr, MMU_PAGESIZE, 0,
	    IOMEM_DATA_UNCACHED, NULL, &mbox_buffer, NULL, NULL);
	if (err != DDI_SUCCESS)
		cmn_err(CE_PANIC, "i_ddi_mem_alloc faild for mbox buffer");
	mbox_buffer_phys = ptob(hat_getpfnum(kas.a_hat, mbox_buffer));
	ASSERT(mbox_buffer_phys == (uint32_t)mbox_buffer_phys);
}

static uint32_t
bcm2835_mbox_reg_read(uint32_t offset)
{
	return (*(volatile uint32_t *)(mbox_conf.mbox_base + offset));
}

static void
bcm2835_mbox_reg_write(uint32_t offset, uint32_t val)
{
	*(volatile uint32_t *)(mbox_conf.mbox_base + offset) = val;
}

static uint32_t
bcm2835_mbox_prop_send_impl(uint32_t chan, uint32_t addr)
{
	// sync
	for (;;) {
		if (bcm2835_mbox_reg_read(BCM2835_MBOX0_STATUS) &
		    BCM2835_MBOX_STATUS_EMPTY) {
			break;
		}
		bcm2835_mbox_reg_read(BCM2835_MBOX0_READ);
	}
	for (;;) {
		if (!(bcm2835_mbox_reg_read(BCM2835_MBOX1_STATUS) &
		    BCM2835_MBOX_STATUS_FULL)) {
			break;
		}
	}

	bcm2835_mbox_reg_write(BCM2835_MBOX1_WRITE,
	    BCM2835_MBOX_MSG(chan, addr));

	for (;;) {
		if ((bcm2835_mbox_reg_read(BCM2835_MBOX0_STATUS) &
		    BCM2835_MBOX_STATUS_EMPTY)) {
			continue;
		}
		uint32_t val = bcm2835_mbox_reg_read(BCM2835_MBOX0_READ);
		uint8_t rchan = BCM2835_MBOX_CHAN(val);
		uint32_t rdata = BCM2835_MBOX_DATA(val);
		ASSERT(rchan == chan);
		ASSERT(addr == rdata);
		return (rdata);
	}
}

static void
bcm2835_copy_buffer(void * dst, void *src, uint32_t len)
{
	while (len >= sizeof (uint64_t)) {
		*(volatile uint64_t *)dst = *(volatile uint64_t *)src;
		dst = (caddr_t)dst + sizeof (uint64_t);
		src = (caddr_t)src + sizeof (uint64_t);
		len -= sizeof (uint64_t);
	}
	while (len > 0) {
		*(volatile uint8_t *)dst = *(volatile uint8_t *)src;
		dst = (caddr_t)dst + sizeof (uint8_t);
		src = (caddr_t)src + sizeof (uint8_t);
		len -= sizeof (uint8_t);
	}
}

void
bcm2835_mbox_prop_send(void *data, uint32_t len)
{
	ASSERT(len <= MMU_PAGESIZE);

	mutex_enter(&mbox_lock);

	if (!mbox_initialized) {
		bcm2835_mbox_init();
		mbox_initialized = true;
	}

	bcm2835_copy_buffer(mbox_buffer, data, len);

	bcm2835_mbox_prop_send_impl(BCMMBOX_CHANARM2VC,
	    (uint32_t)(mbox_buffer_phys - dma_mem_attr.dma_attr_addr_lo +
	    dma_attr.dma_attr_addr_lo));

	bcm2835_copy_buffer(data, mbox_buffer, len);

	mutex_exit(&mbox_lock);
}
