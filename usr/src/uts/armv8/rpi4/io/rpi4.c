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
 */

#include <sys/types.h>
#include <sys/machclock.h>
#include <sys/platform.h>
#include <sys/modctl.h>
#include <sys/platmod.h>
#include <sys/promif.h>
#include <sys/errno.h>
#include <sys/byteorder.h>
#include <sys/cmn_err.h>
#include <sys/bootsvcs.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/param.h>
#include <vm/hat.h>
#include <sys/bcm2835_mbox.h>
#include <sys/bcm2835_mboxreg.h>
#include <sys/bcm2835_vcprop.h>
#include <sys/bcm2835_vcio.h>
#include <sys/gpio.h>

/*
 * Clock IDs from DT bindings
 *
 * These are the devicetree clock IDs, which will be internally mapped to
 * mailbox properties interface clock IDs in plat_hwclock_get_rate.
 *
 * The comments after each define show the decimal value, the symbolic
 * name of the mailbox properties interface clock ID and the decimal
 * value of that clock ID.
 */
#define	DTPROP_CLK_ARM		0x7	/*  7: VCPROP_CLK_ARM (3) */
#define	DTPROP_CLK_UART		0x13	/* 19: VCPROP_CLK_UART (2) */
#define	DTPROP_CLK_EMMC		0x1C	/* 28: VCPROP_CLK_EMMC (1) */
#define	DTPROP_CLK_EMMC2	0x33	/* 51: VCPROP_CLK_EMMC2 (12) */

void
set_platform_defaults(void)
{
}

static void
find_cprman(pnode_t node, void *arg)
{
	if (!prom_is_compatible(node, "brcm,bcm2711-cprman"))
		return;
	*(pnode_t *)arg = node;
}

uint64_t
plat_get_cpu_clock(int cpu_no)
{
	pnode_t node = 0;
	int err;

	prom_walk(find_cprman, &node);
	if (node == 0)
		cmn_err(CE_PANIC, "cprman register is not found");

	struct prom_hwclock clk = { node, DTPROP_CLK_ARM };
	err = plat_hwclock_get_rate(&clk);
	if (err == -1)
		cmn_err(CE_PANIC, "unable to read CPU clock rate");
	return (err);
}

static kmutex_t mbox_lock;

static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0x000000003FFFFFFFull,		/* dma_attr_addr_hi	*/
	0x000000003FFFFFFFull,		/* dma_attr_count_max	*/
	0x0000000000000001ull,		/* dma_attr_align	*/
	0x00000FFF,			/* dma_attr_burstsizes	*/
	0x00000001,			/* dma_attr_minxfer	*/
	0x000000000FFFFFFFull,		/* dma_attr_maxxfer	*/
	0x000000000FFFFFFFull,		/* dma_attr_seg		*/
	1,				/* dma_attr_sgllen	*/
	0x00000001,			/* dma_attr_granular	*/
	DDI_DMA_FLAGERR			/* dma_attr_flags	*/
};
static ddi_dma_attr_t dma_mem_attr;

static caddr_t mbox_buffer;
static paddr_t mbox_buffer_phys;
static uintptr_t mbox_base;

static int
find_mbox(dev_info_t *dip, void *arg)
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
mbox_init(void)
{
	uint64_t base;
	int err;

	ASSERT(MUTEX_HELD(&mbox_lock));

	dev_info_t *dip = NULL;
	ddi_walk_devs(ddi_root_node(), find_mbox, &dip);

	if (dip == NULL)
		cmn_err(CE_PANIC, "mbox register is not found");

	pnode_t node = ddi_get_nodeid(dip);
	ASSERT(node > 0);
	if (prom_get_reg_address(node, 0, &base) != 0) {
		cmn_err(CE_PANIC,
		    "prom_get_reg_address failed for mbox register");
	}
	mbox_base = SEGKPM_BASE + base;

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
mbox_reg_read(uint32_t offset)
{
	return (*(volatile uint32_t *)(mbox_base + offset));
}
static void
mbox_reg_write(uint32_t offset, uint32_t val)
{
	*(volatile uint32_t *)(mbox_base + offset) = val;
}
static uint32_t
mbox_prop_send_impl(uint32_t chan, uint32_t addr)
{
	// sync
	for (;;) {
		if (mbox_reg_read(BCM2835_MBOX0_STATUS) &
		    BCM2835_MBOX_STATUS_EMPTY) {
			break;
		}
		mbox_reg_read(BCM2835_MBOX0_READ);
	}
	for (;;) {
		if (!(mbox_reg_read(BCM2835_MBOX1_STATUS) &
		    BCM2835_MBOX_STATUS_FULL)) {
			break;
		}
	}

	mbox_reg_write(BCM2835_MBOX1_WRITE, BCM2835_MBOX_MSG(chan, addr));

	for (;;) {
		if ((mbox_reg_read(BCM2835_MBOX0_STATUS) &
		    BCM2835_MBOX_STATUS_EMPTY)) {
			continue;
		}
		uint32_t val = mbox_reg_read(BCM2835_MBOX0_READ);
		uint8_t rchan = BCM2835_MBOX_CHAN(val);
		uint32_t rdata = BCM2835_MBOX_DATA(val);
		ASSERT(rchan == chan);
		ASSERT(addr == rdata);
		return (rdata);
	}
}

static void
copy_buffer(void * dst, void *src, uint32_t len)
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

static void
mbox_prop_send(void *data, uint32_t len)
{
	ASSERT(len <= MMU_PAGESIZE);

	mutex_enter(&mbox_lock);

	static bool mbox_initialized = false;
	if (!mbox_initialized) {
		mbox_init();
		mbox_initialized = true;
	}

	copy_buffer(mbox_buffer, data, len);

	mbox_prop_send_impl(BCMMBOX_CHANARM2VC, (uint32_t)(mbox_buffer_phys -
	    dma_mem_attr.dma_attr_addr_lo + dma_attr.dma_attr_addr_lo));

	copy_buffer(data, mbox_buffer, len);

	mutex_exit(&mbox_lock);
}

int
plat_hwclock_get_rate(struct prom_hwclock *clk)
{
	if (!prom_is_compatible(clk->node, "brcm,bcm2711-cprman"))
		return (-1);

	int id;
	switch (clk->id) {
	case DTPROP_CLK_ARM: id = VCPROP_CLK_ARM; break;
	case DTPROP_CLK_UART: id = VCPROP_CLK_UART; break;
	case DTPROP_CLK_EMMC: id = VCPROP_CLK_EMMC; break;
	case DTPROP_CLK_EMMC2: id = VCPROP_CLK_EMMC2; break;
	default: return (-1);
	}

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_clockrate	vbt_clockrate;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof (vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_clockrate = {
			.tag = {
				.vpt_tag = VCPROPTAG_GET_CLOCKRATE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_clockrate),
				.vpt_rcode = VCPROPTAG_REQUEST,
			},
			.id = id,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL
		},
	};

	mbox_prop_send(&vb, sizeof (vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return (-1);
	if (!vcprop_tag_success_p(&vb.vbt_clockrate.tag))
		return (-1);

	return (vb.vbt_clockrate.rate);
}

int
plat_gpio_get(struct gpio_ctrl *gpio)
{
	int offset;
	if (prom_is_compatible(gpio->node, "raspberrypi,firmware-gpio")) {
		offset = 128;
	} else if (prom_is_compatible(gpio->node, "brcm,bcm2711-gpio")) {
		offset = 0;
	} else {
		return (-1);
	}

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_gpiostate	vbt_gpio;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof (vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_gpio = {
			.tag = {
				.vpt_tag = VCPROPTAG_GET_GPIO_STATE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_gpio),
				.vpt_rcode = VCPROPTAG_REQUEST,
			},
			.gpio = gpio->pin + offset,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL
		},
	};

	mbox_prop_send(&vb, sizeof (vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return (-1);
	if (!vcprop_tag_success_p(&vb.vbt_gpio.tag))
		return (-1);

	return (vb.vbt_gpio.state);
}

int
plat_gpio_set(struct gpio_ctrl *gpio, int value)
{
	int offset;
	if (prom_is_compatible(gpio->node, "raspberrypi,firmware-gpio")) {
		offset = VCPROP_EXP_GPIO_BASE;
	} else if (prom_is_compatible(gpio->node, "brcm,bcm2711-gpio")) {
		offset = 0;
	} else {
		return (-1);
	}

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_gpiostate	vbt_gpio;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof (vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_gpio = {
			.tag = {
				.vpt_tag = VCPROPTAG_SET_GPIO_STATE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_gpio),
				.vpt_rcode = VCPROPTAG_REQUEST,
			},
			.gpio = gpio->pin + offset,
			.state = value,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL
		},
	};

	mbox_prop_send(&vb, sizeof (vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return (-1);

	return (0);
}
