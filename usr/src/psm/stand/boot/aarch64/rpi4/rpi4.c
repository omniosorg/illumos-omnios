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

#include <stdbool.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <sys/byteorder.h>
#include <sys/sysmacros.h>
#include <sys/controlregs.h>
#include <sys/dditypes.h>
#include <sys/devops.h>
#include <sys/sdcard/sda.h>
#include <sys/platform.h>
#include <util/sscanf.h>
#include <sys/platmod.h>
#include <sys/gpio.h>
#include <sys/bcm2835_mbox.h>
#include <sys/bcm2835_mboxreg.h>
#include <sys/bcm2835_vcprop.h>
#include <sys/bcm2835_vcio.h>

static void
cache_flush(void *addr, size_t len)
{
	for (uintptr_t v = P2ALIGN((uintptr_t)addr, DCACHE_LINE);
	    v < (uintptr_t)addr + len; v += DCACHE_LINE) {
		flush_data_cache(v);
	}
	dsb(sy);
}

static char mbox_buffer[0x200] __attribute__ ((aligned (0x200)));
static uint64_t mbox_base;
static uint64_t mbox_buffer_address;

static void
bcm2835_find_mbox(pnode_t node, void *arg)
{
	if (!prom_is_compatible(node, "brcm,bcm2835-mbox"))
		return;
	*(pnode_t *)arg = node;
}

static void
bcm2835_mbox_init(void)
{
	pnode_t node = 0;

	ASSERT(MUTEX_HELD(&mbox_lock));

	prom_walk(bcm2835_find_mbox, &node);
	ASSERT(node != 0);
	prom_get_reg_address(node, 0, &mbox_base);
	ASSERT(mbox_base != 0);

	cache_flush(mbox_buffer, sizeof(mbox_buffer));
	write_s1e1r(P2ALIGN((uintptr_t)mbox_buffer, MMU_PAGESIZE));
	isb();

	uint64_t par = read_par_el1();
	ASSERT((par & PAR_F) == 0);
	uint64_t buffer_phys = ((par & PAR_PA_MASK) |
	    (((uintptr_t)mbox_buffer) & MMU_PAGEOFFSET));
	prom_get_bus_address(node, buffer_phys, &mbox_buffer_address);
}

static uint32_t
bcm2835_mbox_reg_read(uint32_t offset)
{
	return *(volatile uint32_t *)(mbox_base + offset);
}

static void
bcm2835_mbox_reg_write(uint32_t offset, uint32_t val)
{
	*(volatile uint32_t *)(mbox_base + offset) = val;
}

static uint32_t
bcm2835_mbox_prop_send_impl(uint32_t chan)
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
	    BCM2835_MBOX_MSG(chan, mbox_buffer_address));

	for (;;) {
		if ((bcm2835_mbox_reg_read(BCM2835_MBOX0_STATUS) &
		    BCM2835_MBOX_STATUS_EMPTY)) {
			continue;
		}
		uint32_t val = bcm2835_mbox_reg_read(BCM2835_MBOX0_READ);
		uint32_t rdata = BCM2835_MBOX_DATA(val);
		return rdata;
	}
}

void
bcm2835_mbox_prop_send(void *data, uint32_t len)
{
	ASSERT(len <= MMU_PAGESIZE);

	static bool mbox_initialized = false;
	if (!mbox_initialized) {
		bcm2835_mbox_init();
		mbox_initialized = true;
	}

	memcpy(mbox_buffer, data, len);
	cache_flush(mbox_buffer, len);

	bcm2835_mbox_prop_send_impl(BCMMBOX_CHANARM2VC);

	cache_flush(mbox_buffer, len);
	memcpy(data, mbox_buffer, len);
}

int
plat_hwclock_get_rate(struct prom_hwclock *clk)
{
	if (!prom_is_compatible(clk->node, "brcm,bcm2711-cprman"))
		return -1;

	int id;
	switch (clk->id) {
	case 19: id = VCPROP_CLK_UART; break;
	case 28: id = VCPROP_CLK_EMMC; break;
	case 51: id = VCPROP_CLK_EMMC2; break;
	default: return -1;
	}

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_clockrate	vbt_clockrate;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof(vb),
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

	bcm2835_mbox_prop_send(&vb, sizeof(vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return -1;
	if (!vcprop_tag_success_p(&vb.vbt_clockrate.tag))
		return -1;

	return (vb.vbt_clockrate.rate);
}

int
plat_hwclock_get_max_rate(struct prom_hwclock *clk)
{
	if (!prom_is_compatible(clk->node, "brcm,bcm2711-cprman"))
		return -1;

	int id;
	switch (clk->id) {
	case 19: id = VCPROP_CLK_UART; break;
	case 28: id = VCPROP_CLK_EMMC; break;
	case 51: id = VCPROP_CLK_EMMC2; break;
	default: return -1;
	}

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_clockrate	vbt_clockrate;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof(vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_clockrate = {
			.tag = {
				.vpt_tag = VCPROPTAG_GET_MAX_CLOCKRATE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_clockrate),
				.vpt_rcode = VCPROPTAG_REQUEST,
			},
			.id = id,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL
		},
	};

	bcm2835_mbox_prop_send(&vb, sizeof(vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return -1;
	if (!vcprop_tag_success_p(&vb.vbt_clockrate.tag))
		return -1;

	return (vb.vbt_clockrate.rate);
}

int
plat_hwclock_get_min_rate(struct prom_hwclock *clk)
{
	if (!prom_is_compatible(clk->node, "brcm,bcm2711-cprman"))
		return -1;

	int id;
	switch (clk->id) {
	case 19: id = VCPROP_CLK_UART; break;
	case 28: id = VCPROP_CLK_EMMC; break;
	case 51: id = VCPROP_CLK_EMMC2; break;
	default: return -1;
	}

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_clockrate	vbt_clockrate;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof(vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_clockrate = {
			.tag = {
				.vpt_tag = VCPROPTAG_GET_MIN_CLOCKRATE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_clockrate),
				.vpt_rcode = VCPROPTAG_REQUEST,
			},
			.id = id,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL
		},
	};

	bcm2835_mbox_prop_send(&vb, sizeof(vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return -1;
	if (!vcprop_tag_success_p(&vb.vbt_clockrate.tag))
		return -1;

	return (vb.vbt_clockrate.rate);
}

int
plat_hwclock_set_rate(struct prom_hwclock *clk, int rate)
{
	if (!prom_is_compatible(clk->node, "brcm,bcm2711-cprman"))
		return -1;

	int id;
	switch (clk->id) {
	case 19: id = VCPROP_CLK_UART; break;
	case 28: id = VCPROP_CLK_EMMC; break;
	case 51: id = VCPROP_CLK_EMMC2; break;
	default: return -1;
	}

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_clockrate	vbt_clockrate;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof(vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_clockrate = {
			.tag = {
				.vpt_tag = VCPROPTAG_SET_CLOCKRATE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_clockrate),
				.vpt_rcode = VCPROPTAG_REQUEST,
			},
			.id = id,
			.rate = rate,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL
		},
	};

	bcm2835_mbox_prop_send(&vb, sizeof(vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return -1;
	if (!vcprop_tag_success_p(&vb.vbt_clockrate.tag))
		return -1;

	return 0;
}

int
plat_gpio_get(struct gpio_ctrl *gpio)
{
	int offset;
	if (prom_is_compatible(gpio->node, "raspberrypi,firmware-gpio")) {
		offset = 128;
	}
	else if (prom_is_compatible(gpio->node, "brcm,bcm2711-gpio")) {
		offset = 0;
	}
	else
		return -1;

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_gpiostate	vbt_gpio;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof(vb),
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

	bcm2835_mbox_prop_send(&vb, sizeof(vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return -1;
	if (!vcprop_tag_success_p(&vb.vbt_gpio.tag))
		return -1;

	return vb.vbt_gpio.state;
}

int
plat_gpio_set(struct gpio_ctrl *gpio, int value)
{
	int offset;
	if (prom_is_compatible(gpio->node, "raspberrypi,firmware-gpio")) {
		offset = VCPROP_EXP_GPIO_BASE;
	}
	else if (prom_is_compatible(gpio->node, "brcm,bcm2711-gpio")) {
		offset = 0;
	}
	else
		return -1;

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_gpiostate	vbt_gpio;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof(vb),
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

	bcm2835_mbox_prop_send(&vb, sizeof(vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return -1;

	return 0;
}

int
plat_power_on(int module)
{
	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_powerstate	vbt_powerstate;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof(vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_powerstate = {
			.tag = {
				.vpt_tag = VCPROPTAG_SET_POWERSTATE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_powerstate),
				.vpt_rcode = VCPROPTAG_REQUEST,
			},
			.id = module,
			.state = (1u << 1) | (1u << 0),	// wait | on
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL
		},
	};

	bcm2835_mbox_prop_send(&vb, sizeof(vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return -1;
	if (!vcprop_tag_success_p(&vb.vbt_powerstate.tag))
		return -1;

	return 0;
}
