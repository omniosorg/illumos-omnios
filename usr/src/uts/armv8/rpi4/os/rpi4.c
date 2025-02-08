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
 */

#include <sys/types.h>
#include <sys/systm.h>
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
#define	DTPROP_CLK_UART		0x13	/* 19: VCPROP_CLK_UART (2) */
#define	DTPROP_CLK_EMMC		0x1C	/* 28: VCPROP_CLK_EMMC (1) */
#define	DTPROP_CLK_EMMC2	0x33	/* 51: VCPROP_CLK_EMMC2 (12) */

/*
 * Platform power management drivers list - empty by default
 */
char *platform_module_list[] = {
	NULL,
};

typedef enum {
	VCCLOCKID = 0,
	DTCLOCKID = 1,
} clockid_type_t;

void
plat_tod_fault(enum tod_fault_type tod_bad __unused)
{
}

static void
find_cprman(pnode_t node, void *arg)
{
	if (!prom_is_compatible(node, "brcm,bcm2711-cprman"))
		return;
	*(pnode_t *)arg = node;
}

static inline int
translate_clk_id_domain(clockid_type_t fromclkidtype,
    clockid_type_t toclkidtype, int clkid)
{
	if (fromclkidtype == toclkidtype)
		return (clkid);

	if (fromclkidtype == DTCLOCKID && toclkidtype == VCCLOCKID) {
		switch (clkid) {
		case DTPROP_CLK_UART: return (VCPROP_CLK_UART);
		case DTPROP_CLK_EMMC: return (VCPROP_CLK_EMMC);
		case DTPROP_CLK_EMMC2: return (VCPROP_CLK_EMMC2);
		default: return (-1);
		}
	}

	cmn_err(CE_WARN, "unknown clock ID domain translation from ID type %d "
	    "to ID type %d", fromclkidtype, toclkidtype);

	return (-1);
}

static int
plat_vc_hwclock_rate(struct prom_hwclock *clk, clockid_type_t clkidtype,
    int vcproptag, int rate)
{
	if (!prom_is_compatible(clk->node, "brcm,bcm2711-cprman"))
		return (-1);

	int id = translate_clk_id_domain(clkidtype, VCCLOCKID, clk->id);
	if (id == -1)
		cmn_err(CE_PANIC, "unknown clock ID type");

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
				.vpt_tag = vcproptag,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_clockrate),
				.vpt_rcode = VCPROPTAG_REQUEST,
			},
			.id = id,
			.rate = rate,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL,
		},
	};

	bcm2835_mbox_prop_send(&vb, sizeof (vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return (-1);
	if (!vcprop_tag_success_p(&vb.vbt_clockrate.tag))
		return (-1);

	return (vb.vbt_clockrate.rate);
}

uint64_t
plat_get_cpu_clock(int cpu_no)
{
	pnode_t node = 0;
	int clkhz;

	prom_walk(find_cprman, &node);
	if (node == 0)
		cmn_err(CE_PANIC, "cprman register is not found");

	struct prom_hwclock clk = { node, VCPROP_CLK_ARM };
	clkhz = plat_vc_hwclock_rate(&clk, VCCLOCKID,
	    VCPROPTAG_GET_CLOCKRATE, 0);
	if (clkhz == -1)
		cmn_err(CE_PANIC, "unable to read CPU clock rate");

	return (clkhz);
}

void
plat_set_max_cpu_clock(int cpu_no)
{
	pnode_t node = 0;
	int clkhz;

	prom_walk(find_cprman, &node);
	if (node == 0)
		cmn_err(CE_PANIC, "cprman register is not found");

	struct prom_hwclock clk = { node, VCPROP_CLK_ARM };
	clkhz = plat_vc_hwclock_rate(&clk, VCCLOCKID,
	    VCPROPTAG_GET_MAX_CLOCKRATE, 0);
	if (clkhz == -1)
		cmn_err(CE_PANIC, "unable to read maximum CPU clock rate");
	clkhz = plat_vc_hwclock_rate(&clk, VCCLOCKID,
	    VCPROPTAG_SET_CLOCKRATE, clkhz);
	if (clkhz == -1)
		cmn_err(CE_PANIC, "unable to set CPU clock rate");
}

int
plat_hwclock_get_rate(struct prom_hwclock *clk)
{
	return (plat_vc_hwclock_rate(clk, DTCLOCKID,
	    VCPROPTAG_GET_CLOCKRATE, 0));
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

	bcm2835_mbox_prop_send(&vb, sizeof (vb));

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

	bcm2835_mbox_prop_send(&vb, sizeof (vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return (-1);

	return (0);
}
