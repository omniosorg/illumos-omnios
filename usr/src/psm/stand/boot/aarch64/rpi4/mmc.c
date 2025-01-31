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
#include <sys/arch_timer.h>
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
#include <sys/bcm2711_emmctworeg.h>
#include "prom_dev.h"
#include "boot_plat.h"
#include "mmc.h"

#define BUFFER_SIZE	0x20000

struct mmc_sc {
	uint64_t base;
	uint32_t ocr;
	uint32_t ocr_avail;
	uint32_t vdd;
	uint32_t csd[4];
	uint32_t cid[4];
	uint32_t scr[2];
	uint32_t func_status[16];
	uint32_t rca;
	char *buffer;
	uint64_t buffer_bus_address;
	bool tuning_enable;
};

static struct mmc_sc *mmc_dev[3];

static void
usecwait(int usec)
{
	arch_timer_udelay(usec);
}

static uint64_t
get_usec()
{
	return (arch_timer_count() / (arch_timer_freq() / 1000000));
}

static void
cache_flush(void *addr, size_t len)
{
	for (uintptr_t v = P2ALIGN((uintptr_t)addr, DCACHE_LINE); v < (uintptr_t)addr + len; v += DCACHE_LINE) {
		flush_data_cache(v);
	}
	dsb(sy);
}

struct regulator_state
{
	uint32_t microvolt;
	uint32_t val;
};

struct gpio_regulator
{
	struct gpio_ctrl *gpios;
	int ngpios;
	struct regulator_state *states;
	int nstates;
	uint32_t min_volt;
	uint32_t max_volt;
};

static int
init_gpio_regulator(pnode_t node, struct gpio_regulator *regulator)
{
	int len;

	regulator->ngpios = 0;
	regulator->gpios = NULL;
	regulator->nstates = 0;
	regulator->states = NULL;

	len = prom_getproplen(node, "gpios");
	if (len == 0 || len % (sizeof(uint32_t) * 3) != 0)
		goto err_exit;
	regulator->ngpios = len / (sizeof(uint32_t) * 3);
	regulator->gpios = kmem_alloc(sizeof(struct gpio_ctrl) * regulator->ngpios, 0);
	uint32_t *gpios = __builtin_alloca(len);
	prom_getprop(node, "gpios", (caddr_t)gpios);
	for (int i = 0; i < regulator->ngpios; i++) {
		regulator->gpios[i].node = prom_findnode_by_phandle(ntohl(gpios[3 * i + 0]));
		regulator->gpios[i].pin = ntohl(gpios[3 * i + 1]);
		regulator->gpios[i].flags = ntohl(gpios[3 * i + 2]);
	}

	len = prom_getproplen(node, "states");
	if (len == 0 || len % (sizeof(uint32_t) * 2) != 0)
		goto err_exit;
	regulator->nstates = len / (sizeof(uint32_t) * 2);
	regulator->states = kmem_alloc(sizeof(struct regulator_state) * regulator->nstates, 0);
	uint32_t *states = __builtin_alloca(len);
	prom_getprop(node, "states", (caddr_t)states);
	for (int i = 0; i < regulator->nstates; i++) {
		regulator->states[i].microvolt = ntohl(states[2 * i + 0]);
		regulator->states[i].val = ntohl(states[2 * i + 1]);
	}
	regulator->min_volt = prom_get_prop_int(node, "regulator-min-microvolt", -1);
	regulator->max_volt = prom_get_prop_int(node, "regulator-max-microvolt", -1);

	return 0;
err_exit:
	if (regulator->ngpios && regulator->gpios) {
		kmem_free(regulator->gpios, sizeof(struct gpio_ctrl) * regulator->ngpios);
	}
	if (regulator->nstates && regulator->states) {
		kmem_free(regulator->states, sizeof(struct regulator_state) * regulator->nstates);
	}
	return -1;
}

static int
set_gpio_regulator(uint32_t microvolt, struct gpio_regulator *regulator)
{
	ASSERT(regulator->ngpios == 1);
	ASSERT(regulator->nstates == 2);
	int i;
	for (i = 0; i < regulator->nstates; i++) {
		if (microvolt == regulator->states[i].microvolt)
			break;
	}
	if (i == regulator->nstates)
		return -1;
	return plat_gpio_set(&regulator->gpios[0], regulator->states[i].val);
}

static int
get_gpio_regulator(uint32_t *microvolt, struct gpio_regulator *regulator)
{
	ASSERT(regulator->ngpios == 1);
	ASSERT(regulator->nstates == 2);
	int val = plat_gpio_get(&regulator->gpios[0]);
	if (val < 0)
		return -1;
	int i;
	for (i = 0; i < regulator->nstates; i++) {
		if (val == regulator->states[i].val)
			break;
	}
	if (i == regulator->nstates)
		return -1;
	*microvolt = regulator->states[i].microvolt;
	return 0;
}

static uint32_t
mmc_extract_bits(uint32_t *bits, int hi, int len)
{
	uint32_t val = 0;

	for (int i = hi; i >= (hi - len + 1); i--) {
		val = (val << 1) | (((bits[i / 32]) >> (i % 32)) & 1);
	}

	return val;
}

static void
mmc_reg_write(struct mmc_sc *sc, size_t offset, uint32_t val)
{
	*(volatile uint32_t *)(sc->base + offset) = val;
}

static uint32_t
mmc_reg_read(struct mmc_sc *sc, size_t offset)
{
	uint32_t val = *(volatile uint32_t *)(sc->base + offset);
	return val;
}

static void
mmc_reset(struct mmc_sc *sc)
{
	union emmc_control1 control1;
	control1.dw = mmc_reg_read(sc, EMMC_CONTROL1);
	control1.srst_hc = 1;
	control1.clk_intlen = 0;
	control1.clk_en = 0;
	mmc_reg_write(sc, EMMC_CONTROL1, control1.dw);
	for (;;) {
		control1.dw = mmc_reg_read(sc, EMMC_CONTROL1);
		if (control1.srst_hc == 0)
			break;
		usecwait(200);
	}
}

static void
mmc_soft_reset(struct mmc_sc *sc)
{
	union emmc_control1 control1 = { mmc_reg_read(sc, EMMC_CONTROL1) };
	control1.srst_cmd = 1;
	control1.srst_data = 1;
	mmc_reg_write(sc, EMMC_CONTROL1, control1.dw);
	for (;;) {
		control1.dw = mmc_reg_read(sc, EMMC_CONTROL1);
		if (control1.srst_cmd == 0 && control1.srst_data == 0)
			break;
	}
}

static uint32_t
mmc_wait_intr(struct mmc_sc *sc, uint32_t mask, uint64_t usec)
{
	uint64_t timeout = get_usec() + usec;
	union emmc_interrupt interrupt_mask = { mask };
	interrupt_mask.error = 0xffff;
	uint32_t val;
	for (;;) {
		bool timeout_occurred = (get_usec() > timeout);
		val = (mmc_reg_read(sc, EMMC_INTERRUPT) & interrupt_mask.dw);
		if (val != 0) {
			mmc_reg_write(sc, EMMC_INTERRUPT, val);
			break;
		}
		if (timeout_occurred)
			break;
	}

	union emmc_interrupt interrupt = { val };
	if (interrupt.error || val == 0) {
		mmc_soft_reset(sc);
		val = 0;
	}
	return val;
}

static int
mmc_wait_state_idle(struct mmc_sc *sc, uint32_t mask, uint64_t usec)
{
	uint64_t timeout = get_usec() + usec;
	union emmc_status state_mask = { mask };
	for (;;) {
		bool timeout_occurred = (get_usec() > timeout);
		if ((mmc_reg_read(sc, EMMC_STATUS) & state_mask.dw) == 0)
			return 0;
		if (timeout_occurred)
			break;
		usecwait(200);
	}

	mmc_soft_reset(sc);
	return -1;
}

static int
mmc_start_cmd(struct mmc_sc *sc, struct sda_cmd *cmd)
{
	// check
	union emmc_status status_mask = { 0 };
	status_mask.cmd_inhibit = 1;
	if ((cmd->sc_flags & (SDA_CMDF_READ | SDA_CMDF_WRITE)) && cmd->sc_kvaddr)
		status_mask.dat_inhibit = 1;
	else if (cmd->sc_rtype & Rb)
		status_mask.dat_inhibit = 1;

	if (mmc_wait_state_idle(sc, status_mask.dw, 1000000) != 0)
		return -1;

	union emmc_cmdtm1 cmdtm1 = { 0 };
	cmdtm1.cmd_type = ((cmd->sc_index == CMD_STOP_TRANSMIT)? 3: 0);
	cmdtm1.cmd_index = cmd->sc_index;

	switch (cmd->sc_rtype) {
	case R1:
	case R5:
	case R6:
	case R7:
		// resp 48
		cmdtm1.cmd_rspns_type = 2;
		cmdtm1.cmd_ixchk_en = 1;
		cmdtm1.cmd_crcchk_en = 1;
		break;
	case R1b:
	case R5b:
		// resp 48b
		cmdtm1.cmd_rspns_type = 3;
		cmdtm1.cmd_ixchk_en = 1;
		cmdtm1.cmd_crcchk_en = 1;
		break;
	case R2:
		// resp 136
		cmdtm1.cmd_rspns_type = 1;
		cmdtm1.cmd_ixchk_en = 0;
		cmdtm1.cmd_crcchk_en = 0;
		break;
	case R3:
	case R4:
		// resp 48
		cmdtm1.cmd_rspns_type = 2;
		cmdtm1.cmd_ixchk_en = 0;
		cmdtm1.cmd_crcchk_en = 0;
		break;
	case R0:
		cmdtm1.cmd_rspns_type = 0;
		cmdtm1.cmd_ixchk_en = 1;
		cmdtm1.cmd_crcchk_en = 1;
		break;
	default:
		break;
	}

	if (cmd->sc_flags & (SDA_CMDF_READ | SDA_CMDF_WRITE)) {
		union emmc_blksizecnt blksizecnt = {0};
		blksizecnt.blksize = cmd->sc_blksz;
		blksizecnt.sdma_bound = 7;
		blksizecnt.blkcnt = cmd->sc_nblks;
		mmc_reg_write(sc, EMMC_BLKSIZECNT, blksizecnt.dw);

		if (cmd->sc_kvaddr) {
			mmc_reg_write(sc, EMMC_ARG2, (uint32_t)((cmd->sc_kvaddr - sc->buffer) + sc->buffer_bus_address));
			cmdtm1.tm_dma_en = 1;
		}
		cmdtm1.cmd_isdata = 1;
		cmdtm1.tm_blkcnt_en = 1;
		if (cmd->sc_flags & SDA_CMDF_READ)
			cmdtm1.tm_dat_dir = 1;
		if (cmd->sc_index == CMD_READ_MULTI || cmd->sc_index == CMD_WRITE_MULTI) {
			cmdtm1.tm_multi_block = 1;
			cmdtm1.tm_auto_cmd_en = 1;
		}
	}
	mmc_reg_write(sc, EMMC_ARG1, cmd->sc_argument);
	mmc_reg_write(sc, EMMC_CMDTM1, cmdtm1.dw);

	return 0;
}

static int
mmc_wait_cmd_done(struct mmc_sc *sc, struct sda_cmd *cmd)
{
	union emmc_interrupt cmd_done = {0};
	cmd_done.cmd_done = 1;
	if (mmc_wait_intr(sc, cmd_done.dw, 1000000) == 0)
		return -1;

	switch (cmd->sc_rtype) {
	case R0:
		break;
	case R2:
		cmd->sc_response[0] = mmc_reg_read(sc, EMMC_RESP0);
		cmd->sc_response[1] = mmc_reg_read(sc, EMMC_RESP1);
		cmd->sc_response[2] = mmc_reg_read(sc, EMMC_RESP2);
		cmd->sc_response[3] = mmc_reg_read(sc, EMMC_RESP3);

		cmd->sc_response[3] = (cmd->sc_response[3] << 8) | (cmd->sc_response[2] >> 24);
		cmd->sc_response[2] = (cmd->sc_response[2] << 8) | (cmd->sc_response[1] >> 24);
		cmd->sc_response[1] = (cmd->sc_response[1] << 8) | (cmd->sc_response[0] >> 24);
		cmd->sc_response[0] = (cmd->sc_response[0] << 8);
		break;
	default:
		cmd->sc_response[0] = mmc_reg_read(sc, EMMC_RESP0);
		break;
	}

	if ((cmd->sc_rtype & Rb) || (cmd->sc_flags & (SDA_CMDF_READ | SDA_CMDF_WRITE))) {
		for (;;) {
			union emmc_interrupt data_done = {0};
			data_done.data_done = 1;
			data_done.dma = 1;
			union emmc_interrupt result = { mmc_wait_intr(sc, data_done.dw, 10000000) };
			if (result.dw == 0)
				return -1;
			if (result.data_done)
				break;
			mmc_reg_write(sc, EMMC_ARG2, mmc_reg_read(sc, EMMC_ARG2));
		}
		mmc_reg_write(sc, EMMC_ARG2, 0);
	}

	return 0;
}

static void
mmc_init_clock(struct mmc_sc *sc)
{
	union emmc_preset_value preset_value = {
		mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x0),
		mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x4),
		mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x8),
		mmc_reg_read(sc, EMMC_PRESET_VALUE + 0xc),
	};

	union emmc_control1 control1 = { mmc_reg_read(sc, EMMC_CONTROL1) };
	control1.clk_freq8 = preset_value.init.div;
	control1.clk_freq_ms2 = preset_value.init.div >> 8;
	control1.clk_gensel = preset_value.init.clk_gensel;
	control1.clk_intlen = 1;
	control1.data_tounit = 0xe;

	mmc_reg_write(sc, EMMC_CONTROL1, control1.dw);
	usecwait(2000);

	do {
		control1.dw = mmc_reg_read(sc, EMMC_CONTROL1);
	} while (control1.clk_stable == 0);
	usecwait(2000);

	control1.clk_en = 1;
	mmc_reg_write(sc, EMMC_CONTROL1, control1.dw);
	usecwait(2000);

	do {
		control1.dw = mmc_reg_read(sc, EMMC_CONTROL1);
	} while (control1.clk_stable == 0);
	usecwait(2000);
}

static void
mmc_set_sd_clock(struct mmc_sc *sc, int enable)
{
	union emmc_control1 control1 = { mmc_reg_read(sc, EMMC_CONTROL1) };

	control1.clk_en = enable;
	mmc_reg_write(sc, EMMC_CONTROL1, control1.dw);
	usecwait(2000);

	do {
		control1.dw = mmc_reg_read(sc, EMMC_CONTROL1);
	} while (control1.clk_stable == 0);
	usecwait(2000);
}

static void
mmc_set_clock(struct mmc_sc *sc, int mode)
{
	mmc_set_sd_clock(sc, 0);

	union emmc_preset_value preset_value = {
		mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x0),
		mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x4),
		mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x8),
		mmc_reg_read(sc, EMMC_PRESET_VALUE + 0xc),
	};
	union emmc_control0 control0 = { mmc_reg_read(sc, EMMC_CONTROL0) };
	union emmc_control1 control1 = { mmc_reg_read(sc, EMMC_CONTROL1) };
	union emmc_control2 control2 = { mmc_reg_read(sc, EMMC_CONTROL2) };

	control2.uhsmode = mode;

	if (mode == 0 && sc->vdd == 3300000) {
		control0.hctl_hs_en = 0;
		control1.clk_freq8 =    preset_value.default_speed.div;
		control1.clk_freq_ms2 = preset_value.default_speed.div >> 8;
		control1.clk_gensel =   preset_value.default_speed.clk_gensel;
		control2.drv_typ =      preset_value.default_speed.strengthsel;
	}
	if (mode == 0 && sc->vdd == 1800000) {
		control0.hctl_hs_en = 1;
		control1.clk_freq8 =    preset_value.sdr12.div;
		control1.clk_freq_ms2 = preset_value.sdr12.div >> 8;
		control1.clk_gensel =   preset_value.sdr12.clk_gensel;
		control2.drv_typ =      preset_value.sdr12.strengthsel;
	}
	if (mode == 1 && sc->vdd == 3300000) {
		control1.clk_freq8 =    preset_value.high_speed.div;
		control1.clk_freq_ms2 = preset_value.high_speed.div >> 8;
		control1.clk_gensel =   preset_value.high_speed.clk_gensel;
		control2.drv_typ =      preset_value.high_speed.strengthsel;
	}
	if (mode == 1 && sc->vdd == 1800000) {
		control1.clk_freq8 =    preset_value.sdr25.div;
		control1.clk_freq_ms2 = preset_value.sdr25.div >> 8;
		control1.clk_gensel =   preset_value.sdr25.clk_gensel;
		control2.drv_typ =      preset_value.sdr25.strengthsel;
	}
	if (mode == 2) {
		control1.clk_freq8 =    preset_value.sdr50.div;
		control1.clk_freq_ms2 = preset_value.sdr50.div >> 8;
		control1.clk_gensel =   preset_value.sdr50.clk_gensel;
		control2.drv_typ =      preset_value.sdr50.strengthsel;
	}
	if (mode == 3) {
		control1.clk_freq8 =    preset_value.sdr104.div;
		control1.clk_freq_ms2 = preset_value.sdr104.div >> 8;
		control1.clk_gensel =   preset_value.sdr104.clk_gensel;
		control2.drv_typ =      preset_value.sdr104.strengthsel;
	}
	if (mode == 4) {
		control1.clk_freq8 =    preset_value.ddr50.div;
		control1.clk_freq_ms2 = preset_value.ddr50.div >> 8;
		control1.clk_gensel =   preset_value.ddr50.clk_gensel;
		control2.drv_typ =      preset_value.ddr50.strengthsel;
	}
	mmc_reg_write(sc, EMMC_CONTROL0, control0.dw);
	mmc_reg_write(sc, EMMC_CONTROL1, control1.dw);
	mmc_reg_write(sc, EMMC_CONTROL2, control2.dw);

	mmc_set_sd_clock(sc, 1);
}

static int
mmc_set_voltage(struct mmc_sc *sc, struct gpio_regulator *regulator, uint32_t voltage)
{
	union emmc_control0 control0;

	if (voltage != 3300000 && voltage != 1800000)
		return -1;

	mmc_set_sd_clock(sc, 0);

	union emmc_control2 control2 = { mmc_reg_read(sc, EMMC_CONTROL2) };
	control2.vdd180 = (voltage == 1800000? 1: 0);
	mmc_reg_write(sc, EMMC_CONTROL2, control2.dw);

	control0.dw = mmc_reg_read(sc, EMMC_CONTROL0);
	control0.power_vdd1 = 0;
	mmc_reg_write(sc, EMMC_CONTROL0, control0.dw);

	if (set_gpio_regulator(voltage, regulator) < 0)
		return -1;

	usecwait(5000);

	uint32_t microvolt;
	if (get_gpio_regulator(&microvolt, regulator) < 0)
		return -1;
	if (voltage != microvolt)
		return -1;

	control0.vol_sel_vdd1 = (voltage == 1800000? 0x5: 0x7);
	control0.power_vdd1 = 1;
	mmc_reg_write(sc, EMMC_CONTROL0, control0.dw);

	usecwait(5000);

	control2.dw = mmc_reg_read(sc, EMMC_CONTROL2);
	if (control2.vdd180 != (voltage == 1800000? 1: 0))
		return -1;

	mmc_set_sd_clock(sc, 1);
	usecwait(1000);

	return 0;
}

static void
mmc_reset_tune(struct mmc_sc *sc)
{
	union emmc_control2 control2 = { mmc_reg_read(sc, EMMC_CONTROL2)} ;
	control2.tuneon = 0;
	control2.tuned = 0;
	mmc_reg_write(sc, EMMC_CONTROL2, control2.dw);
}

static void
mmc_start_tune(struct mmc_sc *sc)
{
	union emmc_control2 control2 = { mmc_reg_read(sc, EMMC_CONTROL2)} ;
	control2.tuneon = 1;
	mmc_reg_write(sc, EMMC_CONTROL2, control2.dw);
}

static int mmc_send_tuning_block(struct mmc_sc *);

static int
mmc_retune(struct mmc_sc *sc)
{
	mmc_start_tune(sc);

	union emmc_interrupt interrupt = { mmc_reg_read(sc, EMMC_IRPT_MASK) };
	interrupt.read_rdy = 1;
	mmc_reg_write(sc, EMMC_IRPT_MASK, interrupt.dw);

	union emmc_control2 control2;
	for (int i = 0; i < 150; i++)
	{
		if (mmc_send_tuning_block(sc) != 0)
			goto err_exit;

		usecwait(1000);
		control2.dw = mmc_reg_read(sc, EMMC_CONTROL2);
		if (!control2.tuneon)
			break;
	}

	if (!(control2.tuneon == 0 && control2.tuned == 1)) {
		sc->tuning_enable = false;
		mmc_reset_tune(sc);
	}

	interrupt.read_rdy = 0;
	mmc_reg_write(sc, EMMC_IRPT_MASK, interrupt.dw);
	return 0;

err_exit:
	mmc_reset_tune(sc);
	interrupt.read_rdy = 0;
	mmc_reg_write(sc, EMMC_IRPT_MASK, interrupt.dw);
	return -1;
}

static int mmc_stop_transmission(struct mmc_sc *);

static int
mmc_send_cmd(struct mmc_sc *sc, struct sda_cmd *cmd)
{
	if (sc->tuning_enable) {
		// check retune
		union emmc_status state = { mmc_reg_read(sc, EMMC_STATUS) };
		if (state.retune_req)
			mmc_retune(sc);
	}

	if (mmc_start_cmd(sc, cmd) != 0)
		goto err_exit;

	if (mmc_wait_cmd_done(sc, cmd) != 0)
		goto err_exit;

	if (cmd->sc_index == CMD_STOP_TRANSMIT)
		mmc_soft_reset(sc);

	return 0;
err_exit:
	if (cmd->sc_index == CMD_READ_MULTI || cmd->sc_index == CMD_WRITE_MULTI) {
		mmc_stop_transmission(sc);
	}
	return -1;
}

static int
mmc_go_idle_state(struct mmc_sc *sc)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_GO_IDLE,
		.sc_rtype = R0,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;
	return 0;
}

static int
mmc_send_if_cond(struct mmc_sc *sc)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_SEND_IF_COND,
		.sc_rtype = R7,
		.sc_argument = ((!!(sc->ocr_avail & OCR_HI_MASK)) << 8) | 0xaa,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;
	if ((cmd.sc_response[0] & 0xff) != 0xaa)
		return -1;
	return 0;
}


static int
mmc_sd_send_ocr(struct mmc_sc *sc)
{
	struct sda_cmd acmd = {
		.sc_index = CMD_APP_CMD,
		.sc_rtype = R1,
	};
	if (mmc_send_cmd(sc, &acmd) != 0)
		return -1;

	uint32_t ocr = (sc->ocr_avail & OCR_HI_MASK) | OCR_CCS;

	union emmc_capabilities caps = {{ mmc_reg_read(sc, EMMC_CAPABILITIES), mmc_reg_read(sc, EMMC_CAPABILITIES + 4)}};
	union emmc_max_current max_current = {{ mmc_reg_read(sc, EMMC_MAX_CURRENT), mmc_reg_read(sc, EMMC_MAX_CURRENT + 4)}};
	uint32_t max_current_180 = max_current.for_180_vdd1 * 4;
	uint32_t max_current_330 = max_current.for_330_vdd1 * 4;

	if (sc->vdd == 3300000 && max_current_330 > 150)
		ocr |= OCR_XPC;
	if (sc->vdd == 1800000 && max_current_180 > 150)
		ocr |= OCR_XPC;
	if (caps.sup_180)
		ocr |= OCR_S18R;

	struct sda_cmd cmd = {
		.sc_index = ACMD_SD_SEND_OCR,
		.sc_rtype = R3,
		.sc_argument = ocr,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;
	if (cmd.sc_response[0] & OCR_POWER_UP)
		sc->ocr = cmd.sc_response[0];

	return 0;
}

static int
mmc_voltage_switch(struct mmc_sc *sc, struct gpio_regulator *regulator)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_VOLTAGE_SWITCH,
		.sc_rtype = R1,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;

	usecwait(1000);

	if (mmc_set_voltage(sc, regulator, 1800000) < 0)
		return -1;

	sc->vdd = 1800000;

	return 0;
}

static int
mmc_all_send_cid(struct mmc_sc *sc)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_BCAST_CID,
		.sc_rtype = R2,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;

	memcpy(sc->cid, cmd.sc_response, sizeof(sc->cid));

	return 0;
}

static int
mmc_send_relative_addr(struct mmc_sc *sc)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_SEND_RCA,
		.sc_rtype = R6,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;

	sc->rca = (cmd.sc_response[0] >> 16) & 0xffff;

	return 0;
}

static int
mmc_send_csd(struct mmc_sc *sc)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_SEND_CSD,
		.sc_rtype = R2,
		.sc_argument = sc->rca << 16,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;

	memcpy(sc->csd, cmd.sc_response, sizeof(sc->csd));

	return 0;
}

static int
mmc_select_card(struct mmc_sc *sc)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_SELECT_CARD,
		.sc_rtype = R1,
		.sc_argument = sc->rca << 16,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;

	return 0;
}

static int
mmc_send_scr(struct mmc_sc *sc)
{
	struct sda_cmd acmd = {
		.sc_index = CMD_APP_CMD,
		.sc_rtype = R1,
		.sc_argument = sc->rca << 16,
	};
	if (mmc_send_cmd(sc, &acmd) != 0)
		return -1;

	struct sda_cmd cmd = {
		.sc_index = ACMD_SEND_SCR,
		.sc_rtype = R1,

		.sc_nblks = 1,
		.sc_blksz = 8,
		.sc_flags = SDA_CMDF_READ,
		.sc_kvaddr = sc->buffer,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;

	cache_flush(sc->buffer, sizeof(sc->scr));

	for (int i = 0; i < ARRAY_SIZE(sc->scr); i++)
		sc->scr[i] = ntohl(*(uint32_t *)(sc->buffer + sizeof(sc->scr) * (ARRAY_SIZE(sc->scr) - 1 - i)));

	return 0;
}

static int
mmc_swtch_func(struct mmc_sc *sc, uint32_t argument)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_SWITCH_FUNC,
		.sc_rtype = R1,
		.sc_argument = argument,

		.sc_nblks = 1,
		.sc_blksz = 64,
		.sc_flags = SDA_CMDF_READ,
		.sc_kvaddr = sc->buffer,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;

	cache_flush(sc->buffer, sizeof(sc->func_status));

	for (int i = 0; i < ARRAY_SIZE(sc->func_status); i++)
		sc->func_status[i] = ntohl(*(uint32_t *)(sc->buffer + sizeof(sc->func_status[0]) * (ARRAY_SIZE(sc->func_status) - 1 - i)));

	return 0;
}

static int
mmc_stop_transmission(struct mmc_sc *sc)
{
	struct sda_cmd cmd = {
		.sc_index = CMD_STOP_TRANSMIT,
		.sc_rtype = R1b,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return -1;
	return 0;
}

static int
mmc_send_tuning_block(struct mmc_sc *sc)
{
	struct sda_cmd cmd = {
		.sc_index = 19,
		.sc_rtype = R1,

		.sc_nblks = 1,
		.sc_blksz = 64,
		.sc_flags = SDA_CMDF_READ,
	};

	if (mmc_start_cmd(sc, &cmd) != 0)
		return -1;

	union emmc_interrupt interrupt_mask = {0};
	interrupt_mask.read_rdy = 1;
	if (mmc_wait_intr(sc, interrupt_mask.dw, 150000) == 0)
		return -1;

	return 0;
}

static int
mmc_set_bus_width(struct mmc_sc *sc, int width)
{
	ASSERT(width == 1 || width == 4);
	struct sda_cmd acmd = {
		.sc_index = CMD_APP_CMD,
		.sc_rtype = R1,
		.sc_argument = sc->rca << 16,
	};
	if (mmc_send_cmd(sc, &acmd) < 0)
		return -1;

	struct sda_cmd cmd = {
		.sc_index = ACMD_SET_BUS_WIDTH,
		.sc_rtype = R1,
		.sc_argument = (width == 1? 0: 2),
	};
	if (mmc_send_cmd(sc, &cmd) < 0)
		return -1;

	union emmc_control0 control0 = { mmc_reg_read(sc, EMMC_CONTROL0) };
	control0.hctl_dwidth = (width == 1? 0: 1);
	control0.hctl_8bit = 0;
	mmc_reg_write(sc, EMMC_CONTROL0, control0.dw);

	return 0;
}

static int
mmc_set_blocklen(struct mmc_sc *sc, int len)
{
	ASSERT(len == DEV_BSIZE);
	struct sda_cmd cmd = {
		.sc_index = CMD_SET_BLOCKLEN,
		.sc_rtype = R1,

		.sc_argument = len,
	};
	if (mmc_send_cmd(sc, &cmd) < 0)
		return -1;

	return 0;
}

static int
mmc_open(const char *name)
{
	pnode_t node;
	int fd;

	for (fd = 0; fd < sizeof(mmc_dev) / sizeof(mmc_dev[0]); fd++) {
		if (mmc_dev[fd] == NULL)
			break;
	}

	if (fd == sizeof(mmc_dev) / sizeof(mmc_dev[0]))
		return -1;

	struct mmc_sc *sc = kmem_alloc(sizeof(struct mmc_sc), 0);
	memset(sc, 0, sizeof(struct mmc_sc));

	node = prom_finddevice(name);
	if (node <= 0)
		return -1;

	if (!prom_is_compatible(node, "brcm,bcm2711-emmc2"))
		return -1;

	if (prom_get_reg_address(node, 0, &sc->base) != 0)
		return -1;

	// clock
	struct prom_hwclock clock;
	if (prom_get_clock(node, 0, &clock) != 0)
		return -1;

	// regulator
	struct gpio_regulator regulator;
	phandle_t phandle = prom_get_prop_int(node, "vqmmc-supply", -1);
	if (phandle < 0)
		return -1;
	pnode_t vqmmc_node = prom_findnode_by_phandle(phandle);
	if (vqmmc_node < 0)
		return -1;
	if (init_gpio_regulator(vqmmc_node, &regulator) < 0)
		return -1;

	sc->buffer = malloc(BUFFER_SIZE + 2 * DCACHE_LINE);
	cache_flush(sc->buffer, BUFFER_SIZE + 2 * DCACHE_LINE);
	sc->buffer = (char *)roundup((uintptr_t)sc->buffer, DCACHE_LINE);

	write_s1e1r(P2ALIGN((uintptr_t)sc->buffer, MMU_PAGESIZE));
	isb();

	uint64_t par = read_par_el1();
	if (par & PAR_F)
		return -1;
	uint64_t buffer_phys = ((par & PAR_PA_MASK) | (((uintptr_t)sc->buffer) & MMU_PAGEOFFSET));
	if (prom_get_bus_address(node, buffer_phys, &sc->buffer_bus_address) < 0)
		return -1;

	if (get_gpio_regulator(&sc->vdd, &regulator) != 0)
		return -1;

	// reset
	mmc_reset(sc);

	mmc_init_clock(sc);

	if (mmc_set_voltage(sc, &regulator, sc->vdd) < 0)
		return -1;

	{
		union emmc_interrupt interrupt = {0};
		interrupt.cmd_done = 1;
		interrupt.data_done = 1;
		interrupt.retune = 1;
		interrupt.dma = 1;
		interrupt.error = 0xffff;
		mmc_reg_write(sc, EMMC_IRPT_MASK, interrupt.dw);
	}

	union emmc_capabilities caps = {{ mmc_reg_read(sc, EMMC_CAPABILITIES), mmc_reg_read(sc, EMMC_CAPABILITIES + 4)}};
	union emmc_max_current max_current = {{ mmc_reg_read(sc, EMMC_MAX_CURRENT), mmc_reg_read(sc, EMMC_MAX_CURRENT + 4)}};

	uint32_t max_current_180 = max_current.for_180_vdd1 * 4;
	uint32_t max_current_330 = max_current.for_330_vdd1 * 4;

	sc->ocr_avail = 0;
	if (caps.sup_330)
		sc->ocr_avail |= OCR_33_34V | OCR_32_33V;
	if (caps.sup_300)
		sc->ocr_avail |= OCR_30_31V | OCR_29_30V;
	if (caps.sup_180)
		sc->ocr_avail |= OCR_18_19V;

	int i;
	if (mmc_go_idle_state(sc) != 0)
		return -1;

	if (mmc_send_if_cond(sc) != 0)
		return -1;

	for (i = 0; i < 1000; i++) {
		if (mmc_sd_send_ocr(sc) != 0)
			return -1;

		if (sc->ocr & OCR_POWER_UP)
			break;

		usecwait(1000);
	}
	if (i >= 1000)
		return -1;

	uint32_t max_current_ = (sc->vdd == 3300000? max_current_330: max_current_180);

	if ((sc->ocr & OCR_CCS) && (sc->ocr & OCR_S18A)) {
		if (mmc_voltage_switch(sc, &regulator) != 0)
			return -1;
	}

	if (mmc_all_send_cid(sc) != 0)
		return -1;

	if (mmc_send_relative_addr(sc) != 0)
		return -1;

	if (mmc_send_csd(sc) != 0)
		return -1;

	if (mmc_select_card(sc) != 0)
		return -1;

	for (i = 0; i < 3; i++) {
		if (mmc_send_scr(sc) == 0)
			break;
	}
	if (i >= 3)
		return -1;

	if (mmc_swtch_func(sc, 0) != 0)
		return -1;

	// 4bit
	if (mmc_extract_bits(sc->scr, 51, 4) & (1 << 2)) {
		if (mmc_set_bus_width(sc, 4) < 0)
			return -1;
	}

	if (mmc_set_blocklen(sc, DEV_BSIZE) != 0)
		return -1;

	{
		uint32_t argument = (1u << 31) | 0xffffff;
		union emmc_preset_value preset_value = {
			mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x0),
			mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x4),
			mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x8),
			mmc_reg_read(sc, EMMC_PRESET_VALUE + 0xc),
		};
		// group 4
		if (max_current_ >= 800 && (mmc_extract_bits(sc->func_status, 463, 16) & (1u << 3))) {
			argument &= ~(0xf << ((4 - 1) * 4));
			argument |= (0x3 << ((4 - 1) * 4));
		}
		else if (max_current_ >= 600 && (mmc_extract_bits(sc->func_status, 463, 16) & (1u << 2))) {
			argument &= ~(0xf << ((4 - 1) * 4));
			argument |= (0x2 << ((4 - 1) * 4));
		}
		else if (max_current_ >= 400 && (mmc_extract_bits(sc->func_status, 463, 16) & (1u << 1))) {
			argument &= ~(0xf << ((4 - 1) * 4));
			argument |= (0x1 << ((4 - 1) * 4));
		}
		else if (max_current_ >= 200 && (mmc_extract_bits(sc->func_status, 463, 16) & (1u << 0))) {
			argument &= ~(0xf << ((4 - 1) * 4));
			argument |= (0x0 << ((4 - 1) * 4));
		}
		// group 3
		if (caps.sup_sdr104 && (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 3))) {
			argument &= ~(0xf << ((3 - 1) * 4));
			argument |= (preset_value.sdr104.strengthsel << ((3 - 1) * 4));
		}
		else if (caps.sup_ddr50 && (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 4))) {
			argument &= ~(0xf << ((3 - 1) * 4));
			argument |= (preset_value.ddr50.strengthsel << ((3 - 1) * 4));
		}
		else if (caps.sup_sdr50 && (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 2))) {
			argument &= ~(0xf << ((3 - 1) * 4));
			argument |= (preset_value.sdr50.strengthsel << ((3 - 1) * 4));
		}
		else if (caps.sup_hispeed && (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 1))) {
			argument &= ~(0xf << ((3 - 1) * 4));
			if (sc->vdd == 1800000)
				argument |= (preset_value.sdr25.strengthsel << ((3 - 1) * 4));
			else
				argument |= (preset_value.high_speed.strengthsel << ((3 - 1) * 4));
		}
		else {
			argument &= ~(0xf << ((3 - 1) * 4));
			if (sc->vdd == 1800000)
				argument |= (preset_value.sdr12.strengthsel << ((3 - 1) * 4));
			else
				argument |= (preset_value.default_speed.strengthsel << ((3 - 1) * 4));
		}
		// group 1
		if (caps.sup_sdr104 && (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 3))) {
			argument &= ~(0xf << ((1 - 1) * 4));
			argument |= (0x3 << ((1 - 1) * 4));
		}
		else if (caps.sup_ddr50 && (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 4))) {
			argument &= ~(0xf << ((1 - 1) * 4));
			argument |= (0x4 << ((1 - 1) * 4));
		}
		else if (caps.sup_sdr50 && (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 2))) {
			argument &= ~(0xf << ((1 - 1) * 4));
			argument |= (0x2 << ((1 - 1) * 4));
		}
		else if (caps.sup_hispeed && (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 1))) {
			argument &= ~(0xf << ((1 - 1) * 4));
			argument |= (0x1 << ((1 - 1) * 4));
		}

		if (mmc_swtch_func(sc, argument) != 0)
			return -1;
	}

	mmc_set_clock(sc, mmc_extract_bits(sc->func_status, 379, 4));

	switch (mmc_extract_bits(sc->func_status, 379, 4)) {
	case 2:
		if (!caps.tuning_sdr50)
			break;
		/* FALLTHROUGH */
	case 3:
	case 4:
		sc->tuning_enable = true;
		break;
	default:
		break;
	}

	if (sc->tuning_enable) {
		mmc_reset_tune(sc);
		if (mmc_retune(sc) != 0)
			return -1;
	}

	mmc_dev[fd] = sc;

	return fd;
}

static ssize_t
mmc_read(int dev, caddr_t buf, size_t buf_len, uint_t startblk)
{
	size_t read_size = buf_len;
	struct mmc_sc *sc = mmc_dev[dev];

	while (read_size > 0) {
		size_t nblks = MIN(read_size, BUFFER_SIZE) / DEV_BSIZE;

		struct sda_cmd cmd = {
			.sc_index = (nblks == 1? CMD_READ_SINGLE: CMD_READ_MULTI),
			.sc_rtype = R1,
			.sc_nblks = nblks,
			.sc_blksz = DEV_BSIZE,
			.sc_flags = SDA_CMDF_READ,
			.sc_kvaddr = sc->buffer,
		};
		if (sc->ocr & OCR_CCS) {
			cmd.sc_argument = startblk;
		} else {
			cmd.sc_argument = startblk * DEV_BSIZE;
		}
		if (mmc_send_cmd(sc, &cmd) < 0)
			return -1;

		cache_flush(sc->buffer, nblks * DEV_BSIZE);
		memcpy(buf, sc->buffer, nblks * DEV_BSIZE);

		buf += nblks * DEV_BSIZE;
		startblk += nblks;
		read_size -= nblks * DEV_BSIZE;
	}

	return buf_len;
}

static int
mmc_match(const char *path)
{
	pnode_t node = prom_finddevice(path);
	if (node <= 0)
		return 0;

	if (!prom_is_compatible(node, "brcm,bcm2711-emmc2"))
		return 0;

	return 1;
}

static struct prom_dev mmc_prom_dev =
{
	.match = mmc_match,
	.open = mmc_open,
	.read = mmc_read,
};

void init_mmc(void)
{
	prom_register(&mmc_prom_dev);
}
