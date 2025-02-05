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
 * Copyright 2019 Hayashi Naoyuki
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/platform.h>
#include <sys/promif.h>
#include <sys/byteorder.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/platmod.h>
#include <sys/gpio.h>
#include <sys/bcm2711_emmctworeg.h>
#include <sys/sdcard/sda.h>
#include <sys/callo.h>
#include <sys/ddi_subrdefs.h>
#include <sys/obpdefs.h>
#include <sys/blkdev.h>

#define	MMC_BUFFER_SIZE		0x10000
#define	MMC_REQUESTS_MAX	0x20

struct mmc_sc {
	dev_info_t *dip;
	bd_handle_t bdh;
	kmutex_t lock;

	uint32_t interrupted;

	uint32_t ocr;
	uint32_t ocr_avail;
	uint32_t vdd;
	uint32_t csd[4];
	uint32_t cid[4];
	uint32_t capacity;
	uint32_t scr[2];
	uint32_t func_status[16];
	uint32_t rca;

	boolean_t tune_req;
	boolean_t in_tuning;
	boolean_t tuning_enable;
	boolean_t detach;

	ddi_taskq_t *tq;
	list_t free_request;

	/* register access */
	caddr_t base;
	ddi_acc_handle_t handle;

	/* interrupt */
	ddi_intr_handle_t ihandle;
	kmutex_t intrlock;
	kcondvar_t waitcv;

	/* dma */
	caddr_t			buffer;
	ddi_dma_handle_t	buf_dmah;
	ddi_acc_handle_t	buf_acch;
	ddi_dma_cookie_t	buf_dmac;
};

static const ddi_device_acc_attr_t reg_acc_attr = {
	.devacc_attr_version = DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder = DDI_STRICTORDER_ACC,
	.devacc_attr_access = DDI_DEFAULT_ACC,
};

static const ddi_device_acc_attr_t buf_acc_attr = {
	.devacc_attr_version = DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder = DDI_STORECACHING_OK_ACC,
	.devacc_attr_access = DDI_DEFAULT_ACC,
};

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
	.dma_attr_flags = DDI_DMA_FLAGERR,
};

struct mmc_request
{
	list_node_t node;
	struct mmc_sc *sc;
	bd_xfer_t *xfer;
};

static void
usecwait(int usec)
{
	drv_usecwait(usec);
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
init_gpio_regulator(dev_info_t *dip, struct gpio_regulator *regulator)
{
	int *buf;
	uint_t len;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0,
	    "gpios", &buf, &len) != DDI_PROP_SUCCESS) {
		goto err_exit;
	}

	if (len == 0 || len % 3 != 0) {
		ddi_prop_free(buf);
		goto err_exit;
	}

	regulator->ngpios = len / 3;
	regulator->gpios = kmem_alloc(sizeof (struct gpio_ctrl) *
	    regulator->ngpios, KM_SLEEP);

	for (int i = 0; i < regulator->ngpios; i++) {
		regulator->gpios[i].node = buf[3 * i + 0];
		regulator->gpios[i].pin = buf[3 * i + 1];
		regulator->gpios[i].flags = buf[3 * i + 2];
	}

	ddi_prop_free(buf);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0,
	    "states", &buf, &len) != DDI_PROP_SUCCESS) {
		goto err_exit;
	}

	if (len == 0 || len % 2 != 0) {
		ddi_prop_free(buf);
		goto err_exit;
	}

	regulator->nstates = len / 2;
	regulator->states = kmem_alloc(sizeof (struct regulator_state) *
	    regulator->nstates, KM_SLEEP);

	for (int i = 0; i < regulator->nstates; i++) {
		regulator->states[i].microvolt = buf[2 * i + 0];
		regulator->states[i].val = buf[2 * i + 1];
	}

	ddi_prop_free(buf);

	int prop;
	if ((prop = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "regulator-min-microvolt", -1)) == -1) {
		goto err_exit;
	}
	regulator->min_volt = prop;

	if ((prop = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "regulator-max-microvolt", -1)) == -1) {
		goto err_exit;
	}
	regulator->max_volt = prop;

	return (0);

err_exit:
	if (regulator->ngpios != 0 && regulator->gpios != NULL) {
		kmem_free(regulator->gpios, sizeof (struct gpio_ctrl) *
		    regulator->ngpios);
	}

	if (regulator->nstates != 0 && regulator->states != NULL) {
		kmem_free(regulator->states, sizeof (struct regulator_state) *
		    regulator->nstates);
	}

	return (-1);
}

static void
fini_gpio_regulator(struct gpio_regulator *regulator)
{
	if ((regulator->ngpios > 0) && (regulator->gpios != NULL)) {
		kmem_free(regulator->gpios, sizeof (struct gpio_ctrl) *
		    regulator->ngpios);
	}
	if ((regulator->nstates > 0) && (regulator->states != NULL)) {
		kmem_free(regulator->states, sizeof (struct regulator_state) *
		    regulator->nstates);
	}
}

static int
set_gpio_regulator(uint32_t microvolt, struct gpio_regulator *regulator)
{
	ASSERT3S(regulator->ngpios, ==, 1);
	ASSERT3S(regulator->nstates, ==, 2);
	int i;
	for (i = 0; i < regulator->nstates; i++) {
		if (microvolt == regulator->states[i].microvolt)
			break;
	}
	if (i == regulator->nstates)
		return (-1);
	return (plat_gpio_set(&regulator->gpios[0], regulator->states[i].val));
}

static int
get_gpio_regulator(uint32_t *microvolt, struct gpio_regulator *regulator)
{
	ASSERT3S(regulator->ngpios, ==, 1);
	ASSERT3S(regulator->nstates, ==, 2);
	int val = plat_gpio_get(&regulator->gpios[0]);
	if (val < 0)
		return (-1);
	int i;
	for (i = 0; i < regulator->nstates; i++) {
		if (val == regulator->states[i].val)
			break;
	}
	if (i == regulator->nstates)
		return (-1);
	*microvolt = regulator->states[i].microvolt;
	return (0);
}

static uint32_t
mmc_extract_bits(uint32_t *bits, int hi, int len)
{
	uint32_t val = 0;

	for (int i = hi; i >= (hi - len + 1); i--) {
		val = (val << 1) | (((bits[i / 32]) >> (i % 32)) & 1);
	}

	return (val);
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
	return (val);
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
		usecwait(200);
	}

	{
		mutex_enter(&sc->intrlock);

		union emmc_interrupt interrupt_clear = { 0 };
		interrupt_clear.cmd_done = 1;
		interrupt_clear.read_rdy = 1;
		interrupt_clear.write_rdy = 1;
		interrupt_clear.dma = 1;
		interrupt_clear.block_gap = 1;
		interrupt_clear.data_done = 1;
		interrupt_clear.error = 0xffff;
		uint32_t val = mmc_reg_read(sc, EMMC_INTERRUPT);
		mmc_reg_write(sc, EMMC_INTERRUPT, val & interrupt_clear.dw);

		sc->interrupted = val & ~interrupt_clear.dw;

		mutex_exit(&sc->intrlock);
	}
}

static uint32_t
mmc_wait_intr(struct mmc_sc *sc, uint32_t mask, uint64_t usec)
{
	uint32_t val;
	{
		mutex_enter(&sc->intrlock);

		hrtime_t timeout = gethrtime() + USEC2NSEC(usec);
		union emmc_interrupt interrupt_mask = { mask };
		interrupt_mask.error = 0xffff;
		boolean_t timeout_occurred = B_FALSE;
		for (;;) {
			val = (sc->interrupted & interrupt_mask.dw);
			if (val != 0 || timeout_occurred)
				break;

			if (cv_timedwait_hires(&sc->waitcv,
			    &sc->intrlock, timeout, USEC2NSEC(1),
			    CALLOUT_FLAG_ABSOLUTE) < 0) {
				timeout_occurred = B_TRUE;
			}
		}

		sc->interrupted &= ~val;

		mutex_exit(&sc->intrlock);
	}

	union emmc_interrupt interrupt = { val };
	if (interrupt.error || val == 0) {
		mmc_soft_reset(sc);
		val = 0;
	}
	return (val);
}

static int
mmc_wait_state_idle(struct mmc_sc *sc, uint32_t mask, uint64_t usec)
{
	hrtime_t timeout = gethrtime() + USEC2NSEC(usec);
	for (;;) {
		boolean_t timeout_occurred = (gethrtime() > timeout);
		if ((mmc_reg_read(sc, EMMC_STATUS) & mask) == 0)
			return (0);
		if (timeout_occurred)
			break;
		usecwait(200);
	}

	mmc_soft_reset(sc);
	return (-1);
}

static int
mmc_start_cmd(struct mmc_sc *sc, sda_cmd_t *cmd)
{
	// check
	union emmc_status status_mask = { 0 };
	status_mask.cmd_inhibit = 1;
	if ((cmd->sc_flags & (SDA_CMDF_READ | SDA_CMDF_WRITE)) && cmd->sc_ndmac)
		status_mask.dat_inhibit = 1;
	else if (cmd->sc_rtype & Rb)
		status_mask.dat_inhibit = 1;

	if (mmc_wait_state_idle(sc, status_mask.dw, 1000000) != 0)
		return (-1);

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
		if (cmd->sc_ndmac) {
			ASSERT3U(cmd->sc_ndmac, ==, 1);
			mmc_reg_write(sc, EMMC_ARG2,
			    (uint32_t)cmd->sc_dmac.dmac_address);
			cmdtm1.tm_dma_en = 1;
		}
		cmdtm1.cmd_isdata = 1;
		cmdtm1.tm_blkcnt_en = 1;
		if (cmd->sc_flags & SDA_CMDF_READ)
			cmdtm1.tm_dat_dir = 1;
		if (cmd->sc_index == CMD_READ_MULTI ||
		    cmd->sc_index == CMD_WRITE_MULTI) {
			cmdtm1.tm_multi_block = 1;
			cmdtm1.tm_auto_cmd_en = 1;
		}
	}
	mmc_reg_write(sc, EMMC_ARG1, cmd->sc_argument);
	mmc_reg_write(sc, EMMC_CMDTM1, cmdtm1.dw);

	return (0);
}

static int
mmc_wait_cmd_done(struct mmc_sc *sc, sda_cmd_t *cmd)
{
	union emmc_interrupt cmd_done = {0};
	cmd_done.cmd_done = 1;
	if (mmc_wait_intr(sc, cmd_done.dw, 1000000) == 0)
		return (-1);

	switch (cmd->sc_rtype) {
	case R0:
		break;
	case R2:
		cmd->sc_response[0] = mmc_reg_read(sc, EMMC_RESP0);
		cmd->sc_response[1] = mmc_reg_read(sc, EMMC_RESP1);
		cmd->sc_response[2] = mmc_reg_read(sc, EMMC_RESP2);
		cmd->sc_response[3] = mmc_reg_read(sc, EMMC_RESP3);

		cmd->sc_response[3] = (cmd->sc_response[3] << 8) |
		    (cmd->sc_response[2] >> 24);
		cmd->sc_response[2] = (cmd->sc_response[2] << 8) |
		    (cmd->sc_response[1] >> 24);
		cmd->sc_response[1] = (cmd->sc_response[1] << 8) |
		    (cmd->sc_response[0] >> 24);
		cmd->sc_response[0] = (cmd->sc_response[0] << 8);
		break;
	default:
		cmd->sc_response[0] = mmc_reg_read(sc, EMMC_RESP0);
		break;
	}

	if ((cmd->sc_rtype & Rb) ||
	    (cmd->sc_flags & (SDA_CMDF_READ | SDA_CMDF_WRITE))) {
		for (;;) {
			union emmc_interrupt data_done = {0};
			data_done.data_done = 1;
			data_done.dma = 1;
			union emmc_interrupt result = { mmc_wait_intr(sc,
			    data_done.dw, 10000000) };

			if (result.dw == 0)
				return (-1);
			if (result.data_done)
				break;
			mmc_reg_write(sc, EMMC_ARG2,
			    mmc_reg_read(sc, EMMC_ARG2));
		}
		mmc_reg_write(sc, EMMC_ARG2, 0);
	}

	return (0);
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
		control1.clk_freq8 = preset_value.default_speed.div;
		control1.clk_freq_ms2 = preset_value.default_speed.div >> 8;
		control1.clk_gensel = preset_value.default_speed.clk_gensel;
		control2.drv_typ = preset_value.default_speed.strengthsel;
	}
	if (mode == 0 && sc->vdd == 1800000) {
		control0.hctl_hs_en = 1;
		control1.clk_freq8 = preset_value.sdr12.div;
		control1.clk_freq_ms2 = preset_value.sdr12.div >> 8;
		control1.clk_gensel = preset_value.sdr12.clk_gensel;
		control2.drv_typ = preset_value.sdr12.strengthsel;
	}
	if (mode == 1 && sc->vdd == 3300000) {
		control1.clk_freq8 = preset_value.high_speed.div;
		control1.clk_freq_ms2 = preset_value.high_speed.div >> 8;
		control1.clk_gensel = preset_value.high_speed.clk_gensel;
		control2.drv_typ = preset_value.high_speed.strengthsel;
	}
	if (mode == 1 && sc->vdd == 1800000) {
		control1.clk_freq8 = preset_value.sdr25.div;
		control1.clk_freq_ms2 = preset_value.sdr25.div >> 8;
		control1.clk_gensel = preset_value.sdr25.clk_gensel;
		control2.drv_typ = preset_value.sdr25.strengthsel;
	}
	if (mode == 2) {
		control1.clk_freq8 = preset_value.sdr50.div;
		control1.clk_freq_ms2 = preset_value.sdr50.div >> 8;
		control1.clk_gensel = preset_value.sdr50.clk_gensel;
		control2.drv_typ = preset_value.sdr50.strengthsel;
	}
	if (mode == 3) {
		control1.clk_freq8 = preset_value.sdr104.div;
		control1.clk_freq_ms2 = preset_value.sdr104.div >> 8;
		control1.clk_gensel = preset_value.sdr104.clk_gensel;
		control2.drv_typ = preset_value.sdr104.strengthsel;
	}
	if (mode == 4) {
		control1.clk_freq8 = preset_value.ddr50.div;
		control1.clk_freq_ms2 = preset_value.ddr50.div >> 8;
		control1.clk_gensel = preset_value.ddr50.clk_gensel;
		control2.drv_typ = preset_value.ddr50.strengthsel;
	}
	mmc_reg_write(sc, EMMC_CONTROL0, control0.dw);
	mmc_reg_write(sc, EMMC_CONTROL1, control1.dw);
	mmc_reg_write(sc, EMMC_CONTROL2, control2.dw);

	mmc_set_sd_clock(sc, 1);
}

static int
mmc_set_voltage(struct mmc_sc *sc, struct gpio_regulator *regulator,
    uint32_t voltage)
{
	union emmc_control0 control0;

	if (voltage != 3300000 && voltage != 1800000)
		return (-1);

	mmc_set_sd_clock(sc, 0);

	union emmc_control2 control2 = { mmc_reg_read(sc, EMMC_CONTROL2) };
	control2.vdd180 = (voltage == 1800000? 1: 0);
	mmc_reg_write(sc, EMMC_CONTROL2, control2.dw);

	control0.dw = mmc_reg_read(sc, EMMC_CONTROL0);
	control0.power_vdd1 = 0;
	mmc_reg_write(sc, EMMC_CONTROL0, control0.dw);

	if (set_gpio_regulator(voltage, regulator) < 0)
		return (-1);

	usecwait(5000);

	uint32_t microvolt;
	if (get_gpio_regulator(&microvolt, regulator) < 0)
		return (-1);
	if (voltage != microvolt)
		return (-1);

	control0.vol_sel_vdd1 = (voltage == 1800000? 0x5: 0x7);
	control0.power_vdd1 = 1;
	mmc_reg_write(sc, EMMC_CONTROL0, control0.dw);

	usecwait(5000);

	control2.dw = mmc_reg_read(sc, EMMC_CONTROL2);
	if (control2.vdd180 != (voltage == 1800000? 1: 0))
		return (-1);

	mmc_set_sd_clock(sc, 1);
	usecwait(1000);

	return (0);
}

static void
mmc_reset_tune(struct mmc_sc *sc)
{
	union emmc_control2 control2 = { mmc_reg_read(sc, EMMC_CONTROL2)};
	control2.tuneon = 0;
	control2.tuned = 0;
	mmc_reg_write(sc, EMMC_CONTROL2, control2.dw);
}

static void
mmc_start_tune(struct mmc_sc *sc)
{
	union emmc_control2 control2 = { mmc_reg_read(sc, EMMC_CONTROL2)};
	control2.tuneon = 1;
	mmc_reg_write(sc, EMMC_CONTROL2, control2.dw);
}

static int mmc_send_tuning_block(struct mmc_sc *);

static int
mmc_retune(struct mmc_sc *sc)
{
	mmc_start_tune(sc);

	union emmc_interrupt interrupt = { mmc_reg_read(sc, EMMC_IRPT_MASK) };
	union emmc_interrupt interrupt_mask  __unused = {0}; /* XXXARM */
	interrupt.read_rdy = 1;
	interrupt_mask.read_rdy = 1;
	mmc_reg_write(sc, EMMC_IRPT_MASK, interrupt.dw);
	mmc_reg_write(sc, EMMC_IRPT_EN, interrupt.dw);

	union emmc_control2 control2;
	for (int i = 0; i < 150; i++) {
		if (mmc_send_tuning_block(sc) != 0)
			goto err_exit;

		usecwait(1000);
		control2.dw = mmc_reg_read(sc, EMMC_CONTROL2);
		if (!control2.tuneon)
			break;
	}

	if (!(control2.tuneon == 0 && control2.tuned == 1)) {
		sc->tuning_enable = B_FALSE;
		mmc_reset_tune(sc);
	}

	interrupt.read_rdy = 0;
	mmc_reg_write(sc, EMMC_IRPT_MASK, interrupt.dw);
	mmc_reg_write(sc, EMMC_IRPT_EN, interrupt.dw);
	return (0);

err_exit:
	mmc_reset_tune(sc);
	interrupt.read_rdy = 0;
	mmc_reg_write(sc, EMMC_IRPT_MASK, interrupt.dw);
	mmc_reg_write(sc, EMMC_IRPT_EN, interrupt.dw);
	return (-1);
}

static int mmc_stop_transmission(struct mmc_sc *);

static int
mmc_send_cmd(struct mmc_sc *sc, sda_cmd_t *cmd)
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

	return (0);
err_exit:
	if (cmd->sc_index == CMD_READ_MULTI ||
	    cmd->sc_index == CMD_WRITE_MULTI) {
		mmc_stop_transmission(sc);
	}
	return (-1);
}

static int
mmc_go_idle_state(struct mmc_sc *sc)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_GO_IDLE,
		.sc_rtype = R0,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);
	return (0);
}

static int
mmc_send_if_cond(struct mmc_sc *sc)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_SEND_IF_COND,
		.sc_rtype = R7,
		.sc_argument = ((!!(sc->ocr_avail & OCR_HI_MASK)) << 8) | 0xaa,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);
	if ((cmd.sc_response[0] & 0xff) != 0xaa)
		return (-1);
	return (0);
}


static int
mmc_sd_send_ocr(struct mmc_sc *sc)
{
	sda_cmd_t acmd = {
		.sc_index = CMD_APP_CMD,
		.sc_rtype = R1,
	};
	if (mmc_send_cmd(sc, &acmd) != 0)
		return (-1);

	uint32_t ocr = (sc->ocr_avail & OCR_HI_MASK) | OCR_CCS;

	union emmc_capabilities caps = {
		{
			mmc_reg_read(sc, EMMC_CAPABILITIES),
			mmc_reg_read(sc, EMMC_CAPABILITIES + 4)
		}
	};
	union emmc_max_current max_current = {
		{
			mmc_reg_read(sc, EMMC_MAX_CURRENT),
			mmc_reg_read(sc, EMMC_MAX_CURRENT + 4)
		}
	};
	uint32_t max_current_180 = max_current.for_180_vdd1 * 4;
	uint32_t max_current_330 = max_current.for_330_vdd1 * 4;

	if (sc->vdd == 3300000 && max_current_330 > 150)
		ocr |= OCR_XPC;
	if (sc->vdd == 1800000 && max_current_180 > 150)
		ocr |= OCR_XPC;
	if (caps.sup_180)
		ocr |= OCR_S18R;

	sda_cmd_t cmd = {
		.sc_index = ACMD_SD_SEND_OCR,
		.sc_rtype = R3,
		.sc_argument = ocr,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);
	if (cmd.sc_response[0] & OCR_POWER_UP)
		sc->ocr = cmd.sc_response[0];

	return (0);
}

static int
mmc_voltage_switch(struct mmc_sc *sc, struct gpio_regulator *regulator)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_VOLTAGE_SWITCH,
		.sc_rtype = R1,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);

	usecwait(1000);

	if (mmc_set_voltage(sc, regulator, 1800000) < 0)
		return (-1);

	sc->vdd = 1800000;

	return (0);
}

static int
mmc_all_send_cid(struct mmc_sc *sc)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_BCAST_CID,
		.sc_rtype = R2,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);

	memcpy(sc->cid, cmd.sc_response, sizeof (sc->cid));

	return (0);
}

static int
mmc_send_relative_addr(struct mmc_sc *sc)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_SEND_RCA,
		.sc_rtype = R6,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);

	sc->rca = (cmd.sc_response[0] >> 16) & 0xffff;

	return (0);
}

static int
mmc_send_csd(struct mmc_sc *sc)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_SEND_CSD,
		.sc_rtype = R2,
		.sc_argument = sc->rca << 16,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);

	memcpy(sc->csd, cmd.sc_response, sizeof (sc->csd));

	return (0);
}

static int
mmc_select_card(struct mmc_sc *sc)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_SELECT_CARD,
		.sc_rtype = R1,
		.sc_argument = sc->rca << 16,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);

	return (0);
}

static int
mmc_send_scr(struct mmc_sc *sc)
{
	sda_cmd_t acmd = {
		.sc_index = CMD_APP_CMD,
		.sc_rtype = R1,
		.sc_argument = sc->rca << 16,
	};
	if (mmc_send_cmd(sc, &acmd) != 0)
		return (-1);

	sda_cmd_t cmd = {
		.sc_index = ACMD_SEND_SCR,
		.sc_rtype = R1,

		.sc_nblks = 1,
		.sc_blksz = 8,
		.sc_flags = SDA_CMDF_READ,
		.sc_dmah = sc->buf_dmah,
		.sc_ndmac = 1,
		.sc_dmac = sc->buf_dmac,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);

	ddi_dma_sync(sc->buf_dmah, 0, sizeof (sc->scr), DDI_DMA_SYNC_FORKERNEL);

	for (int i = 0; i < ARRAY_SIZE(sc->scr); i++) {
		sc->scr[i] = ntohl(*(uint32_t *)(sc->buffer + sizeof (sc->scr) *
		    (ARRAY_SIZE(sc->scr) - 1 - i)));
	}

	return (0);
}

static int
mmc_swtch_func(struct mmc_sc *sc, uint32_t argument)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_SWITCH_FUNC,
		.sc_rtype = R1,
		.sc_argument = argument,

		.sc_nblks = 1,
		.sc_blksz = 64,
		.sc_flags = SDA_CMDF_READ,
		.sc_dmah = sc->buf_dmah,
		.sc_ndmac = 1,
		.sc_dmac = sc->buf_dmac,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);

	ddi_dma_sync(sc->buf_dmah, 0, sizeof (sc->func_status),
	    DDI_DMA_SYNC_FORKERNEL);

	for (int i = 0; i < ARRAY_SIZE(sc->func_status); i++) {
		sc->func_status[i] = ntohl(*(uint32_t *)(sc->buffer +
		    sizeof (sc->func_status[0]) *
		    (ARRAY_SIZE(sc->func_status) - 1 - i)));
	}

	return (0);
}

static int
mmc_stop_transmission(struct mmc_sc *sc)
{
	sda_cmd_t cmd = {
		.sc_index = CMD_STOP_TRANSMIT,
		.sc_rtype = R1b,
	};
	if (mmc_send_cmd(sc, &cmd) != 0)
		return (-1);
	return (0);
}

static int
mmc_send_tuning_block(struct mmc_sc *sc)
{
	sda_cmd_t cmd = {
		.sc_index = 19,
		.sc_rtype = R1,

		.sc_nblks = 1,
		.sc_blksz = 64,
		.sc_flags = SDA_CMDF_READ,
	};

	if (mmc_start_cmd(sc, &cmd) != 0)
		return (-1);

	union emmc_interrupt interrupt_mask = {0};
	interrupt_mask.read_rdy = 1;
	if (mmc_wait_intr(sc, interrupt_mask.dw, 150000) == 0)
		return (-1);

	return (0);
}

static int
mmc_set_bus_width(struct mmc_sc *sc, int width)
{
	ASSERT(width == 1 || width == 4);
	sda_cmd_t acmd = {
		.sc_index = CMD_APP_CMD,
		.sc_rtype = R1,
		.sc_argument = sc->rca << 16,
	};
	if (mmc_send_cmd(sc, &acmd) < 0)
		return (-1);

	sda_cmd_t cmd = {
		.sc_index = ACMD_SET_BUS_WIDTH,
		.sc_rtype = R1,
		.sc_argument = (width == 1? 0: 2),
	};
	if (mmc_send_cmd(sc, &cmd) < 0)
		return (-1);

	union emmc_control0 control0 = { mmc_reg_read(sc, EMMC_CONTROL0) };
	control0.hctl_dwidth = (width == 1? 0: 1);
	control0.hctl_8bit = 0;
	mmc_reg_write(sc, EMMC_CONTROL0, control0.dw);

	return (0);
}

static int
mmc_set_blocklen(struct mmc_sc *sc, int len)
{
	ASSERT3S(len, ==, DEV_BSIZE);
	sda_cmd_t cmd = {
		.sc_index = CMD_SET_BLOCKLEN,
		.sc_rtype = R1,

		.sc_argument = len,
	};
	if (mmc_send_cmd(sc, &cmd) < 0)
		return (-1);

	return (0);
}

static int
mmc_init(struct mmc_sc *sc)
{
	// regulator
	struct gpio_regulator regulator = {0};
	phandle_t ph;

	if ((ph = ddi_prop_get_int(DDI_DEV_T_ANY, sc->dip, 0,
	    "vqmmc-supply", -1)) == -1) {
		return (-1);
	}

	dev_info_t *vqmmc_dip = e_ddi_nodeid_to_dip(ph);
	if (vqmmc_dip == NULL)
		return (-1);

	if (init_gpio_regulator(vqmmc_dip, &regulator) < 0) {
		ndi_rele_devi(vqmmc_dip);
		return (-1);
	}

	ndi_rele_devi(vqmmc_dip);

	if (get_gpio_regulator(&sc->vdd, &regulator) != 0)
		goto err_exit;

	// reset
	mmc_reset(sc);

	mmc_init_clock(sc);

	if (mmc_set_voltage(sc, &regulator, sc->vdd) < 0)
		goto err_exit;

	{
		union emmc_interrupt interrupt = {0};
		interrupt.cmd_done = 1;
		interrupt.data_done = 1;
		interrupt.retune = 1;
		interrupt.dma = 1;
		interrupt.error = 0xffff;
		mmc_reg_write(sc, EMMC_IRPT_MASK, interrupt.dw);
		mmc_reg_write(sc, EMMC_IRPT_EN, interrupt.dw);
	}

	union emmc_capabilities caps = {
		{
			mmc_reg_read(sc, EMMC_CAPABILITIES),
			mmc_reg_read(sc, EMMC_CAPABILITIES + 4)
		}
	};
	union emmc_max_current max_current = {
		{
			mmc_reg_read(sc, EMMC_MAX_CURRENT),
			mmc_reg_read(sc, EMMC_MAX_CURRENT + 4)
		}
	};

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
		goto err_exit;

	if (mmc_send_if_cond(sc) != 0)
		goto err_exit;

	for (i = 0; i < 1000; i++) {
		if (mmc_sd_send_ocr(sc) != 0)
			goto err_exit;

		if (sc->ocr & OCR_POWER_UP)
			break;

		usecwait(1000);
	}
	if (i >= 1000)
		goto err_exit;

	uint32_t max_current_ = (sc->vdd == 3300000 ? max_current_330 :
	    max_current_180);

	if ((sc->ocr & OCR_CCS) && (sc->ocr & OCR_S18A)) {
		if (mmc_voltage_switch(sc, &regulator) != 0)
			goto err_exit;
	}

	if (mmc_all_send_cid(sc) != 0)
		goto err_exit;

	if (mmc_send_relative_addr(sc) != 0)
		goto err_exit;

	if (mmc_send_csd(sc) != 0)
		goto err_exit;

	if (mmc_select_card(sc) != 0)
		goto err_exit;

	for (i = 0; i < 3; i++) {
		if (mmc_send_scr(sc) == 0)
			break;
	}
	if (i >= 3)
		goto err_exit;

	if (mmc_swtch_func(sc, 0) != 0)
		goto err_exit;

	// 4bit
	if (mmc_extract_bits(sc->scr, 51, 4) & (1 << 2)) {
		if (mmc_set_bus_width(sc, 4) < 0)
			goto err_exit;
	}

	if (mmc_set_blocklen(sc, DEV_BSIZE) != 0)
		goto err_exit;

	{
		uint32_t argument = (1u << 31) | 0xffffff;
		union emmc_preset_value preset_value = {
			mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x0),
			mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x4),
			mmc_reg_read(sc, EMMC_PRESET_VALUE + 0x8),
			mmc_reg_read(sc, EMMC_PRESET_VALUE + 0xc),
		};
		// group 4
		if ((max_current_ >= 800) &&
		    (mmc_extract_bits(sc->func_status, 463, 16) & (1u << 3))) {
			argument &= ~(0xf << ((4 - 1) * 4));
			argument |= (0x3 << ((4 - 1) * 4));
		} else if ((max_current_ >= 600) &&
		    (mmc_extract_bits(sc->func_status, 463, 16) & (1u << 2))) {
			argument &= ~(0xf << ((4 - 1) * 4));
			argument |= (0x2 << ((4 - 1) * 4));
		} else if ((max_current_ >= 400) &&
		    (mmc_extract_bits(sc->func_status, 463, 16) & (1u << 1))) {
			argument &= ~(0xf << ((4 - 1) * 4));
			argument |= (0x1 << ((4 - 1) * 4));
		} else if ((max_current_ >= 200) &&
		    (mmc_extract_bits(sc->func_status, 463, 16) & (1u << 0))) {
			argument &= ~(0xf << ((4 - 1) * 4));
			argument |= (0x0 << ((4 - 1) * 4));
		}
		// group 3
		if (caps.sup_sdr104 &&
		    (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 3))) {
			argument &= ~(0xf << ((3 - 1) * 4));
			argument |= (preset_value.sdr104.strengthsel <<
			    ((3 - 1) * 4));
		} else if (caps.sup_ddr50 &&
		    (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 4))) {
			argument &= ~(0xf << ((3 - 1) * 4));
			argument |= (preset_value.ddr50.strengthsel <<
			    ((3 - 1) * 4));
		} else if (caps.sup_sdr50 &&
		    (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 2))) {
			argument &= ~(0xf << ((3 - 1) * 4));
			argument |= (preset_value.sdr50.strengthsel <<
			    ((3 - 1) * 4));
		} else if (caps.sup_hispeed &&
		    (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 1))) {
			argument &= ~(0xf << ((3 - 1) * 4));
			if (sc->vdd == 1800000) {
				argument |= (preset_value.sdr25.strengthsel <<
				    ((3 - 1) * 4));
			} else {
				argument |=
				    (preset_value.high_speed.strengthsel <<
				    ((3 - 1) * 4));
			}
		} else {
			argument &= ~(0xf << ((3 - 1) * 4));
			if (sc->vdd == 1800000) {
				argument |= (preset_value.sdr12.strengthsel <<
				    ((3 - 1) * 4));
			} else {
				argument |=
				    (preset_value.default_speed.strengthsel <<
				    ((3 - 1) * 4));
			}
		}
		// group 1
		if (caps.sup_sdr104 &&
		    (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 3))) {
			argument &= ~(0xf << ((1 - 1) * 4));
			argument |= (0x3 << ((1 - 1) * 4));
		} else if (caps.sup_ddr50 &&
		    (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 4))) {
			argument &= ~(0xf << ((1 - 1) * 4));
			argument |= (0x4 << ((1 - 1) * 4));
		} else if (caps.sup_sdr50 &&
		    (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 2))) {
			argument &= ~(0xf << ((1 - 1) * 4));
			argument |= (0x2 << ((1 - 1) * 4));
		} else if (caps.sup_hispeed &&
		    (mmc_extract_bits(sc->func_status, 415, 16) & (1u << 1))) {
			argument &= ~(0xf << ((1 - 1) * 4));
			argument |= (0x1 << ((1 - 1) * 4));
		}

		if (mmc_swtch_func(sc, argument) != 0)
			goto err_exit;
	}

	mmc_set_clock(sc, mmc_extract_bits(sc->func_status, 379, 4));

	switch (mmc_extract_bits(sc->func_status, 379, 4)) {
	case 2:
		if (!caps.tuning_sdr50)
			break;
		/* FALLTHROUGH */
	case 3:
	case 4:
		sc->tuning_enable = B_TRUE;
		break;
	default:
		break;
	}

	if (sc->tuning_enable) {
		mmc_reset_tune(sc);
		if (mmc_retune(sc) != 0)
			goto err_exit;
	}

	fini_gpio_regulator(&regulator);
	return (DDI_SUCCESS);

err_exit:
	fini_gpio_regulator(&regulator);
	return (DDI_FAILURE);
}

static void
mmc_read_block(void *arg)
{
	struct mmc_sc *sc = ((struct mmc_request *)arg)->sc;
	bd_xfer_t *xfer = ((struct mmc_request *)arg)->xfer;

	ASSERT3P(xfer->x_dmah, ==, NULL);
	ASSERT3P(xfer->x_kaddr, !=, NULL);
	ASSERT3U(xfer->x_nblks * DEV_BSIZE, <=, MMC_BUFFER_SIZE);

	boolean_t detach;
	mutex_enter(&sc->lock);
	detach = sc->detach;
	mutex_exit(&sc->lock);

	int r = EIO;
	if (!detach) {
		sda_cmd_t cmd = {
			.sc_index = (xfer->x_nblks == 1 ? CMD_READ_SINGLE :
			    CMD_READ_MULTI),
			.sc_rtype = R1,
			.sc_nblks = xfer->x_nblks,
			.sc_blksz = DEV_BSIZE,
			.sc_flags = SDA_CMDF_READ,

			.sc_dmah = sc->buf_dmah,
			.sc_ndmac = 1,
			.sc_dmac = sc->buf_dmac,
		};
		if (sc->ocr & OCR_CCS) {
			cmd.sc_argument = xfer->x_blkno;
		} else {
			cmd.sc_argument = xfer->x_blkno * DEV_BSIZE;
		}

		if (mmc_send_cmd(sc, &cmd) == 0) {
			ddi_dma_sync(sc->buf_dmah, 0, xfer->x_nblks * DEV_BSIZE,
			    DDI_DMA_SYNC_FORKERNEL);
			memcpy(xfer->x_kaddr, sc->buffer,
			    xfer->x_nblks * DEV_BSIZE);
			r = 0;
		}
	}

	mutex_enter(&sc->lock);
	list_insert_head(&sc->free_request, arg);
	mutex_exit(&sc->lock);

	bd_xfer_done(xfer, r);
}


static void
mmc_write_block(void *arg)
{
	struct mmc_sc *sc = ((struct mmc_request *)arg)->sc;
	bd_xfer_t *xfer = ((struct mmc_request *)arg)->xfer;

	ASSERT3P(xfer->x_dmah, ==, NULL);
	ASSERT3P(xfer->x_kaddr, !=, NULL);
	ASSERT3U(xfer->x_nblks * DEV_BSIZE, <=, MMC_BUFFER_SIZE);

	boolean_t detach;
	mutex_enter(&sc->lock);
	detach = sc->detach;
	mutex_exit(&sc->lock);

	int r = EIO;
	if (!detach) {
		memcpy(sc->buffer, xfer->x_kaddr, xfer->x_nblks * DEV_BSIZE);
		ddi_dma_sync(sc->buf_dmah, 0, xfer->x_nblks * DEV_BSIZE,
		    DDI_DMA_SYNC_FORDEV);

		sda_cmd_t cmd = {
			.sc_index = (xfer->x_nblks == 1 ?
			    CMD_WRITE_SINGLE : CMD_WRITE_MULTI),
			.sc_rtype = R1,
			.sc_nblks = xfer->x_nblks,
			.sc_blksz = DEV_BSIZE,
			.sc_flags = SDA_CMDF_WRITE,

			.sc_dmah = sc->buf_dmah,
			.sc_ndmac = 1,
			.sc_dmac = sc->buf_dmac,
		};
		if (sc->ocr & OCR_CCS) {
			cmd.sc_argument = xfer->x_blkno;
		} else {
			cmd.sc_argument = xfer->x_blkno * DEV_BSIZE;
		}

		if (mmc_send_cmd(sc, &cmd) == 0)
			r = 0;
	}

	mutex_enter(&sc->lock);
	list_insert_head(&sc->free_request, arg);
	mutex_exit(&sc->lock);

	bd_xfer_done(xfer, r);
}

static int
mmc_bd_read(void *arg, bd_xfer_t *xfer)
{
	if (xfer->x_flags & BD_XFER_POLL)
		return (EIO);

	int r = 0;
	struct mmc_request *req = NULL;
	struct mmc_sc *sc = arg;
	mutex_enter(&sc->lock);
	if (!sc->detach) {
		req = list_head(&sc->free_request);
		if (req != NULL) {
			list_remove(&sc->free_request, req);
			req->sc = sc;
			req->xfer = xfer;
		} else {
			r = ENOMEM;
		}
	} else {
		r = ENXIO;
	}
	mutex_exit(&sc->lock);
	if (req) {
		if (ddi_taskq_dispatch(sc->tq, mmc_read_block, req,
		    DDI_SLEEP) != DDI_SUCCESS) {
			mutex_enter(&sc->lock);
			list_insert_head(&sc->free_request, req);
			mutex_exit(&sc->lock);
			r = EIO;
		}
	}
	return (r);
}

static int
mmc_bd_write(void *arg, bd_xfer_t *xfer)
{
	if (xfer->x_flags & BD_XFER_POLL)
		return (EIO);

	int r = 0;
	struct mmc_request *req = NULL;
	struct mmc_sc *sc = arg;
	mutex_enter(&sc->lock);
	if (!sc->detach) {
		req = list_head(&sc->free_request);
		if (req != NULL) {
			list_remove(&sc->free_request, req);
			req->sc = sc;
			req->xfer = xfer;
		} else {
			r = ENOMEM;
		}
	} else {
		r = ENXIO;
	}
	mutex_exit(&sc->lock);
	if (req) {
		if (ddi_taskq_dispatch(sc->tq, mmc_write_block, req,
		    DDI_SLEEP) != DDI_SUCCESS) {
			mutex_enter(&sc->lock);
			list_insert_head(&sc->free_request, req);
			mutex_exit(&sc->lock);
			r = EIO;
		}
	}
	return (r);
}

static void
mmc_bd_driveinfo(void *arg, bd_drive_t *drive)
{
	struct mmc_sc *sc = arg;
	drive->d_qsize = 4;
	drive->d_removable = B_FALSE;
	drive->d_hotpluggable = B_FALSE;
	drive->d_target = 0;
	drive->d_lun = 0;
	drive->d_maxxfer = MMC_BUFFER_SIZE;

	switch (mmc_extract_bits(sc->cid, 127, 8)) {
	case 0x01: drive->d_vendor = "Panasonic"; break;
	case 0x02: drive->d_vendor = "Toshiba"; break;
	case 0x03: drive->d_vendor = "SanDisk"; break;
	case 0x1b: drive->d_vendor = "Samsung"; break;
	case 0x1d: drive->d_vendor = "AData"; break;
	case 0x27: drive->d_vendor = "Phison"; break;
	case 0x28: drive->d_vendor = "Lexar"; break;
	case 0x31: drive->d_vendor = "Silicon Power"; break;
	case 0x41: drive->d_vendor = "Kingston"; break;
	case 0x74: drive->d_vendor = "Transcend"; break;
	default: drive->d_vendor = "unknown"; break;
	}
	drive->d_vendor_len = strlen(drive->d_vendor);

	drive->d_product = kmem_zalloc(6, KM_SLEEP);
	drive->d_product[4] = mmc_extract_bits(sc->cid, 71, 8);
	drive->d_product[3] = mmc_extract_bits(sc->cid, 79, 8);
	drive->d_product[2] = mmc_extract_bits(sc->cid, 87, 8);
	drive->d_product[1] = mmc_extract_bits(sc->cid, 95, 8);
	drive->d_product[0] = mmc_extract_bits(sc->cid, 103, 8);
	drive->d_product_len = strlen(drive->d_product);

	uint32_t serial = mmc_extract_bits(sc->cid, 55, 32);
	drive->d_serial = kmem_zalloc(9, KM_SLEEP);
	sprintf(drive->d_serial, "%08x", serial);
	drive->d_serial_len = 8;
	uint32_t rev = mmc_extract_bits(sc->cid, 63, 8);
	drive->d_revision = kmem_zalloc(6, KM_SLEEP);
	sprintf(drive->d_revision, "%d.%d", rev >> 4, rev & 0xF);
	drive->d_revision_len = strlen(drive->d_revision);
}

static int
mmc_bd_mediainfo(void *arg, bd_media_t *media)
{
	struct mmc_sc *sc = arg;
	uint64_t size;
	if (mmc_extract_bits(sc->csd, 127, 2) == 0) {
		uint64_t csz = mmc_extract_bits(sc->csd, 73, 12);
		uint32_t cmult = mmc_extract_bits(sc->csd, 49, 3);
		uint32_t read_bl_len = mmc_extract_bits(sc->csd, 83, 4);
		size = ((csz + 1) * (1 << (cmult + 2))) * read_bl_len;
	} else if (mmc_extract_bits(sc->csd, 127, 2) == 1) {
		uint64_t csz = mmc_extract_bits(sc->csd, 69, 22);
		size = (csz + 1) * (512 * 1024);
	} else {
		return (-1);
	}

	media->m_nblks = size / 512;
	media->m_blksize = 512;
	media->m_readonly = B_FALSE;
	media->m_solidstate = B_TRUE;
	return (0);
}

static bd_ops_t mmc_bd_ops = {
	BD_OPS_VERSION_0,
	mmc_bd_driveinfo,
	mmc_bd_mediainfo,
	NULL,			/* devid_init */
	NULL,			/* sync_cache */
	mmc_bd_read,
	mmc_bd_write,
};

static void
mmc_destroy(struct mmc_sc *sc)
{
	if (sc->bdh) {
		bd_free_handle(sc->bdh);
	}
	if (sc->tq) {
		ddi_taskq_destroy(sc->tq);
	}

	for (;;) {
		struct mmc_request *req = list_head(&sc->free_request);
		if (req == NULL)
			break;
		list_remove(&sc->free_request, req);
		kmem_free(req, sizeof (struct mmc_request));
	}
	if (sc->buf_dmah) {
		ddi_dma_unbind_handle(sc->buf_dmah);
		ddi_dma_mem_free(&sc->buf_acch);
		ddi_dma_free_handle(&sc->buf_dmah);
	}
	if (sc->ihandle) {
		ddi_intr_disable(sc->ihandle);
		ddi_intr_remove_handler(sc->ihandle);
		ddi_intr_free(sc->ihandle);
	}
	if (sc->handle)
		ddi_regs_map_free(&sc->handle);

	list_destroy(&sc->free_request);
	cv_destroy(&sc->waitcv);
	mutex_destroy(&sc->intrlock);
	mutex_destroy(&sc->lock);
	kmem_free(sc, sizeof (*sc));
}

static int
mmc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}
	struct mmc_sc *sc = ddi_get_driver_private(dip);

	mutex_enter(&sc->lock);
	sc->detach = B_TRUE;
	mutex_exit(&sc->lock);
	ddi_taskq_wait(sc->tq);

	bd_detach_handle(sc->bdh);

	ddi_set_driver_private(sc->dip, NULL);
	mmc_destroy(sc);

	return (DDI_SUCCESS);
}

static int
mmc_quiesce(dev_info_t *dip)
{
	cmn_err(CE_WARN, "%s%d: mmc_quiesce is not implemented",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	return (DDI_FAILURE);
}

/* Check the device is not disabled */
static int
mmc_probe(dev_info_t *dip)
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

static uint_t
mmc_intr(caddr_t arg1, caddr_t arg2)
{
	struct mmc_sc *sc = (struct mmc_sc *)arg1;
	uint_t status = DDI_INTR_UNCLAIMED;

	mutex_enter(&sc->intrlock);

	uint32_t interrupt = mmc_reg_read(sc, EMMC_INTERRUPT);
	if (interrupt) {
		mmc_reg_write(sc, EMMC_INTERRUPT, interrupt);
		status = DDI_INTR_CLAIMED;
		sc->interrupted |= interrupt;
		cv_signal(&sc->waitcv);
	}

	mutex_exit(&sc->intrlock);

	return (status);
}

static int
mmc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	struct mmc_sc *sc = kmem_zalloc(sizeof (struct mmc_sc), KM_SLEEP);
	ddi_set_driver_private(dip, sc);

	sc->dip = dip;

	mutex_init(&sc->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->intrlock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sc->waitcv, NULL, CV_DRIVER, NULL);
	list_create(&sc->free_request, sizeof (struct mmc_request),
	    offsetof(struct mmc_request, node));

	int rv;
	rv = ddi_regs_map_setup(sc->dip, 0, (caddr_t *)&sc->base, 0, 0,
	    &reg_acc_attr, &sc->handle);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_regs_map_setup failed (%d)!", rv);
		sc->handle = 0;
		goto err_exit;
	}

	rv = i_ddi_update_dma_attr(dip, &dma_attr);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "i_ddi_update_dma_attr failed (%d)!", rv);
		goto err_exit;
	}
	dma_attr.dma_attr_count_max = dma_attr.dma_attr_addr_hi -
	    dma_attr.dma_attr_addr_lo;

	rv = ddi_dma_alloc_handle(dip, &dma_attr, DDI_DMA_SLEEP,
	    NULL, &sc->buf_dmah);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_dma_alloc_handle failed (%d)!", rv);
		sc->buf_dmah = 0;
		goto err_exit;
	}

	size_t real_length;
	rv = ddi_dma_mem_alloc(sc->buf_dmah, MMC_BUFFER_SIZE,
	    &buf_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &sc->buffer, &real_length, &sc->buf_acch);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_dma_mem_alloc failed (%d)!", rv);
		ddi_dma_free_handle(&sc->buf_dmah);
		sc->buf_dmah = 0;
		goto err_exit;
	}
	uint_t ndmac;
	rv = ddi_dma_addr_bind_handle(sc->buf_dmah, NULL, sc->buffer,
	    real_length, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &sc->buf_dmac, &ndmac);
	if ((rv != DDI_DMA_MAPPED) || (ndmac != 1)) {
		cmn_err(CE_WARN, "ddi_dma_addr_bind_handle failed (%d, %u)!",
		    rv, ndmac);
		ddi_dma_mem_free(&sc->buf_acch);
		ddi_dma_free_handle(&sc->buf_dmah);
		sc->buf_dmah = 0;
		goto err_exit;
	}

	for (int i = 0; i < MMC_REQUESTS_MAX; i++) {
		void *req = kmem_alloc(sizeof (struct mmc_request), KM_NOSLEEP);
		if (req == NULL) {
			cmn_err(CE_WARN, "kmem_alloc failed for mmc_request");
			goto err_exit;
		}
		list_insert_head(&sc->free_request, req);
	}

	int actual;
	rv = ddi_intr_alloc(sc->dip, &sc->ihandle, DDI_INTR_TYPE_FIXED, 0, 1,
	    &actual, DDI_INTR_ALLOC_STRICT);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_intr_alloc failed (%d)!", rv);
		sc->ihandle = 0;
		goto err_exit;
	}

	rv = ddi_intr_add_handler(sc->ihandle, mmc_intr, sc, NULL);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_intr_add_handler failed (%d)!", rv);
		ddi_intr_free(sc->ihandle);
		sc->ihandle = 0;
		goto err_exit;
	}

	rv = ddi_intr_enable(sc->ihandle);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed enabling interrupts");
		ddi_intr_remove_handler(sc->ihandle);
		ddi_intr_free(sc->ihandle);
		sc->ihandle = 0;
		goto err_exit;
	}

	rv = mmc_init(sc);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "mmc_init failed!");
		goto err_exit;
	}

	sc->tq = ddi_taskq_create(sc->dip, "taskq", 1, TASKQ_DEFAULTPRI, 0);
	if (sc->tq == NULL) {
		cmn_err(CE_WARN, "ddi_taskq_create failed!");
		goto err_exit;
	}

	sc->bdh = bd_alloc_handle(sc, &mmc_bd_ops, NULL, KM_SLEEP);
	if (sc->bdh == NULL) {
		cmn_err(CE_WARN, "bd_alloc_handle failed!");
		goto err_exit;
	}

	rv = bd_attach_handle(sc->dip, sc->bdh);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "bd_attach_handle failed!");
		goto err_exit;
	}

	return (DDI_SUCCESS);
err_exit:
	mmc_destroy(sc);
	return (DDI_FAILURE);
}

static struct dev_ops mmc_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	ddi_no_info,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	mmc_probe,			/* devo_probe */
	mmc_attach,			/* devo_attach */
	mmc_detach,			/* devo_detach */
	nodev,				/* devo_reset */
	NULL,				/* devo_cb_ops */
	NULL,				/* devo_bus_ops */
	NULL,				/* devo_power */
	mmc_quiesce,			/* devo_quiesce */
};

static struct modldrv mmc_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Raspberry Pi MMC",		/* drv_linkinfo */
	&mmc_dev_ops			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* ml_rev */
	{ &mmc_modldrv, NULL }	/* ml_linkage */
};

int
_init(void)
{
	int i;

	bd_mod_init(&mmc_dev_ops);
	if ((i = mod_install(&modlinkage)) != 0) {
		bd_mod_fini(&mmc_dev_ops);
	}
	return (i);
}

int
_fini(void)
{
	int i;

	if ((i = mod_remove(&modlinkage)) == 0) {
		bd_mod_fini(&mmc_dev_ops);
	}
	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
