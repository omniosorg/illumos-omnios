/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2022 Hayashi Naoyuki
 */

#ifndef _IO_MMCREG_H
#define _IO_MMCREG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define EMMC_ARG2		0x00
#define EMMC_BLKSIZECNT		0x04
#define EMMC_ARG1		0x08
#define EMMC_CMDTM1		0x0c
#define EMMC_RESP0		0x10
#define EMMC_RESP1		0x14
#define EMMC_RESP2		0x18
#define EMMC_RESP3		0x1c
#define EMMC_DATA		0x20
#define EMMC_STATUS		0x24
#define EMMC_CONTROL0		0x28
#define EMMC_CONTROL1		0x2c
#define EMMC_INTERRUPT		0x30
#define EMMC_IRPT_MASK		0x34
#define EMMC_IRPT_EN		0x38
#define EMMC_CONTROL2		0x3c
#define EMMC_CAPABILITIES	0x40
#define EMMC_MAX_CURRENT	0x48
#define EMMC_FORCE_IRPT		0x50
#define EMMC_PRESET_VALUE	0x60
#define EMMC_BOOT_TIMEOUT	0x70
#define EMMC_DBG_SEL		0x74
#define EMMC_EXRDFIFO_CFG	0x80
#define EMMC_EXRDFIFO_EN	0x84
#define EMMC_TUNE_STEP		0x88
#define EMMC_TUNE_STEPS_STD	0x8c
#define EMMC_TUNE_STEPS_DDR	0x90
#define EMMC_SPI_INT_SPT	0xf0
#define EMMC_SLOTISR_VER	0xfc

union emmc_blksizecnt {
	uint32_t dw;
	struct {
		uint32_t blksize	:12;
		uint32_t sdma_bound	: 3;
		uint32_t		: 1;
		uint32_t blkcnt		:16;
	};
};

union emmc_cmdtm1 {
	uint32_t dw;
	struct {
		uint32_t tm_dma_en	: 1;
		uint32_t tm_blkcnt_en	: 1;
		uint32_t tm_auto_cmd_en	: 2;
		uint32_t tm_dat_dir	: 1;
		uint32_t tm_multi_block	: 1;
		uint32_t		:10;

		uint32_t cmd_rspns_type	: 2;
		uint32_t cmd_sub_flag	: 1;
		uint32_t cmd_crcchk_en	: 1;
		uint32_t cmd_ixchk_en	: 1;
		uint32_t cmd_isdata	: 1;
		uint32_t cmd_type	: 2;
		uint32_t cmd_index	: 6;
		uint32_t		: 2;
	};
};

union emmc_status {
	uint32_t dw;
	struct {
		uint32_t cmd_inhibit	: 1;
		uint32_t dat_inhibit	: 1;
		uint32_t dat_active	: 1;
		uint32_t retune_req	: 1;
		uint32_t dat_level1	: 4;
		uint32_t write_transfer	: 1;
		uint32_t read_transfer	: 1;
		uint32_t buf_wr_en	: 1;
		uint32_t buf_rd_en	: 1;
		uint32_t		: 4;
		uint32_t card_insert	: 1;
		uint32_t card_stable	: 1;
		uint32_t card_level	: 1;
		uint32_t card_wp	: 1;
		uint32_t dat_level0	: 4;
		uint32_t cmd_level	: 1;
		uint32_t hc_reg_stable	: 1;
		uint32_t		: 1;
		uint32_t cmd_err	: 1;
		uint32_t sub_cmd_stat	: 1;
		uint32_t		: 3;
	};
};

union emmc_control0 {
	uint32_t dw;
	struct {
		uint32_t		: 1;
		uint32_t hctl_dwidth	: 1;
		uint32_t hctl_hs_en	: 1;
		uint32_t		: 2;
		uint32_t hctl_8bit	: 1;
		uint32_t		: 2;

		uint32_t power_vdd1	: 1;
		uint32_t vol_sel_vdd1	: 3;
		uint32_t		: 4;

		uint32_t gap_stop	: 1;
		uint32_t gap_restart	: 1;
		uint32_t readwait_en	: 1;
		uint32_t gap_ien	: 1;
		uint32_t spi_mode	: 1;
		uint32_t boot_en	: 1;
		uint32_t alt_boot_en	: 1;
		uint32_t		: 9;
	};
};

union emmc_control1 {
	uint32_t dw;
	struct {
		uint32_t clk_intlen	: 1;
		uint32_t clk_stable	: 1;
		uint32_t clk_en		: 1;
		uint32_t		: 2;
		uint32_t clk_gensel	: 1;
		uint32_t clk_freq_ms2	: 2;

		uint32_t clk_freq8	: 8;

		uint32_t data_tounit	: 4;
		uint32_t		: 4;
		uint32_t srst_hc	: 1;
		uint32_t srst_cmd	: 1;
		uint32_t srst_data	: 1;
		uint32_t		: 5;
	};
};

union emmc_interrupt {
	uint32_t dw;
	struct {
		uint16_t normal;
		uint16_t error;
	};
	struct {
		uint32_t cmd_done	: 1;
		uint32_t data_done	: 1;
		uint32_t block_gap	: 1;
		uint32_t dma		: 1;
		uint32_t write_rdy	: 1;
		uint32_t read_rdy	: 1;
		uint32_t		: 2;
		uint32_t card		: 1;
		uint32_t		: 3;
		uint32_t retune		: 1;
		uint32_t bootack	: 1;
		uint32_t endboot	: 1;
		uint32_t err		: 1;

		uint32_t cto_err	: 1;
		uint32_t ccrc_err	: 1;
		uint32_t cend_err	: 1;
		uint32_t cbad_err	: 1;
		uint32_t dto_err	: 1;
		uint32_t dcrc_err	: 1;
		uint32_t dend_err	: 1;
		uint32_t		: 1;

		uint32_t acmd_err	: 1;
		uint32_t		: 7;
	};
};

union emmc_control2 {
	uint32_t dw;
	struct {
		uint32_t acnox_err	: 1;
		uint32_t acto_err	: 1;
		uint32_t accrc_err	: 1;
		uint32_t acend_err	: 1;
		uint32_t acbad_err	: 1;
		uint32_t		: 2;
		uint32_t notc12_err	: 1;
		uint32_t		: 8;

		uint32_t uhsmode	: 3;
		uint32_t vdd180		: 1;
		uint32_t drv_typ	: 2;
		uint32_t tuneon		: 1;
		uint32_t tuned		: 1;
		uint32_t		: 7;
		uint32_t preset		: 1;
	};
};

union emmc_capabilities {
	uint32_t dw[2];
	struct {
		uint32_t timeout_clk	: 6;
		uint32_t		: 1;
		uint32_t timeout_unit	: 1;	// 0: KHz, 1: MHz
		uint32_t base_clk	: 8;
		uint32_t max_blk_len	: 2;	// 0: 512, 1: 1024, 2: 2048
		uint32_t sup_8bit	: 1;
		uint32_t sup_adma2	: 1;
		uint32_t		: 1;
		uint32_t sup_hispeed	: 1;
		uint32_t sup_sdma	: 1;
		uint32_t sup_suspend	: 1;
		uint32_t sup_330	: 1;
		uint32_t sup_300	: 1;
		uint32_t sup_180	: 1;
		uint32_t sup_64b_v4	: 1;
		uint32_t sup_64b_v3	: 1;
		uint32_t sup_async_irq	: 1;
		uint32_t slot_type	: 2;

		uint32_t sup_sdr50	: 1;
		uint32_t sup_sdr104	: 1;
		uint32_t sup_ddr50	: 1;
		uint32_t sup_uhs2	: 1;
		uint32_t sup_type_a	: 1;
		uint32_t sup_type_c	: 1;
		uint32_t sup_type_d	: 1;
		uint32_t		: 1;
		uint32_t retuning_time	: 4;
		uint32_t		: 1;
		uint32_t tuning_sdr50	: 1;
		uint32_t tuning_mode	: 2;
		uint32_t clk_mul	: 8;
		uint32_t		: 3;
		uint32_t sup_adma3	: 1;
		uint32_t sup_180_vdd2	: 1;
		uint32_t		: 3;
	};
};

union emmc_max_current {
	uint32_t dw[2];
	struct {
		uint32_t for_330_vdd1	: 8;
		uint32_t for_300_vdd1	: 8;
		uint32_t for_180_vdd1	: 8;
		uint32_t		: 8;
		uint32_t for_180_vdd2	: 8;
		uint32_t		: 8;
		uint32_t		: 8;
		uint32_t		: 8;
	};
};

struct emmc_preset_value_field {
	uint16_t div		:10;
	uint16_t clk_gensel	: 1;
	uint16_t		: 3;
	uint16_t strengthsel	: 2;
};

union emmc_preset_value {
	uint32_t dw[4];
	struct {
		struct emmc_preset_value_field init;
		struct emmc_preset_value_field default_speed;
		struct emmc_preset_value_field high_speed;
		struct emmc_preset_value_field sdr12;
		struct emmc_preset_value_field sdr25;
		struct emmc_preset_value_field sdr50;
		struct emmc_preset_value_field sdr104;
		struct emmc_preset_value_field ddr50;
	};
};

union emmc_dbg_sel {
	uint32_t dw;
	struct {
		uint32_t select		: 1;
		uint32_t		:31;
	};
};

union emmc_exrdfifo_cfg {
	uint32_t dw;
	struct {
		uint32_t rd_thrsh	: 3;
		uint32_t		:29;
	};
};

union emmc_exrdfifo_en {
	uint32_t dw;
	struct {
		uint32_t enable		: 1;
		uint32_t		:31;
	};
};

union emmc_tune_step {
	uint32_t dw;
	struct {
		uint32_t delay		: 3;
		uint32_t		:29;
	};
};

union emmc_tune_steps_std {
	uint32_t dw;
	struct {
		uint32_t steps		: 6;
		uint32_t		:26;
	};
};

union emmc_tune_steps_ddr {
	uint32_t dw;
	struct {
		uint32_t steps		: 6;
		uint32_t		:26;
	};
};

union emmc_spi_int_spt {
	uint32_t dw;
	struct {
		uint32_t select		: 1;
		uint32_t		:31;
	};
};

union emmc_slotisr_ver {
	uint32_t dw;
	struct {
		uint32_t slot_status	: 8;
		uint32_t		: 8;
		uint32_t sdversion	: 8;
		uint32_t vendor		: 8;
	};
};

union mmc_ocr {
	uint32_t dw;
	struct {
		uint32_t		: 7;
		uint32_t lvr		: 1;
		uint32_t		: 7;
		uint32_t vdd_27_28	: 1;
		uint32_t vdd_28_29	: 1;
		uint32_t vdd_29_30	: 1;
		uint32_t vdd_30_31	: 1;
		uint32_t vdd_31_32	: 1;
		uint32_t vdd_32_33	: 1;
		uint32_t vdd_33_34	: 1;
		uint32_t vdd_34_35	: 1;
		uint32_t vdd_35_36	: 1;
		uint32_t s18a		: 1;
		uint32_t		: 2;
		uint32_t co2t		: 1;
		uint32_t		: 1;
		uint32_t uhs2_cs	: 1;
		uint32_t ccs		: 1;
		uint32_t busy		: 1;
	};
};

#ifdef __cplusplus
}
#endif

#endif	/* _IO_MMCREG_H */
