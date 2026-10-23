/* BEGIN CSTYLED */
/*	$OpenBSD: if_iwmreg.h,v 1.70 2024/09/01 03:08:59 jsg Exp $	*/

/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2005 - 2014 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2014 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

/* END CSTYLED */

/*
 * Copyright 2026 lex0de <lex0de@tuta.com>
 * Preserve the original donor licence notices above verbatim.
 */

/*
 * OpenBSD sys/dev/pci/if_iwmreg.h at
 * 0efabb066d34187a404f31d303b3b97103df1117, BSD licence option.
 * Transport ABI subset for the 8260.  Local changes are native guards,
 * includes, packing spelling, comment/whitespace style and layout assertions.
 * No wire fields are changed.
 */
#ifndef _IF_IWMREG_H
#define	_IF_IWMREG_H

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Direct CSR register offsets; peripheral access needs NIC ownership. */
#define	IWM_CSR_INT		0x008
#define	IWM_CSR_INT_MASK	0x00c
#define	IWM_CSR_FH_INT_STATUS	0x010
#define	IWM_CSR_RESET		0x020
#define	IWM_CSR_GP_CNTRL	0x024
#define	IWM_CSR_HW_REV		0x028
#define	IWM_CSR_INT_PERIODIC_REG	0x005

/* Pinned donor CSR fields; no MAC clock or peripheral access is required. */
#define	IWM_CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW	0x08000000
#define	IWM_CSR_INT_BIT_FH_RX	(1U << 31)
#define	IWM_CSR_INT_BIT_HW_ERR	(1U << 29)
#define	IWM_CSR_INT_BIT_RX_PERIODIC	(1U << 28)
#define	IWM_CSR_INT_BIT_FH_TX	(1U << 27)
#define	IWM_CSR_INT_BIT_SCD	(1U << 26)
#define	IWM_CSR_INT_BIT_SW_ERR	(1U << 25)
#define	IWM_CSR_INT_BIT_RF_KILL	(1U << 7)
#define	IWM_CSR_INT_BIT_CT_KILL	(1U << 6)
#define	IWM_CSR_INT_BIT_SW_RX	(1U << 3)
#define	IWM_CSR_INT_BIT_WAKEUP	(1U << 1)
#define	IWM_CSR_INT_BIT_ALIVE	(1U << 0)
#define	IWM_CSR_FH_INT_BIT_ERR	(1U << 31)
#define	IWM_CSR_FH_INT_BIT_HI_PRIOR	(1U << 30)
#define	IWM_CSR_FH_INT_BIT_RX_CHNL1	(1U << 17)
#define	IWM_CSR_FH_INT_BIT_RX_CHNL0	(1U << 16)
#define	IWM_CSR_FH_INT_BIT_TX_CHNL1	(1U << 1)
#define	IWM_CSR_FH_INT_BIT_TX_CHNL0	(1U << 0)

struct iwm_ucode_tlv {
	uint32_t type;		/* see above */
	uint32_t length;		/* not including type/length fields */
	uint8_t data[0];
};

struct iwm_ucode_api {
	uint32_t api_index;
	uint32_t api_flags;
} __attribute__((__packed__));

struct iwm_ucode_capa {
	uint32_t api_index;
	uint32_t api_capa;
} __attribute__((__packed__));

#define	IWM_TLV_UCODE_MAGIC	0x0a4c5749

struct iwm_tlv_ucode_header {
	/*
	 * The TLV style ucode header is distinguished from
	 * the v1/v2 style header by first four bytes being
	 * zero, as such is an invalid combination of
	 * major/minor/API/serial versions.
	 */
	uint32_t zero;
	uint32_t magic;
	uint8_t human_readable[64];
	uint32_t ver;		/* major/minor/API/serial */
	uint32_t build;
	uint64_t ignore;
	/*
	 * The data contained herein has a TLV layout,
	 * see above for the TLV header and types.
	 * Note that each TLV is padded to a length
	 * that is a multiple of 4 for alignment.
	 */
	uint8_t data[0];
};

#define	IWM_NUM_OF_TBS	20
#define	IWM_TFD_QUEUE_SIZE_MAX	256
#define	IWM_TFD_QUEUE_SIZE_BC_DUP	64
#define	IWM_TFD_QUEUE_BC_SIZE	(IWM_TFD_QUEUE_SIZE_MAX + \
    IWM_TFD_QUEUE_SIZE_BC_DUP)

#define	IWM_RX_QUEUE_SIZE	256
#define	IWM_RX_QUEUE_MASK	255
#define	IWM_RX_QUEUE_SIZE_LOG	8

/*
 * RX related structures and functions
 */
#define	IWM_RX_FREE_BUFFERS 64
#define	IWM_RX_LOW_WATERMARK 8

/*
 * struct iwm_rb_status - reserve buffer status
 * 	host memory mapped FH registers
 * @closed_rb_num [0:11] - Indicates the index of the RB which was closed
 * @closed_fr_num [0:11] - Indicates the index of the RX Frame which was closed
 * @finished_rb_num [0:11] - Indicates the index of the current RB
 * 	in which the last frame was written to
 * @finished_fr_num [0:11] - Indicates the index of the RX Frame
 * 	which was transferred
 */
struct iwm_rb_status {
	uint16_t closed_rb_num;
	uint16_t closed_fr_num;
	uint16_t finished_rb_num;
	uint16_t finished_fr_nam;
	uint32_t unused;
} __attribute__((__packed__));
/*
 * struct iwm_tfd_tb transmit buffer descriptor within transmit frame descriptor
 *
 * This structure contains dma address and length of transmission address
 *
 * @lo: low [31:0] portion of the dma address of TX buffer
 * 	every even is unaligned on 16 bit boundary
 * @hi_n_len 0-3 [35:32] portion of dma
 *	     4-15 length of the tx buffer
 */
struct iwm_tfd_tb {
	uint32_t lo;
	uint16_t hi_n_len;
} __attribute__((__packed__));

/*
 * struct iwm_tfd
 *
 * Transmit Frame Descriptor (TFD)
 *
 * @ __reserved1[3] reserved
 * @ num_tbs 0-4 number of active tbs
 *	     5   reserved
 *	     6-7 padding (not used)
 * @ tbs[20]	transmit frame buffer descriptors
 * @ __pad 	padding
 *
 * Each Tx queue uses a circular buffer of 256 TFDs stored in host DRAM.
 * Both driver and device share these circular buffers, each of which must be
 * contiguous 256 TFDs x 128 bytes-per-TFD = 32 KBytes
 *
 * Driver must indicate the physical address of the base of each
 * circular buffer via the IWM_FH_MEM_CBBC_QUEUE registers.
 *
 * Each TFD contains pointer/size information for up to 20 data buffers
 * in host DRAM.  These buffers collectively contain the (one) frame described
 * by the TFD.  Each buffer must be a single contiguous block of memory within
 * itself, but buffers may be scattered in host DRAM.  Each buffer has max size
 * of (4K - 4).  The concatenates all of a TFD's buffers into a single
 * Tx frame, up to 8 KBytes in size.
 *
 * A maximum of 255 (not 256!) TFDs may be on a queue waiting for Tx.
 */
struct iwm_tfd {
	uint8_t __reserved1[3];
	uint8_t num_tbs;
	struct iwm_tfd_tb tbs[IWM_NUM_OF_TBS];
	uint32_t __pad;
} __attribute__((__packed__));

/* Keep Warm Size */
#define	IWM_KW_SIZE 0x1000	/* 4k */

/* Fixed (non-configurable) rx data from phy */

/*
 * struct iwm_agn_schedq_bc_tbl scheduler byte count table
 *	base physical address provided by IWM_SCD_DRAM_BASE_ADDR
 * @tfd_offset  0-12 - tx command byte count
 *	       12-16 - station index
 */
struct iwm_agn_scd_bc_tbl {
	uint16_t tfd_offset[IWM_TFD_QUEUE_BC_SIZE];
} __attribute__((__packed__));
struct iwm_cmd_header {
	uint8_t code;
	uint8_t flags;
	uint8_t idx;
	uint8_t qid;
} __attribute__((__packed__));

struct iwm_cmd_header_wide {
	uint8_t opcode;
	uint8_t group_id;
	uint8_t idx;
	uint8_t qid;
	uint16_t length;
	uint8_t reserved;
	uint8_t version;
} __attribute__((__packed__));

#define	IWM_POWER_SCHEME_CAM	1
#define	IWM_POWER_SCHEME_BPS	2
#define	IWM_POWER_SCHEME_LP	3

#define	IWM_DEF_CMD_PAYLOAD_SIZE 320
#define	IWM_MAX_CMD_PAYLOAD_SIZE ((4096 - 4) - sizeof (struct iwm_cmd_header))
#define	IWM_CMD_FAILED_MSK 0x40

/*
 * struct iwm_device_cmd
 *
 * For allocation of the command and tx queues, this establishes the overall
 * size of the largest command we send to uCode, except for commands that
 * aren't fully copied and use other TFD space.
 */
struct iwm_device_cmd {
	union {
		struct {
			struct iwm_cmd_header hdr;
			uint8_t data[IWM_DEF_CMD_PAYLOAD_SIZE];
		};
		struct {
			struct iwm_cmd_header_wide hdr_wide;
			uint8_t data_wide[IWM_DEF_CMD_PAYLOAD_SIZE -
					sizeof (struct iwm_cmd_header_wide) +
					sizeof (struct iwm_cmd_header)];
		};
	};
} __attribute__((__packed__));

struct iwm_rx_packet {
	/*
	 * The first 4 bytes of the RX frame header contain both the RX frame
	 * size and some flags.
	 * Bit fields:
	 * 31:    flag flush RB request
	 * 30:    flag ignore TC (terminal counter) request
	 * 29:    flag fast IRQ request
	 * 28-26: Reserved
	 * 25:    Offload enabled
	 * 24:    RPF enabled
	 * 23:    RSS enabled
	 * 22:    Checksum enabled
	 * 21-16: RX queue
	 * 15-14: Reserved
	 * 13-00: RX frame size
	 */
	uint32_t len_n_flags;
	struct iwm_cmd_header hdr;
	uint8_t data[];
} __attribute__((__packed__));

CTASSERT(sizeof (struct iwm_ucode_tlv) == 8);
CTASSERT(sizeof (struct iwm_tlv_ucode_header) == 88);
CTASSERT(sizeof (struct iwm_rb_status) == 12);
CTASSERT(sizeof (struct iwm_tfd_tb) == 6);
CTASSERT(sizeof (struct iwm_tfd) == 128);
CTASSERT(sizeof (struct iwm_cmd_header) == 4);
CTASSERT(sizeof (struct iwm_cmd_header_wide) == 8);
CTASSERT(sizeof (struct iwm_device_cmd) == 324);
CTASSERT(sizeof (struct iwm_rx_packet) == 8);


/* BEGIN CSTYLED */
/* Additional pinned 8000-family hardware and command definitions. */
#define IWM_CSR_HW_IF_CONFIG_REG    (0x000) /* hardware interface config */

#define IWM_CSR_INT_COALESCING      (0x004) /* accum ints, 32-usec units */

#define IWM_CSR_GIO_REG		(0x03C)

#define IWM_CSR_UCODE_DRV_GP1_CLR   (0x05c)

#define IWM_CSR_MBOX_SET_REG		(0x088)

#define IWM_CSR_MBOX_SET_REG_OS_ALIVE	0x20

#define IWM_CSR_MAC_SHADOW_REG_CTRL	(0x0A8) /* 6000 and up */

#define IWM_CSR_GIO_CHICKEN_BITS    (0x100)

#define IWM_CSR_DBG_HPET_MEM_REG	(0x240)

#define IWM_CSR_DBG_LINK_PWR_MGMT_REG	(0x250)

#define IWM_CSR_HW_IF_CONFIG_REG_MSK_MAC_DASH	(0x00000003)

#define IWM_CSR_HW_IF_CONFIG_REG_MSK_MAC_STEP	(0x0000000C)

#define IWM_CSR_HW_IF_CONFIG_REG_BIT_MAC_SI	(0x00000100)

#define IWM_CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI	(0x00000200)

#define IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_TYPE	(0x00000C00)

#define IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_DASH	(0x00003000)

#define IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_STEP	(0x0000C000)

#define IWM_CSR_HW_IF_CONFIG_REG_POS_MAC_DASH	(0)

#define IWM_CSR_HW_IF_CONFIG_REG_POS_MAC_STEP	(2)

#define IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_TYPE	(10)

#define IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_DASH	(12)

#define IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_STEP	(14)

#define IWM_CSR_HW_IF_CONFIG_REG_BIT_HAP_WAKE_L1A	(0x00080000)

#define IWM_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY	(0x00400000) /* PCI_OWN_SEM */

#define IWM_CSR_HW_IF_CONFIG_REG_PREPARE	(0x08000000) /* WAKE_ME */

#define IWM_CSR_HW_IF_CONFIG_REG_ENABLE_PME	(0x10000000)

#define IWM_CSR_INT_PERIODIC_DIS		(0x00) /* disable periodic int*/

#define IWM_CSR_INT_PERIODIC_ENA		(0xFF) /* 255*32 usec ~ 8 msec*/

#define IWM_CSR_FH_INT_RX_MASK	(IWM_CSR_FH_INT_BIT_HI_PRIOR | \
				IWM_CSR_FH_INT_BIT_RX_CHNL1 | \
				IWM_CSR_FH_INT_BIT_RX_CHNL0)

#define IWM_CSR_FH_INT_TX_MASK	(IWM_CSR_FH_INT_BIT_TX_CHNL1 | \
				IWM_CSR_FH_INT_BIT_TX_CHNL0)

#define IWM_CSR_RESET_REG_FLAG_SW_RESET                  (0x00000080)

#define IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED           (0x00000100)

#define IWM_CSR_RESET_REG_FLAG_STOP_MASTER               (0x00000200)

#define IWM_CSR_RESET_LINK_PWR_MGMT_DISABLED             (0x80000000)

#define IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY        (0x00000001)

#define IWM_CSR_GP_CNTRL_REG_FLAG_INIT_DONE              (0x00000004)

#define IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ         (0x00000008)

#define IWM_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP         (0x00000010)

#define IWM_CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN           (0x00000001)

#define IWM_CSR_HW_REV_DASH(_val)          (((_val) & 0x0000003) >> 0)

#define IWM_CSR_HW_REV_STEP(_val)          (((_val) & 0x000000C) >> 2)

#define IWM_CSR_GIO_REG_VAL_L0S_ENABLED	(0x00000002)

#define IWM_CSR_UCODE_SW_BIT_RFKILL                     (0x00000002)

#define IWM_CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED           (0x00000004)

#define IWM_CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX  (0x00800000)

#define IWM_CSR_DBG_HPET_MEM_REG_VAL	(0xFFFF0000)

#define IWM_FH_UCODE_LOAD_STATUS	0x1af0

#define IWM_FH_MEM_TB_MAX_LENGTH	0x20000

#define IWM_FW_MEM_EXTENDED_START       0x40000

#define IWM_FW_MEM_EXTENDED_END         0x57FFF

#define IWM_LMPM_CHICK				0xa01ff8

#define IWM_LMPM_CHICK_EXTENDED_ADDR_SPACE	0x01

#define IWM_HBUS_BASE	(0x400)

#define IWM_HBUS_TARG_MEM_WADDR     (IWM_HBUS_BASE+0x010)

#define IWM_HBUS_TARG_MEM_WDAT      (IWM_HBUS_BASE+0x018)

#define IWM_HBUS_TARG_PRPH_WADDR    (IWM_HBUS_BASE+0x044)

#define IWM_HBUS_TARG_PRPH_RADDR    (IWM_HBUS_BASE+0x048)

#define IWM_HBUS_TARG_PRPH_WDAT     (IWM_HBUS_BASE+0x04c)

#define IWM_HBUS_TARG_PRPH_RDAT     (IWM_HBUS_BASE+0x050)

#define IWM_WFMP_MAC_ADDR_0			0xa03080

#define IWM_WFMP_MAC_ADDR_1			0xa03084

#define IWM_WFPM_CTRL_REG			0xa03030

#define IWM_ENABLE_WFPM				0x80000000

#define IWM_AUX_MISC_REG			0xa200b0

#define IWM_HW_STEP_LOCATION_BITS		24

#define IWM_HBUS_TARG_WRPTR         (IWM_HBUS_BASE+0x060)

#define IWM_HOST_INT_TIMEOUT_DEF	(0x40)

#define IWM_UCODE_TLV_CAPA_DQA_SUPPORT			12

#define IWM_FW_PHY_CFG_RADIO_TYPE_POS	0

#define IWM_FW_PHY_CFG_RADIO_TYPE	(0x3 << IWM_FW_PHY_CFG_RADIO_TYPE_POS)

#define IWM_FW_PHY_CFG_RADIO_STEP_POS	2

#define IWM_FW_PHY_CFG_RADIO_STEP	(0x3 << IWM_FW_PHY_CFG_RADIO_STEP_POS)

#define IWM_FW_PHY_CFG_RADIO_DASH_POS	4

#define IWM_FW_PHY_CFG_RADIO_DASH	(0x3 << IWM_FW_PHY_CFG_RADIO_DASH_POS)

#define IWM_PRPH_BASE	(0x00000)

#define IWM_RELEASE_CPU_RESET		0x300c

#define IWM_RELEASE_CPU_RESET_BIT	0x1000000

#define IWM_SCD_MEM_LOWER_BOUND		(0x0000)

#define IWM_SCD_QUEUE_STTS_REG_POS_TXF		(0)

#define IWM_SCD_QUEUE_STTS_REG_POS_ACTIVE	(3)

#define IWM_SCD_QUEUE_STTS_REG_POS_WSL		(4)

#define IWM_SCD_QUEUE_STTS_REG_POS_SCD_ACT_EN	(19)

#define IWM_SCD_QUEUE_STTS_REG_MSK		(0x017F0000)

#define IWM_SCD_QUEUE_CTX_REG2_WIN_SIZE_POS	(0)

#define IWM_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS	(16)

#define IWM_SCD_GP_CTRL_ENABLE_31_QUEUES	(1 << 0)

#define IWM_SCD_GP_CTRL_AUTO_ACTIVE_MODE	(1 << 18)

#define IWM_SCD_CONTEXT_MEM_LOWER_BOUND	(IWM_SCD_MEM_LOWER_BOUND + 0x600)

#define IWM_SCD_TRANS_TBL_MEM_UPPER_BOUND (IWM_SCD_MEM_LOWER_BOUND + 0x808)

#define IWM_SCD_CONTEXT_QUEUE_OFFSET(x)\
	(IWM_SCD_CONTEXT_MEM_LOWER_BOUND + ((x) * 8))

#define IWM_SCD_BASE			(IWM_PRPH_BASE + 0xa02c00)

#define IWM_SCD_SRAM_BASE_ADDR	(IWM_SCD_BASE + 0x0)

#define IWM_SCD_DRAM_BASE_ADDR	(IWM_SCD_BASE + 0x8)

#define IWM_SCD_TXFACT		(IWM_SCD_BASE + 0x10)

#define IWM_SCD_CHAINEXT_EN	(IWM_SCD_BASE + 0x244)

#define IWM_SCD_AGGR_SEL	(IWM_SCD_BASE + 0x248)

#define IWM_SCD_GP_CTRL		(IWM_SCD_BASE + 0x1a8)

#define IWM_SCD_EN_CTRL		(IWM_SCD_BASE + 0x254)

#define IWM_FH_MEM_LOWER_BOUND                   (0x1000)

#define IWM_FH_KW_MEM_ADDR_REG		     (IWM_FH_MEM_LOWER_BOUND + 0x97C)

#define IWM_FH_MEM_RSCSR_LOWER_BOUND	(IWM_FH_MEM_LOWER_BOUND + 0xBC0)

#define IWM_FH_MEM_RSCSR_CHNL0		(IWM_FH_MEM_RSCSR_LOWER_BOUND)

#define IWM_FH_RSCSR_CHNL0_STTS_WPTR_REG	(IWM_FH_MEM_RSCSR_CHNL0)

#define IWM_FH_RSCSR_CHNL0_RBDCB_BASE_REG	(IWM_FH_MEM_RSCSR_CHNL0 + 0x004)

#define IWM_FH_RSCSR_CHNL0_RBDCB_WPTR_REG	(IWM_FH_MEM_RSCSR_CHNL0 + 0x008)

#define IWM_FH_RSCSR_CHNL0_WPTR		(IWM_FH_RSCSR_CHNL0_RBDCB_WPTR_REG)

#define IWM_FW_RSCSR_CHNL0_RXDCB_RDPTR_REG	(IWM_FH_MEM_RSCSR_CHNL0 + 0x00c)

#define IWM_FH_RSCSR_CHNL0_RDPTR		IWM_FW_RSCSR_CHNL0_RXDCB_RDPTR_REG

#define IWM_FH_MEM_RCSR_LOWER_BOUND      (IWM_FH_MEM_LOWER_BOUND + 0xC00)

#define IWM_FH_MEM_RCSR_CHNL0            (IWM_FH_MEM_RCSR_LOWER_BOUND)

#define IWM_FH_MEM_RCSR_CHNL0_CONFIG_REG	(IWM_FH_MEM_RCSR_CHNL0)

#define IWM_FH_MEM_RCSR_CHNL0_RBDCB_WPTR	(IWM_FH_MEM_RCSR_CHNL0 + 0x8)

#define IWM_FH_MEM_RCSR_CHNL0_FLUSH_RB_REQ	(IWM_FH_MEM_RCSR_CHNL0 + 0x10)

#define IWM_FH_RCSR_RX_CONFIG_RBDCB_SIZE_POS	(20)

#define IWM_FH_RCSR_RX_CONFIG_REG_IRQ_RBTH_POS	(4)

#define IWM_RX_RB_TIMEOUT	(0x11)

#define IWM_FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL        (0x80000000)

#define IWM_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K    (0x00000000)

#define IWM_FH_RCSR_CHNL0_RX_IGNORE_RXF_EMPTY              (0x00000004)

#define IWM_FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL  (0x00001000)

#define IWM_FH_MEM_RSSR_LOWER_BOUND     (IWM_FH_MEM_LOWER_BOUND + 0xC40)

#define IWM_FH_MEM_RSSR_RX_STATUS_REG	(IWM_FH_MEM_RSSR_LOWER_BOUND + 0x004)

#define IWM_FH_RSSR_CHNL0_RX_STATUS_CHNL_IDLE	(0x01000000)

#define IWM_FH_MEM_TFDIB_REG1_ADDR_BITSHIFT	28

#define IWM_FH_TFDIB_LOWER_BOUND       (IWM_FH_MEM_LOWER_BOUND + 0x900)

#define IWM_FH_TFDIB_CTRL0_REG(_chnl)  (IWM_FH_TFDIB_LOWER_BOUND + 0x8 * (_chnl))

#define IWM_FH_TFDIB_CTRL1_REG(_chnl)  (IWM_FH_TFDIB_LOWER_BOUND + 0x8 * (_chnl) + 0x4)

#define IWM_FH_TCSR_LOWER_BOUND  (IWM_FH_MEM_LOWER_BOUND + 0xD00)

#define IWM_FH_TCSR_CHNL_NUM                            (8)

#define IWM_FH_TCSR_CHNL_TX_CONFIG_REG(_chnl)	\
		(IWM_FH_TCSR_LOWER_BOUND + 0x20 * (_chnl))

#define IWM_FH_TCSR_CHNL_TX_BUF_STS_REG(_chnl)	\
		(IWM_FH_TCSR_LOWER_BOUND + 0x20 * (_chnl) + 0x8)

#define IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE	(0x00000000)

#define IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE		(0x00000008)

#define IWM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD	(0x00100000)

#define IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE		(0x00000000)

#define IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE		(0x80000000)

#define IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID	(0x00000003)

#define IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM		(20)

#define IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX		(12)

#define IWM_FH_TSSR_LOWER_BOUND		(IWM_FH_MEM_LOWER_BOUND + 0xEA0)

#define IWM_FH_TSSR_TX_STATUS_REG	(IWM_FH_TSSR_LOWER_BOUND + 0x010)

#define IWM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_chnl) ((1 << (_chnl)) << 16)

#define IWM_FH_SRVC_CHNL		(9)

#define IWM_FH_SRVC_LOWER_BOUND	(IWM_FH_MEM_LOWER_BOUND + 0x9C8)

#define IWM_FH_SRVC_CHNL_SRAM_ADDR_REG(_chnl) \
		(IWM_FH_SRVC_LOWER_BOUND + ((_chnl) - 9) * 0x4)

#define IWM_FH_TX_CHICKEN_BITS_REG	(IWM_FH_MEM_LOWER_BOUND + 0xE98)

#define IWM_FH_TX_CHICKEN_BITS_SCD_AUTO_RETRY_EN	(0x00000002)

#define IWM_MAX_QUEUES	31

#define IWM_DQA_CMD_QUEUE		0

#define IWM_CMD_QUEUE		9

#define IWM_TX_FIFO_CMD	7

#define IWM_ALIVE		0x1

#define IWM_NVM_ACCESS_CMD	0x88

#define IWM_MFUART_LOAD_NOTIFICATION	0xb1

#define IWM_NVM_LAR_OFFSET_8000_OLD	0x4C7

#define IWM_NVM_LAR_OFFSET_8000		0x507

#define IWM_NVM_SKU_CAP_BAND_24GHZ	(1 << 0)

#define IWM_NVM_SKU_CAP_BAND_52GHZ	(1 << 1)
#define IWM_NVM_SKU_CAP_11N_ENABLE	(1 << 2)

#define IWM_NVM_RF_CFG_TX_ANT_MSK_8000(x)	((x >> 24) & 0xF)

#define IWM_NVM_RF_CFG_RX_ANT_MSK_8000(x)	((x >> 28) & 0xF)

#define IWM_NVM_NUM_OF_SECTIONS			13

#define IWM_ALIVE_STATUS_OK 0xCAFE

#define IWM_FRAME_LIMIT	64

#define	IWM_FH_RSCSR_FRAME_SIZE_MSK	0x00003fff

#define	IWM_FH_RSCSR_FRAME_INVALID	0x55550000

#define	IWM_FH_RSCSR_FRAME_ALIGN	0x40

struct iwm_nvm_access_cmd {
	uint8_t op_code;
	uint8_t target;
	uint16_t type;
	uint16_t offset;
	uint16_t length;
	uint8_t data[];
} __attribute__((__packed__));

struct iwm_nvm_access_resp {
	uint16_t offset;
	uint16_t length;
	uint16_t type;
	uint16_t status;
	uint8_t data[];
} __attribute__((__packed__));

struct iwm_alive_resp_v1 {
	uint16_t status;
	uint16_t flags;
	uint8_t ucode_minor;
	uint8_t ucode_major;
	uint16_t id;
	uint8_t api_minor;
	uint8_t api_major;
	uint8_t ver_subtype;
	uint8_t ver_type;
	uint8_t mac;
	uint8_t opt;
	uint16_t reserved2;
	uint32_t timestamp;
	uint32_t error_event_table_ptr;	/* SRAM address for error log */
	uint32_t log_event_table_ptr;	/* SRAM address for event log */
	uint32_t cpu_register_ptr;
	uint32_t dbgm_config_ptr;
	uint32_t alive_counter_ptr;
	uint32_t scd_base_ptr;		/* SRAM address for SCD */
} __attribute__((__packed__));

struct iwm_alive_resp_v2 {
	uint16_t status;
	uint16_t flags;
	uint8_t ucode_minor;
	uint8_t ucode_major;
	uint16_t id;
	uint8_t api_minor;
	uint8_t api_major;
	uint8_t ver_subtype;
	uint8_t ver_type;
	uint8_t mac;
	uint8_t opt;
	uint16_t reserved2;
	uint32_t timestamp;
	uint32_t error_event_table_ptr;	/* SRAM address for error log */
	uint32_t log_event_table_ptr;	/* SRAM address for LMAC event log */
	uint32_t cpu_register_ptr;
	uint32_t dbgm_config_ptr;
	uint32_t alive_counter_ptr;
	uint32_t scd_base_ptr;		/* SRAM address for SCD */
	uint32_t st_fwrd_addr;		/* pointer to Store and forward */
	uint32_t st_fwrd_size;
	uint8_t umac_minor;			/* UMAC version: minor */
	uint8_t umac_major;			/* UMAC version: major */
	uint16_t umac_id;			/* UMAC version: id */
	uint32_t error_info_addr;		/* SRAM address for UMAC error log */
	uint32_t dbg_print_buff_addr;
} __attribute__((__packed__));

struct iwm_alive_resp_v3 {
	uint16_t status;
	uint16_t flags;
	uint32_t ucode_minor;
	uint32_t ucode_major;
	uint8_t ver_subtype;
	uint8_t ver_type;
	uint8_t mac;
	uint8_t opt;
	uint32_t timestamp;
	uint32_t error_event_table_ptr;	/* SRAM address for error log */
	uint32_t log_event_table_ptr;	/* SRAM address for LMAC event log */
	uint32_t cpu_register_ptr;
	uint32_t dbgm_config_ptr;
	uint32_t alive_counter_ptr;
	uint32_t scd_base_ptr;		/* SRAM address for SCD */
	uint32_t st_fwrd_addr;		/* pointer to Store and forward */
	uint32_t st_fwrd_size;
	uint32_t umac_minor;		/* UMAC version: minor */
	uint32_t umac_major;		/* UMAC version: major */
	uint32_t error_info_addr;		/* SRAM address for UMAC error log */
	uint32_t dbg_print_buff_addr;
} __attribute__((__packed__));

static inline unsigned int IWM_SCD_QUEUE_WRPTR(unsigned int chnl)
{
	if (chnl < 20)
		return IWM_SCD_BASE + 0x18 + chnl * 4;
	return IWM_SCD_BASE + 0x284 + (chnl - 20) * 4;
}

static inline unsigned int IWM_SCD_QUEUE_RDPTR(unsigned int chnl)
{
	if (chnl < 20)
		return IWM_SCD_BASE + 0x68 + chnl * 4;
	return IWM_SCD_BASE + 0x2B4 + chnl * 4;
}

static inline unsigned int IWM_SCD_QUEUE_STATUS_BITS(unsigned int chnl)
{
	if (chnl < 20)
		return IWM_SCD_BASE + 0x10c + chnl * 4;
	return IWM_SCD_BASE + 0x334 + chnl * 4;
}
#define IWM_TX_CRC_SIZE 4
#define IWM_TX_DELIMITER_SIZE 4
#define IWM_UCODE_TLV_FLAGS_DW_BC_TABLE (1 << 4)

#define IWM_FH_MEM_CBBC_0_15_LOWER_BOUND	(IWM_FH_MEM_LOWER_BOUND + 0x9D0)
#define IWM_FH_MEM_CBBC_0_15_UPPER_BOUN		(IWM_FH_MEM_LOWER_BOUND + 0xA10)
#define IWM_FH_MEM_CBBC_16_19_LOWER_BOUND	(IWM_FH_MEM_LOWER_BOUND + 0xBF0)
#define IWM_FH_MEM_CBBC_16_19_UPPER_BOUND	(IWM_FH_MEM_LOWER_BOUND + 0xC00)
#define IWM_FH_MEM_CBBC_20_31_LOWER_BOUND	(IWM_FH_MEM_LOWER_BOUND + 0xB20)
#define IWM_FH_MEM_CBBC_20_31_UPPER_BOUND	(IWM_FH_MEM_LOWER_BOUND + 0xB80)
static inline unsigned int IWM_FH_MEM_CBBC_QUEUE(unsigned int chnl)
{
	if (chnl < 16)
		return IWM_FH_MEM_CBBC_0_15_LOWER_BOUND + 4 * chnl;
	if (chnl < 20)
		return IWM_FH_MEM_CBBC_16_19_LOWER_BOUND + 4 * (chnl - 16);
	return IWM_FH_MEM_CBBC_20_31_LOWER_BOUND + 4 * (chnl - 20);
}
/* END CSTYLED */

CTASSERT(sizeof (struct iwm_nvm_access_cmd) == 8);
CTASSERT(sizeof (struct iwm_nvm_access_resp) == 8);
CTASSERT(offsetof(struct iwm_nvm_access_cmd, op_code) == 0);
CTASSERT(offsetof(struct iwm_nvm_access_cmd, target) == 1);
CTASSERT(offsetof(struct iwm_nvm_access_cmd, type) == 2);
CTASSERT(offsetof(struct iwm_nvm_access_cmd, offset) == 4);
CTASSERT(offsetof(struct iwm_nvm_access_cmd, length) == 6);
CTASSERT(offsetof(struct iwm_nvm_access_cmd, data) == 8);
CTASSERT(offsetof(struct iwm_nvm_access_resp, offset) == 0);
CTASSERT(offsetof(struct iwm_nvm_access_resp, length) == 2);
CTASSERT(offsetof(struct iwm_nvm_access_resp, type) == 4);
CTASSERT(offsetof(struct iwm_nvm_access_resp, status) == 6);
CTASSERT(offsetof(struct iwm_nvm_access_resp, data) == 8);
CTASSERT(offsetof(struct iwm_cmd_header, code) == 0);
CTASSERT(offsetof(struct iwm_cmd_header, flags) == 1);
CTASSERT(offsetof(struct iwm_cmd_header, idx) == 2);
CTASSERT(offsetof(struct iwm_cmd_header, qid) == 3);
CTASSERT(sizeof (struct iwm_alive_resp_v1) == 44);
CTASSERT(sizeof (struct iwm_alive_resp_v2) == 64);
CTASSERT(sizeof (struct iwm_alive_resp_v3) == 68);

/* Selected API36 scan/RX wire layouts from the pinned donor. */
#define	IWM_SCAN_OFFLOAD_PROBE_REQ_SIZE	512
#define	IWM_PROBE_OPTION_MAX	20
#define	IWM_MAX_SCHED_SCAN_PLANS	2
#define	IWM_RX_INFO_PHY_CNT	8
struct iwm_scd_txq_cfg_cmd {
	uint8_t token;
	uint8_t sta_id;
	uint8_t tid;
	uint8_t scd_queue;
	uint8_t enable;
	uint8_t aggregate;
	uint8_t tx_fifo;
	uint8_t window;
	uint16_t ssn;
	uint16_t reserved;
} __attribute__((__packed__));

/* API36 compressed TX BA; firmware does not echo a session generation. */
struct iwm_ba_notif {
	uint8_t sta_addr[6];
	uint16_t reserved;
	uint8_t sta_id;
	uint8_t tid;
	uint16_t seq_ctl;
	uint64_t bitmap;
	uint16_t scd_flow;
	uint16_t scd_ssn;
	uint8_t txed;
	uint8_t txed_2_done;
	uint8_t reduced_txp;
	uint8_t reserved1;
} __attribute__((__packed__));

/* Pinned donor LINK_QUALITY_CMD_API_S_VER_1; fixed MCS0 in this port. */
struct iwm_lq_cmd {
	uint8_t sta_id;
	uint8_t reserved1;
	uint16_t control;
	uint8_t flags;
	uint8_t mimo_delim;
	uint8_t single_stream_ant_msk;
	uint8_t dual_stream_ant_msk;
	uint8_t initial_rate_index[4];
	uint16_t agg_time_limit;
	uint8_t agg_disable_start_th;
	uint8_t agg_frame_cnt_limit;
	uint32_t reserved2;
	uint32_t rs_table[16];
	uint32_t bf_params;
} __attribute__((__packed__));

struct iwm_add_sta_cmd {
	uint8_t add_modify;
	uint8_t awake_acs;
	uint16_t tid_disable_tx;
	uint32_t mac_id_n_color;
	uint8_t addr[6];	/* _STA_ID_MODIFY_INFO_API_S_VER_1 */
	uint16_t reserved2;
	uint8_t sta_id;
	uint8_t modify_mask;
	uint16_t reserved3;
	uint32_t station_flags;
	uint32_t station_flags_msk;
	uint8_t add_immediate_ba_tid;
	uint8_t remove_immediate_ba_tid;
	uint16_t add_immediate_ba_ssn;
	uint16_t sleep_tx_count;
	uint8_t sleep_state_flags;
	uint8_t station_type;
	uint16_t assoc_id;
	uint16_t beamform_flags;
	uint32_t tfd_queue_msk;
	uint16_t rx_ba_window;
	uint8_t sp_length;
	uint8_t uapsd_acs;
} __attribute__((__packed__));

struct iwm_scan_probe_segment {
	uint16_t offset;
	uint16_t len;
} __attribute__((__packed__));

struct iwm_scan_probe_req_v1 {
	struct iwm_scan_probe_segment mac_header;
	struct iwm_scan_probe_segment band_data[2];
	struct iwm_scan_probe_segment common_data;
	uint8_t buf[IWM_SCAN_OFFLOAD_PROBE_REQ_SIZE];
} __attribute__((__packed__));

struct iwm_ssid_ie {
	uint8_t id;
	uint8_t len;
	uint8_t ssid[IEEE80211_NWID_LEN];
} __attribute__((__packed__));

struct iwm_scan_umac_schedule {
	uint16_t interval;
	uint8_t iter_count;
	uint8_t reserved;
} __attribute__((__packed__));

struct iwm_scan_req_umac_tail_v1 {
	/* SCAN_PERIODIC_PARAMS_API_S_VER_1 */
	struct iwm_scan_umac_schedule schedule[IWM_MAX_SCHED_SCAN_PLANS];
	uint16_t delay;
	uint16_t reserved;
	/* SCAN_PROBE_PARAMS_API_S_VER_1 */
	struct iwm_scan_probe_req_v1 preq;
	struct iwm_ssid_ie direct_scan[IWM_PROBE_OPTION_MAX];
} __attribute__((__packed__));

struct iwm_scan_umac_chan_param {
	uint8_t flags;
	uint8_t count;
	uint16_t reserved;
} __attribute__((__packed__));

struct iwm_scan_channel_cfg_umac {
	uint32_t flags;
	uint8_t channel_num;
	uint8_t iter_count;
	uint16_t iter_interval;
} __attribute__((__packed__));

struct iwm_scan_config {
	uint32_t flags;
	uint32_t tx_chains;
	uint32_t rx_chains;
	uint32_t legacy_rates;
	uint32_t out_of_channel_time;
	uint32_t suspend_time;
	uint8_t dwell_active;
	uint8_t dwell_passive;
	uint8_t dwell_fragmented;
	uint8_t dwell_extended;
	uint8_t mac_addr[6];
	uint8_t bcast_sta_id;
	uint8_t channel_flags;
	uint8_t channel_array[];
} __attribute__((__packed__));

struct iwm_rx_phy_info {
	uint8_t non_cfg_phy_cnt;
	uint8_t cfg_phy_cnt;
	uint8_t stat_id;
	uint8_t reserved1;
	uint32_t system_timestamp;
	uint64_t timestamp;
	uint32_t beacon_time_stamp;
	uint16_t phy_flags;
	uint16_t channel;
	uint32_t non_cfg_phy[IWM_RX_INFO_PHY_CNT];
	uint32_t rate_n_flags;
	uint32_t byte_count;
	uint16_t mac_active_msk;
	uint16_t frame_time;
} __attribute__((__packed__));

/* Pinned donor's API36 receive and HT rate fields. */
#define	IWM_RX_RES_PHY_FLAGS_AGG		(1 << 7)
#define	IWM_RX_RES_PHY_FLAGS_OFDM_HT	(1 << 8)
#define	IWM_RX_RES_PHY_FLAGS_OFDM_GF	(1 << 9)
#define	IWM_RX_RES_PHY_FLAGS_OFDM_VHT	(1 << 10)
#define	IWM_RATE_MCS_HT_MSK		(1 << 8)
#define	IWM_RATE_MCS_CCK_MSK		(1 << 9)
#define	IWM_RATE_MCS_CHAN_WIDTH_MSK	(3 << 11)
#define	IWM_RATE_MCS_SGI_MSK		(1 << 13)
#define	IWM_RATE_MCS_ANT_POS		14
#define	IWM_RATE_MCS_ANT_MSK		(7 << IWM_RATE_MCS_ANT_POS)
#define	IWM_RATE_MCS_STBC_MSK		(1 << 17)
#define	IWM_RATE_MCS_VHT_MSK		(1 << 26)

struct iwm_rx_mpdu_res_start {
	uint16_t byte_count;
	uint16_t reserved;
} __attribute__((__packed__));

struct iwm_umac_scan_complete {
	uint32_t uid;
	uint8_t last_schedule;
	uint8_t last_iter;
	uint8_t status;
	uint8_t ebs_status;
	uint32_t time_from_last_iter;
	uint32_t reserved;
} __attribute__((__packed__));

/* Only the selected v7 prefix; other UMAC request generations omitted. */
struct iwm_scan_v7 {
	uint32_t flags;
	uint32_t uid;
	uint32_t ooc_priority;
	uint16_t general_flags;
	uint8_t reserved;
	uint8_t scan_start_mac_id;
	uint8_t active_dwell;
	uint8_t passive_dwell;
	uint8_t fragmented_dwell;
	uint8_t adwell_default_n_aps;
	uint8_t adwell_default_n_aps_social;
	uint8_t reserved3;
	uint16_t adwell_max_budget;
	uint32_t max_out_time[2];
	uint32_t suspend_time[2];
	uint32_t scan_priority;
	struct iwm_scan_umac_chan_param channel;
} __attribute__((__packed__));

/* API36 time-event v2 command and v1 response/notification. */
#define	IWM_TIME_EVENT_CMD		0x29
#define	IWM_TIME_EVENT_NOTIFICATION	0x2a
#define	IWM_TE_BSS_STA_AGGRESSIVE_ASSOC	0
#define	IWM_TE_HOST_START		0x0001
#define	IWM_TE_HOST_END			0x0002
#define	IWM_TE_START_IMMEDIATELY		0x0800
#define	IWM_FW_CTXT_ACTION_ADD		1
#define	IWM_FW_CTXT_ACTION_MODIFY	2
#define	IWM_FW_CTXT_ACTION_REMOVE	3

struct iwm_time_event_cmd {
	uint32_t id_and_color;
	uint32_t action;
	uint32_t id;
	uint32_t apply_time;
	uint32_t max_delay;
	uint32_t depends_on;
	uint32_t interval;
	uint32_t duration;
	uint8_t repeat;
	uint8_t max_frags;
	uint16_t policy;
} __attribute__((__packed__));

struct iwm_time_event_resp {
	uint32_t status;
	uint32_t id;
	uint32_t unique_id;
	uint32_t id_and_color;
} __attribute__((__packed__));

struct iwm_time_event_notif {
	uint32_t timestamp;
	uint32_t session_id;
	uint32_t unique_id;
	uint32_t id_and_color;
	uint32_t action;
	uint32_t status;
} __attribute__((__packed__));

/* Legacy 8260 context layouts from the pinned donor. */
struct iwm_phy_context_cmd {
	uint32_t id_and_color;
	uint32_t action;
	uint32_t apply_time;
	uint32_t tx_param_color;
	uint8_t band;
	uint8_t channel;
	uint8_t width;
	uint8_t ctrl_pos;
	uint32_t txchain_info;
	uint32_t rxchain_info;
	uint32_t acquisition_data;
	uint32_t dsp_cfg_flags;
} __attribute__((__packed__));

struct iwm_binding_cmd_v1 {
	uint32_t id_and_color;
	uint32_t action;
	uint32_t macs[3];
	uint32_t phy;
} __attribute__((__packed__));

struct iwm_mac_data_sta {
	uint32_t is_assoc;
	uint32_t dtim_time;
	uint64_t dtim_tsf;
	uint32_t bi;
	uint32_t bi_reciprocal;
	uint32_t dtim_interval;
	uint32_t dtim_reciprocal;
	uint32_t listen_interval;
	uint32_t assoc_id;
	uint32_t assoc_beacon_arrive_time;
} __attribute__((__packed__));

struct iwm_ac_qos {
	uint16_t cw_min;
	uint16_t cw_max;
	uint8_t aifsn;
	uint8_t fifos_mask;
	uint16_t edca_txop;
} __attribute__((__packed__));

#define	IWM_MAC_FILTER_DIS_DECRYPT	(1U << 3)
#define	IWM_MAC_FILTER_DIS_GRP_DECRYPT	(1U << 4)
#define	IWM_MAC_PROT_FLG_HT_PROT		(1 << 23)
#define	IWM_MAC_PROT_FLG_FAT_PROT		(1 << 24)
#define	IWM_MAC_QOS_FLG_UPDATE_EDCA	(1 << 0)
#define	IWM_MAC_QOS_FLG_TGN		(1 << 1)

struct iwm_mac_ctx_cmd {
	uint32_t id_and_color;
	uint32_t action;
	uint32_t mac_type;
	uint32_t tsf_id;
	uint8_t node_addr[6];
	uint16_t reserved_for_node_addr;
	uint8_t bssid_addr[6];
	uint16_t reserved_for_bssid_addr;
	uint32_t cck_rates;
	uint32_t ofdm_rates;
	uint32_t protection_flags;
	uint32_t cck_short_preamble;
	uint32_t short_slot;
	uint32_t filter_flags;
	uint32_t qos_flags;
	struct iwm_ac_qos ac[5];
	struct iwm_mac_data_sta sta;
	/* Preserve the donor union's P2P-STA-sized tail; never enable P2P. */
	uint32_t reserved;
} __attribute__((__packed__));

struct iwm_tx_path_flush_cmd_v1 {
	uint32_t queues_ctl;
	uint16_t flush_ctl;
	uint16_t reserved;
} __attribute__((__packed__));

/* API36 TX prefix. Encryption and aggregation remain host-owned/disabled. */
#define	IWM_TX_CMD_FLG_BT_DIS		(1 << 12)
#define	IWM_TX_CMD_FLG_SEQ_CTL		(1 << 13)
#define	IWM_TX_CMD_FLG_MH_PAD		(1 << 20)
#define	IWM_TX_CMD_OFFLD_PAD		(1 << 13)

struct iwm_tx_cmd {
	uint16_t len;
	uint16_t offload_assist;
	uint32_t tx_flags;
	uint32_t scratch;
	uint32_t rate_n_flags;
	uint8_t sta_id;
	uint8_t sec_ctl;
	uint8_t initial_rate_index;
	uint8_t reserved2;
	uint8_t key[16];
	uint32_t reserved3;
	uint32_t life_time;
	uint32_t dram_lsb_ptr;
	uint8_t dram_msb_ptr;
	uint8_t rts_retry_limit;
	uint8_t data_retry_limit;
	uint8_t tid_tspec;
	uint16_t pm_frame_timeout;
	uint16_t reserved4;
} __attribute__((__packed__));

struct iwm_mac_power_cmd {
	uint32_t id_and_color;
	uint16_t flags;
	uint16_t keep_alive_seconds;
	uint32_t rx_data_timeout;
	uint32_t tx_data_timeout;
	uint32_t rx_data_timeout_uapsd;
	uint32_t tx_data_timeout_uapsd;
	uint8_t lprx_rssi_threshold;
	uint8_t skip_dtim_periods;
	uint16_t snooze_interval;
	uint16_t snooze_window;
	uint8_t snooze_step;
	uint8_t qndp_tid;
	uint8_t uapsd_ac_flags;
	uint8_t uapsd_max_sp;
	uint8_t heavy_tx_thld_packets;
	uint8_t heavy_rx_thld_packets;
	uint8_t heavy_tx_thld_percentage;
	uint8_t heavy_rx_thld_percentage;
	uint8_t limited_ps_threshold;
	uint8_t reserved;
} __attribute__((__packed__));

struct iwm_time_quota_data {
	uint32_t id_and_color;
	uint32_t quota;
	uint32_t max_duration;
	uint32_t low_latency;
} __attribute__((__packed__));

CTASSERT(sizeof (struct iwm_phy_context_cmd) == 36);
CTASSERT(sizeof (struct iwm_binding_cmd_v1) == 24);
CTASSERT(sizeof (struct iwm_mac_data_sta) == 44);
CTASSERT(sizeof (struct iwm_mac_ctx_cmd) == 148);
CTASSERT(sizeof (struct iwm_tx_path_flush_cmd_v1) == 8);
CTASSERT(sizeof (struct iwm_tx_cmd) == 56);
CTASSERT(sizeof (struct iwm_mac_power_cmd) == 40);
CTASSERT(sizeof (struct iwm_time_quota_data) == 16);
CTASSERT(sizeof (struct iwm_time_event_cmd) == 36);
CTASSERT(sizeof (struct iwm_time_event_resp) == 16);
CTASSERT(sizeof (struct iwm_time_event_notif) == 24);
CTASSERT(sizeof (struct iwm_scan_v7) == 48);
CTASSERT(sizeof (struct iwm_add_sta_cmd) == 48);
CTASSERT(sizeof (struct iwm_scd_txq_cfg_cmd) == 12);
CTASSERT(sizeof (struct iwm_ba_notif) == 28);
CTASSERT(sizeof (struct iwm_lq_cmd) == 88);
CTASSERT(sizeof (struct iwm_rx_phy_info) == 68);
CTASSERT(sizeof (struct iwm_rx_mpdu_res_start) == 4);
CTASSERT(sizeof (struct iwm_umac_scan_complete) == 16);
CTASSERT(sizeof (struct iwm_scan_config) == 36);
CTASSERT(sizeof (struct iwm_scan_channel_cfg_umac) == 8);

#ifdef __cplusplus
}
#endif

#endif /* _IF_IWMREG_H */
