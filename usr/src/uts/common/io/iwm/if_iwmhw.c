/* BEGIN CSTYLED */
/*	$OpenBSD: if_iwm.c,v 1.419 2025/12/01 16:30:46 stsp Exp $	*/

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Based on BSD-licensed source modules in the Linux iwlwifi driver,
 * which were used as the reference documentation for this implementation.
 *
 ***********************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2007 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
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
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
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
 */

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* END CSTYLED */

/*
 * Copyright 2026 lex0de <lex0de@tuta.com>
 * 8260 firmware transport derived from OpenBSD sys/dev/pci/if_iwm.c,
 * 0efabb066d34187a404f31d303b3b97103df1117, BSD licence option.
 * Native DDI ownership, bounded waits and private passive net80211 scanning.
 */
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <sys/atomic.h>
#include "if_iwmvar.h"

#define	IWM_RUN_MASK	(IWM_CSR_INT_BIT_FH_TX | IWM_CSR_INT_BIT_FH_RX | \
	IWM_CSR_INT_BIT_SW_RX | IWM_CSR_INT_BIT_RX_PERIODIC | \
	IWM_CSR_INT_BIT_ALIVE | IWM_CSR_INT_BIT_HW_ERR | IWM_CSR_INT_BIT_SW_ERR)
#define	IWM_NVM_READ_OPCODE	0
#define	IWM_NVM_LIMIT	32768
#define	IWM_NVM_CHUNK	2048
#define	IWM_WAIT_US	1000000
#define	IWM_CALIB_US	2000000
#define	IWM_PHY_DB_GROUPS	9
#define	IWM_PHY_DB_ENTRIES	(2 + 2 * IWM_PHY_DB_GROUPS)
#define	IWM_INIT_COMPLETE_NOTIF	0x04
#define	IWM_PHY_CONFIGURATION_CMD	0x6a
#define	IWM_CALIB_RES_NOTIF_PHY_DB	0x6b
#define	IWM_PHY_DB_CMD	0x6c
#define	IWM_TX_ANT_CONFIGURATION_CMD	0x98
#define	IWM_REPLY_SF_CFG_CMD	0xd1
#define	IWM_PAGING_CMD	0x14f
#define	IWM_DQA_ENABLE_CMD	0x500
#define	IWM_TEMP_THRESHOLDS_CMD	0x404
#define	IWM_CAPA_CT_KILL_BY_FW	74
#define	IWM_STATISTICS_NOTIFICATION	0x9d
#define	IWM_API_NEW_RX_STATS	35
/* API35 statistics v13: flags + RX + TX + general + load blocks. */
#define	IWM_STATISTICS_V13_SIZE	(4 + 136 + 180 + 180 + 64)
#define	IWM_PHY_DB_CFG	1
#define	IWM_PHY_DB_CALIB_NCH	2
#define	IWM_PHY_DB_CALIB_CHG_PAPD	4
#define	IWM_PHY_DB_CALIB_CHG_TXP	5
#define	IWM_PAGING_BLOCK_SIZE	32768
#define	IWM_PAGING_BLOCKS	33
#define	IWM_MCC_UPDATE_CMD	0xc8
#define	IWM_MCC_CHUB_UPDATE_CMD	0xc9
#define	IWM_MCC_COMMAND_SIZE	28
#define	IWM_MCC_HEADER_SIZE	16
#define	IWM_MCC_CHANNELS	51
#define	IWM_MCC_SOURCE_GET_CURRENT	0x10
#define	IWM_MCC_NEW_PROFILE	0
#define	IWM_MCC_SAME_PROFILE	1
#define	IWM_LAR_VALID	0x01
#define	IWM_LAR_ACTIVE	0x08
#define	IWM_LAR_RESTRICTED	0x90	/* RADAR or DFS */

/* Current-profile state belongs to one REGULAR firmware generation. */
struct iwm_lar_state {
	boolean_t attempted;
	boolean_t ready;
	boolean_t changed;
	int error;
	uint32_t status;
	uint32_t count;
	uint16_t mcc;
	uint16_t time;
	uint16_t geo;
	uint8_t cap;
	uint8_t source;
	uint16_t changed_mcc;
	uint8_t changed_source;
	uint32_t channels[IWM_MCC_CHANNELS];
};

enum iwm_fw_state {
	IWM_FW_CLOSED, IWM_FW_LOADED, IWM_FW_PARSED, IWM_CARD_PREPARED,
	IWM_INIT_UPLOAD, IWM_INIT_ALIVE, IWM_NVM_READING, IWM_NVM_PARSED,
	IWM_INIT_CALIBRATING, IWM_PHY_DB_COMPLETE, IWM_IMAGE_STOPPING,
	IWM_IMAGE_STOPPED, IWM_REGULAR_UPLOAD, IWM_REGULAR_ALIVE,
	IWM_REGULAR_IDLE, IWM_DEVICE_STOPPING, IWM_DEVICE_STOPPED
};

/* Stable rejection identifiers; values are retained until runtime cleanup. */
enum iwm_proto_reason {
	IWM_PROTO_OK, IWM_PROTO_ALIVE, IWM_PROTO_RX_INDEX,
	IWM_PROTO_RX_SHORT, IWM_PROTO_RX_LENGTH, IWM_PROTO_COMMAND_ID,
	IWM_PROTO_NO_COMMAND, IWM_PROTO_QUEUE, IWM_PROTO_SEQUENCE,
	IWM_PROTO_NVM_SHORT, IWM_PROTO_RESPONSE_SIZE, IWM_PROTO_FH_TX,
	IWM_PROTO_NVM_OFFSET, IWM_PROTO_NVM_STATUS,
	IWM_PROTO_NVM_COUNT, IWM_PROTO_NVM_LENGTH, IWM_PROTO_NVM_ZERO,
	IWM_PROTO_COMMAND_GROUP, IWM_PROTO_PHY_DB, IWM_PROTO_INIT_STATE,
	IWM_PROTO_NOTIFICATION
};

enum iwm_rx_class {
	IWM_RX_RESPONSE, IWM_RX_ASYNC, IWM_RX_FRAME, IWM_RX_TX_DONE,
	IWM_RX_UNSUPPORTED, IWM_RX_INVALID
};

/* Legacy sequence bit 15 distinguishes unsolicited firmware packets. */
static enum iwm_rx_class
iwm_rx_classify(uint_t code, uint_t qid)
{
	boolean_t unsolicited = (qid & 0x80) != 0;

	switch (code) {
	case 0xc0:	/* legacy RX PHY */
	case 0xc1:	/* legacy RX MPDU */
		return (unsolicited ? IWM_RX_FRAME : IWM_RX_INVALID);
	case 0x1c:	/* ordinary station TX completion */
		return (unsolicited ? IWM_RX_INVALID : IWM_RX_TX_DONE);
	case IWM_INIT_COMPLETE_NOTIF:
		return (IWM_RX_ASYNC);
	case IWM_ALIVE:
	case IWM_CALIB_RES_NOTIF_PHY_DB:
	case IWM_MFUART_LOAD_NOTIFICATION:
	case IWM_TIME_EVENT_NOTIFICATION:
	case IWM_MCC_CHUB_UPDATE_CMD:
	case IWM_STATISTICS_NOTIFICATION:
	case 0x0f:	/* UMAC scan completion */
	case 0xb5:	/* UMAC scan iteration */
	case 0xa2:	/* missed beacons */
	case 0xa1:	/* card state */
	case 0xc5:	/* API36 compressed TX BA */
	case 0x02:	/* firmware error */
	case 0x4fe:	/* critical temperature */
		return (unsolicited ? IWM_RX_ASYNC : IWM_RX_INVALID);
	default:
		return (unsolicited ? IWM_RX_UNSUPPORTED : IWM_RX_RESPONSE);
	}
}

/* No statistics fields are consumed until their native reporting is needed. */
static boolean_t
iwm_statistics_check(uint32_t api, size_t length)
{
	return ((api & (1U << (IWM_API_NEW_RX_STATS % 32))) != 0 &&
	    length == IWM_STATISTICS_V13_SIZE);
}

struct iwm_proto_diag {
	enum iwm_proto_reason reason;
	uint32_t interrupt;
	uint32_t fh;
	uint32_t raw;
	size_t length;
	size_t available;
	size_t payload;
	uint_t rxcur;
	uint_t rxhw;
	uint_t code;
	uint_t sequence;
	uint_t expected_sequence;
	uint_t expected_code;
	uint_t section;
	uint_t offset;
	uint_t requested;
	uint_t actual_type;
	uint_t actual_offset;
	uint_t count;
	uint_t status;
	boolean_t packet_valid;
	boolean_t nvm_valid;
	boolean_t pending;
};

/* These pure checks preserve the existing transport acceptance conditions. */
static enum iwm_proto_reason
iwm_packet_check(size_t length, size_t available)
{
	if (length < 4)
		return (IWM_PROTO_RX_SHORT);
	if (length > available)
		return (IWM_PROTO_RX_LENGTH);
	return (IWM_PROTO_OK);
}

static enum iwm_proto_reason
iwm_command_check(uint_t code, boolean_t pending, uint_t sequence,
    uint_t expected, size_t length)
{
	if ((code & 0xff) != IWM_NVM_ACCESS_CMD)
		return (IWM_PROTO_COMMAND_ID);
	if ((code >> 8) != 0)
		return (IWM_PROTO_COMMAND_GROUP);
	if (!pending)
		return (IWM_PROTO_NO_COMMAND);
	if ((sequence >> 8) != (expected >> 8))
		return (IWM_PROTO_QUEUE);
	if ((sequence & 0xff) != (expected & 0xff))
		return (IWM_PROTO_SEQUENCE);
	if (length < sizeof (struct iwm_nvm_access_resp))
		return (IWM_PROTO_NVM_SHORT);
	if (length > IWM_NVM_CHUNK + 32)
		return (IWM_PROTO_RESPONSE_SIZE);
	return (IWM_PROTO_OK);
}

static enum iwm_proto_reason
iwm_nvm_check(const struct iwm_proto_diag *d)
{
	if (d->payload < 8)
		return (IWM_PROTO_NVM_SHORT);
	/* A failed firmware read has no success metadata or data body. */
	if (d->status != 0)
		return (IWM_PROTO_NVM_STATUS);
	if (d->actual_offset != d->offset)
		return (IWM_PROTO_NVM_OFFSET);
	if (d->count == 0)
		return (IWM_PROTO_NVM_ZERO);
	if (d->count > d->requested)
		return (IWM_PROTO_NVM_COUNT);
	if (d->count > d->payload - 8)
		return (IWM_PROTO_NVM_LENGTH);
	return (IWM_PROTO_OK);
}

struct iwm_phy_entry {
	uint8_t *data;
	size_t length;
};

#define	IWM_SCAN_CHANNELS	52
#define	IWM_SCAN_RX_LIMIT	64
#define	IWM_SCAN_UID	0
#define	IWM_SCAN_PASSIVE	0x200c
#define	IWM_AUX_QUEUE	1
#define	IWM_AUX_STA	1
#define	IWM_SCAN_COMPLETED	1
#define	IWM_SCAN_ABORTED	2

struct iwm_scan_frame {
	mblk_t *mp;
	uint_t channel;
	int rssi;
	uint32_t timestamp;
};

struct iwm_scan_state {
	boolean_t enabled;
	boolean_t attached;
	boolean_t running;
	boolean_t submitted;
	boolean_t outstanding;
	boolean_t accepting;
	boolean_t delivering;
	boolean_t abort_requested;
	boolean_t terminal_consumed;
	uint32_t uid;
	uint32_t terminal_uid;
	uint_t abort_commands;
	int error;
	int abort_error;
	boolean_t complete;
	boolean_t cancelled;
	boolean_t aux_queue;
	boolean_t aux_station;
	boolean_t configured;
	boolean_t phy_valid;
	uint_t channels;
	uint8_t channel[14];
	struct iwm_rx_phy_info phy;
	struct iwm_scan_frame frames[IWM_SCAN_RX_LIMIT];
	uint_t head;
	uint_t tail;
	uint_t queued;
	uint_t accepted;
	uint_t malformed;
	uint_t channel_mismatch;
	uint_t dropped;
	uint_t beacons;
	uint_t probes;
	uint_t overflow;
	uint_t xmit_calls;
	uint_t state_violations;
	uint_t nodes;
	uint_t completion_status;
	uint_t completion_iteration;
	int (*newstate)(ieee80211com_t *, enum ieee80211_state, int);
};

/* Protected by sc->lock; command acceptance is not scheduling acceptance. */
struct iwm_time_event_state {
	boolean_t submitted;
	boolean_t responded;
	boolean_t accepted;
	boolean_t started;
	boolean_t ended;
	boolean_t active;
	boolean_t removing;
	boolean_t removed;
	uint32_t uid;
	uint_t generation;
	uint32_t id_color;
	uint32_t response_status;
	uint32_t remove_status;
	uint32_t remove_id;
	uint32_t remove_id_color;
	uint32_t notification_status;
	uint32_t notification_action;
	uint32_t timestamp;
	uint32_t session;
	int error;
};

enum iwm_ba_state {
	IWM_BA_CLOSED, IWM_BA_STARTING, IWM_BA_ACTIVE,
	IWM_BA_STOPPING, IWM_BA_DRAINING
};

/* Borrowed node identity is protected by the connection worker's reference. */
struct iwm_tx_ba {
	enum iwm_ba_state state;
	uint64_t generation;
	struct ieee80211_node *node;
	uint_t runtime_generation;
	uint8_t tid;
	uint8_t ac;
	uint8_t token;
	uint8_t qid;
	uint16_t ssn;
	uint16_t next_sequence;
	uint16_t window;
	clock_t deadline;
	boolean_t accepted;
	boolean_t admission;
	uint_t responses;
	uint_t notifications;
	uint_t rejected;
};

/* One station topology, independent of the scan AUX station. */
struct iwm_association {
	boolean_t phy;
	boolean_t mac;
	boolean_t binding;
	boolean_t station;
	boolean_t run_configured;
	uint_t queues;
	struct iwm_tx_ring tx[IWM_ASSOC_TX_RINGS];
	struct iwm_tx_ba ba[8];
	uint64_t generation;
	struct iwm_rx_phy_info rx_phy;
	uint32_t rx_rate_flags;
	boolean_t phy_valid;
	struct iwm_scan_frame frames[IWM_SCAN_RX_LIMIT];
	uint_t head;
	uint_t tail;
	uint_t queued;
	boolean_t beacon_valid;
	uint32_t beacon_gp2;
	uint64_t beacon_tsf;
	uint8_t dtim_count;
	uint8_t dtim_period;
	uint_t tx_submitted;
	uint_t tx_completed;
	uint_t rx_delivered;
	uint_t rx_dropped;
};

struct iwm_runtime {
	/* Disabled scheduler history outlives association storage. */
	uint_t released_queues;
	/* API36 has no BA epoch: only full runtime destruction resets this. */
	boolean_t ba_queue_used;
	uint64_t ba_generation;
	struct iwm_scan_state scan;
	struct iwm_lar_state lar;
	struct iwm_time_event_state protection;
	struct iwm_association association;
	struct iwm_proto_diag diagnostic;
	struct iwm_proto_diag first_error;
	struct iwm_proto_diag response_diagnostic;
	enum iwm_fw_state state;
	kcondvar_t cv;
	boolean_t touched;
	boolean_t stopped;
	boolean_t stop_failed;
	boolean_t rx_started;
	boolean_t tx_started;
	boolean_t published;
	boolean_t alive;
	boolean_t chunk_done;
	boolean_t command_done;
	boolean_t command_pending;
	int error;
	uint32_t mask;
	uint32_t causes;
	uint_t interrupt_count;
	clock_t interrupt_epoch;
	uint_t interrupt_window;
	uint32_t fh_causes;
	uint32_t sched_base;
	uint32_t hw_rev;
	uint32_t alive_data[32];
	size_t alive_len;
	uint_t cmdqid;
	uint_t cmdcur;
	uint_t rxcur;
	uint_t nic_locks;
	uint8_t response[IWM_NVM_CHUNK + 32];
	size_t response_len;
	struct iwm_dma_info transfer;
	struct iwm_dma_info scheduler;
	struct iwm_dma_info tx[IWM_MAX_QUEUES];
	struct iwm_dma_info commands;
	struct iwm_dma_info rx[IWM_RX_RING_COUNT];
	uint8_t *nvm[IWM_NVM_NUM_OF_SECTIONS];
	size_t nvm_len[IWM_NVM_NUM_OF_SECTIONS];
	boolean_t cancel_requested;
	boolean_t full_cycle;
	uint_t image;
	uint_t generation;
	uint_t expected_code;
	boolean_t control_command;
	enum iwm_rx_class packet_class;
	uint_t statistics_notifications;
	uint_t missed_beacon_notifications;
	uint_t unsupported_notifications;
	uint_t unsupported_code;
	uint_t unsupported_sequence;
	size_t unsupported_length;
	boolean_t init_complete;
	boolean_t calib_complete;
	uint_t phy_notifications;
	struct iwm_phy_entry phy_db[IWM_PHY_DB_ENTRIES];
	struct iwm_dma_info paging[IWM_PAGING_BLOCKS];
	uint_t paging_blocks;
	uint_t paging_last;
};

static uint16_t iwm_u16(const uint8_t *);
static uint32_t iwm_u32(const uint8_t *);
static struct iwm_softc *iwm_scan_softc(ieee80211com_t *);
static int iwm_association_tx(struct iwm_softc *, mblk_t *, boolean_t,
    boolean_t);
static int iwm_ba_work(struct iwm_softc *);
static void iwm_ba_retire(struct iwm_softc *);
static int iwm_association_reclaim(struct iwm_softc *, boolean_t);

static void
iwm_proto_report(struct iwm_softc *sc, const struct iwm_proto_diag *d)
{
	static const char * const names[] = {
		"ok", "alive-layout", "rx-index", "rx-short", "rx-length",
		"command-id", "no-command", "command-queue", "command-index",
		"nvm-short", "response-size", "fh-tx-state", "nvm-offset",
		"nvm-status", "nvm-count", "nvm-length",
		"nvm-zero", "command-group", "phy-db", "init-state",
		"notification"
	};

	dev_err(sc->dip, CE_NOTE, "!iwm protocol reason=%s(%u) "
	    "csr=%08x fh=%08x rx=%u/%u raw=%08x length=%lu available=%lu",
	    names[d->reason], d->reason, d->interrupt, d->fh,
	    d->rxcur, d->rxhw, d->raw, (ulong_t)d->length,
	    (ulong_t)d->available);
	dev_err(sc->dip, CE_NOTE, "!iwm protocol packet-valid=%u "
	    "code=%04x sequence=%04x q=%u idx=%u expected-code=%04x "
	    "expected-sequence=%04x pending=%u payload=%lu",
	    d->packet_valid, d->code, d->sequence, d->sequence >> 8,
	    d->sequence & 0xff, d->expected_code, d->expected_sequence,
	    d->pending, (ulong_t)d->payload);
	dev_err(sc->dip, CE_NOTE, "!iwm protocol nvm-header-valid=%u "
	    "type=%u requested=%u offset=%u/%u count=%u/requested=%u status=%u",
	    d->nvm_valid, d->actual_type, d->section,
	    d->actual_offset, d->offset, d->count, d->requested, d->status);
}

static void
iwm_proto_error(struct iwm_softc *sc, enum iwm_proto_reason reason)
{
	struct iwm_runtime *r = sc->run;

	if (r->first_error.reason == IWM_PROTO_OK) {
		r->diagnostic.reason = reason;
		r->first_error = r->diagnostic;
		iwm_proto_report(sc, &r->first_error);
	}
	r->error = EPROTO;
}

static uint32_t
iwm_rd(struct iwm_softc *sc, uint_t reg)
{
	uint32_t value = 0xffffffff;

	(void) iwm_reg_read(sc, reg, &value);
	return (value);
}

static void
iwm_wr(struct iwm_softc *sc, uint_t reg, uint32_t value)
{
	VERIFY0(iwm_reg_write(sc, reg, value));
}

static void
iwm_bits(struct iwm_softc *sc, uint_t reg, uint32_t set, uint32_t clear)
{
	iwm_wr(sc, reg, (iwm_rd(sc, reg) & ~clear) | set);
}

static void
iwm_wr8(struct iwm_softc *sc, uint_t reg, uint8_t value)
{
	ASSERT(reg < sc->regsize);
	ddi_put8(sc->regh, (uint8_t *)(sc->regs + reg), value);
}

static int
iwm_poll(struct iwm_softc *sc, uint_t reg, uint32_t mask,
    uint32_t wanted, uint_t usec)
{
	uint_t n;

	for (n = 0; n <= usec; n += 10) {
		if ((iwm_rd(sc, reg) & mask) == wanted)
			return (0);
		drv_usecwait(10);
	}
	return (ETIMEDOUT);
}

/* All peripheral windows and lifecycle state serialize under sc->lock. */
static int
iwm_nic_lock(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;

	ASSERT(MUTEX_HELD(&sc->lock));
	if (r->nic_locks != 0) {
		r->nic_locks++;
		return (0);
	}
	iwm_bits(sc, IWM_CSR_GP_CNTRL,
	    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ, 0);
	drv_usecwait(2);
	if (iwm_poll(sc, IWM_CSR_GP_CNTRL,
	    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
	    IWM_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP,
	    IWM_CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN, 150000) != 0) {
		iwm_bits(sc, IWM_CSR_GP_CNTRL, 0,
		    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
		return (ETIMEDOUT);
	}
	r->nic_locks = 1;
	return (0);
}

static void
iwm_nic_unlock(struct iwm_softc *sc)
{
	ASSERT(sc->run->nic_locks != 0);
	if (--sc->run->nic_locks == 0)
		iwm_bits(sc, IWM_CSR_GP_CNTRL, 0,
		    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
}

static uint32_t
iwm_prph_read(struct iwm_softc *sc, uint32_t addr)
{
	ASSERT(sc->run->nic_locks != 0);
	iwm_wr(sc, IWM_HBUS_TARG_PRPH_RADDR, (addr & 0xfffff) | (3 << 24));
	return (iwm_rd(sc, IWM_HBUS_TARG_PRPH_RDAT));
}

static void
iwm_prph_write(struct iwm_softc *sc, uint32_t addr, uint32_t value)
{
	ASSERT(sc->run->nic_locks != 0);
	iwm_wr(sc, IWM_HBUS_TARG_PRPH_WADDR, (addr & 0xfffff) | (3 << 24));
	iwm_wr(sc, IWM_HBUS_TARG_PRPH_WDAT, value);
}

static void
iwm_prph_bits(struct iwm_softc *sc, uint32_t addr, uint32_t set,
    uint32_t clear)
{
	iwm_prph_write(sc, addr, (iwm_prph_read(sc, addr) & ~clear) | set);
}

static void
iwm_mem_zero(struct iwm_softc *sc, uint32_t addr, size_t bytes)
{
	size_t i;

	ASSERT(sc->run->nic_locks != 0);
	iwm_wr(sc, IWM_HBUS_TARG_MEM_WADDR, addr);
	for (i = 0; i < bytes; i += 4)
		iwm_wr(sc, IWM_HBUS_TARG_MEM_WDAT, 0);
}

static int
iwm_ready(struct iwm_softc *sc)
{
	iwm_bits(sc, IWM_CSR_HW_IF_CONFIG_REG,
	    IWM_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY, 0);
	if (iwm_poll(sc, IWM_CSR_HW_IF_CONFIG_REG,
	    IWM_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY,
	    IWM_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY, 50) != 0)
		return (ETIMEDOUT);
	iwm_bits(sc, IWM_CSR_MBOX_SET_REG, IWM_CSR_MBOX_SET_REG_OS_ALIVE, 0);
	return (0);
}

static int
iwm_prepare(struct iwm_softc *sc)
{
	uint_t i, elapsed = 0;

	sc->run->touched = B_TRUE;
	if (iwm_ready(sc) == 0)
		return (0);
	iwm_bits(sc, IWM_CSR_DBG_LINK_PWR_MGMT_REG,
	    IWM_CSR_RESET_LINK_PWR_MGMT_DISABLED, 0);
	drv_usecwait(1000);
	for (i = 0; i < 10; i++) {
		iwm_bits(sc, IWM_CSR_HW_IF_CONFIG_REG,
		    IWM_CSR_HW_IF_CONFIG_REG_PREPARE, 0);
		do {
			if (iwm_ready(sc) == 0)
				return (0);
			drv_usecwait(200);
			elapsed += 200;
		} while (elapsed < 150000);
		drv_usecwait(25000);
	}
	return (ETIMEDOUT);
}

static int
iwm_apm(struct iwm_softc *sc)
{
	uint16_t link;

	iwm_bits(sc, IWM_CSR_GIO_CHICKEN_BITS,
	    IWM_CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX, 0);
	iwm_bits(sc, IWM_CSR_DBG_HPET_MEM_REG, IWM_CSR_DBG_HPET_MEM_REG_VAL, 0);
	iwm_bits(sc, IWM_CSR_HW_IF_CONFIG_REG,
	    IWM_CSR_HW_IF_CONFIG_REG_BIT_HAP_WAKE_L1A, 0);
	link = pci_config_get16(sc->pcih, sc->pcie_cap + PCIE_LINKCTL);
	if (link & PCIE_LINKCTL_ASPM_CTL_L1)
		iwm_bits(sc, IWM_CSR_GIO_REG, IWM_CSR_GIO_REG_VAL_L0S_ENABLED,
		    0);
	else
		iwm_bits(sc, IWM_CSR_GIO_REG, 0,
		    IWM_CSR_GIO_REG_VAL_L0S_ENABLED);
	iwm_bits(sc, IWM_CSR_GP_CNTRL, IWM_CSR_GP_CNTRL_REG_FLAG_INIT_DONE, 0);
	return (iwm_poll(sc, IWM_CSR_GP_CNTRL,
	    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
	    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000));
}

static int
iwm_start(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint32_t step;
	int error;

	/* Preserve platform bus-master ownership; never turn it on here. */
	if (!(pci_config_get16(sc->pcih, PCI_CONF_COMM) & PCI_COMM_ME))
		return (ENOTSUP);
	if ((error = iwm_prepare(sc)) != 0)
		return (error);
	r->state = IWM_CARD_PREPARED;
	if (iwm_checkpoint(sc, "card-prepared") != 0)
		return (EIO);
	/* 8000 C-step discovery, deliberately omitted from passive attach. */
	r->hw_rev = (sc->hw_rev & 0xfff0) |
	    (IWM_CSR_HW_REV_STEP(sc->hw_rev << 2) << 2);
	iwm_bits(sc, IWM_CSR_GP_CNTRL, IWM_CSR_GP_CNTRL_REG_FLAG_INIT_DONE, 0);
	drv_usecwait(2);
	if (iwm_poll(sc, IWM_CSR_GP_CNTRL,
	    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
	    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000) != 0 ||
	    iwm_nic_lock(sc) != 0)
		return (ETIMEDOUT);
	iwm_prph_bits(sc, IWM_WFPM_CTRL_REG, IWM_ENABLE_WFPM, 0);
	step = iwm_prph_read(sc, IWM_AUX_MISC_REG);
	if (step == 0xffffffff || step == 0xa5a5a5a0) {
		iwm_nic_unlock(sc);
		return (EIO);
	}
	step = (step >> IWM_HW_STEP_LOCATION_BITS) & 0xf;
	if (step == 3)
		r->hw_rev = (r->hw_rev & 0xfffffff3) |
		    (IWM_SILICON_C_STEP << 2);
	iwm_nic_unlock(sc);
	iwm_wr(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_SW_RESET);
	drv_usecwait(5000);
	if ((error = iwm_apm(sc)) != 0)
		return (error);
	return (iwm_checkpoint(sc, "reset-apm"));
}

static int
iwm_sync(struct iwm_dma_info *dma, uint_t direction)
{
	return (ddi_dma_sync(dma->dma_hdl, 0, dma->size, direction) ==
	    DDI_SUCCESS ? 0 : EIO);
}

static uint64_t
iwm_dma_addr(struct iwm_dma_info *dma)
{
	ASSERT(dma->bound && dma->cookie.dmac_laddress <= 0xfffffffffULL);
	return (dma->cookie.dmac_laddress);
}

enum iwm_queue_boundary {
	IWM_QUEUES_LIVE,
	IWM_QUEUES_RELEASED
};

/* Software ownership is checked even when device registers are inaccessible. */
static int
iwm_association_queues_check(struct iwm_runtime *r,
    enum iwm_queue_boundary boundary)
{
	static const uint8_t fifo[] = { 1, 0, 2, 3, 1 };
	uint_t ac, i, mask = 0;

	for (ac = 0; ac < IWM_ASSOC_TX_RINGS; ac++) {
		struct iwm_tx_ring *ring = &r->association.tx[ac];
		uint_t owned = 0;

		if (ring->qid >= IWM_MAX_QUEUES ||
		    ring->cur >= IWM_TX_RING_COUNT ||
		    ring->tail >= IWM_TX_RING_COUNT ||
		    ring->queued >= IWM_TX_RING_COUNT)
			return (EPROTO);
		if (ring->configured) {
			if (boundary != IWM_QUEUES_LIVE || ring->released ||
			    ring->qid == r->cmdqid ||
			    (r->scan.aux_queue && ring->qid == IWM_AUX_QUEUE) ||
			    (mask & (1U << ring->qid)) || ring->station != 0 ||
			    ring->fifo != fifo[ac] || ring->desc == NULL ||
			    !ring->cmd_dma.bound)
				return (EPROTO);
			mask |= 1U << ring->qid;
		}
		for (i = 0; i < IWM_TX_RING_COUNT; i++) {
			struct iwm_tx_data *slot = &ring->data[i];

			if (slot->owned) {
				if (!ring->configured || slot->mp == NULL ||
				    slot->ni == NULL || !slot->dma.bound ||
				    slot->generation != r->generation ||
				    (i + IWM_TX_RING_COUNT - ring->tail) %
				    IWM_TX_RING_COUNT >= ring->queued)
					return (EPROTO);
				owned++;
			} else if (slot->mp != NULL || slot->ni != NULL ||
			    slot->completed || slot->mapped != 0) {
				return (EPROTO);
			}
		}
		if ((ring->released && (ring->queued != 0 ||
		    ring->cur != 0 || ring->tail != 0)) ||
		    owned != ring->queued ||
		    (ring->tail + owned) % IWM_TX_RING_COUNT != ring->cur)
			return (EPROTO);
	}
	return (mask == r->association.queues ? 0 : EPROTO);
}

/* SCD register upper bits are not part of the legacy queue ring index. */
static uint_t
iwm_scd_queue_index(uint32_t raw)
{
	CTASSERT(IWM_TX_RING_COUNT != 0 &&
	    (IWM_TX_RING_COUNT & (IWM_TX_RING_COUNT - 1)) == 0);
	return (raw & (IWM_TX_RING_COUNT - 1));
}

/* Validate live owners before stop; RELEASED is checked after reclamation. */
static int
iwm_queues_check(struct iwm_softc *sc, const char *boundary)
{
	struct iwm_runtime *r = sc->run;
	uint_t q, i;
	uint32_t raw_rd, raw_wr, rd, wr, status, base;
	int error = 0;

	if (iwm_association_queues_check(r, IWM_QUEUES_LIVE) != 0)
		return (EPROTO);
	if (iwm_nic_lock(sc) != 0)
		return (EBUSY);
	for (q = 0; q < IWM_MAX_QUEUES; q++) {
		struct iwm_tx_ring *ring = NULL;
		uint_t ac;

		for (ac = 0; ac < IWM_ASSOC_TX_RINGS; ac++) {
			if (r->association.tx[ac].qid != q)
				continue;
			if (r->association.tx[ac].configured)
				ring = &r->association.tx[ac];
		}
		base = iwm_rd(sc, IWM_FH_MEM_CBBC_QUEUE(q));
		if (base != iwm_dma_addr(&r->tx[q]) >> 8) {
			error = EIO;
			dev_err(sc->dip, CE_WARN, "!iwm %s q%u base=%08x "
			    "expected=%08x", boundary, q, base,
			    (uint32_t)(iwm_dma_addr(&r->tx[q]) >> 8));
		}
		raw_rd = iwm_prph_read(sc, IWM_SCD_QUEUE_RDPTR(q));
		raw_wr = iwm_prph_read(sc, IWM_SCD_QUEUE_WRPTR(q));
		rd = iwm_scd_queue_index(raw_rd);
		wr = iwm_scd_queue_index(raw_wr);
		status = iwm_prph_read(sc, IWM_SCD_QUEUE_STATUS_BITS(q));
		if (q == r->cmdqid)
			continue;
		if (ring != NULL) {
			if (!(status &
			    (1U << IWM_SCD_QUEUE_STTS_REG_POS_ACTIVE)) ||
			    (status & 7) != ring->fifo ||
			    wr != ring->cur ||
			    (rd + IWM_TX_RING_COUNT - ring->tail) %
			    IWM_TX_RING_COUNT > ring->queued)
				error = EIO;
			continue;
		}
		if (r->released_queues & (1U << q)) {
			/* Disable leaves scheduler history, not live work. */
			if (wr != rd ||
			    (status &
			    (1U << IWM_SCD_QUEUE_STTS_REG_POS_ACTIVE)))
				error = EIO;
			dev_err(sc->dip, CE_NOTE, "!iwm %s released q%u "
			    "raw_rd=%08x raw_wr=%08x rd=%u wr=%u "
			    "status=%08x active=%u", boundary, q,
			    raw_rd, raw_wr, rd, wr, status,
			    (status >> IWM_SCD_QUEUE_STTS_REG_POS_ACTIVE) & 1);
			continue;
		}
		if (rd != 0 || wr != 0 ||
		    ((status & (1 << IWM_SCD_QUEUE_STTS_REG_POS_ACTIVE)) &&
		    !(r->scan.aux_queue && q == IWM_AUX_QUEUE))) {
			error = EIO;
			dev_err(sc->dip, CE_WARN, "!iwm %s unused q%u "
			    "raw_rd=%08x raw_wr=%08x rd=%u wr=%u "
			    "status=%08x", boundary, q, raw_rd, raw_wr, rd,
			    wr, status);
		}
		if (iwm_sync(&r->tx[q], DDI_DMA_SYNC_FORCPU) != 0)
			error = EIO;
		for (i = 0; i < r->tx[q].size; i++) {
			if (r->tx[q].vaddr[i] != 0) {
				error = EIO;
				dev_err(sc->dip, CE_WARN,
				    "!iwm %s unused q%u descriptor data at "
				    "byte %u", boundary, q, i);
				break;
			}
		}
		if (iwm_sync(&r->tx[q], DDI_DMA_SYNC_FORDEV) != 0)
			error = EIO;
	}
	iwm_nic_unlock(sc);
	if (error != 0) {
		dev_err(sc->dip, CE_WARN, "!iwm unused queue invariant failed");
		r->error = error;
		r->mask = 0;
		iwm_wr(sc, IWM_CSR_INT_MASK, 0);
	}
	return (error);
}

static int
iwm_transport_init(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint32_t phy = sc->fw.phy_config, mask, value;
	uint_t q;

	if (iwm_apm(sc) != 0 || iwm_nic_lock(sc) != 0)
		return (ETIMEDOUT);
	value = IWM_CSR_HW_REV_STEP(r->hw_rev) <<
	    IWM_CSR_HW_IF_CONFIG_REG_POS_MAC_STEP;
	value |= IWM_CSR_HW_REV_DASH(r->hw_rev) <<
	    IWM_CSR_HW_IF_CONFIG_REG_POS_MAC_DASH;
	value |= ((phy & IWM_FW_PHY_CFG_RADIO_TYPE) >>
	    IWM_FW_PHY_CFG_RADIO_TYPE_POS) <<
	    IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_TYPE;
	value |= ((phy & IWM_FW_PHY_CFG_RADIO_STEP) >>
	    IWM_FW_PHY_CFG_RADIO_STEP_POS) <<
	    IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_STEP;
	value |= ((phy & IWM_FW_PHY_CFG_RADIO_DASH) >>
	    IWM_FW_PHY_CFG_RADIO_DASH_POS) <<
	    IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_DASH;
	mask = IWM_CSR_HW_IF_CONFIG_REG_MSK_MAC_DASH |
	    IWM_CSR_HW_IF_CONFIG_REG_MSK_MAC_STEP |
	    IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_STEP |
	    IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_DASH |
	    IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_TYPE |
	    IWM_CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
	    IWM_CSR_HW_IF_CONFIG_REG_BIT_MAC_SI;
	iwm_bits(sc, IWM_CSR_HW_IF_CONFIG_REG, value, mask);
	iwm_wr(sc, IWM_FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);
	if (iwm_poll(sc, IWM_FH_MEM_RSSR_RX_STATUS_REG,
	    IWM_FH_RSSR_CHNL0_RX_STATUS_CHNL_IDLE,
	    IWM_FH_RSSR_CHNL0_RX_STATUS_CHNL_IDLE, 10000) != 0) {
		iwm_nic_unlock(sc);
		return (ETIMEDOUT);
	}
	iwm_wr(sc, IWM_FH_MEM_RCSR_CHNL0_RBDCB_WPTR, 0);
	iwm_wr(sc, IWM_FH_MEM_RCSR_CHNL0_FLUSH_RB_REQ, 0);
	iwm_wr(sc, IWM_FH_RSCSR_CHNL0_RDPTR, 0);
	iwm_wr(sc, IWM_FH_RSCSR_CHNL0_RBDCB_WPTR_REG, 0);
	iwm_wr(sc, IWM_FH_RSCSR_CHNL0_RBDCB_BASE_REG,
	    iwm_dma_addr(&sc->dma[2]) >> 8);
	iwm_wr(sc, IWM_FH_RSCSR_CHNL0_STTS_WPTR_REG,
	    iwm_dma_addr(&sc->dma[3]) >> 4);
	r->rx_started = B_TRUE;
	iwm_wr(sc, IWM_FH_MEM_RCSR_CHNL0_CONFIG_REG,
	    IWM_FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL |
	    IWM_FH_RCSR_CHNL0_RX_IGNORE_RXF_EMPTY |
	    IWM_FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL |
	    (IWM_RX_RB_TIMEOUT << IWM_FH_RCSR_RX_CONFIG_REG_IRQ_RBTH_POS) |
	    IWM_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K |
	    IWM_RX_QUEUE_SIZE_LOG << IWM_FH_RCSR_RX_CONFIG_RBDCB_SIZE_POS);
	iwm_wr8(sc, IWM_CSR_INT_COALESCING, IWM_HOST_INT_TIMEOUT_DEF);
	iwm_wr(sc, IWM_FH_RSCSR_CHNL0_WPTR, 8);
	iwm_prph_write(sc, IWM_SCD_TXFACT, 0);
	iwm_wr(sc, IWM_FH_KW_MEM_ADDR_REG, iwm_dma_addr(&sc->dma[0]) >> 4);
	for (q = 0; q < IWM_MAX_QUEUES; q++) {
		iwm_wr(sc, IWM_FH_MEM_CBBC_QUEUE(q),
		    iwm_dma_addr(&r->tx[q]) >> 8);
		if (iwm_checkpoint(sc, "TX-base-programmed") != 0) {
			iwm_nic_unlock(sc);
			return (EIO);
		}
	}
	r->published = B_TRUE;
	iwm_prph_bits(sc, IWM_SCD_GP_CTRL,
	    IWM_SCD_GP_CTRL_AUTO_ACTIVE_MODE |
	    IWM_SCD_GP_CTRL_ENABLE_31_QUEUES, 0);
	iwm_nic_unlock(sc);
	iwm_bits(sc, IWM_CSR_MAC_SHADOW_REG_CTRL, 0x800fffff, 0);
	if (iwm_checkpoint(sc, "transport-programmed") != 0)
		return (EIO);
	return (iwm_queues_check(sc, "pre-INIT"));
}

static int
iwm_wait(struct iwm_softc *sc, boolean_t *done)
{
	struct iwm_runtime *r = sc->run;
	clock_t deadline = ddi_get_lbolt() + drv_usectohz(IWM_WAIT_US);

	ASSERT(MUTEX_HELD(&sc->lock));
	while (!*done && r->error == 0) {
		if (cv_timedwait(&r->cv, &sc->lock, deadline) < 0) {
			r->error = ETIMEDOUT;
			break;
		}
	}
	return (r->error);
}

static int
iwm_upload(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_fw_image *im = &sc->fw.image[r->image];
	uint_t i, cpu = 0, bits = 1;
	size_t pos, length;
	uint32_t offset, status;
	uint64_t addr = iwm_dma_addr(&r->transfer);
	int error;

	r->state = r->image == IWM_FW_INIT ?
	    IWM_INIT_UPLOAD : IWM_REGULAR_UPLOAD;
	r->alive = B_FALSE;
	iwm_wr(sc, IWM_CSR_INT, 0xffffffff);
	iwm_wr(sc, IWM_CSR_UCODE_DRV_GP1_CLR,
	    IWM_CSR_UCODE_SW_BIT_RFKILL |
	    IWM_CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
	iwm_wr(sc, IWM_CSR_INT, 0xffffffff);
	r->mask = IWM_CSR_INT_BIT_FH_TX | IWM_CSR_INT_BIT_HW_ERR |
	    IWM_CSR_INT_BIT_SW_ERR;
	iwm_wr(sc, IWM_CSR_INT_MASK, r->mask);
	iwm_wr(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
	iwm_wr(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
	if (iwm_nic_lock(sc) != 0)
		return (EBUSY);
	iwm_prph_write(sc, IWM_RELEASE_CPU_RESET, IWM_RELEASE_CPU_RESET_BIT);
	iwm_nic_unlock(sc);
	if (iwm_checkpoint(sc, "CPU-release") != 0)
		return (EIO);
	for (i = 0; i < im->count; i++) {
		struct iwm_fw_section *s = &im->section[i];

		if (s->offset == IWM_FW_CPU_SEPARATOR ||
		    s->offset == IWM_FW_PAGING_SEPARATOR) {
			if (iwm_nic_lock(sc) != 0)
				return (EBUSY);
			iwm_wr(sc, IWM_FH_UCODE_LOAD_STATUS,
			    cpu == 0 ? 0xffff : 0xffffffff);
			iwm_nic_unlock(sc);
			if (s->offset == IWM_FW_PAGING_SEPARATOR)
				break;
			cpu = 1;
			bits = 1;
			continue;
		}
		for (pos = 0; pos < s->length; pos += length) {
			length = MIN(s->length - pos, IWM_FH_MEM_TB_MAX_LENGTH);
			offset = s->offset + pos;
			bcopy(s->data + pos, r->transfer.vaddr, length);
			if (iwm_sync(&r->transfer, DDI_DMA_SYNC_FORDEV) != 0 ||
			    iwm_nic_lock(sc) != 0)
				return (EIO);
			if (offset >= IWM_FW_MEM_EXTENDED_START &&
			    offset <= IWM_FW_MEM_EXTENDED_END)
				iwm_prph_bits(sc, IWM_LMPM_CHICK,
				    IWM_LMPM_CHICK_EXTENDED_ADDR_SPACE, 0);
			r->chunk_done = B_FALSE;
			r->tx_started = B_TRUE;
			iwm_wr(sc,
			    IWM_FH_TCSR_CHNL_TX_CONFIG_REG(IWM_FH_SRVC_CHNL),
			    IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE);
			iwm_wr(sc,
			    IWM_FH_SRVC_CHNL_SRAM_ADDR_REG(IWM_FH_SRVC_CHNL),
			    offset);
			iwm_wr(sc, IWM_FH_TFDIB_CTRL0_REG(IWM_FH_SRVC_CHNL),
			    (uint32_t)addr);
			iwm_wr(sc, IWM_FH_TFDIB_CTRL1_REG(IWM_FH_SRVC_CHNL),
			    ((addr >> 32) <<
			    IWM_FH_MEM_TFDIB_REG1_ADDR_BITSHIFT) |
			    length);
			iwm_wr(sc,
			    IWM_FH_TCSR_CHNL_TX_BUF_STS_REG(IWM_FH_SRVC_CHNL),
			    1 << IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM |
			    1 << IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX |
			    IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID);
			iwm_wr(sc,
			    IWM_FH_TCSR_CHNL_TX_CONFIG_REG(IWM_FH_SRVC_CHNL),
			    IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
			    IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE |
			    IWM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD);
			iwm_nic_unlock(sc);
			error = iwm_wait(sc, &r->chunk_done);
			if (error != 0)
				return (error);
			if (iwm_nic_lock(sc) != 0)
				return (EBUSY);
			if (offset >= IWM_FW_MEM_EXTENDED_START &&
			    offset <= IWM_FW_MEM_EXTENDED_END)
				iwm_prph_bits(sc, IWM_LMPM_CHICK, 0,
				    IWM_LMPM_CHICK_EXTENDED_ADDR_SPACE);
			iwm_nic_unlock(sc);
		}
		if (iwm_nic_lock(sc) != 0)
			return (EBUSY);
		status = iwm_rd(sc, IWM_FH_UCODE_LOAD_STATUS);
		iwm_wr(sc, IWM_FH_UCODE_LOAD_STATUS,
		    status | (bits << (cpu * 16)));
		bits = (bits << 1) | 1;
		iwm_nic_unlock(sc);
		if (iwm_checkpoint(sc, r->image == IWM_FW_INIT ?
		    "INIT-section" : "REGULAR-section") != 0)
			return (EIO);
	}
	r->mask = IWM_RUN_MASK;
	iwm_wr(sc, IWM_CSR_INT_MASK, r->mask);
	dev_err(sc->dip, CE_NOTE,
	    "!iwm image=%u upload complete; ALIVE wait %u us",
	    r->image, IWM_WAIT_US);
	if ((error = iwm_wait(sc, &r->alive)) != 0)
		return (error);
	r->state = r->image == IWM_FW_INIT ?
	    IWM_INIT_ALIVE : IWM_REGULAR_ALIVE;
	if (iwm_checkpoint(sc, r->image == IWM_FW_INIT ?
	    "INIT-ALIVE" : "REGULAR-ALIVE") != 0)
		return (EIO);
	return (iwm_queues_check(sc, "after-ALIVE"));
}

static int
iwm_post_alive(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint_t q = r->cmdqid, ch;
	uint32_t base;

	if (iwm_nic_lock(sc) != 0)
		return (EBUSY);
	base = iwm_prph_read(sc, IWM_SCD_SRAM_BASE_ADDR);
	if (base != r->sched_base || base == 0 || (base & 3) != 0 ||
	    base > 0xffffffffU - IWM_SCD_TRANS_TBL_MEM_UPPER_BOUND) {
		iwm_nic_unlock(sc);
		return (EIO);
	}
	/* Keep direct CSR MSI handling; no ICT architecture change. */
	iwm_mem_zero(sc, base + IWM_SCD_CONTEXT_MEM_LOWER_BOUND,
	    IWM_SCD_TRANS_TBL_MEM_UPPER_BOUND -
	    IWM_SCD_CONTEXT_MEM_LOWER_BOUND);
	iwm_prph_write(sc, IWM_SCD_DRAM_BASE_ADDR,
	    iwm_dma_addr(&r->scheduler) >> 10);
	iwm_prph_write(sc, IWM_SCD_CHAINEXT_EN, 0);
	/* The only scheduler queue explicitly enabled is the command queue. */
	iwm_wr(sc, IWM_HBUS_TARG_WRPTR, q << 8);
	iwm_prph_write(sc, IWM_SCD_QUEUE_STATUS_BITS(q),
	    1 << IWM_SCD_QUEUE_STTS_REG_POS_SCD_ACT_EN);
	iwm_prph_bits(sc, IWM_SCD_AGGR_SEL, 0, 1U << q);
	iwm_prph_write(sc, IWM_SCD_QUEUE_RDPTR(q), 0);
	iwm_mem_zero(sc, base + IWM_SCD_CONTEXT_QUEUE_OFFSET(q), 4);
	iwm_wr(sc, IWM_HBUS_TARG_MEM_WADDR,
	    base + IWM_SCD_CONTEXT_QUEUE_OFFSET(q) + 4);
	iwm_wr(sc, IWM_HBUS_TARG_MEM_WDAT,
	    (IWM_FRAME_LIMIT << IWM_SCD_QUEUE_CTX_REG2_WIN_SIZE_POS) |
	    (IWM_FRAME_LIMIT << IWM_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS));
	iwm_prph_write(sc, IWM_SCD_QUEUE_STATUS_BITS(q),
	    (1 << IWM_SCD_QUEUE_STTS_REG_POS_ACTIVE) |
	    (IWM_TX_FIFO_CMD << IWM_SCD_QUEUE_STTS_REG_POS_TXF) |
	    (1 << IWM_SCD_QUEUE_STTS_REG_POS_WSL) | IWM_SCD_QUEUE_STTS_REG_MSK);
	iwm_prph_bits(sc, IWM_SCD_EN_CTRL, 1U << q, 0);
	iwm_prph_write(sc, IWM_SCD_TXFACT, 0xff);
	for (ch = 0; ch < IWM_FH_TCSR_CHNL_NUM; ch++)
		iwm_wr(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(ch),
		    IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
		    IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE);
	iwm_bits(sc, IWM_FH_TX_CHICKEN_BITS_REG,
	    IWM_FH_TX_CHICKEN_BITS_SCD_AUTO_RETRY_EN, 0);
	iwm_nic_unlock(sc);
	return (iwm_checkpoint(sc, "post-ALIVE"));
}

static uint16_t
iwm_u16(const uint8_t *p)
{
	return ((uint16_t)p[0] | (uint16_t)p[1] << 8);
}

static uint32_t
iwm_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] | (uint32_t)p[1] << 8 |
	    (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24);
}

/* No host country selection: the donor requests the current NVM/FW profile. */
static void
iwm_lar_command(uint8_t command[IWM_MCC_COMMAND_SIZE])
{
	bzero(command, IWM_MCC_COMMAND_SIZE);
	command[0] = command[1] = 'Z';
	command[2] = IWM_MCC_SOURCE_GET_CURRENT;
}

/* Decode API36 v3 only, after enclosing command ownership validation. */
static int
iwm_lar_parse(struct iwm_lar_state *lar, const uint8_t *p, size_t n)
{
	uint_t i;

	lar->ready = B_FALSE;
	if (n < IWM_MCC_HEADER_SIZE)
		return (EPROTO);
	lar->status = iwm_u32(p);
	lar->mcc = iwm_u16(p + 4);
	lar->cap = p[6];
	lar->source = p[7];
	lar->time = iwm_u16(p + 8);
	lar->geo = iwm_u16(p + 10);
	lar->count = iwm_u32(p + 12);
	if (lar->count > IWM_MCC_CHANNELS ||
	    lar->count > (n - IWM_MCC_HEADER_SIZE) / 4 ||
	    n != IWM_MCC_HEADER_SIZE + 4 * lar->count)
		return (EPROTO);
	if (lar->status != IWM_MCC_NEW_PROFILE &&
	    lar->status != IWM_MCC_SAME_PROFILE)
		return (EIO);
	if (lar->count == 0 || lar->changed)
		return (EACCES);
	for (i = 0; i < lar->count; i++)
		lar->channels[i] = iwm_u32(p + IWM_MCC_HEADER_SIZE + 4 * i);
	lar->ready = B_TRUE;
	return (0);
}

/*
 * Deliberately narrower than a general station regulatory policy. ACTIVE is
 * active-scan permission, not a universal station-TX bit; require it in both
 * maps for the initial controlled-BSS experiment without enabling probes.
 */
static int
iwm_lar_channel(const struct iwm_lar_state *lar, const uint16_t *nvm,
    uint_t channel)
{
	uint32_t flags, required = IWM_LAR_VALID | IWM_LAR_ACTIVE;

	if (!lar->ready || lar->changed || channel == 0 || channel > 13 ||
	    channel > lar->count)
		return (EACCES);
	flags = lar->channels[channel - 1];
	if ((flags & required) != required ||
	    (nvm[channel - 1] & required) != required ||
	    ((flags | nvm[channel - 1]) & IWM_LAR_RESTRICTED) != 0)
		return (EACCES);
	return (0);
}

static int
iwm_lar_changed(struct iwm_lar_state *lar, const uint8_t *p, size_t n,
    boolean_t regular)
{
	lar->ready = B_FALSE;
	lar->changed = B_TRUE;
	lar->error = EPROTO;
	if (regular && n == 4) {
		lar->changed_mcc = iwm_u16(p);
		lar->changed_source = p[2];
		lar->error = EIO;
	}
	return (lar->error);
}

/* Validate the complete fixed PHY DB header before using its group index. */
static int
iwm_phy_index(const uint8_t *data, size_t length, uint_t *slot,
    size_t *size)
{
	uint_t type, group;

	if (length < 4)
		return (EPROTO);
	type = iwm_u16(data);
	*size = iwm_u16(data + 2);
	if (*size == 0 || *size > length - 4)
		return (EPROTO);
	if (type == IWM_PHY_DB_CFG || type == IWM_PHY_DB_CALIB_NCH) {
		*slot = type - 1;
		return (0);
	}
	if ((type != IWM_PHY_DB_CALIB_CHG_PAPD &&
	    type != IWM_PHY_DB_CALIB_CHG_TXP) || *size < 2)
		return (EPROTO);
	group = iwm_u16(data + 4);
	if (group >= IWM_PHY_DB_GROUPS ||
	    (type == IWM_PHY_DB_CALIB_CHG_TXP && *size < 6))
		return (EPROTO);
	*slot = 2 + (type - IWM_PHY_DB_CALIB_CHG_PAPD) *
	    IWM_PHY_DB_GROUPS + group;
	return (0);
}

/* Interrupt context, sc->lock held. Replacement never loses ownership. */
static void
iwm_phy_notification(struct iwm_softc *sc, const uint8_t *data, size_t n)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_phy_entry *entry;
	uint8_t *copy;
	size_t size;
	uint_t slot;

	if (r->state != IWM_INIT_CALIBRATING || r->image != IWM_FW_INIT) {
		iwm_proto_error(sc, IWM_PROTO_INIT_STATE);
		return;
	}
	if (iwm_phy_index(data, n, &slot, &size) != 0) {
		iwm_proto_error(sc, IWM_PROTO_PHY_DB);
		return;
	}
	copy = kmem_alloc(size, KM_NOSLEEP);
	if (copy == NULL) {
		r->error = ENOMEM;
		return;
	}
	bcopy(data + 4, copy, size);
	entry = &r->phy_db[slot];
	if (entry->data != NULL)
		kmem_free(entry->data, entry->length);
	entry->data = copy;
	entry->length = size;
	r->calib_complete = B_TRUE;
	r->phy_notifications++;
	if (iwm_checkpoint(sc, "PHY-DB-record") != 0)
		r->error = EIO;
}

/* Both firmware completion and independently validated data are required. */
static boolean_t
iwm_calibration_complete(const struct iwm_runtime *r)
{
	uint_t i;
	boolean_t papd = B_FALSE, txp = B_FALSE;

	if (!r->init_complete || !r->calib_complete ||
	    r->phy_db[0].length == 0 || r->phy_db[1].length == 0)
		return (B_FALSE);
	for (i = 0; i < IWM_PHY_DB_GROUPS; i++) {
		papd |= r->phy_db[2 + i].length != 0;
		txp |= r->phy_db[2 + IWM_PHY_DB_GROUPS + i].length != 0;
	}
	return (papd && txp);
}

/* Build only the authenticated firmware's UMAC v7 / v1-tail request. */
static int
iwm_scan_request(const struct iwm_scan_state *s, const uint8_t *mac,
    uint8_t *data, size_t size)
{
	struct iwm_scan_v7 *req = (void *)data;
	struct iwm_scan_channel_cfg_umac *ch;
	struct iwm_scan_req_umac_tail_v1 *tail;
	uint8_t *probe;
	uint_t i;
	static const uint8_t rates[] =
	    { 1, 8, 2, 4, 11, 22, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108 };

	if (size != sizeof (*req) + IWM_SCAN_CHANNELS * sizeof (*ch) +
	    sizeof (*tail) || s->channels == 0 || s->channels > 14)
		return (EINVAL);
	for (i = 0; i < s->channels; i++) {
		if (s->channel[i] == 0 || s->channel[i] > 14 ||
		    (i != 0 && s->channel[i] <= s->channel[i - 1]))
			return (EINVAL);
	}
	bzero(data, size);
	req->uid = LE_32(IWM_SCAN_UID);
	req->ooc_priority = LE_32(2);
	req->general_flags = LE_16(IWM_SCAN_PASSIVE);
	req->active_dwell = 10;
	req->passive_dwell = 110;
	req->fragmented_dwell = 44;
	req->adwell_default_n_aps = 2;
	req->adwell_default_n_aps_social = 10;
	req->adwell_max_budget = LE_16(300);
	req->scan_priority = LE_32(2);
	req->channel.count = s->channels;
	ch = (void *)(data + sizeof (*req));
	for (i = 0; i < s->channels; i++) {
		ch[i].channel_num = s->channel[i];
		ch[i].iter_count = 1;
	}
	tail = (void *)(ch + IWM_SCAN_CHANNELS);
	tail->schedule[0].iter_count = 1;
	/* ABI template only: no SSID selection or active-probe permission. */
	probe = tail->preq.buf;
	probe[0] = IEEE80211_FC0_SUBTYPE_PROBE_REQ;
	memset(probe + 4, 0xff, 6);
	bcopy(mac, probe + 10, 6);
	memset(probe + 16, 0xff, 6);
	tail->preq.mac_header.len = LE_16(26);
	tail->preq.band_data[0].offset = LE_16(26);
	tail->preq.band_data[0].len = LE_16(sizeof (rates));
	bcopy(rates, probe + 26, sizeof (rates));
	return (0);
}

/*
 * Only RSN/CCMP-128/PSK is supported. Validate complete lists and optional
 * fields before passing an IE to native WPA or selecting a protected BSS.
 * The caller owns p; no bytes or references are retained.
 */
int
iwm_rsn_check(const uint8_t *p, size_t n)
{
	static const uint8_t ccmp[] = { 0, 0x0f, 0xac, 4 };
	static const uint8_t psk[] = { 0, 0x0f, 0xac, 2 };
	size_t off = 20, count;
	uint16_t caps;

	if (p == NULL || n < off || n > IEEE80211_MAX_WPA_IE ||
	    p[0] != IEEE80211_ELEMID_RSN || p[1] != n - 2 ||
	    iwm_u16(p + 2) != 1)
		return (EPROTO);
	if (bcmp(p + 4, ccmp, sizeof (ccmp)) || iwm_u16(p + 8) != 1 ||
	    bcmp(p + 10, ccmp, sizeof (ccmp)) || iwm_u16(p + 14) != 1 ||
	    bcmp(p + 16, psk, sizeof (psk)))
		return (ENOTSUP);
	if (off == n)
		return (0);
	if (n - off < 2)
		return (EPROTO);
	caps = iwm_u16(p + off);
	/* No pairwise, required PMF or required SPP A-MSDU are unsupported. */
	if (caps & ((1U << 1) | (1U << 6) | (1U << 11)))
		return (ENOTSUP);
	off += 2;
	if (off == n)
		return (0);
	if (n - off < 2)
		return (EPROTO);
	count = iwm_u16(p + off);
	off += 2;
	if (count > (n - off) / 16)
		return (EPROTO);
	off += count * 16;
	if (off == n)
		return (0);
	/* Optional BIP capability is not negotiated as PMF by this station. */
	if (n - off != 4 || !(caps & (1U << 7)) ||
	    p[off] != 0 || p[off + 1] != 0x0f ||
	    p[off + 2] != 0xac || p[off + 3] != 6)
		return (ENOTSUP);
	return (0);
}

/* Three-address data; BA ACK policy is validated separately at TX admission. */
static int
iwm_frame_header(const uint8_t *p, size_t n, size_t *header)
{
	if (n < sizeof (struct ieee80211_frame) || (p[0] & 3) != 0 ||
	    (p[1] & 0x84) != 0 || (p[1] & 3) == 3 ||
	    (iwm_u16(p + 22) & 15) != 0)
		return (EPROTO);
	*header = sizeof (struct ieee80211_frame);
	if ((p[0] & 0x0c) == IEEE80211_FC0_TYPE_DATA) {
		if (p[0] != 8 && p[0] != 0x88)
			return (ENOTSUP);
		if (p[0] == 0x88) {
			*header = sizeof (struct ieee80211_qosframe);
			if (n < *header || (p[24] & 0x98) != 0 ||
			    ((p[24] & 0x60) != 0 && (p[24] & 0x60) != 0x60) ||
			    p[25] != 0)
				return (EPROTO);
		}
	} else if ((p[0] & 0x0c) != IEEE80211_FC0_TYPE_MGT) {
		return (ENOTSUP);
	}
	return (0);
}

/* Limit native ACTION processing to a bounded incoming ADDBA request. */
static int
iwm_addba_request_check(const uint8_t *p, size_t n)
{
	if (n != 33 || p[24] != IEEE80211_ACTION_CAT_BA ||
	    p[25] != IEEE80211_ACTION_BA_ADDBA_REQUEST ||
	    ((iwm_u16(p + 27) >> 2) & 15) >= 8 ||
	    (iwm_u16(p + 31) & 15) != 0)
		return (ENOTSUP);
	return (0);
}

/* Native action handlers assume these complete, unfragmented wire bodies. */
static int
iwm_ba_action_check(const uint8_t *p, size_t n, boolean_t tx)
{
	uint_t params;

	if (n < 26 || p[24] != IEEE80211_ACTION_CAT_BA)
		return (ENOTSUP);
	switch (p[25]) {
	case IEEE80211_ACTION_BA_ADDBA_REQUEST:
		if (iwm_addba_request_check(p, n) != 0)
			return (EPROTO);
		params = iwm_u16(p + 27);
		if (tx && (((params >> 2) & 15) != 0 ||
		    (params >> 6) != IWM_TX_AGG_WINDOW ||
		    !(params & 2) || iwm_u16(p + 29) != 0))
			return (ENOTSUP);
		return (0);
	case IEEE80211_ACTION_BA_ADDBA_RESPONSE:
		if (n != 33 || ((iwm_u16(p + 29) >> 2) & 15) >= 8)
			return (EPROTO);
		/* RX sessions are never accepted in 8B1. */
		return (tx && iwm_u16(p + 27) == 0 ? ENOTSUP : 0);
	case IEEE80211_ACTION_BA_DELBA:
		if (n != 30 || (iwm_u16(p + 26) >> 12) != 0 ||
		    (iwm_u16(p + 26) & 0x7ff) != 0)
			return (EPROTO);
		return (0);
	default:
		return (ENOTSUP);
	}
}

/* One bounded native BE stream; no firmware work or new owner in callbacks. */
static int
iwm_ba_request(struct ieee80211_node *node, struct ieee80211_tx_ampdu *tap,
    int token, int params, int timeout)
{
	struct iwm_softc *sc = iwm_scan_softc(node->in_ic);
	struct iwm_runtime *r;
	struct iwm_tx_ba *ba;
	int accepted = 0;

	ASSERT(MUTEX_HELD(&sc->ic.ic_genlock));
	if (tap != &node->in_tx_ampdu[WME_AC_BE] || token < 0 ||
	    token >= 63 || timeout != 0 || (params & 0x3f) != 2 ||
	    (params >> 6) != IWM_TX_AGG_WINDOW)
		return (0);
	mutex_enter(&sc->lock);
	r = sc->run;
	if (r == NULL || r->ba_queue_used || !sc->connection.running ||
	    !sc->connection.tx_admission || sc->connection.cancel ||
	    sc->connection.node != node ||
	    !(node->in_flags & IEEE80211_NODE_HT) ||
	    !(sc->fw.capa[0] & (1U << IWM_UCODE_TLV_CAPA_DQA_SUPPORT)))
		goto out;
	ba = &r->association.ba[0];
	if (ba->state != IWM_BA_CLOSED)
		goto out;
	bzero(ba, sizeof (*ba));
	ba->state = IWM_BA_STARTING;
	ba->generation = r->association.generation;
	ba->runtime_generation = r->generation;
	ba->node = node;
	ba->ac = WME_AC_BE;
	ba->qid = IWM_TX_AGG_QUEUE;
	ba->token = token;
	ba->ssn = node->in_txseqs[0] & 0xfff;
	ba->window = IWM_TX_AGG_WINDOW;
	ba->deadline = ddi_get_lbolt() + drv_usectohz(250000);
	tap->txa_token = token;
	tap->txa_start = tap->txa_seqstart = ba->ssn;
	tap->txa_wnd = IWM_TX_AGG_WINDOW;
	tap->txa_timer = NULL;
	tap->txa_flags |= IEEE80211_AGGR_IMMEDIATE | IEEE80211_AGGR_XCHGPEND;
	tap->txa_lastrequest = ddi_get_lbolt();
	accepted = 1;
	cv_broadcast(&r->cv);
out:
	mutex_exit(&sc->lock);
	return (accepted);
}

static int
iwm_ba_response(struct ieee80211_node *node, struct ieee80211_tx_ampdu *tap,
    int status, int params, int timeout)
{
	struct iwm_softc *sc = iwm_scan_softc(node->in_ic);
	struct iwm_tx_ba *ba;
	uint_t window = params >> 6;

	ASSERT(MUTEX_HELD(&sc->ic.ic_genlock));
	mutex_enter(&sc->lock);
	if (sc->run == NULL || tap != &node->in_tx_ampdu[WME_AC_BE])
		goto out;
	ba = &sc->run->association.ba[0];
	if (ba->state != IWM_BA_STARTING || ba->accepted || ba->node != node ||
	    ba->generation != sc->run->association.generation ||
	    ba->runtime_generation != sc->run->generation ||
	    ddi_get_lbolt() >= ba->deadline)
		goto out;
	ba->responses++;
	tap->txa_flags &= ~IEEE80211_AGGR_XCHGPEND;
	/* Peer A-MSDU support does not require sending A-MSDUs. */
	if (status != 0 || (params & IEEE80211_BAPS_TID) != 0 ||
	    (params & IEEE80211_BAPS_POLICY) !=
	    IEEE80211_BAPS_POLICY_IMMEDIATE || timeout != 0 ||
	    (window != 0 && window != IWM_TX_AGG_WINDOW)) {
		ba->state = IWM_BA_CLOSED;
		tap->txa_flags |= IEEE80211_AGGR_NAK;
	} else {
		ba->accepted = B_TRUE;
		ba->deadline = ddi_get_lbolt() + drv_usectohz(IWM_WAIT_US);
	}
	cv_broadcast(&sc->run->cv);
out:
	mutex_exit(&sc->lock);
	return (1);
}

static void
iwm_ba_stop(struct ieee80211_node *node, struct ieee80211_tx_ampdu *tap)
{
	struct iwm_softc *sc = iwm_scan_softc(node->in_ic);
	struct iwm_tx_ba *ba;

	/* Native pre-RUN HT cleanup is serialized by the connection worker. */
	tap->txa_flags &= ~(IEEE80211_AGGR_RUNNING | IEEE80211_AGGR_XCHGPEND);
	tap->txa_flags |= IEEE80211_AGGR_NAK;
	tap->txa_timer = NULL;
	mutex_enter(&sc->lock);
	if (sc->run != NULL && sc->connection.node == node &&
	    tap == &node->in_tx_ampdu[WME_AC_BE]) {
		ba = &sc->run->association.ba[0];
		ba->admission = B_FALSE;
		if (ba->state == IWM_BA_ACTIVE || ba->state == IWM_BA_STARTING)
			ba->state = IWM_BA_STOPPING;
		cv_broadcast(&sc->run->cv);
	}
	mutex_exit(&sc->lock);
}

static int
iwm_ba_send_action(struct ieee80211_node *node, int category, int action,
    uint16_t args[4])
{
	struct iwm_softc *sc = iwm_scan_softc(node->in_ic);
	uint16_t copy[4];

	bcopy(args, copy, sizeof (copy));
	if (category != IEEE80211_ACTION_CAT_BA)
		return (ENOTSUP);
	if (action == IEEE80211_ACTION_BA_ADDBA_REQUEST) {
		mutex_enter(&sc->lock);
		if (sc->run == NULL || sc->connection.node != node ||
		    sc->run->association.ba[0].state != IWM_BA_STARTING) {
			mutex_exit(&sc->lock);
			return (ECANCELED);
		}
		copy[3] = sc->run->association.ba[0].ssn << 4;
		mutex_exit(&sc->lock);
	} else if (action != IEEE80211_ACTION_BA_ADDBA_RESPONSE &&
	    action != IEEE80211_ACTION_BA_DELBA) {
		return (ENOTSUP);
	}
	return (sc->connection.send_action(node, category, action, copy));
}

static void
iwm_ba_recv_action(struct ieee80211_node *node, const uint8_t *p,
    const uint8_t *end)
{
	struct iwm_softc *sc = iwm_scan_softc(node->in_ic);
	boolean_t valid;

	/* Native recv_mgmt owns genlock throughout ACTION dispatch. */
	ASSERT(MUTEX_HELD(&sc->ic.ic_genlock));
	/* Full management-frame bounds were checked before native input. */
	if (end < p || end - p < 2 || p[0] != IEEE80211_ACTION_CAT_BA)
		return;
	mutex_enter(&sc->lock);
	valid = sc->run != NULL && sc->connection.running &&
	    !sc->connection.cancel && sc->connection.node == node;
	if (valid && p[1] == IEEE80211_ACTION_BA_ADDBA_RESPONSE) {
		struct iwm_tx_ba *ba = &sc->run->association.ba[0];

		valid = end - p == 9 && ((iwm_u16(p + 5) >> 2) & 15) == 0 &&
		    ba->state == IWM_BA_STARTING && !ba->accepted &&
		    ba->node == node && ba->token == p[2] &&
		    ba->generation == sc->run->association.generation &&
		    ba->runtime_generation == sc->run->generation &&
		    ddi_get_lbolt() < ba->deadline;
	} else if (valid && p[1] == IEEE80211_ACTION_BA_DELBA) {
		valid = end - p == 6 && (iwm_u16(p + 2) >> 12) == 0;
	} else if (p[1] != IEEE80211_ACTION_BA_ADDBA_REQUEST) {
		valid = B_FALSE;
	}
	mutex_exit(&sc->lock);
	if (valid)
		sc->connection.recv_action(node, p, end);
}

/* Logical rate policy is separate from this bounded firmware encoding. */
static int
iwm_tx_rate_encode(boolean_t ht, uint_t rate, uint8_t antenna,
    uint32_t *encoded)
{
	static const uint8_t rates[] =
	    { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };
	static const uint8_t plcp[] =
	    { 10, 20, 55, 110, 0x0d, 0x0f, 0x05, 0x07,
	    0x09, 0x0b, 0x01, 0x03 };
	uint_t i;

	if (antenna == 0 || antenna > 7 || (antenna & (antenna - 1)))
		return (EINVAL);
	if (ht) {
		if (rate > 7)
			return (ENOTSUP);
		*encoded = IWM_RATE_MCS_HT_MSK | rate;
	} else {
		for (i = 0; i < sizeof (rates); i++) {
			if (rates[i] == rate)
				break;
		}
		if (i == sizeof (rates))
			return (ENOTSUP);
		*encoded = plcp[i] | (i < 4 ? IWM_RATE_MCS_CCK_MSK : 0);
	}
	*encoded |= (uint32_t)antenna << IWM_RATE_MCS_ANT_POS;
	return (0);
}

/* Observe actual PHY metadata; never infer an RX MCS from the TX policy. */
static int
iwm_rx_rate_check(const struct iwm_rx_phy_info *phy, boolean_t ht,
    uint8_t rx_ant, uint32_t *rate)
{
	uint32_t value = LE_32(phy->rate_n_flags);
	uint16_t flags = LE_16(phy->phy_flags);
	uint32_t antenna = (value & IWM_RATE_MCS_ANT_MSK) >>
	    IWM_RATE_MCS_ANT_POS;

	if ((flags & (IWM_RX_RES_PHY_FLAGS_AGG |
	    IWM_RX_RES_PHY_FLAGS_OFDM_GF | IWM_RX_RES_PHY_FLAGS_OFDM_VHT)) ||
	    (value & IWM_RATE_MCS_VHT_MSK))
		return (ENOTSUP);
	/* API36 rate_n_flags describes HT even without PHY OFDM_HT. */
	if ((value & IWM_RATE_MCS_HT_MSK) && (!ht || (value & 0xff) > 7 ||
	    antenna == 0 || (antenna & rx_ant) == 0 ||
	    (antenna & ~rx_ant) != 0 ||
	    (value & (IWM_RATE_MCS_CCK_MSK | IWM_RATE_MCS_CHAN_WIDTH_MSK |
	    IWM_RATE_MCS_SGI_MSK | IWM_RATE_MCS_STBC_MSK))))
		return (ENOTSUP);
	*rate = value;
	return (0);
}

/* Complete TLVs and native parser field minima, before ieee80211_input. */
static int
iwm_scan_frame_check(const uint8_t *p, size_t n, uint_t channel)
{
	size_t off = 36, len;
	uint_t id;
	boolean_t ssid = B_FALSE, rates = B_FALSE;

	if (n < 24)
		return (EPROTO);
	if ((p[0] & 0x0f) != 0 || (p[0] != 0x80 && p[0] != 0x50))
		return (ENOTSUP);
	if (n < off || (p[1] & 0xc7) != 0 || (iwm_u16(p + 22) & 15) != 0 ||
	    (p[10] & 1) != 0 || (p[16] & 1) != 0)
		return (EPROTO);
	while (off < n) {
		if (n - off < 2)
			return (EPROTO);
		id = p[off];
		len = p[off + 1];
		if (len > n - off - 2)
			return (EPROTO);
		if (id == 0) {
			if (ssid || len > 32)
				return (EPROTO);
			ssid = B_TRUE;
		} else if (id == 1) {
			if (rates || len == 0 || len > 8)
				return (EPROTO);
			rates = B_TRUE;
		} else if (id == 3) {
			if (len != 1)
				return (EPROTO);
			if (p[off + 2] != channel)
				return (EXDEV);
		} else if ((id == 45 && len != 26) ||
		    (id == 61 && len != 22) || (id == 5 && len < 4) ||
		    (id == 221 && len < 4)) {
			return (EPROTO);
		}
		off += len + 2;
	}
	return (ssid && rates ? 0 : EPROTO);
}

/*
 * CONNECT owns the public operation and no RX delivery is active. The native
 * lookup returns a referenced node, transferred to the caller only on success.
 * Never select a substitute for an absent or incompatible pinned BSSID.
 */
int
iwm_select_bss(struct iwm_softc *sc, const uint8_t *essid, size_t length,
    uint_t requested_channel, ieee80211_node_t **result)
{
	ieee80211_node_t *node;
	uint_t channel, i, j;
	boolean_t basic = B_FALSE;
	int error = EINVAL;
	static const uint8_t rates[] =
	    { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };

	*result = NULL;
	ASSERT(sc->operation == IWM_OP_CONNECT);
	if (!sc->net_attached || !sc->identity.valid ||
	    !sc->desired_bssid_valid || essid == NULL || length == 0 ||
	    length > IEEE80211_NWID_LEN || requested_channel > 13 ||
	    sc->ic.ic_state != IEEE80211_S_INIT)
		return (EINVAL);
	node = ieee80211_find_node(&sc->ic.ic_scan, sc->desired_bssid);
	if (node == NULL)
		return (ENOENT);
	if (bcmp(node->in_bssid, sc->desired_bssid, IEEE80211_ADDR_LEN) ||
	    bcmp(node->in_macaddr, sc->desired_bssid, IEEE80211_ADDR_LEN) ||
	    node->in_esslen != length ||
	    bcmp(node->in_essid, essid, length))
		goto out;
	error = ENOTSUP;
	if ((node->in_capinfo & (IEEE80211_CAPINFO_ESS |
	    IEEE80211_CAPINFO_IBSS)) != IEEE80211_CAPINFO_ESS ||
	    node->in_intval == 0)
		goto out;
	if (sc->connection.wpa) {
		if (!(node->in_capinfo & IEEE80211_CAPINFO_PRIVACY) ||
		    node->in_wpa_ie == NULL || iwm_rsn_check(node->in_wpa_ie,
		    node->in_wpa_ie[1] + 2) != 0)
			goto out;
	} else if ((node->in_capinfo & IEEE80211_CAPINFO_PRIVACY) ||
	    node->in_wpa_ie != NULL) {
		goto out;
	}
	for (channel = 1; channel <= 13; channel++) {
		if (node->in_chan == &sc->ic.ic_sup_channels[channel])
			break;
	}
	if (channel > 13 || !(sc->identity.channels[channel - 1] & 1) ||
	    (requested_channel != 0 && requested_channel != channel))
		goto out;
	/* A full native array may have truncated a required membership rate. */
	if (node->in_rates.ir_nrates == 0 || node->in_rates.ir_nrates >=
	    sizeof (node->in_rates.ir_rates))
		goto out;
	for (i = 0; i < node->in_rates.ir_nrates; i++) {
		uint8_t rate = node->in_rates.ir_rates[i];

		for (j = 0; j < sizeof (rates); j++) {
			if ((rate & IEEE80211_RATE_VAL) == rates[j])
				break;
		}
		/* Native negotiation discards unsupported optional rates. */
		if ((rate & IEEE80211_RATE_VAL) == 0 ||
		    (rate & IEEE80211_RATE_VAL) >= 126 ||
		    (j == sizeof (rates) && (rate & IEEE80211_RATE_BASIC)))
			goto out;
		basic |= (rate & IEEE80211_RATE_BASIC) != 0;
	}
	if (!basic)
		goto out;
	*result = node;
	return (0);
out:
	ieee80211_free_node(node);
	return (error);
}

static struct iwm_softc *
iwm_scan_softc(ieee80211com_t *ic)
{
	return ((struct iwm_softc *)((char *)ic -
	    offsetof(struct iwm_softc, ic)));
}

/* Native parameters are stable under ic_genlock, or before public attach. */
static int
iwm_wme_encode(const struct ieee80211_wme_state *native,
    struct iwm_ac_qos *ac)
{
	static const uint8_t fifo[] = { 1, 0, 2, 3 };
	uint_t i;

	bzero(ac, 4 * sizeof (*ac));
	for (i = 0; i < 4; i++) {
		const struct wmeParams *p =
		    &native->wme_chanParams.cap_wmeParams[i];
		struct iwm_ac_qos *q = &ac[fifo[i]];
		uint_t txop = p->wmep_txopLimit;

		if (p->wmep_aifsn > 15 || p->wmep_logcwmin > 15 ||
		    p->wmep_logcwmax > 15 ||
		    p->wmep_logcwmin > p->wmep_logcwmax ||
		    txop > UINT16_MAX / 32)
			return (EINVAL);
		q->cw_min = LE_16((1U << p->wmep_logcwmin) - 1);
		q->cw_max = LE_16((1U << p->wmep_logcwmax) - 1);
		q->aifsn = p->wmep_aifsn;
		q->fifos_mask = 1U << fifo[i];
		q->edca_txop = LE_16(txop * 32);
	}
	return (0);
}

/* No queued task or retained native pointer survives an association epoch. */
static void
iwm_wme_reset(struct iwm_softc *sc, boolean_t accepting)
{
	struct iwm_wme_state *w = &sc->connection.wme;
	uint64_t epoch = w->epoch + 1;

	ASSERT(MUTEX_HELD(&sc->lock));
	bzero(w, sizeof (*w));
	w->epoch = epoch;
	w->accepting = accepting;
}

/*
 * Native join/input holds ic_genlock; attach is not yet publicly reachable.
 * Lock order is ic_genlock -> sc->lock. Never wait for firmware here.
 */
static int
iwm_wme_update(ieee80211com_t *ic)
{
	struct iwm_softc *sc = iwm_scan_softc(ic);
	struct iwm_connection *c = &sc->connection;
	struct iwm_wme_state *w = &c->wme;
	struct iwm_ac_qos ac[4];
	int error;

	error = iwm_wme_encode(&ic->ic_wme, ac);
	mutex_enter(&sc->lock);
	if (!w->accepting || c->cancel ||
	    (c->pending && ic->ic_bss != c->node)) {
		mutex_exit(&sc->lock);
		return (ECANCELED);
	}
	if (error == 0 && (!w->valid || bcmp(ac, w->ac,
	    sizeof (ac)) != 0)) {
		if (w->requested == UINT64_MAX) {
			error = EOVERFLOW;
		} else {
			bcopy(ac, w->ac, sizeof (ac));
			w->requested++;
			w->valid = B_TRUE;
		}
	}
	/* Native ignores this return value; the worker must see errors. */
	if (error != 0) {
		if (w->error == 0)
			w->error = error;
		if (c->pending && c->error == 0)
			c->error = error;
	}
	if (c->pending && sc->run != NULL)
		cv_broadcast(&sc->run->cv);
	mutex_exit(&sc->lock);
	return (error);
}

static int iwm_association_tx(struct iwm_softc *, mblk_t *, boolean_t,
    boolean_t);
static int iwm_connection_state(struct iwm_softc *, enum ieee80211_state,
    int);
static int iwm_connection_rollback(struct iwm_softc *);

static int
iwm_scan_xmit(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct iwm_softc *sc = iwm_scan_softc(ic);
	int error;

	if (sc->connection.pending && type == IEEE80211_FC0_TYPE_MGT) {
		error = iwm_association_tx(sc, mp, B_TRUE, B_FALSE);
		if (error != 0) {
			freemsg(mp);
			mutex_enter(&sc->lock);
			if (sc->connection.tx_admission &&
			    sc->connection.error == 0)
				sc->connection.error = error;
			mutex_exit(&sc->lock);
		}
		return (error);
	}
	freemsg(mp);
	mutex_enter(&sc->lock);
	sc->xmit_rejected++;
	if (sc->run != NULL) {
		sc->run->scan.xmit_calls++;
		sc->run->error = EACCES;
		cv_broadcast(&sc->run->cv);
	}
	mutex_exit(&sc->lock);
	return (ENOTSUP);
}

static int
iwm_scan_newstate(ieee80211com_t *ic, enum ieee80211_state state, int arg)
{
	struct iwm_softc *sc = iwm_scan_softc(ic);
	boolean_t allowed;

	if (sc->connection.pending)
		return (iwm_connection_state(sc, state, arg));
	mutex_enter(&sc->lock);
	allowed = state == IEEE80211_S_INIT ||
	    (state == IEEE80211_S_SCAN && ic->ic_state == IEEE80211_S_INIT &&
	    sc->run != NULL && sc->run->scan.running &&
	    !sc->run->scan.cancelled);
	if (!allowed) {
		sc->state_rejected++;
		if (sc->run != NULL) {
			sc->run->scan.state_violations++;
			sc->run->error = EACCES;
			cv_broadcast(&sc->run->cv);
		}
	}
	mutex_exit(&sc->lock);
	if (!allowed)
		return (ENOTSUP);
	mutex_enter(&ic->ic_genlock);
	ic->ic_state = state;
	mutex_exit(&ic->ic_genlock);
	return (0);
}

/* Called in thread context without sc->lock; NVM is already validated. */
int
iwm_scan_attach(struct iwm_softc *sc)
{
	ieee80211com_t *ic = &sc->ic;
	uint_t i, count = 0;
	boolean_t ht;
	int error;
	static const struct ieee80211_htrateset mcs =
	    { 8, { 0, 1, 2, 3, 4, 5, 6, 7 } };
	static const struct ieee80211_rateset rates_b =
	    { 4, { 2, 4, 11, 22 } };
	static const struct ieee80211_rateset rates_g =
	    { 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

	if (sc->net_attached || !sc->identity.valid ||
	    !sc->identity.tx_ant || !sc->identity.rx_ant ||
	    !(sc->identity.sku & 1) ||
	    sc->fw.scan_channels != IWM_SCAN_CHANNELS ||
	    !(sc->fw.capa[0] & (1U << 2)) || !(sc->fw.api[1] & 1) ||
	    (sc->fw.api[1] & ((1U << 10) | (1U << 26))))
		return (ENOTSUP);
	bzero(ic, sizeof (*ic));
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_state = IEEE80211_S_INIT;
	ic->ic_curmode = IEEE80211_MODE_11G;
	ic->ic_maxrssi = 100;
	ic->ic_xmit = iwm_scan_xmit;
	/* AES-CCM hardware capability stays absent: native software crypto. */
	if (sc->public_enabled)
		ic->ic_caps = IEEE80211_C_WPA2;
	ht = sc->public_enabled &&
	    (sc->identity.sku & IWM_NVM_SKU_CAP_11N_ENABLE) != 0;
	if (ht) {
		mutex_enter(&sc->lock);
		iwm_wme_reset(sc, B_TRUE);
		mutex_exit(&sc->lock);
		ic->ic_wme.wme_update = iwm_wme_update;
		ic->ic_caps |= IEEE80211_C_WME;
		/* Static SMPS: one stream, long GI, no width40 or STBC. */
		ic->ic_htcaps = IEEE80211_HTC_HT;
	}
	bcopy(sc->identity.mac, ic->ic_macaddr, sizeof (ic->ic_macaddr));
	ic->ic_sup_rates[IEEE80211_MODE_11B] = rates_b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = rates_g;
	for (i = 0; i < 13; i++) {
		if (!(sc->identity.channels[i] & 1))
			continue;
		count++;
		ic->ic_sup_channels[i + 1].ich_freq =
		    ieee80211_ieee2mhz(i + 1, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i + 1].ich_flags = IEEE80211_CHAN_CCK |
		    IEEE80211_CHAN_OFDM | IEEE80211_CHAN_DYN |
		    IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_PASSIVE;
		if (ht)
			ic->ic_sup_channels[i + 1].ich_flags |=
			    IEEE80211_CHAN_HT20;
	}
	if (count == 0)
		return (ENOENT);
	if (ht) {
		error = ieee80211_attach_mcs(ic, &mcs);
		if (error != 0)
			return (error);
		/* HT's mandatory AMPDU field is not an aggregation opt-out. */
		ic->ic_flags_ext &= ~(IEEE80211_FEXT_HTCOMPAT |
		    IEEE80211_FEXT_AMPDU_RX | IEEE80211_FEXT_AMPDU_TX |
		    IEEE80211_FEXT_AMSDU_RX | IEEE80211_FEXT_AMSDU_TX);
	} else {
		ieee80211_attach(ic);
	}
	if (ht && (sc->fw.capa[0] &
	    (1U << IWM_UCODE_TLV_CAPA_DQA_SUPPORT))) {
		ic->ic_htcaps |= IEEE80211_HTC_AMPDU;
		ic->ic_flags_ext |= IEEE80211_FEXT_AMPDU_TX;
		sc->connection.recv_action = ic->ic_recv_action;
		sc->connection.send_action = ic->ic_send_action;
		ic->ic_recv_action = iwm_ba_recv_action;
		ic->ic_send_action = iwm_ba_send_action;
		ic->ic_addba_request = iwm_ba_request;
		ic->ic_addba_response = iwm_ba_response;
		ic->ic_addba_stop = iwm_ba_stop;
	}
	if (sc->public_enabled)
		ieee80211_register_door(ic, "iwm", ddi_get_instance(sc->dip));
	sc->connection.newstate = ic->ic_newstate;
	sc->net_attached = B_TRUE;
	if (sc->run != NULL)
		sc->run->scan.attached = B_TRUE;
	ic->ic_newstate = iwm_scan_newstate;
	ieee80211_media_init(ic);
	return (iwm_checkpoint(sc, "net80211-attached"));
}

/* Driver lock held; the sole delivery thread also owns scan teardown. */
static void
iwm_scan_drain(struct iwm_softc *sc)
{
	struct iwm_scan_state *s = &sc->run->scan;
	uint_t i;

	s->accepting = B_FALSE;
	ASSERT(!s->delivering);
	for (i = 0; i < IWM_SCAN_RX_LIMIT; i++) {
		if (s->frames[i].mp != NULL) {
			freemsg(s->frames[i].mp);
			s->frames[i].mp = NULL;
		}
	}
	s->queued = 0;
	s->head = s->tail = 0;
}

/* Same thread as native input; no callback can survive this boundary. */
int
iwm_scan_detach(struct iwm_softc *sc)
{
	if (!sc->net_attached)
		return (0);
	mutex_enter(&sc->lock);
	iwm_wme_reset(sc, B_FALSE);
	if (sc->run != NULL) {
		ASSERT(!sc->run->scan.outstanding || sc->run->stopped);
		iwm_scan_drain(sc);
		sc->run->scan.attached = B_FALSE;
	}
	mutex_exit(&sc->lock);
	ieee80211_cancel_scan(&sc->ic);
	sc->ic.ic_flags &= ~IEEE80211_F_SCANONLY;
	(void) iwm_scan_newstate(&sc->ic, IEEE80211_S_INIT, 0);
	ieee80211_detach(&sc->ic);
	sc->net_attached = B_FALSE;
	return (iwm_checkpoint(sc, "net80211-detached"));
}

/* MSI context, validated enclosing packet, driver lock held. */
static void
iwm_scan_rx(struct iwm_softc *sc, uint_t code, const uint8_t *p, size_t n)
{
	struct iwm_scan_state *s = &sc->run->scan;
	struct iwm_scan_frame *f;
	uint_t channel, i, energy;
	uint32_t status, signals;
	size_t size;
	int error, dbm = -256, rssi;
	boolean_t allowed = B_FALSE;

	if (sc->run->image != IWM_FW_REGULAR ||
	    !s->accepting || !s->running || !s->submitted ||
	    s->complete || s->cancelled) {
		s->dropped++;
		return;
	}
	if (code == 0xc0) {
		s->phy_valid = B_FALSE;
		if (n < sizeof (s->phy) || p[0] < 8 ||
		    p[0] > sizeof (s->phy.non_cfg_phy) || p[1] > 20) {
			s->malformed++;
			return;
		}
		bcopy(p, &s->phy, sizeof (s->phy));
		s->phy_valid = B_TRUE;
		return;
	}
	if (!s->phy_valid || n < 8) {
		s->malformed++;
		return;
	}
	size = iwm_u16(p);
	if (size > n - 8) {
		s->malformed++;
		return;
	}
	status = iwm_u32(p + 4 + size);
	channel = LE_16(s->phy.channel);
	for (i = 0; i < s->channels; i++)
		allowed |= s->channel[i] == channel;
	if ((status & 3) != 3 || !allowed ||
	    !(LE_16(s->phy.phy_flags) & 1)) {
		s->malformed++;
		return;
	}
	error = iwm_scan_frame_check(p + 4, size, channel);
	if (error != 0) {
		if (error == EXDEV)
			s->channel_mismatch++;
		else if (error == ENOTSUP)
			s->dropped++;
		else
			s->malformed++;
		return;
	}
	if (s->queued == IWM_SCAN_RX_LIMIT ||
	    s->accepted + s->queued >= 256) {
		s->overflow++;
		return;
	}
	f = &s->frames[s->tail];
	f->mp = allocb(size, BPRI_MED);
	if (f->mp == NULL) {
		s->overflow++;
		return;
	}
	signals = LE_32(s->phy.non_cfg_phy[1]);
	for (i = 0; i < 3; i++) {
		energy = (signals >> (8 * i)) & 255;
		if (energy && -(int)energy > dbm)
			dbm = -(int)energy;
	}
	rssi = (100 * 75 * 75 - (-20 - dbm) *
	    (15 * 75 + 62 * (-20 - dbm))) / (75 * 75);
	f->rssi = MAX(1, MIN(100, rssi));
	f->channel = channel;
	f->timestamp = LE_32(s->phy.system_timestamp);
	bcopy(p + 4, f->mp->b_wptr, size);
	f->mp->b_wptr += size;
	s->tail = (s->tail + 1) % IWM_SCAN_RX_LIMIT;
	s->queued++;
	/* Retain the queued copy on failure for thread-context teardown. */
	if (s->accepted == 0 && s->queued == 1 &&
	    (error = iwm_checkpoint(sc, "scan-frame-queued")) != 0) {
		s->error = error;
		s->accepting = B_FALSE;
	}
	cv_broadcast(&sc->run->cv);
}

static void
iwm_scan_completion(struct iwm_softc *sc, const uint8_t *p, size_t n)
{
	struct iwm_scan_state *s = &sc->run->scan;

	if (sc->run->image != IWM_FW_REGULAR ||
	    sc->run->state != IWM_REGULAR_IDLE ||
	    !s->running || !s->submitted || s->complete || s->cancelled ||
	    n != 16 ||
	    iwm_u32(p) != s->uid || p[4] != 0 || p[5] > 1) {
		sc->run->error = EPROTO;
		return;
	}
	s->terminal_uid = iwm_u32(p);
	s->completion_status = p[6];
	s->completion_iteration = p[5];
	s->complete = B_TRUE;
	s->outstanding = B_FALSE;
	s->accepting = B_FALSE;
	/* Result policy belongs to the waiter, not the command transport. */
	cv_broadcast(&sc->run->cv);
}

/* Record the UID in the RX batch before a following START can be consumed. */
static int
iwm_time_event_response(struct iwm_time_event_state *t, const uint8_t *p,
    size_t n)
{
	if (t->removing) {
		if (n == sizeof (struct iwm_time_event_resp)) {
			t->remove_status = iwm_u32(p);
			t->remove_id = iwm_u32(p + 4);
			t->remove_id_color = iwm_u32(p + 12);
		}
		if (!t->accepted || t->removed ||
		    n != sizeof (struct iwm_time_event_resp) ||
		    iwm_u32(p) != 0 ||
		    iwm_u32(p + 8) != t->uid)
			return (t->error = EPROTO);
		/* REMOVE id/context are diagnostic; correlate only the UID. */
		t->removed = B_TRUE;
		t->removing = B_FALSE;
		t->active = B_FALSE;
		return (0);
	}
	if (!t->submitted || t->responded ||
	    n != sizeof (struct iwm_time_event_resp))
		return (t->error = EPROTO);
	t->responded = B_TRUE;
	t->response_status = iwm_u32(p);
	if (iwm_u32(p + 8) == 0 || iwm_u32(p + 8) == UINT32_MAX ||
	    iwm_u32(p + 4) != IWM_TE_BSS_STA_AGGRESSIVE_ASSOC ||
	    iwm_u32(p + 12) != t->id_color)
		return (t->error = EPROTO);
	/* Legacy command acceptance is distinct from notification success. */
	if (t->response_status != 0)
		return (t->error = EIO);
	t->uid = iwm_u32(p + 8);
	t->accepted = B_TRUE;
	t->active = B_TRUE;
	return (0);
}

static int
iwm_time_event_notification(struct iwm_time_event_state *t,
    const uint8_t *p, size_t n, boolean_t regular)
{
	if (n != sizeof (struct iwm_time_event_notif))
		return (t->error = EPROTO);
	/* A retired event cannot affect work in another firmware generation. */
	if (!regular && (t->removed || t->ended))
		return (0);
	if (!regular || !t->submitted || !t->accepted)
		return (t->error = EPROTO);
	t->timestamp = iwm_u32(p);
	t->session = iwm_u32(p + 4);
	t->notification_action = iwm_u32(p + 16);
	t->notification_status = iwm_u32(p + 20);
	if (iwm_u32(p + 8) != t->uid ||
	    iwm_u32(p + 12) != t->id_color)
		return (t->error = EPROTO);
	if (t->notification_action == IWM_TE_HOST_START) {
		if (t->started || t->ended || t->removed || t->removing ||
		    t->error != 0)
			return (t->error = EPROTO);
		if (t->notification_status != 1)
			return (t->error = EIO);
		t->started = B_TRUE;
	} else if (t->notification_action == IWM_TE_HOST_END) {
		t->ended = B_TRUE;
		t->active = B_FALSE;
		if (!t->removed && (!t->started ||
		    t->notification_status != 1))
			return (t->error = EIO);
	} else {
		return (t->error = EPROTO);
	}
	return (0);
}

/* A firmware SSN retires a prefix, not each independently ACKed bitmap bit. */
static int
iwm_ba_advance(struct iwm_softc *sc, uint_t ssn, boolean_t commit)
{
	struct iwm_association *a = &sc->run->association;
	struct iwm_tx_ba *ba = &a->ba[0];
	struct iwm_tx_ring *ring = &a->tx[4];
	uint_t i, count;

	if (ssn >= IEEE80211_SEQ_RANGE ||
	    IEEE80211_SEQ_BA_BEFORE(ssn, ba->ssn))
		return (ESTALE);
	if (IEEE80211_SEQ_SUB(ssn, ba->ssn) > ba->window)
		return (EPROTO);
	if (ring->queued == 0)
		return (ssn == ba->ssn ? 0 : EPROTO);
	count = IEEE80211_SEQ_SUB(ssn, ring->data[ring->tail].sequence);
	if (count > ring->queued || count > IWM_TX_AGG_WINDOW)
		return (EPROTO);
	for (i = 0; i < count; i++) {
		struct iwm_tx_data *slot = &ring->data[(ring->tail + i) & 0xff];

		if (!slot->owned || slot->generation != sc->run->generation ||
		    slot->ba_generation != ba->generation ||
		    slot->sequence != IEEE80211_SEQ_ADD(
		    ring->data[ring->tail].sequence, i))
			return (EPROTO);
	}
	if (commit) {
		for (i = 0; i < count; i++)
			ring->data[(ring->tail + i) & 0xff].completed = B_TRUE;
		ba->ssn = ssn;
		cv_broadcast(&sc->run->cv);
	}
	return (0);
}

static boolean_t
iwm_ba_owned(struct iwm_softc *sc)
{
	struct iwm_association *a = &sc->run->association;
	struct iwm_tx_ba *ba = &a->ba[0];

	return (a->tx[4].configured && ba->node == sc->connection.node &&
	    ba->generation == a->generation &&
	    ba->runtime_generation == sc->run->generation &&
	    (ba->state == IWM_BA_ACTIVE || ba->state == IWM_BA_STOPPING ||
	    ba->state == IWM_BA_DRAINING));
}

/* Validate the whole API3 response before recording any member ownership. */
static int
iwm_ba_tx_done(struct iwm_softc *sc, uint_t idx, const uint8_t *p, size_t n)
{
	struct iwm_tx_ring *ring = &sc->run->association.tx[4];
	struct iwm_tx_ba *ba = &sc->run->association.ba[0];
	uint_t count, i, j, member, ssn;
	int error;

	if (!iwm_ba_owned(sc))
		return (ESTALE);
	if (n < 44 || (count = p[0]) == 0 || count > IWM_TX_AGG_WINDOW ||
	    n != 40 + count * 4 || p[33] != 0 || idx >= IWM_TX_RING_COUNT)
		return (EPROTO);
	ssn = iwm_u32(p + 36 + count * 4) & 0xfff;
	if ((error = iwm_ba_advance(sc, ssn, B_FALSE)) != 0)
		return (error);
	if (count == 1) {
		if (!ring->data[idx].owned ||
		    ring->data[idx].sequence != (iwm_u16(p + 28) >> 4) ||
		    ring->data[idx].ba_generation != ba->generation)
			return (ESTALE);
		if ((error = iwm_ba_advance(sc, ssn, B_FALSE)) != 0)
			return (error);
		ring->data[idx].status = iwm_u32(p + 36);
		ring->data[idx].transmitted = B_TRUE;
		return (iwm_ba_advance(sc, ssn, B_TRUE));
	}
	for (i = 0; i < count; i++) {
		member = p[36 + i * 4 + 2];
		for (j = 0; j < i; j++) {
			if (p[36 + j * 4 + 2] == member)
				return (EPROTO);
		}
		if (p[36 + i * 4 + 3] != IWM_TX_AGG_QUEUE ||
		    !ring->data[member].owned ||
		    ring->data[member].generation != sc->run->generation ||
		    IEEE80211_SEQ_SUB(ring->data[member].sequence,
		    ba->ssn) >= ba->window ||
		    ring->data[member].ba_generation != ba->generation)
			return (EPROTO);
	}
	for (i = 0; i < count; i++) {
		member = p[36 + i * 4 + 2];
		ring->data[member].status = iwm_u16(p + 36 + i * 4);
		ring->data[member].transmitted =
		    (ring->data[member].status & 0xfff) == 0;
	}
	return (0);
}

/* No pointer from this notification is retained after the interrupt returns. */
static int
iwm_ba_notification(struct iwm_softc *sc, const uint8_t *p, size_t n)
{
	struct iwm_tx_ba *ba = &sc->run->association.ba[0];
	struct iwm_tx_ring *ring = &sc->run->association.tx[4];
	uint64_t bitmap;
	uint_t base, ssn, bit, sequence, idx;
	int error;

	if (!iwm_ba_owned(sc))
		return (ESTALE);
	if (n != sizeof (struct iwm_ba_notif) || p[8] != 0 || p[9] != 0 ||
	    iwm_u16(p + 20) != IWM_TX_AGG_QUEUE ||
	    (iwm_u16(p + 10) & 15) != 0 ||
	    p[24] > IWM_TX_AGG_WINDOW || p[25] > p[24] ||
	    bcmp(p, ba->node->in_bssid, 6))
		return (EPROTO);
	base = iwm_u16(p + 10) >> 4;
	ssn = iwm_u16(p + 22);
	if ((error = iwm_ba_advance(sc, ssn, B_FALSE)) != 0)
		return (error);
	if (IEEE80211_SEQ_SUB(base, ba->ssn) >= ba->window &&
	    IEEE80211_SEQ_SUB(ba->ssn, base) > ba->window)
		return (EPROTO);
	bitmap = iwm_u32(p + 12) | (uint64_t)iwm_u32(p + 16) << 32;
	for (bit = 0; bit < IWM_TX_AGG_WINDOW; bit++) {
		if (!(bitmap & (1ULL << bit)))
			continue;
		sequence = IEEE80211_SEQ_ADD(base, bit);
		/* The AP bitmap may also cover frames outside our queue. */
		if (IEEE80211_SEQ_BA_BEFORE(sequence, ba->ssn) ||
		    IEEE80211_SEQ_SUB(sequence, ba->ssn) >=
		    IEEE80211_SEQ_SUB(ba->next_sequence, ba->ssn))
			continue;
		idx = sequence & 0xff;
		if (IEEE80211_SEQ_SUB(sequence, ba->ssn) >= ba->window ||
		    !ring->data[idx].owned ||
		    ring->data[idx].sequence != sequence ||
		    ring->data[idx].generation != sc->run->generation ||
		    ring->data[idx].ba_generation != ba->generation)
			return (EPROTO);
	}
	/* Validate all identities and slots before recording sparse ACKs. */
	for (bit = 0; bit < IWM_TX_AGG_WINDOW; bit++) {
		sequence = IEEE80211_SEQ_ADD(base, bit);
		if ((bitmap & (1ULL << bit)) &&
		    !IEEE80211_SEQ_BA_BEFORE(sequence, ba->ssn) &&
		    IEEE80211_SEQ_SUB(sequence, ba->ssn) <
		    IEEE80211_SEQ_SUB(ba->next_sequence, ba->ssn))
			ring->data[sequence & 0xff].acknowledged = B_TRUE;
	}
	ba->notifications++;
	return (iwm_ba_advance(sc, ssn, B_TRUE));
}

/* Firmware completion only marks slots; thread context releases native refs. */
static int
iwm_association_tx_done(struct iwm_softc *sc, uint_t qid, uint_t idx,
    const uint8_t *p, size_t n)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_tx_ring *ring;
	uint_t count, i, next;

	if (qid == IWM_TX_AGG_QUEUE)
		return (iwm_ba_tx_done(sc, idx, p, n));
	if (r->image != IWM_FW_REGULAR || r->state != IWM_REGULAR_IDLE ||
	    qid < 5 || qid > 8 || idx >= IWM_TX_RING_COUNT ||
	    n != 44 || p[0] != 1 || (p[33] >> 4) != 0)
		return (EPROTO);
	ring = &r->association.tx[qid - 5];
	if (!(r->association.queues & (1U << qid)) ||
	    !ring->data[idx].owned || ring->data[idx].completed ||
	    ring->data[idx].generation != r->generation)
		return (EPROTO);
	next = iwm_u32(p + 40) & 0xff;
	count = (next - ring->tail) & 0xff;
	if (count == 0 || count > ring->queued ||
	    ((idx - ring->tail) & 0xff) >= count)
		return (EPROTO);
	for (i = 0; i < count; i++) {
		struct iwm_tx_data *slot =
		    &ring->data[(ring->tail + i) & 0xff];

		if (!slot->owned || slot->generation != r->generation)
			return (EPROTO);
	}
	ring->data[idx].status = iwm_u32(p + 36);
	for (i = 0; i < count; i++)
		ring->data[(ring->tail + i) & 0xff].completed = B_TRUE;
	cv_broadcast(&r->cv);
	return (0);
}

/* Native management parsers require complete, legacy-compatible IEs. */
static int
iwm_association_ies(const uint8_t *p, size_t n, size_t off, boolean_t wpa)
{
	size_t len;
	uint_t nrates = 0;
	boolean_t rates = B_FALSE;
	static const uint8_t legacy[] =
	    { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };

	for (; off < n; off += len + 2) {
		uint_t i, j;

		if (n - off < 2 || (len = p[off + 1]) > n - off - 2)
			return (EPROTO);
		if (p[off] == 1 || p[off] == 50) {
			if (len == 0 || (p[off] == 1 && (rates || len > 8)))
				return (EPROTO);
			if (p[off] == 1)
				rates = B_TRUE;
			nrates += len;
			if (nrates >= IEEE80211_RATE_MAXSIZE)
				return (EPROTO);
			for (i = 0; i < len; i++) {
				uint8_t rate = p[off + 2 + i];

				for (j = 0; j < sizeof (legacy); j++) {
					if ((rate & IEEE80211_RATE_VAL) ==
					    legacy[j])
						break;
				}
				/* Native negotiation removes optional rates. */
				if ((rate & IEEE80211_RATE_VAL) == 0 ||
				    (rate & IEEE80211_RATE_VAL) >= 126 ||
				    (j == sizeof (legacy) &&
				    (rate & IEEE80211_RATE_BASIC)))
					return (ENOTSUP);
			}
		} else if ((p[off] == 221 && len < 4) ||
		    (p[off] == 45 && len != 26) ||
		    (p[off] == 61 && len != 22)) {
			return (EPROTO);
		} else if (p[off] == 221 && p[off + 2] == 0 &&
		    p[off + 3] == 0x50 && p[off + 4] == 0xf2) {
			if (p[off + 5] == 1)
				return (ENOTSUP);
			if (p[off + 5] == 2 && (len < 7 ||
			    (p[off + 6] == 1 && len != 24)))
				return (EPROTO);
		} else if (p[off] == 48) {
			if (!wpa)
				return (ENOTSUP);
			if (iwm_rsn_check(p + off, len + 2) != 0)
				return (EPROTO);
		}
	}
	return (rates ? 0 : EPROTO);
}

/* Validate before native input, which assumes several management IE sizes. */
static int
iwm_association_frame_check(const uint8_t *p, size_t n,
    const uint8_t *bssid, const uint8_t *local, uint_t channel,
    enum ieee80211_state state, boolean_t wpa)
{
	uint_t subtype;
	size_t header;
	int error;

	if (iwm_frame_header(p, n, &header) != 0 ||
	    bcmp(p + 10, bssid, 6))
		return (EPROTO);
	if ((p[0] & 0x0c) == 8) {
		/* No RX BA/reorder ownership is exposed in 8B1. */
		if (header == sizeof (struct ieee80211_qosframe) &&
		    (p[24] & 0x60) != 0)
			return (ENOTSUP);
		if (state != IEEE80211_S_RUN ||
		    (p[1] & 3) != 2 || n < header + 8 ||
		    (!(p[4] & 1) && bcmp(p + 4, local, 6)))
			return (ENOTSUP);
		if (p[1] & IEEE80211_FC1_WEP) {
			if (!wpa || n < header + IEEE80211_WEP_HDRLEN +
			    IEEE80211_WEP_EXTIVLEN + 8 + IEEE80211_WEP_MICLEN ||
			    p[header + 2] != 0 ||
			    (p[header + 3] & 0x3f) != IEEE80211_WEP_EXTIV ||
			    (!(p[4] & 1) && (p[header + 3] >> 6) != 0))
				return (EPROTO);
		} else if (wpa) {
			static const uint8_t eapol[] =
			    { 0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e };

			/* Plaintext WPA input is restricted to EAPOL. */
			if (bcmp(p + header, eapol, sizeof (eapol)))
				return (EACCES);
		}
		return (0);
	}
	if ((p[0] & 0x0c) != 0 || (p[1] & 0x43) != 0 ||
	    bcmp(p + 16, bssid, 6))
		return (EPROTO);
	subtype = p[0] & 0xf0;
	if (subtype == 0x80) {
		if (!(p[4] & 1) && bcmp(p + 4, local, 6))
			return (EPROTO);
		error = iwm_scan_frame_check(p, n, channel);
		if (error != 0)
			return (error);
		if ((iwm_u16(p + 34) & 0x13) != (wpa ? 0x11 : 1))
			return (ENOTSUP);
		return (iwm_association_ies(p, n, 36, wpa));
	}
	if (bcmp(p + 4, local, 6))
		return (EPROTO);
	if (subtype == IEEE80211_FC0_SUBTYPE_ACTION) {
		if (state != IEEE80211_S_RUN)
			return (ENOTSUP);
		return (iwm_ba_action_check(p, n, B_FALSE));
	}
	if (subtype == 0xb0) {
		if (state != IEEE80211_S_AUTH || n != 30 ||
		    iwm_u16(p + 24) != 0 || iwm_u16(p + 26) != 2)
			return (EPROTO);
		return (iwm_u16(p + 28) == 0 ? 0 : EACCES);
	}
	if (subtype == 0xa0 || subtype == 0xc0)
		return (n >= 26 ? 0 : EPROTO);
	if ((subtype != 0x10 && subtype != 0x30) ||
	    state != IEEE80211_S_ASSOC || n < 30)
		return (ENOTSUP);
	if (iwm_u16(p + 26) != 0)
		return (EACCES);
	if ((iwm_u16(p + 24) & 0x13) != (wpa ? 0x11 : 1) ||
	    (iwm_u16(p + 28) & 0x3fff) == 0 ||
	    (iwm_u16(p + 28) & 0x3fff) > 2007)
		return (EPROTO);
	return (iwm_association_ies(p, n, 30, wpa));
}

static void
iwm_association_rx(struct iwm_softc *sc, uint_t code,
    const uint8_t *p, size_t n)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_association *a = &r->association;
	struct iwm_connection *c = &sc->connection;
	struct iwm_scan_frame *frame;
	size_t length, off;
	uint32_t rate;
	uint_t channel;
	int error;

	if (!c->rx_admission || c->node == NULL ||
	    r->image != IWM_FW_REGULAR || r->state != IWM_REGULAR_IDLE)
		goto drop;
	if (code == 0xc0) {
		a->phy_valid = B_FALSE;
		if (n < sizeof (a->rx_phy) || p[0] < 8 ||
		    p[0] > sizeof (a->rx_phy.non_cfg_phy) || p[1] > 20)
			goto drop;
		bcopy(p, &a->rx_phy, sizeof (a->rx_phy));
		a->phy_valid = B_TRUE;
		return;
	}
	if (!a->phy_valid || n < 8)
		goto drop;
	length = iwm_u16(p);
	channel = LE_16(a->rx_phy.channel);
	if (length > n - 8 || channel != c->channel ||
	    (iwm_u32(p + 4 + length) & 3) != 3 ||
	    !(LE_16(a->rx_phy.phy_flags) & 1) ||
	    iwm_rx_rate_check(&a->rx_phy,
	    (c->node->in_flags & IEEE80211_NODE_HT) != 0,
	    sc->identity.rx_ant, &rate) != 0)
		goto drop;
	p += 4;
	a->rx_rate_flags = rate;
	error = iwm_association_frame_check(p, length, c->node->in_bssid,
	    sc->identity.mac, channel, sc->ic.ic_state, c->wpa);
	if (error != 0) {
		if ((p[0] & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_MGT && error == EACCES && c->error == 0)
			c->error = error;
		goto drop;
	}
	if (p[0] == 0x80) {
		/* Fresh device-clock timing, never a prior scan generation. */
		if (iwm_u16(p + 32) != c->node->in_intval)
			goto drop;
		for (off = 36; off < length; off += p[off + 1] + 2) {
			if (p[off] == 0 && (p[off + 1] != c->esslen ||
			    bcmp(p + off + 2, c->essid, c->esslen)))
				goto drop;
			if (p[off] != 5)
				continue;
			if (p[off + 3] == 0 || p[off + 2] >= p[off + 3])
				goto drop;
			a->beacon_gp2 = LE_32(a->rx_phy.system_timestamp);
			a->beacon_tsf = iwm_u32(p + 24) |
			    (uint64_t)iwm_u32(p + 28) << 32;
			a->dtim_count = p[off + 2];
			a->dtim_period = p[off + 3];
			a->beacon_valid = B_TRUE;
		}
	}
	if (a->queued == IWM_SCAN_RX_LIMIT)
		goto drop;
	frame = &a->frames[a->tail];
	frame->mp = allocb(length, BPRI_MED);
	if (frame->mp == NULL)
		goto drop;
	bcopy(p, frame->mp->b_wptr, length);
	frame->mp->b_wptr += length;
	frame->channel = channel;
	frame->timestamp = LE_32(a->rx_phy.system_timestamp);
	frame->rssi = c->node->in_rssi;
	a->tail = (a->tail + 1) % IWM_SCAN_RX_LIMIT;
	a->queued++;
	cv_broadcast(&r->cv);
	return;
drop:
	a->rx_dropped++;
}

static void
iwm_unsupported_notification(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_proto_diag *d = &r->diagnostic;

	r->unsupported_code = d->code;
	r->unsupported_sequence = d->sequence;
	r->unsupported_length = d->payload;
	/* Retain the last packet; bound console output per runtime. */
	if (r->unsupported_notifications++ < 8)
		dev_err(sc->dip, CE_NOTE, "!iwm unsupported notification "
		    "code=%04x sequence=%04x q=%u idx=%u length=%lu gen=%u",
		    d->code, d->sequence, d->sequence >> 8,
		    d->sequence & 0xff, (ulong_t)d->payload, r->generation);
}

/* Current DMA generation only, under sc->lock; stop drains before reuse. */
static void
iwm_notification(struct iwm_softc *sc, const uint8_t *p, size_t length)
{
	struct iwm_runtime *r = sc->run;
	uint_t code, idx, qid;
	const uint8_t *data;
	size_t n;
	enum iwm_proto_reason reason;
	struct iwm_proto_diag *d = &r->diagnostic;

	if (length < 4) {
		iwm_proto_error(sc, IWM_PROTO_RX_SHORT);
		return;
	}
	code = p[0] | (uint_t)p[1] << 8;
	idx = p[2];
	qid = p[3];
	data = p + 4;
	n = length - 4;
	d->packet_valid = B_TRUE;
	d->code = code;
	d->sequence = qid << 8 | idx;
	d->expected_sequence = r->cmdqid << 8 | r->cmdcur;
	d->expected_code = r->control_command ?
	    r->expected_code : IWM_NVM_ACCESS_CMD;
	d->pending = r->command_pending;
	d->payload = n;
	r->packet_class = iwm_rx_classify(code, qid);
	if (r->packet_class == IWM_RX_INVALID) {
		iwm_proto_error(sc, IWM_PROTO_NOTIFICATION);
		return;
	}
	if (r->packet_class == IWM_RX_UNSUPPORTED) {
		iwm_unsupported_notification(sc);
		return;
	}
	if (code == IWM_STATISTICS_NOTIFICATION) {
		if (!iwm_statistics_check(sc->fw.api[IWM_API_NEW_RX_STATS / 32],
		    n)) {
			iwm_proto_error(sc, IWM_PROTO_NOTIFICATION);
			return;
		}
		r->statistics_notifications++;
		return;
	}
	if (code == 0xa2 || code == 0xa1 || code == 0x02 || code == 0x4fe) {
		size_t expected = (code == 0xa2 || code == 0x02) ? 20 : 4;

		if (n != expected) {
			iwm_proto_error(sc, IWM_PROTO_NOTIFICATION);
			return;
		}
		if (code == 0xa2)
			r->missed_beacon_notifications++;
		else if (code != 0xa1 || (iwm_u32(data) & 0xf) != 0)
			r->error = EIO;
		return;
	}
	if (code == 0xb5) {
		/* UMAC v1 fixed header followed by scanned-channel records. */
		if (n < 16 || n != 16 + (size_t)data[4] * 8)
			iwm_proto_error(sc, IWM_PROTO_NOTIFICATION);
		return;
	}
	if (sc->connection.pending && (code == 0xc0 || code == 0xc1)) {
		iwm_association_rx(sc, code, data, n);
		return;
	}
	if (code == 0x1c) {
		int error = iwm_association_tx_done(sc, qid, idx, data, n);

		if (qid == IWM_TX_AGG_QUEUE && error != 0)
			r->association.ba[0].rejected++;
		else if (error != 0 && r->error == 0)
			r->error = error;
		cv_broadcast(&r->cv);
		return;
	}
	if (code == 0xc5) {
		if (iwm_ba_notification(sc, data, n) != 0)
			r->association.ba[0].rejected++;
		return;
	}

	if (code == IWM_TIME_EVENT_NOTIFICATION) {
		int error = iwm_time_event_notification(&r->protection, data, n,
		    r->image == IWM_FW_REGULAR &&
		    r->state == IWM_REGULAR_IDLE &&
		    r->protection.generation == r->generation &&
		    (!r->cancel_requested || r->protection.removing));

		/* Event failure does not invalidate the command transport. */
		(void) error;
		cv_broadcast(&r->cv);
		return;
	}
	if (code == IWM_MCC_CHUB_UPDATE_CMD && r->lar.attempted) {
		/* Close admission; the thread owner performs bounded stop. */
		(void) iwm_lar_changed(&r->lar, data, n,
		    r->image == IWM_FW_REGULAR &&
		    r->state == IWM_REGULAR_IDLE);
		if (r->error == 0)
			r->error = r->lar.error;
		cv_broadcast(&r->cv);
		return;
	}
	if (r->scan.enabled && (code == 0xc0 || code == 0xc1)) {
		iwm_scan_rx(sc, code, data, n);
		return;
	}
	if (r->scan.enabled && code == 0x0f) {
		iwm_scan_completion(sc, data, n);
		return;
	}
	if (code == IWM_ALIVE) {
		if (r->alive || (r->state != IWM_INIT_UPLOAD &&
		    r->state != IWM_REGULAR_UPLOAD) ||
		    (n != sizeof (struct iwm_alive_resp_v1) &&
		    n != sizeof (struct iwm_alive_resp_v2) &&
		    n != sizeof (struct iwm_alive_resp_v3))) {
			iwm_proto_error(sc, IWM_PROTO_ALIVE);
			return;
		}
		r->alive_len = n;
		bcopy(data, r->alive_data, n);
		if (iwm_u16(data) != IWM_ALIVE_STATUS_OK) {
			r->error = EIO;
			return;
		}
		dev_err(sc->dip, CE_NOTE,
		    "!iwm image=%u ALIVE status=%04x length=%lu",
		    r->image, iwm_u16(data), (ulong_t)n);
		/* All three donor ALIVE layouts place SCD at byte 40. */
		r->sched_base = iwm_u32(data + 40);
		dev_err(sc->dip, CE_NOTE, "!iwm ALIVE scd=%08x error=%08x "
		    "log=%08x version=%08x/%08x umac-error=%08x",
		    r->sched_base, iwm_u32(data + 20), iwm_u32(data + 24),
		    n == sizeof (struct iwm_alive_resp_v3) ?
		    iwm_u32(data + 8) : data[5],
		    n == sizeof (struct iwm_alive_resp_v3) ?
		    iwm_u32(data + 4) : data[4],
		    n == sizeof (struct iwm_alive_resp_v3) ?
		    iwm_u32(data + 60) :
		    n == sizeof (struct iwm_alive_resp_v2) ?
		    iwm_u32(data + 56) : 0);
		r->alive = B_TRUE;
		return;
	}
	if (code == IWM_MFUART_LOAD_NOTIFICATION) {
		dev_err(sc->dip, CE_NOTE, "!iwm MFUART notification bytes=%lu",
		    (ulong_t)n);
		return;
	}
	if (code == IWM_CALIB_RES_NOTIF_PHY_DB) {
		iwm_phy_notification(sc, data, n);
		return;
	}
	if (code == IWM_INIT_COMPLETE_NOTIF) {
		/* Completion event; framed payload bytes are opaque. */
		if (r->image == IWM_FW_INIT && r->init_complete)
			return;
		if (r->state != IWM_INIT_CALIBRATING ||
		    r->image != IWM_FW_INIT) {
			iwm_proto_error(sc, IWM_PROTO_INIT_STATE);
			return;
		}
		r->init_complete = B_TRUE;
		return;
	}
	/* Inactive notifications cannot complete a command. */
	if (r->packet_class != IWM_RX_RESPONSE) {
		iwm_unsupported_notification(sc);
		return;
	}
	if (r->control_command) {
		if (code != r->expected_code || !r->command_pending ||
		    qid != r->cmdqid || idx != r->cmdcur ||
		    n > sizeof (r->response)) {
			iwm_proto_error(sc, code != r->expected_code ?
			    IWM_PROTO_COMMAND_ID : IWM_PROTO_SEQUENCE);
			return;
		}
		bcopy(data, r->response, n);
		r->response_len = n;
		if (code == IWM_TIME_EVENT_CMD) {
			if (r->image != IWM_FW_REGULAR ||
			    r->state != IWM_REGULAR_IDLE ||
			    r->protection.generation != r->generation) {
				iwm_proto_error(sc, IWM_PROTO_COMMAND_ID);
				return;
			}
			(void) iwm_time_event_response(&r->protection, data, n);
		}
		r->command_done = B_TRUE;
		return;
	}
	reason = iwm_command_check(code, r->command_pending,
	    qid << 8 | idx, r->cmdqid << 8 | r->cmdcur, n);
	if (reason != IWM_PROTO_OK) {
		iwm_proto_error(sc, reason);
		return;
	}
	/* Decode the fixed header after command ownership checks. */
	if (code == IWM_NVM_ACCESS_CMD) {
		d->nvm_valid = B_TRUE;
		d->actual_offset = iwm_u16(data);
		d->count = iwm_u16(data + 2);
		d->actual_type = iwm_u16(data + 4);
		d->status = iwm_u16(data + 6);
	}
	bcopy(data, r->response, n);
	r->response_len = n;
	r->response_diagnostic = *d;
	r->command_done = B_TRUE;
}

static void
iwm_notifications(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint_t hw, count = 0;
	size_t off, length, advance;
	uint8_t *p;
	uint32_t raw;
	enum iwm_proto_reason reason;
	struct iwm_proto_diag *d = &r->diagnostic;

	d->packet_valid = B_FALSE;
	d->nvm_valid = B_FALSE;
	d->raw = 0;
	d->length = d->available = d->payload = 0;
	d->code = d->sequence = 0;
	d->actual_type = d->actual_offset = d->count = d->status = 0;
	d->rxcur = r->rxcur;
	if (iwm_sync(&sc->dma[3], DDI_DMA_SYNC_FORCPU) != 0) {
		r->error = EIO;
		return;
	}
	hw = iwm_u16((uint8_t *)sc->dma[3].vaddr) & 0xfff;
	d->rxhw = hw;
	if (hw >= IWM_RX_RING_COUNT) {
		iwm_proto_error(sc, IWM_PROTO_RX_INDEX);
		return;
	}
	while (r->rxcur != hw && count++ < IWM_RX_RING_COUNT && r->error == 0) {
		struct iwm_dma_info *dma = &r->rx[r->rxcur];

		if (iwm_sync(dma, DDI_DMA_SYNC_FORCPU) != 0) {
			r->error = EIO;
			return;
		}
		p = (uint8_t *)dma->vaddr;
		for (off = 0; off + 8 <= IWM_RBUF_SIZE; off += advance) {
			raw = iwm_u32(p + off);
			if (raw == IWM_FH_RSCSR_FRAME_INVALID ||
			    iwm_u32(p + off + 4) == 0)
				break;
			length = raw & IWM_FH_RSCSR_FRAME_SIZE_MSK;
			d->packet_valid = B_FALSE;
			d->nvm_valid = B_FALSE;
			d->code = d->sequence = 0;
			d->payload = 0;
			d->actual_type = d->actual_offset = 0;
			d->count = d->status = 0;
			d->rxcur = r->rxcur;
			d->raw = raw;
			d->length = length;
			d->available = IWM_RBUF_SIZE - off - 4;
			reason = iwm_packet_check(length, d->available);
			if (reason != IWM_PROTO_OK) {
				iwm_proto_error(sc, reason);
				break;
			}
			iwm_notification(sc, p + off + 4, length);
			advance = P2ROUNDUP(length + 4,
			    IWM_FH_RSCSR_FRAME_ALIGN);
			if (r->error != 0 || advance > IWM_RBUF_SIZE - off)
				break;
		}
		bzero(p, IWM_RBUF_SIZE);
		if (iwm_sync(dma, DDI_DMA_SYNC_FORDEV) != 0)
			r->error = EIO;
		r->rxcur = (r->rxcur + 1) % IWM_RX_RING_COUNT;
	}
	if (iwm_sync(&sc->dma[3], DDI_DMA_SYNC_FORDEV) != 0)
		r->error = EIO;
	if (r->error == 0)
		iwm_wr(sc, IWM_FH_RSCSR_CHNL0_WPTR,
		    ((hw == 0 ? IWM_RX_RING_COUNT : hw) - 1) & ~7);
}

/* Called by the single MSI handler with sc->lock held; never sleeps. */
uint_t
iwm_active_intr(struct iwm_softc *sc, uint32_t causes, uint32_t fh)
{
	struct iwm_runtime *r = sc->run;
	boolean_t alive = r->alive, init_complete = r->init_complete;
	boolean_t command_done = r->command_done, chunk_done = r->chunk_done;
	uint32_t rx = IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX |
	    IWM_CSR_INT_BIT_RX_PERIODIC;

	ASSERT(MUTEX_HELD(&sc->lock));
	if (causes == 0 && fh == 0) {
		iwm_wr(sc, IWM_CSR_INT_MASK, r->mask);
		return (DDI_INTR_UNCLAIMED);
	}
	r->causes |= causes;
	r->fh_causes |= fh;
	r->diagnostic.interrupt = causes;
	r->diagnostic.fh = fh;
	r->interrupt_count++;
	if (r->state == IWM_REGULAR_IDLE) {
		clock_t now = ddi_get_lbolt();

		if (now - r->interrupt_epoch >= drv_usectohz(1000000)) {
			r->interrupt_epoch = now;
			r->interrupt_window = 0;
		}
		if (++r->interrupt_window > 4096)
			r->error = EOVERFLOW;
	} else if (r->interrupt_count > 1024) {
		r->error = EOVERFLOW;
	}
	iwm_wr(sc, IWM_CSR_INT, causes);
	iwm_wr(sc, IWM_CSR_FH_INT_STATUS, fh);
	if (causes == 0xffffffff || (causes & ~IWM_RUN_MASK) != 0 ||
	    (fh & ~(IWM_CSR_FH_INT_TX_MASK | IWM_CSR_FH_INT_RX_MASK)) != 0 ||
	    (causes & (IWM_CSR_INT_BIT_HW_ERR | IWM_CSR_INT_BIT_SW_ERR))) {
		r->error = EIO;
	} else {
		if (causes & IWM_CSR_INT_BIT_FH_TX) {
			if ((r->state != IWM_INIT_UPLOAD &&
			    r->state != IWM_REGULAR_UPLOAD) || r->chunk_done)
				iwm_proto_error(sc, IWM_PROTO_FH_TX);
			else
				r->chunk_done = B_TRUE;
		}
		if (causes & rx) {
			iwm_wr8(sc, IWM_CSR_INT_PERIODIC_REG,
			    IWM_CSR_INT_PERIODIC_DIS);
			if (causes & (IWM_CSR_INT_BIT_FH_RX |
			    IWM_CSR_INT_BIT_SW_RX))
				iwm_wr8(sc, IWM_CSR_INT_PERIODIC_REG,
				    IWM_CSR_INT_PERIODIC_ENA);
			iwm_notifications(sc);
		}
	}
	if (r->error != 0)
		r->mask = 0;
	iwm_wr(sc, IWM_CSR_INT_MASK, r->mask);
	/* Routine notifications do not wake command/upload waiters. */
	if (r->error != 0 || r->alive != alive ||
	    r->init_complete != init_complete ||
	    r->command_done != command_done || r->chunk_done != chunk_done)
		cv_broadcast(&r->cv);
	return (DDI_INTR_CLAIMED);
}

/*
 * Serialized non-packet command. The transfer buffer is reusable only after
 * upload completion; it remains device-owned until the matching response.
 */
static int
iwm_control(struct iwm_softc *sc, uint_t code, const void *data, size_t size)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_tfd *tfd = (void *)r->tx[r->cmdqid].vaddr;
	struct iwm_agn_scd_bc_tbl *bc = (void *)r->scheduler.vaddr;
	uint8_t *header;
	uint64_t addr;
	uint32_t low;
	uint16_t value, bytes;
	uint_t hlen;
	int error;

	hlen = (code >> 8) != 0 ? 8 : 4;
	if (!r->alive || r->command_pending || r->error != 0 ||
	    size == 0 || size > 4095 - hlen ||
	    r->transfer.size < hlen || size > r->transfer.size - hlen)
		return (EINVAL);
	tfd += r->cmdcur;
	bzero(tfd, sizeof (*tfd));
	header = (uint8_t *)r->transfer.vaddr;
	bzero(header, hlen);
	header[0] = code & 0xff;
	header[1] = code >> 8;
	header[2] = r->cmdcur;
	header[3] = r->cmdqid;
	if (hlen == 8) {
		value = LE_16(size);
		bcopy(&value, header + 4, sizeof (value));
	}
	bcopy(data, header + hlen, size);
	addr = iwm_dma_addr(&r->transfer);
	low = LE_32((uint32_t)addr);
	bcopy(&low, &tfd->tbs[0].lo, sizeof (low));
	tfd->tbs[0].hi_n_len = LE_16((addr >> 32) | ((hlen + size) << 4));
	tfd->num_tbs = 1;
	bytes = IWM_TX_CRC_SIZE + IWM_TX_DELIMITER_SIZE;
	if (sc->fw.flags & IWM_UCODE_TLV_FLAGS_DW_BC_TABLE)
		bytes /= 4;
	bc[r->cmdqid].tfd_offset[r->cmdcur] = LE_16(bytes);
	if (r->cmdcur < IWM_TFD_QUEUE_SIZE_BC_DUP)
		bc[r->cmdqid].tfd_offset[IWM_TFD_QUEUE_SIZE_MAX + r->cmdcur] =
		    LE_16(bytes);
	if (iwm_sync(&r->scheduler, DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&r->transfer, DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&r->tx[r->cmdqid], DDI_DMA_SYNC_FORDEV) != 0)
		return (EIO);
	r->control_command = B_TRUE;
	r->expected_code = code;
	r->command_done = B_FALSE;
	r->command_pending = B_TRUE;
	r->response_len = 0;
	iwm_wr(sc, IWM_HBUS_TARG_WRPTR,
	    r->cmdqid << 8 | ((r->cmdcur + 1) % IWM_TX_RING_COUNT));
	error = iwm_wait(sc, &r->command_done);
	r->command_pending = B_FALSE;
	if (error == 0) {
		r->cmdcur = (r->cmdcur + 1) % IWM_TX_RING_COUNT;
		r->control_command = B_FALSE;
	}
	return (error);
}

/* The authenticated image, not a newer donor label, selects the wire ABI. */
static boolean_t
iwm_command_version(const struct iwm_fw_info *fw, uint8_t code,
    uint8_t version)
{
	uint_t i;

	for (i = 0; i < fw->cmd_version_count; i++) {
		const uint8_t *entry = fw->cmd_versions + 4 * i;

		if (entry[0] == code && entry[1] == 0)
			return (entry[2] == version);
	}
	return (B_FALSE);
}

static int
iwm_association_phy(struct iwm_softc *sc, uint_t action)
{
	struct iwm_phy_context_cmd cmd;
	struct iwm_association *a = &sc->run->association;
	int error;

	if (!iwm_command_version(&sc->fw, 0x08, 1) ||
	    (sc->fw.capa[1] & (1U << 16)) != 0)
		return (ENOTSUP);
	if ((action == IWM_FW_CTXT_ACTION_ADD) == a->phy)
		return (EINVAL);
	bzero(&cmd, sizeof (cmd));
	cmd.action = LE_32(action);
	cmd.band = 1;
	cmd.channel = sc->connection.channel;
	cmd.rxchain_info = LE_32((sc->identity.rx_ant << 1) |
	    (1U << 10) | (1U << 12));
	cmd.txchain_info = LE_32(sc->identity.tx_ant);
	error = iwm_control(sc, 0x08, &cmd, sizeof (cmd));
	if (error == 0)
		a->phy = action != IWM_FW_CTXT_ACTION_REMOVE;
	return (error);
}

/* Basic rates plus the mandatory lower control-response rates. */
static void
iwm_association_ack_rates(const ieee80211_node_t *node, uint32_t *cck,
    uint32_t *ofdm)
{
	static const uint8_t rates[] =
	    { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };
	uint_t i, j, low_cck = 4, low_ofdm = 12;

	*cck = *ofdm = 1;
	for (i = 0; i < node->in_rates.ir_nrates; i++) {
		uint8_t rate = node->in_rates.ir_rates[i];

		if (!(rate & IEEE80211_RATE_BASIC))
			continue;
		for (j = 0; j < sizeof (rates); j++) {
			if ((rate & IEEE80211_RATE_VAL) == rates[j])
				break;
		}
		if (j < 4) {
			*cck |= 1U << j;
			low_cck = MIN(low_cck, j);
		} else if (j < 12) {
			*ofdm |= 1U << (j - 4);
			low_ofdm = MIN(low_ofdm, j);
		}
	}
	for (j = 0; low_cck != 4 && j < low_cck; j++)
		*cck |= 1U << j;
	if (low_ofdm != 12 && low_ofdm > 6)
		*ofdm |= 1U << 2;
	if (low_ofdm != 12 && low_ofdm > 8)
		*ofdm |= 1U << 4;
}

static int
iwm_association_mac(struct iwm_softc *sc, uint_t action, boolean_t assoc)
{
	struct iwm_association *a = &sc->run->association;
	struct iwm_wme_state *w = &sc->connection.wme;
	ieee80211_node_t *node = sc->connection.node;
	struct iwm_mac_ctx_cmd cmd;
	uint32_t cck, ofdm, offset, interval;
	uint64_t epoch = w->epoch, revision = w->requested;
	int error;

	if (!iwm_command_version(&sc->fw, 0x28, 3))
		return (ENOTSUP);
	if ((action == IWM_FW_CTXT_ACTION_ADD && a->mac) ||
	    (action != IWM_FW_CTXT_ACTION_ADD && !a->mac) || !a->phy)
		return (EINVAL);
	if (assoc && (!a->beacon_valid || a->dtim_period == 0 ||
	    IEEE80211_AID(node->in_associd) == 0 ||
	    IEEE80211_AID(node->in_associd) > 2007))
		return (EINVAL);
	bzero(&cmd, sizeof (cmd));
	cmd.action = LE_32(action);
	cmd.mac_type = LE_32(5);
	bcopy(sc->identity.mac, cmd.node_addr, sizeof (cmd.node_addr));
	bcopy(node->in_bssid, cmd.bssid_addr, sizeof (cmd.bssid_addr));
	iwm_association_ack_rates(node, &cck, &ofdm);
	cmd.cck_rates = LE_32(cck);
	cmd.ofdm_rates = LE_32(ofdm);
	if (sc->ic.ic_flags & IEEE80211_F_SHPREAMBLE)
		cmd.cck_short_preamble = LE_32(0x20);
	if (sc->ic.ic_flags & IEEE80211_F_SHSLOT)
		cmd.short_slot = LE_32(0x10);
	if (sc->ic.ic_flags & IEEE80211_F_USEPROT)
		cmd.protection_flags = LE_32(1U << 3);
	if (node->in_flags & IEEE80211_NODE_QOS)
		cmd.qos_flags |= LE_32(IWM_MAC_QOS_FLG_UPDATE_EDCA);
	if (node->in_flags & IEEE80211_NODE_HT) {
		cmd.qos_flags |= LE_32(IWM_MAC_QOS_FLG_TGN);
		if (node->in_htopmode == IEEE80211_HTINFO_OPMODE_PROTOPT ||
		    node->in_htopmode == IEEE80211_HTINFO_OPMODE_MIXED)
			cmd.protection_flags |= LE_32(IWM_MAC_PROT_FLG_HT_PROT |
			    IWM_MAC_PROT_FLG_FAT_PROT);
	}
	/* Receive beacons for native ERP/DTIM maintenance; no beacon filter. */
	cmd.filter_flags = LE_32((1U << 2) | (1U << 6));
	if (sc->connection.wpa) {
		/* Preserve the full protected MPDU for native software CCMP. */
		cmd.filter_flags |= LE_32(IWM_MAC_FILTER_DIS_DECRYPT |
		    IWM_MAC_FILTER_DIS_GRP_DECRYPT);
	}
	if (sc->ic.ic_caps & IEEE80211_C_WME) {
		if ((action == IWM_FW_CTXT_ACTION_ADD || assoc) &&
		    (!w->valid || w->error != 0))
			return (w->error != 0 ? w->error : EINVAL);
		bcopy(w->ac, cmd.ac, sizeof (w->ac));
	} else if ((error = iwm_wme_encode(&sc->ic.ic_wme, cmd.ac)) != 0) {
		return (error);
	}
	if (assoc) {
		interval = (uint32_t)node->in_intval * a->dtim_period;
		offset = (uint32_t)a->dtim_count * node->in_intval * 1024;
		cmd.sta.is_assoc = LE_32(1);
		cmd.sta.dtim_time = LE_32(a->beacon_gp2 + offset);
		cmd.sta.dtim_tsf = LE_64(a->beacon_tsf + offset);
		cmd.sta.bi = LE_32(node->in_intval);
		cmd.sta.bi_reciprocal = LE_32(UINT32_MAX / node->in_intval);
		cmd.sta.dtim_interval = LE_32(interval);
		cmd.sta.dtim_reciprocal = LE_32(UINT32_MAX / interval);
		cmd.sta.listen_interval = LE_32(10);
		cmd.sta.assoc_id = LE_32(IEEE80211_AID(node->in_associd));
		cmd.sta.assoc_beacon_arrive_time = LE_32(a->beacon_gp2);
	}
	error = iwm_control(sc, 0x28, &cmd, sizeof (cmd));
	if (error == 0) {
		a->mac = action != IWM_FW_CTXT_ACTION_REMOVE;
		if (assoc && w->accepting && w->epoch == epoch)
			w->applied = revision;
	}
	return (error);
}

/* Sole connection worker, sc->lock held; state transitions share this owner. */
static int
iwm_wme_work(struct iwm_softc *sc)
{
	struct iwm_connection *c = &sc->connection;
	struct iwm_wme_state *w = &c->wme;
	struct iwm_association *a;
	int error;

	ASSERT(MUTEX_HELD(&sc->lock));
	ASSERT(curthread == c->thread);
	if (!c->running || c->cancel || !w->accepting ||
	    w->requested == w->applied)
		return (0);
	if (sc->run == NULL || !w->valid)
		return (EINVAL);
	if (w->error != 0)
		return (w->error);
	a = &sc->run->association;
	if (!a->phy || !a->mac || !a->binding || !a->station ||
	    !a->run_configured)
		return (EINVAL);
	if ((error = iwm_nic_lock(sc)) != 0)
		return (error);
	error = iwm_association_mac(sc, IWM_FW_CTXT_ACTION_MODIFY, B_TRUE);
	iwm_nic_unlock(sc);
	return (error);
}

static int
iwm_association_binding(struct iwm_softc *sc, uint_t action)
{
	struct iwm_association *a = &sc->run->association;
	struct iwm_binding_cmd_v1 cmd;
	int error;

	if (!iwm_command_version(&sc->fw, 0x2b, 1) ||
	    (sc->fw.capa[1] & (1U << 7)) != 0)
		return (ENOTSUP);
	if (!a->phy || !a->mac ||
	    (action == IWM_FW_CTXT_ACTION_ADD) == a->binding)
		return (EINVAL);
	bzero(&cmd, sizeof (cmd));
	cmd.action = LE_32(action);
	cmd.macs[1] = cmd.macs[2] = LE_32(UINT32_MAX);
	error = iwm_control(sc, 0x2b, &cmd, sizeof (cmd));
	if (error == 0 && (sc->run->response_len != 4 ||
	    iwm_u32(sc->run->response) != 0))
		error = EIO;
	if (error == 0)
		a->binding = action != IWM_FW_CTXT_ACTION_REMOVE;
	return (error);
}

static int
iwm_association_queue(struct iwm_softc *sc, uint_t ac, boolean_t enable)
{
	static const uint8_t fifo[] = { 1, 0, 2, 3, 1 };
	struct iwm_association *a = &sc->run->association;
	struct iwm_scd_txq_cfg_cmd cmd;
	uint_t qid = ac == 4 ? IWM_TX_AGG_QUEUE : 5 + ac;
	int error;

	if (ac >= IWM_ASSOC_TX_RINGS ||
	    !!(a->queues & (1U << qid)) == enable ||
	    (!enable && a->tx[ac].queued != 0))
		return (EINVAL);
	if (enable && ac == 4 && sc->run->ba_queue_used)
		return (EBUSY);
	bzero(&cmd, sizeof (cmd));
	cmd.scd_queue = qid;
	cmd.enable = enable;
	if (enable) {
		cmd.tx_fifo = fifo[ac];
		cmd.window = IWM_TX_AGG_WINDOW;
		if (ac == 4) {
			uint_t ssn = a->ba[0].ssn;

			cmd.aggregate = 1;
			/* Pinned 8000 SCD workaround, before admission. */
			if (((ssn - a->tx[ac].cur) & 0x3f) == 0 &&
			    ssn != a->tx[ac].cur)
				ssn = IEEE80211_SEQ_ADD(ssn, 1);
			cmd.ssn = LE_16(ssn);
		}
		iwm_wr(sc, IWM_HBUS_TARG_WRPTR,
		    qid << 8 | (LE_16(cmd.ssn) & 0xff));
	}
	error = iwm_control(sc, 0x1d, &cmd, sizeof (cmd));
	if (error == 0) {
		a->tx[ac].configured = enable;
		a->tx[ac].released = !enable;
		a->tx[ac].station = cmd.sta_id;
		a->tx[ac].fifo = cmd.tx_fifo;
		if (enable) {
			a->queues |= 1U << qid;
			sc->run->released_queues &= ~(1U << qid);
			if (ac == 4) {
				sc->run->ba_queue_used = B_TRUE;
				a->ba[0].ssn = LE_16(cmd.ssn);
				a->ba[0].next_sequence = a->ba[0].ssn;
				a->tx[ac].cur = a->tx[ac].tail =
				    a->ba[0].ssn & 0xff;
			}
		} else {
			a->queues &= ~(1U << qid);
			sc->run->released_queues |= 1U << qid;
			bzero(a->tx[ac].desc, sc->run->tx[qid].size);
			a->tx[ac].cur = a->tx[ac].tail = 0;
			error = iwm_sync(&sc->run->tx[qid],
			    DDI_DMA_SYNC_FORDEV);
		}
	}
	return (error);
}

static int
iwm_association_station(struct iwm_softc *sc, boolean_t update,
    boolean_t drain)
{
	struct iwm_association *a = &sc->run->association;
	struct iwm_add_sta_cmd cmd;
	int error;

	if (!a->binding || a->station != update ||
	    (a->queues & ~(1U << IWM_TX_AGG_QUEUE)) != 0x1e0)
		return (EINVAL);
	bzero(&cmd, sizeof (cmd));
	cmd.add_modify = update;
	if (drain) {
		cmd.station_flags = LE_32(1U << 12);
		cmd.station_flags_msk = LE_32(1U << 12);
	} else {
		cmd.tid_disable_tx = LE_16((a->ba[0].state == IWM_BA_STARTING &&
		    a->ba[0].accepted) || a->ba[0].admission ? 0xfffe : 0xffff);
		cmd.tfd_queue_msk = LE_32(a->queues);
		cmd.station_flags_msk = LE_32((1U << 12) |
		    (3U << 26) | (3U << 28));
		if (sc->connection.node->in_flags & IEEE80211_NODE_HT) {
			uint_t param = sc->connection.node->in_htparam;

			/* Peer AMPDU limit/density; SISO/width20 stay clear. */
			cmd.station_flags_msk |= LE_32((7U << 19) | (7U << 23));
			cmd.station_flags |= LE_32((param & 3) << 19 |
			    ((param >> 2) & 7) << 23);
		}
		if (update)
			cmd.modify_mask = (1U << 1) | (1U << 7);
		else
			bcopy(sc->connection.node->in_bssid, cmd.addr, 6);
	}
	error = iwm_control(sc, 0x18, &cmd, sizeof (cmd));
	if (error == 0 && (sc->run->response_len != 4 ||
	    (iwm_u32(sc->run->response) & 0xff) != 1))
		error = EIO;
	if (error == 0)
		a->station = B_TRUE;
	return (error);
}

/* Allocate outside interrupt context before any queue can own a frame. */
static int
iwm_association_tx_alloc(struct iwm_softc *sc)
{
	struct iwm_association *a = &sc->run->association;
	uint_t ac, i;
	int error;

	if (sc->run->ba_generation == UINT64_MAX)
		return (EOVERFLOW);
	a->generation = ++sc->run->ba_generation;
	for (ac = 0; ac < IWM_ASSOC_TX_RINGS; ac++) {
		struct iwm_tx_ring *ring = &a->tx[ac];

		ring->qid = ac == 4 ? IWM_TX_AGG_QUEUE : 5 + ac;
		ring->desc = (void *)sc->run->tx[ring->qid].vaddr;
		error = iwm_dma_alloc(sc, &ring->cmd_dma,
		    IWM_TX_RING_COUNT * sizeof (struct iwm_device_cmd),
		    4, DDI_DMA_RDWR);
		if (error != 0)
			return (error);
		ring->cmd = (void *)ring->cmd_dma.vaddr;
		for (i = 0; i < IWM_TX_RING_COUNT; i++) {
			error = iwm_dma_alloc(sc, &ring->data[i].dma,
			    IWM_RBUF_SIZE, 4, DDI_DMA_WRITE);
			if (error != 0)
				return (error);
		}
	}
	return (0);
}

/* Connection worker only; leave native state inaccessible during FW waits. */
static void
iwm_ba_native(struct iwm_softc *sc, boolean_t active)
{
	struct iwm_tx_ba *ba = &sc->run->association.ba[0];
	ieee80211_node_t *node = sc->connection.node;
	struct ieee80211_tx_ampdu *tap;

	ASSERT(MUTEX_HELD(&sc->lock));
	mutex_exit(&sc->lock);
	mutex_enter(&sc->connection.crypto_lock);
	mutex_enter(&sc->ic.ic_genlock);
	mutex_enter(&sc->lock);
	if (node != NULL && node == ba->node) {
		tap = &node->in_tx_ampdu[WME_AC_BE];
		tap->txa_flags &= ~(IEEE80211_AGGR_RUNNING |
		    IEEE80211_AGGR_XCHGPEND);
		tap->txa_timer = NULL;
		if (active && ba->state == IWM_BA_STARTING && ba->accepted &&
		    sc->connection.running && !sc->connection.cancel &&
		    ba->generation == sc->run->association.generation &&
		    ba->runtime_generation == sc->run->generation) {
			node->in_txseqs[0] = ba->next_sequence;
			tap->txa_start = tap->txa_seqstart = ba->ssn;
			tap->txa_wnd = ba->window;
			tap->txa_flags |= IEEE80211_AGGR_RUNNING;
			ba->state = IWM_BA_ACTIVE;
			ba->admission = B_TRUE;
		} else {
			tap->txa_flags |= IEEE80211_AGGR_NAK;
			ba->admission = B_FALSE;
		}
	}
	mutex_exit(&sc->lock);
	mutex_exit(&sc->ic.ic_genlock);
	mutex_exit(&sc->connection.crypto_lock);
	mac_tx_update(sc->ic.ic_mach);
	mutex_enter(&sc->lock);
}

/* No timer retains a raw tap pointer; the existing worker owns the deadline. */
static int
iwm_ba_work(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_association *a = &r->association;
	struct iwm_tx_ba *ba = &a->ba[0];
	struct iwm_lq_cmd lq;
	struct iwm_tx_path_flush_cmd_v1 flush;
	uint32_t rate;
	uint_t i, queued;
	clock_t end;
	int error;
	boolean_t admission;

	ASSERT(MUTEX_HELD(&sc->lock));
	ASSERT(curthread == sc->connection.thread);
	if (ba->state == IWM_BA_CLOSED || ba->state == IWM_BA_ACTIVE)
		return (0);
	if (ba->generation != a->generation ||
	    ba->node != sc->connection.node ||
	    ba->runtime_generation != r->generation)
		return (EPROTO);
	if (ba->state == IWM_BA_STARTING) {
		/* A late accepted response cannot reopen retired admission. */
		if (!sc->connection.running || sc->connection.cancel ||
		    !sc->connection.tx_admission || ba->tid != 0 ||
		    ba->ac != WME_AC_BE) {
			ba->accepted = B_FALSE;
			ba->state = IWM_BA_CLOSED;
			iwm_ba_native(sc, B_FALSE);
			return (0);
		}
		if (!ba->accepted) {
			if (ddi_get_lbolt() < ba->deadline)
				return (0);
			ba->state = IWM_BA_CLOSED;
			iwm_ba_native(sc, B_FALSE);
			return (0);
		}
		/* Drain earlier TID0 traffic before activation. */
		if (a->tx[0].queued != 0)
			return (ddi_get_lbolt() >= ba->deadline ?
			    ETIMEDOUT : 0);
		if ((error = iwm_nic_lock(sc)) != 0)
			return (error);
		error = iwm_association_queue(sc, 4, B_TRUE);
		if (error == 0)
			error = iwm_association_station(sc, B_TRUE, B_FALSE);
		if (error == 0)
			error = iwm_tx_rate_encode(B_TRUE, 0,
			    sc->identity.tx_ant & -sc->identity.tx_ant, &rate);
		if (error == 0) {
			bzero(&lq, sizeof (lq));
			lq.flags = (sc->ic.ic_flags &
			    IEEE80211_F_USEPROT) ? 1 : 0;
			lq.single_stream_ant_msk =
			    sc->identity.tx_ant & -sc->identity.tx_ant;
			lq.dual_stream_ant_msk = sc->identity.tx_ant;
			lq.agg_time_limit = LE_16(4000);
			lq.agg_disable_start_th = 3;
			lq.agg_frame_cnt_limit = 0x3f;
			for (i = 0; i < 16; i++)
				lq.rs_table[i] = LE_32(rate);
			error = iwm_control(sc, 0x4e, &lq, sizeof (lq));
		}
		iwm_nic_unlock(sc);
		if (error == 0) {
			if (sc->connection.cancel)
				ba->state = IWM_BA_STOPPING;
			else
				iwm_ba_native(sc, B_TRUE);
		}
		return (error);
	}
	/* DELBA closes admission; q10 survives until RUN departure. */
	ba->admission = B_FALSE;
	ba->state = IWM_BA_DRAINING;
	admission = sc->connection.tx_admission;
	sc->connection.tx_admission = B_FALSE;
	iwm_ba_native(sc, B_FALSE);
	if (a->tx[4].configured) {
		if ((error = iwm_nic_lock(sc)) != 0)
			return (error);
		error = iwm_association_station(sc, B_TRUE, B_TRUE);
		if (error == 0) {
			bzero(&flush, sizeof (flush));
			flush.queues_ctl = LE_32(a->queues);
			flush.flush_ctl = LE_16(2);
			error = iwm_control(sc, 0x1e, &flush, sizeof (flush));
		}
		iwm_nic_unlock(sc);
		end = ddi_get_lbolt() + drv_usectohz(IWM_WAIT_US);
		while (error == 0) {
			error = iwm_association_reclaim(sc, B_FALSE);
			queued = 0;
			for (i = 0; i < IWM_ASSOC_TX_RINGS; i++)
				queued += a->tx[i].queued;
			if (error != 0 || queued == 0)
				break;
			if (cv_timedwait(&r->cv, &sc->lock, end) == -1)
				error = ETIMEDOUT;
		}
		if (error == 0 && (error = iwm_nic_lock(sc)) == 0) {
			error = iwm_association_station(sc, B_TRUE, B_FALSE);
			iwm_nic_unlock(sc);
		}
		if (error != 0)
			return (error);
	}
	ba->state = IWM_BA_CLOSED;
	if (sc->connection.running && !sc->connection.cancel)
		sc->connection.tx_admission = admission;
	mutex_exit(&sc->lock);
	mac_tx_update(sc->ic.ic_mach);
	mutex_enter(&sc->lock);
	return (0);
}

/* Close logical BA admission before native/key retirement; no FW wait here. */
static void
iwm_ba_retire(struct iwm_softc *sc)
{
	ieee80211_node_t *node;
	uint_t ac;

	mutex_enter(&sc->connection.crypto_lock);
	mutex_enter(&sc->ic.ic_genlock);
	mutex_enter(&sc->lock);
	node = sc->connection.node;
	if (sc->run != NULL) {
		struct iwm_tx_ba *ba = &sc->run->association.ba[0];

		ba->admission = B_FALSE;
		if (ba->state != IWM_BA_CLOSED)
			ba->state = IWM_BA_DRAINING;
	}
	if (node != NULL) {
		for (ac = 0; ac < 4; ac++) {
			ASSERT(node->in_tx_ampdu[ac].txa_timer == NULL);
			bzero(&node->in_tx_ampdu[ac],
			    sizeof (node->in_tx_ampdu[ac]));
			node->in_tx_ampdu[ac].txa_ac = ac;
		}
	}
	mutex_exit(&sc->lock);
	mutex_exit(&sc->ic.ic_genlock);
	mutex_exit(&sc->connection.crypto_lock);
}

/* A failed unbind retains its data-block reference for stopped cleanup. */
static int
iwm_tx_unmap(struct iwm_tx_data *slot)
{
	while (slot->mapped != 0) {
		struct iwm_tx_mapping *map = &slot->maps[slot->mapped - 1];

		if (map->bound) {
			if (ddi_dma_sync(map->handle, 0, 0,
			    DDI_DMA_SYNC_FORCPU) != DDI_SUCCESS ||
			    ddi_dma_unbind_handle(map->handle) != DDI_SUCCESS)
				return (EIO);
			map->bound = B_FALSE;
		}
		ddi_dma_free_handle(&map->handle);
		freemsg(map->mp);
		map->mp = NULL;
		slot->mapped--;
	}
	return (0);
}

/* Fixed header stays in the command; map every payload block, without sleep. */
static int
iwm_tx_map(struct iwm_softc *sc, struct iwm_tx_data *slot, mblk_t *mp,
    struct iwm_tfd *tfd, size_t header)
{
	ddi_dma_attr_t attr = {
		DMA_ATTR_V0, 0, 0xfffffffffULL, 0xfff, 1, 0x7ff, 1,
		0xfff, 0xfffffffffULL, IWM_NUM_OF_TBS - 2, 1, 0
	};
	ddi_dma_cookie_t cookie;
	struct iwm_tx_mapping *map;
	size_t offset = header, length, total;
	uint_t count, i;
	uint64_t address;

	ASSERT(slot->mapped == 0);
	tfd->num_tbs = 2;
	for (; mp != NULL; mp = mp->b_cont, offset = 0) {
		length = MBLKL(mp) - offset;
		if (length == 0)
			continue;
		if (slot->mapped == IWM_NUM_OF_TBS - 2)
			return (ENOBUFS);
		map = &slot->maps[slot->mapped];
		map->mp = dupb(mp);
		if (map->mp == NULL)
			return (ENOMEM);
		if (ddi_dma_alloc_handle(sc->dip, &attr, DDI_DMA_DONTWAIT,
		    NULL, &map->handle) != DDI_SUCCESS) {
			freemsg(map->mp);
			map->mp = NULL;
			return (ENOMEM);
		}
		slot->mapped++;
		if (ddi_dma_addr_bind_handle(map->handle, NULL,
		    (caddr_t)mp->b_rptr + offset, length,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
		    NULL, &cookie, &count) != DDI_DMA_MAPPED)
			return (ENOBUFS);
		map->bound = B_TRUE;
		if (count == 0 || count >
		    (uint_t)(IWM_NUM_OF_TBS - tfd->num_tbs))
			return (ENOBUFS);
		total = 0;
		for (i = 0; i < count; i++) {
			address = cookie.dmac_laddress;
			if (cookie.dmac_size == 0 || cookie.dmac_size > 0xfff ||
			    cookie.dmac_size > length - total ||
			    address > 0xfffffffffULL || cookie.dmac_size - 1 >
			    0xfffffffffULL - address)
				return (EINVAL);
			total += cookie.dmac_size;
			tfd->tbs[tfd->num_tbs].lo = LE_32(address);
			tfd->tbs[tfd->num_tbs++].hi_n_len = LE_16(
			    (address >> 32) | (cookie.dmac_size << 4));
			if (i + 1 < count)
				ddi_dma_nextcookie(map->handle, &cookie);
		}
		if (total != length)
			return (EINVAL);
		if (ddi_dma_sync(map->handle, 0, 0,
		    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS)
			return (EIO);
	}
	return (0);
}

/* Whole MPDU bounds are independent of header contiguity and payload blocks. */
static int
iwm_tx_frame_check(mblk_t *mp, boolean_t management, size_t *length)
{
	static const uint8_t snap[] = { 0xaa, 0xaa, 3, 0, 0, 0 };
	mblk_t *block;
	const uint8_t *frame = mp->b_rptr;
	uint_t fragments = 0;
	size_t n, header;

	*length = 0;
	for (block = mp; block != NULL; block = block->b_cont) {
		if (++fragments > IWM_RBUF_SIZE ||
		    block->b_wptr < block->b_rptr)
			return (EINVAL);
		n = MBLKL(block);
		if (n > IWM_RBUF_SIZE - *length)
			return (EINVAL);
		*length += n;
	}
	if (iwm_frame_header(frame, MBLKL(mp), &header) != 0 ||
	    MBLKL(mp) < header + (management ? 0 : 8) ||
	    *length <= header ||
	    (frame[0] & 0x0f) != (management ? 0 : 8) ||
	    (management && (frame[1] & IEEE80211_FC1_WEP)))
		return (EINVAL);
	if (!management) {
		if ((frame[1] & 3) != 1)
			return (EINVAL);
		if (frame[1] & IEEE80211_FC1_WEP) {
			/* SNAP is encrypted in a protected frame. */
			if (mp->b_cont != NULL || *length < header +
			    IEEE80211_WEP_HDRLEN + IEEE80211_WEP_EXTIVLEN +
			    sizeof (struct ieee80211_llc) +
			    IEEE80211_WEP_MICLEN ||
			    frame[header + 2] != 0 ||
			    (frame[header + 3] & 0x3f) != IEEE80211_WEP_EXTIV)
				return (EINVAL);
		} else if (bcmp(frame + header, snap, sizeof (snap)) != 0) {
			return (EINVAL);
		}
	}
	return (0);
}

/* Caller retains mp on error; the ring owns mp and its node after publish. */
static int
iwm_association_tx(struct iwm_softc *sc, mblk_t *mp, boolean_t management,
    boolean_t eapol)
{
	static const uint8_t rates[] =
	    { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };
	struct iwm_runtime *r;
	struct iwm_tx_ring *ring;
	struct iwm_tx_data *slot = NULL;
	struct iwm_device_cmd *cmd;
	struct iwm_tx_cmd *tx;
	struct iwm_tfd *tfd;
	struct iwm_agn_scd_bc_tbl *bc;
	ieee80211_node_t *node;
	const uint8_t *frame = mp->b_rptr;
	size_t length, header, pad;
	boolean_t ht, aggregate;
	uint64_t address, scratch;
	uint32_t flags, rate_flags;
	uint_t ac = management ? 3 : 0, i, j, selected = 12;
	uint16_t bytes;
	int error = EINVAL;

	if (iwm_tx_frame_check(mp, management, &length) != 0 ||
	    (management && mp->b_cont != NULL))
		return (EINVAL);
	if (management && frame[0] != IEEE80211_FC0_SUBTYPE_AUTH &&
	    frame[0] != IEEE80211_FC0_SUBTYPE_ASSOC_REQ &&
	    frame[0] != IEEE80211_FC0_SUBTYPE_REASSOC_REQ &&
	    (frame[0] != IEEE80211_FC0_SUBTYPE_ACTION ||
	    iwm_ba_action_check(frame, length, B_TRUE) != 0))
		return (ENOTSUP);
	if (iwm_frame_header(frame, MBLKL(mp), &header) != 0)
		return (EINVAL);
	pad = (4 - (header & 3)) & 3;
	mutex_enter(&sc->lock);
	r = sc->run;
	node = sc->connection.node;
	if (r == NULL || node == NULL || !sc->connection.tx_admission ||
	    (!management && !sc->connection.running) || r->error != 0 ||
	    iwm_lar_channel(&r->lar, sc->identity.channels,
	    sc->connection.channel) != 0) {
		error = ENETDOWN;
		goto out;
	}
	if (bcmp(frame + 4, node->in_bssid, 6) ||
	    bcmp(frame + 10, sc->identity.mac, 6))
		goto out;
	aggregate = !management && !eapol && !(frame[16] & 1) &&
	    header == sizeof (struct ieee80211_qosframe) &&
	    frame[24] == IEEE80211_QOS_ACKPOLICY_BA &&
	    (node->in_flags & IEEE80211_NODE_HT) != 0;
	if (header == sizeof (struct ieee80211_qosframe) &&
	    (frame[24] & IEEE80211_QOS_ACKPOLICY_BA) && !aggregate)
		goto out;
	if (aggregate) {
		struct iwm_tx_ba *ba = &r->association.ba[0];

		if (!ba->admission || ba->state != IWM_BA_ACTIVE ||
		    ba->node != node ||
		    ba->generation != r->association.generation ||
		    ba->runtime_generation != r->generation ||
		    (ba->next_sequence & 0xff) != r->association.tx[4].cur ||
		    (iwm_u16(frame + 22) >> 4) != ba->next_sequence)
			goto out;
		ac = 4;
	}
	ring = &r->association.tx[ac];
	if (!(r->association.queues & (1U << ring->qid)) ||
	    !r->association.station)
		goto out;
	slot = &ring->data[ring->cur];
	if (ring->queued >= (aggregate ? IWM_TX_AGG_WINDOW :
	    IWM_TX_RING_COUNT - 1) || slot->owned ||
	    slot->mapped != 0) {
		error = EAGAIN;
		goto out;
	}
	/* Fixed lowest shared basic legacy rate; no firmware rate offload. */
	for (i = 0; i < node->in_rates.ir_nrates; i++) {
		uint8_t rate = node->in_rates.ir_rates[i];

		for (j = 0; j < sizeof (rates); j++) {
			if ((sc->connection.basic_rates & (1U << j)) &&
			    (rate & IEEE80211_RATE_VAL) == rates[j] &&
			    (selected == 12 || rates[j] < rates[selected]))
				selected = j;
		}
	}
	if (selected == 12)
		goto out;
	cmd = &ring->cmd[ring->cur];
	bzero(cmd, sizeof (*cmd));
	cmd->hdr.code = 0x1c;
	cmd->hdr.idx = ring->cur;
	cmd->hdr.qid = ring->qid;
	tx = (void *)cmd->data;
	tx->len = LE_16(length);
	flags = (1U << 3) | IWM_TX_CMD_FLG_BT_DIS;
	if (header == sizeof (struct ieee80211_frame))
		flags |= IWM_TX_CMD_FLG_SEQ_CTL;
	if (pad != 0) {
		flags |= IWM_TX_CMD_FLG_MH_PAD;
		tx->offload_assist = LE_16(IWM_TX_CMD_OFFLD_PAD);
	}
	if (!management && (sc->ic.ic_flags & IEEE80211_F_USEPROT))
		flags |= 1;
	tx->tx_flags = LE_32(flags);
	ht = !management && !eapol && !(frame[16] & 1) &&
	    (node->in_flags & IEEE80211_NODE_HT) != 0;
	error = iwm_tx_rate_encode(ht, ht ? 0 : rates[selected],
	    sc->identity.tx_ant & -sc->identity.tx_ant, &rate_flags);
	if (error != 0)
		goto out;
	tx->rate_n_flags = LE_32(rate_flags);
	tx->life_time = LE_32(UINT32_MAX);
	tx->rts_retry_limit = 60;
	tx->data_retry_limit = management ? 60 : 15;
	tx->tid_tspec = management ? 8 :
	    (header == sizeof (struct ieee80211_qosframe) ? frame[24] & 7 : 0);
	tx->pm_frame_timeout = LE_16(management ?
	    ((frame[0] & 0xf0) == 0 ? 3 : 2) : 0);
	address = iwm_dma_addr(&ring->cmd_dma) +
	    ring->cur * sizeof (*cmd);
	scratch = address + sizeof (cmd->hdr) +
	    offsetof(struct iwm_tx_cmd, scratch);
	tx->dram_lsb_ptr = LE_32(scratch);
	tx->dram_msb_ptr = scratch >> 32;
	bcopy(frame, cmd->data + sizeof (*tx), header);
	if (aggregate) {
		struct ieee80211_qosframe *qwh =
		    (void *)(cmd->data + sizeof (*tx));

		/* Native aggregation marker; HT uses implicit immediate BA. */
		qwh->i_qos[0] &= ~IEEE80211_QOS_ACKPOLICY_BA;
	}
	if (management)
		bcopy(frame + header, slot->dma.vaddr, length - header);
	tfd = &ring->desc[ring->cur];
	bzero(tfd, sizeof (*tfd));
	tfd->num_tbs = 3;
	tfd->tbs[0].lo = LE_32(address);
	tfd->tbs[0].hi_n_len = LE_16((address >> 32) | (16U << 4));
	address += 16;
	tfd->tbs[1].lo = LE_32(address);
	tfd->tbs[1].hi_n_len = LE_16((address >> 32) |
	    ((sizeof (cmd->hdr) + sizeof (*tx) + header + pad - 16) << 4));
	if (management) {
		address = iwm_dma_addr(&slot->dma);
		tfd->tbs[2].lo = LE_32(address);
		tfd->tbs[2].hi_n_len = LE_16((address >> 32) |
		    ((length - header) << 4));
	} else if ((error = iwm_tx_map(sc, slot, mp, tfd, header)) != 0) {
		goto out;
	}
	bc = (void *)r->scheduler.vaddr;
	bytes = length + IWM_TX_CRC_SIZE + IWM_TX_DELIMITER_SIZE;
	if (sc->fw.flags & IWM_UCODE_TLV_FLAGS_DW_BC_TABLE)
		bytes = (bytes + 3) / 4;
	bc[ring->qid].tfd_offset[ring->cur] = LE_16(bytes);
	if (ring->cur < IWM_TFD_QUEUE_SIZE_BC_DUP)
		bc[ring->qid].tfd_offset[IWM_TFD_QUEUE_SIZE_MAX + ring->cur] =
		    LE_16(bytes);
	if ((management &&
	    iwm_sync(&slot->dma, DDI_DMA_SYNC_FORDEV) != 0) ||
	    iwm_sync(&ring->cmd_dma, DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&r->tx[ring->qid], DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&r->scheduler, DDI_DMA_SYNC_FORDEV) != 0) {
		error = EIO;
		goto out;
	}
	error = iwm_nic_lock(sc);
	if (error != 0)
		goto out;
	slot->mp = mp;
	slot->ni = ieee80211_ref_node(node);
	slot->generation = r->generation;
	slot->sequence = iwm_u16(frame + 22) >> 4;
	slot->ba_generation = aggregate ? r->association.ba[0].generation : 0;
	slot->transmitted = slot->acknowledged = B_FALSE;
	slot->status = 0;
	slot->expires = ddi_get_lbolt() + drv_usectohz(5000000);
	slot->completed = B_FALSE;
	slot->owned = B_TRUE;
	ring->queued++;
	ring->cur = (ring->cur + 1) % IWM_TX_RING_COUNT;
	if (aggregate)
		r->association.ba[0].next_sequence =
		    IEEE80211_SEQ_ADD(r->association.ba[0].next_sequence, 1);
	r->association.tx_submitted++;
	iwm_wr(sc, IWM_HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);
	iwm_nic_unlock(sc);
out:
	if (error != 0 && slot != NULL && !slot->owned &&
	    iwm_tx_unmap(slot) != 0) {
		r->error = EIO;
		cv_broadcast(&r->cv);
	}
	mutex_exit(&sc->lock);
	return (error);
}

/*
 * ic_genlock and crypto_lock are held. Consume the private header copy on
 * conversion or failure; the framework's original chain is untouched. KCF
 * CCMP requires one complete mblk, including cipher-provided MIC tailroom.
 * reserved describes the MAC plugin's input, before native encap sets WEP.
 */
static mblk_t *
iwm_ccmp_prepare(struct iwm_softc *sc, mblk_t *mp, boolean_t reserved)
{
	static const uint8_t snap[] = { 0xaa, 0xaa, 3, 0, 0, 0 };
	ieee80211com_t *ic = &sc->ic;
	struct ieee80211_key *key;
	const struct ieee80211_cipher *cipher;
	mblk_t *block, *copy;
	size_t total = 0, size, skip, offset, header;
	uint_t fragments = 0;
	boolean_t protected;

	ASSERT(MUTEX_HELD(&ic->ic_genlock));
	ASSERT(MUTEX_HELD(&sc->connection.crypto_lock));
	if (iwm_frame_header(mp->b_rptr, MBLKL(mp), &header) != 0 ||
	    header != ieee80211_hdrspace(ic, mp->b_rptr))
		goto failed;
	protected = (mp->b_rptr[1] & IEEE80211_FC1_WEP) != 0;
	if (!protected) {
		/* Native pre-key EAPOL is clear; WPA data requires a key. */
		if (MBLKL(mp) < header + sizeof (struct ieee80211_llc) ||
		    bcmp(mp->b_rptr + header, snap, sizeof (snap)) ||
		    mp->b_rptr[header + 6] != 0x88 ||
		    mp->b_rptr[header + 7] != 0x8e)
			goto failed;
		return (mp);
	}
	if (!(ic->ic_flags & IEEE80211_F_WPA) ||
	    ic->ic_def_txkey >= IEEE80211_WEP_NKID)
		goto failed;
	key = &ic->ic_nw_keys[ic->ic_def_txkey];
	cipher = key->wk_cipher;
	if (cipher->ic_cipher != IEEE80211_CIPHER_AES_CCM ||
	    !(key->wk_flags & IEEE80211_KEY_SWCRYPT) ||
	    !(key->wk_flags & IEEE80211_KEY_XMIT) ||
	    key->wk_keytsc >= 0xffffffffffffULL)
		goto failed;
	for (block = mp; block != NULL; block = block->b_cont) {
		if (++fragments > IWM_RBUF_SIZE ||
		    block->b_wptr < block->b_rptr ||
		    MBLKL(block) > IWM_RBUF_SIZE - total)
			goto failed;
		total += MBLKL(block);
	}
	skip = header + (reserved ? cipher->ic_header : 0);
	if (total < skip + sizeof (struct ieee80211_llc))
		goto failed;
	size = total + (reserved ? 0 : cipher->ic_header);
	if (size > IWM_RBUF_SIZE ||
	    cipher->ic_trailer > IWM_RBUF_SIZE - size)
		goto failed;
	copy = allocb(size + cipher->ic_trailer, BPRI_MED);
	if (copy == NULL)
		goto failed;
	bcopy(mp->b_rptr, copy->b_wptr, header);
	copy->b_wptr += header;
	bzero(copy->b_wptr, cipher->ic_header);
	copy->b_wptr += cipher->ic_header;
	for (block = mp; block != NULL; block = block->b_cont) {
		offset = MIN(skip, MBLKL(block));
		skip -= offset;
		bcopy(block->b_rptr + offset, copy->b_wptr,
		    MBLKL(block) - offset);
		copy->b_wptr += MBLKL(block) - offset;
	}
	freemsg(mp);
	if (MBLKL(copy) != size || bcmp(copy->b_rptr + header +
	    cipher->ic_header, snap, sizeof (snap)) ||
	    ieee80211_crypto_encap(ic, copy) == NULL) {
		freemsg(copy);
		return (NULL);
	}
	return (copy);
failed:
	freemsg(mp);
	return (NULL);
}

/* crypto_lock and ic_genlock held; no sequence/PN consumed while starting. */
static int
iwm_ba_prepare(struct iwm_softc *sc, ieee80211_node_t *node, mblk_t *copy,
    boolean_t eapol, boolean_t *aggregate, boolean_t *nonqos)
{
	struct ieee80211_tx_ampdu *tap = &node->in_tx_ampdu[WME_AC_BE];
	struct iwm_tx_ba *ba;
	boolean_t eligible;

	*aggregate = *nonqos = B_FALSE;
	if (!(sc->ic.ic_flags_ext & IEEE80211_FEXT_AMPDU_TX) ||
	    !(node->in_flags & IEEE80211_NODE_HT))
		return (0);
	eligible = !eapol && !(copy->b_rptr[16] & 1) &&
	    ieee80211_classify(&sc->ic, copy, node) == WME_AC_BE;
	mutex_enter(&sc->lock);
	if (sc->run == NULL || sc->connection.cancel ||
	    sc->connection.node != node) {
		mutex_exit(&sc->lock);
		return (ENETDOWN);
	}
	ba = &sc->run->association.ba[0];
	*nonqos = (eapol || (copy->b_rptr[16] & 1)) &&
	    ba->state != IWM_BA_CLOSED;
	if (!eligible) {
		mutex_exit(&sc->lock);
		return (0);
	}
	if (sc->connection.wpa &&
	    (sc->ic.ic_def_txkey >= IEEE80211_WEP_NKID ||
	    sc->ic.ic_nw_keys[sc->ic.ic_def_txkey].
	    wk_keylen != 16)) {
		mutex_exit(&sc->lock);
		return (EAGAIN);
	}
	if (ba->state == IWM_BA_CLOSED && !sc->run->ba_queue_used &&
	    !IEEE80211_AMPDU_REQUESTED(tap)) {
		mutex_exit(&sc->lock);
		(void) ieee80211_ampdu_request(node, tap);
		mutex_enter(&sc->lock);
	}
	if (ba->state == IWM_BA_ACTIVE && ba->admission &&
	    ba->generation == sc->run->association.generation &&
	    ba->node == node) {
		/* Unpublished sequence consumption cannot move the SCD ring. */
		node->in_txseqs[0] = ba->next_sequence;
		*aggregate = B_TRUE;
		mutex_exit(&sc->lock);
		return (0);
	}
	if (ba->state != IWM_BA_CLOSED) {
		mutex_exit(&sc->lock);
		return (EAGAIN);
	}
	mutex_exit(&sc->lock);
	return (0);
}

/* MAC owns the returned suffix. A ring-accepted copy consumes its input. */
mblk_t *
iwm_connection_tx(struct iwm_softc *sc, mblk_t *mp)
{
	static const uint8_t snap[] = { 0xaa, 0xaa, 3, 0, 0, 0 };
	mblk_t *copy, *next;
	ieee80211_node_t *node;
	boolean_t reserved, allowed, eapol, aggregate, nonqos;
	uint_t node_flags;
	size_t header, llc;
	int error;

	while (mp != NULL) {
		if (iwm_frame_header(mp->b_rptr, MBLKL(mp), &header) != 0)
			return (mp);
		mutex_enter(&sc->lock);
		if (!sc->connection.running || !sc->connection.tx_admission ||
		    sc->connection.node == NULL) {
			mutex_exit(&sc->lock);
			return (mp);
		}
		node = ieee80211_ref_node(sc->connection.node);
		mutex_exit(&sc->lock);
		/* Copy the mutable header/LLC, retaining payload blocks. */
		reserved = (mp->b_rptr[1] & IEEE80211_FC1_WEP) != 0;
		llc = header + (reserved ? IEEE80211_WEP_HDRLEN +
		    IEEE80211_WEP_EXTIVLEN : 0);
		copy = msgpullup(mp, llc + sizeof (struct ieee80211_llc));
		if (copy == NULL) {
			ieee80211_free_node(node);
			return (mp);
		}
		eapol = bcmp(copy->b_rptr + llc, snap, sizeof (snap)) == 0 &&
		    copy->b_rptr[llc + 6] == 0x88 &&
		    copy->b_rptr[llc + 7] == 0x8e;
		mutex_enter(&sc->connection.crypto_lock);
		mutex_enter(&sc->ic.ic_genlock);
		mutex_enter(&sc->lock);
		allowed = sc->connection.running &&
		    sc->connection.tx_admission && !sc->connection.cancel &&
		    sc->connection.node == node &&
		    (header == sizeof (struct ieee80211_qosframe)) ==
		    ((node->in_flags & (IEEE80211_NODE_HT |
		    IEEE80211_NODE_QOS)) != 0);
		mutex_exit(&sc->lock);
		if (allowed) {
			error = iwm_ba_prepare(sc, node, copy, eapol,
			    &aggregate, &nonqos);
			if (error != 0) {
				freemsg(copy);
				mutex_exit(&sc->ic.ic_genlock);
				mutex_exit(&sc->connection.crypto_lock);
				ieee80211_free_node(node);
				return (mp);
			}
			node_flags = node->in_flags;
			if (!aggregate)
				node->in_flags &= ~IEEE80211_NODE_AMPDU_TX;
			if (nonqos && header ==
			    sizeof (struct ieee80211_qosframe)) {
				/* Separate group/EAPOL from TID0 sequences. */
				bcopy(copy->b_rptr + header, copy->b_rptr + 24,
				    MBLKL(copy) - header);
				copy->b_wptr -= 2;
				copy->b_rptr[0] = IEEE80211_FC0_TYPE_DATA;
				node->in_flags &= ~(IEEE80211_NODE_QOS |
				    IEEE80211_NODE_HT);
			}
			copy = ieee80211_encap(&sc->ic, copy, node);
			node->in_flags = node_flags;
			if (copy != NULL && sc->connection.wpa)
				copy = iwm_ccmp_prepare(sc, copy, reserved);
		} else {
			freemsg(copy);
			copy = NULL;
		}
		mutex_exit(&sc->ic.ic_genlock);
		error = copy == NULL ? ENOMEM :
		    iwm_association_tx(sc, copy, B_FALSE, eapol);
		mutex_exit(&sc->connection.crypto_lock);
		ieee80211_free_node(node);
		if (error != 0) {
			if (copy != NULL)
				freemsg(copy);
			return (mp);
		}
		next = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);
		mp = next;
	}
	return (NULL);
}

/*
 * Thread context, no driver mutex held. Retire all native keys before node,
 * topology or runtime destruction; TX preparation shares this exclusion.
 */
void
iwm_connection_keys_clear(struct iwm_softc *sc)
{
	wl_del_key_t deletion = { 0 };
	uint_t i;

	if (!sc->net_attached)
		return;
	mutex_enter(&sc->connection.crypto_lock);
	for (i = 0; i < IEEE80211_WEP_NKID; i++) {
		deletion.idk_keyix = i;
		(void) ieee80211_setprop(&sc->ic, "", MAC_PROP_WL_DELKEY,
		    sizeof (deletion), &deletion);
	}
	mutex_enter(&sc->ic.ic_genlock);
	sc->ic.ic_def_txkey = IEEE80211_KEYIX_NONE;
	mutex_exit(&sc->ic.ic_genlock);
	mutex_exit(&sc->connection.crypto_lock);
}

/* crypto_lock is held; management builders have stopped. */
void
iwm_connection_config_clear(struct iwm_softc *sc)
{
	wl_wpa_ie_t ie = { 0 };
	wl_wpa_t wpa = { 0 };
	wl_del_key_t deletion = { 0 };
	struct iwm_connection *c = &sc->connection;
	uint_t i;

	ASSERT(MUTEX_HELD(&c->crypto_lock));
	if (c->clear_ie) {
		(void) ieee80211_setprop(&sc->ic, "", MAC_PROP_WL_SETOPTIE,
		    sizeof (ie), &ie);
		c->clear_ie = B_FALSE;
		mutex_enter(&sc->lock);
		sc->desired_bssid_valid = B_FALSE;
		bzero(sc->desired_bssid, sizeof (sc->desired_bssid));
		mutex_exit(&sc->lock);
	}
	if (c->disable_wpa) {
		for (i = 0; i < IEEE80211_WEP_NKID; i++) {
			deletion.idk_keyix = i;
			(void) ieee80211_setprop(&sc->ic, "",
			    MAC_PROP_WL_DELKEY, sizeof (deletion), &deletion);
		}
		(void) ieee80211_setprop(&sc->ic, "", MAC_PROP_WL_WPA,
		    sizeof (wpa), &wpa);
		mutex_enter(&sc->ic.ic_genlock);
		sc->ic.ic_def_txkey = IEEE80211_KEYIX_NONE;
		sc->ic.ic_des_esslen = 0;
		bzero(sc->ic.ic_des_essid, sizeof (sc->ic.ic_des_essid));
		mutex_exit(&sc->ic.ic_genlock);
		mutex_enter(&sc->lock);
		c->wpa = B_FALSE;
		c->configuration = 0;
		c->esslen = c->channel = 0;
		bzero(c->essid, sizeof (c->essid));
		mutex_exit(&sc->lock);
		c->disable_wpa = B_FALSE;
	}
}

/*
 * CONNECT owns the runtime and station topology; sc->lock is held. This is
 * called before delegating AUTH to net80211, which can immediately send a
 * management frame. A command response alone never permits that delegation.
 */
static int
iwm_protect_session(struct iwm_softc *sc, uint16_t beacon_interval)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_time_event_state *t;
	struct iwm_time_event_cmd cmd;
	clock_t end;
	int error;

	ASSERT(MUTEX_HELD(&sc->lock));
	ASSERT(sc->operation == IWM_OP_CONNECT);
	if (r == NULL || r->image != IWM_FW_REGULAR ||
	    r->state != IWM_REGULAR_IDLE || r->cancel_requested ||
	    beacon_interval == 0)
		return (EINVAL);
	t = &r->protection;
	if (t->submitted)
		return (EBUSY);
	bzero(&cmd, sizeof (cmd));
	cmd.action = LE_32(IWM_FW_CTXT_ACTION_ADD);
	cmd.id = LE_32(IWM_TE_BSS_STA_AGGRESSIVE_ASSOC);
	cmd.max_delay = LE_32(beacon_interval / 2);
	cmd.interval = LE_32(1);
	cmd.duration = LE_32((uint32_t)beacon_interval * 2);
	cmd.repeat = 1;
	cmd.policy = LE_16(IWM_TE_HOST_START | IWM_TE_HOST_END |
	    IWM_TE_START_IMMEDIATELY);
	/* Station MAC id/color is 0; firmware assigns the event UID. */
	t->generation = r->generation;
	t->submitted = B_TRUE;
	error = iwm_control(sc, IWM_TIME_EVENT_CMD, &cmd, sizeof (cmd));
	if (error != 0)
		return (t->error = error);
	if (t->error != 0)
		return (t->error);
	if (!t->responded || !t->accepted)
		return (t->error = EPROTO);
	/* TU is 1024us. The uint16_t interval bounds this addition. */
	end = ddi_get_lbolt() + drv_usectohz(
	    (uint32_t)(beacon_interval / 2) * 1024 + IWM_WAIT_US);
	while (!t->started && !t->ended && t->error == 0 &&
	    r->error == 0 && !r->cancel_requested) {
		if (cv_timedwait(&r->cv, &sc->lock, end) == -1)
			break;
	}
	if (t->error != 0)
		return (t->error);
	if (r->error != 0)
		return (t->error = r->error);
	if (r->cancel_requested)
		return (t->error = ECANCELED);
	if (!t->started || t->ended)
		return (t->error = ETIMEDOUT);
	return (0);
}

/* sc->lock held; command completion and event END are distinct observations. */
static int
iwm_unprotect_session(struct iwm_softc *sc)
{
	struct iwm_time_event_state *t = &sc->run->protection;
	struct iwm_time_event_cmd cmd;
	int error;

	if (!t->active)
		return (0);
	if (!t->accepted || t->removing)
		return (EPROTO);
	bzero(&cmd, sizeof (cmd));
	cmd.action = LE_32(IWM_FW_CTXT_ACTION_REMOVE);
	cmd.id = LE_32(t->uid);
	cmd.id_and_color = LE_32(t->id_color);
	t->removing = B_TRUE;
	error = iwm_control(sc, IWM_TIME_EVENT_CMD, &cmd, sizeof (cmd));
	if (error == 0 && !t->removed)
		error = t->error != 0 ? t->error : EPROTO;
	return (error);
}

/* API36 quota v2; a single binding receives the available quota. */
static int
iwm_association_quota(struct iwm_softc *sc, boolean_t running)
{
	struct iwm_time_quota_data quota[4];
	uint_t i;

	if (sc->fw.capa[1] & (1U << 12))
		return (0);
	if (!iwm_command_version(&sc->fw, 0x2c, 2))
		return (ENOTSUP);
	bzero(quota, sizeof (quota));
	for (i = 0; i < 4; i++)
		quota[i].id_and_color = LE_32(UINT32_MAX);
	if (sc->run->association.binding) {
		quota[0].id_and_color = 0;
		quota[0].quota = LE_32(running ? 128 : 0);
	} else if (running) {
		return (EINVAL);
	}
	return (iwm_control(sc, 0x2c, quota, sizeof (quota)));
}

static int
iwm_association_sf(struct iwm_softc *sc, boolean_t running)
{
	uint32_t command[23];
	uint_t i;

	bzero(command, sizeof (command));
	command[0] = LE_32(running ? 1 : 3);
	command[1] = LE_32(4096);
	command[2] = LE_32(running ? 4096 : 8192);
	for (i = 3; i < 13; i++)
		command[i] = LE_32(1000000);
	for (i = 0; i < 5; i++) {
		command[13 + 2 * i] = LE_32(running ?
		    (i == 2 ? 10016 : 2016) : 400);
		command[14 + 2 * i] = LE_32(running ?
		    (i == 2 ? 2016 : 320) : 160);
	}
	return (iwm_control(sc, 0xd1, command, sizeof (command)));
}

/* Donor RUN stop retains the legacy PHY/MAC/binding/station and queues. */
static int
iwm_association_run_stop(struct iwm_softc *sc)
{
	struct iwm_association *a = &sc->run->association;
	int error;

	if (!a->run_configured)
		return (0);
	if ((error = iwm_association_sf(sc, B_FALSE)) != 0 ||
	    (error = iwm_association_quota(sc, B_FALSE)) != 0)
		return (error);
	/* Legacy power policy has no station PM or beacon filter to disable. */
	error = iwm_association_mac(sc, IWM_FW_CTXT_ACTION_MODIFY,
	    B_FALSE);
	if (error == 0)
		a->run_configured = B_FALSE;
	return (error);
}

/* No native RUN or public UP until all these commands have completed. */
static int
iwm_association_run(struct iwm_softc *sc)
{
	struct iwm_association *a = &sc->run->association;
	struct iwm_mac_power_cmd power;
	uint8_t multicast[12];
	uint16_t device_power[2] = { LE_16(1), 0 };
	uint32_t keepalive;
	int error;

	/* Partial RUN updates also require RUN-stop before topology removal. */
	a->run_configured = B_TRUE;
	if ((error = iwm_association_station(sc, B_TRUE, B_FALSE)) != 0 ||
	    (error = iwm_association_mac(sc, IWM_FW_CTXT_ACTION_MODIFY,
	    B_TRUE)) != 0 ||
	    (error = iwm_association_sf(sc, B_TRUE)) != 0)
		return (error);
	bzero(multicast, sizeof (multicast));
	multicast[0] = 1;
	multicast[3] = 1;
	bcopy(sc->connection.node->in_bssid, multicast + 4, 6);
	if ((error = iwm_control(sc, 0xd0, multicast,
	    sizeof (multicast))) != 0 ||
	    (error = iwm_control(sc, 0x77, device_power,
	    sizeof (device_power))) != 0)
		return (error);
	bzero(&power, sizeof (power));
	/* Allow device idle, but do not enable station power management. */
	power.flags = LE_16(1);
	keepalive = (3U * a->dtim_period * sc->connection.node->in_intval +
	    999) / 1000;
	power.keep_alive_seconds = LE_16(MAX(25, keepalive));
	if ((error = iwm_control(sc, 0xa9, &power, sizeof (power))) != 0 ||
	    (error = iwm_association_quota(sc, B_TRUE)) != 0)
		return (error);
	return (iwm_unprotect_session(sc));
}

/* Thread context. Slot ownership clears under lock, native refs outside it. */
static int
iwm_association_reclaim(struct iwm_softc *sc, boolean_t stopped)
{
	struct iwm_association *a = &sc->run->association;
	struct iwm_tx_ring *ring;
	struct iwm_tx_data *slot;
	mblk_t *mp;
	ieee80211_node_t *node;
	uint_t ac;
	int error = 0;

	ASSERT(MUTEX_HELD(&sc->lock));
	ASSERT(!stopped || sc->run->stopped);
	for (ac = 0; ac < IWM_ASSOC_TX_RINGS; ac++) {
		ring = &a->tx[ac];
		while (ring->queued != 0) {
			slot = &ring->data[ring->tail];
			ASSERT(slot->owned);
			if (!stopped && !slot->completed) {
				if (ddi_get_lbolt() >= slot->expires)
					error = ETIMEDOUT;
				break;
			}
			if (slot->mapped != 0) {
				if (iwm_tx_unmap(slot) != 0)
					return (EIO);
			} else if (iwm_sync(&slot->dma,
			    DDI_DMA_SYNC_FORCPU) != 0) {
				return (EIO);
			}
			mp = slot->mp;
			node = slot->ni;
			if (!stopped && sc->connection.tx_admission &&
			    (slot->status & 0xff) != 1 &&
			    (slot->status & 0xff) != 2 &&
			    (mp->b_rptr[0] & IEEE80211_FC0_TYPE_MASK) ==
			    IEEE80211_FC0_TYPE_MGT)
				error = EIO;
			slot->mp = NULL;
			slot->ni = NULL;
			slot->owned = slot->completed = B_FALSE;
			slot->transmitted = slot->acknowledged = B_FALSE;
			slot->ba_generation = 0;
			ring->queued--;
			ring->tail = (ring->tail + 1) % IWM_TX_RING_COUNT;
			a->tx_completed++;
			mutex_exit(&sc->lock);
			freemsg(mp);
			ieee80211_free_node(node);
			mutex_enter(&sc->lock);
		}
		/* Failed unbinds can retain unpublished block references. */
		if (stopped) {
			uint_t i;

			for (i = 0; i < IWM_TX_RING_COUNT; i++) {
				if (iwm_tx_unmap(&ring->data[i]) != 0)
					return (EIO);
			}
		}
	}
	return (error);
}

/* Only after queues are disabled, or the hardware stop has proved DMA idle. */
static int
iwm_association_free(struct iwm_softc *sc)
{
	struct iwm_association *a = &sc->run->association;
	uint_t ac, i;

	if (iwm_association_queues_check(sc->run,
	    IWM_QUEUES_RELEASED) != 0)
		return (EPROTO);
	for (ac = 0; ac < IWM_ASSOC_TX_RINGS; ac++) {
		ASSERT(a->tx[ac].queued == 0);
		for (i = 0; i < IWM_TX_RING_COUNT; i++) {
			if (iwm_dma_free(&a->tx[ac].data[i].dma) != 0)
				return (EIO);
		}
		if (iwm_dma_free(&a->tx[ac].cmd_dma) != 0)
			return (EIO);
	}
	return (0);
}

/*
 * Caller owns the public connection operation, keeping runtime alive. This
 * does not start firmware and is never called by the passive scan path.
 */
int
iwm_lar_prepare(struct iwm_softc *sc, uint_t channel)
{
	struct iwm_runtime *r;
	uint8_t command[IWM_MCC_COMMAND_SIZE];
	int error;

	mutex_enter(&sc->lock);
	r = sc->run;
	if (r == NULL || !sc->identity.valid ||
	    r->image != IWM_FW_REGULAR || r->state != IWM_REGULAR_IDLE ||
	    r->cancel_requested || r->error != 0) {
		error = ENXIO;
		goto out;
	}
	/* GET_CURRENT accepts either source-aware API or multi-MCC support. */
	if ((sc->identity.lar & 7) == 0 ||
	    (sc->fw.capa[0] & (1U << 1)) == 0 ||
	    ((sc->fw.api[0] & (1U << 9)) == 0 &&
	    (sc->fw.capa[0] & (1U << 29)) == 0) ||
	    (sc->fw.capa[2] & (1U << 9)) == 0) {
		error = ENOTSUP;
		goto out;
	}
	if (channel == 0 || channel > 13) {
		error = EINVAL;
		goto out;
	}
	if (!r->lar.attempted) {
		r->lar.attempted = B_TRUE;
		iwm_lar_command(command);
		error = iwm_nic_lock(sc);
		if (error == 0) {
			error = iwm_control(sc, IWM_MCC_UPDATE_CMD, command,
			    sizeof (command));
			iwm_nic_unlock(sc);
		}
		if (error == 0)
			error = iwm_lar_parse(&r->lar, r->response,
			    r->response_len);
		r->lar.error = error;
		if (error != 0)
			dev_err(sc->dip, CE_WARN, "!iwm LAR error=%d "
			    "status=%u mcc=%04x source=%u count=%u",
			    error, r->lar.status, r->lar.mcc,
			    r->lar.source, r->lar.count);
	}
	error = r->lar.error;
	if (error == 0)
		error = iwm_lar_channel(&r->lar, sc->identity.channels,
		    channel);
out:
	mutex_exit(&sc->lock);
	return (error);
}

/* This path has no PHY_CONTEXT, MAC, binding or normal-station command. */
static int
iwm_scan_configure(struct iwm_softc *sc)
{
	struct iwm_scan_state *s = &sc->run->scan;
	struct iwm_scd_txq_cfg_cmd queue;
	struct iwm_add_sta_cmd station;
	uint8_t config[sizeof (struct iwm_scan_config) + IWM_SCAN_CHANNELS];
	struct iwm_scan_config *cfg = (void *)config;
	uint32_t flags;
	int error;

	if (sc->run->image != IWM_FW_REGULAR ||
	    sc->run->state != IWM_REGULAR_IDLE || !s->attached ||
	    !(sc->fw.capa[0] & (1U << 12)) ||
	    !(sc->fw.api[0] & (1U << 30)))
		return (ENOTSUP);
	if (s->configured)
		return (0);
	bzero(&queue, sizeof (queue));
	queue.sta_id = IWM_AUX_STA;
	queue.tid = 8;
	queue.scd_queue = IWM_AUX_QUEUE;
	queue.enable = 1;
	queue.tx_fifo = 5;
	queue.window = 64;
	if ((error = iwm_checkpoint(sc, "before-aux-queue")) != 0)
		return (error);
	if ((error = iwm_nic_lock(sc)) != 0)
		return (error);
	/* Donor queue setup publishes zero, never a host frame. */
	iwm_wr(sc, IWM_HBUS_TARG_WRPTR, IWM_AUX_QUEUE << 8);
	error = iwm_control(sc, 0x1d, &queue, sizeof (queue));
	iwm_nic_unlock(sc);
	if (error != 0)
		return (error);
	s->aux_queue = B_TRUE;
	if ((error = iwm_checkpoint(sc, "aux-queue")) != 0)
		return (error);
	bzero(&station, sizeof (station));
	station.sta_id = IWM_AUX_STA;
	station.station_type = 4;
	station.mac_id_n_color = LE_32(4);
	station.tfd_queue_msk = LE_32(1U << IWM_AUX_QUEUE);
	station.tid_disable_tx = LE_16(0xffff);
	if ((error = iwm_control(sc, 0x18, &station, sizeof (station))) != 0)
		return (error);
	if (sc->run->response_len != 4 ||
	    (iwm_u32(sc->run->response) & 0xff) != 1)
		return (EIO);
	s->aux_station = B_TRUE;
	if ((error = iwm_checkpoint(sc, "aux-station")) != 0)
		return (error);
	bzero(config, sizeof (config));
	/* ACTIVATE, forbid CHUB, set masks/station/times/rates/MAC/channels. */
	flags = 1U | (1U << 2) | (15U << 8) | (7U << 13) |
	    (1U << 17) | (s->channels << 26);
	cfg->flags = LE_32(flags);
	cfg->tx_chains = LE_32(sc->identity.tx_ant);
	cfg->rx_chains = LE_32(sc->identity.rx_ant);
	cfg->legacy_rates = LE_32(0x0fff0fff);
	cfg->dwell_active = 10;
	cfg->dwell_passive = 110;
	cfg->dwell_fragmented = 44;
	cfg->dwell_extended = 90;
	bcopy(sc->identity.mac, cfg->mac_addr, 6);
	cfg->bcast_sta_id = IWM_AUX_STA;
	bcopy(s->channel, cfg->channel_array, s->channels);
	if ((error = iwm_checkpoint(sc, "scan-config-zero-contexts")) != 0)
		return (error);
	if ((error = iwm_control(sc, 0x10c, config, sizeof (config))) != 0)
		return (error);
	s->configured = B_TRUE;
	return (iwm_checkpoint(sc, "scan-configured"));
}

/* Called with sc->lock; drops it only while native stack owns the copy. */
static int
iwm_scan_deliver(struct iwm_softc *sc)
{
	struct iwm_scan_state *s = &sc->run->scan;
	struct iwm_scan_frame f;
	ieee80211_node_t *node;
	uint_t subtype;
	int error = 0;

	while (s->queued != 0 && s->error == 0 && sc->run->error == 0 &&
	    !sc->run->cancel_requested) {
		f = s->frames[s->head];
		s->frames[s->head].mp = NULL;
		s->head = (s->head + 1) % IWM_SCAN_RX_LIMIT;
		s->queued--;
		subtype = f.mp->b_rptr[0];
		s->delivering = B_TRUE;
		mutex_exit(&sc->lock);
		sc->ic.ic_curchan = &sc->ic.ic_sup_channels[f.channel];
		node = ieee80211_find_rxnode(&sc->ic,
		    (struct ieee80211_frame *)f.mp->b_rptr);
		if (node != NULL) {
			ieee80211_input(&sc->ic, f.mp, node, f.rssi,
			    f.timestamp);
			ieee80211_free_node(node);
		} else {
			freemsg(f.mp);
		}
		mutex_enter(&sc->lock);
		s->delivering = B_FALSE;
		if (node == NULL)
			continue;
		s->accepted++;
		if (subtype == 0x80)
			s->beacons++;
		else
			s->probes++;
		if (s->accepted == 1)
			error = iwm_checkpoint(sc, "scan-first-frame");
		if (error != 0)
			return (error);
	}
	if (s->error != 0)
		return (s->error);
	if (sc->run->error != 0)
		return (sc->run->error);
	return (sc->run->cancel_requested ? ECANCELED : 0);
}

static void
iwm_scan_node(void *arg, ieee80211_node_t *node)
{
	struct iwm_softc *sc = arg;

	if (node != sc->ic.ic_bss)
		sc->run->scan.nodes++;
	/* Read-only FBT/MDB observes the native node here before detach. */
}

/* Full passive-scan bound also bounds abort termination, without retries. */
static clock_t
iwm_scan_ticks(const struct iwm_scan_state *s)
{
	return (drv_usectohz(2000000 + s->channels * (110000 + 300 * 1024)));
}

/* Driver lock held. Command response and final scan event are independent. */
static int
iwm_scan_terminate(struct iwm_softc *sc)
{
	struct iwm_scan_state *s = &sc->run->scan;
	uint32_t abort[2] = { LE_32(s->uid), 0 };
	clock_t end;
	int error = 0;

	s->accepting = B_FALSE;
	/* Recheck under the lock: a recorded terminal needs no abort. */
	if (s->outstanding && !s->complete) {
		if (s->abort_requested || sc->run->error != 0 ||
		    sc->run->control_command)
			return (EIO);
		s->abort_requested = B_TRUE;
		s->abort_commands++;
		error = iwm_control(sc, 0x10e, abort, sizeof (abort));
		if (error != 0)
			return (error);
		end = ddi_get_lbolt() + iwm_scan_ticks(s);
		while (!s->complete && sc->run->error == 0) {
			if (cv_timedwait(&sc->run->cv, &sc->lock, end) == -1)
				break;
		}
		if (sc->run->error != 0)
			return (sc->run->error);
		if (!s->complete)
			return (ETIMEDOUT);
	}
	if (s->complete) {
		s->terminal_consumed = B_TRUE;
		if (s->completion_status != IWM_SCAN_COMPLETED &&
		    s->completion_status != IWM_SCAN_ABORTED)
			error = EIO;
	}
	return (error);
}

/* One scan only. The caller owns the eventual hardware stop on every result. */
static int
iwm_passive_scan(struct iwm_softc *sc)
{
	struct iwm_scan_state *s = &sc->run->scan;
	uint8_t request[sizeof (struct iwm_scan_v7) +
	    IWM_SCAN_CHANNELS * sizeof (struct iwm_scan_channel_cfg_umac) +
	    sizeof (struct iwm_scan_req_umac_tail_v1)];
	clock_t end;
	int error;

	if (s->running || s->cancelled || s->complete)
		return (EBUSY);
	if ((error = iwm_scan_configure(sc)) != 0)
		return (error);
	if (sc->run->cancel_requested)
		return (ECANCELED);
	if ((error = iwm_scan_request(s, sc->identity.mac, request,
	    sizeof (request))) != 0)
		return (error);
	s->running = B_TRUE;
	mutex_exit(&sc->lock);
	ieee80211_node_table_reset(&sc->ic.ic_scan);
	sc->ic.ic_flags &= ~IEEE80211_F_ASCAN;
	sc->ic.ic_flags |= IEEE80211_F_SCAN | IEEE80211_F_SCANONLY;
	error = iwm_scan_newstate(&sc->ic, IEEE80211_S_SCAN, 0);
	mutex_enter(&sc->lock);
	if (error == 0 && sc->run->cancel_requested)
		error = ECANCELED;
	if (error == 0)
		error = iwm_checkpoint(sc, "scan-submit-zero-contexts");
	if (error == 0) {
		s->uid = IWM_SCAN_UID;
		s->submitted = B_TRUE;
		s->outstanding = B_TRUE;
		s->accepting = B_TRUE;
		error = iwm_control(sc, 0x10d, request, sizeof (request));
		if (error == 0 && !s->complete)
			error = iwm_checkpoint(sc, "scan-running");
	}
	/* 110ms dwell + 300 TU adaptive budget per channel, plus 2s. */
	end = ddi_get_lbolt() + iwm_scan_ticks(s);
	while (error == 0 && sc->run->error == 0 && s->error == 0) {
		if (sc->run->cancel_requested) {
			error = ECANCELED;
			break;
		}
		error = iwm_scan_deliver(sc);
		if (error != 0 || s->complete)
			break;
		if (cv_timedwait(&sc->run->cv, &sc->lock, end) == -1) {
			error = ETIMEDOUT;
			break;
		}
	}
	if (s->error != 0)
		error = s->error;
	else if (error == 0)
		error = sc->run->error;
	if (error == 0 && s->completion_status != IWM_SCAN_COMPLETED)
		error = EIO;
	if (error == 0)
		error = iwm_checkpoint(sc, "scan-complete");
	s->abort_error = iwm_scan_terminate(sc);
	/* A timeout retains ownership until hardware stop/reset. */
	if (!s->outstanding)
		s->running = B_FALSE;
	iwm_scan_drain(sc);
	s->cancelled = B_TRUE;
	mutex_exit(&sc->lock);
	ieee80211_cancel_scan(&sc->ic);
	sc->ic.ic_flags &= ~IEEE80211_F_SCANONLY;
	(void) iwm_scan_newstate(&sc->ic, IEEE80211_S_INIT, 0);
	ieee80211_iterate_nodes(&sc->ic.ic_scan, iwm_scan_node, sc);
	mutex_enter(&sc->lock);
	dev_err(sc->dip, CE_NOTE, "!iwm passive scan error=%d abort=%d "
	    "complete=%u status=%u frames=%u beacon=%u probe=%u nodes=%u "
	    "malformed=%u dropped=%u overflow=%u xmit=%u state-errors=%u",
	    error, s->abort_error, s->complete, s->completion_status,
	    s->accepted,
	    s->beacons, s->probes, s->nodes, s->malformed, s->dropped,
	    s->overflow, s->xmit_calls, s->state_violations);
	if (error == 0)
		error = iwm_checkpoint(sc, "scan-cancelled");
	return (error != 0 ? error : s->abort_error);
}

static int
iwm_tx_ant_config(struct iwm_softc *sc)
{
	uint32_t mask = (sc->fw.phy_config >> 16) & 7;

	mask &= sc->identity.tx_ant;
	if (mask == 0)
		return (EINVAL);
	mask = LE_32(mask);
	return (iwm_control(sc, IWM_TX_ANT_CONFIGURATION_CMD,
	    &mask, sizeof (mask)));
}

static int
iwm_phy_config(struct iwm_softc *sc)
{
	struct iwm_fw_image *image = &sc->fw.image[sc->run->image];
	uint32_t command[3];

	command[0] = LE_32(sc->fw.phy_config);
	command[1] = LE_32(image->calib_flow);
	command[2] = LE_32(image->calib_event);
	return (iwm_control(sc, IWM_PHY_CONFIGURATION_CMD,
	    command, sizeof (command)));
}

static int
iwm_calibrate(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint32_t sf[23];
	uint_t i;
	clock_t deadline;
	int error;

	if ((iwm_rd(sc, IWM_CSR_GP_CNTRL) &
	    IWM_CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW) == 0)
		return (EPERM);
	/* Donor SF_INIT_OFF, unassociated default watermarks and timers. */
	bzero(sf, sizeof (sf));
	sf[0] = LE_32(3);
	sf[1] = LE_32(4096);
	sf[2] = LE_32(8192);
	for (i = 3; i < 13; i++)
		sf[i] = LE_32(1000000);
	for (i = 13; i < 23; i += 2) {
		sf[i] = LE_32(400);
		sf[i + 1] = LE_32(160);
	}
	if ((error = iwm_control(sc, IWM_REPLY_SF_CFG_CMD,
	    sf, sizeof (sf))) != 0 || (error = iwm_tx_ant_config(sc)) != 0)
		return (error);
	r->state = IWM_INIT_CALIBRATING;
	if ((error = iwm_phy_config(sc)) != 0)
		return (error);
	if (iwm_checkpoint(sc, "INIT-calibration-command") != 0)
		return (EIO);
	deadline = ddi_get_lbolt() + drv_usectohz(IWM_CALIB_US);
	while (!iwm_calibration_complete(r) && r->error == 0) {
		if (cv_timedwait(&r->cv, &sc->lock, deadline) < 0)
			return (ETIMEDOUT);
	}
	if (r->error != 0)
		return (r->error);
	if (!iwm_calibration_complete(r))
		return (EPROTO);
	for (i = 0; i < IWM_PHY_DB_ENTRIES; i++)
		dev_err(sc->dip, CE_NOTE, "!iwm PHY DB slot=%u length=%lu",
		    i, (ulong_t)r->phy_db[i].length);
	r->state = IWM_PHY_DB_COMPLETE;
	dev_err(sc->dip, CE_NOTE, "!iwm INIT calibration complete, %u records",
	    r->phy_notifications);
	return (iwm_checkpoint(sc, "INIT-calibration-complete"));
}

static int
iwm_nvm_chunk(struct iwm_softc *sc, uint_t section, uint_t offset,
    uint_t requested, uint_t *received)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_device_cmd *cmd = (void *)r->commands.vaddr;
	struct iwm_tfd *desc = (void *)r->tx[r->cmdqid].vaddr;
	struct iwm_nvm_access_cmd *nvm;
	enum iwm_proto_reason reason;
	uint64_t addr;
	uint32_t low;
	uint_t n;
	uint16_t bytes;
	struct iwm_agn_scd_bc_tbl *bc = (void *)r->scheduler.vaddr;
	int error;

	if (section >= IWM_NVM_NUM_OF_SECTIONS || offset >= IWM_NVM_LIMIT ||
	    requested > IWM_NVM_CHUNK || requested > IWM_NVM_LIMIT - offset ||
	    r->state != IWM_NVM_READING || r->error != 0)
		return (EINVAL);
	cmd += r->cmdcur;
	desc += r->cmdcur;
	bzero(cmd, sizeof (*cmd));
	bzero(desc, sizeof (*desc));
	cmd->hdr.code = IWM_NVM_ACCESS_CMD;
	cmd->hdr.qid = r->cmdqid;
	cmd->hdr.idx = r->cmdcur;
	nvm = (void *)cmd->data;
	nvm->op_code = IWM_NVM_READ_OPCODE;
	nvm->type = LE_16(section);
	/* Preserve the offset instead of the donor's unconditional zero. */
	nvm->offset = LE_16(offset);
	nvm->length = LE_16(requested);
	addr = iwm_dma_addr(&r->commands) + r->cmdcur * sizeof (*cmd);
	low = LE_32((uint32_t)addr);
	bcopy(&low, &desc->tbs[0].lo, sizeof (low));
	desc->tbs[0].hi_n_len = LE_16((addr >> 32) |
	    ((sizeof (cmd->hdr) + sizeof (*nvm)) << 4));
	desc->num_tbs = 1;
	/* Donor command accounting includes CRC and delimiter only. */
	bytes = IWM_TX_CRC_SIZE + IWM_TX_DELIMITER_SIZE;
	if (sc->fw.flags & IWM_UCODE_TLV_FLAGS_DW_BC_TABLE)
		bytes /= 4;
	bc[r->cmdqid].tfd_offset[r->cmdcur] = LE_16(bytes);
	if (r->cmdcur < IWM_TFD_QUEUE_SIZE_BC_DUP)
		bc[r->cmdqid].tfd_offset[IWM_TFD_QUEUE_SIZE_MAX + r->cmdcur] =
		    LE_16(bytes);
	if (iwm_sync(&r->scheduler, DDI_DMA_SYNC_FORDEV) != 0)
		return (EIO);
	if (iwm_sync(&r->commands, DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&r->tx[r->cmdqid], DDI_DMA_SYNC_FORDEV) != 0)
		return (EIO);
	r->command_done = B_FALSE;
	r->command_pending = B_TRUE;
	r->response_len = 0;
	r->diagnostic.section = section;
	r->diagnostic.offset = offset;
	r->diagnostic.requested = requested;
	r->diagnostic.expected_sequence = r->cmdqid << 8 | r->cmdcur;
	r->diagnostic.pending = B_TRUE;
	/* No external input or packet can select a queue. */
	iwm_wr(sc, IWM_HBUS_TARG_WRPTR,
	    r->cmdqid << 8 | ((r->cmdcur + 1) % IWM_TX_RING_COUNT));
	error = iwm_wait(sc, &r->command_done);
	r->command_pending = B_FALSE;
	if (error != 0)
		return (error);
	r->cmdcur = (r->cmdcur + 1) % IWM_TX_RING_COUNT;
	r->diagnostic = r->response_diagnostic;
	r->diagnostic.actual_offset = iwm_u16(r->response);
	r->diagnostic.count = iwm_u16(r->response + 2);
	r->diagnostic.actual_type = iwm_u16(r->response + 4);
	r->diagnostic.status = iwm_u16(r->response + 6);
	r->diagnostic.payload = r->response_len;
	r->diagnostic.nvm_valid = B_TRUE;
	reason = iwm_nvm_check(&r->diagnostic);
	if (reason == IWM_PROTO_NVM_STATUS) {
		/* Failed sections are absent; fields are not success data. */
		r->diagnostic.reason = reason;
		dev_err(sc->dip, CE_NOTE, "!iwm NVM section%u read failed "
		    "status=%u; section remains absent", section,
		    r->diagnostic.status);
		return (ENOENT);
	}
	if (reason != IWM_PROTO_OK) {
		iwm_proto_error(sc, reason);
		return (EPROTO);
	}
	n = r->diagnostic.count;
	bcopy(r->response + 8, r->nvm[section] + offset, n);
	*received = n;
	return (iwm_checkpoint(sc, "NVM-chunk"));
}

static boolean_t
iwm_mac_valid(const uint8_t *mac)
{
	uint_t i;
	uint8_t any = 0;
	static const uint8_t reserved[6] = { 2, 0xcc, 0xaa, 0xff, 0xee, 0 };

	for (i = 0; i < 6; i++)
		any |= mac[i];
	return (any != 0 && !(mac[0] & 1) && bcmp(mac, reserved, 6) != 0);
}

static boolean_t
iwm_nvm_sections_valid(const struct iwm_runtime *r)
{
	return (r->nvm_len[1] >= 8 && r->nvm_len[3] >= 102 &&
	    r->nvm_len[12] >= 8 &&
	    (r->nvm_len[10] >= 8 || r->nvm_len[11] >= 8));
}

static int
iwm_nvm_parse(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint_t i, laroff;
	uint32_t a, b;
	static const uint8_t channels[] = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
		36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92,
		96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
		149, 153, 157, 161, 165, 169, 173, 177, 181
	};

	if (!iwm_nvm_sections_valid(r)) {
		dev_err(sc->dip, CE_WARN, "!iwm NVM mandatory sections missing "
		    "sw=%lu regulatory=%lu phy-sku=%lu hw-8000=%lu "
		    "mac-override=%lu", (ulong_t)r->nvm_len[1],
		    (ulong_t)r->nvm_len[3], (ulong_t)r->nvm_len[12],
		    (ulong_t)r->nvm_len[10], (ulong_t)r->nvm_len[11]);
		return (EINVAL);
	}
	sc->identity.nvm_version = iwm_u16(r->nvm[1]);
	laroff = sc->identity.nvm_version < 0xe39 ?
	    IWM_NVM_LAR_OFFSET_8000_OLD :
	    IWM_NVM_LAR_OFFSET_8000;
	if (laroff * 2 + 2 > r->nvm_len[3])
		return (EINVAL);
	sc->identity.lar = iwm_u16(r->nvm[3] + laroff * 2);
	sc->identity.radio_cfg = iwm_u32(r->nvm[12]);
	sc->identity.sku = iwm_u32(r->nvm[12] + 4);
	sc->identity.tx_ant =
	    IWM_NVM_RF_CFG_TX_ANT_MSK_8000(sc->identity.radio_cfg);
	sc->identity.rx_ant =
	    IWM_NVM_RF_CFG_RX_ANT_MSK_8000(sc->identity.radio_cfg);
	if (r->nvm_len[11] >= 8)
		bcopy(r->nvm[11] + 2, sc->identity.mac, 6);
	if (!iwm_mac_valid(sc->identity.mac)) {
		if (r->nvm_len[10] == 0 || iwm_nic_lock(sc) != 0)
			return (EINVAL);
		a = iwm_prph_read(sc, IWM_WFMP_MAC_ADDR_0);
		b = iwm_prph_read(sc, IWM_WFMP_MAC_ADDR_1);
		iwm_nic_unlock(sc);
		sc->identity.mac[0] = a >> 24;
		sc->identity.mac[1] = a >> 16;
		sc->identity.mac[2] = a >> 8;
		sc->identity.mac[3] = a;
		sc->identity.mac[4] = b >> 8;
		sc->identity.mac[5] = b;
	}
	if (!iwm_mac_valid(sc->identity.mac) || sc->identity.tx_ant == 0 ||
	    sc->identity.rx_ant == 0)
		return (EINVAL);
	dev_err(sc->dip, CE_NOTE, "!iwm NVM version=%04x radio=%08x sku=%08x "
	    "TXant=%x RXant=%x bands24=%u bands5=%u LAR=%04x hwaddrs=%u",
	    sc->identity.nvm_version, sc->identity.radio_cfg, sc->identity.sku,
	    sc->identity.tx_ant, sc->identity.rx_ant,
	    !!(sc->identity.sku & IWM_NVM_SKU_CAP_BAND_24GHZ),
	    !!(sc->identity.sku & IWM_NVM_SKU_CAP_BAND_52GHZ), sc->identity.lar,
	    iwm_u16(r->nvm[1] + 6));
	dev_err(sc->dip, CE_NOTE, "!iwm NVM MAC %02x:%02x:%02x:%02x:%02x:%02x",
	    sc->identity.mac[0], sc->identity.mac[1], sc->identity.mac[2],
	    sc->identity.mac[3], sc->identity.mac[4], sc->identity.mac[5]);
	for (i = 0; i < sizeof (channels); i++) {
		sc->identity.channels[i] = iwm_u16(r->nvm[3] + 2 * i);
	}
	sc->identity.valid = B_TRUE;
	r->state = IWM_NVM_PARSED;
	return (iwm_checkpoint(sc, "NVM-parsed"));
}

static int
iwm_nvm(struct iwm_softc *sc)
{
	static const uint_t sections[] = { 0, 1, 3, 4, 5, 8, 10, 11, 12 };
	struct iwm_runtime *r = sc->run;
	uint_t i, s, offset, n, want;
	int error;

	r->state = IWM_NVM_READING;
	for (i = 0; i < sizeof (sections) / sizeof (sections[0]); i++) {
		s = sections[i];
		r->nvm_len[s] = 0;
		for (offset = 0; offset < IWM_NVM_LIMIT; offset += n) {
			want = MIN(IWM_NVM_CHUNK, IWM_NVM_LIMIT - offset);
			error = iwm_nvm_chunk(sc, s, offset, want, &n);
			if (error == ENOENT)
					/* Firmware rejected this section. */
					break;
			if (error != 0)
				return (error);
			r->nvm_len[s] = offset + n;
			if (n < want)
				break;
		}
		dev_err(sc->dip, CE_NOTE, "!iwm NVM section%u length=%lu",
		    s, (ulong_t)r->nvm_len[s]);
		if (iwm_checkpoint(sc, "NVM-section") != 0 ||
		    iwm_queues_check(sc, "NVM-section") != 0)
			return (EIO);
	}
	if ((error = iwm_nvm_parse(sc)) != 0)
		return (error);
	return (iwm_queues_check(sc, "after-NVM"));
}

/*
 * Stop every enabled channel before any published DMA mapping can be freed.
 * Timeout is a failure, never permission to release memory still owned by NIC.
 */
static int
iwm_device_stop(struct iwm_softc *sc, boolean_t final)
{
	struct iwm_runtime *r = sc->run;
	uint_t ch;
	uint32_t mask;
	int error = 0;

	r->lar.ready = B_FALSE;
	if (r->stop_failed)
		return (EIO);
	if (!r->touched || r->stopped) {
		if (final)
			r->state = IWM_DEVICE_STOPPED;
		return (0);
	}
	if (r->published && iwm_queues_check(sc, "pre-stop") != 0)
		r->error = EIO;
	r->state = final ? IWM_DEVICE_STOPPING : IWM_IMAGE_STOPPING;
	r->mask = 0;
	iwm_wr(sc, IWM_CSR_INT_MASK, 0);
	(void) iwm_rd(sc, IWM_CSR_INT_MASK);
	if (r->tx_started || r->rx_started) {
		if (iwm_nic_lock(sc) != 0) {
			error = EIO;
		} else {
			iwm_prph_write(sc, IWM_SCD_TXFACT, 0);
			for (ch = 0; ch < IWM_FH_TCSR_CHNL_NUM; ch++)
				iwm_wr(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(ch),
				    0);
			for (ch = 0; ch < IWM_FH_TCSR_CHNL_NUM; ch++) {
				mask =
				    IWM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(ch);
				if (iwm_poll(sc, IWM_FH_TSSR_TX_STATUS_REG,
				    mask, mask, 4000) != 0)
					error = ETIMEDOUT;
			}
			iwm_wr(sc, IWM_FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);
			if (iwm_poll(sc, IWM_FH_MEM_RSSR_RX_STATUS_REG,
			    IWM_FH_RSSR_CHNL0_RX_STATUS_CHNL_IDLE,
			    IWM_FH_RSSR_CHNL0_RX_STATUS_CHNL_IDLE, 10000) != 0)
				error = ETIMEDOUT;
			iwm_nic_unlock(sc);
		}
	}
	iwm_bits(sc, IWM_CSR_GP_CNTRL, 0,
	    IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
	r->nic_locks = 0;
	iwm_bits(sc, IWM_CSR_DBG_LINK_PWR_MGMT_REG,
	    IWM_CSR_RESET_LINK_PWR_MGMT_DISABLED, 0);
	iwm_bits(sc, IWM_CSR_HW_IF_CONFIG_REG,
	    IWM_CSR_HW_IF_CONFIG_REG_PREPARE |
	    IWM_CSR_HW_IF_CONFIG_REG_ENABLE_PME, 0);
	drv_usecwait(1000);
	iwm_bits(sc, IWM_CSR_DBG_LINK_PWR_MGMT_REG, 0,
	    IWM_CSR_RESET_LINK_PWR_MGMT_DISABLED);
	drv_usecwait(5000);
	iwm_bits(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_STOP_MASTER, 0);
	if (iwm_poll(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED,
	    IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED, 100) != 0)
		error = ETIMEDOUT;
	iwm_bits(sc, IWM_CSR_GP_CNTRL, 0, IWM_CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
	iwm_wr(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_SW_RESET);
	r->command_pending = B_FALSE;
	r->alive = B_FALSE;
	drv_usecwait(5000);
	iwm_wr(sc, IWM_CSR_INT_MASK, 0);
	iwm_wr8(sc, IWM_CSR_INT_PERIODIC_REG, IWM_CSR_INT_PERIODIC_DIS);
	iwm_wr(sc, IWM_CSR_INT, 0xffffffff);
	iwm_wr(sc, IWM_CSR_FH_INT_STATUS, 0xffffffff);
	dev_err(sc->dip, CE_NOTE, "!iwm stop error=%d HW_REV=%08x "
	    "GP=%08x RESET=%08x MASK=%08x causes=%08x FH=%08x",
	    error, iwm_rd(sc, IWM_CSR_HW_REV), iwm_rd(sc, IWM_CSR_GP_CNTRL),
	    iwm_rd(sc, IWM_CSR_RESET), iwm_rd(sc, IWM_CSR_INT_MASK),
	    r->causes, r->fh_causes);
	if (error != 0) {
		r->stop_failed = B_TRUE;
		return (error);
	}
	r->scan.accepting = B_FALSE;
	r->scan.outstanding = B_FALSE;
	r->scan.running = B_FALSE;
	r->stopped = B_TRUE;
	r->state = final ? IWM_DEVICE_STOPPED : IWM_IMAGE_STOPPED;
	return (0);
}

/* Hardware stopped; retain host allocations and firmware/NVM/PHY data. */
static int
iwm_restart(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint_t i;
	int error;

	if (r->command_pending || r->error != 0)
		return (EBUSY);
	error = iwm_device_stop(sc, B_FALSE);
	if (error != 0)
		return (error);
	mutex_exit(&sc->lock);
	error = iwm_intr_disable(sc);
	mutex_enter(&sc->lock);
	if (error != 0 || r->error != 0 || r->nic_locks != 0)
		return (EIO);
	if (iwm_checkpoint(sc, "inter-image-stop") != 0)
		return (EIO);
	for (i = 0; i < IWM_RX_RING_COUNT; i++) {
		if (iwm_sync(&r->rx[i], DDI_DMA_SYNC_FORCPU) != 0)
			return (EIO);
		bzero(r->rx[i].vaddr, r->rx[i].size);
		if (iwm_sync(&r->rx[i], DDI_DMA_SYNC_FORDEV) != 0)
			return (EIO);
	}
	for (i = 0; i < IWM_MAX_QUEUES; i++) {
		if (iwm_sync(&r->tx[i], DDI_DMA_SYNC_FORCPU) != 0)
			return (EIO);
		bzero(r->tx[i].vaddr, r->tx[i].size);
		if (iwm_sync(&r->tx[i], DDI_DMA_SYNC_FORDEV) != 0)
			return (EIO);
	}
	if (iwm_sync(&sc->dma[3], DDI_DMA_SYNC_FORCPU) != 0)
		return (EIO);
	bzero(sc->dma[3].vaddr, sc->dma[3].size);
	bzero(r->commands.vaddr, r->commands.size);
	bzero(r->scheduler.vaddr, r->scheduler.size);
	if (iwm_sync(&sc->dma[3], DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&r->commands, DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&r->scheduler, DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&sc->dma[2], DDI_DMA_SYNC_FORDEV) != 0)
		return (EIO);
	r->cmdcur = r->rxcur = 0;
	r->command_done = r->chunk_done = B_FALSE;
	r->control_command = r->command_pending = B_FALSE;
	r->response_len = 0;
	bzero(r->response, sizeof (r->response));
	bzero(&r->diagnostic, sizeof (r->diagnostic));
	bzero(&r->response_diagnostic, sizeof (r->response_diagnostic));
	bzero(r->alive_data, sizeof (r->alive_data));
	r->alive_len = 0;
	r->sched_base = 0;
	r->tx_started = r->rx_started = r->published = B_FALSE;
	r->image = IWM_FW_REGULAR;
	r->generation++;
	/* Old callbacks have drained and RX is reset before MSI is enabled. */
	if (sc->intr_cap & DDI_INTR_FLAG_BLOCK)
		error = ddi_intr_block_enable(&sc->intr, 1);
	else
		error = ddi_intr_enable(sc->intr);
	if (error != DDI_SUCCESS)
		return (EIO);
	sc->intr_enabled = B_TRUE;
	r->stopped = B_FALSE;
	if ((error = iwm_start(sc)) != 0 ||
	    (error = iwm_transport_init(sc)) != 0)
		return (error);
	return (iwm_checkpoint(sc, "restarted-transport"));
}

static int
iwm_paging_alloc(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_fw_image *im = &sc->fw.image[IWM_FW_REGULAR];
	uint_t i;
	size_t size, copied = 0, used;
	const uint8_t *data = im->section[11].data;

	r->paging_blocks = (sc->fw.paging_size + IWM_PAGING_BLOCK_SIZE - 1) /
	    IWM_PAGING_BLOCK_SIZE;
	if (r->paging_blocks == 0 || r->paging_blocks >= IWM_PAGING_BLOCKS)
		return (EINVAL);
	r->paging_last = (sc->fw.paging_size -
	    (r->paging_blocks - 1) * IWM_PAGING_BLOCK_SIZE) / 4096;
	for (i = 0; i <= r->paging_blocks; i++) {
		size = i == 0 ? 4096 : IWM_PAGING_BLOCK_SIZE;
		if (iwm_dma_alloc(sc, &r->paging[i], size, 4096,
		    DDI_DMA_RDWR) != 0)
			return (ENOMEM);
		/* Copy only the declared CSS bytes. */
		used = i == 0 ? im->section[10].length :
		    MIN(sc->fw.paging_size - copied, size);
		bzero(r->paging[i].vaddr, size);
		bcopy(i == 0 ? im->section[10].data : data + copied,
		    r->paging[i].vaddr, used);
		if (i != 0)
			copied += used;
		if (iwm_sync(&r->paging[i], DDI_DMA_SYNC_FORDEV) != 0)
			return (EIO);
	}
	return (copied == sc->fw.paging_size ? 0 : EINVAL);
}

static int
iwm_regular_config(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint32_t paging[3 + IWM_PAGING_BLOCKS];
	uint32_t dqa;
	uint8_t thermal[20];
	uint8_t phy[IWM_RBUF_SIZE];
	uint16_t value;
	uint_t i, type;
	int error;

	bzero(paging, sizeof (paging));
	paging[0] = LE_32((1U << 9) | (1U << 8) | r->paging_last);
	paging[1] = LE_32(15);
	paging[2] = LE_32(r->paging_blocks);
	for (i = 0; i <= r->paging_blocks; i++)
		paging[3 + i] = LE_32(iwm_dma_addr(&r->paging[i]) >> 12);
	if ((error = iwm_control(sc, IWM_PAGING_CMD,
	    paging, sizeof (paging))) != 0)
		return (error);
	if (iwm_checkpoint(sc, "REGULAR-first-command") != 0)
		return (EIO);
	if ((error = iwm_tx_ant_config(sc)) != 0)
		return (error);
	for (i = 0; i < IWM_PHY_DB_ENTRIES; i++) {
		struct iwm_phy_entry *entry = &r->phy_db[i];

		if (entry->length == 0)
			continue;
		if (entry->length > sizeof (phy) - 4)
			return (EOVERFLOW);
		type = i < 2 ? i + 1 : i < 2 + IWM_PHY_DB_GROUPS ?
		    IWM_PHY_DB_CALIB_CHG_PAPD : IWM_PHY_DB_CALIB_CHG_TXP;
		value = LE_16(type);
		bcopy(&value, phy, 2);
		value = LE_16(entry->length);
		bcopy(&value, phy + 2, 2);
		bcopy(entry->data, phy + 4, entry->length);
		if ((error = iwm_control(sc, IWM_PHY_DB_CMD,
		    phy, entry->length + 4)) != 0)
			return (error);
		if (iwm_checkpoint(sc, "PHY-DB-replay") != 0)
			return (EIO);
	}
	if ((error = iwm_phy_config(sc)) != 0)
		return (error);
	if (sc->fw.capa[0] & (1U << IWM_UCODE_TLV_CAPA_DQA_SUPPORT)) {
		/* Match firmware queue mode; no packet queues are activated. */
		dqa = LE_32(r->cmdqid);
		if ((error = iwm_control(sc, IWM_DQA_ENABLE_CMD,
		    &dqa, sizeof (dqa))) != 0)
			return (error);
	}
	/* CAPA_CT_KILL_BY_FW: delegate thermal protection to firmware. */
	if (sc->fw.capa[2] & (1U << (IWM_CAPA_CT_KILL_BY_FW % 32))) {
		bzero(thermal, sizeof (thermal));
		if ((error = iwm_control(sc, IWM_TEMP_THRESHOLDS_CMD,
		    thermal, sizeof (thermal))) != 0)
			return (error);
	}
	r->state = IWM_REGULAR_IDLE;
	return (iwm_checkpoint(sc, "REGULAR-idle"));
}

/*
 * Quiesce cannot take locks or tear down mappings. Normally the INIT session
 * has already stopped before attach completes. For an interrupted session,
 * request master stop and reset, without treating a timeout as success.
 */
int
iwm_run_quiesce(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	int error;

	if (r == NULL || !r->touched || r->stopped)
		return (0);
	iwm_wr(sc, IWM_CSR_INT_MASK, 0);
	iwm_bits(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_STOP_MASTER, 0);
	error = iwm_poll(sc, IWM_CSR_RESET,
	    IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED,
	    IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED, 100);
	iwm_wr(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_SW_RESET);
	(void) iwm_rd(sc, IWM_CSR_RESET);
	return (error);
}

/* All firmware topology transitions run in the sole connection worker. */
static int
iwm_connection_state(struct iwm_softc *sc, enum ieee80211_state state,
    int arg)
{
	struct iwm_connection *c = &sc->connection;
	struct iwm_runtime *r = sc->run;
	uint_t ac;
	clock_t end;
	enum ieee80211_state old;
	int error = 0;

	mutex_enter(&sc->lock);
	if (curthread != c->thread || c->cancel || r == NULL) {
		c->cancel = B_TRUE;
		if (r != NULL)
			cv_broadcast(&r->cv);
		mutex_exit(&sc->lock);
		return (ECANCELED);
	}
	old = sc->ic.ic_state;
	if (c->error != 0) {
		mutex_exit(&sc->lock);
		return (c->error);
	}
	if (old == IEEE80211_S_RUN && state != old &&
	    !c->operation_owned) {
		mutex_exit(&sc->lock);
		error = iwm_operation_enter(sc, IWM_OP_CONNECT);
		mutex_enter(&sc->lock);
		if (error != 0)
			goto failed;
		c->operation_owned = B_TRUE;
		if (c->cancel) {
			error = ECANCELED;
			goto failed;
		}
	}
	if (old == IEEE80211_S_RUN && state != old) {
		c->tx_admission = c->running = B_FALSE;
		sc->associated_bssid_valid = B_FALSE;
		bzero(sc->associated_bssid, sizeof (sc->associated_bssid));
		mutex_exit(&sc->lock);
		iwm_ba_retire(sc);
		mutex_enter(&sc->lock);
		if ((error = iwm_ba_work(sc)) != 0)
			goto failed;
	}
	if (old == IEEE80211_S_RUN && state != old && c->wpa) {
		mutex_exit(&sc->lock);
		iwm_connection_keys_clear(sc);
		mutex_enter(&sc->lock);
	}
	if (state == IEEE80211_S_SCAN || state == IEEE80211_S_INIT) {
		/* Honor native departure; no automatic AP selection or scan. */
		if (state == IEEE80211_S_SCAN && arg == -1 &&
		    (old == IEEE80211_S_AUTH || old == IEEE80211_S_ASSOC) &&
		    c->error == 0)
			c->error = ETIMEDOUT;
		c->tx_admission = c->rx_admission = B_FALSE;
		c->cancel = B_TRUE;
		c->wme.accepting = B_FALSE;
		mutex_exit(&sc->lock);
		error = c->newstate(&sc->ic, state, arg);
		mutex_enter(&sc->lock);
		c->link_up = B_FALSE;
		cv_broadcast(&r->cv);
		mutex_exit(&sc->lock);
		return (error);
	}
	if ((error = iwm_nic_lock(sc)) != 0) {
		if (c->error == 0)
			c->error = error;
		mutex_exit(&sc->lock);
		return (error);
	}
	if (old == IEEE80211_S_RUN && state != old) {
		error = iwm_association_run_stop(sc);
		if (error != 0) {
			iwm_nic_unlock(sc);
			goto failed;
		}
		if (state == IEEE80211_S_AUTH) {
			/* Deauthentication needs fresh topology/protection. */
			c->rx_admission = B_FALSE;
			iwm_nic_unlock(sc);
			error = iwm_connection_rollback(sc);
			if (error != 0)
				goto failed;
			bzero(&r->protection, sizeof (r->protection));
			mutex_exit(&sc->lock);
			error = iwm_association_tx_alloc(sc);
			mutex_enter(&sc->lock);
			if (error != 0 ||
			    (error = iwm_nic_lock(sc)) != 0)
				goto failed;
		}
	}
	switch (state) {
	case IEEE80211_S_AUTH:
		if (old != IEEE80211_S_INIT && old != IEEE80211_S_RUN) {
			error = ECONNRESET;
			break;
		}
		if ((error = iwm_association_phy(sc,
		    IWM_FW_CTXT_ACTION_ADD)) != 0 ||
		    (error = iwm_association_mac(sc,
		    IWM_FW_CTXT_ACTION_ADD, B_FALSE)) != 0 ||
		    (error = iwm_association_binding(sc,
		    IWM_FW_CTXT_ACTION_ADD)) != 0)
			break;
		for (ac = 0; ac < 4; ac++) {
			error = iwm_association_queue(sc, ac, B_TRUE);
			if (error != 0)
				break;
		}
		if (error != 0 || (error = iwm_association_station(sc,
		    B_FALSE, B_FALSE)) != 0)
			break;
		c->reassociating = B_FALSE;
		c->rx_admission = B_TRUE;
		error = iwm_protect_session(sc, c->node->in_intval);
		if (error == 0)
			c->tx_admission = B_TRUE;
		break;
	case IEEE80211_S_ASSOC:
		if (old == IEEE80211_S_RUN) {
			c->reassociating = B_TRUE;
			r->association.beacon_valid = B_FALSE;
			c->tx_admission = B_TRUE;
		} else if (old != IEEE80211_S_AUTH ||
		    !r->protection.started || r->protection.error != 0) {
			error = EPROTO;
		}
		break;
	case IEEE80211_S_RUN:
		if (sc->ic.ic_state != IEEE80211_S_ASSOC || c->running) {
			error = EPROTO;
			break;
		}
		end = ddi_get_lbolt() + drv_usectohz(IWM_WAIT_US);
		while (!r->association.beacon_valid && !c->cancel &&
		    r->error == 0) {
			if (cv_timedwait(&r->cv, &sc->lock, end) == -1)
				break;
		}
		if (!r->association.beacon_valid) {
			error = ETIMEDOUT;
			break;
		}
		c->node->in_flags &= ~(IEEE80211_NODE_HTCOMPAT |
		    IEEE80211_NODE_AMPDU_RX);
		if (!(sc->ic.ic_flags_ext & IEEE80211_FEXT_AMPDU_TX))
			c->node->in_flags &= ~IEEE80211_NODE_AMPDU_TX;
		if (c->node->in_flags & IEEE80211_NODE_HT) {
			uint_t i;

			if (c->node->in_chw != 20 ||
			    c->node->in_htctlchan != c->channel ||
			    c->node->in_htrates.rs_nrates == 0 ||
			    c->node->in_htrates.rs_nrates > 8) {
				error = ENOTSUP;
				break;
			}
			for (i = 0; i < c->node->in_htrates.rs_nrates; i++) {
				if ((c->node->in_htrates.rs_rates[i] &
				    IEEE80211_RATE_VAL) > 7)
					break;
			}
			/* Fixed initial MCS0 policy needs MCS0 negotiated. */
			if (i != c->node->in_htrates.rs_nrates ||
			    (c->node->in_htrates.rs_rates[0] &
			    IEEE80211_RATE_VAL) != 0) {
				error = ENOTSUP;
				break;
			}
		} else {
			/* Preserve the accepted non-QoS legacy data path. */
			c->node->in_flags &= ~IEEE80211_NODE_QOS;
		}
		error = iwm_association_run(sc);
		break;
	default:
		/* No autonomous rescan, reauthentication or roaming. */
		error = ECONNRESET;
		break;
	}
	iwm_nic_unlock(sc);
	if (error == 0 && (c->cancel || c->error != 0 || r->error != 0))
		error = c->cancel ? ECANCELED :
		    (c->error != 0 ? c->error : r->error);
failed:
	if (error != 0) {
		if (c->error == 0)
			c->error = error;
		mutex_exit(&sc->lock);
		return (error);
	}
	mutex_exit(&sc->lock);
	/* Native sta_leave publishes DOWN once, before its management TX. */
	error = c->newstate(&sc->ic, state, arg);
	mutex_enter(&sc->lock);
	if (error == 0 && (state == IEEE80211_S_AUTH ||
	    state == IEEE80211_S_ASSOC)) {
		/* Five native management ticks plus one scheduling tick. */
		c->deadline = ddi_get_lbolt() + drv_usectohz(6000000);
	}
	if (error == 0 && state == IEEE80211_S_RUN) {
		c->running = c->link_up = B_TRUE;
		c->reassociating = B_FALSE;
		bcopy(c->node->in_bssid, sc->associated_bssid, 6);
		sc->associated_bssid_valid = B_TRUE;
	}
	if (error == 0 && old == IEEE80211_S_RUN && state != old)
		c->link_up = B_FALSE;
	if (error != 0 && c->error == 0)
		c->error = error;
	mutex_exit(&sc->lock);
	return (error);
}

/* Cancel only. The worker remains the sole association teardown owner. */
void
iwm_connection_cancel(struct iwm_softc *sc)
{
	mutex_enter(&sc->lock);
	if (sc->connection.pending) {
		sc->connection.cancel = B_TRUE;
		if (sc->run != NULL)
			cv_broadcast(&sc->run->cv);
	}
	mutex_exit(&sc->lock);
}

/* Thread context, no public operation or MAC perimeter held by the caller. */
int
iwm_connection_disconnect(struct iwm_softc *sc)
{
	struct iwm_connection *c = &sc->connection;
	clock_t end = ddi_get_lbolt() + drv_usectohz(60000000);
	int error = 0;

	mutex_enter(&c->crypto_lock);
	mutex_enter(&sc->lock);
	c->resetting = B_TRUE;
	mutex_exit(&c->crypto_lock);
	if (c->pending) {
		c->cancel = B_TRUE;
		if (sc->run != NULL)
			cv_broadcast(&sc->run->cv);
		while (!c->finished) {
			if (cv_timedwait(&c->cv, &sc->lock, end) == -1) {
				error = ETIMEDOUT;
				break;
			}
		}
		if (error == 0)
			error = c->cleanup_error;
	}
	mutex_exit(&sc->lock);
	if (error == 0) {
		mutex_enter(&c->crypto_lock);
		/* Preparatory MLME reset does not call this public path. */
		c->clear_ie = c->disable_wpa = B_TRUE;
		iwm_connection_config_clear(sc);
		c->resetting = B_FALSE;
		mutex_exit(&c->crypto_lock);
	}
	return (error);
}

/* Stop before free: a failed firmware rollback requires proven device stop. */
static int
iwm_connection_rollback(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	struct iwm_association *a = &r->association;
	struct iwm_tx_path_flush_cmd_v1 flush;
	uint32_t remove = 0;
	uint_t ac, i, queued;
	clock_t end;
	int error = 0;
	boolean_t nic = B_FALSE;
	boolean_t transport_failed = r->error != 0;

	ASSERT(MUTEX_HELD(&sc->lock));
	if (transport_failed)
		goto stopped_cleanup;
	if (error == 0) {
		error = iwm_nic_lock(sc);
		nic = error == 0;
	}
	if (error == 0)
		error = iwm_unprotect_session(sc);
	/* Quota and associated MAC state still refer to the live topology. */
	if (error == 0)
		error = iwm_association_run_stop(sc);
	if (error == 0 && a->station) {
		error = iwm_association_station(sc, B_TRUE, B_TRUE);
		if (error == 0 && !iwm_command_version(&sc->fw, 0x1e, 1))
			error = ENOTSUP;
		if (error == 0) {
			bzero(&flush, sizeof (flush));
			flush.queues_ctl = LE_32(a->queues);
			flush.flush_ctl = LE_16(2);
			error = iwm_control(sc, 0x1e, &flush, sizeof (flush));
		}
	}
	end = ddi_get_lbolt() + drv_usectohz(IWM_WAIT_US);
	while (error == 0) {
		/* Closed TX admission makes failed transmissions drainable. */
		error = iwm_association_reclaim(sc, B_FALSE);
		if (error != 0)
			break;
		queued = 0;
		for (ac = 0; ac < IWM_ASSOC_TX_RINGS; ac++)
			queued += a->tx[ac].queued;
		if (queued == 0)
			break;
		if (r->error != 0)
			error = r->error;
		else if (cv_timedwait(&r->cv, &sc->lock, end) == -1)
			error = ETIMEDOUT;
	}
	for (ac = 0; error == 0 && ac < IWM_ASSOC_TX_RINGS; ac++) {
		if (a->tx[ac].configured)
			error = iwm_association_queue(sc, ac, B_FALSE);
	}
	if (error == 0 && a->station) {
		error = iwm_control(sc, 0x19, &remove, sizeof (remove));
		if (error == 0)
			a->station = B_FALSE;
	}
	if (error == 0 && a->binding)
		error = iwm_association_binding(sc, IWM_FW_CTXT_ACTION_REMOVE);
	if (error == 0 && a->mac)
		error = iwm_association_mac(sc, IWM_FW_CTXT_ACTION_REMOVE,
		    B_FALSE);
	if (error == 0 && a->phy)
		error = iwm_association_phy(sc, IWM_FW_CTXT_ACTION_REMOVE);
	if (error == 0)
		error = iwm_queues_check(sc, "association-released");
	if (nic)
		iwm_nic_unlock(sc);
stopped_cleanup:
	if (error != 0 || transport_failed) {
		/* Preserve the provider claim on this failed generation. */
		if (r->error == 0)
			r->error = error;
		if (iwm_device_stop(sc, B_TRUE) != 0)
			return (EIO);
		if (iwm_association_reclaim(sc, B_TRUE) != 0)
			return (EIO);
		/* Reset ended device ownership, including partial topology. */
		for (ac = 0; ac < IWM_ASSOC_TX_RINGS; ac++)
			a->tx[ac].configured = B_FALSE;
		a->queues = 0;
		a->station = a->binding = a->mac = a->phy = B_FALSE;
		a->run_configured = B_FALSE;
	}
	for (i = 0; i < IWM_SCAN_RX_LIMIT; i++) {
		if (a->frames[i].mp != NULL) {
			freemsg(a->frames[i].mp);
			a->frames[i].mp = NULL;
		}
	}
	a->head = a->tail = a->queued = 0;
	mutex_exit(&sc->lock);
	i = iwm_association_free(sc);
	mutex_enter(&sc->lock);
	if (error == 0 && i != 0)
		error = i;
	if (error == 0) {
		bzero(a, sizeof (*a));
	}
	return (error);
}

/* Open ESSID or WPA MLME reserves CONNECT; this task owns subsequent waits. */
void
iwm_connection_task(void *arg)
{
	struct iwm_softc *sc = arg;
	struct iwm_connection *c = &sc->connection;
	struct iwm_runtime *r;
	struct iwm_scan_frame frame;
	ieee80211_node_t *node = NULL;
	static const uint8_t rates[] =
	    { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };
	clock_t tick;
	uint_t i, j;
	int error, cleanup = 0;
	boolean_t notify_disabled;

	c->thread = curthread;
	c->operation_owned = B_TRUE;
	/* WPA MLME already validated and transferred this referenced node. */
	node = c->node;
	error = 0;
	if (node == NULL) {
		error = iwm_select_bss(sc, c->essid, c->esslen, c->channel,
		    &node);
		if (error != 0)
			goto done;
	}
	c->node = node;
	mutex_enter(&sc->lock);
	iwm_wme_reset(sc, (sc->ic.ic_caps & IEEE80211_C_WME) != 0);
	mutex_exit(&sc->lock);
	/* Native ASSOC negotiation overwrites the AP's basic-rate bits. */
	c->basic_rates = 0;
	for (i = 0; i < node->in_rates.ir_nrates; i++) {
		uint8_t rate = node->in_rates.ir_rates[i];

		if (!(rate & IEEE80211_RATE_BASIC))
			continue;
		for (j = 0; j < sizeof (rates); j++) {
			if ((rate & IEEE80211_RATE_VAL) == rates[j])
				c->basic_rates |= 1U << j;
		}
	}
	c->channel = ieee80211_chan2ieee(&sc->ic, node->in_chan);
	error = iwm_runtime_acquire(sc, IWM_RUNTIME_CONNECT);
	if (error != 0)
		goto done;
	r = sc->run;
	mutex_enter(&sc->lock);
	if (r->protection.active) {
		mutex_exit(&sc->lock);
		error = EBUSY;
		goto teardown;
	}
	bzero(&r->protection, sizeof (r->protection));
	mutex_exit(&sc->lock);
	if ((error = iwm_lar_prepare(sc, c->channel)) != 0 ||
	    (error = iwm_association_tx_alloc(sc)) != 0)
		goto teardown;
	/* Native join consumes this extra reference; c->node owns the first. */
	ieee80211_sta_join(&sc->ic, ieee80211_ref_node(node));
	tick = ddi_get_lbolt() + drv_usectohz(1000000);
	mutex_enter(&sc->lock);
	for (;;) {
		error = iwm_association_reclaim(sc, B_FALSE);
		if (error == 0)
			error = c->error != 0 ? c->error : r->error;
		if (error == 0 && c->cancel) {
			/* Explicit disconnect from RUN is normal completion. */
			error = c->running ? 0 : ECANCELED;
			break;
		}
		if (error == 0)
			error = r->protection.error;
		if (error == 0 && ddi_get_lbolt() >= tick) {
			mutex_exit(&sc->lock);
			/* Run the native timeout before the fallback. */
			ieee80211_watchdog(&sc->ic);
			mac_tx_update(sc->ic.ic_mach);
			mutex_enter(&sc->lock);
			tick = ddi_get_lbolt() + drv_usectohz(1000000);
			error = c->error != 0 ? c->error : r->error;
		}
		if (error == 0 && !c->running &&
		    ddi_get_lbolt() >= c->deadline)
			error = ETIMEDOUT;
		if (error != 0)
			break;
		if ((error = iwm_ba_work(sc)) != 0)
			break;
		if ((error = iwm_wme_work(sc)) != 0)
			break;
		if (c->running && c->operation_owned) {
			mutex_exit(&sc->lock);
			iwm_operation_exit(sc);
			c->operation_owned = B_FALSE;
			mutex_enter(&sc->lock);
		}
		if (r->association.queued != 0) {
			struct iwm_association *a = &r->association;

			frame = a->frames[a->head];
			a->frames[a->head].mp = NULL;
			a->head = (a->head + 1) % IWM_SCAN_RX_LIMIT;
			a->queued--;
			a->rx_delivered++;
			mutex_exit(&sc->lock);
			ieee80211_input(&sc->ic, frame.mp, node, frame.rssi,
			    frame.timestamp);
			mutex_enter(&sc->lock);
			continue;
		}
		(void) cv_timedwait(&r->cv, &sc->lock,
		    r->association.ba[0].state == IWM_BA_STARTING ?
		    MIN(tick, r->association.ba[0].deadline) : tick);
	}
	mutex_exit(&sc->lock);
teardown:
	if (!c->operation_owned) {
		cleanup = iwm_operation_enter(sc, IWM_OP_DISCONNECT);
		if (cleanup != 0)
			goto done;
		c->operation_owned = B_TRUE;
	}
	mutex_enter(&sc->lock);
	c->tx_admission = c->rx_admission = B_FALSE;
	c->running = B_FALSE;
	c->wme.accepting = B_FALSE;
	sc->associated_bssid_valid = B_FALSE;
	bzero(sc->associated_bssid, sizeof (sc->associated_bssid));
	mutex_exit(&sc->lock);
	iwm_ba_retire(sc);
	/* Native INIT publishes DOWN from RUN before resource removal. */
	if (c->wpa)
		iwm_connection_keys_clear(sc);
	notify_disabled = B_FALSE;
	mutex_enter(&c->crypto_lock);
	if (c->mlme_cancel) {
		mutex_enter(&sc->ic.ic_genlock);
		notify_disabled = (sc->ic.ic_flags & IEEE80211_F_WPA) != 0;
		sc->ic.ic_flags &= ~IEEE80211_F_WPA;
		mutex_exit(&sc->ic.ic_genlock);
	}
	(void) c->newstate(&sc->ic, IEEE80211_S_INIT, 0);
	if (notify_disabled) {
		mutex_enter(&sc->ic.ic_genlock);
		sc->ic.ic_flags |= IEEE80211_F_WPA;
		mutex_exit(&sc->ic.ic_genlock);
	}
	mutex_exit(&c->crypto_lock);
	c->link_up = B_FALSE;
	mutex_enter(&sc->lock);
	cleanup = iwm_connection_rollback(sc);
	mutex_exit(&sc->lock);
	if (cleanup == 0 || sc->run->stopped) {
		int stop_error = iwm_runtime_release(sc, IWM_RUNTIME_CONNECT);

		if (cleanup == 0)
			cleanup = stop_error;
	}
done:
	mutex_enter(&sc->lock);
	iwm_wme_reset(sc, B_FALSE);
	c->error = error;
	c->cleanup_error = cleanup;
	/* Do not release a node still reachable by unsafe retained TX slots. */
	if (cleanup == 0 || sc->run == NULL || sc->run->stopped) {
		c->node = NULL;
	} else {
		node = NULL;
	}
	mutex_exit(&sc->lock);
	if (node != NULL)
		ieee80211_free_node(node);
	if (c->operation_owned) {
		iwm_operation_exit(sc);
		c->operation_owned = B_FALSE;
	}
	dev_err(sc->dip, CE_NOTE, "!iwm connection error=%d cleanup=%d",
	    error, cleanup);
	mutex_enter(&c->crypto_lock);
	if (c->wpa) {
		/* A later MLME attempt must supply fresh RSN and BSSID. */
		c->clear_ie = B_TRUE;
		iwm_connection_config_clear(sc);
	}
	mutex_enter(&sc->lock);
	c->pending = c->node != NULL;
	c->thread = NULL;
	c->finished = B_TRUE;
	cv_broadcast(&c->cv);
	mutex_exit(&sc->lock);
	mutex_exit(&c->crypto_lock);
}

/* Attach/detach thread: runtime resources precede passive cleanup. */
int
iwm_run_free(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	int i, error, scan_error;

	if (r == NULL)
		return (0);
	mutex_enter(&sc->lock);
	error = iwm_device_stop(sc, B_TRUE);
	mutex_exit(&sc->lock);
	if (iwm_intr_disable(sc) != 0 || error != 0)
		return (EIO);
	scan_error = sc->public_enabled ? 0 : iwm_scan_detach(sc);
	mutex_enter(&sc->lock);
	iwm_scan_drain(sc);
	if (iwm_association_reclaim(sc, B_TRUE) != 0) {
		mutex_exit(&sc->lock);
		return (EIO);
	}
	for (i = 0; i < IWM_SCAN_RX_LIMIT; i++) {
		if (r->association.frames[i].mp != NULL) {
			freemsg(r->association.frames[i].mp);
			r->association.frames[i].mp = NULL;
		}
	}
	r->association.queued = 0;
	for (i = 0; i < IWM_ASSOC_TX_RINGS; i++)
		r->association.tx[i].configured = B_FALSE;
	r->association.queues = 0;
	mutex_exit(&sc->lock);
	if (iwm_association_free(sc) != 0)
		return (EIO);
	for (i = IWM_PAGING_BLOCKS - 1; i >= 0; i--) {
		if (iwm_dma_free(&r->paging[i]) != 0)
			return (EIO);
	}
	for (i = IWM_PHY_DB_ENTRIES - 1; i >= 0; i--) {
		if (r->phy_db[i].data != NULL) {
			kmem_free(r->phy_db[i].data, r->phy_db[i].length);
			r->phy_db[i].data = NULL;
			r->phy_db[i].length = 0;
		}
	}
	for (i = IWM_NVM_NUM_OF_SECTIONS - 1; i >= 0; i--) {
		if (r->nvm[i] != NULL) {
			kmem_free(r->nvm[i], IWM_NVM_LIMIT);
			r->nvm[i] = NULL;
		}
	}
	for (i = IWM_RX_RING_COUNT - 1; i >= 0; i--) {
		if (iwm_dma_free(&r->rx[i]) != 0)
			return (EIO);
	}
	if (iwm_dma_free(&r->commands) != 0)
		return (EIO);
	for (i = IWM_MAX_QUEUES - 1; i >= 0; i--) {
		if (iwm_dma_free(&r->tx[i]) != 0)
			return (EIO);
	}
	if (iwm_dma_free(&r->scheduler) != 0 || iwm_dma_free(&r->transfer) != 0)
		return (EIO);
	for (i = IWM_PASSIVE_DMA_COUNT - 1; i >= 0; i--) {
		if (iwm_dma_free(&sc->dma[i]) != 0)
			return (EIO);
	}
	mutex_enter(&sc->lock);
	sc->run = NULL;
	mutex_exit(&sc->lock);
	cv_destroy(&r->cv);
	kmem_free(r, sizeof (*r));
	return (scan_error);
}

static int
iwm_run_alloc(struct iwm_softc *sc)
{
	struct iwm_runtime *r = sc->run;
	uint32_t *desc = (void *)sc->dma[2].vaddr;
	uint_t i;

	if (iwm_dma_alloc(sc, &r->transfer, sc->cfg->fw_dma_size,
	    16, DDI_DMA_WRITE) != 0 ||
	    iwm_dma_alloc(sc, &r->scheduler,
	    IWM_MAX_QUEUES * sizeof (struct iwm_agn_scd_bc_tbl),
	    1024, DDI_DMA_RDWR) != 0)
		return (ENOMEM);
	for (i = 0; i < IWM_MAX_QUEUES; i++) {
		if (iwm_dma_alloc(sc, &r->tx[i],
		    IWM_TX_RING_COUNT * sizeof (struct iwm_tfd),
		    256, DDI_DMA_RDWR) != 0)
			return (ENOMEM);
	}
	/* Only command storage exists. All other TX queues have empty TFDs. */
	if (iwm_dma_alloc(sc, &r->commands,
	    IWM_TX_RING_COUNT * sizeof (struct iwm_device_cmd),
	    4, DDI_DMA_WRITE) != 0)
		return (ENOMEM);
	for (i = 0; i < IWM_RX_RING_COUNT; i++) {
		if (iwm_dma_alloc(sc, &r->rx[i], IWM_RBUF_SIZE,
		    256, DDI_DMA_READ) != 0)
			return (ENOMEM);
		desc[i] = LE_32((uint32_t)(iwm_dma_addr(&r->rx[i]) >> 8));
	}
	/* End the allocator's host-side test sync before device publication. */
	if (iwm_sync(&sc->dma[0], DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&sc->dma[2], DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&sc->dma[3], DDI_DMA_SYNC_FORDEV) != 0 ||
	    iwm_sync(&r->scheduler, DDI_DMA_SYNC_FORDEV) != 0)
		return (EIO);
	for (i = 0; i < IWM_MAX_QUEUES; i++) {
		if (iwm_sync(&r->tx[i], DDI_DMA_SYNC_FORDEV) != 0)
			return (EIO);
	}
	for (i = 0; i < IWM_RX_RING_COUNT; i++) {
		if (iwm_sync(&r->rx[i], DDI_DMA_SYNC_FORDEV) != 0)
			return (EIO);
	}
	if (!sc->identity.valid) {
		for (i = 0; i < IWM_NVM_NUM_OF_SECTIONS; i++)
			r->nvm[i] = kmem_zalloc(IWM_NVM_LIMIT, KM_SLEEP);
	}
	return (iwm_checkpoint(sc, "runtime-allocated"));
}

/*
 * Development opt-in performs one INIT/NVM cycle; iwm-full-init additionally
 * calibrates and restarts REGULAR. No retries, MAC or packet submissions.
 */
int
iwm_init_nvm(struct iwm_softc *sc)
{
	struct iwm_runtime *r;
	int error, stop_error, host_error;
	clock_t idle_end;

	ASSERT(sc->run == NULL);
	r = kmem_zalloc(sizeof (*r), KM_SLEEP);
	cv_init(&r->cv, NULL, CV_DRIVER, NULL);
	mutex_enter(&sc->lock);
	sc->run = r;
	mutex_exit(&sc->lock);
	r->image = IWM_FW_INIT;
	r->generation = ++sc->generation;
	r->full_cycle = ddi_prop_get_int(DDI_DEV_T_ANY, sc->dip,
	    DDI_PROP_DONTPASS, "iwm-full-init", 0) != 0;
	r->scan.enabled = ddi_prop_get_int(DDI_DEV_T_ANY, sc->dip,
	    DDI_PROP_DONTPASS, "iwm-passive-scan", 0) != 0;
	if (sc->public_enabled) {
		r->full_cycle = sc->identity.valid;
		r->scan.enabled = sc->identity.valid;
		r->scan.attached = sc->net_attached;
	}
	if (r->scan.enabled) {
		uint_t i;

		for (i = 0; i < 13; i++) {
			if (sc->identity.channels[i] & 1)
				r->scan.channel[r->scan.channels++] = i + 1;
		}
	}
	if (r->scan.enabled && !r->full_cycle)
		return (EINVAL);
	if (!sc->identity.valid) {
		if ((error = iwm_fw_read(sc)) != 0)
			return (error);
		r->state = IWM_FW_LOADED;
		if ((error = iwm_fw_parse(&sc->fw)) != 0)
			return (error);
	}
	r->state = IWM_FW_PARSED;
	if (iwm_checkpoint(sc, "firmware-parsed") != 0)
		return (EIO);
	r->cmdqid = (sc->fw.capa[IWM_UCODE_TLV_CAPA_DQA_SUPPORT / 32] &
	    (1U << (IWM_UCODE_TLV_CAPA_DQA_SUPPORT % 32))) ?
	    IWM_DQA_CMD_QUEUE : IWM_CMD_QUEUE;
	dev_err(sc->dip, CE_NOTE, "!iwm firmware %u.%08x.%u "
	    "command-q=%u PHY=%08x timeout=%u us", sc->fw.version[0],
	    sc->fw.version[1], sc->fw.version[2], r->cmdqid,
	    sc->fw.phy_config, IWM_WAIT_US);
	if ((error = iwm_base_dma_alloc(sc)) != 0)
		return (error);
	if ((error = iwm_run_alloc(sc)) != 0)
		return (error);
	if (r->full_cycle && (error = iwm_paging_alloc(sc)) != 0)
		return (error);
	if (sc->intr_cap & DDI_INTR_FLAG_BLOCK)
		error = ddi_intr_block_enable(&sc->intr, 1);
	else
		error = ddi_intr_enable(sc->intr);
	if (error != DDI_SUCCESS)
		return (EIO);
	sc->intr_enabled = B_TRUE;
	mutex_enter(&sc->lock);
	error = r->error;
	if (error == 0)
		error = iwm_start(sc);
	if (error == 0)
		error = iwm_transport_init(sc);
	if (error == 0)
		error = iwm_upload(sc);
	if (error == 0)
		error = iwm_post_alive(sc);
	if (error == 0 && !sc->identity.valid)
		error = iwm_nvm(sc);
	if (error == 0 && r->scan.enabled && !sc->public_enabled) {
		mutex_exit(&sc->lock);
		error = iwm_scan_attach(sc);
		if (error == 0) {
			uint_t i;

			for (i = 0; i < 13; i++) {
				if (sc->identity.channels[i] & 1)
					r->scan.channel[r->scan.channels++] =
					    i + 1;
			}
		}
		mutex_enter(&sc->lock);
	}
	if (error == 0 && r->full_cycle)
		error = iwm_calibrate(sc);
	if (error == 0 && r->full_cycle)
		error = iwm_restart(sc);
	if (error == 0 && r->full_cycle)
		error = iwm_upload(sc);
	if (error == 0 && r->full_cycle)
		error = iwm_post_alive(sc);
	if (error == 0 && r->full_cycle) {
		/* Keep NIC access across the donor's REGULAR configuration. */
		error = iwm_nic_lock(sc);
		if (error == 0) {
			error = iwm_regular_config(sc);
			iwm_nic_unlock(sc);
		}
	}
	if (error == 0 && r->full_cycle) {
		idle_end = ddi_get_lbolt() + drv_usectohz(IWM_WAIT_US);
		while (r->error == 0 && ddi_get_lbolt() < idle_end)
			(void) cv_timedwait(&r->cv, &sc->lock, idle_end);
		error = r->error;
		if (error == 0)
			error = iwm_queues_check(sc, "REGULAR-idle");
	}
	if (error == 0 && sc->public_enabled && r->full_cycle) {
		mutex_exit(&sc->lock);
		return (0);
	}
	if (error == 0 && r->scan.enabled && !sc->public_enabled) {
		error = iwm_nic_lock(sc);
		if (error == 0) {
			error = iwm_passive_scan(sc);
			iwm_nic_unlock(sc);
		}
	}
	if (!sc->public_enabled && r->scan.attached &&
	    !r->scan.outstanding) {
		mutex_exit(&sc->lock);
		host_error = iwm_scan_detach(sc);
		if (error == 0)
			error = host_error;
		mutex_enter(&sc->lock);
	}
	if (error != 0)
		dev_err(sc->dip, CE_WARN,
		    "!iwm firmware cycle failed error=%d state=%u "
		    "INT=%08x FH=%08x RESET=%08x", error, r->state,
		    iwm_rd(sc, IWM_CSR_INT), iwm_rd(sc, IWM_CSR_FH_INT_STATUS),
		    iwm_rd(sc, IWM_CSR_RESET));
	if (r->first_error.reason != IWM_PROTO_OK)
		iwm_proto_report(sc, &r->first_error);
	stop_error = iwm_device_stop(sc, B_TRUE);
	dev_err(sc->dip, CE_NOTE,
	    "!iwm protocol original-error=%d reason=%u shutdown-error=%d",
	    error, r->first_error.reason, stop_error);
	mutex_exit(&sc->lock);
	host_error = iwm_intr_disable(sc);
	if (stop_error != 0 || host_error != 0)
		return (EIO);
	host_error = sc->public_enabled ? 0 : iwm_scan_detach(sc);
	if (error == 0)
		error = host_error;
	/* Include errors from the final callback, now drained by DDI. */
	if (error == 0)
		error = r->error;
	if (error == 0)
		dev_err(sc->dip, CE_NOTE,
		    "!iwm firmware cycle complete and stopped; full=%u "
		    "private-scan=%u no MAC; checkpoints=%d", r->full_cycle,
		    r->scan.enabled,
		    sc->attach_step);
	return (error);
}

/* Public operation ownership serializes these thread-context entrypoints. */
int
iwm_preinit(struct iwm_softc *sc)
{
	int error, cleanup;

	ASSERT(!sc->identity.valid && sc->run == NULL);
	error = iwm_init_nvm(sc);
	cleanup = iwm_run_free(sc);
	if (error != 0 || cleanup != 0) {
		sc->identity.valid = B_FALSE;
		return (error != 0 ? error : cleanup);
	}
	if (!sc->identity.valid)
		return (EINVAL);
	return (iwm_checkpoint(sc, "preinit-persistent"));
}

int
iwm_runtime_start(struct iwm_softc *sc)
{
	int error;

	if (!sc->identity.valid || !sc->net_attached || sc->run != NULL)
		return (EINVAL);
	error = iwm_init_nvm(sc);
	if (error != 0)
		sc->runtime_stop_error = iwm_run_free(sc);
	return (error);
}

/* Public operation ownership keeps this runtime generation allocated. */
int
iwm_runtime_status(struct iwm_softc *sc)
{
	struct iwm_runtime *r;
	int error;

	mutex_enter(&sc->lock);
	r = sc->run;
	error = r == NULL || r->stopped || r->state != IWM_REGULAR_IDLE ?
	    ENXIO : r->error;
	mutex_exit(&sc->lock);
	return (error);
}

void
iwm_scan_stop_request(struct iwm_softc *sc)
{
	mutex_enter(&sc->lock);
	if (sc->run != NULL) {
		sc->run->cancel_requested = B_TRUE;
		cv_broadcast(&sc->run->cv);
	}
	mutex_exit(&sc->lock);
}

int
iwm_runtime_stop(struct iwm_softc *sc)
{
	/* A SCAN owner must finish cancellation/drain before STOP can enter. */
	return (iwm_run_free(sc));
}

int
iwm_public_scan(struct iwm_softc *sc)
{
	struct iwm_scan_state *s;
	boolean_t configured, auxq, auxsta;
	uint_t i;
	int error;

	mutex_enter(&sc->lock);
	if (sc->run == NULL || !sc->net_attached ||
	    sc->ic.ic_state != IEEE80211_S_INIT || sc->run->scan.running ||
	    sc->run->scan.outstanding || sc->run->cancel_requested) {
		mutex_exit(&sc->lock);
		return (EBUSY);
	}
	s = &sc->run->scan;
	configured = s->configured;
	auxq = s->aux_queue;
	auxsta = s->aux_station;
	ASSERT(!s->delivering && s->queued == 0);
	bzero(s, sizeof (*s));
	s->enabled = s->attached = B_TRUE;
	s->configured = configured;
	s->aux_queue = auxq;
	s->aux_station = auxsta;
	for (i = 0; i < 13; i++) {
		if (sc->identity.channels[i] & 1)
			s->channel[s->channels++] = i + 1;
	}
	sc->scan_generation++;
	error = iwm_nic_lock(sc);
	if (error == 0) {
		error = iwm_passive_scan(sc);
		iwm_nic_unlock(sc);
	}
	mutex_exit(&sc->lock);
	if (error != 0) {
		/* No partial/stale results are advertised for a failed scan. */
		ieee80211_node_table_reset(&sc->ic.ic_scan);
	}
	return (error);
}
