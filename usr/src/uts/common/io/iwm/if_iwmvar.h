/* BEGIN CSTYLED */
/*	$OpenBSD: if_iwmvar.h,v 1.79 2025/12/01 16:30:46 stsp Exp $	*/

/*
 * Copyright (c) 2014 genua mbh <info@genua.de>
 * Copyright (c) 2014 Fixup Software Ltd.
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
 * Driver version we are currently based off of is
 * Linux 3.14.3 (tag id a2df521e42b1d9a23f620ac79dbfe8655a8391dd)
 *
 ***********************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2007 - 2013 Intel Corporation. All rights reserved.
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
 * Preserve the original donor licence notices above verbatim.
 */

/*
 * Derived from OpenBSD sys/dev/pci/if_iwmvar.h at
 * 0efabb066d34187a404f31d303b3b97103df1117, BSD licence option.
 * The ring shape and 8000-family limits are retained.  OS-owned resources
 * use illumos types.  TX aggregation is limited to TID0; no RX reorder,
 * radiotap or other device families.
 */
#ifndef _IF_IWMVAR_H
#define	_IF_IWMVAR_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/net80211.h>
#include <sys/mac_wifi.h>
#include <sys/taskq.h>
#include <io/iwm/if_iwmreg.h>
#include <io/iwm/if_iwmfw.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	IWM_TX_RING_COUNT	256
#define	IWM_ASSOC_TX_RINGS	5
#define	IWM_TX_AGG_QUEUE	10
#define	IWM_TX_AGG_WINDOW	64
#define	IWM_RX_RING_COUNT	256
#define	IWM_RBUF_SIZE		4096
#define	IWM_FWDMASEGSZ_8000	(320 * 1024)
#define	IWM_DEVICE_FAMILY_8000	2
#define	IWM_UCODE_SECT_MAX	16

/* Explicit handle/memory/binding ownership; stop DMA before releasing. */
struct iwm_dma_info {
	ddi_dma_handle_t	dma_hdl;
	ddi_acc_handle_t	acc_hdl;
	ddi_dma_cookie_t	cookie;
	caddr_t		vaddr;
	size_t		length;
	size_t		size;
	boolean_t	allocated;
	boolean_t	memory;
	boolean_t	bound;
};

/* Each streaming mapping holds a data-block reference until unbound. */
struct iwm_tx_mapping {
	ddi_dma_handle_t		handle;
	mblk_t			*mp;
	boolean_t		bound;
};

struct iwm_tx_data {
	struct iwm_dma_info	dma;
	struct iwm_tx_mapping	maps[IWM_NUM_OF_TBS - 2];
	uint_t			mapped;
	mblk_t			*mp;
	struct ieee80211_node	*ni;
	boolean_t		owned;
	boolean_t		completed;
	uint_t			generation;
	uint64_t		ba_generation;
	uint16_t		sequence;
	boolean_t		transmitted;
	boolean_t		acknowledged;
	clock_t			expires;
	uint32_t		status;
};

struct iwm_tx_ring {
	struct iwm_dma_info	desc_dma;
	struct iwm_dma_info	cmd_dma;
	struct iwm_tfd		*desc;
	struct iwm_device_cmd	*cmd;
	struct iwm_tx_data	data[IWM_TX_RING_COUNT];
	uint_t			qid;
	boolean_t		configured;
	boolean_t		released;
	uint8_t			station;
	uint8_t			fifo;
	uint_t			queued;
	uint_t			cur;
	uint_t			tail;
};

struct iwm_rx_ring {
	struct iwm_dma_info	desc_dma;
	struct iwm_dma_info	stat_dma;
	uint32_t		*desc;
	struct iwm_rb_status	*stat;
	struct iwm_dma_info	data[IWM_RX_RING_COUNT];
	uint_t			cur;
};

struct iwm_cfg {
	uint16_t	vendor;
	uint16_t	device;
	uint16_t	subvendor;
	uint16_t	subdevice;
	uint8_t		revision;
	uint_t		family;
	size_t		fw_dma_size;
	size_t		nvm_section_size;
	boolean_t	nvm_external;
	const char	*fwname;
};

#define	IWM_SILICON_C_STEP	2
#define	IWM_PASSIVE_DMA_COUNT	4

/* Immutable after the bounded attach-time NVM bootstrap. */
struct iwm_identity {
	boolean_t valid;
	uint8_t mac[6];
	uint16_t nvm_version;
	uint32_t radio_cfg;
	uint32_t sku;
	uint8_t tx_ant;
	uint8_t rx_ant;
	uint16_t channels[51];
	uint16_t lar;
};

enum iwm_operation {
	IWM_OP_NONE, IWM_OP_START, IWM_OP_SCAN, IWM_OP_STOP,
	IWM_OP_DETACH, IWM_OP_READ, IWM_OP_CONNECT, IWM_OP_DISCONNECT,
	IWM_OP_SELECT
};

enum iwm_runtime_owner {
	IWM_RUNTIME_PROVIDER = 0x01,
	IWM_RUNTIME_CONNECT = 0x02
};

/* Persistent worker/selector state; transport belongs to the runtime. */
#define	IWM_CONFIG_CHANNEL	0x01
#define	IWM_CONFIG_AUTH		0x02
#define	IWM_CONFIG_BSSTYPE	0x04
#define	IWM_CONFIG_ESSID	0x08
#define	IWM_CONFIG_OPEN		0x10
#define	IWM_CONFIG_COMMON	(IWM_CONFIG_CHANNEL | IWM_CONFIG_AUTH | \
	IWM_CONFIG_BSSTYPE | IWM_CONFIG_ESSID)

/* sc->lock protects snapshots; only the connection worker applies them. */
struct iwm_wme_state {
	struct iwm_ac_qos ac[4];
	uint64_t epoch;
	uint64_t requested;
	uint64_t applied;
	boolean_t accepting;
	boolean_t valid;
	int error;
};

struct iwm_connection {
	taskq_t *taskq;
	kcondvar_t cv;
	/* Key properties and retirement: crypto_lock -> ic_genlock -> lock. */
	kmutex_t crypto_lock;
	kthread_t *thread;
	ieee80211_node_t *node;
	boolean_t pending;
	boolean_t operation_owned;
	boolean_t reassociating;
	clock_t deadline;
	boolean_t finished;
	boolean_t cancel;
	boolean_t running;
	boolean_t link_up;
	boolean_t tx_admission;
	boolean_t rx_admission;
	/* Native WPA configuration enabled; ic_flags owns crypto semantics. */
	boolean_t wpa;
	boolean_t mlme_cancel;
	boolean_t clear_ie;
	boolean_t disable_wpa;
	boolean_t resetting;
	uint8_t essid[IEEE80211_NWID_LEN];
	uint_t esslen;
	uint_t channel;
	uint16_t basic_rates;
	uint_t configuration;
	struct iwm_wme_state wme;
	int error;
	int cleanup_error;
	int (*newstate)(ieee80211com_t *, enum ieee80211_state, int);
	void (*recv_action)(ieee80211_node_t *, const uint8_t *,
	    const uint8_t *);
	int (*send_action)(ieee80211_node_t *, int, int, uint16_t[4]);
};

struct iwm_softc {
	dev_info_t		*dip;
	const struct iwm_cfg	*cfg;
	ieee80211com_t		ic;
	struct iwm_identity	identity;
	struct iwm_connection	connection;
	wifi_data_t		wifi;
	kmutex_t		operation_lock;
	kcondvar_t		operation_cv;
	enum iwm_operation	operation;
	boolean_t		operation_initialized;
	boolean_t		public_enabled;
	boolean_t		net_attached;
	boolean_t		mac_registered;
	boolean_t		minor_created;
	boolean_t		runtime_started;
	uint_t			runtime_owners;
	boolean_t		desired_bssid_valid;
	boolean_t		associated_bssid_valid;
	uint8_t			desired_bssid[IEEE80211_ADDR_LEN];
	uint8_t			associated_bssid[IEEE80211_ADDR_LEN];
	boolean_t		stop_requested;
	boolean_t		detach_requested;
	uint_t			generation;
	uint_t			scan_generation;
	uint32_t		xmit_rejected;
	uint32_t		state_rejected;
	uint32_t		tx_rejected;
	uint32_t		multicast_calls;
	int			runtime_stop_error;
	ddi_acc_handle_t		pcih;
	ddi_acc_handle_t		regh;
	caddr_t			regs;
	off_t			regsize;
	ddi_intr_handle_t	intr;
	uint_t			intr_pri;
	int			intr_types;
	int			intr_cap;
	boolean_t		intr_allocated;
	boolean_t		intr_added;
	boolean_t		intr_enabled;
	boolean_t		lock_initialized;
	boolean_t		csr_valid;
	boolean_t		attached;
	boolean_t		intr_fault;
	uint32_t		intr_calls;
	uint32_t		hw_rev;
	uint32_t		gp_cntrl;
	uint16_t		pci_command;
	uint16_t		pcie_cap;
	uint16_t		msi_cap;
	uint16_t		pm_cap;
	int			fail_step;
	int			attach_step;
	kmutex_t		lock;
	struct iwm_dma_info	dma[IWM_PASSIVE_DMA_COUNT];
	struct iwm_fw_info	fw;
	struct iwm_runtime	*run;
};

/*
 * Attach/detach own resources in thread context. The lock serializes firmware
 * state, completion predicates and register windows with the MSI handler.
 * Bounded CV waits release it; allocations and host interrupt operations run
 * outside it. Stop device DMA before releasing published mappings, then
 * disable/remove the handler before destroying its lock or BAR.
 */
int iwm_pci_map(struct iwm_softc *);
void iwm_pci_unmap(struct iwm_softc *);
int iwm_reg_read(struct iwm_softc *, uint_t, uint32_t *);
int iwm_reg_write(struct iwm_softc *, uint_t, uint32_t);
int iwm_dma_alloc(struct iwm_softc *, struct iwm_dma_info *, size_t,
    uint_t, uint_t);
int iwm_dma_free(struct iwm_dma_info *);
int iwm_fw_read(struct iwm_softc *);
int iwm_checkpoint(struct iwm_softc *, const char *);
int iwm_intr_disable(struct iwm_softc *);
int iwm_init_nvm(struct iwm_softc *);
int iwm_base_dma_alloc(struct iwm_softc *);
int iwm_preinit(struct iwm_softc *);
int iwm_runtime_start(struct iwm_softc *);
int iwm_runtime_status(struct iwm_softc *);
int iwm_operation_enter(struct iwm_softc *, enum iwm_operation);
void iwm_operation_exit(struct iwm_softc *);
int iwm_runtime_acquire(struct iwm_softc *, enum iwm_runtime_owner);
int iwm_runtime_release(struct iwm_softc *, enum iwm_runtime_owner);
void iwm_connection_task(void *);
void iwm_connection_cancel(struct iwm_softc *);
int iwm_connection_disconnect(struct iwm_softc *);
mblk_t *iwm_connection_tx(struct iwm_softc *, mblk_t *);
int iwm_rsn_check(const uint8_t *, size_t);
void iwm_connection_keys_clear(struct iwm_softc *);
void iwm_connection_config_clear(struct iwm_softc *);
int iwm_runtime_stop(struct iwm_softc *);
int iwm_public_scan(struct iwm_softc *);
int iwm_select_bss(struct iwm_softc *, const uint8_t *, size_t, uint_t,
    ieee80211_node_t **);
int iwm_lar_prepare(struct iwm_softc *, uint_t);
void iwm_scan_stop_request(struct iwm_softc *);
int iwm_scan_attach(struct iwm_softc *);
int iwm_scan_detach(struct iwm_softc *);
int iwm_run_free(struct iwm_softc *);
int iwm_run_quiesce(struct iwm_softc *);
uint_t iwm_active_intr(struct iwm_softc *, uint32_t, uint32_t);
void iwm_fw_free(struct iwm_fw_info *);

#ifdef __cplusplus
}
#endif

#endif /* _IF_IWMVAR_H */
