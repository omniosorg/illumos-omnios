/*
 * Copyright (c) 2016 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 * Copyright 2023 Racktop Systems, Inc.
 */

#ifndef _VMBUS_VAR_H_
#define	_VMBUS_VAR_H_

#include <sys/list.h>
#include <sys/param.h>
#include <sys/sunddi.h>
#include <sys/param.h>

#include <sys/hyperv_busdma.h>
#include <sys/hyperv_illumos.h>

/*
 * Specify the SINTs (synthetic interrupt sources) to use for vmbus messages
 * and the vmbus event timer. These should be non-zero and different to each
 * other. The values below are taken from the FreeBSD driver.
 */
#define	VMBUS_SINT_MESSAGE	2
#define	VMBUS_SINT_TIMER	4

#define	VMBUS_CONNID_MESSAGE		1
#define	VMBUS_CONNID_EVENT		2

struct vmbus_message;
struct vmbus_softc;

typedef void		(*vmbus_chanmsg_proc_t)(struct vmbus_softc *,
			    const struct vmbus_message *);

#define	VMBUS_CHANMSG_PROC(name, func)	\
	[VMBUS_CHANMSG_TYPE_##name] = func
#define	VMBUS_CHANMSG_PROC_WAKEUP(name)	\
	VMBUS_CHANMSG_PROC(name, vmbus_msghc_wakeup)

struct vmbus_pcpu_data {
	uint64_t		intr_cnt;	/* Hyper-V interrupt counter */
	struct vmbus_message	*message;	/* shared messages */
	uint32_t		vcpuid;		/* virtual cpuid */
	int			event_flags_cnt; /* # of event flags */
	struct vmbus_evtflags	*event_flags;	/* event flags from host */

	/* Rarely used fields */
	struct hyperv_dma	message_dma;	/* busdma glue */
	struct hyperv_dma	event_flags_dma; /* busdma glue */
	ddi_taskq_t		*event_tq;	/* event taskq */
	ddi_taskq_t		*message_tq;	/* message taskq */
} __aligned(64);

typedef enum vmbus_scan_e {
	VMBUS_SCAN_NONE,
	VMBUS_SCAN_INPROGRESS,
	VMBUS_SCAN_COMPLETE,
} vmbus_scan_t;

struct vmbus_softc {
	void			(*vmbus_event_proc)(struct vmbus_softc *, int);
	ulong_t			*vmbus_tx_evtflags;
						/* event flags to host */
	struct vmbus_mnf	*vmbus_mnf2;	/* monitored by host */

	ulong_t			*vmbus_rx_evtflags;
						/* compat evtflgs from host */
	struct vmbus_channel	**vmbus_chmap;
	struct vmbus_xact_ctx	*vmbus_xc;
	struct vmbus_pcpu_data	vmbus_pcpu[NCPU]; /* XXXX */

	/*
	 * Rarely used fields
	 */

	dev_info_t		*vmbus_dev;
	int			vmbus_idtvec;
	ddi_intr_handle_t	vmbus_htable;
	uint32_t		vmbus_flags;	/* see VMBUS_FLAG_ */
	uint32_t		vmbus_version;
	uint32_t		vmbus_gpadl;

	/* Shared memory for vmbus_{rx,tx}_evtflags */
	void			*vmbus_evtflags;
	struct hyperv_dma	vmbus_evtflags_dma;

	void			*vmbus_mnf1;	/* monitored by VM, unused */
	struct hyperv_dma	vmbus_mnf1_dma;
	struct hyperv_dma	vmbus_mnf2_dma;

	vmbus_scan_t		vmbus_scan_status;
	kcondvar_t		vmbus_scandone_cv;
	struct task		vmbus_scandone_task;

	ddi_taskq_t		*vmbus_devtq;	/* for dev attach/detach */
	ddi_taskq_t		*vmbus_subchtq;	/* for sub-chan attach/detach */

	/* Primary channels */
	kmutex_t		vmbus_prichan_lock;
	list_t			vmbus_prichans;
	uint_t			vmbus_nprichans;

	/* Complete channel list */
	kmutex_t		vmbus_chan_lock;
	list_t			vmbus_chans;
	uint_t			vmbus_nchans;
};

#define	VMBUS_FLAG_ATTACHED	0x0001	/* vmbus was attached */
#define	VMBUS_FLAG_SYNIC	0x0002	/* SynIC was setup */

#define	VMBUS_PCPU_GET(sc, field, cpu)	(sc)->vmbus_pcpu[(cpu)].field
#define	VMBUS_PCPU_PTR(sc, field, cpu)	&(sc)->vmbus_pcpu[(cpu)].field

#ifdef DEBUG
extern int vmbus_debug;

#define	VMBUS_DEBUG(sc, ...)						\
	do {								\
		if (__predict_false(vmbus_debug > 0)) {			\
			dev_err((sc)->vmbus_dev, CE_CONT, __VA_ARGS__);	\
		}							\
	} while (0)
#else
#define	VMBUS_DEBUG(sc, ...)
#endif

struct vmbus_channel;
struct trapframe;
struct vmbus_message;
struct vmbus_msghc;

uint_t		vmbus_handle_intr(struct vmbus_softc *);
int		vmbus_add_child(struct vmbus_channel *);
int		vmbus_delete_child(struct vmbus_channel *);
void		vmbus_et_intr(struct trapframe *);
uint32_t	vmbus_gpadl_alloc(struct vmbus_softc *);

struct vmbus_msghc *
		vmbus_msghc_get(struct vmbus_softc *, size_t);
void		vmbus_msghc_put(struct vmbus_softc *, struct vmbus_msghc *);
void		*vmbus_msghc_dataptr(struct vmbus_msghc *);
int		vmbus_msghc_exec_noresult(struct vmbus_msghc *);
int		vmbus_msghc_exec(struct vmbus_softc *, struct vmbus_msghc *);
void		vmbus_msghc_exec_cancel(struct vmbus_softc *,
		    struct vmbus_msghc *);
const struct vmbus_message *
		vmbus_msghc_wait_result(struct vmbus_softc *,
		    struct vmbus_msghc *);
const struct vmbus_message *
		vmbus_msghc_poll_result(struct vmbus_softc *,
		    struct vmbus_msghc *);
void		vmbus_msghc_wakeup(struct vmbus_softc *,
		    const struct vmbus_message *);
void		vmbus_msghc_reset(struct vmbus_msghc *, size_t);

#endif	/* !_VMBUS_VAR_H_ */
