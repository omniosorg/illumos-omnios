/*
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
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
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * VM Bus Driver Implementation
 */
#include <sys/hyperv.h>
#include <sys/vmbus_xact.h>
#include <vmbus/hyperv_var.h>
#include <vmbus/vmbus_var.h>
#include <vmbus/vmbus_reg.h>
#include <vmbus/vmbus_chanvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/callo.h>
#include <sys/sysmacros.h>
#include <sys/smp_impldefs.h>
#include <sys/x_call.h>
#include <sys/x86_archext.h>
#include <sys/sunndi.h>
#include <sys/ddi_subrdefs.h>

#define	curcpu	CPU->cpu_id

#define	VMBUS_GPADL_START		0xe1e10

#ifdef	DEBUG
int vmbus_debug = 0;
int vmbus_ndi_debug = 0;
#endif

struct vmbus_msghc {
	struct vmbus_xact		*mh_xact;
	struct hypercall_postmsg_in	mh_inprm_save;
};

kmutex_t vmbus_lock;

static int			vmbus_attach(dev_info_t *, ddi_attach_cmd_t);
static int			vmbus_detach(dev_info_t *, ddi_detach_cmd_t);
static int			vmbus_init(struct vmbus_softc *);
static int			vmbus_connect(struct vmbus_softc *, uint32_t);
static int			vmbus_req_channels(struct vmbus_softc *sc);
static void			vmbus_disconnect(struct vmbus_softc *);
static int			vmbus_scan(struct vmbus_softc *);
static void			vmbus_scan_teardown(struct vmbus_softc *);
static void			vmbus_scan_done(struct vmbus_softc *,
				    const struct vmbus_message *);
static void			vmbus_chanmsg_handle(struct vmbus_softc *,
				    const struct vmbus_message *);
static void			vmbus_msg_task(void *);
static void			vmbus_synic_setup(void *);
static void			vmbus_synic_teardown(void *);
static int			vmbus_dma_alloc(struct vmbus_softc *);
static void			vmbus_dma_free(struct vmbus_softc *);
static int			vmbus_intr_setup(struct vmbus_softc *);
static void			vmbus_intr_teardown(struct vmbus_softc *);
static int			vmbus_doattach(struct vmbus_softc *);
static void			vmbus_event_proc_dummy(struct vmbus_softc *,
				    int);

typedef void (*vmbus_xcall_func_t)(void *);
static void			vmbus_xcall(vmbus_xcall_func_t, void *);

static void			*vmbus_state = NULL;
static struct vmbus_softc	*vmbus_sc;

uint32_t			vmbus_current_version;

static const uint32_t		vmbus_version[] = {
	VMBUS_VERSION_WIN10,
	VMBUS_VERSION_WIN8_1,
	VMBUS_VERSION_WIN8,
	VMBUS_VERSION_WIN7,
	VMBUS_VERSION_WS2008
};

static const vmbus_chanmsg_proc_t
vmbus_chanmsg_handlers[VMBUS_CHANMSG_TYPE_MAX] = {
	VMBUS_CHANMSG_PROC(CHOFFER_DONE, vmbus_scan_done),
	VMBUS_CHANMSG_PROC_WAKEUP(CONNECT_RESP)
};

static inline struct vmbus_softc *
vmbus_get_softc(void)
{
	return (vmbus_sc);
}

void
vmbus_msghc_reset(struct vmbus_msghc *mh, size_t dsize)
{
	struct hypercall_postmsg_in *inprm;

	if (dsize > HYPERCALL_POSTMSGIN_DSIZE_MAX)
		panic("invalid data size %llu", (u_longlong_t)dsize);

	inprm = vmbus_xact_req_data(mh->mh_xact);
	(void) memset(inprm, 0, HYPERCALL_POSTMSGIN_SIZE);
	inprm->hc_connid = VMBUS_CONNID_MESSAGE;
	inprm->hc_msgtype = HYPERV_MSGTYPE_CHANNEL;
	inprm->hc_dsize = (uint32_t)dsize;
}

struct vmbus_msghc *
vmbus_msghc_get(struct vmbus_softc *sc, size_t dsize)
{
	struct vmbus_msghc *mh = NULL;
	struct vmbus_xact *xact;

	if (dsize > HYPERCALL_POSTMSGIN_DSIZE_MAX)
		panic("invalid data size %llu", (u_longlong_t)dsize);

	xact = vmbus_xact_get(sc->vmbus_xc,
	    dsize + offsetof(struct hypercall_postmsg_in, hc_data[0]));
	if (xact == NULL)
		return (NULL);

	mh = vmbus_xact_priv(xact, sizeof (*mh));
	mh->mh_xact = xact;

	vmbus_msghc_reset(mh, dsize);
	return (mh);
}

/* ARGSUSED */
void
vmbus_msghc_put(struct vmbus_softc *sc, struct vmbus_msghc *mh)
{
	vmbus_xact_put(mh->mh_xact);
}

void *
vmbus_msghc_dataptr(struct vmbus_msghc *mh)
{
	struct hypercall_postmsg_in *inprm;

	inprm = vmbus_xact_req_data(mh->mh_xact);
	return (inprm->hc_data);
}

int
vmbus_msghc_exec_noresult(struct vmbus_msghc *mh)
{
	clock_t delay_us = MILLISEC;
	struct hypercall_postmsg_in *inprm;
	paddr_t inprm_paddr;
	int i;

	inprm = vmbus_xact_req_data(mh->mh_xact);
	inprm_paddr = vmbus_xact_req_paddr(mh->mh_xact);

	/*
	 * Save the input parameter so that we can restore the input
	 * parameter if the Hypercall fails.
	 */
	(void) memcpy(&mh->mh_inprm_save, inprm, HYPERCALL_POSTMSGIN_SIZE);

	/*
	 * In order to cope with transient failures, e.g. insufficient
	 * resources on host side, we retry the post message Hypercall
	 * several times. 20 retries seem sufficient.
	 */
#define	HC_RETRY_MAX	20

	for (i = 0; i < HC_RETRY_MAX; ++i) {
		uint64_t status;

		status = hypercall_post_message(inprm_paddr);
		switch (status) {
			case HYPERCALL_STATUS_SUCCESS:
				return (0);

			case HYPERCALL_STATUS_INVALID_HYPERCALL_CODE:
			case HYPERCALL_STATUS_INVALID_HYPERCALL_INPUT:
			case HYPERCALL_STATUS_INVALID_ALIGNMENT:
			case HYPERCALL_STATUS_INVALID_PARAMETER:
			case HYPERCALL_STATUS_OPERATION_DENIED:
			case HYPERCALL_STATUS_UNKNOWN_PROPERTY:
			case HYPERCALL_STATUS_PROPERTY_VALUE_OUT_OF_RANGE:
				/*
				 * These response codes mean that a retry
				 * with the same parameters will not succeed.
				 */
				return (EIO);
		}

		drv_usecwait(delay_us);
		/* If delay is under 2 seconds, double it for the next retry. */
		if (delay_us < MICROSEC * 2)
			delay_us *= 2;

		/* Restore input parameter and try again. */
		(void) memcpy(inprm, &mh->mh_inprm_save,
		    HYPERCALL_POSTMSGIN_SIZE);
	}

#undef HC_RETRY_MAX

	return (EIO);
}

int
vmbus_msghc_exec(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{
	int error;

	vmbus_xact_activate(mh->mh_xact);
	error = vmbus_msghc_exec_noresult(mh);
	if (error)
		vmbus_xact_deactivate(mh->mh_xact);

	return (error);
}

void
vmbus_msghc_exec_cancel(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{
	vmbus_xact_deactivate(mh->mh_xact);
}

const struct vmbus_message *
vmbus_msghc_wait_result(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{
	size_t resp_len;

	return (vmbus_xact_wait(mh->mh_xact, &resp_len));
}

const struct vmbus_message *
vmbus_msghc_poll_result(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{
	size_t resp_len;

	return (vmbus_xact_poll(mh->mh_xact, &resp_len));
}

void
vmbus_msghc_wakeup(struct vmbus_softc *sc, const struct vmbus_message *msg)
{
	vmbus_xact_ctx_wakeup(sc->vmbus_xc, msg, sizeof (*msg));
}

uint32_t
vmbus_gpadl_alloc(struct vmbus_softc *sc)
{
	uint32_t gpadl;

again:
	gpadl = atomic_inc_32_nv(&sc->vmbus_gpadl) - 1;
	if (gpadl == 0)
		goto again;
	return (gpadl);
}

static int
vmbus_connect(struct vmbus_softc *sc, uint32_t version)
{
	struct vmbus_chanmsg_connect *req;
	const struct vmbus_message *msg;
	struct vmbus_msghc *mh;
	int error, done = 0;

	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL)
		return (ENXIO);

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CONNECT;
	req->chm_ver = version;
	req->chm_evtflags = sc->vmbus_evtflags_dma.hv_paddr;
	req->chm_mnf1 = sc->vmbus_mnf1_dma.hv_paddr;
	req->chm_mnf2 = sc->vmbus_mnf2_dma.hv_paddr;

	error = vmbus_msghc_exec(sc, mh);
	if (error) {
		vmbus_msghc_put(sc, mh);
		return (error);
	}

	msg = vmbus_msghc_wait_result(sc, mh);
	done = ((const struct vmbus_chanmsg_connect_resp *)
	    msg->msg_data)->chm_done;

	vmbus_msghc_put(sc, mh);

	return (done ? 0 : EOPNOTSUPP);
}

static int
vmbus_init(struct vmbus_softc *sc)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(vmbus_version); ++i) {
		int error;

		error = vmbus_connect(sc, vmbus_version[i]);
		if (!error) {
			char version[16];

			vmbus_current_version = vmbus_version[i];
			sc->vmbus_version = vmbus_version[i];
			(void) snprintf(version, sizeof (version),
			    "%u.%u", VMBUS_VERSION_MAJOR(sc->vmbus_version),
			    VMBUS_VERSION_MINOR(sc->vmbus_version));
			dev_err(sc->vmbus_dev, CE_CONT, "?version %s",
			    version);
			(void) ddi_prop_update_string(DDI_DEV_T_NONE,
			    sc->vmbus_dev, VMBUS_VERSION, version);
			return (0);
		}
	}
	return (ENXIO);
}

static void
vmbus_disconnect(struct vmbus_softc *sc)
{
	struct vmbus_chanmsg_disconnect *req;
	struct vmbus_msghc *mh;
	int error;

	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL) {
		dev_err(sc->vmbus_dev, CE_WARN,
		    "can not get msg hypercall for disconnect");
		return;
	}

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_DISCONNECT;

	error = vmbus_msghc_exec_noresult(mh);
	vmbus_msghc_put(sc, mh);

	if (error) {
		dev_err(sc->vmbus_dev, CE_WARN,
		    "disconnect msg hypercall failed");
	}
}

static int
vmbus_req_channels(struct vmbus_softc *sc)
{
	struct vmbus_chanmsg_chrequest *req;
	struct vmbus_msghc *mh;
	int error;

	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL)
		return (ENXIO);

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CHREQUEST;

	error = vmbus_msghc_exec_noresult(mh);
	vmbus_msghc_put(sc, mh);

	return (error);
}

static void
vmbus_scan_done(struct vmbus_softc *sc,
    const struct vmbus_message *msg __unused)
{
	mutex_enter(&vmbus_lock);
	sc->vmbus_scan_status = VMBUS_SCAN_COMPLETE;
	cv_broadcast(&sc->vmbus_scandone_cv);
	mutex_exit(&vmbus_lock);
}

static int
vmbus_scan(struct vmbus_softc *sc)
{
	int error;

	VMBUS_DEBUG(sc, "?%s: starting scan\n", __func__);

	mutex_enter(&vmbus_lock);

	switch (sc->vmbus_scan_status) {
	case VMBUS_SCAN_COMPLETE:
		/*
		 * Another thread also invoked vmbus_scan(), but we got in
		 * before it could finish, just piggyback off their results.
		 */
		mutex_exit(&vmbus_lock);
		return (NDI_SUCCESS);
	case VMBUS_SCAN_NONE:
		/* Start vmbus scanning. */
		sc->vmbus_scan_status = VMBUS_SCAN_INPROGRESS;

		error = vmbus_req_channels(sc);
		if (error != 0) {
			sc->vmbus_scan_status = VMBUS_SCAN_NONE;
			mutex_exit(&vmbus_lock);
			dev_err(sc->vmbus_dev, CE_WARN,
			    "channel request failed: %d", error);
			return (error);
		}

		break;
	case VMBUS_SCAN_INPROGRESS:
		VMBUS_DEBUG(sc, "?%s: scan already in progress; waiting\n",
		    __func__);

		break;
	}

	/*
	 * Wait for all vmbus devices from the initial channel offers to be
	 * attached.
	 */
	while (sc->vmbus_scan_status != VMBUS_SCAN_COMPLETE)
		cv_wait(&sc->vmbus_scandone_cv, &vmbus_lock);

	sc->vmbus_scan_status = VMBUS_SCAN_NONE;
	mutex_exit(&vmbus_lock);

	VMBUS_DEBUG(sc, "?%s: device scan done\n", __func__);
	return (NDI_SUCCESS);
}

static void
vmbus_scan_teardown(struct vmbus_softc *sc)
{
	ddi_taskq_t *tq = NULL;

	ASSERT(MUTEX_HELD(&vmbus_lock));

	if (sc->vmbus_devtq != NULL) {
		tq = sc->vmbus_devtq;
		sc->vmbus_devtq = NULL;
		mutex_exit(&vmbus_lock);

		ddi_taskq_destroy(tq);
		mutex_enter(&vmbus_lock);
	}

	if (sc->vmbus_subchtq != NULL) {
		tq = sc->vmbus_subchtq;
		sc->vmbus_subchtq = NULL;
		mutex_exit(&vmbus_lock);

		ddi_taskq_destroy(tq);
		mutex_enter(&vmbus_lock);
	}
}

/*
 * Split name (driver@addr) into its component parts. Returns -1 if either
 * name is malformed, driver is too small for the result, or addr is
 * too small for the result.
 */
static int
vmbus_parse_name(const char *name, char *drv, size_t drvlen, char *addr,
    size_t addrlen)
{
	size_t i = 0;

	/* Copy up to '@' into drv */
	while (*name != '\0' && *name != '@' && i < drvlen - 1) {
		*drv++ = *name++;
		i++;
	}
	*drv = '\0';

	if (*name == '\0')
		return (-1);

	ASSERT(*name == '@');
	name++;

	/* Copy addr */
	i = 0;
	while (*name != '\0' && i < addrlen - 1) {
		*addr++ = *name++;
		i++;
	}

	if (*name != '\0')
		return (-1);
	*addr = '\0';

	return (0);
}

static int
vmbus_config_one_impl(struct vmbus_channel *chan)
{
	if (chan->ch_dev != NULL) {
		/* node already exists and should be bound */
		return (NDI_SUCCESS);
	}

	return (vmbus_add_child(chan));
}

static int
vmbus_config_one(struct vmbus_softc *sc, const char *name)
{
	char driver[HYPERV_GUID_STRLEN + 9] = { 0 }; /* hv_vmbus, + <guid> */
	char inst[HYPERV_GUID_STRLEN] = { 0 };
	struct hyperv_guid inst_guid = { 0 };
	struct vmbus_channel *chan = NULL;
	int rc;

	rc = vmbus_parse_name(name, driver, sizeof (driver), inst,
	    sizeof (inst));
	if (rc != 0) {
		dev_err(sc->vmbus_dev, CE_NOTE, "%s: invalid device name '%s'",
		    __func__, name);
		return (NDI_FAILURE);
	}

	if (!hyperv_str2guid(inst, &inst_guid)) {
		dev_err(sc->vmbus_dev, CE_NOTE, "%s: invalid instance guid '%s'",
		    __func__, inst);
		return (NDI_FAILURE);
	}

	/* This returns a refheld chan */
	chan = vmbus_chan_getguid(sc, &inst_guid, NULL);
	if (chan == NULL) {
		VMBUS_DEBUG(sc, "?%s: device '%s' not found", __func__, name);
		return (NDI_FAILURE);
	}

	rc = vmbus_config_one_impl(chan);
	vmbus_chan_refrele(chan);
	return (rc);

}

static int
vmbus_config_all(struct vmbus_softc *sc)
{
	struct vmbus_channel **chlist, *chan;
	uint_t i, nchan;

	/*
	 * This is ugly, but given the almost total lack of documentation
	 * surrounding the nexus and dev tree APIs, it's not clear we can do
	 * any better. Specifically, when onlining a device that is itself
	 * a nexus driver (e.g. a SCSI HBA), it can cause recursive calls
	 * into vmbus_config(), which could deadlock. At the same time, it's
	 * not clear we can rely on our list of channels not changing while
	 * iterating through them without holding vmbus_chan_lock over the
	 * entire list of primary channels.
	 *
	 * As a result, we allocate an array of primary channels and refhold
	 * all of them so we can iterate through them without holding
	 * vmbus_chan_lock.
	 */
	mutex_enter(&sc->vmbus_prichan_lock);
	nchan = sc->vmbus_nprichans;
	chlist = kmem_zalloc(nchan * sizeof (struct vmbus_channel *),
	    KM_SLEEP);
	i = 0;
	for (chan = list_head(&sc->vmbus_prichans); chan != NULL;
	    chan = list_next(&sc->vmbus_prichans, chan)) {
		chlist[i++] = chan;
		vmbus_chan_refhold(chan);
	}
	mutex_exit(&sc->vmbus_prichan_lock);

	for (i = 0; i < nchan; i++) {
		(void) vmbus_config_one_impl(chlist[i]);
		vmbus_chan_refrele(chlist[i]);
	}

	kmem_free(chlist, nchan * sizeof (struct vmbus_channel *));
	return (NDI_SUCCESS);
}

static int
vmbus_config(dev_info_t *parent, uint_t flag, ddi_bus_config_op_t op, void *arg,
    dev_info_t **childp)
{
	struct vmbus_softc *sc;
	int rc = NDI_SUCCESS;

	sc = ddi_get_soft_state(vmbus_state, ddi_get_instance(parent));

	ndi_devi_enter(parent);

	switch (op) {
	case BUS_CONFIG_ONE:
		VMBUS_DEBUG(sc, "?BUS_CONFIG_ONE %s\n", (const char *)arg);
		rc = vmbus_config_one(sc, arg);
		break;
	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:
		VMBUS_DEBUG(sc, "?BUS_CONFIG_DRIVER/ALL\n");

		rc = vmbus_scan(sc);
		if (rc != NDI_SUCCESS)
			goto done;

		rc = vmbus_config_all(sc);
		break;
	default:
		rc = NDI_FAILURE;
		break;
	}

done:
	ndi_devi_exit(parent);
	if (rc == NDI_SUCCESS) {
		flag |= NDI_ONLINE_ATTACH | NDI_CONFIG;
#ifdef DEBUG
		if (__predict_false(vmbus_ndi_debug))
			flag |= NDI_DEVI_DEBUG;
#endif

		rc = ndi_busop_bus_config(parent, flag, op, arg, childp, 0);
	}
	return (rc);
}

static int
vmbus_unconfig(dev_info_t *parent, uint_t flag, ddi_bus_config_op_t op,
    void *arg)
{
	struct vmbus_softc *sc __maybe_unused;
	int rc;

	sc = ddi_get_soft_state(vmbus_state, ddi_get_instance(parent));

	switch (op) {
	case BUS_UNCONFIG_ONE:
		VMBUS_DEBUG(sc, "?BUS_UNCONFIG_ONE %s\n", (const char *)arg);
		break;
	case BUS_UNCONFIG_DRIVER:
	case BUS_UNCONFIG_ALL:
		VMBUS_DEBUG(sc, "?BUS_UNCONFIG_DRIVER/ALL\n");
		break;
	default:
		break;
	}

	ndi_devi_enter(parent);
	rc = ndi_busop_bus_unconfig(parent, flag, op, arg);
	ndi_devi_exit(parent);

	return (rc);
}

static void
vmbus_chanmsg_handle(struct vmbus_softc *sc, const struct vmbus_message *msg)
{
	vmbus_chanmsg_proc_t msg_proc;
	uint32_t msg_type;

	msg_type = ((const struct vmbus_chanmsg_hdr *)msg->msg_data)->chm_type;
	if (msg_type >= VMBUS_CHANMSG_TYPE_MAX) {
		dev_err(sc->vmbus_dev, CE_WARN, "unknown message type 0x%x",
		    msg_type);
		return;
	}

	msg_proc = vmbus_chanmsg_handlers[msg_type];
	if (msg_proc != NULL)
		msg_proc(sc, msg);

	/* Channel specific processing */
	vmbus_chan_msgproc(sc, msg);
}

static void
vmbus_msg_task(void *arg)
{
	struct vmbus_message *msg_base = (struct vmbus_message *)arg;
	volatile struct vmbus_message *msg;
	struct vmbus_softc *sc = vmbus_get_softc();

	msg = msg_base + VMBUS_SINT_MESSAGE;
	for (;;) {
		if (msg->msg_type == HYPERV_MSGTYPE_NONE) {
			/* No message */
			break;
		} else if (msg->msg_type == HYPERV_MSGTYPE_CHANNEL) {
			/* Channel message */
			vmbus_chanmsg_handle(sc, (struct vmbus_message *)msg);
		}

		msg->msg_type = HYPERV_MSGTYPE_NONE;
		/*
		 * Make sure the write to msg_type (i.e. set to
		 * HYPERV_MSGTYPE_NONE) happens before we read the
		 * msg_flags and EOMing. Otherwise, the EOMing will
		 * not deliver any more messages since there is no
		 * empty slot
		 *
		 * NOTE:
		 * membar_sync() is used here, since
		 * atomic_thread_fence_seq_cst()
		 * will become compiler fence on UP kernel.
		 */
		membar_sync();
		if (msg->msg_flags & VMBUS_MSGFLAG_PENDING) {
			/*
			 * This will cause message queue rescan to possibly
			 * deliver another msg from the hypervisor
			 */
			wrmsr(MSR_HV_EOM, 0);
		}
	}
}

static int
vmbus_handle_intr1(struct vmbus_softc *sc, int cpu)
{
	volatile struct vmbus_message *msg;
	struct vmbus_message *msg_base;

	msg_base = VMBUS_PCPU_GET(sc, message, cpu);

	/*
	 * Check event timer.
	 *
	 * TODO: move this to independent IDT vector.
	 */
	msg = msg_base + VMBUS_SINT_TIMER;
	if (msg->msg_type == HYPERV_MSGTYPE_TIMER_EXPIRED) {
		msg->msg_type = HYPERV_MSGTYPE_NONE;

		/*
		 * Make sure the write to msg_type (i.e. set to
		 * HYPERV_MSGTYPE_NONE) happens before we read the
		 * msg_flags and EOMing. Otherwise, the EOMing will
		 * not deliver any more messages since there is no
		 * empty slot
		 *
		 * NOTE:
		 * membar_sync() is used here, since
		 * atomic_thread_fence_seq_cst()
		 * will become compiler fence on UP kernel.
		 */
		membar_sync();
		if (msg->msg_flags & VMBUS_MSGFLAG_PENDING) {
			/*
			 * This will cause message queue rescan to possibly
			 * deliver another msg from the hypervisor
			 */
			wrmsr(MSR_HV_EOM, 0);
		}
	}

	/*
	 * Check events.  Hot path for network and storage I/O data; high rate.
	 *
	 * NOTE:
	 * As recommended by the Windows guest fellows, we check events before
	 * checking messages.
	 */
	sc->vmbus_event_proc(sc, cpu);

	/*
	 * Check messages.  Mainly management stuffs; ultra low rate.
	 */
	msg = msg_base + VMBUS_SINT_MESSAGE;
	if (__predict_false(msg->msg_type != HYPERV_MSGTYPE_NONE)) {
		/*
		 * Pass in the msg_base to the vmbus_msg_task so that it knows
		 * which message to process.
		 */
		(void) ddi_taskq_dispatch(VMBUS_PCPU_GET(sc, message_tq, cpu),
		    vmbus_msg_task, msg_base, DDI_SLEEP);
	}

	return (DDI_INTR_CLAIMED);
}

uint_t
vmbus_handle_intr(struct vmbus_softc *sc)
{
	int cpu = curcpu;

	/*
	 * Disable preemption.
	 */
	kpreempt_disable();

	/*
	 * Do a little interrupt counting.
	 */
	VMBUS_PCPU_GET(sc, intr_cnt, cpu)++;

	int rc = vmbus_handle_intr1(sc, cpu);

	/*
	 * Enable preemption.
	 */
	kpreempt_enable();
	return (rc);

}

static void
vmbus_synic_setup(void *xsc)
{
	struct vmbus_softc *sc = xsc;
	int cpu = curcpu;
	uint64_t val, orig;
	uint32_t sint;

	if (hyperv_privs_mask & CPUID_HV_MSR_VP_INDEX) {
		/* Save virtual processor id. */
		VMBUS_PCPU_GET(sc, vcpuid, cpu) = rdmsr(MSR_HV_VP_INDEX);
	} else {
		/* Set virtual processor id to 0 for compatibility. */
		VMBUS_PCPU_GET(sc, vcpuid, cpu) = 0;
	}

	/*
	 * Setup the SynIC message.
	 */
	orig = rdmsr(MSR_HV_SIMP);
	val = MSR_HV_SIMP_ENABLE | (orig & MSR_HV_SIMP_RSVD_MASK) |
	    ((VMBUS_PCPU_GET(sc, message_dma.hv_paddr, cpu) >> PAGE_SHIFT) <<
	    MSR_HV_SIMP_PGSHIFT);
	wrmsr(MSR_HV_SIMP, val);

	/*
	 * Setup the SynIC event flags.
	 */
	orig = rdmsr(MSR_HV_SIEFP);
	val = MSR_HV_SIEFP_ENABLE | (orig & MSR_HV_SIEFP_RSVD_MASK) |
	    ((VMBUS_PCPU_GET(sc, event_flags_dma.hv_paddr, cpu)
	    >> PAGE_SHIFT) << MSR_HV_SIEFP_PGSHIFT);
	wrmsr(MSR_HV_SIEFP, val);

	if (sc->vmbus_idtvec >= 0) {
		/*
		 * Configure and unmask SINT for message and event flags.
		 */
		sint = MSR_HV_SINT0 + VMBUS_SINT_MESSAGE;
		orig = rdmsr(sint);
		val = sc->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
		    (orig & MSR_HV_SINT_RSVD_MASK);
		dev_err(sc->vmbus_dev, CE_CONT, "?SINT val %llx\n",
		    (u_longlong_t)val);
		wrmsr(sint, val);

		/*
		 * Configure and unmask SINT for timer.
		 */
		sint = MSR_HV_SINT0 + VMBUS_SINT_TIMER;
		orig = rdmsr(sint);
		val = sc->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
		    (orig & MSR_HV_SINT_RSVD_MASK);
		wrmsr(sint, val);
	}

	/*
	 * All done; enable SynIC.
	 */
	orig = rdmsr(MSR_HV_SCONTROL);
	val = MSR_HV_SCTRL_ENABLE | (orig & MSR_HV_SCTRL_RSVD_MASK);
	wrmsr(MSR_HV_SCONTROL, val);
}

/* ARGSUSED */
static void
vmbus_synic_teardown(void *arg)
{
	uint64_t orig;
	uint32_t sint;

	/*
	 * Disable SynIC.
	 */
	orig = rdmsr(MSR_HV_SCONTROL);
	wrmsr(MSR_HV_SCONTROL, (orig & MSR_HV_SCTRL_RSVD_MASK));

	/*
	 * Mask message and event flags SINT.
	 */
	sint = MSR_HV_SINT0 + VMBUS_SINT_MESSAGE;
	orig = rdmsr(sint);
	wrmsr(sint, orig | MSR_HV_SINT_MASKED);

	/*
	 * Mask timer SINT.
	 */
	sint = MSR_HV_SINT0 + VMBUS_SINT_TIMER;
	orig = rdmsr(sint);
	wrmsr(sint, orig | MSR_HV_SINT_MASKED);

	/*
	 * Teardown SynIC message.
	 */
	orig = rdmsr(MSR_HV_SIMP);
	wrmsr(MSR_HV_SIMP, (orig & MSR_HV_SIMP_RSVD_MASK));

	/*
	 * Teardown SynIC event flags.
	 */
	orig = rdmsr(MSR_HV_SIEFP);
	wrmsr(MSR_HV_SIEFP, (orig & MSR_HV_SIEFP_RSVD_MASK));
}

static int
vmbus_dma_alloc(struct vmbus_softc *sc)
{
	uint8_t *evtflags;
	int cpu;

	for (cpu = 0; cpu < ncpus; cpu++) {
		void *ptr;

		/*
		 * Per-cpu messages and event flags.
		 */
		ptr = hyperv_dmamem_alloc(sc->vmbus_dev, PAGE_SIZE, 0,
		    PAGE_SIZE, VMBUS_PCPU_PTR(sc, message_dma, cpu),
		    DDI_DMA_RDWR);
		if (ptr == NULL)
			return (ENOMEM);
		VMBUS_PCPU_GET(sc, message, cpu) = ptr;

		ptr = hyperv_dmamem_alloc(sc->vmbus_dev, PAGE_SIZE, 0,
		    PAGE_SIZE, VMBUS_PCPU_PTR(sc, event_flags_dma, cpu),
		    DDI_DMA_RDWR);
		if (ptr == NULL)
			return (ENOMEM);
		VMBUS_PCPU_GET(sc, event_flags, cpu) = ptr;
	}

	evtflags = (uint8_t *)hyperv_dmamem_alloc(sc->vmbus_dev, PAGE_SIZE, 0,
	    PAGE_SIZE, &sc->vmbus_evtflags_dma, DDI_DMA_RDWR);
	if (evtflags == NULL)
		return (ENOMEM);
	sc->vmbus_rx_evtflags = (ulong_t *)evtflags;
	sc->vmbus_tx_evtflags = (ulong_t *)(evtflags + (PAGE_SIZE / 2));
	sc->vmbus_evtflags = evtflags;

	sc->vmbus_mnf1 = hyperv_dmamem_alloc(sc->vmbus_dev, PAGE_SIZE, 0,
	    PAGE_SIZE, &sc->vmbus_mnf1_dma, DDI_DMA_RDWR);
	if (sc->vmbus_mnf1 == NULL)
		return (ENOMEM);

	sc->vmbus_mnf2 = (struct vmbus_mnf *)hyperv_dmamem_alloc(sc->vmbus_dev,
	    PAGE_SIZE, 0, sizeof (struct vmbus_mnf), &sc->vmbus_mnf2_dma,
	    DDI_DMA_RDWR);
	if (sc->vmbus_mnf2 == NULL)
		return (ENOMEM);

	return (0);
}

static void
vmbus_dma_free(struct vmbus_softc *sc)
{
	int cpu;

	if (sc->vmbus_evtflags != NULL) {
		hyperv_dmamem_free(&sc->vmbus_evtflags_dma);
		sc->vmbus_evtflags = NULL;
		sc->vmbus_rx_evtflags = NULL;
		sc->vmbus_tx_evtflags = NULL;
	}
	if (sc->vmbus_mnf1 != NULL) {
		hyperv_dmamem_free(&sc->vmbus_mnf1_dma);
		sc->vmbus_mnf1 = NULL;
	}
	if (sc->vmbus_mnf2 != NULL) {
		hyperv_dmamem_free(&sc->vmbus_mnf2_dma);
		sc->vmbus_mnf2 = NULL;
	}

	for (cpu = 0; cpu < ncpus; cpu++) {
		if (VMBUS_PCPU_GET(sc, message, cpu) != NULL) {
			hyperv_dmamem_free(
			    VMBUS_PCPU_PTR(sc, message_dma, cpu));
			VMBUS_PCPU_GET(sc, message, cpu) = NULL;
		}
		if (VMBUS_PCPU_GET(sc, event_flags, cpu) != NULL) {
			hyperv_dmamem_free(
			    VMBUS_PCPU_PTR(sc, event_flags_dma, cpu));
			VMBUS_PCPU_GET(sc, event_flags, cpu) = NULL;
		}
	}
}

#define	IPL_VMBUS	0x1

static int
vmbus_intr_setup_cpu(cpu_setup_t what, int cpu, void *arg)
{
	struct vmbus_softc *sc = arg;

	switch (what) {
	case CPU_ON:
	case CPU_SETUP:
		break;
	default:
		return (0);
	}

	if (VMBUS_PCPU_PTR(sc, event_tq, cpu) != NULL) {
		char tq_name[MAXPATHLEN];

		/* Allocate an interrupt counter for Hyper-V interrupt */
		VMBUS_PCPU_GET(sc, intr_cnt, cpu) = 0;

		/*
		 * Setup taskq to handle events.  Task will be per-
		 * channel.
		 */
		(void) snprintf(tq_name, sizeof (tq_name), "hyperv_event_%d",
		    cpu);
		*VMBUS_PCPU_PTR(sc, event_tq, cpu) = ddi_taskq_create(NULL,
		    tq_name, 1, maxclsyspri, 0);

		/*
		 * Setup tasks and taskq to handle messages.
		 */
		(void) snprintf(tq_name, sizeof (tq_name), "hyperv_msg_%d",
		    cpu);
		*VMBUS_PCPU_PTR(sc, message_tq, cpu) = ddi_taskq_create(NULL,
		    tq_name, 1, maxclsyspri, 0);
	}

	return (0);
}

static int
vmbus_intr_setup(struct vmbus_softc *sc)
{
	cpu_t *cp;

	/*
	 * We are called early enough in the boot process that typically only
	 * a single CPU has been started. Since we don't want to try to
	 * fanout the per-CPU data to non-existent CPUs, we must hook into
	 * when additional CPUs are started to create the per-CPU structs.
	 */
	mutex_enter(&cpu_lock);
	cp = cpu_active;
	do {
		(void) vmbus_intr_setup_cpu(CPU_ON, cp->cpu_seqid, sc);
	} while ((cp = cp->cpu_next_onln) != cpu_active);

	register_cpu_setup_func(vmbus_intr_setup_cpu, sc);
	mutex_exit(&cpu_lock);

	/* Checked in attach, but let's be careful. */
	if (psm_get_ipivect == NULL) {
		dev_err(sc->vmbus_dev, CE_PANIC, "%s: psm_get_ipivect is NULL",
		    __func__);
	}

	sc->vmbus_idtvec = psm_get_ipivect(IPL_VMBUS, -1);
	if (add_avintr(NULL, IPL_VMBUS, (avfunc)(uintptr_t)vmbus_handle_intr,
	    "Hyper-V vmbus", sc->vmbus_idtvec, (caddr_t)sc, NULL,
	    NULL, NULL) == 0) {
		dev_err(sc->vmbus_dev, CE_WARN,
		    "cannot find free IDT (%d) vector", sc->vmbus_idtvec);
		return (ENXIO);
	}
	dev_err(sc->vmbus_dev, CE_CONT, "?vmbus IDT vector %d\n",
	    sc->vmbus_idtvec);
	return (0);
}

static void
vmbus_intr_teardown(struct vmbus_softc *sc)
{
	int cpu;

	if (sc->vmbus_idtvec >= 0) {
		rem_avintr(NULL, IPL_VMBUS,
		    (avfunc)(uintptr_t)vmbus_handle_intr, sc->vmbus_idtvec);
		sc->vmbus_idtvec = -1;
	}

	mutex_enter(&cpu_lock);
	unregister_cpu_setup_func(vmbus_intr_setup_cpu, sc);
	mutex_exit(&cpu_lock);

	for (cpu = 0; cpu < ncpus; cpu++) {
		if (VMBUS_PCPU_GET(sc, event_tq, cpu) != NULL) {
			ddi_taskq_destroy(VMBUS_PCPU_GET(sc, event_tq, cpu));
			VMBUS_PCPU_GET(sc, event_tq, cpu) = NULL;
		}
		if (VMBUS_PCPU_GET(sc, message_tq, cpu) != NULL) {
			ddi_taskq_destroy(VMBUS_PCPU_GET(sc, message_tq, cpu));
			VMBUS_PCPU_GET(sc, message_tq, cpu) = NULL;
		}
	}
}

void
vmbus_walk_children(int (*walk_cb)(dev_info_t *, void *), void *arg)
{
	struct vmbus_softc *sc = vmbus_get_softc();
	ddi_walk_devs(sc->vmbus_dev, walk_cb, arg);
}

/*
 * The parent bus (i.e. vmbus) appears to be responsible for
 * naming their children (the APIs along with assumptions and
 * responsibilities are undocumented, so this is based on observation).
 *
 * Names are of the form 'nodename@address' (this is very likely
 * taken from OpenBoot). The nodename is what is used to identify
 * the type of device and is used to bind a device driver to the
 * device (usually via /etc/driver_aliases) while address is a
 * bus specific value to identify a specific instance of a device.
 *
 * For vmbus, each type of device (network, scsi, etc.) has their
 * own classid (guid), and every device also has a unique guid.
 * There's no notion of a bus address, but the device guid can
 * serve the same purpose to identify an instance of a device.
 *
 * This leads to a naming pattern of
 * 'hv_vmbus,<class guid>@<device guid>.
 *
 * One wrinkle is that early versions of the vmbus driver hard coded
 * a table of device names to guids (vmbus_devices). For those devices, the
 * naming is '<device_name_from_vmbus_devices>@<device guid>'. This had the
 * unfortunate side effect of any new vmbus device drivers requiring
 * an update of the vmbus driver as well. I.e. it was not enough to install the
 * new device driver and run 'add_drv(8)' to make it work. Newer devices
 * should not be added to vmbus_devices so that they get a
 * 'hv_vmbus,<class guid>@<device guid>' name.
 */
typedef struct hv_vmbus_device {
	char	*hv_name;
	char	*hv_devname;
	char	*hv_guid;
} hv_vmbus_device_t;

static hv_vmbus_device_t vmbus_devices[] = {
	{
	"Hyper-V Shutdown", "hv_shutdown",
	"0e0b6031-5213-4934-818b-38d90ced39db"
	},

	{
	"Hyper-V Timesync", "hv_timesync",
	"9527e630-d0ae-497b-adce-e80ab0175caf"
	},

	{
	"Hyper-V Heartbeat", "hv_heartbeat",
	"57164f39-9115-4e78-ab55-382f3bd5422d"
	},

	{
	"Hyper-V KVP", "hv_kvp",
	"a9a0f4e7-5a45-4d96-b827-8a841e8c03e6"
	},

	{
	"Hyper-V Network Interface", "hv_netvsc",
	"f8615163-df3e-46c5-913f-f2d2f965ed0e"
	},

	{
	"Hyper-V IDE Storage Interface", "blksvc",
	"32412632-86cb-44a2-9b5c-50d1417354f5"
	},

	{
	"Hyper-V SCSI Storage Interface", "hv_storvsc",
	"ba6163d9-04a1-4d29-b605-72e2ffb1dc7f"
	},

	{
	NULL,  NULL, NULL
	}
};

int
vmbus_add_child(struct vmbus_channel *chan)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	dev_info_t *parent = sc->vmbus_dev;
	hv_vmbus_device_t *dev;
	char classid[HYPERV_GUID_STRLEN] = { 0 };
	char devname[9 + HYPERV_GUID_STRLEN] = { 0 };

	(void) hyperv_guid2str(&chan->ch_guid_type, classid, sizeof (classid));

	/*
	 * Find a device that matches the classid in the channel.
	 */
	for (dev = vmbus_devices; dev->hv_guid != NULL; dev++) {
		if (strcmp(dev->hv_guid, classid) == 0) {
			(void) strlcpy(devname, dev->hv_devname,
			    sizeof (devname));
			break;
		}
	}

	ASSERT3P(chan->ch_dev, ==, NULL);

	if (devname[0] == '\0') {
		(void) snprintf(devname, sizeof (devname), "hv_vmbus,%s",
		    classid);
	}

	ndi_devi_alloc_sleep(parent, devname, DEVI_SID_NODEID, &chan->ch_dev);
	ddi_set_parent_data(chan->ch_dev, chan);

	if (ndi_devi_bind_driver(chan->ch_dev, 0) != NDI_SUCCESS) {
		(void) ndi_devi_offline(chan->ch_dev, NDI_DEVI_REMOVE);
		chan->ch_dev = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
vmbus_delete_child(struct vmbus_channel *chan)
{
	ASSERT(MUTEX_HELD(&vmbus_lock));

	if (chan->ch_dev == NULL)
		return (DDI_SUCCESS);

	if (ddi_prop_update_string(DDI_DEV_T_NONE, chan->ch_dev,
	    VMBUS_STATE, VMBUS_STATE_OFFLINE) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_WARN,
		    "Unable to set \"%s(%s)\" property", VMBUS_STATE,
		    VMBUS_STATE_OFFLINE);
		return (DDI_FAILURE);
	}

	if (ndi_devi_offline(chan->ch_dev, NDI_DEVI_REMOVE) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_WARN, "Unable to offline device");
		return (DDI_FAILURE);
	}
	chan->ch_dev = NULL;

	return (DDI_SUCCESS);
}

uint32_t
vmbus_get_version(void)
{
	struct vmbus_softc *sc = vmbus_get_softc();

	return (sc->vmbus_version);
}

int
vmbus_probe_guid(dev_info_t *dev, const struct hyperv_guid *guid)
{
	const struct vmbus_channel *chan = vmbus_get_channel(dev);

	if (memcmp(&chan->ch_guid_type, guid, sizeof (struct hyperv_guid)) == 0)
		return (0);
	return (ENXIO);
}

/*
 * @brief Main vmbus driver initialization routine.
 *
 * Here, we
 * - initialize the vmbus driver context
 * - setup various driver entry points
 * - invoke the vmbus hv main init routine
 * - get the irq resource
 * - invoke the vmbus to add the vmbus root device
 * - setup the vmbus root device
 * - retrieve the channel offers
 */
static int
vmbus_doattach(struct vmbus_softc *sc)
{
	int ret;

	if (sc->vmbus_flags & VMBUS_FLAG_ATTACHED)
		return (DDI_SUCCESS);

	sc->vmbus_gpadl = VMBUS_GPADL_START;

	mutex_init(&sc->vmbus_prichan_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&sc->vmbus_prichans, sizeof (struct vmbus_channel),
	    offsetof(struct vmbus_channel, ch_prilink));

	mutex_init(&sc->vmbus_chan_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&sc->vmbus_chans, sizeof (struct vmbus_channel),
	    offsetof(struct vmbus_channel, ch_link));
	sc->vmbus_chmap = kmem_zalloc(
	    sizeof (struct vmbus_channel *) * VMBUS_CHAN_MAX, KM_SLEEP);

	sc->vmbus_devtq = ddi_taskq_create(sc->vmbus_dev, "vmbus_dev", 1,
	    maxclsyspri, 0);
	sc->vmbus_subchtq = ddi_taskq_create(sc->vmbus_dev, "vmbus_subch", 1,
	    maxclsyspri, 0);

	/*
	 * Create context for "post message" Hypercalls
	 */
	sc->vmbus_xc = vmbus_xact_ctx_create(sc->vmbus_dev,
	    HYPERCALL_POSTMSGIN_SIZE, VMBUS_MSG_SIZE,
	    sizeof (struct vmbus_msghc));
	if (sc->vmbus_xc == NULL) {
		ret = ENXIO;
		goto cleanup;
	}

	/*
	 * Allocate DMA stuffs.
	 */
	ret = vmbus_dma_alloc(sc);
	if (ret != 0)
		goto cleanup;

	/*
	 * Setup interrupt.
	 */
	ret = vmbus_intr_setup(sc);
	if (ret != 0)
		goto cleanup;

	/*
	 * Setup SynIC.
	 */
	vmbus_xcall(vmbus_synic_setup, sc);
	sc->vmbus_flags |= VMBUS_FLAG_SYNIC;

	/*
	 * Initialize vmbus, e.g. connect to Hypervisor.
	 */
	ret = vmbus_init(sc);
	if (ret != 0)
		goto cleanup;

	if (sc->vmbus_version == VMBUS_VERSION_WS2008 ||
	    sc->vmbus_version == VMBUS_VERSION_WIN7)
		sc->vmbus_event_proc = vmbus_event_proc_compat;
	else
		sc->vmbus_event_proc = vmbus_event_proc;

	if (ret != 0)
		goto cleanup;

	sc->vmbus_flags |= VMBUS_FLAG_ATTACHED;
	return (DDI_SUCCESS);

cleanup:
	vmbus_scan_teardown(sc);
	vmbus_intr_teardown(sc);
	vmbus_dma_free(sc);
	if (sc->vmbus_xc != NULL) {
		vmbus_xact_ctx_destroy(sc->vmbus_xc);
		sc->vmbus_xc = NULL;
	}
	kmem_free(sc->vmbus_chmap,
	    sizeof (struct vmbus_channel *) * VMBUS_CHAN_MAX);
	mutex_destroy(&sc->vmbus_prichan_lock);
	mutex_destroy(&sc->vmbus_chan_lock);

	return (DDI_FAILURE);
}

/* ARGSUSED */
static void
vmbus_event_proc_dummy(struct vmbus_softc *sc, int cpu)
{
}

static int
vmbus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Make sure the platform module provides psm_get_ipivect
	 * or we'll fail in vmbus_intr_setup
	 */
	if (psm_get_ipivect == NULL) {
		dev_err(dip, CE_WARN, "psm_get_ipivect == NULL");
		return (DDI_FAILURE);
	}

	mutex_enter(&vmbus_lock);
	int instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(vmbus_state, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "ddi_soft_state_zalloc failed");
		mutex_exit(&vmbus_lock);
		return (DDI_FAILURE);
	}
	vmbus_sc = ddi_get_soft_state(vmbus_state, instance);
	vmbus_sc->vmbus_dev = dip;
	vmbus_sc->vmbus_idtvec = -1;

	/*
	 * Event processing logic will be configured:
	 * - After the vmbus protocol version negotiation.
	 * - Before we request channel offers.
	 */
	vmbus_sc->vmbus_event_proc = vmbus_event_proc_dummy;

	int ret = vmbus_doattach(vmbus_sc);
	if (vmbus_sc->vmbus_flags & VMBUS_FLAG_ATTACHED) {
		(void) ddi_hold_driver(ddi_name_to_major("hyperv"));
	}

	ddi_report_dev(dip);
	mutex_exit(&vmbus_lock);

	ret = vmbus_scan(vmbus_sc);

	return (ret);
}

static int
vmbus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct vmbus_softc *sc = NULL;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&vmbus_lock);
	int instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(vmbus_state, instance);
	if (sc == NULL) {
		mutex_exit(&vmbus_lock);
		return (DDI_FAILURE);
	}

	vmbus_chan_destroy_all(sc);

	vmbus_scan_teardown(sc);

	vmbus_disconnect(sc);

	if (sc->vmbus_flags & VMBUS_FLAG_SYNIC) {
		sc->vmbus_flags &= ~VMBUS_FLAG_SYNIC;
		vmbus_xcall(vmbus_synic_teardown, NULL);
	}

	vmbus_intr_teardown(sc);
	vmbus_dma_free(sc);

	if (sc->vmbus_xc != NULL) {
		vmbus_xact_ctx_destroy(sc->vmbus_xc);
		sc->vmbus_xc = NULL;
	}

	list_destroy(&sc->vmbus_chans);
	list_destroy(&sc->vmbus_prichans);

	kmem_free(sc->vmbus_chmap,
	    sizeof (struct vmbus_channel *) * VMBUS_CHAN_MAX);
	mutex_destroy(&sc->vmbus_prichan_lock);
	mutex_destroy(&sc->vmbus_chan_lock);

	if (sc->vmbus_flags & VMBUS_FLAG_ATTACHED) {
		(void) ddi_rele_driver(ddi_name_to_major("hyperv"));
		sc->vmbus_flags &= ~VMBUS_FLAG_ATTACHED;
	}
	ddi_soft_state_free(vmbus_state, instance);
	mutex_exit(&vmbus_lock);
	return (DDI_SUCCESS);
}

static int
vmbus_sysinit(void)
{
	if ((get_hwenv() & HW_MICROSOFT) == 0)
		return (-1);

	int error = ddi_soft_state_init(&vmbus_state,
	    sizeof (struct vmbus_softc), 0);
	if (error != 0)
		return (error);

	return (0);
}

static void
vmbus_xcall(vmbus_xcall_func_t func, void *arg)
{
	cpuset_t set;
	CPUSET_ALL(set);
	uint32_t spl = ddi_enter_critical();
	xc_sync((xc_arg_t)arg, (uintptr_t)NULL, (uintptr_t)NULL,
	    CPUSET2BV(set), (xc_func_t)(uintptr_t)func);
	ddi_exit_critical(spl);
}

static int
vmbus_initchild(dev_info_t *child)
{
	const struct vmbus_channel *chan = vmbus_get_channel(child);
	char addr[80];

	ASSERT3P(chan, !=, NULL);
	ASSERT3P(chan->ch_dev, ==, child);

	char classid[HYPERV_GUID_STRLEN] = { 0 };
	(void) hyperv_guid2str(&chan->ch_guid_type, classid, sizeof (classid));
	if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
	    VMBUS_CLASSID, classid) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_WARN, "Unable to set \"%s(%s)\" "
		    "property", VMBUS_CLASSID, classid);
		return (DDI_FAILURE);
	}

	char deviceid[HYPERV_GUID_STRLEN] = { 0 };
	(void) hyperv_guid2str(&chan->ch_guid_inst, deviceid,
	    sizeof (deviceid));
	if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
	    VMBUS_DEVICEID, deviceid) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_WARN, "Unable to set \"%s(%s)\" "
		    "property", VMBUS_DEVICEID, deviceid);
		return (DDI_FAILURE);
	}

	if (ddi_prop_update_string(DDI_DEV_T_NONE, child,
	    VMBUS_STATE, VMBUS_STATE_ONLINE) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_WARN, "Unable to set "
		    "\"%s(%s)\" property", VMBUS_STATE,
		    VMBUS_STATE_ONLINE);
		return (DDI_FAILURE);
	}

	VMBUS_DEBUG(vmbus_get_softc(), "?%s: child dip 0x%p (%s: %s)\n",
	    __func__, child, classid, deviceid);

	(void) snprintf(addr, sizeof (addr), "%s", deviceid);
	ddi_set_name_addr(child, addr);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
vmbus_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?%s@%s, %s%d\n", ddi_node_name(rdip),
		    ddi_get_name_addr(rdip), ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (vmbus_initchild(arg));

	case DDI_CTLOPS_UNINITCHILD:
		ddi_set_name_addr((dev_info_t *)arg, NULL);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		return (DDI_FAILURE);

	case DDI_CTLOPS_POWER:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	/* NOTREACHED */

}

static struct cb_ops vmbus_cb_ops = {
	nulldev,	/* open */
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	nodev,		/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* chpoll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* stream */
	D_NEW | D_MP,	/* flag */
	CB_REV,		/* rev */
	nodev,		/* aread */
	nodev		/* awrite */
};

static struct bus_ops vmbus_bus_ops = {
	BUSO_REV,
	i_ddi_bus_map,
	NULL,   /* NO OP */
	NULL,   /* NO OP */
	NULL,   /* NO OP */
	i_ddi_map_fault,
	NULL,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	vmbus_ctlops,
	ddi_bus_prop_op,
	NULL,		/* (*bus_get_eventcookie)();	*/
	NULL,		/* (*bus_add_eventcall)();	*/
	NULL,		/* (*bus_remove_eventcall)();	*/
	NULL,		/* (*bus_post_event)();		*/
	NULL,		/* (*bus_intr_ctl)();		*/
	vmbus_config,	/* (*bus_config)();		*/
	vmbus_unconfig,	/* (*bus_unconfig)();		*/
	NULL,		/* (*bus_fm_init)();		*/
	NULL,		/* (*bus_fm_fini)();		*/
	NULL,		/* (*bus_fm_access_enter)();    */
	NULL,		/* (*bus_fm_access_fini)();	*/
	NULL,		/* (*bus_power)();		*/
	i_ddi_intr_ops,	/* (*bus_intr_op)();		*/
};

static struct dev_ops vmbus_ops = {
	DEVO_REV,	/* version */
	0,		/* refcnt */
	NULL,		/* info */
	nulldev,	/* identify */
	nulldev,	/* probe */
	vmbus_attach,	/* attach */
	vmbus_detach,	/* detach */
	nodev,		/* reset */
	&vmbus_cb_ops,	/* driver operations */
	&vmbus_bus_ops,	/* no bus operations */
	NULL,		/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv vmbus_modldrv = {
	&mod_driverops,
	"Hyper-V VMBus driver",
	&vmbus_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&vmbus_modldrv,
	NULL
};

int
_init(void)
{
	mutex_init(&vmbus_lock, NULL, MUTEX_DEFAULT, NULL);

	if (vmbus_sysinit() != 0)
		return (ENOTSUP);

	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int error = mod_remove(&modlinkage);
	if (error == 0) {
		ddi_soft_state_fini(vmbus_state);
		mutex_destroy(&vmbus_lock);
	}
	return (error);
}
