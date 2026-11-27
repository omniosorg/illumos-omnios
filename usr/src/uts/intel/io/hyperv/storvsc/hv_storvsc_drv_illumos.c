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
 * Copyright 2022-2026 RackTop Systems Inc.
 */

/*
 * StorVSC driver for Hyper-V.  This driver presents a SCSI HBA interface
 * by plugging into the SCSA transport layer.
 * scsi_pkts are converted into VSCSI protocol messages which are delivered
 * to the parent partition StorVSP driver over the Hyper-V VMBUS.
 */

#include <sys/atomic.h>
#include <sys/ksynch.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/scsi/scsi.h>
#include <sys/cpuvar.h>

#include <sys/hyperv.h>
#include <sys/vmbus.h>
#include <sys/dditypes.h>
#include <sys/ddidmareq.h>
#include "hv_vstorage.h"

/*
 * These values are defined by Microsoft and should not be changed unless
 * the FreeBSD drivers, which this code is derived from, have also changed them.
 */
#define	STORVSC_MAX_LUNS_PER_TARGET	(64)
#define	STORVSC_MAX_IO_REQUESTS		(STORVSC_MAX_LUNS_PER_TARGET * 2)
#define	BLKVSC_MAX_IDE_DISKS_PER_TARGET	(1)
#define	BLKVSC_MAX_IO_REQUESTS		STORVSC_MAX_IO_REQUESTS
#define	STORVSC_MAX_TARGETS		(2)
#define	VSTOR_PKT_SIZE			(sizeof (struct vstor_packet))

#define	MAXCPU				256

#define	STORVSC_IDENT			"Hyper-V SCSI Interface"

#define	STORVSC_STATUS_MASK	(STATUS_MASK | STATUS_TASK_ABORT)

#define	STORVSC_DATA_SEGCNT_MAX		128
#define	STORVSC_DATA_SEGSZ_MAX		4096		/* PAGESIZE */
#define	STORVSC_DATA_SIZE_MAX		\
	(STORVSC_DATA_SEGCNT_MAX * STORVSC_DATA_SEGSZ_MAX)

enum storvsc_request_type {
	WRITE_TYPE,
	READ_TYPE,
	UNKNOWN_TYPE
};

typedef struct storvsc_softc storvsc_softc_t;
typedef struct storvsc_cmd storvsc_cmd_t;
typedef struct storvsc_dev storvsc_dev_t;
typedef struct storvsc_req storvsc_req_t;

extern int do_polled_io;
int hv_storvsc_chan_cnt = 0;
static uint_t hv_storvsc_ringbuffer_size;

#define	STORVSC_MAX_IO						\
    vmbus_chan_prplist_nelem(hv_storvsc_ringbuffer_size,	\
    STORVSC_DATA_SEGCNT_MAX, VSTOR_PKT_SIZE)

/*
 * The following structure has gpa_pages immediately
 * following gpa_range, to allow for the fact that the
 * last element of gpa_range is a 0-length array of pages.
 * The gpa_space member should never be accessed directly.
 */
struct storvsc_gpa_range {
	struct vmbus_gpa_range	gpa_range;
	uint64_t		gpa_space[STORVSC_DATA_SEGCNT_MAX];
} __packed;

struct storvsc_req {
	struct vstor_packet		sr_vp;
	int				sr_target;
	int				sr_lun;
	int				sr_prp_cnt;
	struct storvsc_gpa_range	sr_prp_list;
	uint8_t				sr_cdb[SCSI_CDB_SIZE];
	uint_t				sr_cdblen;
	struct scsi_pkt			*sr_pkt;
	uint32_t			sr_resid;
	int				sr_time;	/* relative seconds */
	hrtime_t			sr_expire;	/* absolute */
	boolean_t			sr_poll;
	boolean_t			sr_mgmt;
	boolean_t			sr_expired;
	uint8_t				sr_done;
};

struct storvsc_dev {
	list_node_t	list;
	int		target;
	int		lun;
};


struct storvsc_softc {
	struct vmbus_channel		*hs_chan;
	kmutex_t			hs_lock;
	kmutex_t			hs_chan_lock;
	struct storvsc_driver_props	*hs_drv_props;
	uint32_t			hs_nchan;
	struct vmbus_channel		*hs_sel_chan[MAXCPU];
	dev_info_t			*hs_dip;
	int				hs_instance;
	scsi_hba_tran_t			*hs_tran;
	struct kmem_cache		*hs_req_cache;
	int				hs_max_luns;
	uint16_t			hs_report_luns[STORVSC_MAX_TARGETS];
	list_t				hs_devnodes;
	kstat_t				*hs_stats;
	scsi_hba_tgtmap_t		*hs_tgtmap;
	ddi_taskq_t			*hs_tq;
};

struct storvsc_driver_props {
	char		*drv_name;
	char		*drv_desc;
	uint8_t		drv_max_luns_per_target;
	uint32_t	drv_max_ios_per_target;		/* Not used */
	uint32_t	drv_ringbuffer_size;
};

typedef enum {
	DRIVER_BLKVSC,
	DRIVER_STORVSC,
	DRIVER_UNKNOWN
} storvsc_type_t;

#define	HS_MAX_ADAPTERS 10

/*
 * Used to check if the host supports mult-channel I/O. The host
 * will set the chan_prop.flag bit to indicate support.
 */
#define	HV_STORAGE_SUPPORTS_MULTI_CHANNEL 0x1

/* {ba6163d9-04a1-4d29-b605-72e2ffb1dc7f} */
static const struct hyperv_guid gStorVscDeviceType = {
	.hv_guid = {0xd9, 0x63, 0x61, 0xba, 0xa1, 0x04, 0x29, 0x4d,
	    0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f}
};

/* {32412632-86cb-44a2-9b5c-50d1417354f5} */
static const struct hyperv_guid gBlkVscDeviceType = {
	.hv_guid = {0x32, 0x26, 0x41, 0x32, 0xcb, 0x86, 0xa2, 0x44,
	    0x9b, 0x5c, 0x50, 0xd1, 0x41, 0x73, 0x54, 0xf5}
};

static struct storvsc_driver_props g_drv_props_table[] = {
	{"blkvsc", "Hyper-V IDE Storage Interface",
	    BLKVSC_MAX_IDE_DISKS_PER_TARGET, BLKVSC_MAX_IO_REQUESTS, 0},
	{"storvsc", "Hyper-V SCSI Storage Interface",
	    STORVSC_MAX_LUNS_PER_TARGET, STORVSC_MAX_IO_REQUESTS, 0}
};

/*
 * The storage protocol version is determined during the
 * initial exchange with the host.  It will indicate which
 * storage functionality is available in the host.
 */
static int vmstor_proto_version;

static int vmstor_proto_list[] = {
	VMSTOR_PROTOCOL_VERSION_WIN10,
	0, /* must be last */
};

typedef struct storvsc_stats {
	kstat_named_t vscstat_reads;
	kstat_named_t vscstat_writes;
	kstat_named_t vscstat_non_rw;
	kstat_named_t vscstat_pending;
	kstat_named_t vscstat_chansend[MAXCPU];
} storvsc_stats_t;

#define	VSC_INCR_STAT(sc, x)						\
	if ((sc)->hs_stats != NULL) {					\
		storvsc_stats_t *sp;					\
		sp = (storvsc_stats_t *)(sc)->hs_stats->ks_data;	\
		atomic_inc_64(&sp->x.value.ui64);			\
	}

#define	VSC_DECR_STAT(sc, x) \
	if ((sc)->hs_stats != NULL) {					\
		storvsc_stats_t *sp;					\
		sp = (storvsc_stats_t *)(sc)->hs_stats->ks_data;	\
		atomic_dec_64(&sp->x.value.ui64);			\
	}

/* static functions */
static int storvsc_attach(dev_info_t *, ddi_attach_cmd_t);
static int storvsc_detach(dev_info_t *, ddi_detach_cmd_t);
static void storvsc_on_channel_callback(struct vmbus_channel *, void *);
static storvsc_type_t storvsc_get_storage_type(dev_info_t *);
static void storvsc_complete_request(storvsc_softc_t *, storvsc_req_t *);
static void storvsc_set_dma(storvsc_req_t *, uint_t, const ddi_dma_cookie_t *);
static void storvsc_init_kstat(storvsc_softc_t *);
static void storvsc_poll_request(storvsc_softc_t *, storvsc_req_t *);
static int storvsc_mgmt_request(storvsc_softc_t *, storvsc_req_t *);
static void storvsc_discover(void *);

static struct dev_ops storvsc_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = ddi_no_info,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = storvsc_attach,
	.devo_detach = storvsc_detach,
	.devo_reset = nodev,
	.devo_cb_ops = NULL,
	.devo_bus_ops = NULL,
	.devo_power = NULL,
	.devo_quiesce = ddi_quiesce_not_supported
};

static struct modldrv modldrv = {
	&mod_driverops,
	STORVSC_IDENT,
	&storvsc_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static ddi_dma_attr_t storvsc_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0xFFF,
	.dma_attr_align =	0x0000000000001000ull,
	.dma_attr_burstsizes =	0x0000000000000FFFull,
	.dma_attr_minxfer =	0x00000001,
	.dma_attr_maxxfer =	STORVSC_DATA_SIZE_MAX,
	.dma_attr_seg =		STORVSC_DATA_SEGSZ_MAX - 1,
	.dma_attr_sgllen =	STORVSC_DATA_SEGCNT_MAX,
	.dma_attr_granular =	512,
	.dma_attr_flags =	0
};

static ddi_device_acc_attr_t storvsc_acc_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags =	DDI_STRUCTURE_BE_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
	.devacc_attr_access =		DDI_DEFAULT_ACC,
};

static void
storvsc_subchan_attach(storvsc_softc_t *sc,
    struct vmbus_channel *new_channel)
{
	struct vmstor_chan_props props;

	bzero(&props, sizeof (props));

	vmbus_chan_cpu_rr(new_channel);
	VERIFY0(vmbus_chan_open(new_channel,
	    sc->hs_drv_props->drv_ringbuffer_size,
	    sc->hs_drv_props->drv_ringbuffer_size,
	    (void *)&props,
	    sizeof (struct vmstor_chan_props),
	    storvsc_on_channel_callback, sc));
}

/*
 * @brief Send multi-channel creation request to host
 *
 * @param device  a Hyper-V device pointer
 * @param max_chans  the max channels supported by vmbus
 */
static void
storvsc_send_multichannel_request(storvsc_softc_t *sc, int max_subch)
{
	struct vmbus_channel **subchan;
	storvsc_req_t req;
	struct vstor_packet *vp;
	uint16_t request_subch;

	/* get sub-channel count that need to create */
	request_subch = MIN(max_subch, ncpus - 1);

	/* request the host to create multi-channel */
	bzero(&req, sizeof (req));

	vp = &req.sr_vp;

	vp->operation = VSTOR_OPERATION_CREATE_MULTI_CHANNELS;
	vp->u.multi_channels_cnt = request_subch;

	if (((storvsc_mgmt_request(sc, &req)) != DDI_SUCCESS) ||
	    (vp->status != 0)) {
		dev_err(sc->hs_dip, CE_WARN, "create multi-channel failed");
		return;
	}

	/* Update channel count */
	sc->hs_nchan = request_subch + 1;

	/* Wait for sub-channels setup to complete. */
	subchan = vmbus_subchan_get(sc->hs_chan, request_subch);

	/* Attach the sub-channels. */
	for (uint16_t i = 0; i < request_subch; ++i)
		storvsc_subchan_attach(sc, subchan[i]);

	/* Release the sub-channels. */
	vmbus_subchan_rel(subchan, request_subch);
}

/*
 * @brief initialize channel connection to parent partition
 *
 * @param dev  a Hyper-V device pointer
 * @returns  0 on success, non-zero error on failure
 */
static int
storvsc_channel_init(storvsc_softc_t *sc)
{
	storvsc_req_t req;
	struct vstor_packet *vp = &req.sr_vp;
	uint16_t max_subch = 0;
	boolean_t support_multichannel = B_FALSE;

	bzero(&req, sizeof (req));

	vp->operation = VSTOR_OPERATION_BEGININITIALIZATION;

	if ((storvsc_mgmt_request(sc, &req) != DDI_SUCCESS) ||
	    (vp->status != 0)) {
		dev_err(sc->hs_dip, CE_WARN, "failed to begin init");
		return (DDI_FAILURE);
	}

	for (int i = 0; vmstor_proto_list[i] != 0; i++) {
		/* reuse the packet for version range supported */

		bzero(vp, sizeof (*vp));
		vp->operation = VSTOR_OPERATION_QUERYPROTOCOLVERSION;
		vp->u.version.major_minor = vmstor_proto_list[i];
		/* revision is only significant for Windows guests */
		vp->u.version.revision = 0;

		if (storvsc_mgmt_request(sc, &req) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		if (vp->status == 0) {
			vmstor_proto_version = vmstor_proto_list[i];
			break;
		}
	}

	if (vp->status != 0) {
		dev_err(sc->hs_dip, CE_WARN,
		    "failed to negotiate protocol, status %x", vp->status);
		return (DDI_FAILURE);
	}

	/*
	 * Query channel properties
	 */
	bzero(vp, sizeof (*vp));
	vp->operation = VSTOR_OPERATION_QUERYPROPERTIES;

	if ((storvsc_mgmt_request(sc, &req) != DDI_SUCCESS) ||
	    (vp->status != 0)) {
		return (DDI_FAILURE);
	}

	max_subch = vp->u.chan_props.max_channel_cnt;
	if (hv_storvsc_chan_cnt > 0 && hv_storvsc_chan_cnt < (max_subch + 1))
		max_subch = hv_storvsc_chan_cnt - 1;

	if (vp->u.chan_props.flags & HV_STORAGE_SUPPORTS_MULTI_CHANNEL) {
		support_multichannel = B_TRUE;
	}

	bzero(vp, sizeof (*vp));
	vp->operation = VSTOR_OPERATION_ENDINITIALIZATION;

	if (((storvsc_mgmt_request(sc, &req)) != DDI_SUCCESS) ||
	    (vp->status != 0)) {
		dev_err(sc->hs_dip, CE_WARN, "failed to end init");
		return (DDI_FAILURE);
	}

	/*
	 * If multi-channel is supported, send multichannel create
	 * request to host.
	 */
	if (support_multichannel && max_subch > 0)
		storvsc_send_multichannel_request(sc, max_subch);
	return (DDI_SUCCESS);
}

/*
 * @brief Open channel connection to parent partition StorVSP driver
 *
 * Open and initialize channel connection to parent partition StorVSP driver.
 *
 * @param pointer to a Hyper-V device
 * @returns 0 on success, non-zero error on failure
 */
static int
storvsc_connect_vsp(storvsc_softc_t *sc)
{
	int ret = 0;
	struct vmstor_chan_props props;

	bzero(&props, sizeof (struct vmstor_chan_props));

	/*
	 * Open the channel
	 */
	vmbus_chan_cpu_rr(sc->hs_chan);
	ret = vmbus_chan_open(
	    sc->hs_chan,
	    sc->hs_drv_props->drv_ringbuffer_size,
	    sc->hs_drv_props->drv_ringbuffer_size,
	    (void *)&props,
	    sizeof (struct vmstor_chan_props),
	    storvsc_on_channel_callback, sc);

	if (ret != 0)
		return (DDI_FAILURE);

	return (storvsc_channel_init(sc));
}

static int
storvsc_host_reset(storvsc_softc_t *sc, int op)
{
	storvsc_req_t req;
	struct vstor_packet *vp = &req.sr_vp;

	bzero(&req, sizeof (req));
	vp->operation = op;

	return (storvsc_mgmt_request(sc, &req));
}

static int
storvsc_mgmt_request(storvsc_softc_t *sc, storvsc_req_t *req)
{
	struct vstor_packet *vp = &req->sr_vp;
	int ret;

	vp->flags |= REQUEST_COMPLETION_FLAG;

	/* mgmt requests are always polled */
	req->sr_poll = B_TRUE;
	req->sr_mgmt = B_TRUE;
	req->sr_expired = B_FALSE;
	req->sr_done = 0;
	req->sr_time = 10;	/* ten seconds */
	req->sr_expire = gethrtime() + (10 * NANOSEC);

	ret = vmbus_chan_send(sc->hs_chan,
	    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
	    vp, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)req);

	if (ret != 0) {
		dev_err(sc->hs_dip, CE_WARN, "mgmt request %x failed: %x",
		    vp->operation, ret);
		return (DDI_FAILURE);
	}
	storvsc_poll_request(sc, req);
	if ((req->sr_expired) ||
	    (vp->operation != VSTOR_OPERATION_COMPLETEIO)) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * @brief Function to initiate an I/O request
 *
 * @param device Hyper-V device pointer
 * @param request pointer to a request structure
 * @returns 0 on success, non-zero error on failure
 */
static int
storvsc_io_request(storvsc_softc_t *sc, storvsc_req_t *req,
    uint_t num_cookies, const ddi_dma_cookie_t *cookies, uint_t dma_flags)
{
	struct vstor_packet *vp = &req->sr_vp;
	struct vmscsi_req *srb = &vp->u.vm_srb;
	struct vmbus_channel *outgoing_channel = NULL;
	int ret = 0, ch_sel;
	uint8_t op = req->sr_cdb[0];

	bcopy(req->sr_cdb, &srb->u.cdb, req->sr_cdblen);

	srb->port = sc->hs_instance;
	srb->path_id = 0;
	srb->target_id = req->sr_target;
	srb->lun = req->sr_lun;
	srb->time_out_value = req->sr_time;
	srb->srb_flags |= SRB_FLAGS_DISABLE_SYNCH_TRANSFER;
	srb->cdb_len = req->sr_cdblen;
	srb->length = sizeof (struct vmscsi_req);
	srb->sense_info_len = SENSE_LENGTH;

	if ((num_cookies == 0) || (dma_flags == 0)) {
		srb->data_in = UNKNOWN_TYPE;
		srb->srb_flags |= SRB_FLAGS_NO_DATA_TRANSFER;
		storvsc_set_dma(req, 0, NULL);

	} else if ((dma_flags & DDI_DMA_READ) != 0) {
		srb->data_in = READ_TYPE;
		srb->srb_flags |= SRB_FLAGS_DATA_IN;
		storvsc_set_dma(req, num_cookies, cookies);
	} else {
		srb->data_in = WRITE_TYPE;
		srb->srb_flags |= SRB_FLAGS_DATA_OUT;
		storvsc_set_dma(req, num_cookies, cookies);
	}
	srb->transfer_len = req->sr_prp_list.gpa_range.gpa_len;

	vp->flags |= REQUEST_COMPLETION_FLAG;
	vp->operation = VSTOR_OPERATION_EXECUTESRB;
	ch_sel = (vp->u.vm_srb.lun + CPU->cpu_id) % sc->hs_nchan;
	outgoing_channel = sc->hs_sel_chan[ch_sel];

	if (req->sr_prp_list.gpa_range.gpa_len) {
		ret = vmbus_chan_send_prplist(outgoing_channel,
		    &req->sr_prp_list.gpa_range, req->sr_prp_cnt,
		    vp, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)req);
	} else {
		ret = vmbus_chan_send(outgoing_channel,
		    VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
		    vp, VSTOR_PKT_SIZE, (uint64_t)(uintptr_t)req);
	}

	if (ret != 0) {
		dev_err(sc->hs_dip, CE_WARN, "failed sending packet");
	} else {
		VSC_INCR_STAT(sc, vscstat_pending);
		VSC_INCR_STAT(sc, vscstat_chansend[ch_sel]);
		switch (op) {
		case SCMD_READ:
		case SCMD_READ_G1:
			VSC_INCR_STAT(sc, vscstat_reads);
			break;
		case SCMD_WRITE:
		case SCMD_WRITE_G1:
			VSC_INCR_STAT(sc, vscstat_writes);
			break;
		default:
			VSC_INCR_STAT(sc, vscstat_non_rw);
			break;
		}
	}

	return (ret);
}

/*
 * Fix some errors resulting from the fact that the underlying
 * implementation on the host does not handle certain SCSI-3
 * features.
 */
static void
storvsc_fix_errors(storvsc_req_t *req)
{
	struct vmscsi_req *srb = &req->sr_vp.u.vm_srb;

	if (((srb->srb_status & SRB_STATUS_AUTOSENSE_VALID) != 0) &&
	    ((srb->srb_status & STORVSC_STATUS_MASK) == STATUS_CHECK)) {
		/*
		 * we actually have sense data, so turn this into
		 * a success condition.
		 */
		srb->srb_status = SRB_STATUS_SUCCESS |
		    SRB_STATUS_AUTOSENSE_VALID;
		return;
	}

	switch (req->sr_cdb[0]) {
	case SCMD_INQUIRY:
		/* no serial number page ... oops */
		if (((req->sr_cdb[1] & 0x1) == 1) &&
		    (req->sr_cdb[2] == 0x80)) {
			srb->srb_status = SRB_STATUS_SUCCESS |
			    SRB_STATUS_AUTOSENSE_VALID;
			srb->scsi_status = STATUS_CHECK;
			/* fixed sense, INVALID FIELD IN CDB */
			srb->u.sense_data[0] = 0x70;
			srb->u.sense_data[2] = KEY_ILLEGAL_REQUEST;
			srb->u.sense_data[12] = 0x24;
			srb->u.sense_data[13] = 0x00;
		}
		break;
	case SCMD_PERSISTENT_RESERVE_IN:
	case SCMD_PERSISTENT_RESERVE_OUT:
		srb->srb_status = SRB_STATUS_SUCCESS |
		    SRB_STATUS_AUTOSENSE_VALID;
		srb->scsi_status = STATUS_CHECK;
		/* fixed sense, opcode not supported */
		srb->u.sense_data[0] = 0x70;
		srb->u.sense_data[2] = KEY_ILLEGAL_REQUEST;
		srb->u.sense_data[12] = 0x20;
		srb->u.sense_data[13] = 0x00;
		break;
	}
}

static void
storvsc_on_channel_callback(struct vmbus_channel *channel, void *arg)
{
	storvsc_softc_t *sc = arg;
	struct {
		struct vstor_packet	vp;
		uint64_t		pad;
	} buffer;

	for (;;) {
		uint64_t id = 0;
		int ret = 0;
		int count;
		storvsc_req_t *req;

		bzero(&buffer, sizeof (buffer));
		count = roundup(VSTOR_PKT_SIZE, 8);
		mutex_enter(&sc->hs_chan_lock);
		ret = vmbus_chan_recv(channel, &buffer, &count, &id);
		mutex_exit(&sc->hs_chan_lock);
		if ((ret != 0) || (count == 0)) {
			if (ret == ENOBUFS)
				panic("storvsc recvbuf is not large enough");
			return;
		}

		switch (buffer.vp.operation) {
		case VSTOR_OPERATION_COMPLETEIO:
			if (id == 0) {
				panic("zero ID for complete IO");
			}
			req = (storvsc_req_t *)(uintptr_t)id;
			req->sr_vp = buffer.vp;

			if (req->sr_mgmt) {
				atomic_or_8(&req->sr_done, 1);
				continue;
			}
			storvsc_complete_request(sc, req);
			break;
		case VSTOR_OPERATION_REMOVEDEVICE:
		case VSTOR_OPERATION_ENUMERATE_BUS:
			(void) ddi_taskq_dispatch(sc->hs_tq,
			    storvsc_discover, sc, DDI_NOSLEEP);
			break;
		default:
			dev_err(sc->hs_dip, CE_WARN,
			    "operation: %d not yet implemented.",
			    buffer.vp.operation);
			break;
		}
	}
}

static void
storvsc_create_chan_sel(storvsc_softc_t *sc)
{
	struct vmbus_channel **subch;
	int i, nsubch;

	sc->hs_sel_chan[0] = sc->hs_chan;
	nsubch = sc->hs_nchan - 1;
	if (nsubch == 0)
		return;

	subch = vmbus_subchan_get(sc->hs_chan, nsubch);
	for (i = 0; i < nsubch; i++)
		sc->hs_sel_chan[i + 1] = subch[i];
	vmbus_subchan_rel(subch, nsubch);
}

static void
storvsc_set_sense(storvsc_req_t *req)
{
	struct scsi_arq_status *astat = (void*)(req->sr_pkt->pkt_scbp);
	req->sr_pkt->pkt_state |= STATE_ARQ_DONE;
	bcopy(req->sr_vp.u.vm_srb.u.sense_data,
	    &astat->sts_sensedata, SENSE_LENGTH);
	astat->sts_rqpkt_resid = 0;
	astat->sts_rqpkt_statistics = 0;
	astat->sts_rqpkt_reason = CMD_CMPLT;
	(*(uint8_t *)&astat->sts_rqpkt_status) = STATUS_GOOD;
	astat->sts_rqpkt_state  = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
}

static void
storvsc_set_request_status(storvsc_req_t *req)
{
	struct scsi_pkt *pkt = req->sr_pkt;
	struct vmscsi_req *srb = &req->sr_vp.u.vm_srb;
	uint8_t scsi_status = (srb->scsi_status & STORVSC_STATUS_MASK);

	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD);
	switch SRB_STATUS(srb->srb_status) {
	case SRB_STATUS_SUCCESS:
		/* normal hot code path */
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= STATE_GOT_STATUS;
		pkt->pkt_resid = 0;
		*(pkt->pkt_scbp) = srb->scsi_status;
		if ((scsi_status == STATUS_CHECK) &&
		    ((srb->srb_status & SRB_STATUS_AUTOSENSE_VALID) != 0)) {
			storvsc_set_sense(req);
		} else if (srb->transfer_len != 0) {
			pkt->pkt_resid = req->sr_resid  - srb->transfer_len;
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		break;

	case SRB_STATUS_PENDING:
		/* we didn't complete, so it must have timed out */
		pkt->pkt_reason = CMD_TIMEOUT;
		pkt->pkt_statistics |= STAT_TIMEOUT;
		break;

	case SRB_STATUS_INVALID_LUN:
		pkt->pkt_reason = CMD_DEV_GONE;
		break;

	case SRB_STATUS_ERROR:
	case SRB_STATUS_ABORTED:
	case SRB_STATUS_ERROR|SRB_STATUS_ABORTED:
		/*
		 * we might get this with a check condition,
		 * but only trust it if we got sense data
		 */
		if ((scsi_status == STATUS_CHECK) &&
		    ((srb->srb_status & SRB_STATUS_AUTOSENSE_VALID) != 0)) {
			pkt->pkt_reason = CMD_CMPLT;
			pkt->pkt_resid = 0;
			*(pkt->pkt_scbp) = srb->scsi_status;
			pkt->pkt_state |= STATE_GOT_STATUS;
			storvsc_set_sense(req);
		} else if (srb->srb_status == SRB_STATUS_ABORTED) {
			pkt->pkt_reason = CMD_ABORTED;
			pkt->pkt_statistics |= STAT_ABORTED;
		} else {
			pkt->pkt_reason = CMD_TRAN_ERR;
		}
		break;

	default:
		/* unrecognized status */
		pkt->pkt_reason = CMD_TRAN_ERR;
		break;
	}
}

static void
storvsc_complete_request(storvsc_softc_t *sc, storvsc_req_t *req)
{
	struct scsi_pkt *pkt = req->sr_pkt;
	struct vmscsi_req *srb = &req->sr_vp.u.vm_srb;

	VSC_DECR_STAT(sc, vscstat_pending);

	/*
	 * fix up any errors where we don't already have
	 * reasonable check condition data
	 */
	if ((srb->srb_status & SRB_STATUS_ERROR) != 0) {
		storvsc_fix_errors(req);
	}
	if (pkt != NULL) {
		storvsc_set_request_status(req);

		if (req->sr_poll) {
			atomic_or_8(&req->sr_done, 1);
		} else {
			scsi_hba_pkt_comp(pkt);
		}
	} else {
		atomic_or_8(&req->sr_done, 1);
	}

}

static void
storvsc_set_dma(storvsc_req_t *req, uint_t num, const ddi_dma_cookie_t *cookies)
{
	size_t	len = 0;

	/*
	 * First page may be offset from, but subsequent
	 * pages will be aligned.
	 */
	if (num > 0) {
		req->sr_prp_list.gpa_range.gpa_ofs =
		    cookies[0].dmac_laddress & PAGEOFFSET;
	} else {
		req->sr_prp_list.gpa_range.gpa_ofs = 0;
	}
	for (uint_t i = 0; i < num; i++) {
		req->sr_prp_list.gpa_range.gpa_page[i] =
		    btop(cookies[i].dmac_laddress);
		len += cookies[i].dmac_size;
	}
	req->sr_prp_list.gpa_range.gpa_len = (uint32_t)len;
	req->sr_prp_cnt = num;
	req->sr_resid = (uint32_t)len;
}

static int
storvsc_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	storvsc_softc_t		*sc = ap->a_hba_tran->tran_hba_private;
	storvsc_req_t		*req = pkt->pkt_ha_private;
	storvsc_dev_t		*dev;
	struct scsi_device	*sd;
	int			lun;
	int			error;
	boolean_t		poll;

	if (((sd = scsi_address_device(ap)) == NULL) ||
	    ((dev = scsi_device_hba_private_get(sd)) == NULL) ||
	    (pkt->pkt_cdblen > sizeof (req->sr_cdb)))  {
		return (TRAN_BADPKT);
	}

	lun = dev->lun;
	if ((req->sr_cdb[0] == SCMD_REPORT_LUNS) &&
	    (dev->target < STORVSC_MAX_TARGETS)) {
		/* dirty hack to redirect report luns */
		mutex_enter(&sc->hs_lock);
		lun = sc->hs_report_luns[dev->target];
		mutex_exit(&sc->hs_lock);
		if (lun == 0xffff) {
			/* we don't know better, so do what was asked */
			lun = dev->lun;
		}
	}

	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;

	/* Zero status byte */
	*(pkt->pkt_scbp) = 0;

	req->sr_target = dev->target;
	req->sr_lun = dev->lun;
	req->sr_mgmt = B_FALSE;
	req->sr_expired = B_FALSE;
	req->sr_poll = poll = ((pkt->pkt_flags & FLAG_NOINTR) != 0);
	req->sr_done = 0;
	req->sr_time = pkt->pkt_time != 0 ? pkt->pkt_time : 30;
	req->sr_expire = gethrtime() + SEC2NSEC(req->sr_time);
	req->sr_cdblen = pkt->pkt_cdblen;
	bcopy(pkt->pkt_cdbp, req->sr_cdb, pkt->pkt_cdblen);

	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |  STATE_SENT_CMD);

	/*
	 * A full ring is transient, but a revoked channel cannot accept any
	 * more requests.  Do not retry permanent transport loss as congestion.
	 */
	error = storvsc_io_request(sc, req, pkt->pkt_numcookies,
	    pkt->pkt_cookies,
	    pkt->pkt_dma_flags & (DDI_DMA_READ|DDI_DMA_WRITE));
	if (error != 0) {
		pkt->pkt_state &= ~(STATE_GOT_TARGET | STATE_SENT_CMD);
		if (error == ENXIO) {
			pkt->pkt_reason = CMD_DEV_GONE;
			return (TRAN_FATAL_ERROR);
		}
		return (TRAN_BUSY);
	}

	if (poll) {
		storvsc_poll_request(sc, req);
	}

	return (TRAN_ACCEPT);
}

static int
storvsc_reset(struct scsi_address *ap, int level)
{
	storvsc_softc_t *sc = ap->a_hba_tran->tran_hba_private;

	switch (level) {
	case RESET_ALL:
		if (storvsc_host_reset(sc, VSTOR_OPERATION_RESETBUS) ==
		    DDI_SUCCESS) {
			return (1); /* think true */
		}
		return (0);
	case RESET_TARGET:
	case RESET_LUN:
		/* not documented */
		return (0);
	default:
		return (0);
	}
}

/*
 * Hyper-V guarantees that every valid I/O will be returned so
 * there is no need to abort a command.
 */
/* ARGSUSED */
static int
storvsc_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	return (0);
}

/* ARGSUSED */
static int
storvsc_getcap(struct scsi_address *ap, char *cap, int tgtonly)
{
	if (cap == NULL)
		return (-1);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_CDB_LEN:
		return (CDB_GROUP4);
	/* enable tag queuing and disconnected mode */
	case SCSI_CAP_ARQ:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_DISCONNECT:
		return (1);
	case SCSI_CAP_SCSI_VERSION:
		return (SCSI_VERSION_2);
	default:
		return (-1);
	}
}

/* ARGSUSED */
static int
storvsc_setcap(struct scsi_address *ap, char *cap, int value, int tgtonly)
{
	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_TAGGED_QING:
		return (1);
	case SCSI_CAP_ARQ:
	case SCSI_CAP_CDB_LEN:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SCSI_VERSION:
		/* These are not modifiable */
		return (0);
	default:
		return (1);
	}
}

static void
storvsc_pkt_dtor(struct scsi_pkt *pkt __unused, scsi_hba_tran_t *tran __unused)
{
	/* Nothing we need to do. */
}

int
storvsc_pkt_ctor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran,
    int sleep __unused)
{
	storvsc_req_t *req = pkt->pkt_ha_private;
	req->sr_pkt = pkt;
	return (0);
}

/* type to satisfy cstyle which gets confused */
typedef int (*callback_t)(caddr_t);

static int
storvsc_setup_pkt(struct scsi_pkt *pkt,
    callback_t cb __unused, caddr_t arg __unused)
{
	storvsc_req_t *req = pkt->pkt_ha_private;
	req->sr_pkt = pkt; /* should be already set by ctor */
	return (0);
}

static void
storvsc_teardown_pkt(struct scsi_pkt *pkt __unused)
{
	/* Nothing for us to do. */
}

static int
storvsc_parse_ua(const char *ua, int *target, int *lun)
{
	long num;
	char *end;

	if ((ddi_strtol(ua, &end, 16, &num) != 0) ||
	    ((*end != ',') && (*end != 0))) {
		return (DDI_FAILURE);
	}
	*target = (int)num;
	if (*end == 0) {
		*lun = 0;
		return (DDI_SUCCESS);
	}
	end++;
	if ((ddi_strtol(end, &end, 16, &num) != 0) || (*end != 0)) {
		return (DDI_FAILURE);
	}
	*lun = (int)num;
	return (DDI_SUCCESS);
}

static int
storvsc_tgt_init(dev_info_t *hba __unused, dev_info_t *tgt __unused,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	const char *ua;
	storvsc_softc_t *sc;
	storvsc_dev_t *dev;
	int target, lun;

	if ((scsi_hba_iport_unit_address(hba) == NULL) ||
	    ((sc = tran->tran_hba_private) == NULL) ||
	    ((ua = scsi_device_unit_address(sd)) == NULL)||
	    (storvsc_parse_ua(ua, &target, &lun) != DDI_SUCCESS) ||
	    (target >= STORVSC_MAX_TARGETS) ||
	    (lun >= sc->hs_max_luns)) {
		return (DDI_FAILURE);
	}

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->target = target;
	dev->lun = lun;
	list_link_init(&dev->list);

	mutex_enter(&sc->hs_lock);
	list_insert_tail(&sc->hs_devnodes, dev);
	mutex_exit(&sc->hs_lock);

	scsi_device_hba_private_set(sd, dev);

	return (DDI_SUCCESS);
}

static void
storvsc_tgt_free(dev_info_t *hba __unused, dev_info_t *tgt __unused,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	storvsc_softc_t *sc = tran->tran_hba_private;
	storvsc_dev_t *dev = scsi_device_hba_private_get(sd);

	scsi_device_hba_private_set(sd, NULL);

	mutex_enter(&sc->hs_lock);
	list_remove(&sc->hs_devnodes, dev);
	mutex_exit(&sc->hs_lock);

	kmem_free(dev, sizeof (*dev));
}

static int
storvsc_hba_setup(storvsc_softc_t *sc)
{
	scsi_hba_tran_t *tran;
	int		tran_flags;

	tran = sc->hs_tran = scsi_hba_tran_alloc(sc->hs_dip,
	    SCSI_HBA_CANSLEEP);

	tran->tran_hba_private = sc;
	tran->tran_hba_len = sizeof (storvsc_req_t);
	tran->tran_tgt_init = storvsc_tgt_init;
	tran->tran_tgt_free = storvsc_tgt_free;
	tran->tran_tgt_probe = scsi_hba_probe;

	tran->tran_start = storvsc_start;
	tran->tran_reset = storvsc_reset;
	tran->tran_abort = storvsc_abort;
	tran->tran_getcap = storvsc_getcap;
	tran->tran_setcap = storvsc_setcap;
	tran->tran_pkt_constructor = storvsc_pkt_ctor;
	tran->tran_pkt_destructor = storvsc_pkt_dtor;
	tran->tran_setup_pkt = storvsc_setup_pkt;
	tran->tran_teardown_pkt = storvsc_teardown_pkt;

	tran->tran_interconnect_type = INTERCONNECT_SAS;

	tran_flags = (SCSI_HBA_TRAN_SCB | SCSI_HBA_TRAN_CDB |
	    SCSI_HBA_HBA | SCSI_HBA_ADDR_COMPLEX);

	if (scsi_hba_attach_setup(sc->hs_dip, &storvsc_dma_attr,
	    tran, tran_flags) != DDI_SUCCESS) {
		scsi_hba_tran_free(tran);
		sc->hs_tran = NULL;
		return (DDI_FAILURE);
	}
	if (scsi_hba_iport_register(sc->hs_dip, "iport0") != DDI_SUCCESS) {
		(void) scsi_hba_detach(sc->hs_dip);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
storvsc_init_kstat(storvsc_softc_t *sc)
{
	int	ndata;
	storvsc_stats_t *sp = NULL;
	char name[32] = { 0 };

	ndata = (sizeof (storvsc_stats_t) /
	    sizeof (kstat_named_t)) - MAXCPU;
	ndata += sc->hs_nchan;

	mutex_enter(&sc->hs_lock);
	sc->hs_stats = kstat_create("storvsc", ddi_get_instance(sc->hs_dip),
	    "vscstats", "misc", KSTAT_TYPE_NAMED, ndata, 0);

	if (sc->hs_stats == NULL) {
		dev_err(sc->hs_dip, CE_WARN, "Failed to create kstats");
		mutex_exit(&sc->hs_lock);
		return;
	}

	sp = (storvsc_stats_t *)sc->hs_stats->ks_data;
	kstat_named_init(&sp->vscstat_reads, "reads", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->vscstat_writes, "writes", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->vscstat_non_rw, "other", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->vscstat_pending, "pending", KSTAT_DATA_UINT64);
	for (int i = 0; i < sc->hs_nchan; i++) {
		struct vmbus_channel *chanp = sc->hs_sel_chan[i];
		if (chanp != NULL) {
			if (snprintf(name, sizeof (name), "%s.%d", "chan",
			    vmbus_chan_id(chanp)) < sizeof (name)) {
				kstat_named_init(&sp->vscstat_chansend[i],
				    name, KSTAT_DATA_UINT64);
			}
		}
	}
	sc->hs_stats->ks_private = sc;
	sc->hs_stats->ks_update = nulldev;

	kstat_install(sc->hs_stats);
	mutex_exit(&sc->hs_lock);
}

static void
storvsc_discover(void *arg)
{
	storvsc_softc_t *sc = arg;
	dev_info_t *dip = sc->hs_dip;
	scsi_hba_tgtmap_t *tgtmap;
	ddi_dma_handle_t dmah = NULL;
	ddi_acc_handle_t acch = NULL;
	ddi_dma_attr_t attr = storvsc_dma_attr;
	size_t len = sizeof (struct scsi_inquiry);
	char addr[16];
	char *inq;

	attr.dma_attr_sgllen = 1;
	if (ddi_dma_alloc_handle(dip, &attr, DDI_DMA_SLEEP, NULL, &dmah) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to alloc DMA hdl for discovery");
		return;
	}
	if (ddi_dma_mem_alloc(dmah, len, &storvsc_acc_attr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &inq, &len, &acch) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to alloc DMA mem for discovery");
		ddi_dma_free_handle(&dmah);
		return;
	}
	if (ddi_dma_addr_bind_handle(dmah, NULL, inq, len,
	    DDI_DMA_READ, DDI_DMA_SLEEP, NULL, NULL, NULL) != DDI_DMA_MAPPED) {
		dev_err(dip, CE_WARN, "failed to bind DMA for discovery");
		ddi_dma_mem_free(&acch);
		ddi_dma_free_handle(&dmah);
		return;
	}

	mutex_enter(&sc->hs_lock);
	if ((tgtmap = sc->hs_tgtmap) == NULL) {
		goto done;
	}
	if (scsi_hba_tgtmap_set_begin(tgtmap) != DDI_SUCCESS) {
		goto done;
	}
	for (int i = 0; i < STORVSC_MAX_TARGETS; i++) {
		sc->hs_report_luns[i] = 0xffff;

		/*
		 * We scan every possible LUN.  This is necessary
		 * because HyperV doesn't ensure that REPORT LUNS
		 * works for LUN 0, and has no way to address the
		 * well-known REPORT LUNS LUN.  (HyperV is not really
		 * SPC-3 compliant.)
		 */
		for (int l = 0; l < sc->hs_max_luns; l++) {
			storvsc_req_t req;
			struct vmscsi_req *srb = &req.sr_vp.u.vm_srb;
			bzero(&req, sizeof (req));

			/* Issue an inquiry */
			req.sr_target = i;
			req.sr_lun = l;
			req.sr_poll = B_TRUE;
			req.sr_expired = B_FALSE;
			req.sr_done = 0;
			req.sr_time = 5;
			req.sr_expire = gethrtime() + 5 * NANOSEC;
			req.sr_cdblen = 6;
			req.sr_cdb[0] = SCMD_INQUIRY;
			req.sr_cdb[1] = 0;
			req.sr_cdb[2] = 0;
			req.sr_cdb[3] = 0;
			req.sr_cdb[4] = sizeof (struct scsi_inquiry);
			req.sr_cdb[5] = 0;
			if (storvsc_io_request(sc, &req, 1,
			    ddi_dma_cookie_one(dmah), DDI_DMA_READ) != 0) {
				(void) scsi_hba_tgtmap_set_flush(tgtmap);
				goto done;
			}
			storvsc_poll_request(sc, &req);
			if ((srb->srb_status == SRB_STATUS_SUCCESS) &&
			    ((ddi_get8(acch, (uint8_t *)inq) & DTYPE_MASK) !=
			    DTYPE_UNKNOWN)) {
				sc->hs_report_luns[i] = l;
				break;
			}
		}
		if (sc->hs_report_luns[i] == 0xffff) {
			continue; /* no LUNs responded for this target */
		}
		(void) snprintf(addr, sizeof (addr), "%x", i);
		if (scsi_hba_tgtmap_set_add(tgtmap, SCSI_TGT_SCSI_DEVICE,
		    addr, NULL) != DDI_SUCCESS) {
			(void) scsi_hba_tgtmap_set_flush(tgtmap);
			goto done;
		}
	}
	(void) scsi_hba_tgtmap_set_end(tgtmap, 0);

	for (int i = 0; i < STORVSC_MAX_TARGETS; i++) {
		if (sc->hs_report_luns[i] != 0xffff) {
			(void) snprintf(addr, sizeof (addr), "%x", i);
			(void) scsi_hba_tgtmap_scan_luns(tgtmap, addr);
		}
	}
done:
	mutex_exit(&sc->hs_lock);
	(void) ddi_dma_unbind_handle(dmah);
	ddi_dma_mem_free(&acch);
	ddi_dma_free_handle(&dmah);
}

static int
storvsc_detach_iport(dev_info_t *dip)
{
	const char *ua = scsi_hba_iport_unit_address(dip);
	scsi_hba_tran_t *tran;
	scsi_hba_tgtmap_t *tgtmap;
	storvsc_softc_t *sc;

	if ((ua == NULL) || (strcmp(ua, "iport0") != 0)) {
		return (DDI_FAILURE);
	}
	if (((tran = ddi_get_driver_private(dip)) == NULL) ||
	    ((sc = tran->tran_hba_private) == NULL)) {
		return (DDI_FAILURE);
	}
	mutex_enter(&sc->hs_lock);
	if (!list_is_empty(&sc->hs_devnodes)) {
		mutex_exit(&sc->hs_lock);
		return (DDI_FAILURE);
	}
	tgtmap = sc->hs_tgtmap;
	sc->hs_tgtmap = NULL;
	mutex_exit(&sc->hs_lock);

	scsi_hba_tgtmap_destroy(tgtmap);
	return (DDI_SUCCESS);
}

static int
storvsc_attach_iport(dev_info_t *dip)
{
	const char *ua = scsi_hba_iport_unit_address(dip);
	scsi_hba_tran_t *tran;
	scsi_hba_tgtmap_t *tgtmap;
	storvsc_softc_t *sc;

	/* We only support iport0 */
	if ((ua == NULL) || (strcmp(ua, "iport0") != 0)) {
		return (DDI_FAILURE);
	}

	/* Get tran from parent's private data, so we can get sc */
	tran = ddi_get_driver_private(ddi_get_parent(dip));
	if ((tran == NULL) ||
	    ((sc = tran->tran_hba_private) == NULL)) {
		return (DDI_FAILURE);
	}

	/* This resets tran to our copy, which we configure */
	tran = ddi_get_driver_private(dip);
	tran->tran_hba_private = sc;

	if (scsi_hba_tgtmap_create(dip, SCSI_TM_FULLSET, MICROSEC,
	    2 * MICROSEC, sc, NULL, NULL, &tgtmap) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	mutex_enter(&sc->hs_lock);
	sc->hs_tgtmap = tgtmap;
	mutex_exit(&sc->hs_lock);

	(void) ddi_taskq_dispatch(sc->hs_tq, storvsc_discover, sc, DDI_SLEEP);
	return (DDI_SUCCESS);
}

/*
 * @brief StorVSC attach function
 *
 * Function responsible for allocating per-device structures,
 * setting up SCSA interfaces and scanning for available LUNs to
 * be used for SCSI device peripherals.
 *
 * @param a device
 * @returns 0 on success or an error on failure
 */
static int
storvsc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	storvsc_softc_t	*sc;
	storvsc_type_t stor_type;

	/* Invoke iport attach if this is an iport node */
	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (storvsc_attach_iport(dip));
	}

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	/* Allocate softstate information */
	stor_type = storvsc_get_storage_type(dip);
	if (stor_type == DRIVER_UNKNOWN) {
		dev_err(dip, CE_WARN, "stor type %d not expected", stor_type);
		return (DDI_FAILURE);
	}


	sc = kmem_zalloc(sizeof (*sc), KM_SLEEP);

	/* Setup HBA instance */
	sc->hs_instance = ddi_get_instance(dip);
	sc->hs_dip = dip;
	sc->hs_max_luns = STORVSC_MAX_LUNS_PER_TARGET;
	mutex_init(&sc->hs_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->hs_chan_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&sc->hs_devnodes, sizeof (storvsc_dev_t),
	    offsetof(storvsc_dev_t, list));

	sc->hs_nchan = 1;
	sc->hs_chan = vmbus_get_channel(sc->hs_dip);
	ASSERT3P(sc->hs_chan, !=, NULL);

	/* fill in driver specific properties */
	sc->hs_drv_props = &g_drv_props_table[stor_type];
	hv_storvsc_ringbuffer_size = (64 * PAGESIZE);
	sc->hs_drv_props->drv_ringbuffer_size = hv_storvsc_ringbuffer_size;

	if (storvsc_connect_vsp(sc) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "connect_vsp failed");
		goto fail;
	}

	/* Construct cpu to channel mapping */
	storvsc_create_chan_sel(sc);

	if (storvsc_hba_setup(sc) != 0) {
		dev_err(dip, CE_WARN, "hba_setup failed");
		goto fail;
	}

	storvsc_init_kstat(sc);

	sc->hs_tq = ddi_taskq_create(dip, "discover", 1, TASKQ_DEFAULTPRI, 0);
	if (sc->hs_tq == NULL) {
		/* this should never happen */
		panic("taskq create failed");
	}

	ddi_report_dev(sc->hs_dip);
	return (DDI_SUCCESS);

fail:
	mutex_destroy(&sc->hs_lock);
	mutex_destroy(&sc->hs_chan_lock);
	kmem_free(sc, sizeof (*sc));

	return (DDI_FAILURE);
}

/*
 * @brief StorVSC device detach function
 *
 * This function is responsible for safely detaching a
 * StorVSC device.  This includes waiting for inbound responses
 * to complete and freeing associated per-device structures.
 *
 * @param dev a device
 * returns 0 on success
 */
static int
storvsc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	storvsc_softc_t *sc;
	scsi_hba_tran_t *tran;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (storvsc_detach_iport(dip));
	}

	if (((tran = ddi_get_driver_private(dip)) == NULL) ||
	    ((sc = tran->tran_hba_private) == NULL)) {
		return (DDI_FAILURE);
	}
	if (scsi_hba_detach(dip) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	ddi_taskq_suspend(sc->hs_tq);

	mutex_enter(&sc->hs_lock);

	/*
	 * Since we have already drained, we don't need to busy wait.
	 * The call to close the channel will reset the callback
	 * under the protection of the incoming channel lock.
	 */

	vmbus_chan_close(sc->hs_chan);

	ddi_taskq_destroy(sc->hs_tq);
	kstat_delete(sc->hs_stats);
	mutex_exit(&sc->hs_lock);
	mutex_destroy(&sc->hs_lock);
	mutex_destroy(&sc->hs_chan_lock);
	kmem_free(sc, sizeof (*sc));

	return (DDI_SUCCESS);
}

/*
 * @brief StorVSC device poll function
 *
 * This function is responsible for servicing requests when
 * interrupts are disabled (i.e when we are dumping core.)
 */
static void
storvsc_poll_request(storvsc_softc_t *sc, storvsc_req_t *req)
{
	while (gethrtime() < req->sr_expire) {
		storvsc_on_channel_callback(sc->hs_chan, sc);
		if (req->sr_done != 0) {
			return;
		}

		/* busy wait */
		drv_usecwait(10);
	}

	/*
	 * We don't have a documented way to reset the adapter safely.
	 * in fact, the reset commands we have go through this same
	 * submission process.  If we find ourselves here, really
	 * the only option left to us is to panic and hope that whatever
	 * is wrong in the hypervisor clears up.  We've been told that
	 * the hypervisor guarantees to complete commands.
	 */
	panic("request stuck, hypervisor hung?");
}

/*
 * @brief Determine type of storage device from GUID
 *
 * Using the type GUID, determine if this is a StorVSC (paravirtual
 * SCSI or BlkVSC (paravirtual IDE) device.
 *
 * @param dev a device
 * returns an enum
 */
static storvsc_type_t
storvsc_get_storage_type(dev_info_t *dev)
{
	if (vmbus_probe_guid(dev, &gBlkVscDeviceType) == 0)
		return (DRIVER_BLKVSC);
	if (vmbus_probe_guid(dev, &gStorVscDeviceType) == 0)
		return (DRIVER_STORVSC);
	return (DRIVER_UNKNOWN);
}

int
_init(void)
{
	int	rv;

	if ((rv = scsi_hba_init(&modlinkage)) != 0) {
		return (rv);
	}

	if ((rv = mod_install(&modlinkage)) != 0) {
		scsi_hba_fini(&modlinkage);
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		scsi_hba_fini(&modlinkage);
	}

	return (rv);
}
