/*-
 * Copyright (c) 2017 Microsoft Corp.
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

/* Copyright 2022 Racktop Systems, Inc. */

#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/policy.h>
#include <sys/kbd.h>
#include <sys/kbio.h>
#include <sys/modctl.h>
#include <sys/hyperv.h>
#include <sys/vmbus_xact.h>
#include <sys/vmbus.h>

#include "hv_kbd.h"

int hv_kbd_debug = 0;

#define	HV_KBD_VER_MAJOR	(1)
#define	HV_KBD_VER_MINOR	(0)
#define	HV_KBD_VERSION		(HV_KBD_VER_MINOR | (HV_KBD_VER_MAJOR << 16))

#define	HV_KBD_PROTO_ACCEPTED   (1)

#define	HV_BUFF_SIZE		(4 * PAGE_SIZE)
#define	HV_KBD_RINGBUFF_SEND_SZ	(10 * PAGE_SIZE)
#define	HV_KBD_RINGBUFF_RECV_SZ	(10 * PAGE_SIZE)

enum hv_kbd_msg_type_t {
	HV_KBD_PROTO_REQUEST		= 1,
	HV_KBD_PROTO_RESPONSE		= 2,
	HV_KBD_PROTO_EVENT		= 3,
	HV_KBD_PROTO_LED_INDICATORS	= 4,
};

typedef struct hv_kbd_msg_hdr {
	uint32_t type;
} hv_kbd_msg_hdr_t;

typedef struct hv_kbd_msg {
	hv_kbd_msg_hdr_t	hdr;
	char			data[];
} hv_kbd_msg_t;

typedef struct hv_kbd_proto_req {
	hv_kbd_msg_hdr_t	hdr;
	uint32_t		ver;
} hv_kbd_proto_req_t;

typedef struct hv_kbd_proto_resp {
	hv_kbd_msg_hdr_t	hdr;
	uint32_t		status;
} hv_kbd_proto_resp_t;

typedef struct hv_kbd_keystroke {
	hv_kbd_msg_hdr_t	hdr;
	hv_keystroke_t		ks;
} hv_kbd_keystroke_t;

#define	HV_KBD_PROTO_REQ_SZ	(sizeof (hv_kbd_proto_req_t))
#define	HV_KBD_PROTO_RESP_SZ	(sizeof (hv_kbd_proto_resp_t))

typedef boolean_t (*hv_kbd_attach_fn_t)(hv_kbd_sc_t *);
typedef void (*hv_kbd_cleanup_fn_t)(hv_kbd_sc_t *);

typedef struct hv_kbd_attach_desc {
	hv_kbd_attach_seq_t	hkad_seq;
	const char		*hkad_name;
	hv_kbd_attach_fn_t	hkad_attach;
	hv_kbd_cleanup_fn_t	hkad_cleanup;
} hv_kbd_attach_desc_t;

static void *hv_kbd_ssp;

static void hv_kbd_streams_setled(struct kbtrans_hardware *, int);
static void hv_kbd_polled_setled(struct kbtrans_hardware *, int);
static boolean_t hv_kbd_polled_keycheck(struct kbtrans_hardware *, int *,
    enum keystate *);

static struct kbtrans_callbacks hv_kbd_callbacks = {
	hv_kbd_streams_setled,
	hv_kbd_polled_setled,
	hv_kbd_polled_keycheck,
};

static void
hv_kbd_streams_setled(struct kbtrans_hardware *hw, int led_state)
{
}

static void
hv_kbd_polled_setled(struct kbtrans_hardware *hw, int led_state)
{
}

static boolean_t
hv_kbd_polled_keycheck(struct kbtrans_hardware *hw, kbtrans_key_t *key,
    enum keystate *statep)
{
	/* TODO */
	return (B_FALSE);
}

static int
hv_kbd_polled_getchar(cons_polledio_arg_t arg)
{
	/* TODO */
	return (0);
}

static boolean_t
hv_kbd_polled_ischar(cons_polledio_arg_t arg)
{
	/* TODO */
	return (0);
}

static void
hv_kbd_polled_enter(cons_polledio_arg_t arg)
{
	/* TODO */
}

static void
hv_kbd_polled_exit(cons_polledio_arg_t arg)
{
	/* TODO */
}

static void
hv_kbd_on_response(hv_kbd_sc_t *sc, struct vmbus_chanpkt_hdr *hdr)
{
	struct vmbus_xact_ctx *xact = sc->hk_xact_ctx;

	if (xact == NULL)
		return;

	DEBUG_HVSVC(sc, "!%s: hvkbd is ready\n", __func__);
	vmbus_xact_ctx_wakeup(xact, VMBUS_CHANPKT_CONST_DATA(hdr),
	    VMBUS_CHANPKT_DATALEN(hdr));
}

static void
hv_kbd_on_keypress(hv_kbd_sc_t *sc, const hv_keystroke_t *ks)
{
	/* If the device hasn't been opened, just discard */
	if (sc->hk_wq == NULL)
		return;

	mblk_t *mp = allocb(sizeof (hv_keystroke_t), BPRI_HI);

	if (mp == NULL)
		return;

	bcopy(ks, mp->b_wptr, sizeof (*ks));
	mp->b_wptr += sizeof (*ks);
	if (putq(RD(sc->hk_wq), mp) == 0)
		freemsg(mp);
}

static void
hv_kbd_on_received(hv_kbd_sc_t *sc, struct vmbus_chanpkt_hdr *hdr)
{
	const hv_kbd_msg_t *msg = VMBUS_CHANPKT_CONST_DATA(hdr);
	const hv_kbd_proto_resp_t *resp = (const hv_kbd_proto_resp_t *)msg;
	const hv_kbd_keystroke_t *ksmsg = (const hv_kbd_keystroke_t *)msg;
	uint32_t msg_len = VMBUS_CHANPKT_DATALEN(hdr);
	enum hv_kbd_msg_type_t msg_type;

	if (msg_len <= sizeof (hv_kbd_msg_t)) {
		dev_err(sc->hk_dip, CE_NOTE, "!%s: illegal packet\n", __func__);
		return;
	}

	msg_type = msg->hdr.type;
	switch (msg_type) {
	case HV_KBD_PROTO_RESPONSE:
		hv_kbd_on_response(sc, hdr);
		DEBUG_HVSVC(sc, "!%s: keyboard resp: 0x%x\n", __func__,
		    resp->status);
		break;
	case HV_KBD_PROTO_EVENT:
		if (msg_len < sizeof (hv_kbd_keystroke_t)) {
			dev_err(sc->hk_dip, CE_NOTE,
			    "!%s: illegal keystroke packet\n", __func__);
			return;
		}
		hv_kbd_on_keypress(sc, &ksmsg->ks);
		break;
	default:
		DEBUG_HVSVC(sc, "!%s: unknown msgtype 0x%x\n", __func__,
		    msg_type);
	}
}

static void
hv_kbd_read_channel(struct vmbus_channel *chan, void *ctx)
{
	hv_kbd_sc_t *sc = ctx;
	uint8_t *buf = sc->hk_buf;
	size_t buflen = sc->hk_buflen;
	int ret = 0;

	mutex_enter(&sc->hk_mutex);
	for (;;) {
		struct vmbus_chanpkt_hdr *hdr = (struct vmbus_chanpkt_hdr *)buf;
		int32_t rxlen = buflen;

		ret = vmbus_chan_recv_pkt(chan, hdr, &rxlen);
		if (__predict_false(ret == ENOBUFS)) {
			buflen = sc->hk_buflen * 2;
			while (buflen < rxlen)
				buflen *= 2;
			buf = kmem_zalloc(buflen, KM_SLEEP);
			DEBUG_HVSVC(sc, "!%s: expanded recvbuf %lu -> %lu\n",
			    __func__, sc->hk_buflen, buflen);
			kmem_free(sc->hk_buf, sc->hk_buflen);
			sc->hk_buf = buf;
			sc->hk_buflen = buflen;
			continue;
		} else if (__predict_false(ret == EAGAIN)) {
			/* No more channel packets */
			break;
		}

		switch (hdr->cph_type) {
		case VMBUS_CHANPKT_TYPE_COMP:
		case VMBUS_CHANPKT_TYPE_RXBUF:
			dev_err(sc->hk_dip, CE_NOTE,
			    "!%s: unhandled event: %d\n", __func__,
			    hdr->cph_type);
			break;
		case VMBUS_CHANPKT_TYPE_INBAND:
			hv_kbd_on_received(sc, hdr);
			break;
		default:
			dev_err(sc->hk_dip, CE_NOTE, "!%s: unknown event %d\n",
			    __func__, hdr->cph_type);
			break;
		}
	}
	mutex_exit(&sc->hk_mutex);
}

static int
hv_kbd_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	hv_kbd_sc_t *sc;
	int instance = getminor(*devp);
	int err = 0;

	sc = ddi_get_soft_state(hv_kbd_ssp, instance);

	mutex_enter(&sc->hk_mutex);
	if (q->q_ptr != NULL) {
		mutex_exit(&sc->hk_mutex);
		return (0);
	}

	if (secpolicy_console(credp) != 0) {
		mutex_exit(&sc->hk_mutex);
		return (EPERM);
	}

	sc->hk_ops++;

	q->q_ptr = sc;
	WR(q)->q_ptr = sc;
	if (sc->hk_wq == NULL)
		sc->hk_wq = q;
	mutex_exit(&sc->hk_mutex);

	err = kbtrans_streams_init(q, sflag, (struct kbtrans_hardware *)sc,
	    &hv_kbd_callbacks, &sc->hk_kbtrans,
	    0 /* initial leds */,
	    0 /* initial_led_mask */);
	if (err != 0)
		goto done;

	kbtrans_streams_set_keyboard(sc->hk_kbtrans, KB_PC, &keyindex_hvkbd);

	qprocson(q);
	kbtrans_streams_enable(sc->hk_kbtrans);

done:
	mutex_enter(&sc->hk_mutex);
	VERIFY3U(sc->hk_ops, >, 0);
	if (--sc->hk_ops == 0)
		cv_broadcast(&sc->hk_cv);
	mutex_exit(&sc->hk_mutex);
	return (err);
}

static int
hv_kbd_close(queue_t *q, int flag, cred_t *credp)
{
	hv_kbd_sc_t *sc = q->q_ptr;

	mutex_enter(&sc->hk_mutex);
	sc->hk_ops++;
	mutex_exit(&sc->hk_mutex);

	(void) kbtrans_streams_fini(sc->hk_kbtrans);
	sc->hk_wq = NULL;
	qprocsoff(q);

	mutex_enter(&sc->hk_mutex);
	VERIFY3U(sc->hk_ops, >, 0);
	if (--sc->hk_ops == 0)
		cv_broadcast(&sc->hk_cv);
	mutex_exit(&sc->hk_mutex);

	return (0);
}

static void
hv_kbd_received_ks(hv_kbd_sc_t *sc, const hv_keystroke_t *ks)
{
	enum keystate state;
	int keynum;

	DEBUG_HVSVC(sc, "!%s: keypress info 0x%b scancode: 0x%x\n", __func__,
	    ks->hks_info, INFO_STR, KS_SCANCODE(ks));

	if (!hv_kbd_convert_scan(sc, ks, &keynum, &state)) {
		return;
	}

	kbtrans_streams_key(sc->hk_kbtrans, keynum, state);
}

static int
hv_kbd_rsrv(queue_t *q)
{
	hv_kbd_sc_t *sc = q->q_ptr;
	mblk_t *mp;

	while ((mp = getq(q)) != NULL) {
		if (DB_TYPE(mp) == M_DATA) {
			hv_keystroke_t ks;

			bcopy(mp->b_rptr, &ks, sizeof (ks));
			hv_kbd_received_ks(sc, &ks);
		}
		freemsg(mp);
	}

	return (0);
}

static void
hk_kbd_cmd(hv_kbd_sc_t *sc, int cmd)
{
	switch (cmd) {
	case KBD_CMD_RESET:
	case KBD_CMD_BELL:
	case KBD_CMD_NOBELL:
	case KBD_CMD_CLICK:
	case KBD_CMD_NOCLICK:
		/* These aren't supported, ignore */
		break;
	default:
		dev_err(sc->hk_dip, CE_NOTE, "!%s: unknown 0x%x\n", __func__,
		    cmd);
	}

}

static void
hv_kbd_ioctl(hv_kbd_sc_t *sc, queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	mblk_t *datap;
	int err;
	int tmp;

	switch (iocp->ioc_cmd) {
	case CONSOPENPOLLEDIO:
		DEBUG_HVSVC(sc, "!%s: CONSOPENPOLLEDIO\n", __func__);

		err = miocpullup(mp, sizeof (struct cons_polledio *));
		if (err != 0) {
			miocnak(q, mp, 0, err);
			return;
		}

		*(struct cons_polledio **)mp->b_cont->b_rptr = &sc->hk_polledio;
		DB_TYPE(mp) = M_IOCACK;
		iocp->ioc_error = 0;
		qreply(q, mp);
		return;
	case CONSCLOSEPOLLEDIO:
		DEBUG_HVSVC(sc, "!%s: CONSCLOSEPOLLEDIO\n", __func__);
		miocack(q, mp, 0, 0);
		break;
	case CONSSETABORTENABLE:
		DEBUG_HVSVC(sc, "!%s: CONSSETABORTENABLE\n", __func__);
		if (iocp->ioc_count != TRANSPARENT) {
			miocnak(q, mp, 0, EINVAL);
			return;
		}

		/* TODO */

		miocack(q, mp, 0, 0);
		break;
	case CONSSETKBDTYPE:
		err = miocpullup(mp, sizeof (int));
		if (err != 0) {
			DEBUG_HVSVC(sc,
			    "!%s: CONSSETKBDTYPE (miocpullup failed)\n",
			    __func__);
			miocnak(q, mp, 0, err);
			return;
		}
		bcopy(mp->b_cont->b_rptr, &tmp, sizeof (int));
		if (tmp != KB_PC && tmp != KB_USB) {
			DEBUG_HVSVC(sc, "!%s: CONSSETKBDTYPE %d (invalid)\n",
			    __func__, tmp);
			miocnak(q, mp, 0, EINVAL);
			return;
		}
		DEBUG_HVSVC(sc, "!%s: CONSSETKBDTYPE %d\n", __func__, tmp);
		mutex_enter(&sc->hk_mutex);
		sc->hk_vkbd_type = tmp;
		mutex_exit(&sc->hk_mutex);
		miocack(q, mp, 0, 0);
		break;
	case KIOCLAYOUT:
		if (sc->hk_kblayout == -1) {
			DEBUG_HVSVC(sc, "!%s: KIOCLAYOUT (invalid)\n",
			    __func__);
			miocnak(q, mp, 0, EINVAL);
			return;
		}

		if ((datap = allocb(sizeof (int), 0)) == NULL) {
			DEBUG_HVSVC(sc, "!%s: KIOCLAYOUT (nomem)\n", __func__);
			miocnak(q, mp, 0, ENOMEM);
			return;
		}

		if (sc->hk_vkbd_type == KB_USB) {
			tmp = KBTRANS_USBKB_DEFAULT_LAYOUT;
		} else {
			mutex_enter(&sc->hk_mutex);
			tmp = sc->hk_kblayout;
			mutex_exit(&sc->hk_mutex);
		}

		DEBUG_HVSVC(sc, "!%s: KIOCLAYOUT %d\n", __func__, tmp);

		bcopy(&tmp, datap->b_wptr, sizeof (int));
		datap->b_wptr += sizeof (int);

		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		DB_TYPE(mp) = M_IOCACK;
		iocp->ioc_error = 0;
		qreply(q, mp);
		break;
	case KIOCSLAYOUT:
		if (iocp->ioc_count != TRANSPARENT) {
			DEBUG_HVSVC(sc,
			    "!%s: KIOCSLAYOUT (ioc_count invalid)\n", __func__);
			miocnak(q, mp, 0, EINVAL);
			return;
		}
		DEBUG_HVSVC(sc, "!%s: KIOCSLAYOUT%d\n", __func__,
		    *mp->b_cont->b_rptr);
		mutex_enter(&sc->hk_mutex);
		bcopy(mp->b_cont->b_rptr, &sc->hk_kblayout, sizeof (int));
		mutex_exit(&sc->hk_mutex);
		miocack(q, mp, 0, 0);
		break;
	case KIOCCMD:
		err = miocpullup(mp, sizeof (int));
		if (err != 0) {
			DEBUG_HVSVC(sc, "!%s: KIOCCMD failed\n", __func__);
			miocnak(q, mp, 0, err);
			return;
		}
		bcopy(mp->b_cont->b_rptr, &tmp, sizeof (int));
		DEBUG_HVSVC(sc, "!%s: KIOCCMD = %d\n", __func__, tmp);
		hk_kbd_cmd(sc, tmp);
		miocack(q, mp, 0, 0);
		break;
	case KIOCMKTONE:
		DEBUG_HVSVC(sc, "!%s: KIOCMKTONE\n", __func__);

		if (iocp->ioc_count != TRANSPARENT) {
			miocnak(q, mp, 0, EINVAL);
			return;
		}

		/* Ignore */
		miocack(q, mp, 0, 0);
		break;
	default:
		dev_err(sc->hk_dip, CE_NOTE, "!%s: unknown msg 0x%x\n",
		    __func__, iocp->ioc_cmd);
		miocnak(q, mp, 0, EINVAL);
	}
}

static void
hv_kbd_iocdatamsg(queue_t *q, mblk_t *mp)
{
	struct copyresp *csp = (struct copyresp *)mp->b_rptr;

	if (csp->cp_rval != NULL) {
		freemsg(mp);
		return;
	}

	miocack(q, mp, 0, 0);
}

static int
hv_kbd_wsrv(queue_t *q)
{
	hv_kbd_sc_t *sc = q->q_ptr;
	mblk_t *mp;

	mutex_enter(&sc->hk_mutex);
	sc->hk_ops++;
	mutex_exit(&sc->hk_mutex);

	while ((mp = getq(q)) != NULL) {
		switch (kbtrans_streams_message(sc->hk_kbtrans, mp)) {
		case KBTRANS_MESSAGE_HANDLED:
			continue;
		case KBTRANS_MESSAGE_NOT_HANDLED:
			break;
		}

		switch (DB_TYPE(mp)) {
		case M_IOCTL:
			hv_kbd_ioctl(sc, q, mp);
			continue;
		case M_IOCDATA:
			hv_kbd_iocdatamsg(q, mp);
			continue;
		case M_DELAY:
		case M_STARTI:
		case M_STOPI:
		case M_READ:
			/* ignore, no buffered data */
			freemsg(mp);
			continue;
		case M_FLUSH:
			*mp->b_rptr &= ~FLUSHW;
			if ((*mp->b_rptr & FLUSHR) != 0)
				qreply(q, mp);
			else
				freemsg(mp);
			continue;
		default:
			dev_err(sc->hk_dip, CE_NOTE, "!%s: bad msg 0x%x",
			    __func__, DB_TYPE(mp));
			freemsg(mp);
			continue;
		}
	}

	mutex_enter(&sc->hk_mutex);
	sc->hk_ops--;
	mutex_exit(&sc->hk_mutex);
	return (0);
}

static boolean_t
hv_kbd_polledio_attach(hv_kbd_sc_t *sc)
{
	struct cons_polledio *pio = &sc->hk_polledio;

	pio->cons_polledio_version = CONSPOLLEDIO_V1;
	pio->cons_polledio_argument = (cons_polledio_arg_t)sc;
	pio->cons_polledio_putchar = NULL;
	pio->cons_polledio_getchar = hv_kbd_polled_getchar;
	pio->cons_polledio_ischar = hv_kbd_polled_ischar;
	pio->cons_polledio_enter = hv_kbd_polled_enter;
	pio->cons_polledio_exit = hv_kbd_polled_exit;
	pio->cons_polledio_keycheck = (boolean_t (*)(cons_polledio_arg_t,
	    int *, enum keystate *))hv_kbd_polled_keycheck;
	return (B_TRUE);
}

static void
hv_kbd_polledio_cleanup(hv_kbd_sc_t *sc)
{
	/* Nothing needed */
}

static boolean_t
hv_kbd_mem_attach(hv_kbd_sc_t *sc)
{
	sc->hk_xact_ctx = vmbus_xact_ctx_create(sc->hk_dip,
	    HV_KBD_PROTO_REQ_SZ, HV_KBD_PROTO_RESP_SZ, 0);
	if (sc->hk_xact_ctx == NULL)
		return (B_FALSE);

	sc->hk_buf = kmem_zalloc(HV_BUFF_SIZE, KM_SLEEP);
	sc->hk_buflen = HV_BUFF_SIZE;

	return (B_TRUE);
}

static void
hv_kbd_mem_cleanup(hv_kbd_sc_t *sc)
{
	if (sc->hk_buf != NULL)
		kmem_free(sc->hk_buf, sc->hk_buflen);
	if (sc->hk_xact_ctx != NULL)
		vmbus_xact_ctx_destroy(sc->hk_xact_ctx);

	sc->hk_buf = NULL;
	sc->hk_buflen = 0;
	sc->hk_xact_ctx = NULL;
}

static boolean_t
hv_kbd_sync_attach(hv_kbd_sc_t *sc)
{
	mutex_init(&sc->hk_mutex, NULL, MUTEX_DEFAULT, NULL);
	return (B_TRUE);
}

static void
hv_kbd_sync_cleanup(hv_kbd_sc_t *sc)
{
	mutex_destroy(&sc->hk_mutex);
}

static boolean_t
hv_kbd_chan_attach(hv_kbd_sc_t *sc)
{
	int ret;

	sc->hk_chan = vmbus_get_channel(sc->hk_dip);
	vmbus_chan_set_readbatch(sc->hk_chan, B_FALSE);
	ret = vmbus_chan_open(sc->hk_chan, HV_KBD_RINGBUFF_SEND_SZ,
	    HV_KBD_RINGBUFF_RECV_SZ, NULL, 0, hv_kbd_read_channel, sc);
	if (ret != 0)
		return (B_FALSE);
	return (B_TRUE);
}

static void
hv_kbd_chan_cleanup(hv_kbd_sc_t *sc)
{
	vmbus_chan_close(sc->hk_chan);
	sc->hk_chan = NULL;
}

static boolean_t
hv_kbd_vsp_attach(hv_kbd_sc_t *sc)
{
	struct vmbus_xact		*xact;
	hv_kbd_proto_req_t		*req;
	const hv_kbd_proto_resp_t	*resp;
	size_t				resplen;
	int				rc;
	boolean_t			ret = B_TRUE;

	xact = vmbus_xact_get(sc->hk_xact_ctx, sizeof (*req));
	if (xact == NULL) {
		dev_err(sc->hk_dip, CE_WARN, "%s: no xact for keyboard init\n",
		    __func__);
		return (B_FALSE);
	}

	req = vmbus_xact_req_data(xact);
	req->hdr.type = HV_KBD_PROTO_REQUEST;
	req->ver = HV_KBD_VERSION;

	vmbus_xact_activate(xact);
	rc = vmbus_chan_send(sc->hk_chan, VMBUS_CHANPKT_TYPE_INBAND,
	    VMBUS_CHANPKT_FLAG_RC, req, sizeof (hv_kbd_proto_req_t),
	    (uint64_t)(uintptr_t)xact);
	if (rc != 0) {
		dev_err(sc->hk_dip, CE_WARN, "%s: failed to send request\n",
		    __func__);
		vmbus_xact_deactivate(xact);
		return (B_FALSE);
	}

	resp = vmbus_chan_xact_wait(sc->hk_chan, xact, &resplen, B_TRUE);
	if (resplen < HV_KBD_PROTO_RESP_SZ) {
		dev_err(sc->hk_dip, CE_WARN,
		    "%s: hv_kbd init communicate failed\n", __func__);
		ret = B_FALSE;
		goto done;
	}

	if ((resp->status & HV_KBD_PROTO_ACCEPTED) == 0) {
		dev_err(sc->hk_dip, CE_WARN,
		    "%s: hv_kbd protocol request failed\n", __func__);
		ret = B_FALSE;
	}

done:
	vmbus_xact_put(xact);
	return (ret);
}

static void
hv_kbd_vsp_cleanup(hv_kbd_sc_t *sc)
{
	/* Nothing needed */
}

static boolean_t
hv_kbd_node_attach(hv_kbd_sc_t *sc)
{
	if (ddi_create_minor_node(sc->hk_dip, "hv_kbd", S_IFCHR, 0,
	    DDI_NT_KEYBOARD, 0) != DDI_SUCCESS) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

static void
hv_kbd_node_cleanup(hv_kbd_sc_t *sc)
{
	ddi_remove_minor_node(sc->hk_dip, "hv_kbd");
}

static hv_kbd_attach_desc_t hv_kbd_attach_tbl[] = {
	{
		.hkad_seq = HKA_POLLEDIO,
		.hkad_name = "polled io",
		.hkad_attach = hv_kbd_polledio_attach,
		.hkad_cleanup = hv_kbd_polledio_cleanup,
	},
	{
		.hkad_seq = HKA_MEM,
		.hkad_name = "memory",
		.hkad_attach = hv_kbd_mem_attach,
		.hkad_cleanup = hv_kbd_mem_cleanup,
	},
	{
		.hkad_seq = HKA_SYNC,
		.hkad_name = "sync",
		.hkad_attach = hv_kbd_sync_attach,
		.hkad_cleanup = hv_kbd_sync_cleanup,
	},
	{
		.hkad_seq = HKA_CHAN,
		.hkad_name = "vmbus channel",
		.hkad_attach = hv_kbd_chan_attach,
		.hkad_cleanup = hv_kbd_chan_cleanup,
	},
	{
		.hkad_seq = HKA_VSP,
		.hkad_name = "vsp",
		.hkad_attach = hv_kbd_vsp_attach,
		.hkad_cleanup = hv_kbd_vsp_cleanup,
	},
	{
		.hkad_seq = HKA_NODE,
		.hkad_name = "dev node",
		.hkad_attach = hv_kbd_node_attach,
		.hkad_cleanup = hv_kbd_node_cleanup,
	}
};

static void
hv_kbd_cleanup(hv_kbd_sc_t *sc)
{
	if (sc == NULL || sc->hk_attach_seq == 0)
		return;

	while (sc->hk_attach_seq > 0) {
		hv_kbd_attach_seq_t seq = --sc->hk_attach_seq;
		hv_kbd_attach_desc_t *desc = &hv_kbd_attach_tbl[seq];

		DEBUG_HVSVC(sc, "running cleanup sequence %s (%d)\n",
		    desc->hkad_name, seq);

		desc->hkad_cleanup(sc);
	}

	ASSERT3U(sc->hk_attach_seq, ==, 0);
}

static int
hv_kbd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	hv_kbd_sc_t *sc;
	int instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_FAILURE);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(hv_kbd_ssp, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	sc = ddi_get_soft_state(hv_kbd_ssp, instance);
	sc->hk_dip = dip;
	sc->hk_vkbd_type = KB_PC;
	sc->hk_kblayout = 0;

	for (uint_t i = 0; i < ARRAY_SIZE(hv_kbd_attach_tbl); i++) {
		hv_kbd_attach_desc_t *desc = &hv_kbd_attach_tbl[i];

		DEBUG_HVSVC(sc, "running attach sequence %s (%d)\n",
		    desc->hkad_name, desc->hkad_seq);

		if (!desc->hkad_attach(sc)) {
			dev_err(dip, CE_WARN, "attach sequence %s (%d) failed",
			    desc->hkad_name, desc->hkad_seq);
			hv_kbd_cleanup(sc);
			ddi_soft_state_free(hv_kbd_ssp, instance);
			return (DDI_FAILURE);
		}

		sc->hk_attach_seq = desc->hkad_seq;
	}

	return (DDI_SUCCESS);
}

static int
hv_kbd_detach(dev_info_t *dp, ddi_detach_cmd_t cmd)
{
	hv_kbd_sc_t *sc;
	int instance = ddi_get_instance(dp);

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_FAILURE);
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(hv_kbd_ssp, instance);
	hv_kbd_cleanup(sc);
	ddi_soft_state_free(hv_kbd_ssp, instance);
	return (DDI_SUCCESS);
}

static int
hv_kbd_getinfo(dev_info_t *dp, ddi_info_cmd_t cmd, void *arg, void **res)
{
	hv_kbd_sc_t *sc;
	int instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		sc = ddi_get_soft_state(hv_kbd_ssp, instance);
		*res = sc->hk_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*res = (void *)(uintptr_t)instance;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static struct module_info hv_kbd_sinfo = {
	.mi_idnum = 0,		/* Module ID */
	.mi_idname = "hv_kbd",	/* Module name */
	.mi_minpsz = 0,		/* Minimum packet size */
	.mi_maxpsz = 32,	/* Maximum packet size */
	.mi_hiwat = 256,	/* High water mark */
	.mi_lowat = 128,	/* Low water mark */
};

static struct qinit hv_kbd_rinit = {
	.qi_putp = NULL,
	.qi_srvp = hv_kbd_rsrv,
	.qi_qopen = hv_kbd_open,
	.qi_qclose = hv_kbd_close,
	.qi_qadmin = NULL,
	.qi_minfo = &hv_kbd_sinfo,
	.qi_mstat = NULL,
	.qi_rwp = NULL,
	.qi_infop = NULL,
	.qi_struiot = 0,
};

static struct qinit hv_kbd_winit = {
	.qi_putp = putq,
	.qi_srvp = hv_kbd_wsrv,
	.qi_qopen = hv_kbd_open,
	.qi_qclose = hv_kbd_close,
	.qi_qadmin = NULL,
	.qi_minfo = &hv_kbd_sinfo,
	.qi_mstat = NULL,
	.qi_rwp = NULL,
	.qi_infop = NULL,
	.qi_struiot = 0,
};

struct streamtab hv_kbd_str_info = {
	.st_rdinit = &hv_kbd_rinit,
	.st_wrinit = &hv_kbd_winit,
	.st_muxrinit = NULL,
	.st_muxwinit = NULL,
};

static struct cb_ops hv_kbd_cb_ops = {
	.cb_open = nulldev,
	.cb_close = nulldev,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = nodev,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_str = &hv_kbd_str_info,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev,
};

struct dev_ops hv_kbd_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = hv_kbd_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = hv_kbd_attach,
	.devo_detach = hv_kbd_detach,
	.devo_reset = nodev,
	.devo_cb_ops = &hv_kbd_cb_ops,
	.devo_bus_ops = NULL,
	.devo_power = NULL,
	.devo_quiesce = ddi_quiesce_not_needed,
};

static struct modldrv modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Hyper-V keyboard driver",
	.drv_dev_ops = &hv_kbd_ops,
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &modldrv, NULL }
};

int
_init(void)
{
	int rv;

	rv = ddi_soft_state_init(&hv_kbd_ssp, sizeof (hv_kbd_sc_t), 1);
	if (rv != 0)
		return (rv);

	rv = mod_install(&modlinkage);
	if (rv != 0)
		ddi_soft_state_fini(hv_kbd_ssp);

	return (rv);
}

int
_fini(void)
{
	int rv;

	rv = mod_remove(&modlinkage);
	if (rv != 0)
		return (rv);

	ddi_soft_state_fini(hv_kbd_ssp);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
