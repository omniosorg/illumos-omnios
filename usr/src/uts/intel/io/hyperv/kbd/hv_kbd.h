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
 *
 */

/* Copyright 2022 Racktop Systems, Inc. */

#ifndef _HV_KBD_H
#define	_HV_KBD_H

#include <sys/consdev.h>
#include <sys/kbtrans.h>
#include <sys/types.h>

#define	IS_UNICODE	(1 << 0)
#define	IS_BREAK	(1 << 1)
#define	IS_E0		(1 << 2)
#define	IS_E1		(1 << 3)
#define	INFO_STR	"\020\4E1\3E0\2BREAK\1UNICODE"

#define	KS_IS_UNICODE(ks)	(((ks)->hks_info & IS_UNICODE) != 0)
#define	KS_IS_BREAK(ks)		(((ks)->hks_info & IS_BREAK) != 0)
#define	KS_IS_E0(ks)		(((ks)->hks_info & IS_E0) != 0)
#define	KS_IS_E1(ks)		(((ks)->hks_info & IS_E1) != 0)
#define	KS_SCANCODE(ks)		((ks)->hks_makecode)

#define	DEBUG_HVSVC(sc, ...) do {				\
	if (hv_kbd_debug > 0) {					\
		dev_err((sc)->hk_dip, CE_CONT, __VA_ARGS__);	\
	}							\
} while (0)

struct vmbus_channel;
struct vmbus_xact_ctx;

typedef struct hv_keystroke {
	uint16_t	hks_makecode;
	uint16_t	hks_pad;
	uint32_t	hks_info;
} hv_keystroke_t;

typedef enum hv_kbd_attach_seq {
	HKA_POLLEDIO,
	HKA_MEM,
	HKA_SYNC,
	HKA_CHAN,
	HKA_VSP,
	HKA_NODE,
} hv_kbd_attach_seq_t;

typedef struct hv_kbd_sc {
	dev_info_t		*hk_dip;
	struct vmbus_channel	*hk_chan;
	struct vmbus_xact_ctx	*hk_xact_ctx;
	kmutex_t		hk_mutex;
	kcondvar_t		hk_cv;
	uint_t			hk_ops;
	struct kbtrans		*hk_kbtrans;
	struct cons_polledio	hk_polledio;
	int			hk_vkbd_type;
	int			hk_kblayout;
	queue_t			*hk_wq;
	uint8_t			*hk_buf;
	size_t			hk_buflen;
	hv_kbd_attach_seq_t	hk_attach_seq;
} hv_kbd_sc_t;

boolean_t hv_kbd_convert_scan(hv_kbd_sc_t *, const hv_keystroke_t *, int *,
    enum keystate *);

extern struct keyboard keyindex_hvkbd;

#endif /* _HV_KBD_H */
