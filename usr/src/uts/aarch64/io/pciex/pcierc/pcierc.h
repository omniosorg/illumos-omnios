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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _PCIERC_H
#define	_PCIERC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/pci_cfgacc.h>

extern int	pcierc_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
    off_t, off_t, caddr_t *);
extern int	pcierc_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
    void *, void *);
extern int	pcierc_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
    ddi_intr_handle_impl_t *, void *);
extern int	pcierc_fm_init(dev_info_t *, dev_info_t *, int,
    ddi_iblock_cookie_t *);
extern int	pcierc_bus_get_eventcookie(dev_info_t *, dev_info_t *, char *,
    ddi_eventcookie_t *);
extern int	pcierc_bus_add_eventcall(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void (*)(dev_info_t *,
	ddi_eventcookie_t, void *, void *),
    void *, ddi_callback_id_t *);
extern int	pcierc_bus_remove_eventcall(dev_info_t *, ddi_callback_id_t);
extern int	pcierc_bus_post_event(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void *);

extern int	pcierc_fm_callback(dev_info_t *, ddi_fm_error_t *,
    const void *);

extern int	pcierc_open(dev_t *, int, int, cred_t *);
extern int	pcierc_close(dev_t, int, int, cred_t *);
extern int	pcierc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

extern int	pcierc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
extern int	pcierc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
extern int	pcierc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
extern int	pcierc_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *, dev_info_t **);

#ifdef __cplusplus
}
#endif

#endif /* _PCIERC_H */
