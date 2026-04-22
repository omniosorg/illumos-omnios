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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DDI_SUBRDEFS_H
#define	_SYS_DDI_SUBRDEFS_H

#include <sys/dditypes.h>
#include <sys/ddidmareq.h>

/*
 * Sun DDI platform implementation subroutines definitions
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

extern void impl_bus_add_probe(void (*)(int));
extern void impl_bus_delete_probe(void (*)(int));
extern int i_ddi_convert_dma_attr(ddi_dma_attr_t *, dev_info_t *,
    const ddi_dma_attr_t *, int64_t *);
extern int i_ddi_update_dma_attr(dev_info_t *, ddi_dma_attr_t *);
extern uint32_t i_ddi_get_intr_pri(dev_info_t *dip, uint_t inumber);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_SUBRDEFS_H */
