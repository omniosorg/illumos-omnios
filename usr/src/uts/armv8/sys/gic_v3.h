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
 * Copyright 2026 Michael van der Westhuizen
 */

#ifndef _SYS_GIC_V3_H
#define	_SYS_GIC_V3_H

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi_intr_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GICv3 LPI exports for ITS and MBI drivers.
 *
 * This is a private interface between the GIC and the subordinate ITS driver
 * or embedded MBI driver.
 */

#define	GICV3_ITS_PEND_ALIGN	(64 * 1024)	/* 64KiB alignment */

/* Contiguous memory allocation */
extern int
gicv3_contig_alloc(dev_info_t *dip, size_t size, size_t align,
    caddr_t *vap, uint64_t *pap, ddi_dma_handle_t *dma_hdlp,
    ddi_acc_handle_t *acc_hdlp);
extern void
gicv3_contig_free(ddi_dma_handle_t *dma_hdlp, ddi_acc_handle_t *acc_hdlp);

/* LPI INTID allocation */
extern int	gicv3_alloc_lpi(dev_info_t *, uint32_t *);
extern int	gicv3_alloc_lpi_block(dev_info_t *, uint32_t, uint32_t,
		    uint32_t *);
extern void	gicv3_free_lpi(dev_info_t *, uint32_t);
extern void	gicv3_free_lpi_block(dev_info_t *, uint32_t, uint32_t);
extern size_t	gicv3_lpi_navail(dev_info_t *);

/* LPI IRM pool */
extern ddi_irm_pool_t	*gicv3_get_lpi_irm_pool(dev_info_t *);

/* LPI configuration (PROPBASER table access) */
extern void	gicv3_lpi_set_config(dev_info_t *, uint32_t, uint8_t,
		    boolean_t);
extern uint8_t	gicv3_lpi_get_config(dev_info_t *, uint32_t);
extern boolean_t gicv3_lpi_ispending(dev_info_t *, uint32_t, processorid_t);

/* Redistributor info for ITS MAPC commands */
extern uint64_t	gicv3_redist_pa(dev_info_t *, processorid_t);
extern uint32_t	gicv3_redist_procnum(dev_info_t *, processorid_t);
extern uint32_t	gicv3_num_redists(dev_info_t *);
extern uint32_t	gicv3_lpi_idbits(dev_info_t *);

/* SPI targeting - inner functions for use by child MSI controllers */
extern processorid_t	gicv3_get_target_spi(dev_info_t *, uint32_t);
extern void		gicv3_set_target_spi(dev_info_t *, uint32_t, processorid_t);

/* MSI SPI range registration for child MSI controllers */
extern void	gicv3_register_msi_range(dev_info_t *, uint32_t, uint32_t);
extern void	gicv3_unregister_msi_range(dev_info_t *, uint32_t, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GIC_V3_H */
