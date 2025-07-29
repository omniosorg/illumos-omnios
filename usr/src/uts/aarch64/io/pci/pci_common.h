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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	_PCI_PCI_COMMON_H
#define	_PCI_PCI_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Common header file with definitions shared between
 *	pci(4D) and pcierc(4D)
 */

/* State structure. */
typedef struct pci_state {
	dev_info_t *pci_dip;
	int pci_fmcap;
	uint_t pci_soft_state;
	ddi_iblock_cookie_t pci_fm_ibc;
	kmutex_t pci_mutex;
	kmutex_t pci_peek_poke_mutex;
	kmutex_t pci_err_mutex;

	/*
	 * The following members are only used by pcierc(4D).
	 * See uts/armv8/io/pciex/pcierc/pcierc.c for more information.
	 */
	ndi_event_hdl_t pci_ndi_event_hdl;
	boolean_t pci_enumerated;
} pci_state_t;

/*
 * PCI tool related declarations
 */
int	pci_common_ioctl(dev_info_t *dip, dev_t dev, int cmd,
	    intptr_t arg, int mode, cred_t *credp, int *rvalp);

/*
 * Interrupt related declaration
 */
int	pci_common_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
	    ddi_intr_handle_impl_t *, void *);
void	pci_common_set_parent_private_data(dev_info_t *);

/*
 * Miscellaneous library functions
 */
int	pci_common_get_reg_prop(dev_info_t *dip, pci_regspec_t *pci_rp);
int	pci_common_name_child(dev_info_t *child, char *name, int namelen);
int	pci_common_peekpoke(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result);
int	pci_fm_acc_setup(ddi_acc_hdl_t *hp, off_t offset, off_t len);

#ifdef	__cplusplus
}
#endif

#endif	/* _PCI_PCI_COMMON_H */
