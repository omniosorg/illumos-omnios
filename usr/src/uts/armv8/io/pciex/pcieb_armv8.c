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
 *
 * Copyright 2019 Joyent, Inc.
 */

/* armv8 specific code used by the pcieb driver */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <sys/hotplug/hpctrl.h>
#include <io/pciex/pcieb.h>
#include <sys/obpdefs.h>

void
pcieb_peekpoke_cb(dev_info_t *dip, ddi_fm_error_t *derr)
{
	pf_eh_enter(PCIE_DIP2BUS(dip));
	(void) pf_scan_fabric(dip, derr, NULL);
	pf_eh_exit(PCIE_DIP2BUS(dip));
}

void
pcieb_set_prot_scan(dev_info_t *dip, ddi_acc_impl_t *hdlp)
{
	pcieb_devstate_t *pcieb = ddi_get_soft_state(pcieb_state,
	    ddi_get_instance(dip));

	hdlp->ahi_err_mutexp = &pcieb->pcieb_err_mutex;
	hdlp->ahi_peekpoke_mutexp = &pcieb->pcieb_peek_poke_mutex;
	hdlp->ahi_scan_dip = dip;
	hdlp->ahi_scan = pcieb_peekpoke_cb;
}

int
pcieb_plat_peekpoke(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	pcieb_devstate_t *pcieb = ddi_get_soft_state(pcieb_state,
	    ddi_get_instance(dip));

	if (!PCIE_IS_RP(PCIE_DIP2BUS(dip)))
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));

	return (pci_peekpoke_check(dip, rdip, ctlop, arg, result,
	    ddi_ctlops, &pcieb->pcieb_err_mutex,
	    &pcieb->pcieb_peek_poke_mutex,
	    pcieb_peekpoke_cb));
}

void
pcieb_plat_attach_workaround(dev_info_t *dip)
{
}

int
pcieb_plat_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result));
}

/*ARGSUSED*/
boolean_t
pcieb_plat_pwr_disable(dev_info_t *dip)
{
	/* Always disable on armv8 */
	return (B_TRUE);
}

boolean_t
pcieb_plat_msi_supported(dev_info_t *dip)
{
	return (B_FALSE);	/* XXXARM: We don't right now, but need to */
}

void
pcieb_plat_intr_attach(pcieb_devstate_t *pcieb)
{

}

void
pcieb_plat_initchild(dev_info_t *child)
{
	struct ddi_parent_private_data *pdptr;
	if (ddi_prop_exists(DDI_DEV_T_NONE, child, DDI_PROP_DONTPASS,
	    OBP_INTERRUPTS)) {
		pdptr = kmem_zalloc((sizeof (struct ddi_parent_private_data) +
		    sizeof (struct intrspec)), KM_SLEEP);
		pdptr->par_intr = (struct intrspec *)(pdptr + 1);
		pdptr->par_nintr = 1;
		ddi_set_parent_data(child, pdptr);
	} else
		ddi_set_parent_data(child, NULL);
}

void
pcieb_plat_uninitchild(dev_info_t *child)
{
	struct ddi_parent_private_data	*pdptr;

	if ((pdptr = ddi_get_parent_data(child)) != NULL)
		kmem_free(pdptr, (sizeof (*pdptr) + sizeof (struct intrspec)));

	ddi_set_parent_data(child, NULL);
}

int
pcieb_plat_ctlops(dev_info_t *rdip, ddi_ctl_enum_t ctlop, void *arg)
{
	struct detachspec *ds;
	struct attachspec *as;

	switch (ctlop) {
	case DDI_CTLOPS_DETACH:
		ds = (struct detachspec *)arg;
		switch (ds->when) {
		case DDI_POST:
			if (ds->cmd == DDI_SUSPEND) {
				if (pci_post_suspend(rdip) != DDI_SUCCESS)
					return (DDI_FAILURE);
			}
			break;
		default:
			break;
		}
		break;
	case DDI_CTLOPS_ATTACH:
		as = (struct attachspec *)arg;
		switch (as->when) {
		case DDI_PRE:
			if (as->cmd == DDI_RESUME) {
				if (pci_pre_resume(rdip) != DDI_SUCCESS)
					return (DDI_FAILURE);
			}
			break;
		case DDI_POST:
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return (DDI_SUCCESS);
}
