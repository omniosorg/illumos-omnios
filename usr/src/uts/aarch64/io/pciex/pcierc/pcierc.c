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

/*
 *	pcierc -- PCIE root complex support module
 *
 *	pcierc serves to support the drivers for PCIe Root Complexes
 *
 *	This was derived from the i86 npe(4D). For more information about
 *	hotplug, see the big theory statement at uts/common/os/ddi_hp_impl.c.
 *
 *	The following comment comes from the original npe(4D) too.
 *
 *	NDI EVENT HANDLING SUPPORT
 *
 *	pcierc supports NDI event handling. The only available event is surprise
 *	removal of a device. Child drivers can register surprise removal event
 *	callbacks by requesting an event cookie using ddi_get_eventcookie for
 *	the DDI_DEVI_REMOVE_EVENT and add their callback using
 *	ddi_add_event_handler. For an example, see the nvme driver in
 *	uts/common/io/nvme/nvme.c.
 *
 *	The NDI events in pcierc are retrieved using NDI_EVENT_NOPASS, which
 *	prevent them from being propagated up the tree once they reach the
 *	pcierc's bus_get_eventcookie operations. This is important because
 *	pcierc maintains the state of PCIe devices and their receptacles, via
 *	the PCIe hotplug controller driver (pciehpc).
 *
 *	Hot removal events are ultimately posted by the PCIe hotplug controller
 *	interrupt handler for hotplug events. Events are posted using the
 *	ndi_post_event interface.
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/pci_impl.h>
#include <sys/pcie_impl.h>
#include <sys/sysmacros.h>
#include <sys/ddi_intr.h>
#include <sys/sunndi.h>
#include <sys/sunddi.h>
#include <sys/ddifm.h>
#include <sys/ndifm.h>
#include <sys/fm/util.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <io/pci/pci_tools_ext.h>
#include <io/pci/pci_common.h>
#include <sys/obpdefs.h>

#include <pcierc.h>

/*
 * Helper Macros
 */
#define	PCIERC_IS_HANDLE_FOR_STDCFG_ACC(hp) \
	((hp) != NULL &&						\
	((ddi_acc_hdl_t *)(hp))->ah_platform_private != NULL &&		\
	(((ddi_acc_impl_t *)((ddi_acc_hdl_t *)(hp))->			\
	ah_platform_private)->						\
	    ahi_acc_attr &(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_CONFIG_SPACE)) \
		== DDI_ACCATTR_CONFIG_SPACE)

/*
 * Disable URs and Received MA for all PCIe devices.  Until x86 SW is changed so
 * that random drivers do not do PIO accesses on devices that it does not own,
 * these error bits must be disabled.  SERR must also be disabled if URs have
 * been masked.
 */
uint32_t	pcierc_aer_uce_mask = PCIE_AER_UCE_UR;
uint32_t	pcierc_aer_ce_mask = 0;
uint32_t	pcierc_aer_suce_mask = PCIE_AER_SUCE_RCVD_MA;

/*
 * Internal routines in support of particular pcierc_ctlops.
 */
static int pcierc_removechild(dev_info_t *child);
static int pcierc_initchild(dev_info_t *child);

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "PCIe Root Complex Framework Module",
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &modlmisc, NULL }
};

/* Save minimal state. */
void *pcierc_statep;

int
_init(void)
{
	int e;

	/*
	 * Initialize per-pci bus soft state pointer.
	 */
	e = ddi_soft_state_init(&pcierc_statep, sizeof (pci_state_t), 1);
	if (e != 0)
		return (e);

	if ((e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&pcierc_statep);

	return (e);
}


int
_fini(void)
{
	int rc;

	rc = mod_remove(&modlinkage);
	if (rc != 0)
		return (rc);

	ddi_soft_state_fini(&pcierc_statep);
	return (rc);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * See big theory statement at the top of this file for more information about
 * surprise removal events.
 */
#define	PCIERC_EVENT_TAG_HOT_REMOVAL	0
static ndi_event_definition_t pcierc_ndi_event_defs[] = {
	{
		.ndi_event_tag = PCIERC_EVENT_TAG_HOT_REMOVAL,
		.ndi_event_name = DDI_DEVI_REMOVE_EVENT,
		.ndi_event_plevel = EPL_KERNEL,
		.ndi_event_attributes = NDI_EVENT_POST_TO_ALL
	}
};

static ndi_event_set_t pcierc_ndi_events = {
	.ndi_events_version = NDI_EVENTS_REV1,
	.ndi_n_events = ARRAY_SIZE(pcierc_ndi_event_defs),
	.ndi_event_defs = pcierc_ndi_event_defs,
};

/*
 * Update the ranges in the DDI PPD with the information only we have -- the
 * bustype information that must be decoded from a pci-binding 3-word address.
 *
 * Unfortunately, this means we know things about the "parent-private" data we
 * should not.  But otherwise the parent knows things that we should not.
 *
 * We have to do this or `i_ddi_apply_range()` will refuse to map between
 * address spaces, which is critical to supporting "I/O space" access on
 * aarch64.
 *
 * XXXARM: This sucks
 */
static int
pcierc_update_ppd_ranges(dev_info_t *dip)
{
	pci_ranges_t *ranges;
	uint_t rangesln;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_RANGES, (int **)&ranges, &rangesln) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	for (int i = 0; i < i_ddi_pd_getnrng(dip); i++) {
		switch (ranges[i].child_high & PCI_REG_ADDR_M) {
		case PCI_ADDR_IO:
			i_ddi_pd_getrng(dip, i)->rng_cbustype = 1;
			break;
		case PCI_ADDR_CONFIG:	/* fallthrough */
		case PCI_ADDR_MEM32:	/* fallthrough */
		case PCI_ADDR_MEM64:
			i_ddi_pd_getrng(dip, i)->rng_cbustype = 0;
			break;
		default:
			dev_err(dip, CE_PANIC, "unhandled bus type 0x%x",
			    ranges[i].child_high & PCI_REG_ADDR_M);
		}
	}

	ddi_prop_free(ranges);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
pcierc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(devi);
	pci_state_t	*pcip = NULL;
	int		ret;

	pcie_rc_init_bus(devi);

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	}

	/*
	 * Update the parent-private range data
	 * XXXARM: This sucks, see the implementation for a description of why.
	 */
	pcierc_update_ppd_ranges(devi);

	if (ddi_soft_state_zalloc(pcierc_statep, instance) == DDI_SUCCESS)
		pcip = ddi_get_soft_state(pcierc_statep, instance);

	if (pcip == NULL)
		return (DDI_FAILURE);

	pcip->pci_dip = devi;
	pcip->pci_soft_state = PCI_SOFT_STATE_CLOSED;

	if (pcie_init(devi, NULL) != DDI_SUCCESS)
		goto fail1;

	ret = ndi_event_alloc_hdl(pcip->pci_dip, NULL, &pcip->pci_ndi_event_hdl,
	    NDI_SLEEP);
	if (ret == NDI_SUCCESS) {
		ret = ndi_event_bind_set(pcip->pci_ndi_event_hdl,
		    &pcierc_ndi_events, NDI_SLEEP);
		if (ret != NDI_SUCCESS) {
			dev_err(pcip->pci_dip, CE_WARN, "failed to bind "
			    "NDI event set (error=%d)", ret);
			goto fail1;
		}
	} else {
		dev_err(pcip->pci_dip, CE_WARN, "failed to allocate "
		    "event handle (error=%d)", ret);
		goto fail1;
	}

	/* Second arg: initialize for pci_express root nexus */
	if (pcitool_init(devi, B_TRUE) != DDI_SUCCESS)
		goto fail2;

	pcip->pci_fmcap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;
	ddi_fm_init(devi, &pcip->pci_fmcap, &pcip->pci_fm_ibc);

	if (pcip->pci_fmcap & DDI_FM_ERRCB_CAPABLE) {
		ddi_fm_handler_register(devi, pcierc_fm_callback, NULL);
	}

	PCIE_DIP2PFD(devi) = kmem_zalloc(sizeof (pf_data_t), KM_SLEEP);
	pcie_rc_init_pfd(devi, PCIE_DIP2PFD(devi));

	return (DDI_SUCCESS);
fail2:
	(void) pcie_uninit(devi);
fail1:
	pcie_rc_fini_bus(devi);
	ddi_soft_state_free(pcierc_statep, instance);

	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
pcierc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	pci_state_t *pcip;
	int ret;

	pcip = ddi_get_soft_state(pcierc_statep, ddi_get_instance(devi));

	switch (cmd) {
	case DDI_DETACH:

		/*
		 * Clean up event handling first, to ensure there are no
		 * oustanding callbacks registered.
		 */
		ret = ndi_event_unbind_set(pcip->pci_ndi_event_hdl,
		    &pcierc_ndi_events, NDI_SLEEP);
		if (ret == NDI_SUCCESS) {
			/* ndi_event_free_hdl always succeeds. */
			(void) ndi_event_free_hdl(pcip->pci_ndi_event_hdl);
		} else {
			/*
			 * The event set will only fail to unbind if there are
			 * outstanding callbacks registered for it, which
			 * probably means a child driver still has one
			 * registered and thus was not cleaned up properly
			 * before pcierc's detach routine was
			 * called. Consequently, we should fail the detach
			 * here.
			 */
			dev_err(pcip->pci_dip, CE_WARN, "failed to "
			    "unbind NDI event set (error=%d)", ret);
			return (DDI_FAILURE);
		}

		pcie_fab_fini_bus(devi, PCIE_BUS_INITIAL);

		/* Uninitialize pcitool support. */
		pcitool_uninit(devi);

		if (pcie_uninit(devi) != DDI_SUCCESS)
			return (DDI_FAILURE);

		if (pcip->pci_fmcap & DDI_FM_ERRCB_CAPABLE)
			ddi_fm_handler_unregister(devi);

		pcie_rc_fini_pfd(PCIE_DIP2PFD(devi));
		kmem_free(PCIE_DIP2PFD(devi), sizeof (pf_data_t));

		ddi_fm_fini(devi);
		ddi_soft_state_free(pcierc_statep, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*
 * Configure the access handle for standard configuration space
 * access (see pci_fm_acc_setup for code that initializes the
 * access-function pointers).
 */
static int
pcierc_setup_std_pcicfg_acc(dev_info_t *rdip, ddi_map_req_t *mp,
    ddi_acc_hdl_t *hp, off_t offset, off_t len)
{
	int ret;

	if ((ret = pci_fm_acc_setup(hp, offset, len)) ==
	    DDI_SUCCESS) {
		if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(rdip)) &&
		    mp->map_handlep->ah_acc.devacc_attr_access
		    != DDI_DEFAULT_ACC) {
			ndi_fmc_insert(rdip, ACC_HANDLE,
			    (void *)mp->map_handlep, NULL);
		}
	}
	return (ret);
}

int
pcierc_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	int		rnumber;
	int		space;
	ddi_acc_impl_t	*ap;
	ddi_acc_hdl_t	*hp;
	ddi_map_req_t	mr;
	pci_regspec_t	pci_reg;
	pci_regspec_t	*pci_rp;
	struct regspec	reg;
	pci_acc_cfblk_t	*cfp;
	int		retval;
	uint_t		nelem;
	uint64_t	pci_rlength;

	mr = *mp; /* Get private copy of request */
	mp = &mr;

	/*
	 * check for register number
	 */
	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		pci_reg = *(pci_regspec_t *)(mp->map_obj.rp);
		pci_rp = &pci_reg;
		if (pci_common_get_reg_prop(rdip, pci_rp) != DDI_SUCCESS)
			return (DDI_FAILURE);
		break;
	case DDI_MT_RNUMBER:
		rnumber = mp->map_obj.rnumber;
		/*
		 * get ALL "reg" properties for dip, select the one of
		 * of interest. In x86, "assigned-addresses" property
		 * is identical to the "reg" property, so there is no
		 * need to cross check the two to determine the physical
		 * address of the registers.
		 * This routine still performs some validity checks to
		 * make sure that everything is okay.
		 */
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp, &nelem) !=
		    DDI_PROP_SUCCESS)
			return (DDI_FAILURE);

		/*
		 * validate the register number.
		 */
		nelem /= (sizeof (pci_regspec_t) / sizeof (int));
		if (rnumber >= nelem) {
			ddi_prop_free(pci_rp);
			return (DDI_FAILURE);
		}

		/*
		 * copy the required entry.
		 */
		pci_reg = pci_rp[rnumber];

		/*
		 * free the memory allocated by ddi_prop_lookup_int_array
		 */
		ddi_prop_free(pci_rp);

		pci_rp = &pci_reg;
		if (pci_common_get_reg_prop(rdip, pci_rp) != DDI_SUCCESS)
			return (DDI_FAILURE);
		mp->map_type = DDI_MT_REGSPEC;
		break;
	default:
		return (DDI_ME_INVAL);
	}

	space = pci_rp->pci_phys_hi & PCI_REG_ADDR_M;

	/*
	 * check for unmap and unlock of address space
	 */
	if ((mp->map_op == DDI_MO_UNMAP) || (mp->map_op == DDI_MO_UNLOCK)) {
		switch (space) {
		case PCI_ADDR_IO:
			reg.regspec_bustype = 1;
			break;

		case PCI_ADDR_CONFIG:
			/*
			 * If this is an unmap/unlock of a standard config
			 * space mapping (memory-mapped config space mappings
			 * would have the DDI_ACCATTR_CPU_VADDR bit set in the
			 * acc_attr), undo that setup here.
			 */
			if (PCIERC_IS_HANDLE_FOR_STDCFG_ACC(mp->map_handlep)) {

				if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(rdip)) &&
				    mp->map_handlep->ah_acc.devacc_attr_access
				    != DDI_DEFAULT_ACC) {
					ndi_fmc_remove(rdip, ACC_HANDLE,
					    (void *)mp->map_handlep);
				}
				return (DDI_SUCCESS);
			}

			pci_rp->pci_size_hi = 0;
			pci_rp->pci_size_low = PCIE_CONF_HDR_SIZE;

			/* FALLTHROUGH */
		case PCI_ADDR_MEM64:
		case PCI_ADDR_MEM32:
			reg.regspec_bustype = 0;
			break;

		default:
			return (DDI_FAILURE);
		}

		reg.regspec_addr = (uint64_t)pci_rp->pci_phys_mid << 32 |
		    (uint64_t)pci_rp->pci_phys_low;
		reg.regspec_size = (uint64_t)pci_rp->pci_size_hi << 32 |
		    (uint64_t)pci_rp->pci_size_low;

		/*
		 * Adjust offset and length
		 * A non-zero length means override the one in the regspec.
		 */
		if (reg.regspec_addr + offset < MAX(reg.regspec_addr, offset))
			return (DDI_FAILURE);
		reg.regspec_addr += offset;
		if (len != 0)
			reg.regspec_size = len;

		mp->map_obj.rp = (struct regspec *)&reg;
		mp->map_flags |= DDI_MF_EXT_REGSPEC;

		i_ddi_apply_range(dip, rdip, &reg);

		retval = ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp);
		if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(rdip)) &&
		    mp->map_handlep->ah_acc.devacc_attr_access !=
		    DDI_DEFAULT_ACC) {
			ndi_fmc_remove(rdip, ACC_HANDLE,
			    (void *)mp->map_handlep);
		}
		return (retval);

	}

	/* check for user mapping request - not legal for Config */
	if (mp->map_op == DDI_MO_MAP_HANDLE && space == PCI_ADDR_CONFIG) {
		dev_err(dip, CE_NOTE, "Config mapping request from user\n");
		return (DDI_FAILURE);
	}


	/*
	 * Note that pci_fm_acc_setup() is called to serve two purposes
	 * i) enable legacy PCI I/O style config space access
	 * ii) register with FMA
	 */
	if (space == PCI_ADDR_CONFIG) {

		/* Can't map config space without a handle */
		hp = (ddi_acc_hdl_t *)mp->map_handlep;
		if (hp == NULL)
			return (DDI_FAILURE);

		/* record the device address for future reference */
		cfp = (pci_acc_cfblk_t *)hp->ah_bus_private;
		cfp->c_rootdip = dip;
		cfp->c_busnum = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
		cfp->c_devnum = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
		cfp->c_funcnum = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

		*vaddrp = (caddr_t)offset;

		return (pcierc_setup_std_pcicfg_acc(rdip, mp, hp, offset, len));
	}

	/*
	 * range check
	 */
	pci_rlength = (uint64_t)pci_rp->pci_size_low |
	    (uint64_t)pci_rp->pci_size_hi << 32;
	if ((offset >= pci_rlength) || (len > pci_rlength) ||
	    (offset + len > pci_rlength) || (offset + len < MAX(offset, len))) {
		return (DDI_FAILURE);
	}

	/*
	 * convert the pci regsec into the generic regspec used by the
	 * parent root nexus driver.
	 */
	switch (space) {
	case PCI_ADDR_IO:
		reg.regspec_bustype = 1;
		break;
	case PCI_ADDR_CONFIG:
	case PCI_ADDR_MEM64:
	case PCI_ADDR_MEM32:
		reg.regspec_bustype = 0;
		break;
	default:
		return (DDI_FAILURE);
	}

	reg.regspec_addr = (uint64_t)pci_rp->pci_phys_mid << 32 |
	    (uint64_t)pci_rp->pci_phys_low;
	reg.regspec_size = pci_rlength;

	/*
	 * Adjust offset and length
	 * A non-zero length means override the one in the regspec.
	 */
	if (reg.regspec_addr + offset < MAX(reg.regspec_addr, offset))
		return (DDI_FAILURE);
	reg.regspec_addr += offset;
	if (len != 0)
		reg.regspec_size = len;


	mp->map_obj.rp = (struct regspec *)&reg;
	mp->map_flags |= DDI_MF_EXT_REGSPEC;

	i_ddi_apply_range(dip, rdip, &reg);

	retval = ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp);
	if (retval == DDI_SUCCESS) {
		/*
		 * For config space gets force use of cautious access routines.
		 * These will handle default and protected mode accesses too.
		 */
		if (space == PCI_ADDR_CONFIG) {
			ap = (ddi_acc_impl_t *)mp->map_handlep;
			ap->ahi_acc_attr &= ~DDI_ACCATTR_DIRECT;
			ap->ahi_acc_attr |= DDI_ACCATTR_CONFIG_SPACE;
			ap->ahi_get8 = i_ddi_caut_get8;
			ap->ahi_get16 = i_ddi_caut_get16;
			ap->ahi_get32 = i_ddi_caut_get32;
			ap->ahi_get64 = i_ddi_caut_get64;
			ap->ahi_rep_get8 = i_ddi_caut_rep_get8;
			ap->ahi_rep_get16 = i_ddi_caut_rep_get16;
			ap->ahi_rep_get32 = i_ddi_caut_rep_get32;
			ap->ahi_rep_get64 = i_ddi_caut_rep_get64;
		}
		if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(rdip)) &&
		    mp->map_handlep->ah_acc.devacc_attr_access !=
		    DDI_DEFAULT_ACC) {
			ndi_fmc_insert(rdip, ACC_HANDLE,
			    (void *)mp->map_handlep, NULL);
		}
	}
	return (retval);
}



/*ARGSUSED*/
int
pcierc_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	int		totreg;
	uint_t		reglen;
	pci_regspec_t	*drv_regp;
	struct attachspec *asp;
	struct detachspec *dsp;
	pci_state_t	*pci_p = ddi_get_soft_state(pcierc_statep,
	    ddi_get_instance(dip));

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?PCI Express-device: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (pcierc_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (pcierc_removechild((dev_info_t *)arg));

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);

		*(int *)result = 0;
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "reg", (int **)&drv_regp,
		    &reglen) != DDI_PROP_SUCCESS) {
			return (DDI_FAILURE);
		}

		totreg = (reglen * sizeof (int)) / sizeof (pci_regspec_t);
		if (ctlop == DDI_CTLOPS_NREGS)
			*(int *)result = totreg;
		else if (ctlop == DDI_CTLOPS_REGSIZE) {
			uint64_t val;
			int rn;

			rn = *(int *)arg;
			if (rn >= totreg) {
				ddi_prop_free(drv_regp);
				return (DDI_FAILURE);
			}
			val = drv_regp[rn].pci_size_low |
			    (uint64_t)drv_regp[rn].pci_size_hi << 32;
			if (val > OFF_MAX) {
				int ce = CE_NOTE;
#ifdef DEBUG
				ce = CE_WARN;
#endif
				dev_err(rdip, ce, "failed to get register "
				    "size, value larger than OFF_MAX: 0x%"
				    PRIx64 "\n", val);
				return (DDI_FAILURE);
			}
			*(off_t *)result = (off_t)val;
		}
		ddi_prop_free(drv_regp);

		return (DDI_SUCCESS);

	case DDI_CTLOPS_POWER:
	{
		power_req_t	*reqp = (power_req_t *)arg;
		/*
		 * We currently understand reporting of PCI_PM_IDLESPEED
		 * capability. Everything else is passed up.
		 */
		if ((reqp->request_type == PMR_REPORT_PMCAP) &&
		    (reqp->req.report_pmcap_req.cap ==  PCI_PM_IDLESPEED))
			return (DDI_SUCCESS);

		break;
	}

	case DDI_CTLOPS_PEEK:
	case DDI_CTLOPS_POKE:
		return (pci_common_peekpoke(dip, rdip, ctlop, arg, result));

	/* X86 systems support PME wakeup from suspended state */
	case DDI_CTLOPS_ATTACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		asp = (struct attachspec *)arg;
		if ((asp->when == DDI_POST) && (asp->result == DDI_SUCCESS)) {
			pf_init(rdip, (void *)pci_p->pci_fm_ibc, asp->cmd);
			(void) pcie_postattach_child(rdip);
		}

		/* only do this for immediate children */
		if (asp->cmd == DDI_RESUME && asp->when == DDI_PRE &&
		    ddi_get_parent(rdip) == dip)
			if (pci_pre_resume(rdip) != DDI_SUCCESS) {
				/* Not good, better stop now. */
				cmn_err(CE_PANIC,
				    "Couldn't pre-resume device %p",
				    (void *) dip);
				/* NOTREACHED */
			}

		return (DDI_SUCCESS);

	case DDI_CTLOPS_DETACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		dsp = (struct detachspec *)arg;

		if (dsp->when == DDI_PRE)
			pf_fini(rdip, dsp->cmd);

		/* only do this for immediate children */
		if (dsp->cmd == DDI_SUSPEND && dsp->when == DDI_POST &&
		    ddi_get_parent(rdip) == dip)
			if (pci_post_suspend(rdip) != DDI_SUCCESS)
				return (DDI_FAILURE);

		return (DDI_SUCCESS);

	default:
		break;
	}

	return (ddi_ctlops(dip, rdip, ctlop, arg, result));

}


/*
 * pcierc_intr_ops
 */
int
pcierc_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (pci_common_intr_ops(pdip, rdip, intr_op, hdlp, result));
}


/*
 * If the bridge is empty, disable it
 */
static int
pcierc_disable_empty_bridges_workaround(dev_info_t *child)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(child);

	/*
	 * Do not bind drivers to empty bridges.
	 * Fail above, if the bridge is found to be hotplug capable
	 */
	if (ddi_driver_major(child) == ddi_name_to_major("pcieb") &&
	    ddi_get_child(child) == NULL && bus_p->bus_hp_sup_modes ==
	    PCIE_NONE_HP_MODE) {
		return (1);
	}

	return (0);
}

static int
pcierc_initchild(dev_info_t *child)
{
	char		name[80];
	pcie_bus_t	*bus_p;
	uint32_t	regs;

	/*
	 * Do not bind drivers to empty bridges.
	 * Fail above, if the bridge is found to be hotplug capable
	 */
	if (pcierc_disable_empty_bridges_workaround(child) == 1)
		return (DDI_FAILURE);

	if (pci_common_name_child(child, name, sizeof (name)) != DDI_SUCCESS)
		return (DDI_FAILURE);

	ddi_set_name_addr(child, name);

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		extern int pci_allow_pseudo_children;

		ddi_set_parent_data(child, NULL);

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, pci_common_name_child) ==
		    DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			return (DDI_FAILURE);
		}

		/* workaround for DDIVS to run under PCI Express */
		if (pci_allow_pseudo_children) {
			/*
			 * If the "interrupts" property doesn't exist,
			 * this must be the ddivs no-intr case, and it returns
			 * DDI_SUCCESS instead of DDI_FAILURE.
			 */
			if (ddi_prop_get_int(DDI_DEV_T_ANY, child,
			    DDI_PROP_DONTPASS, OBP_INTERRUPTS, -1) == -1)
				return (DDI_SUCCESS);
			/*
			 * Create the ddi_parent_private_data for a pseudo
			 * child.
			 */
			pci_common_set_parent_private_data(child);
			return (DDI_SUCCESS);
		}

		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_get_name(child), ddi_get_name_addr(child),
		    ddi_get_name(child));
		ddi_set_name_addr(child, NULL);
		return (DDI_NOT_WELL_FORMED);
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    OBP_INTERRUPTS, -1) != -1)
		pci_common_set_parent_private_data(child);
	else
		ddi_set_parent_data(child, NULL);

	/* Disable certain errors on PCIe drivers for x86 platforms */
	regs = pcie_get_aer_uce_mask() | pcierc_aer_uce_mask;
	pcie_set_aer_uce_mask(regs);
	regs = pcie_get_aer_ce_mask() | pcierc_aer_ce_mask;
	pcie_set_aer_ce_mask(regs);
	regs = pcie_get_aer_suce_mask() | pcierc_aer_suce_mask;
	pcie_set_aer_suce_mask(regs);

	/*
	 * If URs are disabled, mask SERRs as well, otherwise the system will
	 * still be notified of URs
	 */
	if (pcierc_aer_uce_mask & PCIE_AER_UCE_UR)
		pcie_set_serr_mask(1);

	bus_p = PCIE_DIP2BUS(child);
	if (bus_p != NULL) {
		pcie_init_dom(child);
		(void) pcie_initchild(child);
	}

	return (DDI_SUCCESS);
}


static int
pcierc_removechild(dev_info_t *dip)
{
	pcie_uninitchild(dip);

	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	ddi_remove_minor_node(dip, NULL);

	ddi_prop_remove_all(dip);

	return (DDI_SUCCESS);
}

int
pcierc_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	minor_t		minor = getminor(*devp);
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(minor);
	pci_state_t	*pci_p = ddi_get_soft_state(pcierc_statep, instance);
	int	rv;

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (pci_p == NULL)
		return (ENXIO);

	mutex_enter(&pci_p->pci_mutex);
	switch (PCI_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:
	case PCI_TOOL_INTR_MINOR_NUM:
		break;
	default:
		/* Handle devctl ioctls */
		rv = pcie_open(pci_p->pci_dip, devp, flags, otyp, credp);
		mutex_exit(&pci_p->pci_mutex);
		return (rv);
	}

	/* Handle pcitool ioctls */
	if (flags & FEXCL) {
		if (pci_p->pci_soft_state != PCI_SOFT_STATE_CLOSED) {
			mutex_exit(&pci_p->pci_mutex);
			cmn_err(CE_NOTE, "pcierc_open: busy");
			return (EBUSY);
		}
		pci_p->pci_soft_state = PCI_SOFT_STATE_OPEN_EXCL;
	} else {
		if (pci_p->pci_soft_state == PCI_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&pci_p->pci_mutex);
			cmn_err(CE_NOTE, "pcierc_open: busy");
			return (EBUSY);
		}
		pci_p->pci_soft_state = PCI_SOFT_STATE_OPEN;
	}
	mutex_exit(&pci_p->pci_mutex);

	return (0);
}

int
pcierc_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	minor_t		minor = getminor(dev);
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(minor);
	pci_state_t	*pci_p = ddi_get_soft_state(pcierc_statep, instance);
	int	rv;

	if (pci_p == NULL)
		return (ENXIO);

	mutex_enter(&pci_p->pci_mutex);

	switch (PCI_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:
	case PCI_TOOL_INTR_MINOR_NUM:
		break;
	default:
		/* Handle devctl ioctls */
		rv = pcie_close(pci_p->pci_dip, dev, flags, otyp, credp);
		mutex_exit(&pci_p->pci_mutex);
		return (rv);
	}

	/* Handle pcitool ioctls */
	pci_p->pci_soft_state = PCI_SOFT_STATE_CLOSED;
	mutex_exit(&pci_p->pci_mutex);
	return (0);
}

int
pcierc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	minor_t		minor = getminor(dev);
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(minor);
	pci_state_t	*pci_p = ddi_get_soft_state(pcierc_statep, instance);
	int		ret = ENOTTY;

	if (pci_p == NULL)
		return (ENXIO);

	switch (PCI_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:
	case PCI_TOOL_INTR_MINOR_NUM:
		/* To handle pcitool related ioctls */
		ret =  pci_common_ioctl(pci_p->pci_dip, dev, cmd, arg, mode,
		    credp, rvalp);
		break;
	default:
		/* To handle devctl and hotplug related ioctls */
		ret = pcie_ioctl(pci_p->pci_dip, dev, cmd, arg, mode, credp,
		    rvalp);
		break;
	}

	return (ret);
}

/*ARGSUSED*/
int
pcierc_fm_init(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	pci_state_t  *pcip = ddi_get_soft_state(pcierc_statep,
	    ddi_get_instance(dip));

	ASSERT(ibc != NULL);
	*ibc = pcip->pci_fm_ibc;

	return (pcip->pci_fmcap);
}

int
pcierc_bus_get_eventcookie(dev_info_t *dip, dev_info_t *rdip, char *eventname,
    ddi_eventcookie_t *cookiep)
{
	pci_state_t *pcip = ddi_get_soft_state(pcierc_statep,
	    ddi_get_instance(dip));

	return (ndi_event_retrieve_cookie(pcip->pci_ndi_event_hdl, rdip,
	    eventname, cookiep, NDI_EVENT_NOPASS));
}

int
pcierc_bus_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t cookie, void (*callback)(dev_info_t *dip,
    ddi_eventcookie_t cookie, void *arg, void *bus_impldata),
    void *arg, ddi_callback_id_t *cb_id)
{
	pci_state_t *pcip = ddi_get_soft_state(pcierc_statep,
	    ddi_get_instance(dip));

	return (ndi_event_add_callback(pcip->pci_ndi_event_hdl, rdip, cookie,
	    callback, arg, NDI_SLEEP, cb_id));
}

int
pcierc_bus_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	pci_state_t *pcip = ddi_get_soft_state(pcierc_statep,
	    ddi_get_instance(dip));
	return (ndi_event_remove_callback(pcip->pci_ndi_event_hdl, cb_id));
}

int
pcierc_bus_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t cookie, void *impl_data)
{
	pci_state_t *pcip = ddi_get_soft_state(pcierc_statep,
	    ddi_get_instance(dip));
	return (ndi_event_do_callback(pcip->pci_ndi_event_hdl, rdip, cookie,
	    impl_data));

}

/*ARGSUSED*/
int
pcierc_fm_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *no_used)
{
	/*
	 * On current systems, pcierc's callback does not get called for
	 * failed loads.  If in the future this feature is used, the fault PA
	 * should be logged in the derr->fme_bus_specific field.  The
	 * appropriate PCIe error handling code should be called and needs to
	 * be coordinated with safe access handling.
	 */

	return (DDI_FM_OK);
}

int
pcierc_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **rdip)
{
	int rval = DDI_SUCCESS;
	pci_state_t *pcip = NULL;

	pcip = ddi_get_soft_state(pcierc_statep, ddi_get_instance(pdip));

	ASSERT3P(pcip, !=, NULL);

	ndi_devi_enter(pdip);

	/*
	 * While we enumerate using the old pci_autoconfig derived mechanism
	 * we must only do it the one time, lest we duplicate every device on
	 * the bus.
	 *
	 * We do this even if the initial request is smaller, which is
	 * unfortunate in that it means we take possibly unbounded time to
	 * attach the root disk (or whatever) by enumerating the full bus,
	 * rather than directly onlining the single requested device.
	 *
	 * It is necessary that we respond to BUS_CONFIG_ONE is that is the
	 * path taken when mounting root via ndi_devi_config_one() under
	 * resolve_pathname()
	 *
	 * XXXARM: This would be unnecessary if PCI enumeration could target
	 * specific devices, which would also be good.
	 */
	if (((op == BUS_CONFIG_ALL) || (op == BUS_CONFIG_ONE) ||
	    (op == BUS_CONFIG_DRIVER)) && !pcip->pci_enumerated) {
		pcip->pci_enumerated = B_TRUE;

		extern void pci_enumerate(dev_info_t *);
		pci_enumerate(pdip);

		/*
		 * Now that this RC has been enumerated, we can finish
		 * initializing the fabric
		 */
		pcie_fab_init_bus(pdip, PCIE_BUS_FINAL);
	}

	rval = ndi_busop_bus_config(pdip, flags, op, arg, rdip, 0);

	ndi_devi_exit(pdip);

	return (rval);
}
