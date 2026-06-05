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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * Kstat support for aarch64 PCI interrupts.
 *
 * Creates per-interrupt "pci_intrs" kstats consumed by intrd(8) for
 * interrupt load balancing.  Each kstat instance reports the device
 * name, interrupt type, target CPU, priority, cumulative service
 * time, interrupt number (ino), and device/bus paths.
 *
 * The target CPU is obtained by walking the DDI interrupt tree via
 * GETTARGET.  This is more expensive than the x86 PSM direct-read
 * path but preserves the clean DDI abstraction; caching may be
 * added if this proves to be a bottleneck.
 */

#include <sys/conf.h>
#include <sys/mach_intr.h>
#include <sys/clock.h>
#include <sys/ddi_intr_impl.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

typedef struct pci_kstat_private {
	ddi_intr_handle_impl_t	*hdlp;
	dev_info_t		*nexus_dip;
} pci_kstat_private_t;

static struct {
	kstat_named_t ihks_name;
	kstat_named_t ihks_type;
	kstat_named_t ihks_cpu;
	kstat_named_t ihks_pil;
	kstat_named_t ihks_time;
	kstat_named_t ihks_ino;
	kstat_named_t ihks_cookie;
	kstat_named_t ihks_devpath;
	kstat_named_t ihks_buspath;
} pci_ks_template = {
	{ "name",	KSTAT_DATA_CHAR },
	{ "type",	KSTAT_DATA_CHAR },
	{ "cpu",	KSTAT_DATA_UINT64 },
	{ "pil",	KSTAT_DATA_UINT64 },
	{ "time",	KSTAT_DATA_UINT64 },
	{ "ino",	KSTAT_DATA_UINT64 },
	{ "cookie",	KSTAT_DATA_UINT64 },
	{ "devpath",	KSTAT_DATA_STRING },
	{ "buspath",	KSTAT_DATA_STRING },
};

static char ih_devpath[MAXPATHLEN];
static char ih_buspath[MAXPATHLEN];
static uint32_t pci_ks_inst;
static kmutex_t pci_ks_template_lock;

static int
pci_ih_ks_update(kstat_t *ksp, int rw __unused)
{
	pci_kstat_private_t *private_data =
	    (pci_kstat_private_t *)ksp->ks_private;
	dev_info_t *nexus_dip = private_data->nexus_dip;
	ddi_intr_handle_impl_t *ih_p = private_data->hdlp;
	dev_info_t *dip = ih_p->ih_dip;
	const size_t maxlen = sizeof (pci_ks_template.ihks_name.value.c);
	processorid_t cpu_id = 0;

	(void) snprintf(pci_ks_template.ihks_name.value.c, maxlen, "%s%d",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	(void) ddi_pathname(dip, ih_devpath);
	(void) ddi_pathname(nexus_dip, ih_buspath);
	kstat_named_setstr(&pci_ks_template.ihks_devpath, ih_devpath);
	kstat_named_setstr(&pci_ks_template.ihks_buspath, ih_buspath);

	/*
	 * Only populate live fields when the interrupt is enabled.
	 * ADDISR fires before ENABLE, so there is a window where the
	 * kstat exists but the interrupt is not yet active.
	 */
	if (ih_p->ih_state != DDI_IHDL_STATE_ENABLE) {
		(void) strcpy(pci_ks_template.ihks_type.value.c, "disabled");
		pci_ks_template.ihks_pil.value.ui64 = 0;
		pci_ks_template.ihks_time.value.ui64 = 0;
		pci_ks_template.ihks_cookie.value.ui64 = 0;
		pci_ks_template.ihks_cpu.value.ui64 = 0;
		pci_ks_template.ihks_ino.value.ui64 = 0;
		return (0);
	}

	/*
	 * Interrupt type.
	 */
	switch (ih_p->ih_type) {
	case DDI_INTR_TYPE_MSI:
		(void) strcpy(pci_ks_template.ihks_type.value.c, "msi");
		break;
	case DDI_INTR_TYPE_MSIX:
		(void) strcpy(pci_ks_template.ihks_type.value.c, "msix");
		break;
	default:
		(void) strcpy(pci_ks_template.ihks_type.value.c, "fixed");
		break;
	}

	/*
	 * Priority and cumulative interrupt service time.
	 */
	pci_ks_template.ihks_pil.value.ui64 = ih_p->ih_pri;
	pci_ks_template.ihks_time.value.ui64 =
	    ((ihdl_plat_t *)ih_p->ih_private)->ip_ticks;
	scalehrtime((hrtime_t *)&pci_ks_template.ihks_time.value.ui64);

	/*
	 * Interrupt number and cookie: both ih_vector (the GIC INTID).
	 */
	pci_ks_template.ihks_ino.value.ui64 = ih_p->ih_vector;
	pci_ks_template.ihks_cookie.value.ui64 = ih_p->ih_vector;

	/*
	 * Target CPU: walk the DDI interrupt tree via GETTARGET.
	 * This is more expensive than x86's direct PSM register read,
	 * but keeps the DDI abstraction clean.
	 */
	if (get_intr_affinity(
	    (ddi_intr_handle_t)ih_p, &cpu_id) == DDI_SUCCESS) {
		pci_ks_template.ihks_cpu.value.ui64 = cpu_id;
	} else {
		pci_ks_template.ihks_cpu.value.ui64 = 0;
	}

	return (0);
}


void
pci_kstat_create(kstat_t **kspp, dev_info_t *nexus_dip,
    ddi_intr_handle_impl_t *hdlp)
{
	pci_kstat_private_t *private_data;

	*kspp = kstat_create("pci_intrs", atomic_inc_32_nv(&pci_ks_inst),
	    _MODULE_NAME, "interrupts", KSTAT_TYPE_NAMED,
	    sizeof (pci_ks_template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (*kspp != NULL) {
		private_data =
		    kmem_zalloc(sizeof (pci_kstat_private_t), KM_SLEEP);
		private_data->hdlp = hdlp;
		private_data->nexus_dip = nexus_dip;

		(*kspp)->ks_private = private_data;
		(*kspp)->ks_data_size += MAXPATHLEN * 2;
		(*kspp)->ks_lock = &pci_ks_template_lock;
		(*kspp)->ks_data = &pci_ks_template;
		(*kspp)->ks_update = pci_ih_ks_update;
		kstat_install(*kspp);
	}
}


/*
 * This function is invoked in two ways:
 * 1. From the REMISR introp when an interrupt handler is being removed.
 * 2. Potentially from a taskq if user-bound interrupt kstat removal is
 *    added in the future (matching the x86 pattern).
 */
void
pci_kstat_delete(kstat_t *ksp)
{
	pci_kstat_private_t *kstat_private;
	ddi_intr_handle_impl_t *hdlp;

	if (ksp != NULL) {
		kstat_private = ksp->ks_private;
		hdlp = kstat_private->hdlp;
		((ihdl_plat_t *)hdlp->ih_private)->ip_ksp = NULL;

		/*
		 * Delete the kstat before freeing the private data, to
		 * prevent an update callback from running after private
		 * is freed.
		 */
		kstat_delete(ksp);

		kmem_free(kstat_private, sizeof (pci_kstat_private_t));
	}
}
