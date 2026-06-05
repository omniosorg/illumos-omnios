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

/*
 * GICv2m MSI Controller Driver
 *
 * GICv2m is a separate MMIO frame alongside the GICv2 distributor that
 * provides MSI/MSI-X support for PCI devices.  A PCI device writes an SPI
 * number to the doorbell register (V2M_MSI_SETSPI_NS), and the GICv2
 * distributor fires that SPI as a normal edge-triggered interrupt.
 *
 * Each v2m frame provides a range of SPIs for MSI use, described by the
 * MSI_TYPER register (overridden by properties for buggy implementations).
 *
 * Multiple v2m frames can exist.
 *
 * Lock ordering
 * =============
 *   v2m_dev_lock (mutex)
 *     Protects the per-device state list (v2m_devs).
 *
 *   v2m_dev_lock --> syspic_intrs_lock --> av_lock
 *   gc_lock is acquired independently via gicv2_configure_irq()
 *   cross-driver call, and is held only for the duration of that
 *   call.  The base GICv2 driver does not call into the v2m driver.
 */

#include <sys/types.h>
#include <sys/stddef.h>
#include <sys/inttypes.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/vmem.h>
#include <sys/list.h>
#include <sys/avintr.h>
#include <sys/syspic.h>
#include <sys/syspic_impl.h>
#include <sys/mach_intr.h>
#include <sys/gic_reg.h>
#include <sys/ddi_intr_impl.h>

/*
 * Device tree properties for SPI base/count override.
 *
 * Some GIC-400 implementations have incorrect MSI_TYPER values.
 * These properties, when present in the DT v2m node, override
 * the hardware register.  See: arm,gic.yaml in devicetree-source.
 */
#define	V2M_PROP_MSI_BASE_SPI	"arm,msi-base-spi"
#define	V2M_PROP_MSI_NUM_SPIS	"arm,msi-num-spis"

/*
 * Per-device MSI state.
 *
 * Tracks the SPI allocation for a single PCI device (rdip).  ALLOC creates
 * one of these and links it onto the v2m instance's device list.  ENABLE
 * looks up the SPI for a given inum.  FREE tears it all down.
 *
 * For MSI: SPIs are contiguous from ds_base_spi.  Vector for inum i is
 *          ds_base_spi + (i - ds_inum_base).
 * For MSI-X: SPIs are individually allocated into ds_spi_array[].
 *            Vector for inum i is ds_spi_array[i - ds_inum_base].
 */
typedef struct gicv2m_dev_state {
	dev_info_t	*ds_rdip;		/* owning PCI device */
	int		ds_type;		/* DDI_INTR_TYPE_MSI[X] */
	uint32_t	ds_inum_base;		/* starting inum */
	uint32_t	ds_count;		/* number allocated */
	uint32_t	ds_base_spi;		/* MSI: contiguous base */
	uint32_t	*ds_spi_array;		/* MSI-X: per-inum SPIs */
	uint32_t	ds_spi_array_sz;	/* MSI-X: kmem_alloc size */
	list_node_t	ds_node;
} gicv2m_dev_state_t;

/*
 * Soft state for each v2m frame instance.
 */
typedef struct gicv2m_state {
	dev_info_t		*v2m_dip;
	dev_info_t		*v2m_gic_dip;		/* parent GICv2 */
	caddr_t			v2m_base;		/* MMIO VA mapping */
	ddi_acc_handle_t	v2m_regh;		/* MMIO access handle */
	uint64_t		v2m_doorbell_pa;	/* PA of SETSPI_NS */
	uint32_t		v2m_spi_base;		/* first SPI (TYPER) */
	uint32_t		v2m_spi_count;		/* SPI count (TYPER) */
	vmem_t			*v2m_spi_arena;		/* SPI allocator */
	ddi_irm_pool_t		*v2m_irm_pool;		/* IRM pool for SPIs */
	list_t			v2m_devs;		/* gicv2m_dev_state_t */
	kmutex_t		v2m_dev_lock;		/* protects v2m_devs */
} gicv2m_state_t;

/*
 * Configure an SPI as edge-triggered or level-sensitive on the GICv2
 * distributor.  Takes the distributor lock internally.
 *
 * gic_dip: dev_info_t of the parent GICv2 instance
 * irq:     SPI INTID (32-1019)
 * is_edge: B_TRUE for edge-triggered, B_FALSE for level-sensitive
 *
 * This is a private interface, implemented by the GICv2 driver.
 */
extern void gicv2_configure_irq(dev_info_t *gic_dip, uint32_t irq,
    boolean_t is_edge);
extern boolean_t gicv2_irq_ispending(dev_info_t *gic_dip, uint32_t irq);
extern processorid_t gicv2_get_target_spi(dev_info_t *gic_dip,
    uint32_t intid);
extern void gicv2_set_target_spi(dev_info_t *gic_dip, uint32_t intid,
    processorid_t cpuid);
extern void gicv2_register_msi_range(dev_info_t *gic_dip, uint32_t base,
    uint32_t count);
extern void gicv2_unregister_msi_range(dev_info_t *gic_dip, uint32_t base,
    uint32_t count);

static void *gicv2m_soft_state;

/*
 * Find the per-device state for a given MSI/MSI-X-consuming device.
 * Caller must hold sc->v2m_dev_lock.
 */
static gicv2m_dev_state_t *
gicv2m_find_dev(gicv2m_state_t *sc, dev_info_t *rdip)
{
	gicv2m_dev_state_t *ds;

	ASSERT(MUTEX_HELD(&sc->v2m_dev_lock));

	for (ds = list_head(&sc->v2m_devs); ds != NULL;
	    ds = list_next(&sc->v2m_devs, ds)) {
		if (ds->ds_rdip == rdip) {
			return (ds);
		}
	}

	return (NULL);
}

/*
 * Allocate MSI/MSI-X vectors from the v2m frame's SPI range.
 *
 * ALLOC is called once per ddi_intr_alloc() with ih_scratch1 = count.
 * We allocate SPIs and record the assignment in a per-device state
 * structure so that ENABLE can later look up the SPI for each inum.
 *
 * For MSI with count > 1, SPIs must be contiguous and naturally aligned
 * (PCI spec requires power-of-2 count).  If the full request can't be
 * satisfied, we try progressively smaller power-of-2 counts.  The DDI
 * framework handles DDI_INTR_ALLOC_STRICT - if the caller requires
 * exactly count and we return fewer, the framework frees what we
 * allocated and returns DDI_EAGAIN.
 *
 * For MSI-X, each vector is independently addressable, so SPIs need
 * not be contiguous.  We allocate count individual SPIs.
 */
static int
gicv2m_alloc(gicv2m_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int count = hdlp->ih_scratch1;
	int actual = 0;
	gicv2m_dev_state_t *ds;

	ds = kmem_zalloc(sizeof (*ds), KM_SLEEP);
	ds->ds_rdip = rdip;
	ds->ds_type = hdlp->ih_type;
	ds->ds_inum_base = hdlp->ih_inum;

	if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
		/*
		 * MSI requires contiguous, naturally aligned vectors.
		 * vmem_xalloc with align=count gives us both properties.
		 * Try progressively smaller power-of-2 counts.
		 */
		void *base = NULL;
		int try = count;

		while (try > 0) {
			base = vmem_xalloc(sc->v2m_spi_arena, try, try,
			    0, 0, NULL, NULL, VM_NOSLEEP);
			if (base != NULL)
				break;
			try >>= 1;
		}

		if (base == NULL) {
			kmem_free(ds, sizeof (*ds));
			return (DDI_INTR_NOTFOUND);
		}

		ds->ds_base_spi = (uint32_t)(uintptr_t)base;
		ds->ds_count = try;
		actual = try;
	} else {
		/*
		 * MSI-X: allocate count individual SPIs.  Each MSI-X
		 * table entry has its own (address, data) pair, so
		 * contiguity is not required.
		 */
		ds->ds_spi_array = kmem_zalloc(
		    count * sizeof (uint32_t), KM_SLEEP);
		ds->ds_spi_array_sz = count * sizeof (uint32_t);

		for (actual = 0; actual < count; actual++) {
			void *id = vmem_alloc(sc->v2m_spi_arena, 1,
			    VM_NOSLEEP);
			if (id == NULL)
				break;
			ds->ds_spi_array[actual] =
			    (uint32_t)(uintptr_t)id;
		}

		if (actual == 0) {
			kmem_free(ds->ds_spi_array, ds->ds_spi_array_sz);
			kmem_free(ds, sizeof (*ds));
			return (DDI_INTR_NOTFOUND);
		}

		ds->ds_count = actual;
	}

	mutex_enter(&sc->v2m_dev_lock);
	list_insert_tail(&sc->v2m_devs, ds);
	mutex_exit(&sc->v2m_dev_lock);

	*(int *)result = actual;
	return (DDI_SUCCESS);
}

/*
 * Free MSI/MSI-X vectors back to the v2m frame's SPI range.
 *
 * FREE is called per-handle with ih_scratch1 = 1.  We track the
 * allocation in the per-device state and free everything when the
 * last vector for a device is freed.
 *
 * In practice, the DDI framework frees all vectors for a device in
 * rapid succession (ddi_intr_free per handle).  The first FREE for
 * a device releases the entire allocation; subsequent FREEs for the
 * same device are no-ops (the dev_state has already been removed).
 */
static int
gicv2m_free(gicv2m_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	gicv2m_dev_state_t *ds;

	mutex_enter(&sc->v2m_dev_lock);
	ds = gicv2m_find_dev(sc, rdip);
	if (ds == NULL) {
		/* Already removed by a prior handle, not an error */
		mutex_exit(&sc->v2m_dev_lock);
		return (DDI_SUCCESS);
	}
	list_remove(&sc->v2m_devs, ds);
	mutex_exit(&sc->v2m_dev_lock);

	if (ds->ds_type == DDI_INTR_TYPE_MSI) {
		vmem_xfree(sc->v2m_spi_arena,
		    (void *)(uintptr_t)ds->ds_base_spi, ds->ds_count);
	} else {
		for (uint32_t i = 0; i < ds->ds_count; i++) {
			vmem_free(sc->v2m_spi_arena,
			    (void *)(uintptr_t)ds->ds_spi_array[i], 1);
		}
		kmem_free(ds->ds_spi_array, ds->ds_spi_array_sz);
	}

	kmem_free(ds, sizeof (*ds));
	return (DDI_SUCCESS);
}

/*
 * Enable a single MSI/MSI-X vector.
 *
 * 1. Look up the SPI for this handle's inum from per-device state.
 * 2. Configure the SPI as edge-triggered on the GICv2 distributor.
 * 3. Create syspic state tracking (for mdb visibility).
 * 4. Register the handler via add_avintr (triggers addspl which programs
 *    priority, target CPU, and enables the SPI on the distributor).
 *
 * The caller is responsible for programming the device's MSI/MSI-X capability
 * registers with the doorbell physical address and SPI number, which are
 * communicated via ddi_intr_handle_impl_t::ih_private::ip_msi_addr (the
 * doorbell physical address) and
 * ddi_intr_handle_impl_t::ih_private::ip_msi_data (the datum to write to the
 * doorbell address, in this case the base SPI for MSI or the SPI itself for
 * MSI-X).
 *
 * Note that for MSI, the PCI cap has a single shared address/data register
 * pair.  This can be repeatedly programmed with the base SPI and total count
 * from the per-device state, regardless of which inum is being enabled.  This
 * operation is idempotent and correct even when called multiple times.
 *
 * Particularly importantly, the device is programmed to produce MSI/MSI-X
 * interrupts only after the GIC is programmed and the handler installed.
 */
static int
gicv2m_enable(gicv2m_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	uint32_t spi;
	uint32_t msi_base_spi = 0;
	uint32_t idx;
	syspic_intr_state_t *state;
	gicv2m_dev_state_t *ds;
	ihdl_plat_t *priv = hdlp->ih_private;

	/*
	 * Look up the SPI and, for MSI, the base SPI and total count
	 * needed for PCI cap programming.  We do this in a single lock
	 * acquisition.
	 */
	mutex_enter(&sc->v2m_dev_lock);
	ds = gicv2m_find_dev(sc, rdip);
	if (ds == NULL) {
		mutex_exit(&sc->v2m_dev_lock);
		dev_err(sc->v2m_dip, CE_WARN,
		    "no MSI state for %s%d",
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);
	}

	idx = hdlp->ih_inum - ds->ds_inum_base;
	if (idx >= ds->ds_count) {
		mutex_exit(&sc->v2m_dev_lock);
		dev_err(sc->v2m_dip, CE_WARN,
		    "inum %d out of range for %s%d",
		    hdlp->ih_inum, ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_FAILURE);
	}

	if (ds->ds_type == DDI_INTR_TYPE_MSI) {
		spi = ds->ds_base_spi + idx;
		msi_base_spi = ds->ds_base_spi;
	} else {
		spi = ds->ds_spi_array[idx];
	}

	mutex_exit(&sc->v2m_dev_lock);

	/*
	 * The device state values extracted above (spi, msi_base_spi,
	 * ds_type) are immutable after ALLOC.  DDI framework serialisation
	 * of per-device interrupt ops (ALLOC/ENABLE/DISABLE/FREE) prevents
	 * any concurrent FREE from invalidating the device state, so there
	 * is no TOCTOU race after releasing v2m_dev_lock.
	 */

	hdlp->ih_vector = spi;

	/* Configure SPI as edge-triggered; MSI is always edge */
	gicv2_configure_irq(sc->v2m_gic_dip, spi, B_TRUE);

	/*
	 * syspic_get_state() acquires syspic_intrs_lock; we must release
	 * it after add_avintr.
	 */
	state = syspic_get_state(spi);
	VERIFY3P(state, !=, NULL);
	state->si_edge_triggered = B_TRUE;
	state->si_prio = hdlp->ih_pri;

	/* Register handler - triggers addspl path */
	if (!add_avintr((void *)hdlp, hdlp->ih_pri,
	    hdlp->ih_cb_func, DEVI(rdip)->devi_name,
	    spi, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2,
	    NULL, rdip)) {
		syspic_remove_state(spi);
		mutex_exit(&syspic_intrs_lock);
		return (DDI_FAILURE);
	}
	mutex_exit(&syspic_intrs_lock);

	/*
	 * Set MSI address/data on the interrupt handle for framework use.
	 * The DDI MSI framework (pci_common_intr_ops ENABLE) reads
	 * ip_msi_addr and ip_msi_data to program PCI caps.
	 */
	if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
		priv->ip_msi_addr = sc->v2m_doorbell_pa;
		priv->ip_msi_data = msi_base_spi;
	} else {
		priv->ip_msi_addr = sc->v2m_doorbell_pa;
		priv->ip_msi_data = spi;
	}

	return (DDI_SUCCESS);
}

/*
 * Disable a single MSI/MSI-X vector.
 *
 * Prior to calling this function the caller must clear an MSI/MSI-X programming
 * on the device.
 *
 * 1. Remove the handler via rem_avintr (triggers delspl which disables
 *    the SPI and resets priority on the distributor).
 *
 * A subtle interaction here is that rem_avintr ends up calling through to
 * gicv2_delspl (which is the delspl handler delegated via syspic), and
 * that is where the syspic state is removed (and locks are managed).  This
 * is visually imbalanced when you look at `gicv2m_enable', but is correct.
 */
static int
gicv2m_disable(gicv2m_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	uint32_t spi = hdlp->ih_vector;

	/*
	 * PCI capability deconfiguration is handled by the DDI MSI framework
	 * (pci_common_intr_ops DISABLE).
	 */
	rem_avintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func, spi);

	return (DDI_SUCCESS);
}

/*
 * Return the pending state of an MSI/MSI-X interrupt.
 *
 * Each MSI/MSI-X vector maps to an SPI in the GICv2 distributor.
 * We read the GICD_ISPENDRn bit for the corresponding SPI.
 * The result is inherently racy (the bit may change at any instant)
 * but is suitable for diagnostic use.
 */
static int
gicv2m_getpending(gicv2m_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	uint32_t spi;
	uint32_t idx;
	gicv2m_dev_state_t *ds;

	mutex_enter(&sc->v2m_dev_lock);
	ds = gicv2m_find_dev(sc, rdip);
	if (ds == NULL) {
		mutex_exit(&sc->v2m_dev_lock);
		return (DDI_FAILURE);
	}

	idx = hdlp->ih_inum - ds->ds_inum_base;
	if (idx >= ds->ds_count) {
		mutex_exit(&sc->v2m_dev_lock);
		return (DDI_FAILURE);
	}

	if (ds->ds_type == DDI_INTR_TYPE_MSI) {
		spi = ds->ds_base_spi + idx;
	} else {
		spi = ds->ds_spi_array[idx];
	}
	mutex_exit(&sc->v2m_dev_lock);

	*(int *)result = gicv2_irq_ispending(sc->v2m_gic_dip, spi) ? 1 : 0;
	return (DDI_SUCCESS);
}

/*
 * GETTARGET: return the current CPU target for this device's SPI.
 *
 * v2m MSI SPIs live in the distributor just like any other SPI.
 * Delegate to the parent GICv2's exported inner function, which
 * acquires the GICD lock internally.
 */
static int
gicv2m_gettarget(gicv2m_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	gicv2m_dev_state_t *ds;
	uint32_t spi;
	uint32_t idx;

	mutex_enter(&sc->v2m_dev_lock);
	ds = gicv2m_find_dev(sc, rdip);
	if (ds == NULL) {
		mutex_exit(&sc->v2m_dev_lock);
		return (DDI_FAILURE);
	}

	idx = hdlp->ih_inum - ds->ds_inum_base;
	if (idx >= ds->ds_count) {
		mutex_exit(&sc->v2m_dev_lock);
		return (DDI_FAILURE);
	}

	if (ds->ds_type == DDI_INTR_TYPE_MSI) {
		spi = ds->ds_base_spi + idx;
	} else {
		spi = ds->ds_spi_array[idx];
	}
	mutex_exit(&sc->v2m_dev_lock);

	*(processorid_t *)result = gicv2_get_target_spi(sc->v2m_gic_dip, spi);
	return (DDI_SUCCESS);
}

/*
 * SETTARGET: retarget this device's SPI to a different CPU.
 */
static int
gicv2m_settarget(gicv2m_state_t *sc, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	gicv2m_dev_state_t *ds;
	processorid_t new_cpu = *(processorid_t *)result;
	uint32_t spi;
	uint32_t idx;

	if (new_cpu < 0 || new_cpu >= 8) {
		return (DDI_EINVAL);
	}

	mutex_enter(&sc->v2m_dev_lock);
	ds = gicv2m_find_dev(sc, rdip);
	if (ds == NULL) {
		mutex_exit(&sc->v2m_dev_lock);
		return (DDI_FAILURE);
	}

	idx = hdlp->ih_inum - ds->ds_inum_base;
	if (idx >= ds->ds_count) {
		mutex_exit(&sc->v2m_dev_lock);
		return (DDI_FAILURE);
	}

	if (ds->ds_type == DDI_INTR_TYPE_MSI) {
		spi = ds->ds_base_spi + idx;
	} else {
		spi = ds->ds_spi_array[idx];
	}
	mutex_exit(&sc->v2m_dev_lock);

	gicv2_set_target_spi(sc->v2m_gic_dip, spi, new_cpu);
	return (DDI_SUCCESS);
}


/*
 * bus_intr_op entry point - dispatches interrupt operations from the
 * MSI framework to per-operation handlers.
 */
static int
gicv2m_intr_ops(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	gicv2m_state_t *sc = ddi_get_soft_state(gicv2m_soft_state,
	    ddi_get_instance(dip));
	VERIFY3P(sc, !=, NULL);

	switch (intr_op) {
	case DDI_INTROP_ALLOC:
		return (gicv2m_alloc(sc, rdip, hdlp, result));
	case DDI_INTROP_FREE:
		return (gicv2m_free(sc, rdip, hdlp));
	case DDI_INTROP_ENABLE:
		return (gicv2m_enable(sc, rdip, hdlp));
	case DDI_INTROP_DISABLE:
		return (gicv2m_disable(sc, rdip, hdlp));
	case DDI_INTROP_BLOCKENABLE:
		return (DDI_ENOTSUP);
	case DDI_INTROP_BLOCKDISABLE:
		return (DDI_ENOTSUP);
	case DDI_INTROP_ADDISR:
	case DDI_INTROP_REMISR:
		/*
		 * Handler registration is managed via add_avintr/rem_avintr
		 * in the ENABLE/DISABLE paths.
		 */
		return (DDI_SUCCESS);
	case DDI_INTROP_SUPPORTED_TYPES:
		*(int *)result = DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX;
		return (DDI_SUCCESS);
	case DDI_INTROP_NAVAIL:
		*(int *)result = (int)vmem_size(sc->v2m_spi_arena, VMEM_FREE);
		return (DDI_SUCCESS);
	case DDI_INTROP_GETPENDING:
		return (gicv2m_getpending(sc, rdip, hdlp, result));
	case DDI_INTROP_GETCAP:
		*(int *)result &= ~DDI_INTR_FLAG_BLOCK;
		*(int *)result |= DDI_INTR_FLAG_PENDING;
		*(int *)result |= DDI_INTR_FLAG_EDGE;
		*(int *)result &= ~DDI_INTR_FLAG_LEVEL;
		return (DDI_SUCCESS);
	case DDI_INTROP_GETTARGET:
		return (gicv2m_gettarget(sc, rdip, hdlp, result));
	case DDI_INTROP_SETTARGET:
		return (gicv2m_settarget(sc, rdip, hdlp, result));
	case DDI_INTROP_SETPRI: {
		int shared;
		uint_t curpri;
		uint_t newpri;
		uint32_t spi = hdlp->ih_vector;

		DDI_INTR_NEXDBG((CE_CONT, "gicv2m_intr_ops: SETPRI "
		    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x, "
		    "is 0x%x\n",
		    (void *)rdip, (void *)hdlp, hdlp->ih_inum,
		    *(int *)result));
		if (*(int *)result > LOCK_LEVEL) {
			DDI_INTR_NEXDBG((CE_CONT, "gicv2m_intr_ops: SETPRI "
			    "for rdip = 0x%p: new pri %d exceeds "
			    "LOCK_LEVEL %d\n",
			    (void *)rdip, *(int *)result, LOCK_LEVEL));
			return (DDI_FAILURE);
		}

		shared = av_get_shared(spi, &curpri);
		newpri = (uint_t)(*(int *)result);
		if (shared > 0 && newpri != curpri) {
			dev_err(rdip, CE_NOTE,
			    "!%s%d: refusing to set pri 0x%x on "
			    "shared SPI %u with pri 0x%x",
			    ddi_node_name(rdip), ddi_get_instance(rdip),
			    newpri, spi, curpri);
			return (DDI_FAILURE);
		}

		ASSERT3U(*(int *)result, !=, 0);
		hdlp->ih_pri = *(int *)result;
		return (DDI_SUCCESS);
	}
	case DDI_INTROP_GETPOOL:
		if (sc->v2m_irm_pool == NULL) {
			return (DDI_ENOTSUP);
		}
		*(ddi_irm_pool_t **)result = sc->v2m_irm_pool;
		return (DDI_SUCCESS);
	default:
		return (DDI_ENOTSUP);
	}
}

/*
 * Attach a v2m MSI frame.
 */
static int
gicv2m_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	int nregs;
	gicv2m_state_t *sc;
	ddi_device_acc_attr_t reg_acc_attr = {
		.devacc_attr_version		= DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder		= DDI_STRICTORDER_ACC
	};
	ddi_irm_params_t params = {
		.iparams_types = DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX,
	};

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:	/* fallthrough */
	case DDI_PM_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ASSERT3U(cmd, ==, DDI_ATTACH);
	instance = ddi_get_instance(dip);

	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_MSI_CONTROLLER)) {
		dev_err(dip, CE_PANIC, "GICv2m must have the %s property.",
		    OBP_MSI_CONTROLLER);
	}

	if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if (nregs != 1)
		return (DDI_FAILURE);

	if (ddi_soft_state_zalloc(gicv2m_soft_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	sc = ddi_get_soft_state(gicv2m_soft_state, instance);
	VERIFY3P(sc, !=, NULL);
	sc->v2m_dip = dip;

	/*
	 * Verify our parent GICv2 is the system PIC.
	 *
	 * The v2m ENABLE path uses add_avintr() which programs SPIs via
	 * syspic_addspl -> gicv2_addspl on the syspic-registered GICv2.
	 * If our parent were a different (slave) GICv2, we'd program the
	 * wrong distributor.  Subordinate GICv2 is not supported.
	 */
	sc->v2m_gic_dip = ddi_get_parent(dip);
	VERIFY3P(sc->v2m_gic_dip, !=, NULL);
	VERIFY3P(sc->v2m_gic_dip, ==, syspic_get_dip());

	/*
	 * Initialise per-device state list.
	 */
	mutex_init(&sc->v2m_dev_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&sc->v2m_devs, sizeof (gicv2m_dev_state_t),
	    offsetof(gicv2m_dev_state_t, ds_node));

	/* Map the v2m MMIO frame */
	if (ddi_regs_map_setup(dip, 0, &sc->v2m_base, 0, 0,
	    &reg_acc_attr, &sc->v2m_regh) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to map v2m registers");
		goto fail_devs;
	}

	/*
	 * Determine SPI base and count.
	 *
	 * Some GIC-400 implementations have incorrect values in the
	 * MSI_TYPER register.  The DT binding provides optional
	 * "arm,msi-base-spi" and "arm,msi-num-spis" properties to
	 * override the hardware values when this is the case.
	 */
	sc->v2m_spi_base = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, V2M_PROP_MSI_BASE_SPI, -1);
	sc->v2m_spi_count = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, V2M_PROP_MSI_NUM_SPIS, -1);

	if (sc->v2m_spi_base == (uint32_t)-1 ||
	    sc->v2m_spi_count == (uint32_t)-1) {
		uint32_t typer = ddi_get32(sc->v2m_regh,
		    (uint32_t *)(sc->v2m_base + V2M_MSI_TYPER));
		sc->v2m_spi_base = V2M_MSI_TYPER_BASE(typer);
		sc->v2m_spi_count = V2M_MSI_TYPER_COUNT(typer);
	}

	if (sc->v2m_spi_count == 0) {
		dev_err(dip, CE_WARN, "v2m frame reports 0 SPIs");
		goto fail_regs;
	}

	/*
	 * Validate the SPI range falls within the architectural limits.
	 * SPIs are INTIDs 32-1019 (GIC_INTID_SPI_MIN to GIC_INTID_SPI_MAX).
	 */
	if (sc->v2m_spi_base < GIC_INTID_SPI_MIN ||
	    (sc->v2m_spi_base + sc->v2m_spi_count - 1) > GIC_INTID_SPI_MAX) {
		dev_err(dip, CE_WARN,
		    "v2m SPI range [%u-%u] outside valid SPI range [%u-%u]",
		    sc->v2m_spi_base,
		    sc->v2m_spi_base + sc->v2m_spi_count - 1,
		    GIC_INTID_SPI_MIN, GIC_INTID_SPI_MAX);
		goto fail_regs;
	}

	/*
	 * Get the doorbell physical address.
	 *
	 * PCI MSI address registers need the physical address of
	 * V2M_MSI_SETSPI_NS.  We obtain the frame's base address from
	 * the parent-private regspec (set up by impl_ddi_sunbus_initchild
	 * -> make_ddi_ppd -> impl_xlate_regs) and apply the parent's
	 * ranges to translate from child address space to physical
	 * address space.
	 *
	 * This correctly handles both the case where the GIC uses
	 * `ranges` (e.g., GIC-400 DT binding example) and the case
	 * where the v2m reg is already a physical address (no ranges
	 * or identity-mapped ranges).
	 */
	{
		struct regspec *rp;
		struct regspec reg;

		rp = i_ddi_rnumber_to_regspec(dip, 0);
		if (rp == NULL) {
			dev_err(dip, CE_WARN,
			    "no reg property for v2m frame");
			goto fail_regs;
		}
		reg = *rp;
		if (i_ddi_apply_range(sc->v2m_gic_dip, dip, &reg) != 0) {
			dev_err(dip, CE_WARN,
			    "failed to translate v2m register address");
			goto fail_regs;
		}
		sc->v2m_doorbell_pa = reg.regspec_addr + V2M_MSI_SETSPI_NS;
	}

	/*
	 * SPI allocation is managed by a vmem arena, which easily meets
	 * the needs of both MSI and MSI-X allocations.
	 */
	sc->v2m_spi_arena = vmem_create("gicv2m_spi",
	    (void *)(uintptr_t)sc->v2m_spi_base,
	    sc->v2m_spi_count, 1 /* quantum */,
	    NULL, NULL, NULL, 0, VM_SLEEP);

	/*
	 * Create an IRM pool for this v2m frame's SPI range.
	 * Each v2m frame has its own disjoint SPI allocation domain,
	 * so each gets its own pool for IRM rebalancing.
	 */
	params.iparams_total = sc->v2m_spi_count;

	if (ndi_irm_create(dip, &params,
	    &sc->v2m_irm_pool) != NDI_SUCCESS) {
		dev_err(dip, CE_WARN,
		    "failed to create IRM pool");
		sc->v2m_irm_pool = NULL;
	}

	dev_err(dip, CE_CONT, "?GICv2m: %u MSI SPIs [%u-%u], "
	    "doorbell PA 0x%" PRIx64 "\n", sc->v2m_spi_count,
	    sc->v2m_spi_base,
	    sc->v2m_spi_base + sc->v2m_spi_count - 1,
	    sc->v2m_doorbell_pa);

	/*
	 * Register our SPI range with the parent GICv2 so it rejects
	 * direct GETTARGET/SETTARGET for our INTIDs -- only we can
	 * issue targeting operations for our SPIs.
	 */
	gicv2_register_msi_range(sc->v2m_gic_dip, sc->v2m_spi_base,
	    sc->v2m_spi_count);

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

fail_regs:
	ddi_regs_map_free(&sc->v2m_regh);
fail_devs:
	list_destroy(&sc->v2m_devs);
	mutex_destroy(&sc->v2m_dev_lock);
	ddi_soft_state_free(gicv2m_soft_state, instance);

	return (DDI_FAILURE);
}

static int
gicv2m_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/*
	 * It is in theory possible we could evacuate an interrupt controller,
	 * but there's no reason to try.
	 */
	return (DDI_FAILURE);
}

/*
 * Module plumbing
 *
 * bus_ops is required so that process_intr_ops() can find the bus_intr_op
 * entry point when the MSI framework routes operations to the v2m node.
 * The v2m acts as a nexus for interrupt operations only - it does not
 * enumerate child devices.
 */
static struct bus_ops gicv2m_bus_ops = {
	.busops_rev	= BUSO_REV,
	.bus_intr_op	= gicv2m_intr_ops,
};

static struct dev_ops gicv2m_ops = {
	.devo_rev	= DEVO_REV,
	.devo_refcnt	= 0,
	.devo_getinfo	= ddi_no_info,
	.devo_identify	= nulldev,
	.devo_probe	= nulldev,
	.devo_attach	= gicv2m_attach,
	.devo_detach	= gicv2m_detach,
	.devo_reset	= nodev,
	.devo_cb_ops	= NULL,
	.devo_bus_ops	= &gicv2m_bus_ops,
	.devo_power	= NULL,
	.devo_quiesce	= ddi_quiesce_not_needed,
};

static struct modldrv modldrv = {
	.drv_modops	= &mod_driverops,
	.drv_linkinfo	= "GICv2m MSI Controller",
	.drv_dev_ops	= &gicv2m_ops,
};

static struct modlinkage modlinkage = {
	.ml_rev		= MODREV_1,
	.ml_linkage	= { &modldrv, NULL },
};

int
_init(void)
{
	int ret;

	if ((ret = ddi_soft_state_init(&gicv2m_soft_state,
	    sizeof (gicv2m_state_t), 1)) != 0) {
		return (ret);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&gicv2m_soft_state);
		return (ret);
	}

	return (ret);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage))) {
		return (ret);
	}

	ddi_soft_state_fini(&gicv2m_soft_state);
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
