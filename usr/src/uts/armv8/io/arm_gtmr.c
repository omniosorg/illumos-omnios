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
 */

/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

/*
 * Resource management for, and implementation of, the Arm Generic Timer Cyclic
 * Backend.
 *
 * This driver and library attaches very early during boot via cbe_init, which
 * is only concerned with ensuring that this driver is attached. All further
 * cyclic backend logic is contained in this file and registered by the attach
 * routine.
 *
 * Having the cyclic backend be a proper DDI driver means that implementation
 * specific interrupt resource management can take effect without leaking
 * firmware-specific logic into the driver.
 */

#include <sys/types.h>
#include <sys/ccompile.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/cyclic.h>
#include <sys/cyclic_impl.h>
#include <sys/arch_timer.h>
#include <sys/smp_impldefs.h>
#include <sys/clock.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/irq.h>
#include <sys/xc_levels.h>

#define	EXPECTED_NINTRS		4
#define	ARM_GTMR_INUM_HYP	3
#define	ARM_GTMR_INUM_VIRTUAL	2

static ddi_softint_hdl_impl_t cbe_low_hdl =
	{0, 0, NULL, NULL, 0, NULL, NULL, NULL};
static ddi_softint_hdl_impl_t cbe_clock_hdl =
	{0, 0, NULL, NULL, 0, NULL, NULL, NULL};

static hrtime_t cbe_timer_resolution;

static int cbe_ticks = 0;	/* XXXARM: why do we need this? */

/*
 * cbe_xcall_lock is used to protect the xcall globals since the cyclic
 * reprogramming API does not use cpu_lock.
 *
 * XXXARM: This should not really be necessary - we need to look into how
 * xcalls are implemented and make them more like other platforms.
 */
static kmutex_t cbe_xcall_lock;
static cyc_func_t volatile cbe_xcall_func;
static cpu_t *volatile cbe_xcall_cpu;
static void *cbe_xcall_farg;
static cpuset_t cbe_enabled;

/*
 * Cyclic Backend implementation functions
 *
 * See the extensive docblock in common/sys/cyclic_impl.h.
 */

static cyb_arg_t
cbe_configure(cpu_t *cpu)
{
	return (cpu);
}

static void
cbe_unconfigure(cyb_arg_t arg __maybe_unused)
{
	ASSERT(!CPU_IN_SET(cbe_enabled, ((cpu_t *)arg)->cpu_id));
}

static void
cbe_enable(cyb_arg_t arg)
{
	processorid_t me = ((cpu_t *)arg)->cpu_id;

	ASSERT((me == 0) || !CPU_IN_SET(cbe_enabled, me));
	CPUSET_ADD(cbe_enabled, me);
	arch_timer_set_cval(CNT_CVAL_MAX);
	arch_timer_unmask_irq();
	arch_timer_enable();
}

static void
cbe_disable(cyb_arg_t arg)
{
	processorid_t me = ((cpu_t *)arg)->cpu_id;

	ASSERT(CPU_IN_SET(cbe_enabled, me));
	arch_timer_disable();
	arch_timer_mask_irq();
	CPUSET_DEL(cbe_enabled, me);
}

/*
 * XXXARM: Per the CBE block comments we could get a time in the recent past,
 * which we need to arrange to run ASAP.
 */
static void
cbe_reprogram(cyb_arg_t arg __unused, hrtime_t time)
{
	hrtime_t val;
	val = unscalehrtime(time + cbe_timer_resolution);
	arch_timer_set_cval(val);
}

static void
cbe_softint(cyb_arg_t arg __unused, cyc_level_t level)
{
	switch (level) {
	case CY_LOW_LEVEL:
		(*setsoftint)(CBE_LOW_PIL, cbe_low_hdl.ih_pending);
		break;
	case CY_LOCK_LEVEL:
		(*setsoftint)(CBE_LOCK_PIL, cbe_clock_hdl.ih_pending);
		break;
	default:
		panic("cbe_softint: unexpected soft level %d", level);
	}
}

static cyc_cookie_t
cbe_set_level(cyb_arg_t arg __unused, cyc_level_t level)
{
	int ipl;

	switch (level) {
	case CY_LOW_LEVEL:
		ipl = CBE_LOW_PIL;
		break;
	case CY_LOCK_LEVEL:
		ipl = CBE_LOCK_PIL;
		break;
	case CY_HIGH_LEVEL:
		ipl = CBE_HIGH_PIL;
		break;
	default:
		panic("cbe_set_level: unexpected level %d", level);
	}

	return (splr(ipltospl(ipl)));
}

static void
cbe_restore_level(cyb_arg_t arg __unused, cyc_cookie_t cookie)
{
	splx(cookie);
}

static void
cbe_xcall(cyb_arg_t arg __unused, cpu_t *dest, cyc_func_t func, void *farg)
{
	kpreempt_disable();

	if (dest == CPU) {
		(*func)(farg);
		kpreempt_enable();
		return;
	}

	mutex_enter(&cbe_xcall_lock);

	ASSERT(cbe_xcall_func == NULL);

	cbe_xcall_farg = farg;
	membar_producer();
	cbe_xcall_cpu = dest;
	cbe_xcall_func = func;

	send_dirint(dest->cpu_id, IRQ_IPI_CBE);

	while (cbe_xcall_func != NULL || cbe_xcall_cpu != NULL)
		continue;

	mutex_exit(&cbe_xcall_lock);

	kpreempt_enable();
}

static void
cbe_suspend(cyb_arg_t arg __unused)
{
	/*
	 * XXXARM: the timer is in the always-on domain, but the docs suggest
	 * that we could mask it here.
	 */
}

static void
cbe_resume(cyb_arg_t arg __unused)
{
	/*
	 * XXXARM: the timer is in the always-on domain, but the docs suggest
	 * that we could unmask it here.
	 */
}

/*
 * Unbound cyclic, called once per tick (every nsec_per_tick ns).
 *
 * This cyclic is registered in the driver attach routine.
 */
static void
cbe_hres_tick(void)
{
	int s;

	dtrace_hres_tick();

	/*
	 * Because hres_tick effectively locks hres_lock, we must be at the
	 * same PIL as that used for CLOCK_LOCK.
	 */
	s = splr(ipltospl(XC_HI_PIL));
	hres_tick();
	splx(s);

	cbe_ticks++;
}

/*
 * Cyclic backend interrupt handlers.
 *
 * `cbe_fire' is hooked up to the generic timer virtual or non-secure
 * interrupt as appropriate for the boot exception level. `cbe_fire_ipi' is
 * an IPI handler and `cbe_softclock' and `cbe_low_level' are soft interrupts.
 */

static uint_t
cbe_fire(caddr_t arg1 __unused, caddr_t arg2 __unused)
{
	cpu_t *cpu = CPU;
	processorid_t me = cpu->cpu_id, i;

	arch_timer_set_cval(CNT_CVAL_MAX);

	cyclic_fire(cpu);

	for (i = 0; i < NCPU; i++) {
		if (CPU_IN_SET(cbe_enabled, i) && me != i) {
			send_dirint(i, IRQ_IPI_CBE);
		}
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
cbe_fire_ipi(caddr_t arg1 __unused, caddr_t arg2 __unused)
{
	cpu_t *cpu = CPU;
	int cross_call = (cbe_xcall_func != NULL && cbe_xcall_cpu == cpu);

	membar_consumer();

	cyclic_fire(cpu);

	if (cross_call) {
		ASSERT(cbe_xcall_func != NULL && cbe_xcall_cpu == cpu);
		(*cbe_xcall_func)(cbe_xcall_farg);
		cbe_xcall_func = NULL;
		cbe_xcall_cpu = NULL;
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
cbe_softclock(caddr_t arg1 __unused, caddr_t arg2 __unused)
{
	cyclic_softint(CPU, CY_LOCK_LEVEL);
	return (1);
}

static uint_t
cbe_low_level(caddr_t arg1 __unused, caddr_t arg2 __unused)
{
	cyclic_softint(CPU, CY_LOW_LEVEL);
	return (1);
}

/*
 * Driver routines.
 */

static int
arm_gtmr_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	int itypes;
	int icount;
	int iactual;
	int iwanted;
	uint_t intr_pri;
	uint_t inum;
	ddi_intr_handle_t *itable;
	int def_prios[EXPECTED_NINTRS] = {
		CBE_HIGH_PIL,
		CBE_HIGH_PIL,
		CBE_HIGH_PIL,
		CBE_HIGH_PIL
	};
	uint_t def_nprios = EXPECTED_NINTRS;

	cyc_backend_t cbe = {
		.cyb_configure		= cbe_configure,
		.cyb_unconfigure	= cbe_unconfigure,
		.cyb_enable		= cbe_enable,
		.cyb_disable		= cbe_disable,
		.cyb_reprogram		= cbe_reprogram,
		.cyb_softint		= cbe_softint,
		.cyb_set_level		= cbe_set_level,
		.cyb_restore_level	= cbe_restore_level,
		.cyb_xcall		= cbe_xcall,
		.cyb_suspend		= cbe_suspend,
		.cyb_resume		= cbe_resume
	};

	cyc_handler_t hdlr;
	cyc_time_t when;

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
	ASSERT3U(ddi_get_instance(dip), ==, 0);

	arch_timer_disable();
	arch_timer_mask_irq();
	CPUSET_ZERO(cbe_enabled);

	mutex_init(&cbe_xcall_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Per the bindings document there are four interrupts defined for
	 * the armv8 architected timer, these are (with their indices):
	 * - 0: secure physical
	 * - 1: non-secure physical
	 * - 2: virtual
	 * - 3: hypervisor
	 *
	 * If booted at EL2 we use the hypervisor timer (index 3), otherwise
	 * we use the virtual timer (index 2). We only ever use one of the
	 * offered interrupts.
	 *
	 * While it is possible to define a driver.conf(5) for this driver,
	 * it is highly discouraged, as the only property that may make sense
	 * is `interrupt-priorities'. If present, `interrupt-priorities' must
	 * contain an array of four integers and each integer must have the
	 * value 14 (corresponding to CBE_HIGH_PIL), or the cyclic backend
	 * will not behave correctly.
	 */

	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_INTERRUPT_PRIORITIES)) {
		if ((ret = ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		    OBP_INTERRUPT_PRIORITIES,
		    def_prios, def_nprios)) != DDI_PROP_SUCCESS)
			dev_err(dip, CE_PANIC,
			    "Failed to set default priorities");
	}

	iwanted = 1;

	inum = ARM_GTMR_INUM_HYP;
	if (CPU->cpu_m.mcpu_boot_el == 1)
		inum = ARM_GTMR_INUM_VIRTUAL;

	/*
	 * We can only use fixed interrupts
	 */
	ret = ddi_intr_get_supported_types(dip, &itypes);
	if ((ret != DDI_SUCCESS) || (!(itypes & DDI_INTR_TYPE_FIXED)))
		dev_err(dip, CE_PANIC, "Fixed type interrupt is not supported");

	/*
	 * We expect four fixed interrupts, but accept any number that allows
	 * us to use our expected interrupt number
	 */
	ret = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_FIXED, &icount);
	if (ret != DDI_SUCCESS)
		dev_err(dip, CE_PANIC, "Failed to get fixed interrupt count");
	if (icount < (inum + 1))
		dev_err(dip, CE_PANIC, "Need %d fixed interrupts, found %d",
		    inum + 1, icount);
	if (icount != EXPECTED_NINTRS)
		dev_err(dip, CE_NOTE, "Expected %d interrupts, found %d",
		    EXPECTED_NINTRS, icount);

	/*
	 * Allocate our interrupt
	 */
	itable = kmem_zalloc(icount * sizeof (ddi_intr_handle_t), KM_SLEEP);
	ret = ddi_intr_alloc(dip, itable, DDI_INTR_TYPE_FIXED,
	    inum, iwanted, &iactual, DDI_INTR_ALLOC_STRICT);
	if ((ret != DDI_SUCCESS) || (iactual != iwanted))
		dev_err(dip, CE_PANIC, "ddi_intr_alloc() for %d fixed "
		    "interrupts failed (inum %u, ret %d, actual %d)",
		    iwanted, inum, ret, iactual);

	/*
	 * Ensure that our priority is correctly configured
	 */
	if (ddi_intr_get_pri(itable[inum], &intr_pri) != DDI_SUCCESS)
		dev_err(dip, CE_PANIC, "ddi_intr_get_pri() failed");
	VERIFY3U(intr_pri, ==, CBE_HIGH_PIL);

	/*
	 * Add our hardware interrupt handler to our interrupt handle.
	 */
	if ((ret = ddi_intr_add_handler(itable[inum], cbe_fire,
	    NULL, NULL)) != DDI_SUCCESS)
		dev_err(dip, CE_PANIC, "ddi_intr_add_handler() failed");

	/*
	 * Enable our primary per-processor interrupt. This enables the
	 * interrupt for all processors, but the source remains masked, so
	 * no interrupt will make it to a CPU just yet (see `cbe_enable').
	 */
	if ((ret = ddi_intr_enable(itable[inum])) != DDI_SUCCESS)
		dev_err(dip, CE_PANIC, "ddi_intr_enable() failed");

	/*
	 * Add our xcall handler, also firing at priority 14. This is called
	 * from our primary per-processor interrupt. In Arm terms this is
	 * an SGI (software-generated interrupt) and, as such, has an
	 * implementation-defined interrupt number.
	 */
	if (add_avintr(NULL, CBE_HIGH_PIL, cbe_fire_ipi, "cbe_fire_ipi",
	    IRQ_IPI_CBE, 0, NULL, NULL, dip) != 1)
		dev_err(dip, CE_PANIC, "add_avintr() failed for ipi handler");

	/*
	 * Add our clock-level soft interrupt handler. Setting this to
	 * pending is driven by the cyclic subsystem.
	 */
	if (add_avsoftintr(&cbe_clock_hdl, CBE_LOCK_PIL, cbe_softclock,
	    "softclock", NULL, NULL) != 1)
		dev_err(dip, CE_PANIC,
		    "add_avsoftintr() failed for softclock handler");

	/*
	 * Add our low level soft interrupt handler. Setting this to
	 * pending is also driven by the cyclic subsystem.
	 */
	if (add_avsoftintr(&cbe_low_hdl, CBE_LOW_PIL, cbe_low_level,
	    "low level", NULL, NULL) != 1)
		dev_err(dip, CE_PANIC,
		    "add_avsoftintr() failed for low level handler");

	/*
	 * Initialise the cyclic subsystem. This results in calls to
	 * `cbe_configure' and `cbe_enable' (amongst others) to initialise
	 * the boot CPU.
	 */
	mutex_enter(&cpu_lock);
	hrtime_init();
	cbe_timer_resolution = NANOSEC / read_cntfrq();
	if (cbe_timer_resolution == 0)
		cbe_timer_resolution = 1;
	cyclic_init(&cbe, cbe_timer_resolution);
	mutex_exit(&cpu_lock);

	/*
	 * Add the unbound high resolution tick cyclic.
	 */
	hdlr.cyh_level = CY_HIGH_LEVEL;
	hdlr.cyh_func = (cyc_func_t)cbe_hres_tick;
	hdlr.cyh_arg = NULL;

	when.cyt_when = 0;
	when.cyt_interval = nsec_per_tick;

	mutex_enter(&cpu_lock);
	(void) cyclic_add(&hdlr, &when);
	mutex_exit(&cpu_lock);

	/*
	 * Configuring and enabling the cyclic backend is done on a per-CPU
	 * basis by the cyclic subsystem. The boot CPU has already been
	 * configured through the call to `cyclic_init'.
	 */

	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
arm_gtmr_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

static struct dev_ops arm_gtmr_ops = {
	.devo_rev		= DEVO_REV,
	.devo_refcnt		= 0,
	.devo_getinfo		= ddi_no_info,
	.devo_identify		= nulldev,
	.devo_probe		= nulldev,
	.devo_attach		= arm_gtmr_attach,
	.devo_detach		= arm_gtmr_detach,
	.devo_reset		= nodev,
	.devo_cb_ops		= NULL,
	.devo_bus_ops		= NULL,
	.devo_power		= NULL,
	.devo_quiesce		= ddi_quiesce_not_needed,
};

static struct modlmisc modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "Arm Generic Timer Cyclic Backend (misc)"
};

static struct modldrv modldrv = {
	.drv_modops		= &mod_driverops,
	.drv_linkinfo		= "Arm Generic Timer Cyclic Backend (driver)",
	.drv_dev_ops		= &arm_gtmr_ops
};

static struct modlinkage modlinkage = {
	.ml_rev			= MODREV_1,
	.ml_linkage		= { &modlmisc, &modldrv, NULL }
};

int
_init(void)
{
	int err;

	if ((err = mod_install(&modlinkage)) != 0) {
		return (err);
	}

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)))
		return (err);

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
