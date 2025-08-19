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
 * Copyright 2025 Michael van der Westhuizen
 */

/*
 * Arm Generic Interrupt Controller v3 Implementation
 *
 * See IHI0069: Arm® Generic Interrupt Controller Architecture Specification
 *              GIC architecture version 3 and version 4
 *
 * For basic usage, GICv3 differs from GICv2 by introducing a new block, the
 * redistributor. In a setup with affinity routing, which we always configure,
 * the distributor remains responsible for configuring and routing shared
 * peripheral interrupts (SPIs) while responsibility for configuring
 * per-processor interrupts (software generated interrupts, or SGIs, and
 * private peripheral interrupts, or PPIs) moves to the redistributor.
 *
 * Since per-processor registers are no longer banked on a per-processor basis
 * configuration of per-processor interrupts _for other processors_ becomes
 * possible, simplifying the application of consistent configuration across
 * processors after MP startup. For this reason, interrupt configuration is
 * split into three functions per action: one for SPIs, one for per-processor
 * configuration and one to decide which implementation to use.
 *
 * Per-processor configuration is run via a helper that iterates through
 * the redistributors, applying a function to each. Interrupts are disabled
 * for the duration of the iteration and individual redistributors are locked
 * while the configuration function is applied to them. This scales badly as
 * the number of processors grows, but interrupt configuration is infrequent
 * and mostly happens at system startup.
 *
 * A major difference from GICv2 is that the CPU interface is now exposed as
 * system registers, which improves interrupt latency somewhat. A side-effect
 * of this change, alongside the introduction of extended PPI and SPI ranges
 * and a new interrupt type (locality-specific peripheral interrupt, or LPI),
 * is that the interrupt handling registers are now wider (64 bits instead of
 * 32).
 *
 * A redistributor consists of either two or four 64k frames, these are:
 * - The redistributor frame
 * - The SGI frame, badly named as this configures all per-processor interrupts
 * - The virtual LPI frame, if VLPI is supported
 * - A reserved frame, if VLPI is supported
 * Redistributor register offsets are expressed relative to these frames, so
 * the redistributor structure stores pointers into the mapped redistributor
 * regions representing these frame addresses. MMIO helpers exist for each
 * frame to make it clear which registers are being accessed.
 *
 * We always do EOImode=1, which splits interrupt lifecycle management to
 * separate the running priority drop and deactivation of the interrupt.
 * Taking this approach alleviates the strict ordering requirement imposed
 * by the running priority drop, enabling full support for threaded IRQs.
 */

#include <sys/types.h>
#include <sys/syspic.h>
#include <sys/syspic_impl.h>
#include <sys/gic.h>
#include <sys/gic_reg.h>
#include <sys/avintr.h>
#include <sys/smp_impldefs.h>
#include <sys/sunddi.h>
#include <sys/cpuinfo.h>
#include <sys/sysmacros.h>
#include <sys/archsystm.h>
#include <sys/mach_intr.h>

/*
 * A redistributor region is a block of redistributor MMIO space. One finds
 * redistributors within this region by reading the TYPER register at the
 * head of each block and using that to advance a pointer through the space
 * until the GICR_TYPER.Last bit is set, indicating that we've hit the last
 * redistributor in a region.
 *
 * This structure represents the device arena mapping of the redistributor
 * regions.
 */
typedef struct {
	/* Base address of, and handle to, the redistributor region */
	caddr_t			base;
	uint64_t		size;
	ddi_acc_handle_t	hdl;
} gicv3_redist_region_t;

/*
 * The redistributor structure describes a redistributor in terms of the
 * redistributor frame addresses in the kernel address space.
 *
 * The structure also contains a lock, which must be held when accessing the
 * redistributor frames, a cached copy of the redistributor type register and
 * a template to be used when sending software generated interrupts to the
 * processor associated with this redistributor.
 *
 * Redistributor structures are stored in an array, indexed by CPU ID.
 */
struct gicv3_conf;

typedef struct {
	lock_t			gr_lock;
	struct gicv3_conf	*gr_gc;
	ddi_acc_handle_t	gr_hdlp;
	caddr_t			gr_rd_base;
	caddr_t			gr_sgi_base;
	caddr_t			gr_vlpi_base;
	uint64_t		gr_typer;
	uint64_t		gr_sgir;
} gicv3_redistributor_t;

typedef struct gicv3_conf {
	/* Base address of, and handle to, the distributor */
	caddr_t			gc_gicd;
	ddi_acc_handle_t	gc_gicd_regh;
	/* Shadow copy of the distributor type register */
	uint32_t		gc_gicd_typer;
	/* Number of interrupt sources in the traditional interrupt space */
	uint32_t		gc_maxsources;

	/* Owned mappings of the redistributor regions. */
	gicv3_redist_region_t	*gc_redist_regions;
	/* Number of redistributor regions */
	uint32_t		gc_num_redist_regions;
	/* Redistributor iteration stride, 0 if no padding pages are present */
	uint64_t		gc_redist_stride;

	/*
	 * Redistributors, indexed by CPU ID.
	 *
	 * The pointers in these structures index into the mappings owned by
	 * gc_redist_regions.
	 */
	gicv3_redistributor_t	*gc_redist;
	/* Number of redistributors in the gc_redist array */
	uint32_t		gc_num_redist;

	/* A flag indicating that we have 32 (or more) priority levels */
	uint32_t		gc_pri32;
	/* Protect access the distributor */
	lock_t			gc_dist_lock;
	/*
	 * CPUs for which we have initialized the GIC.  Used to limit IPIs to
	 * only those CPUs we can target.
	 */
	cpuset_t		gc_cpuset;

	/*
	 * System programmable interrupt controller registration control
	 *
	 * A GICv3 is always the system PIC.
	 */
	syspic_ops_t		gc_syspic;
} gicv3_conf_t;

#define	TO_CONF(__c)		((gicv3_conf_t *)(__c))

static void			*gicv3_soft_state;

#define	GICR_FRAME_SIZE			(64 * 1024)

#define	GIC_IPL_TO_PRI(__sc, ipl)	((__sc)->gc_pri32 ? \
					(GIC_IPL_TO_PRIO((ipl))) : \
					(GIC_IPL_TO_PRIO16((ipl))))

#define	GICD_LOCK_INIT_HELD(__sc)	uint64_t __s = disable_interrupts(); \
					LOCK_INIT_HELD(&(__sc)->gc_dist_lock)
#define	GICD_LOCK(__sc)			uint64_t __s = disable_interrupts(); \
					lock_set(&(__sc)->gc_dist_lock)
#define	GICD_UNLOCK(__sc)		lock_clear(&(__sc)->gc_dist_lock); \
					restore_interrupts(__s)

static inline uint32_t
reg_rmw4(ddi_acc_handle_t hdl, caddr_t base,
    uint32_t reg, uint32_t clrbits, uint32_t setbits)
{
	uint32_t val;
	val = (ddi_get32(hdl, (uint32_t *)(base + reg)) & (~clrbits)) | setbits;
	ddi_put32(hdl, (uint32_t *)(base + reg), val);
	return (val);
}

static inline void
reg_await_clear4(ddi_acc_handle_t hdl, caddr_t base,
    uint32_t reg, uint32_t mask)
{
	while (ddi_get32(hdl, (uint32_t *)(base + reg)) & mask)
		;
}

static inline uint32_t
gicd_read4(gicv3_conf_t *gic, uint32_t reg)
{
	return (ddi_get32(gic->gc_gicd_regh, (uint32_t *)(gic->gc_gicd + reg)));
}

static inline void
gicd_write4(gicv3_conf_t *gic, uint32_t reg, uint32_t val)
{
	ddi_put32(gic->gc_gicd_regh, (uint32_t *)(gic->gc_gicd + reg), val);
}

static inline void
gicd_write8(gicv3_conf_t *gic, uint32_t reg, uint64_t val)
{
	ddi_put64(gic->gc_gicd_regh, (uint64_t *)(gic->gc_gicd + reg), val);
}

static inline uint32_t
gicd_rmw4(gicv3_conf_t *gic, uint32_t reg, uint32_t clrbits, uint32_t setbits)
{
	return (reg_rmw4(gic->gc_gicd_regh, gic->gc_gicd,
	    reg, clrbits, setbits));
}

/*
 * Drain any outstanding writes to the distributor.
 *
 * Draining is necessary after writes to:
 * - GICD_CTLR[2:0] - group enables, only when disabling.
 * - GICD_CTLR[7:4] - the ARE bits, E1NWF bit and DS bit.
 * - GICD_ICENABLER<n> - write-to-clear (disable) registers.
 */
static void
gicd_drain_writes(gicv3_conf_t *gic)
{
	reg_await_clear4(gic->gc_gicd_regh, gic->gc_gicd,
	    GICD_CTLR, GICD_CTLR_RWP);
}

static inline uint32_t
gicr_rd_read4(gicv3_redistributor_t *r, uint32_t reg)
{
	return (ddi_get32(r->gr_hdlp, (uint32_t *)(r->gr_rd_base + reg)));
}

static inline uint32_t
gicr_rd_rmw4(gicv3_redistributor_t *r,
    uint32_t reg, uint32_t clrbits, uint32_t setbits)
{
	return (reg_rmw4(r->gr_hdlp, r->gr_rd_base, reg, clrbits, setbits));
}

/*
 * Drain any outstanding writes to a redistributor.
 *
 * Needed after writes to:
 * - GICR_ICENABLER0
 * - GICR_CTLR.DPG1S
 * - GICR_CTLR.DPG1NS
 * - GICR_CTLR.DPG0
 * - GICR_CTLR.EnableLPIs on changing from 1 to 0 (disabling)
 * - GICR_VPROPBASER on changing Valid from 1 to 0
 */
static void
gicr_drain_writes(gicv3_redistributor_t *r)
{
	reg_await_clear4(r->gr_hdlp, r->gr_rd_base, GICR_CTLR, GICR_CTLR_RWP);
}

static inline uint32_t
gicr_sgi_read4(gicv3_redistributor_t *r, uint32_t reg)
{
	return (ddi_get32(r->gr_hdlp, (uint32_t *)(r->gr_sgi_base + reg)));
}

static inline void
gicr_sgi_write4(gicv3_redistributor_t *r, uint32_t reg, uint32_t val)
{
	ddi_put32(r->gr_hdlp, (uint32_t *)(r->gr_sgi_base + reg), val);
}

static inline uint32_t
gicr_sgi_rmw4(gicv3_redistributor_t *r,
    uint32_t reg, uint32_t clrbits, uint32_t setbits)
{
	return (reg_rmw4(r->gr_hdlp, r->gr_sgi_base,
	    reg, clrbits, setbits));
}

/*
 * Private function used to awaken a CPU.
 *
 * For a CPU to receive interrupts the GICR_WAKER.ProcessorSleep bit must be
 * clear and the GICR_WAKER.ChildrenAsleep must have cleared (indicating that
 * the wakeup is complete).
 */
static void
gicv3_awaken_cpu(gicv3_conf_t *gc, cpu_t *cp)
{
	gicv3_redistributor_t *r;
	uint64_t s;

	VERIFY(cp->cpu_id < gc->gc_num_redist);
	r = &gc->gc_redist[cp->cpu_id];

	s = disable_interrupts();
	lock_set(&r->gr_lock);
	gicr_rd_rmw4(r, GICR_WAKER, GICR_WAKER_ProcessorSleep, 0x0);
	reg_await_clear4(r->gr_hdlp, r->gr_rd_base,
	    GICR_WAKER, GICR_WAKER_ChildrenAsleep);
	lock_clear(&r->gr_lock);
	restore_interrupts(s);
}

/*
 * Private helper function used to apply a function to all redistributors.
 *
 * Redistributor configuration is treated as atomic, so interrupts are disabled
 * for the duration of all redistributor updates. Each redistributor is locked
 * prior to the passed function being applied to it, then unlocked afterwards.
 */
static void
gicv3_for_each_gicr(gicv3_conf_t *gc,
    void (*fn)(gicv3_redistributor_t *, uint32_t a0, uint32_t a1),
    uint32_t a0, uint32_t a1)
{
	gicv3_redistributor_t	*r;
	uint64_t		s;
	uint32_t		i;

	s = disable_interrupts();
	for (i = 0; i < gc->gc_num_redist; ++i) {
		r = &gc->gc_redist[i];
		VERIFY3P(r->gr_sgi_base, !=, NULL);
		lock_set(&r->gr_lock);
		(*fn)(r, a0, a1);
		lock_clear(&r->gr_lock);
	}
	restore_interrupts(s);
}

/*
 * IRQ Configuration (level or edge triggered).
 */

/* Per-CPU interrupt configuration helper */
static void
gicv3_config_irq_percpu(gicv3_redistributor_t *r, uint32_t irq, uint32_t v)
{
	/*
	 * §12.11.8 Changing Int_config when the interrupt is
	 * individually enabled is UNPREDICTABLE.
	 */
	ASSERT(((gicr_sgi_read4(r, GICR_ISENABLER0) &
	    GICR_IENABLER_REGBIT(irq)) == 0));
	(void) gicr_sgi_rmw4(r,
	    GICR_ICFGR1,
	    GICR_ICFGR_REGVAL(irq, GICR_ICFGR_INT_CONFIG_MASK),
	    GICD_ICFGR_REGVAL(irq, v));
}

/* Shared peripheral interrupt configuration */
static void
gicv3_config_irq_spi(gicv3_conf_t *gc, uint32_t irq, uint32_t v)
{
	GICD_LOCK(gc);
	/*
	 * §12.9.9 Changing Int_config when the interrupt is
	 * individually enabled is UNPREDICTABLE.
	 */
	if ((gicd_read4(gc,
	    GICD_ISENABLERn(GICD_IENABLER_REGNUM(irq))) &
	    GICD_IENABLER_REGBIT(irq)) != 0) {

		if (gicd_read4(gc, GICD_ICFGRn(GICD_ICFGR_REGNUM(irq))) !=
		    GICD_ICFGR_REGVAL(irq, v)) {
			cmn_err(CE_WARN, "gicthree: vector %d already "
			    "configured differently", irq);
			return;
		}

	} else {
		(void) gicd_rmw4(gc,
		    GICD_ICFGRn(GICD_ICFGR_REGNUM(irq)),
		    GICD_ICFGR_REGVAL(irq, GICD_ICFGR_INT_CONFIG_MASK),
		    GICD_ICFGR_REGVAL(irq, v));
	}
	GICD_UNLOCK(gc);
}

static void
gicv3_config_irq(gicv3_conf_t *gc, uint32_t irq, boolean_t is_edge)
{
	const uint32_t v = (is_edge ?
	    GICD_ICFGR_INT_CONFIG_EDGE : GICD_ICFGR_INT_CONFIG_LEVEL);

	if (GIC_INTID_IS_SGI(irq)) {
		/* SGIs are not configurable */
	} else if (GIC_INTID_IS_PPI(irq)) {
		gicv3_for_each_gicr(gc,
		    gicv3_config_irq_percpu, irq, v);
	} else if (GIC_INTID_IS_SPI(irq)) {
		gicv3_config_irq_spi(gc, irq, v);
	}
}

/*
 * Mask interrupts of priority lower than, or equal to, IRQ.
 */
static int
gicv3_intr_enter(spo_ctx_t ctx, intr_intid_t intid)
{
	gicv3_conf_t *gc;
	int new_ipl = 0;

	gc = TO_CONF(ctx);
	VERIFY3P(gc, !=, NULL);

	if (av_get_vec_lvl(intid, &new_ipl) && new_ipl != 0) {
		write_icc_pmr_el1(GIC_IPL_TO_PRI(gc, new_ipl));
	}

	return (new_ipl);
}

/*
 * Mask interrupts of priority lower than or equal to IPL.
 */
static void
gicv3_intr_exit(spo_ctx_t ctx, intr_ipl_t ipl)
{
	gicv3_conf_t *gc;

	gc = TO_CONF(ctx);
	VERIFY3P(gc, !=, NULL);

	write_icc_pmr_el1(GIC_IPL_TO_PRI(gc, ipl));
}

/*
 * Configure such that IRQ cannot happen at or above IPL
 *
 * There are complications here -- which this code doesn't handle -- which are
 * outlined in the pclusmp implementation, I have included that comment
 * below.
 *
 * (from i86pc/io/mp_platform_misc.c:apic_addspl_common)
 *  * Both add and delspl are complicated by the fact that different interrupts
 * may share IRQs. This can happen in two ways.
 * 1. The same H/W line is shared by more than 1 device
 * 1a. with interrupts at different IPLs
 * 1b. with interrupts at same IPL
 * 2. We ran out of vectors at a given IPL and started sharing vectors.
 * 1b and 2 should be handled gracefully, except for the fact some ISRs
 * will get called often when no interrupt is pending for the device.
 * For 1a, we handle it at the higher IPL.
 *
 * XXXARM: We need interrupt redistribution.
 */

/* Add SPL for shared peripheral interrupts */
static void
gicv3_addspl_spi(gicv3_conf_t *gc, uint32_t irq, uint32_t ipl)
{
	GICD_LOCK(gc);

	/*
	 * Set the priority.
	 */
	(void) gicd_rmw4(gc,
	    GICD_IPRIORITYRn(GICD_IPRIORITY_REGNUM(irq)),
	    GICD_IPRIORITY_REGVAL(irq, GICD_IPRIORITY_REGMASK),
	    GICD_IPRIORITY_REGVAL(irq, GIC_IPL_TO_PRI(gc, ipl)));

	/*
	 * Set the target CPU.
	 */
	if ((gc->gc_gicd_typer & GICD_TYPER_No1N) == 0)
		gicd_write8(gc, GICD_IROUTERn(irq),
		    GICD_IROUTER_Interrupt_Routing_Mode);
	else
		gicd_write8(gc, GICD_IROUTERn(irq), cpu[0]->cpu_m.affinity);

	/*
	 * Enable the interrupt.
	 */
	gicd_write4(gc, GICD_ISENABLERn(GICD_IENABLER_REGNUM(irq)),
	    GICD_IENABLER_REGBIT(irq));

	GICD_UNLOCK(gc);
}

/* Add SPL for per-CPU interrupts */
static void
gicv3_addspl_percpu(gicv3_redistributor_t *r, uint32_t irq, uint32_t ipl)
{
	/*
	 * Set the priority.
	 */
	(void) gicr_sgi_rmw4(r,
	    GICR_IPRIORITYRn(GICR_IPRIORITY_REGNUM(irq)),
	    GICR_IPRIORITY_REGVAL(irq, GICR_IPRIORITY_REGMASK),
	    GICR_IPRIORITY_REGVAL(irq, GIC_IPL_TO_PRI(r->gr_gc, ipl)));

	/*
	 * Enable the interrupt.
	 */
	gicr_sgi_write4(r, GICR_ISENABLER0, GICR_IENABLER_REGBIT(irq));
}

/* Enable an interrupt and set it's priority */
static int
gicv3_addspl(spo_ctx_t ctx, intr_intid_t intid, intr_ipl_t ipl,
    intr_ipl_t min_ipl __unused, intr_ipl_t max_ipl __unused)
{
	gicv3_conf_t *gc;
	syspic_intr_state_t *state = NULL;

	gc = TO_CONF(ctx);
	ASSERT3P(gc, !=, NULL);

	if (GIC_INTID_IS_SGI(intid)) {
		ASSERT(!MUTEX_HELD(&syspic_intrs_lock));
		state = syspic_get_state(intid);
		VERIFY3P(state, !=, NULL);
		state->si_edge_triggered = B_TRUE;
		state->si_prio = ipl;
	}

	ASSERT(MUTEX_HELD(&syspic_intrs_lock));

	if (GIC_INTID_IS_PERCPU(intid)) {
		gicv3_for_each_gicr(gc,
		    gicv3_addspl_percpu, (uint32_t)intid, (uint32_t)ipl);
	} else if (GIC_INTID_IS_SPI(intid)) {
		gicv3_addspl_spi(gc, (uint32_t)intid, (uint32_t)ipl);
	}

	if (state != NULL) {
		mutex_exit(&syspic_intrs_lock);
	}

	return (0);
}

/*
 * XXXARM: Comment taken verbatim from
 *         i86pc/io/mp_platform_misc.c:apic_delspl_common)
 *
 * Recompute mask bits for the given interrupt vector.
 * If there is no interrupt servicing routine for this
 * vector, this function should disable interrupt vector
 * from happening at all IPLs. If there are still
 * handlers using the given vector, this function should
 * disable the given vector from happening below the lowest
 * IPL of the remaining handlers.
 */

/* Delete SPL for shared peripheral interrupts */
static void
gicv3_delspl_spi(gicv3_conf_t *gc, uint32_t irq)
{
	GICD_LOCK(gc);

	/*
	 * Disable the IRQ and drain writes.
	 */
	gicd_write4(gc, GICD_ICENABLERn(GICD_IENABLER_REGNUM(irq)),
	    GICD_IENABLER_REGBIT(irq));
	gicd_drain_writes(gc);

	/*
	 * Set the priority to lowest.
	 */
	(void) gicd_rmw4(gc,
	    GICD_IPRIORITYRn(GICD_IPRIORITY_REGNUM(irq)),
	    GICD_IPRIORITY_REGVAL(irq, GICD_IPRIORITY_REGMASK),
	    GICD_IPRIORITY_REGVAL(irq, GIC_IPL_TO_PRI(gc, 0)));

	GICD_UNLOCK(gc);
}

/* Delete SPL for per-CPU interrupts */
static void
gicv3_delspl_percpu(gicv3_redistributor_t *r, uint32_t irq,
    uint32_t a1 __unused)
{
	/*
	 * Disable the IRQ.
	 */
	gicr_sgi_write4(r, GICR_ICENABLER0, GICR_IENABLER_REGBIT(irq));
	gicr_drain_writes(r);

	/*
	 * Set the priority to lowest.
	 */
	(void) gicr_sgi_rmw4(r,
	    GICR_IPRIORITYRn(GICR_IPRIORITY_REGNUM(irq)),
	    GICR_IPRIORITY_REGVAL(irq, GICR_IPRIORITY_REGMASK),
	    GICR_IPRIORITY_REGVAL(irq, GIC_IPL_TO_PRI(r->gr_gc, 0)));
}

/*
 * Disable an interrupt and reset it's priority
 *
 * The generic GIC layer has taken care of checking if there are still
 * handlers, so this is really just deletion.
 */
static int
gicv3_delspl(spo_ctx_t ctx, intr_intid_t intid, intr_ipl_t ipl __unused,
    intr_ipl_t min_ipl __unused, intr_ipl_t max_ipl __unused)
{
	gicv3_conf_t *gc;
	int pri = -1;

	gc = TO_CONF(ctx);
	ASSERT3P(gc, !=, NULL);

	if (av_get_vec_lvl(intid, &pri) == 0 || pri == 0) {
		mutex_enter(&syspic_intrs_lock);
		syspic_remove_state(intid);

		if (GIC_INTID_IS_PERCPU(intid)) {
			gicv3_for_each_gicr(gc,
			    gicv3_delspl_percpu, (uint32_t)intid, 0);
		} else if (GIC_INTID_IS_SPI(intid)) {
			gicv3_delspl_spi(gc, (uint32_t)intid);
		}

		mutex_exit(&syspic_intrs_lock);
	}

	return (0);
}

/*
 * Send an IRQ as an IPI to processors in `cpuset`.
 *
 * Processors not targetable by the GIC will be silently ignored, as will the
 * sending processor.
 *
 * §2.3.1: "If GICD_TYPER.RSS is 0 or ICC_CTLR_ELx.RSS is 0, Arm strongly
 * recommends that only values in the range 0-15 are used at affinity level
 * 0 to align with the SGI target list capability." We assert this.
 */
static void
gicv3_send_ipi(spo_ctx_t ctx, cpuset_t cpuset, intr_intid_t intid)
{
	gicv3_conf_t *gc;
	boolean_t has_rss;
	uint64_t sgir;

	gc = TO_CONF(ctx);
	ASSERT3P(gc, !=, NULL);

	has_rss = (read_icc_ctlr_el1() & ICC_CTLR_EL1_RSS) ? B_TRUE : B_FALSE;
	dsb(ish);

	/*
	 * There is almost definitely a better way to do this, populating
	 * targetlist/RS and issuing SGI with CPUs clustered by AFF3-1+RS.
	 *
	 * However, this is obviously correct, which will do for now.
	 */
	CPUSET_AND(cpuset, gc->gc_cpuset);
	CPUSET_DEL(cpuset, CPU->cpu_id);
	while (!CPUSET_ISNULL(cpuset)) {
		uint_t cpun;
		CPUSET_FIND(cpuset, cpun);
		sgir = gc->gc_redist[cpun].gr_sgir;
		if (!has_rss && ICC_SGInR_EL1_HAS_RS(sgir)) {
			panic("cpu%d: Need range selector support to target "
			    "cpu%d with an SGI", CPU->cpu_id, cpun);
		}
		write_icc_sgi1r_el1(sgir | ICC_SGInR_EL1_MAKE_INTID(intid));
		CPUSET_DEL(cpuset, cpun);
	}
}

/*
 * Acknowledge receipt of an IRQ by reading the interrupt acknowledge register.
 *
 * The value returned from this function must be passed, unchanged, to
 * gicv3_eoi and gicv3_deactivate.
 *
 * To extract the INTID (vector), use gicv3_ack_to_vector.
 */
static uint64_t
gicv3_acknowledge(spo_ctx_t ctx __unused)
{
	return (read_icc_iar1_el1());
}

/*
 * Extract the interrupt vector from an acknowledged IRQ.
 */
static uint32_t
gicv3_ack_to_vector(spo_ctx_t ctx __unused, intr_cookie_t cookie)
{
	return (cookie & ICC_IAR1_INTID);
}

static boolean_t
gicv3_is_spurious(spo_ctx_t ctx __unused, intr_intid_t intid)
{
	if (GIC_INTID_IS_SPECIAL(intid))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Invoke the running priority drop during interrupt processing.
 */
static void
gicv3_eoi(spo_ctx_t ctx __unused, intr_cookie_t cookie)
{
	write_icc_eoir1_el1(cookie);
}

/*
 * Deactivate an interrupt at the end of interrupt processing.
 */
static void
gicv3_deactivate(spo_ctx_t ctx __unused, intr_cookie_t cookie)
{
	write_icc_dir_el1(cookie);
}

/*
 * Discover redistributors in all redistributor regions and assign them to CPUs
 * by CPU ID.
 */
static int
gicv3_assign_redistributors(dev_info_t *dip, gicv3_conf_t *gc)
{
	uint32_t		i;
	uint64_t		gicr_typer;
	uint32_t		num_redistributors;
	uint64_t		affinity;
	caddr_t			gicr_rd_base;
	caddr_t			gicr_sgi_base;
	caddr_t			gicr_vlpi_base;
	caddr_t			cursor;
	caddr_t			ptr;
	struct cpuinfo		*ci;

	/*
	 * Count the number of redistributors present in our redistributor
	 * regions.
	 */
	num_redistributors = 0;
	for (i = 0; i < gc->gc_num_redist_regions; ++i) {
		gicv3_redist_region_t *rr = &gc->gc_redist_regions[i];
		uint32_t local_redistributors = 0;
		gicr_typer = 0;

		for (cursor = rr->base;
		    (cursor < (rr->base + rr->size) &&
		    (gicr_typer & GICR_TYPER_Last) != GICR_TYPER_Last);
		    local_redistributors++, num_redistributors++) {
			if ((cursor + (GICR_FRAME_SIZE * 2)) >
			    (rr->base + rr->size)) {
				break;
			}

			ptr = cursor;
			gicr_typer = ddi_get64(rr->hdl,
			    (uint64_t *)(cursor + GICR_TYPER));
			cursor += (GICR_FRAME_SIZE * 2);

			if (gicr_typer & GICR_TYPER_VLPIS) {
				cursor += (GICR_FRAME_SIZE * 2);
				if (cursor > (rr->base + rr->size)) {
					break;
				}
			}

			if (gc->gc_redist_stride)
				cursor = ptr + gc->gc_redist_stride;
		}
	}

	/*
	 * Check that we have at least as many redistributors as we do CPUs.
	 */
	VERIFY3U(num_redistributors, >=, max_ncpus);

	/*
	 * Allocate the redistributor structures.
	 */
	gc->gc_redist = kmem_zalloc(
	    sizeof (gicv3_redistributor_t) * num_redistributors, KM_SLEEP);
	gc->gc_num_redist = num_redistributors;

	/*
	 * Iterate the redistributors again. For each one, grab the CPU ID
	 * from cpuinfo for this affinity value and populate the value at that
	 * CPU index.
	 */
	for (i = 0; i < gc->gc_num_redist_regions; ++i) {
		gicv3_redist_region_t *rr = &gc->gc_redist_regions[i];
		uint32_t local_redistributors = 0;
		gicr_typer = 0;

		for (cursor = rr->base;
		    (cursor < (rr->base + rr->size) &&
		    (gicr_typer & GICR_TYPER_Last) != GICR_TYPER_Last);
		    local_redistributors++, num_redistributors++) {
			if ((cursor + (GICR_FRAME_SIZE * 2)) >
			    (rr->base + rr->size)) {
				dev_err(dip, CE_CONT, "?redistributor region "
				    "overflow in region %u (%p), "
				    "redistributor %u\n",
				    i, rr->base, local_redistributors);
				break;
			}

			ptr = cursor;
			gicr_typer = ddi_get64(rr->hdl,
			    (uint64_t *)(cursor + GICR_TYPER));
			gicr_rd_base = cursor;
			cursor += GICR_FRAME_SIZE;
			gicr_sgi_base = cursor;
			cursor += GICR_FRAME_SIZE;

			if (gicr_typer & GICR_TYPER_VLPIS) {
				gicr_vlpi_base = cursor;
				cursor += (GICR_FRAME_SIZE * 2);
			} else {
				gicr_vlpi_base = NULL;
			}

			if (cursor > (rr->base + rr->size)) {
				dev_err(dip, CE_CONT, "?redistributor region "
				    "overflow in region %u (%p), "
				    "redistributor %u\n",
				    i, rr->base, local_redistributors);
				break;
			}

			affinity = AFF_GICR_TYPER_TO_PACKED(gicr_typer);

			ci = cpuinfo_for_affinity(
			    AFF_PACKED_TO_MPIDR(affinity));
			VERIFY3P(ci, !=, NULL);
			VERIFY3U(ci->ci_id, <, gc->gc_num_redist);

			/*
			 * Initialize the redistributor record.
			 */
			LOCK_INIT_CLEAR(&gc->gc_redist[ci->ci_id].gr_lock);
			gc->gc_redist[ci->ci_id].gr_gc = gc;
			gc->gc_redist[ci->ci_id].gr_hdlp = rr->hdl;
			gc->gc_redist[ci->ci_id].gr_rd_base = gicr_rd_base;
			gc->gc_redist[ci->ci_id].gr_sgi_base = gicr_sgi_base;
			gc->gc_redist[ci->ci_id].gr_vlpi_base = gicr_vlpi_base;
			gc->gc_redist[ci->ci_id].gr_typer = gicr_typer;
			gc->gc_redist[ci->ci_id].gr_sgir =
			    AFF_PACKED_TO_ICC_SGInR_EL1(affinity);

			if (gc->gc_redist_stride)
				cursor = ptr + gc->gc_redist_stride;
		}
	}

	/*
	 * Iterate the cpuinfo ensuring that we have a redistributor for
	 * each CPU.
	 */
	for (ci = cpuinfo_first();
	    ci != cpuinfo_end();
	    ci = cpuinfo_next(ci)) {
		VERIFY(ci->ci_id < gc->gc_num_redist);
		if (gc->gc_redist[ci->ci_id].gr_rd_base == NULL ||
		    gc->gc_redist[ci->ci_id].gr_sgi_base == NULL) {
			dev_err(dip, CE_WARN, "CPU %d does not have "
			    "an asociated redistributor", ci->ci_id);
			return (-1);
		}
	}

	return (0);
}

/*
 * Initialize a single redistributor
 *
 * In the case of the boot processor we apply initial configuration default
 * values. In the case of application processors we apply the configuration
 * currently active on the boot processor.
 */
static void
gicv3_init_gicr(gicv3_redistributor_t *r,
    uint32_t a0 __unused, uint32_t a1 __unused)
{
	/*
	 * Clear enabled/pending/active status of the CPU-specific interrupts.
	 */
	gicr_sgi_write4(r, GICR_ICENABLER0, 0xffffffff);
	gicr_drain_writes(r);
	gicr_sgi_write4(r, GICR_ICPENDR0, 0xffffffff);
	gicr_sgi_write4(r, GICR_ICACTIVER0, 0xffffffff);

	/*
	 * Configure SGI and PPI to non-secure group 1.
	 */
	gicr_sgi_write4(r, GICR_IGROUPR0, 0xFFFFFFFF);
	gicr_sgi_write4(r, GICR_IGRPMODR0, 0x0);

	if (CPU->cpu_id == 0) {
		/*
		 * Initialize interrupt priorities for per-CPU interrupts,
		 * setting them to the lowest possible priority.
		 */
		for (int i = 0; i < 8; ++i)
			gicr_sgi_write4(r, GICR_IPRIORITYRn(i), 0xffffffff);

		/*
		 * Explicitly set all SGIs to edge triggered, which is the
		 * default.
		 */
		gicr_sgi_write4(r, GICR_ICFGR0, 0xaaaaaaaa);

		/*
		 * Set all PPIs to level sensitive by default.
		 */
		gicr_sgi_write4(r, GICR_ICFGR1, 0x0);

		/*
		 * SGIs and PPIs have already been disabled at the
		 * start of this function.
		 */
	} else {
		gicv3_redistributor_t *r0 = &r->gr_gc->gc_redist[0];

		lock_set(&r0->gr_lock);

		/*
		 * Initialize interrupt priorities for per-CPU interrupts from
		 * the boot processor.
		 */
		for (int i = 0; i < 8; ++i) {
			gicr_sgi_write4(r, GICR_IPRIORITYRn(i),
			    gicr_sgi_read4(r0, GICR_IPRIORITYRn(i)));
		}

		/*
		 * Configure SGIs from the boot processor.
		 */
		gicr_sgi_write4(r, GICR_ICFGR0,
		    gicr_sgi_read4(r0, GICR_ICFGR0));

		/*
		 * Configure PPIs from the boot processor.
		 */
		gicr_sgi_write4(r, GICR_ICFGR1,
		    gicr_sgi_read4(r0, GICR_ICFGR1));

		/*
		 * Enable SGIs and PPIs that are enabled on the boot processor.
		 *
		 * Others have been explicitly disabled at the start of this
		 * function.
		 */
		gicr_sgi_write4(r, GICR_ISENABLER0,
		    gicr_sgi_read4(r0, GICR_ISENABLER0));

		lock_clear(&r0->gr_lock);
	}
}

/*
 * Enable register access, disable FIQ bypass, disable IRQ bypass.
 */
static int
gicv3_enable_system_register_access(void)
{
	write_icc_sre_el1(ICC_SRE_EL1_SRE|ICC_SRE_EL1_DFB|ICC_SRE_EL1_DIB);
	if ((read_icc_sre_el1() &
	    (ICC_SRE_EL1_SRE|ICC_SRE_EL1_DFB|ICC_SRE_EL1_DIB))
	    != (ICC_SRE_EL1_SRE|ICC_SRE_EL1_DFB|ICC_SRE_EL1_DIB))
		return (-1);

	return (0);
}

/*
 * Public function used for initializing CPUs.
 *
 * The boot processor is initialized from the tail of the main gicv3_init
 * function once the distributor and redistributors have been configured.
 */
static void
gicv3_cpu_init_raw(gicv3_conf_t *gc, cpu_t *cp)
{
	/*
	 * Tell the hardware that this CPU is awake and wait for the wakeup to
	 * complete.
	 */
	gicv3_awaken_cpu(gc, cp);

	/*
	 * CPU Interface Configuration
	 */

	/*
	 * First up, we want to use the system register interface.
	 */
	if (gicv3_enable_system_register_access() != 0)
		panic("cpu%d: Failed to enable the GIC system register "
		    "interface.", cp->cpu_id);

	/*
	 * We don't need subpriorities on GICv3.
	 */
	write_icc_bpr1_el1(0);

	/*
	 * Configure the priority mask register to leave us at LOCK_LEVEL once
	 * initialized.
	 */
	write_icc_pmr_el1(GIC_IPL_TO_PRI(gc, LOCK_LEVEL));

	/*
	 * Ensure the use of split-EOI.
	 */
	write_icc_ctlr_el1(read_icc_ctlr_el1() | ICC_CTLR_EL1_EOImode);

	/*
	 * Enable non-secure group one interrupt signalling on the CPU
	 * interface.
	 */
	write_icc_igrpen1_el1(ICC_IGRPEN1_EL1_Enable);

	/*
	 * Configure SGIs and PPIs in this CPU's GIC redistributor.
	 */
	gicv3_init_gicr(&gc->gc_redist[cp->cpu_id], 0, 0);

	/*
	 * Finally, tell the world we're ready.
	 */
	CPUSET_ADD(gc->gc_cpuset, cp->cpu_id);
}

static void
gicv3_cpu_init(spo_ctx_t ctx, cpu_t *cp)
{
	gicv3_cpu_init_raw(TO_CONF(ctx), cp);
}

/*
 * Map GIC register space and perform global GIC initialization followed by
 * configuration of all redistributors. Finish up by configuring the CPU
 * interface for the boot processor.
 *
 * Returns non-zero on error.
 */
static int
gicv3_init(dev_info_t *dip, gicv3_conf_t *gc)
{
	uint32_t	n;

	/*
	 * Global initialization involves the distributor, so lock it.
	 */
	GICD_LOCK_INIT_HELD(gc);

	/*
	 * Allocate redistributors and assign pointers to them.
	 */
	if (gicv3_assign_redistributors(dip, gc) != 0) {
		GICD_UNLOCK(gc);
		dev_err(dip, CE_WARN, "gicv3_assign_redistributors failed");
		return (DDI_FAILURE);
	}

	gc->gc_gicd_typer = gicd_read4(gc, GICD_TYPER);
	gc->gc_maxsources = GICD_TYPER_LINES(gc->gc_gicd_typer);

	/*
	 * Disable the distributor and drain writes. This is done is pieces
	 * as we want to avoid unpredictable behaviour when changing affinity
	 * routing (§2.2.3: Changing affinity routing enables).
	 *
	 * We turn on affinity routing as quickly as possible, then assert
	 * that we were able to turn it on.
	 *
	 * In an implementation that only supports one security state, ARE
	 * is the same bit as ARE_NS, so this logic holds.
	 */
	(void) gicd_rmw4(gc, GICD_CTLR,
	    GICD_CTLR_RWP|GICD_CTLR_EnableGrp1A|GICD_CTLR_EnableGrp1, 0x0);
	gicd_drain_writes(gc);
	(void) gicd_rmw4(gc, GICD_CTLR,
	    GICD_CTLR_RWP|GICD_CTLR_ARE_NS, GICD_CTLR_ARE_NS);
	gicd_drain_writes(gc);
	VERIFY((gicd_read4(gc, GICD_CTLR) & GICD_CTLR_ARE_NS) ==
	    GICD_CTLR_ARE_NS);

	/*
	 * XXXARM: Quirks might be needed
	 *
	 * There's some nice discussion of a few bugs that affect Ampere eMAG
	 * and Rockchip rk3399 in OpenBSD's sys/arch/arm64/dev/agintc.c. Don't
	 * concern ourselves with those workarounds just yet.
	 *
	 * There's some very sneaky detection of these issues in that code,
	 * but when we look at those issues we should include refencing
	 * GICD_TYPER.SecurityExtn=1 to protect the checks.
	 */

	/*
	 * The minimum number of priority bits for a GICv3 that implements a
	 * single security state is 4. If two states are implemented the
	 * minimum is 5.
	 */
	gc->gc_pri32 =
	    ((ICC_CTLR_NUM_PRI_BITS(read_icc_ctlr_el1()) >= 5) ? 1 : 0);

	/*
	 * Disable all SPIs.
	 */
	for (n = 32; n < gc->gc_maxsources; n += 32)
		gicd_write4(gc, GICD_ICENABLERn(n >> 5), 0xFFFFFFFF);
	gicd_drain_writes(gc);

	/*
	 * Move all SPIs to non-secure group 1.
	 */
	for (n = 32; n < gc->gc_maxsources; n += 32) {
		gicd_write4(gc, GICD_IGROUPRn(n >> 5), 0xFFFFFFFF);
		gicd_write4(gc, GICD_IGRPMODRn(n >> 5), 0x0);
	}

	/*
	 * Drop all SPIs to the lowest priority.
	 */
	for (n = 32; n < gc->gc_maxsources; n += 4)
		gicd_write4(gc, GICD_IPRIORITYRn(n >> 2), 0xFFFFFFFF);

	/*
	 * Make all SPIs level-sensitive.
	 */
	for (n = 32; n < gc->gc_maxsources; n += 16)
		gicd_write4(gc, GICD_ICFGRn(n >> 4), 0x0);

	/*
	 * Enable the distributor.
	 */
	(void) gicd_rmw4(gc, GICD_CTLR, GICD_CTLR_RWP,
	    GICD_CTLR_EnableGrp1A);

	/*
	 * Done touching the distributor.
	 */
	GICD_UNLOCK(gc);

	/*
	 * No CPUs have been configured yet.
	 */
	CPUSET_ZERO(gc->gc_cpuset);

	/*
	 * Initialize the boot processor.
	 */
	gicv3_cpu_init_raw(gc, CPU);
	return (DDI_SUCCESS);
}

static int
gicv3_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	int nregs;
	int instance;
	int i;
	int j;
	uint32_t num_redist_regions;
	gicv3_conf_t *gc;

	ddi_device_acc_attr_t gicv3_reg_acc_attr = {
		.devacc_attr_version		= DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder		= DDI_STRICTORDER_ACC
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

	if (gicv3_enable_system_register_access() != 0) {
		dev_err(dip, CE_PANIC, "Failed to enable the GIC system "
		    "register interface for the boot processor.");
	}

	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_INTERRUPT_CONTROLLER)) {
		dev_err(dip, CE_PANIC, "GICv3 must have the %s property.",
		    OBP_INTERRUPT_CONTROLLER);
	}

	if ((ret = ddi_dev_nregs(dip, &nregs)) != DDI_SUCCESS)
		return (ret);

	/* need at least a distributor and redistributor */
	if (nregs < 2)
		return (DDI_FAILURE);

	if ((ret = ddi_soft_state_zalloc(
	    gicv3_soft_state, instance)) != DDI_SUCCESS)
		return (ret);
	gc = ddi_get_soft_state(gicv3_soft_state, instance);
	VERIFY3P(gc, !=, NULL);

	if ((ret = ddi_regs_map_setup(dip, 0, &gc->gc_gicd, 0, 0,
	    &gicv3_reg_acc_attr, &gc->gc_gicd_regh)) != DDI_SUCCESS) {
		ddi_soft_state_free(gicv3_soft_state, instance);
		return (ret);
	}

	gc->gc_redist_stride =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "redistributor-stride", 0);

	num_redist_regions = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dip, 0, "#redistributor-regions", 1);

	gc->gc_redist_regions = kmem_zalloc(
	    sizeof (gicv3_redist_region_t) * num_redist_regions, KM_SLEEP);
	gc->gc_num_redist_regions = num_redist_regions;

	for (i = 0; i < gc->gc_num_redist_regions; ++i) {
		if ((ret = ddi_regs_map_setup(dip, 1 + i,
		    &gc->gc_redist_regions[i].base, 0, 0, &gicv3_reg_acc_attr,
		    &gc->gc_redist_regions[i].hdl)) != DDI_SUCCESS) {
			for (j = 0; j < i; ++j)
				ddi_regs_map_free(
				    &gc->gc_redist_regions[j].hdl);
			kmem_free(gc->gc_redist_regions,
			    sizeof (gicv3_redist_region_t) *
			    gc->gc_num_redist_regions);
			ddi_regs_map_free(&gc->gc_gicd_regh);
			ddi_soft_state_free(gicv3_soft_state, instance);
			return (ret);
		}

		gc->gc_redist_regions[i].size =
		    (uint64_t)i_ddi_pd_getreg(dip, 1 + i)->regspec_size;
	}

	if ((ret = gicv3_init(dip, gc)) != DDI_SUCCESS) {
		if (gc->gc_num_redist && gc->gc_redist)
			kmem_free(gc->gc_redist,
			    sizeof (gicv3_redistributor_t) * gc->gc_num_redist);
		for (i = 0; i < gc->gc_num_redist_regions; ++i)
			ddi_regs_map_free(&gc->gc_redist_regions[i].hdl);
		kmem_free(gc->gc_redist_regions,
		    sizeof (gicv3_redist_region_t) *
		    gc->gc_num_redist_regions);
		ddi_regs_map_free(&gc->gc_gicd_regh);
		ddi_soft_state_free(gicv3_soft_state, instance);
		return (ret);
	}

	gc->gc_syspic.spo_cpu_init = gicv3_cpu_init;
	gc->gc_syspic.spo_intr_enter = gicv3_intr_enter;
	gc->gc_syspic.spo_intr_exit = gicv3_intr_exit;
	gc->gc_syspic.spo_iack = gicv3_acknowledge;
	gc->gc_syspic.spo_cookie_to_intid = gicv3_ack_to_vector;
	gc->gc_syspic.spo_is_spurious = gicv3_is_spurious;
	gc->gc_syspic.spo_eoi = gicv3_eoi;
	gc->gc_syspic.spo_deactivate = gicv3_deactivate;
	gc->gc_syspic.spo_send_ipi = gicv3_send_ipi;
	gc->gc_syspic.spo_addspl = gicv3_addspl;
	gc->gc_syspic.spo_delspl = gicv3_delspl;

	if (!syspic_register_syspic(gc, &gc->gc_syspic)) {
		dev_err(dip, CE_PANIC, "Failed to register GIC as the "
		    "system programmable interrupt controller.");
	}

	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
gicv3_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	/*
	 * It is in theory possible we could evacuate an interrupt controller,
	 * but there's no reason to try.
	 */
	return (DDI_FAILURE);
}

static int
gicv3_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	int ret;

	switch (ctlop) {
	case DDI_CTLOPS_INITCHILD:
		ret = impl_ddi_sunbus_initchild(arg);
		break;
	case DDI_CTLOPS_UNINITCHILD:
		impl_ddi_sunbus_removechild(arg);
		ret = DDI_SUCCESS;
		break;
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?%s%d at %s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ret = DDI_SUCCESS;
		break;
	default:
		ret = ddi_ctlops(dip, rdip, ctlop, arg, result);
		break;
	}

	return (ret);
}

/*
 * Field interrupt operation requests to program this interrupt controller.
 *
 * We only handle the subset of requests that are routed toward an interrupt
 * controller by the system.
 *
 * Operations not intended for us should have been routed away from us and to
 * the root nexus by the DDI implementation.
 */
static int
gicv3_intr_ops(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	switch (intr_op) {
	case DDI_INTROP_ADDISR:
		break;
	case DDI_INTROP_REMISR:
		break;

	case DDI_INTROP_ENABLE: {
		ihdl_plat_t *priv = hdlp->ih_private;
		gicv3_conf_t *gc =
		    ddi_get_soft_state(gicv3_soft_state, ddi_get_instance(dip));
		syspic_intr_state_t *state = NULL;

		VERIFY3P(priv, !=, NULL);
		VERIFY3P(priv->ip_unitintr, !=, NULL);
		VERIFY3P(gc, !=, NULL);

		/*
		 * Always 3+ interrupt cells in the gicv3 binding (but this is
		 * FDT specific, and needs to be better)
		 */
		unit_intr_t *ui = priv->ip_unitintr;
		uint32_t *p = &ui->ui_v[ui->ui_addrcells];
		const uint32_t cfg = *p++;
		const uint32_t vector = *p++;
		const uint32_t sense = *p++;

		for (int i = 3; i < priv->ip_unitintr->ui_intrcells; i++) {
			ASSERT3U(*p++, ==, 0);
		}

		hdlp->ih_vector = GIC_FDT_VEC_TO_IRQ(cfg, vector);

		state = syspic_get_state(hdlp->ih_vector);
		VERIFY3P(state, !=, NULL);

		/*
		 * bits[3:0] trigger type and level flags:
		 * - 1 = edge triggered
		 * - 4 = level-sensitive
		 */
		state->si_edge_triggered =
		    ((sense & 0xff) == 1) ? B_TRUE : B_FALSE;
		gicv3_config_irq(gc, hdlp->ih_vector, state->si_edge_triggered);
		state->si_prio = hdlp->ih_pri;

		/* Add the interrupt handler */
		if (!add_avintr((void *)hdlp, hdlp->ih_pri,
		    hdlp->ih_cb_func, DEVI(rdip)->devi_name, hdlp->ih_vector,
		    hdlp->ih_cb_arg1, hdlp->ih_cb_arg2, NULL, rdip)) {
			mutex_exit(&syspic_intrs_lock);
			return (DDI_FAILURE);
		}

		mutex_exit(&syspic_intrs_lock);
		break;
	}
	case DDI_INTROP_DISABLE: {
		ihdl_plat_t *priv = hdlp->ih_private;

		VERIFY3P(priv, !=, NULL);
		VERIFY3P(priv->ip_unitintr, !=, NULL);

		/*
		 * Always 3+ interrupt cells in the gicv3 binding (but this is
		 * FDT specific, and needs to be better).
		 *
		 * Here we don't use the sense, we asserted in the enable path
		 * that any fields present but not understood are 0.
		 */
		unit_intr_t *ui = priv->ip_unitintr;
		uint32_t *p = &ui->ui_v[ui->ui_addrcells];
		const uint32_t cfg = *p++;
		const uint32_t vector = *p++;

		hdlp->ih_vector = GIC_FDT_VEC_TO_IRQ(cfg, vector);

		/* Remove the interrupt handler */
		rem_avintr((void *)hdlp, hdlp->ih_pri,
		    hdlp->ih_cb_func, hdlp->ih_vector);
		break;
	}

	/* Operations that are valid for us, but unimplemented */
	case DDI_INTROP_BLOCKDISABLE:
	case DDI_INTROP_BLOCKENABLE:
		return (DDI_FAILURE);

	/* Operations which should never have reached us */
	case DDI_INTROP_ALLOC:
	case DDI_INTROP_CLRMASK:
	case DDI_INTROP_DUPVEC:
	case DDI_INTROP_FREE:
	case DDI_INTROP_GETCAP:
	case DDI_INTROP_GETPENDING:
	case DDI_INTROP_GETPOOL:
	case DDI_INTROP_GETPRI:
	case DDI_INTROP_GETTARGET:
	case DDI_INTROP_NAVAIL:
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_SETCAP:
	case DDI_INTROP_SETMASK:
	case DDI_INTROP_SETPRI:
	case DDI_INTROP_SETTARGET:
	case DDI_INTROP_SUPPORTED_TYPES:
		dev_err(dip, CE_WARN, "unexpected introp %d for %s%d\n",
		    intr_op, ddi_node_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static struct bus_ops gicv3_bus_ops = {
	.busops_rev = BUSO_REV,
	.bus_map = i_ddi_bus_map,
	.bus_map_fault = i_ddi_map_fault,
	.bus_dma_map = ddi_no_dma_map,
	.bus_dma_allochdl = ddi_no_dma_allochdl,
	.bus_ctl = gicv3_bus_ctl,
	.bus_intr_op = gicv3_intr_ops,
};

static struct modlmisc modlmisc = {
	&mod_miscops,
	"Generic Interrupt Controller v3 (misc)"
};

static struct dev_ops gicv3_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = NULL,
	.devo_identify = nulldev,
	.devo_attach = gicv3_attach,
	.devo_detach = gicv3_detach,
	.devo_reset = nulldev,
	.devo_cb_ops = NULL,
	.devo_bus_ops = &gicv3_bus_ops,
	.devo_power = nulldev,
	.devo_quiesce = ddi_quiesce_not_supported,
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Generic Interrupt Controller v3 (device)",
	&gicv3_ops,
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &modlmisc, &modldrv, NULL }
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&gicv3_soft_state,
	    sizeof (gicv3_conf_t), 1)) != 0)
		return (err);

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&gicv3_soft_state);
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

	ddi_soft_state_fini(&gicv3_soft_state);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
