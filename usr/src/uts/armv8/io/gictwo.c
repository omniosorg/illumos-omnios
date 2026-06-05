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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * Arm Generic Interrupt Controller v2 Implementation
 *
 * See: IHI0048 ARM® Generic Interrupt Controller Architecture version 2.0.
 *
 * GICv2 supports up to 8 processing elements and the basic SGI, PPI and SPI
 * space, resulting in the following INTID space:
 *    0 -    7: SGI for the non-secure world
 *    8 -   15: SGI for the secure world
 *   16 -   31: PPI
 *   32 - 1019: SPI
 * 1020 - 1023: Special
 *
 * GICv2 does not support affinity routing. Our GICv2 code assumes we're
 * in the normal world, running on a GIC that implements two security states.
 * This is a somewhat safe assumption, as the inetboot (boot shim) common code
 * simply spins if entered in EL3, and we only support A profile cores.
 *
 * A note on priorities.
 *
 * A GICv2 implementation supports at least 16 (0-15) levels of priority.
 * However, only those priorities in the top-half can apply to the normal
 * world (this allows EL1-S to preempt EL1). In reality, this means that on
 * GIC implementations like that found on the Raspberry Pi4 we end up with
 * only eight usable priority mask values.
 *
 * If we find ourselves on such a GIC we use a few bits of sub-priority to
 * order (but not preempt) interrupt delivery. This is safe, but not optimal.
 * If we're on a GIC with a sufficient number of NS priority levels we simply
 * map those to our IPLs.
 *
 * This bodge is local to the GICv2 implementation, as GICv3+ must implement
 * a minimum of 32 priority levels when the implementation supports two
 * security states, which perfectly meets our requirements.
 *
 * Lock ordering
 * =============
 *   gc_lock (GICV2_GICD_LOCK, spinlock + interrupts-disabled)
 *     Protects all GICD register access, including read-only registers,
 *     to maintain the invariant that at most one CPU touches the
 *     distributor at a time.
 *
 *
 *   gc_msi_lock (mutex, blockable - never held with gc_lock)
 *   ih_rwlock --> syspic_intrs_lock --> gc_lock --> av_lock
 *
 *   gc_msi_lock is independent of all the above (no nesting).  It is
 *   only acquired from blockable context (intr_ops, attach, detach)
 *   and must never be held when acquiring gc_lock.
 */

#include <sys/types.h>
#include <sys/stddef.h>
#include <sys/syspic.h>
#include <sys/syspic_impl.h>
#include <sys/gic.h>
#include <sys/gic_reg.h>
#include <sys/avintr.h>
#include <sys/smp_impldefs.h>
#include <sys/sunddi.h>
#include <sys/ddi_subrdefs.h>
#include <sys/archsystm.h>
#include <sys/list.h>
#include <sys/mach_intr.h>

/*
 * MSI SPI range - registered by child MSI controllers (v2m) so the
 * parent can reject direct GETTARGET/SETTARGET for those INTIDs.
 */
typedef struct gicv2_msi_range {
	list_node_t	mr_node;
	uint32_t	mr_base;	/* first SPI in range */
	uint32_t	mr_count;	/* number of SPIs */
} gicv2_msi_range_t;

typedef struct {
	/* Base address and access handle for the CPU interface */
	caddr_t			gc_gicc;
	ddi_acc_handle_t	gc_gicc_regh;
	/* Base address and access handle for the distributor */
	caddr_t			gc_gicd;
	ddi_acc_handle_t	gc_gicd_regh;
	/*
	 * Desired binary point value to support the priority scheme
	 */
	uint32_t		gc_bpr;
	/*
	 * PPI interrupt config for secondary CPUs.
	 */
	uint32_t		gc_icfgr1;
	/*
	 * Shadow copy of GICD_ISENABLER[0] used in initialization of
	 * secondary CPUs (PPI-only);
	 */
	uint32_t		gc_enabled_local;
	/*
	 * Shadow copy of  GICD_IPRIORITYR<0-7> used in initialization of
	 * secondary CPUs.
	 */
	uint32_t		gc_priority[8];
	/*
	 * Protect access to global GIC state.
	 * In the current implementation, the distributor.
	 */
	lock_t			gc_lock;
	/*
	 * Mapping from cpuid to GIC target identifier
	 */
	uint8_t			gc_target[8];
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

	/*
	 * MSI SPI ranges registered by child MSI controllers.
	 * Protected by gc_msi_lock.
	 */
	kmutex_t		gc_msi_lock;
	list_t			gc_msi_ranges;
} gicv2_conf_t;

#define	TO_CONF(__c)		((gicv2_conf_t *)(__c))
static void			*gicv2_soft_state;

static uint32_t standard_priorities[] = {
	[0]	= 248,
	[1]	= 240,
	[2]	= 232,
	[3]	= 224,
	[4]	= 216,	/* Disk */
	[5]	= 208,
	[6]	= 200,
	[7]	= 192,	/* NIC */
	[8]	= 184,
	[9]	= 176,
	[10]	= 168,	/* Clock */
	[11]	= 160,	/* Dispatcher */
	[12]	= 152,
	[13]	= 144,
	[14]	= 136,
	[15]	= 128,
};

#define	STANDARD_PRIORITY_PMR_MASK	0x000000F8
/*
 * Configure the priority fields with the smallest possible sub-priority.
 *
 * In the standard configuration we don't use sub-priority at all.
 */
#define	STANDARD_BPR			0x00000000

/*
 * Required BPR is 3 bits
 */
static uint32_t bodged_priorities[] = {
	[0]	= 240,	/* Real */
	[1]	= 228,	/* Fake */
	[2]	= 226,	/* Fake */
	[3]	= 225,	/* Fake */
	[4]	= 224,	/* Real, Disk */
	[5]	= 209,	/* Fake */
	[6]	= 208,	/* Real */
	[7]	= 192,	/* Real, NIC */
	[8]	= 177,	/* Fake */
	[9]	= 176,	/* Real */
	[10]	= 160,	/* Real, Clock  */
	[11]	= 144,	/* Real, Dispatcher */
	[12]	= 132,	/* Fake */
	[13]	= 130,	/* Fake */
	[14]	= 129,	/* Fake */
	[15]	= 128,	/* Real */
};

#define	BODGED_PRIORITY_PMR_MASK	0x000000F0
/*
 * Configure the priority fields with 5 bits of group priority and 3 bits of
 * subpriority. This may not actually work, as the minimums may be lower,
 * but we do the best that we can.
 *
 * Even of the minimum is lower our priority mask remains valid, it's just
 * ordering that might be affected.
 */
#define	BODGED_BPR			0x00000002

/*
 * IPL -> GIC Priority table to use.
 */
static uint32_t *gicv2_prio_map;
/*
 * Mask to apply to the GIC priority when setting the priority mask register
 * on the GIC CPU Interface.
 *
 * Do not apply this mask when setting interrupt configuration.
 */
static uint32_t gicv2_prio_pmr_mask;

#undef GIC_IPL_TO_PRIO
#define	GIC_IPL_TO_PRIO(v)		(gicv2_prio_map[((v) & 0xF)])

#define	GICV2_GICD_LOCK_INIT_HELD(__sc)	uint64_t __s = disable_interrupts(); \
					LOCK_INIT_HELD(&(__sc)->gc_lock)
#define	GICV2_GICD_LOCK(__sc)		uint64_t __s = disable_interrupts(); \
					lock_set(&(__sc)->gc_lock)
#define	GICV2_GICD_UNLOCK(__sc)		lock_clear(&(__sc)->gc_lock); \
					restore_interrupts(__s)
#define	GICV2_ASSERT_GICD_LOCK_HELD(__sc) \
					ASSERT(LOCK_HELD(&(__sc)->gc_lock))

static inline uint32_t
gicc_read(gicv2_conf_t *sc, uint32_t reg)
{
	return (ddi_get32(sc->gc_gicc_regh, (uint32_t *)(sc->gc_gicc + reg)));
}

static inline void
gicc_write(gicv2_conf_t *sc, uint32_t reg, uint32_t val)
{
	ddi_put32(sc->gc_gicc_regh, (uint32_t *)(sc->gc_gicc + reg), val);
}

static inline uint32_t
gicd_read(gicv2_conf_t *sc, uint32_t reg)
{
	return (ddi_get32(sc->gc_gicd_regh, (uint32_t *)(sc->gc_gicd + reg)));
}

static inline void
gicd_write(gicv2_conf_t *sc, uint32_t reg, uint32_t val)
{
	ddi_put32(sc->gc_gicd_regh, (uint32_t *)(sc->gc_gicd + reg), val);
}

static inline uint32_t
gicd_rmw(gicv2_conf_t *sc, uint32_t reg, uint32_t clrbits, uint32_t setbits)
{
	uint32_t val;
	uint32_t *regaddr = (uint32_t *)(sc->gc_gicd + reg);

	val = (ddi_get32(sc->gc_gicd_regh, regaddr) & (~clrbits)) | setbits;
	ddi_put32(sc->gc_gicd_regh, regaddr, val);
	return (val);
}

/*
 * Enable IRQ in the distributor, which will now be forwarded to a cpu.
 *
 * 4.3.5 Interrupt Set-Enable Registers, GICD_ISENABLERn (Usage constraints):
 *   Whether implemented SGIs are permanently enabled, or can be enabled and
 *   disabled by writes to GICD_ISENABLER0 and GICD_ICENABLER0, is
 *   IMPLEMENTATION DEFINED.
 *
 * We never try to configure SGIs.
 */
static void
gicv2_enable_irq(gicv2_conf_t *sc, int irq)
{
	if (GIC_INTID_IS_SPI(irq) || GIC_INTID_IS_PPI(irq)) {
		GICV2_ASSERT_GICD_LOCK_HELD(sc);
		gicd_write(sc, GICD_ISENABLERn(GICD_IENABLER_REGNUM(irq)),
		    GICD_IENABLER_REGBIT(irq));
	}
}

/*
 * Disable IRQ in the distributor, which will now cease being forwarded to a
 * cpu.
 *
 * 4.3.5 Interrupt Clear-Enable Registers, GICD_ICENABLERn (Usage constraints):
 *   Whether implemented SGIs are permanently enabled, or can be enabled and
 *   disabled by writes to GICD_ISENABLER0 and GICD_ICENABLER0, is
 *   IMPLEMENTATION DEFINED.
 *
 * We never try to configure SGIs.
 */
static void
gicv2_disable_irq(gicv2_conf_t *sc, int irq)
{
	if (GIC_INTID_IS_SPI(irq) || GIC_INTID_IS_PPI(irq)) {
		GICV2_ASSERT_GICD_LOCK_HELD(sc);
		gicd_write(sc, GICD_ICENABLERn(GICD_IENABLER_REGNUM(irq)),
		    GICD_IENABLER_REGBIT(irq));
	}
}

/*
 * Configure whether IRQ is edge or level triggered.
 */
static void
gicv2_config_irq(gicv2_conf_t *sc, uint32_t irq, boolean_t is_edge)
{
	uint32_t v = (is_edge ?
	    GICD_ICFGR_INT_CONFIG_EDGE : GICD_ICFGR_INT_CONFIG_LEVEL);

	/*
	 * SGIs are not configurable.
	 */
	if (GIC_INTID_IS_SGI(irq))
		return;

	GICV2_GICD_LOCK(sc);

	/*
	 * §8.9.7 Software must disable an interrupt before the value of the
	 * corresponding programmable Int_config field is changed. GIC
	 * behavior is otherwise UNPREDICTABLE.
	 */
	if ((gicd_read(sc, GICD_ISENABLERn(GICD_IENABLER_REGNUM(irq))) &
	    GICD_IENABLER_REGBIT(irq)) != 0) {
		if (gicd_read(sc, GICD_ICFGRn(GICD_ICFGR_REGNUM(irq))) !=
		    GICD_ICFGR_REGVAL(irq, v)) {
			cmn_err(CE_WARN, "gictwo: vector %d already "
			    "configured differently", irq);
			goto unlock;
		}
	} else {
		/*
		 * GICD_ICFGR<n> is a packed field with 2 bits per interrupt,
		 * the even bit is reserved, the odd bit is 1 for
		 * edge-triggered 0 for level.
		 */
		(void) gicd_rmw(sc,
		    GICD_ICFGRn(GICD_ICFGR_REGNUM(irq)),
		    GICD_ICFGR_REGVAL(irq, GICD_ICFGR_INT_CONFIG_MASK),
		    GICD_ICFGR_REGVAL(irq, v));
	}

unlock:
	GICV2_GICD_UNLOCK(sc);
}

/*
 * Configure an SPI as edge-triggered or level-sensitive.
 *
 * This is a private interface, for use by GICv2m in setting edge-triggered
 * mode for MSI SPIs.
 */
void
gicv2_configure_irq(dev_info_t *gic_dip, uint32_t irq, boolean_t is_edge)
{
	gicv2_conf_t *sc = ddi_get_soft_state(gicv2_soft_state,
	    ddi_get_instance(gic_dip));
	VERIFY3P(sc, !=, NULL);
	ASSERT(GIC_INTID_IS_ANY_SPI(irq));
	gicv2_config_irq(sc, irq, is_edge);
}

/*
 * Return the pending state of an interrupt from the distributor's ISPENDR
 * register.  For SGIs and PPIs (INTIDs 0-31) the register is banked per-CPU
 * on GICv2, so the result reflects the calling CPU's view.  For SPIs
 * (INTIDs 32+) the register is shared.
 *
 * This is inherently racy: the pending bit can change at any instant.
 * The result is a best-effort snapshot for diagnostic use.
 */
boolean_t
gicv2_irq_ispending(dev_info_t *gic_dip, uint32_t irq)
{
	uint32_t val;
	gicv2_conf_t *sc = ddi_get_soft_state(gicv2_soft_state,
	    ddi_get_instance(gic_dip));

	VERIFY3P(sc, !=, NULL);
	ASSERT(GIC_INTID_IS_SGI(irq) || GIC_INTID_IS_PPI(irq) ||
	    GIC_INTID_IS_SPI(irq));

	GICV2_GICD_LOCK(sc);
	val = gicd_read(sc, GICD_ISPENDRn(GICD_IPENDR_REGNUM(irq)));
	GICV2_GICD_UNLOCK(sc);
	return ((val & GICD_IPENDR_REGBIT(irq)) != 0);
}

/*
 * Check whether an INTID falls within a registered MSI SPI range.
 * Caller must hold gc_msi_lock.
 */
static boolean_t
gicv2_is_msi_spi(gicv2_conf_t *sc, uint32_t intid)
{
	gicv2_msi_range_t *mr;

	ASSERT(MUTEX_HELD(&sc->gc_msi_lock));

	for (mr = list_head(&sc->gc_msi_ranges); mr != NULL;
	    mr = list_next(&sc->gc_msi_ranges, mr)) {
		if (intid >= mr->mr_base &&
		    intid < mr->mr_base + mr->mr_count) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Register an MSI SPI range owned by a child driver (v2m).
 * Called from child attach.
 */
void
gicv2_register_msi_range(dev_info_t *gic_dip, uint32_t base, uint32_t count)
{
	gicv2_conf_t *sc = ddi_get_soft_state(gicv2_soft_state,
	    ddi_get_instance(gic_dip));
	gicv2_msi_range_t *mr;

	VERIFY3P(sc, !=, NULL);

	mr = kmem_alloc(sizeof (*mr), KM_SLEEP);
	mr->mr_base = base;
	mr->mr_count = count;

	mutex_enter(&sc->gc_msi_lock);
	list_insert_tail(&sc->gc_msi_ranges, mr);
	mutex_exit(&sc->gc_msi_lock);
}

/*
 * Unregister an MSI SPI range.  Called from child detach.
 */
void
gicv2_unregister_msi_range(dev_info_t *gic_dip, uint32_t base, uint32_t count)
{
	gicv2_conf_t *sc = ddi_get_soft_state(gicv2_soft_state,
	    ddi_get_instance(gic_dip));
	gicv2_msi_range_t *mr;

	VERIFY3P(sc, !=, NULL);

	mutex_enter(&sc->gc_msi_lock);
	for (mr = list_head(&sc->gc_msi_ranges); mr != NULL;
	    mr = list_next(&sc->gc_msi_ranges, mr)) {
		if (mr->mr_base == base && mr->mr_count == count) {
			list_remove(&sc->gc_msi_ranges, mr);
			mutex_exit(&sc->gc_msi_lock);
			kmem_free(mr, sizeof (*mr));
			return;
		}
	}
	mutex_exit(&sc->gc_msi_lock);
	panic("gicv2_unregister_msi_range: range %u+%u not found", base,
	    count);
}

/*
 * Return the CPU targeted by GICD_ITARGETSRn for an SPI.
 *
 * The ITARGETS field is a bitmask of target CPUs; we return the
 * lowest-numbered one.  Acquires and releases GICD lock internally.
 */
processorid_t
gicv2_get_target_spi(dev_info_t *gic_dip, uint32_t intid)
{
	gicv2_conf_t *sc = ddi_get_soft_state(gicv2_soft_state,
	    ddi_get_instance(gic_dip));
	uint32_t reg;
	uint8_t targets;

	VERIFY3P(sc, !=, NULL);
	ASSERT(GIC_INTID_IS_SPI(intid));

	GICV2_GICD_LOCK(sc);
	reg = gicd_read(sc, GICD_ITARGETSRn(GICD_ITARGETSR_REGNUM(intid)));
	GICV2_GICD_UNLOCK(sc);

	targets = GICD_ITARGETSR_GETTARGETS(reg, intid);

	if (targets == 0) {
		return (0);
	}

	/* Return lowest set bit (lowest-numbered targeted CPU) */
	return ((processorid_t)(lowbit(targets) - 1));
}

/*
 * Reprogram GICD_ITARGETSRn to target a single CPU for an SPI.
 * Acquires and releases GICD lock internally.
 */
void
gicv2_set_target_spi(dev_info_t *gic_dip, uint32_t intid, processorid_t cpuid)
{
	gicv2_conf_t *sc = ddi_get_soft_state(gicv2_soft_state,
	    ddi_get_instance(gic_dip));

	VERIFY3P(sc, !=, NULL);
	ASSERT(GIC_INTID_IS_SPI(intid));
	ASSERT3U(cpuid, <, 8);

	GICV2_GICD_LOCK(sc);
	(void) gicd_rmw(sc,
	    GICD_ITARGETSRn(GICD_ITARGETSR_REGNUM(intid)),
	    GICD_ITARGETSR_REGVAL(intid, GICD_ITARGETSR_REGMASK),
	    GICD_ITARGETSR_REGVAL(intid, (1u << cpuid)));
	GICV2_GICD_UNLOCK(sc);
}

/*
 * Mask interrupts of priority lower than or equal to IRQ.
 */
static int
gicv2_intr_enter(spo_ctx_t ctx, intr_intid_t intid)
{
	gicv2_conf_t *sc;
	int new_ipl = 0;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	if (av_get_vec_lvl(intid, &new_ipl) && new_ipl != 0) {
		gicc_write(sc, GICC_PMR,
		    GIC_IPL_TO_PRIO(new_ipl) & gicv2_prio_pmr_mask);
	}

	return (new_ipl);
}

/*
 * Mask interrupts of priority lower than or equal to IPL.
 */
static void
gicv2_intr_exit(spo_ctx_t ctx, intr_ipl_t ipl)
{
	gicv2_conf_t *sc;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	gicc_write(sc, GICC_PMR, GIC_IPL_TO_PRIO(ipl) & gicv2_prio_pmr_mask);
}

/*
 * Set the priority of IRQ to IPL
 * If IRQ is an SGI or PPI, shadow that priority into `ipriorityr_private`
 */
static void
gicv2_set_ipl(gicv2_conf_t *sc, uint32_t irq, uint32_t ipl)
{
	uint32_t ipriorityr;
	uint32_t n;

	GICV2_ASSERT_GICD_LOCK_HELD(sc);
	n = GICD_IPRIORITY_REGNUM(irq);
	ipriorityr = gicd_rmw(sc,
	    GICD_IPRIORITYRn(n),
	    GICD_IPRIORITY_REGVAL(irq, GICD_IPRIORITY_REGMASK),
	    GICD_IPRIORITY_REGVAL(irq, GIC_IPL_TO_PRIO(ipl)));

	if (GIC_INTID_IS_PERCPU(irq)) {
		sc->gc_priority[n] = ipriorityr;
	}
}

/*
 * Configure non-local IRQs to be delivered through the distributor.
 *
 * XXXARM: We need interrupt redistribution.
 */
static void
gicv2_add_target(gicv2_conf_t *sc, uint32_t irq)
{
	uint32_t coreMask = GICD_ITARGETSR_REGMASK; /* all 8 cpus */

	/*
	 * Each GICD_ITARGETSR<n> contains 4 8-bit fields indicating that int
	 * N is delivered to the cpus with 1 bits set in the value.
	 *
	 * We always program all interrupts to deliver to all possible CPUs,
	 * trusting RAZ/WI for those which don't exist.
	 */
	if (!GIC_INTID_IS_PERCPU(irq)) {
		GICV2_ASSERT_GICD_LOCK_HELD(sc);
		(void) gicd_rmw(sc,
		    GICD_ITARGETSRn(GICD_ITARGETSR_REGNUM(irq)),
		    GICD_ITARGETSR_REGVAL(irq, GICD_ITARGETSR_REGMASK),
		    GICD_ITARGETSR_REGVAL(irq, coreMask));
	}
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
 */
static int
gicv2_addspl(spo_ctx_t ctx, intr_intid_t intid, intr_ipl_t ipl,
    intr_ipl_t min_ipl __unused, intr_ipl_t max_ipl __unused)
{
	gicv2_conf_t *sc;
	syspic_intr_state_t *state = NULL;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	if (GIC_INTID_IS_SGI(intid)) {
		ASSERT(!MUTEX_HELD(&syspic_intrs_lock));
		state = syspic_get_state(intid);
		VERIFY3P(state, !=, NULL);
		state->si_edge_triggered = B_TRUE;
		state->si_prio = ipl;
	}

	ASSERT(MUTEX_HELD(&syspic_intrs_lock));

	GICV2_GICD_LOCK(sc);
	gicv2_set_ipl(sc, (uint32_t)intid, (uint32_t)ipl);
	gicv2_add_target(sc, (uint32_t)intid);
	gicv2_enable_irq(sc, (uint32_t)intid);
	if (GIC_INTID_IS_PPI(intid) && CPU->cpu_id == 0) {
		sc->gc_enabled_local |= (1U << intid);
	}
	GICV2_GICD_UNLOCK(sc);

	if (state != NULL) {
		mutex_exit(&syspic_intrs_lock);
	}

	return (0);
}

/*
 * Disable an interrupt and reset it's priority
 *
 * The generic GIC layer has taken care of checking if there are still
 * handlers, so this is really just deletion.
 */
static int
gicv2_delspl(spo_ctx_t ctx, intr_intid_t intid, intr_ipl_t ipl __unused,
    intr_ipl_t min_ipl __unused, intr_ipl_t max_ipl __unused)
{
	gicv2_conf_t *sc;
	int pri = -1;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	if (av_get_vec_lvl(intid, &pri) == 0 || pri == 0) {
		mutex_enter(&syspic_intrs_lock);
		syspic_remove_state(intid);

		GICV2_GICD_LOCK(sc);
		gicv2_disable_irq(sc, (uint32_t)intid);
		gicv2_set_ipl(sc, (uint32_t)intid, 0);
		if (GIC_INTID_IS_PPI(intid) && CPU->cpu_id == 0) {
			sc->gc_enabled_local &= ~(1U << intid);
		}
		GICV2_GICD_UNLOCK(sc);

		mutex_exit(&syspic_intrs_lock);
	}

	return (0);
}

/*
 * Send an IRQ as an IPI to processors in `cpuset`.
 *
 * Processors not targetable by the GIC will be silently ignored.
 */
static void
gicv2_send_ipi(spo_ctx_t ctx, cpuset_t cpuset, intr_intid_t intid)
{
	gicv2_conf_t *sc;
	uint32_t target = 0;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	GICV2_GICD_LOCK(sc);
	CPUSET_AND(cpuset, sc->gc_cpuset);
	while (!CPUSET_ISNULL(cpuset)) {
		uint_t cpu;
		CPUSET_FIND(cpuset, cpu);
		target |= sc->gc_target[cpu];
		CPUSET_DEL(cpuset, cpu);
	}
	dsb(ish);

	/* The third argument (NSATTR) is ignored from the non-secure world */
	gicd_write(sc, GICD_SGIR, GICD_MAKE_SGIR_REGVAL(0, target, 0, intid));
	GICV2_GICD_UNLOCK(sc);
}

static intr_cookie_t
gicv2_acknowledge(spo_ctx_t ctx)
{
	gicv2_conf_t *sc;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	return ((intr_cookie_t)gicc_read(sc, GICC_IAR));
}

static intr_intid_t
gicv2_ack_to_vector(spo_ctx_t ctx __unused, intr_cookie_t cookie)
{
	return ((intr_intid_t)(cookie & GICC_IAR_INTID_NO_ARE));
}

static boolean_t
gicv2_is_spurious(spo_ctx_t ctx __unused, intr_intid_t intid)
{
	if (GIC_INTID_IS_SPECIAL(intid))
		return (B_TRUE);

	return (B_FALSE);
}

static void
gicv2_eoi(spo_ctx_t ctx, intr_cookie_t cookie)
{
	gicv2_conf_t *sc;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	gicc_write(sc, GICC_EOIR, (uint32_t)(cookie & 0xFFFFFFFF));
}

static void
gicv2_deactivate(spo_ctx_t ctx, intr_cookie_t cookie)
{
	gicv2_conf_t *sc;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	gicc_write(sc, GICC_DIR, (uint32_t)(cookie & 0xFFFFFFFF));
}

/*
 * Return the target representing the current cpu from the GIC point of view
 * by reading the target field of a target specific interrupt.
 *
 * This sets the Nth bit for target N
 */
static uint_t
gicv2_get_target(gicv2_conf_t *sc)
{
	GICV2_ASSERT_GICD_LOCK_HELD(sc);
	return (1U << __builtin_ctz(
	    gicd_read(sc, GICD_ITARGETSRn(0)) & 0xFF));
}

/*
 * Private function used for initializing CPUs.
 *
 * The boot processor is initialized from the tail of the main gicv2_init
 * function, which calls this function with the distributor lock held.
 *
 * Secondary CPUs enter this function via gicv2_cpu_init, which manages the
 * distributor lock.
 */
static void
gicv2_cpu_init_raw(gicv2_conf_t *sc, cpu_t *cp)
{
	GICV2_ASSERT_GICD_LOCK_HELD(sc);

	/*
	 * Disable the current CPU interface.
	 */
	gicc_write(sc, GICC_CTLR, 0);

	/*
	 * Clear enabled/pending/active status of the CPU-specific interrupts.
	 *
	 * We'll restore the enabled state for secondary CPU PPIs below.
	 *
	 * Note that we do not attempt to disable SGIs, as that's an
	 * implementation-defined operation.
	 */
	gicd_write(sc, GICD_ICENABLERn(0), 0xffff0000);
	gicd_write(sc, GICD_ICPENDRn(0), 0xffffffff);
	gicd_write(sc, GICD_ICACTIVERn(0), 0xffffffff);

	/*
	 * When initialising the boot CPU we do a bit more.
	 */
	if (cp->cpu_id == 0) {
		/*
		 * Record that we've cleared the enabled state of PPIs.
		 *
		 * As we enable PPIs on the boot CPU they are recorded into
		 * this variable. We later use this information when booting
		 * secondary CPUs.
		 */
		sc->gc_enabled_local = 0x0;

		/*
		 * Figure out how to map IPLs to GIC priorities.
		 */
		gicc_write(sc, GICC_PMR, 0xFF);

		if ((gicc_read(sc, GICC_PMR) & 0xf) == 0) {
			gicv2_prio_map = bodged_priorities;
			gicv2_prio_pmr_mask = BODGED_PRIORITY_PMR_MASK;
			sc->gc_bpr = BODGED_BPR;
		} else {
			gicv2_prio_map = standard_priorities;
			gicv2_prio_pmr_mask = STANDARD_PRIORITY_PMR_MASK;
			sc->gc_bpr = STANDARD_BPR;
		}

		/*
		 * Initialize interrupt priorities for per-CPU interrupts,
		 * setting them to the lowest possible priority and keeping a
		 * private copy of their priorities for use in initializing
		 * other processors.
		 */
		for (int i = 0; i < 8; ++i) {
			gicd_write(sc, GICD_IPRIORITYRn(i), 0xffffffff);
			sc->gc_priority[i] =
			    gicd_read(sc, GICD_IPRIORITYRn(i));
		}
	} else {
		/*
		 * Set PPIs to the configuration we set for the boot processor.
		 *
		 * Configuring PPIs is implementation-defined, so this might
		 * have no effect.
		 */
		gicd_write(sc, GICD_ICFGRn(1), sc->gc_icfgr1);

		/*
		 * Initialize interrupt priorities for per-CPU interrupts from
		 * the shadow copy of the priority registers.
		 */
		for (int i = 0; i < 8; ++i) {
			gicd_write(sc, GICD_IPRIORITYRn(i),
			    sc->gc_priority[i]);
		}

		/*
		 * Update enable bits for PPIs.
		 *
		 * These reflect the state of PPI on the boot processor at the
		 * time the secondary CPU comes up. No further attempt at
		 * synchronization is made.
		 */
		gicd_write(sc, GICD_ISENABLERn(0), sc->gc_enabled_local);
	}

	/*
	 * Apply our subpriority configuration.
	 */
	gicc_write(sc, GICC_BPR, sc->gc_bpr);

	/*
	 * Confugure the priority mask register to leave us at LOCK_LEVEL once
	 * initialized.
	 */
	gicc_write(sc, GICC_PMR,
	    GIC_IPL_TO_PRIO(LOCK_LEVEL) & gicv2_prio_pmr_mask);

	/*
	 * Record our target for interrupt routing.
	 */
	sc->gc_target[cp->cpu_id] = gicv2_get_target(sc);

	/*
	 * Enable the CPU interface.
	 *
	 * Note that we enable split priority drop and deactivation so that we
	 * can properly support threaded intrerrupts.
	 */
	gicc_write(sc, GICC_CTLR,
	    GICC_CTLR_EnableGrp1 | GICC_CTLR_EOImodeNS);

	/*
	 * Finally, tell the world we're ready.
	 */
	CPUSET_ADD(sc->gc_cpuset, cp->cpu_id);
}

/*
 * Public function used for initializing secondary CPUs.
 *
 * Simply wraps the gicv2_cpu_init_raw call in shared state locks.
 */
static void
gicv2_cpu_init(spo_ctx_t ctx, cpu_t *cp)
{
	gicv2_conf_t *sc;

	sc = TO_CONF(ctx);
	ASSERT3P(sc, !=, NULL);

	GICV2_GICD_LOCK(sc);
	gicv2_cpu_init_raw(sc, cp);
	GICV2_GICD_UNLOCK(sc);
}

/*
 * Map GIC register space and perform global GIC initialization, including
 * disabling the CPU interface on the boot processor.
 *
 * Returns non-zero on error.
 */
static int
gicv2_init(gicv2_conf_t *sc)
{
	/*
	 * Mask all interrupts on the current CPU interface, then disable it.
	 *
	 * This is the last time we should touch the GIC CPU interface in this
	 * function.
	 */
	gicc_write(sc, GICC_CTLR, 0);

	/*
	 * Disable the distributor.
	 */
	gicd_write(sc, GICD_CTLR, 0);

	/*
	 * Clear enabled/pending/active status of global interrupts.
	 */
	for (int i = 1; i < 32; ++i) {
		gicd_write(sc, GICD_ICENABLERn(i), 0xffffffff);
		gicd_write(sc, GICD_ICPENDRn(i), 0xffffffff);
		gicd_write(sc, GICD_ICACTIVERn(i), 0xffffffff);
	}

	/*
	 * Make all hardware interrupts level triggered.
	 *
	 * GICD_ICFGRn(0) is SGI, and we can't configure those.
	 * GICD_ICFGRn(1) is PPI, configuring these is implementation-defined.
	 */
	for (int i = 1; i < 64; i++) {
		gicd_write(sc, GICD_ICFGRn(i), 0x0);
	}

	/*
	 * Save PPI interrupt configuration so we can apply it to secondary
	 * CPUs. Configuring PPIs is implementation-defined, but we try anyway.
	 */
	sc->gc_icfgr1 = gicd_read(sc, GICD_ICFGRn(1));

	/*
	 * Initialize interrupt priorities for global interrupts, setting them
	 * to the lowest possible priority and routing them to all possible
	 * CPUs. XXXARM: we need to implement interrupt redistribution.
	 */
	for (int i = 8; i < 256; ++i) {
		gicd_write(sc, GICD_IPRIORITYRn(i), 0xffffffff);
		gicd_write(sc, GICD_ITARGETSRn(i), 0xffffffff);
	}

	/*
	 * No CPUs have been configured yet.
	 */
	CPUSET_ZERO(sc->gc_cpuset);

	/*
	 * Enable the distributor.
	 */
	gicd_write(sc, GICD_CTLR, GICD_CTLR_EnableGrp1);

	/*
	 * While we still hold the lock we initialize the boot processor.
	 */
	gicv2_cpu_init_raw(sc, CPU);
	return (DDI_SUCCESS);
}

static int
gicv2_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	int nregs;
	int instance;
	gicv2_conf_t *xconf;

	ddi_device_acc_attr_t gicv2_reg_acc_attr = {
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

	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_INTERRUPT_CONTROLLER)) {
		dev_err(dip, CE_PANIC, "GICv2 must have the %s property.",
		    OBP_INTERRUPT_CONTROLLER);
	}

	if ((ret = ddi_dev_nregs(dip, &nregs)) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if (nregs < 2)
		return (DDI_FAILURE);

	if ((ret = ddi_soft_state_zalloc(gicv2_soft_state,
	    instance)) != DDI_SUCCESS)
		return (ret);
	xconf = ddi_get_soft_state(gicv2_soft_state, instance);
	VERIFY3P(xconf, !=, NULL);

	if ((ret = ddi_regs_map_setup(dip, 0, &xconf->gc_gicd, 0, 0,
	    &gicv2_reg_acc_attr, &xconf->gc_gicd_regh)) != DDI_SUCCESS) {
		ddi_soft_state_free(gicv2_soft_state, instance);
		return (ret);
	}

	if ((ret = ddi_regs_map_setup(dip, 1, &xconf->gc_gicc, 0, 0,
	    &gicv2_reg_acc_attr, &xconf->gc_gicc_regh)) != DDI_SUCCESS) {
		ddi_regs_map_free(&xconf->gc_gicd_regh);
		ddi_soft_state_free(gicv2_soft_state, instance);
		return (ret);
	}

	GICV2_GICD_LOCK_INIT_HELD(xconf);

	mutex_init(&xconf->gc_msi_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&xconf->gc_msi_ranges, sizeof (gicv2_msi_range_t),
	    offsetof(gicv2_msi_range_t, mr_node));
	if ((ret = gicv2_init(xconf)) != DDI_SUCCESS) {
		GICV2_GICD_UNLOCK(xconf);
		ddi_regs_map_free(&xconf->gc_gicc_regh);
		ddi_regs_map_free(&xconf->gc_gicd_regh);
		ddi_soft_state_free(gicv2_soft_state, instance);
		return (ret);
	}

	GICV2_GICD_UNLOCK(xconf);

	xconf->gc_syspic.spo_cpu_init = gicv2_cpu_init;
	xconf->gc_syspic.spo_intr_enter = gicv2_intr_enter;
	xconf->gc_syspic.spo_intr_exit = gicv2_intr_exit;
	xconf->gc_syspic.spo_iack = gicv2_acknowledge;
	xconf->gc_syspic.spo_cookie_to_intid = gicv2_ack_to_vector;
	xconf->gc_syspic.spo_is_spurious = gicv2_is_spurious;
	xconf->gc_syspic.spo_eoi = gicv2_eoi;
	xconf->gc_syspic.spo_deactivate = gicv2_deactivate;
	xconf->gc_syspic.spo_send_ipi = gicv2_send_ipi;
	xconf->gc_syspic.spo_addspl = gicv2_addspl;
	xconf->gc_syspic.spo_delspl = gicv2_delspl;

	if (!syspic_register_syspic(xconf, &xconf->gc_syspic, dip)) {
		dev_err(dip, CE_PANIC, "Failed to register GIC as the "
		    "system programmable interrupt controller.");
	}

	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
gicv2_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	/*
	 * It is in theory possible we could evacuate an interrupt controller,
	 * but there's no reason to try.
	 */
	return (DDI_FAILURE);
}

static int
gicv2_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
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

static int
gicv2_parse_unitintr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, uint32_t *pcfg, uint32_t *pvector,
    uint32_t *psense, uint32_t *pintid)
{
	ihdl_plat_t *priv;
	unit_intr_t *ui;
	uint32_t *p;

	if ((priv = hdlp->ih_private) == NULL) {
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_parse_unitintr: "
		    "for rdip = 0x%p (%s%d), hdlp = 0x%p, inum = 0x%x: "
		    "no ihdl_plat\n",
		    rdip, ddi_node_name(rdip), ddi_get_instance(rdip),
		    hdlp, hdlp->ih_inum));
		return (DDI_FAILURE);
	}

	if ((ui = priv->ip_unitintr) == NULL) {
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_parse_unitintr: "
		    "for rdip = 0x%p (%s%d), hdlp = 0x%p, inum = 0x%x: "
		    "no unitintr\n",
		    rdip, ddi_node_name(rdip), ddi_get_instance(rdip),
		    hdlp, hdlp->ih_inum));
		return (DDI_FAILURE);
	}

	/*
	 * Always 3 interrupt cells in the gicv2 binding.
	 */
	p = &ui->ui_v[ui->ui_addrcells];
	*pcfg = *p++;
	*pvector = *p++;
	*psense = *p++;

	*pintid = GIC_FDT_VEC_TO_IRQ(*pcfg, *pvector);
	return (DDI_SUCCESS);
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
gicv2_intr_ops(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	uint32_t cfg;
	uint32_t vector;
	uint32_t sense;
	uint32_t intid;

	ASSERT(RW_WRITE_HELD(&hdlp->ih_rwlock));

	DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: "
	    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x, op 0x%x\n",
	    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum, intr_op));

	switch (intr_op) {
	case DDI_INTROP_NINTRS:		/* fallthrough */
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: op 0x%x "
		    "for rdip = 0x%p is 0x%x\n",
		    intr_op, rdip, *(int *)result));
		break;

	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: ALLOC "
		    "for rdip = 0x%p, inum = 0x%x, result is 0x%x for 0x%x\n",
		    rdip, hdlp->ih_inum, *(int *)result, hdlp->ih_scratch1));
		break;

	case DDI_INTROP_FREE:
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: FREE "
		    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x\n",
		    rdip, hdlp, hdlp->ih_inum));
		break;

	case DDI_INTROP_GETPRI: {
		int shared;
		uint_t curpri;

		if (gicv2_parse_unitintr(dip, rdip, hdlp,
		    &cfg, &vector, &sense, &intid) != DDI_SUCCESS) {
			DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: GETPRI "
			    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x: "
			    "gicv2_parse_unitintr failed\n",
			    rdip, hdlp, hdlp->ih_inum));
			return (DDI_FAILURE);
		}

		shared = av_get_shared(intid, &curpri);
		if (shared > 0) {
			hdlp->ih_pri = curpri;
		} else if (hdlp->ih_pri == 0) {
			hdlp->ih_pri = i_ddi_get_intr_pri(rdip, hdlp->ih_inum);
		}

		ASSERT3U(hdlp->ih_pri, !=, 0);
		*(int *)result = hdlp->ih_pri;
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: GETPRI "
		    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x, "
		    "shared = %d, result = 0x%x\n",
		    rdip, hdlp, hdlp->ih_inum, shared, *(int *)result));
		break;
	}

	case DDI_INTROP_SETPRI: {
		int shared;
		uint_t curpri;
		uint_t newpri;

		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: SETPRI "
		    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x, is 0x%x\n",
		    rdip, hdlp, hdlp->ih_inum, *(int *)result));
		if (*(int *)result > LOCK_LEVEL) {
			DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: SETPRI "
			    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x: "
			    "new pri %d exceed LOCK_LEVEL %d\n",
			    rdip, hdlp, hdlp->ih_inum,
			    *(int *)result, LOCK_LEVEL));
			return (DDI_FAILURE);
		}

		if (gicv2_parse_unitintr(dip, rdip, hdlp,
		    &cfg, &vector, &sense, &intid) != DDI_SUCCESS) {
			DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: SETPRI "
			    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x: "
			    "gicv2_parse_unitintr failed\n",
			    rdip, hdlp, hdlp->ih_inum));
			return (DDI_FAILURE);
		}

		shared = av_get_shared(intid, &curpri);
		newpri = (uint_t)(*(int *)result);
		if (shared > 0 && newpri != curpri) {
			dev_err(dip, CE_NOTE,
			    "!%s%d: refusing attempt to set pri 0x%x on "
			    "shared INTID %u with pri 0x%x",
			    ddi_node_name(rdip), ddi_get_instance(rdip),
			    newpri, intid, curpri);
			return (DDI_FAILURE);
		}

		ASSERT3U(*(int *)result, !=, 0);
		hdlp->ih_pri = *(int *)result;
		break;
	}

	case DDI_INTROP_ADDISR:	/* fallthrough */
	case DDI_INTROP_REMISR:
		/* no-op in this implementation */
		break;

	case DDI_INTROP_ENABLE: {
		gicv2_conf_t *sc =
		    ddi_get_soft_state(gicv2_soft_state, ddi_get_instance(dip));
		syspic_intr_state_t *state = NULL;

		if (gicv2_parse_unitintr(dip, rdip, hdlp,
		    &cfg, &vector, &sense, &intid) != DDI_SUCCESS) {
			DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: ENABLE "
			    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x: "
			    "gicv2_parse_unitintr failed\n",
			    rdip, hdlp, hdlp->ih_inum));
			return (DDI_FAILURE);
		}

		hdlp->ih_vector = intid;

		state = syspic_get_state(hdlp->ih_vector);
		VERIFY3P(state, !=, NULL);

		/*
		 * bits[3:0] trigger type and level flags:
		 * - 1 = low-to-high edge triggered
		 * - 2 = high-to-low edge triggered (invalid for SPIs)
		 * - 4 = active high level-sensitive
		 * - 8 = active low level-sensitive (invalid for SPIs)
		 */
		state->si_edge_triggered =
		    ((sense & 0xf) == 1 || (sense & 0xf) == 2) ?
		    B_TRUE : B_FALSE;
		VERIFY3P(sc, !=, NULL);
		gicv2_config_irq(sc, hdlp->ih_vector, state->si_edge_triggered);
		ASSERT3U(hdlp->ih_pri, !=, 0);
		state->si_prio = hdlp->ih_pri;

		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: ENABLE "
		    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x, op 0x%x, "
		    "vector 0x%x, pri 0x%x, sense %s, devname %s, "
		    "cbfunc 0x%p, arg1 0x%p, arg2 0x%p\n",
		    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum, intr_op,
		    hdlp->ih_vector, hdlp->ih_pri,
		    state->si_edge_triggered ? "EDGE" : "LEVEL",
		    DEVI(rdip)->devi_name,
		    hdlp->ih_cb_func, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2));

		/* Add the interrupt handler */
		if (!add_avintr((void *)hdlp, hdlp->ih_pri,
		    hdlp->ih_cb_func, DEVI(rdip)->devi_name, hdlp->ih_vector,
		    hdlp->ih_cb_arg1, hdlp->ih_cb_arg2, NULL, rdip)) {
			mutex_exit(&syspic_intrs_lock);
			DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: ENABLE "
			    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x: "
			    "add_avintr failed\n",
			    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum));
			return (DDI_FAILURE);
		}

		mutex_exit(&syspic_intrs_lock);
		break;
	}

	case DDI_INTROP_DISABLE: {
		if (gicv2_parse_unitintr(dip, rdip, hdlp,
		    &cfg, &vector, &sense, &intid) != DDI_SUCCESS) {
			DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: DISABLE "
			    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x: "
			    "gicv2_parse_unitintr failed\n",
			    rdip, hdlp, hdlp->ih_inum));
			return (DDI_FAILURE);
		}

		hdlp->ih_vector = intid;
		ASSERT3U(hdlp->ih_pri, !=, 0);

		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: DISABLE "
		    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x, op 0x%x, "
		    "vector 0x%x, pri 0x%x, devname %s, cbfunc 0x%p\n",
		    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum, intr_op,
		    hdlp->ih_vector, hdlp->ih_pri, DEVI(rdip)->devi_name,
		    hdlp->ih_cb_func));

		/* Remove the interrupt handler */
		rem_avintr((void *)hdlp, hdlp->ih_pri,
		    hdlp->ih_cb_func, hdlp->ih_vector);
		break;
	}

	case DDI_INTROP_GETCAP:
		*(int *)result |= DDI_INTR_FLAG_PENDING;
		*(int *)result |= DDI_INTR_FLAG_EDGE;
		*(int *)result |= DDI_INTR_FLAG_LEVEL;
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: GETCAP "
		    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x, op 0x%x, "
		    "result 0x%x\n",
		    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum, intr_op,
		    *(int *)result));
		break;

	case DDI_INTROP_SETCAP:		/* fallthrough */
	case DDI_INTROP_SETMASK:	/* fallthrough */
	case DDI_INTROP_CLRMASK:
		/* SETCAP should have been filtered out by routing */
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: "
		    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x, op 0x%x "
		    "unsupported\n",
		    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum, intr_op));
		return (DDI_ENOTSUP);

	case DDI_INTROP_GETPENDING: {
		if (gicv2_parse_unitintr(dip, rdip, hdlp,
		    &cfg, &vector, &sense, &intid) != DDI_SUCCESS) {
			DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: GETPENDING "
			    "for rdip = 0x%p, hdlp = 0x%p, inum = 0x%x: "
			    "gicv2_parse_unitintr failed\n",
			    rdip, hdlp, hdlp->ih_inum));
			return (DDI_FAILURE);
		}

		*(int *)result =
		    gicv2_irq_ispending(dip, intid) ? 1 : 0;
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: GETPENDING "
		    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x, op 0x%x, "
		    "vector 0x%x, result 0x%x\n",
		    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum, intr_op,
		    intid, *(int *)result));

		break;
	}

	case DDI_INTROP_GETTARGET: {
		gicv2_conf_t *sc;

		if (gicv2_parse_unitintr(dip, rdip, hdlp,
		    &cfg, &vector, &sense, &intid) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		if (GIC_INTID_IS_PERCPU(intid)) {
			*(processorid_t *)result = CPU->cpu_id;
			return (DDI_SUCCESS);
		}
		if (!GIC_INTID_IS_SPI(intid)) {
			return (DDI_ENOTSUP);
		}

		sc = ddi_get_soft_state(gicv2_soft_state,
		    ddi_get_instance(dip));
		VERIFY3P(sc, !=, NULL);

		mutex_enter(&sc->gc_msi_lock);
		if (gicv2_is_msi_spi(sc, intid)) {
			mutex_exit(&sc->gc_msi_lock);
			return (DDI_ENOTSUP);
		}
		mutex_exit(&sc->gc_msi_lock);

		*(processorid_t *)result = gicv2_get_target_spi(dip, intid);
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: GETTARGET "
		    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x, op 0x%x, "
		    "vector 0x%x, result 0x%x\n",
		    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum, intr_op,
		    intid, *(int *)result));
		return (DDI_SUCCESS);
	}

	case DDI_INTROP_SETTARGET: {
		gicv2_conf_t *sc;
		processorid_t new_cpu;

		if (gicv2_parse_unitintr(dip, rdip, hdlp,
		    &cfg, &vector, &sense, &intid) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		new_cpu = *(processorid_t *)result;

		if (GIC_INTID_IS_PERCPU(intid)) {
			return (DDI_ENOTSUP);
		}
		if (!GIC_INTID_IS_SPI(intid)) {
			return (DDI_ENOTSUP);
		}
		if (new_cpu < 0 || new_cpu >= 8) {
			return (DDI_EINVAL);
		}

		sc = ddi_get_soft_state(gicv2_soft_state,
		    ddi_get_instance(dip));
		VERIFY3P(sc, !=, NULL);

		mutex_enter(&sc->gc_msi_lock);
		if (gicv2_is_msi_spi(sc, intid)) {
			mutex_exit(&sc->gc_msi_lock);
			return (DDI_ENOTSUP);
		}
		mutex_exit(&sc->gc_msi_lock);

		gicv2_set_target_spi(dip, intid, new_cpu);
		DDI_INTR_NEXDBG((CE_CONT, "gicv2_intr_ops: SETTARGET "
		    "dip 0x%p, hdlp 0x%p, type 0x%x, inum 0x%x, op 0x%x, "
		    "vector 0x%x, new CPU 0x%x\n",
		    rdip, hdlp, hdlp->ih_type, hdlp->ih_inum, intr_op,
		    intid, (int)new_cpu));
		return (DDI_SUCCESS);
	}

	/* Operations which should never have reached us */
	default:
		dev_err(dip, CE_WARN, "unexpected introp %d for %s%d",
		    intr_op, ddi_node_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static struct bus_ops gicv2_bus_ops = {
	.busops_rev = BUSO_REV,
	.bus_map = i_ddi_bus_map,
	.bus_map_fault = i_ddi_map_fault,
	.bus_ctl = gicv2_bus_ctl,
	.bus_prop_op = ddi_bus_prop_op,
	.bus_intr_op = gicv2_intr_ops,
};

static struct modlmisc modlmisc = {
	&mod_miscops,
	"Generic Interrupt Controller v2 (misc)"
};

static struct dev_ops gicv2_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = NULL,
	.devo_identify = nulldev,
	.devo_attach = gicv2_attach,
	.devo_detach = gicv2_detach,
	.devo_reset = nulldev,
	.devo_cb_ops  = NULL,
	.devo_bus_ops = &gicv2_bus_ops,
	.devo_power = nulldev,
	.devo_quiesce = ddi_quiesce_not_supported,
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Generic Interrupt Controller v2 (device)",
	&gicv2_ops,
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &modlmisc, &modldrv, NULL }
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&gicv2_soft_state,
	    sizeof (gicv2_conf_t), 1)) != 0)
		return (err);

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&gicv2_soft_state);
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

	ddi_soft_state_fini(&gicv2_soft_state);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
