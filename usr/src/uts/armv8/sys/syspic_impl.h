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
 * Copyright 2024 Richard Lowe
 * Copyright 2026 Michael van der Westhuizen
 */

#ifndef _SYSPIC_IMPL_H
#define	_SYSPIC_IMPL_H

/*
 * System Programmable Interrupt Controller interfaces
 *
 * Interfaces to register a system PIC and dispatch calls to it.
 *
 * The `syspic' facility provides a layer between `intr.c' (handling hardware
 * interrupts delivered to the Arm CPU) and a system interrupt controller
 * driver (typically an Arm Generic Interrupt Controller). The subsystem and
 * system interrupt controller driver cooperate to expose interrupt state
 * tracking information to debuggers.
 *
 * The syspic facility is initialised during system startup. Initialisation
 * simply initialises data structures and mutexes.
 *
 * When acting as the root of the interrupt hierarchy, an interrupt controller
 * driver registers a set of interrupt operations with syspic along with a
 * context pointer (typically the driver's soft state or dip). When a hardware
 * interrupt is received and dispatched via `do_interrupt' several interrupt
 * management calls are made through `syspic', which calls the appropriate
 * registered operation, adding the registered context pointer.
 *
 * As interrupts are registered, the driver cooperates with `syspic' to track
 * information about the interrupts in a way that can be inspected by `mdb'.
 * This tracking takes two paths. The first handles standard DDI interrupts -
 * those enabled via the `DDI_INTROP_ENABLE' call. The driver uses the
 * `syspic_get_state' function to obtain a state pointer for the interrupt
 * vector, locking the interrupt tracking structures. The driver then fills
 * in the sense and priority for the interrupt before calling `add_avintr'
 * with the `syspic_intrs_lock' mutex locked. Finally, the driver releases the
 * `syspic_intrs_lock' mutex. The second case handles inter-processor
 * interrupts (called SGIs in Arm terminology). In the case of SGIs, DDI is not
 * involved, so the `addspl' function in the driver must recognise SGIs, create
 * the state object via a call to `syspic_get_state', record the interrupt
 * configuration (SGIs can only be edge triggered) and unlock the mutex when
 * done.
 *
 * When interrupts are disabled the driver should lock the `syspic_intrs_lock'
 * mutex in the `delspl' function, remove state tracking using
 * `syspic_remove_state', program the hardware, and then unlock
 * `syspic_intrs_lock' before returning.
 *
 * The Interrupt Operations
 *
 * The four callers of `syspic' functionality are: CPU startup, IPIs,
 * auto-vectored interrupt management and hardware interrupt handling.
 *
 * The unix startup code calls `syspic_cpu_init' during CPU startup, which
 * calls the `spo_cpu_init' operation against the registered system PIC.
 *
 * Inter-processor interrupts are invoked by `unix' and calls are made to one
 * of three syspic functions (based solely on what's most ergonomic for the
 * callsite): `syspic_send_ipi' (delivers to a cpuset); `syspic_send_ipi_one'
 * (delivers to a CPU object) and `syspic_send_ipi_one_id' (delivers to a CPU
 * ID).
 *
 * The auto-vectored interrupts functionality (via `add_avintr' and
 * `rem_avintr') results in calls to `addspl' and `delspl', which point to
 * `syspic_addspl' and `syspic_delspl' respectively (these names are not
 * visible). These functions then call through to the `spo_addspl' and
 * `spo_addspl' operations, passing the driver context.
 *
 * The remaining operations are called during interrupt processing and are
 * individually documented in `sys/syspic.h'. The programming model reflects
 * Arm's split-EOI model, where the `end-of-interrupt' call becomes a priority
 * drop, and the `deactivate' call returns the interrupt to the inactive or
 * pending state.
 *
 * In all cases, the `syspic' functionality deals with what Arm calls an INTID,
 * which is a flat interrupt ID namespace. Any firmware-specific notion of
 * interrupt identification must be resolved into INTID identifiers prior to
 * calling the `syspic' interfaces.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

typedef void * spo_ctx_t;

typedef void (*spo_cpu_init_t)(spo_ctx_t ctx, cpu_t *cp);
typedef int (*spo_intr_enter_t)(spo_ctx_t ctx, intr_intid_t intid);
typedef void (*spo_intr_exit_t)(spo_ctx_t ctx, intr_ipl_t ipl);
typedef intr_cookie_t (*spo_iack_t)(spo_ctx_t ctx);
typedef intr_intid_t (*spo_cookie_to_intid_t)(
    spo_ctx_t ctx, intr_cookie_t cookie);
typedef boolean_t (*spo_is_spurious_t)(spo_ctx_t ctx, intr_intid_t intid);
typedef void (*spo_eoi_t)(spo_ctx_t ctx, intr_cookie_t cookie);
typedef void (*spo_deactivate_t)(spo_ctx_t ctx, intr_cookie_t ack);
typedef void (*spo_send_ipi_t)(
    spo_ctx_t ctx, cpuset_t cpuset, intr_intid_t intid);
typedef int (*spo_addspl_t)(spo_ctx_t ctx, intr_intid_t intid,
    intr_ipl_t ipl, intr_ipl_t min_ipl, intr_ipl_t max_ipl);
typedef int (*spo_delspl_t)(spo_ctx_t ctx, intr_intid_t intid,
    intr_ipl_t ipl, intr_ipl_t min_ipl, intr_ipl_t max_ipl);

typedef struct {
	spo_cpu_init_t		spo_cpu_init;
	spo_intr_enter_t	spo_intr_enter;
	spo_intr_exit_t		spo_intr_exit;
	spo_iack_t		spo_iack;
	spo_cookie_to_intid_t	spo_cookie_to_intid;
	spo_is_spurious_t	spo_is_spurious;
	spo_eoi_t		spo_eoi;
	spo_deactivate_t	spo_deactivate;
	spo_send_ipi_t		spo_send_ipi;
	spo_addspl_t		spo_addspl;
	spo_delspl_t		spo_delspl;
} syspic_ops_t;

/*
 * The state of each vector known to us and the system interrupt controller..
 * For the benefit of the debugger.
 */
typedef struct {
	avl_node_t		si_node;
	uint_t			si_vector;
	uint32_t		si_prio;
	boolean_t		si_edge_triggered;
} syspic_intr_state_t;

extern kmutex_t syspic_intrs_lock;
/* locks `syspic_intrs_lock', caller must release */
extern syspic_intr_state_t *syspic_get_state(int irq);
/* caller must hold `syspic_intrs_lock' */
extern void syspic_remove_state(int irq);

/*
 * Called in startup.c to initialise global system PIC state.
 */
extern int syspic_init(void);

/*
 * Called by one (and only one) interrupt driver to register the driver
 * instance for the root of the interrupt hierarchy.
 */
extern int syspic_register_syspic(spo_ctx_t ctx, syspic_ops_t *ops,
    dev_info_t *dip);

/*
 * Return the dev_info_t of the registered system PIC.
 */
extern dev_info_t *syspic_get_dip(void);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYSPIC_IMPL_H */
