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
 * Copyright 2017 Hayashi Naoyuki
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>
#include <sys/xc_levels.h>
#include <sys/cpu.h>
#include <sys/psw.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/mutex_impl.h>
#include <sys/stack.h>
#include <sys/promif.h>
#include <sys/spl.h>
#include <sys/irq.h>
#include <sys/syspic.h>
#include <sys/smp_impldefs.h>

struct	xc_mbox {
	xc_func_t	func;
	xc_arg_t	arg0;
	xc_arg_t	arg1;
	xc_arg_t	arg2;
	cpuset_t	set;
};

enum {
	XC_DONE,	/* x-call session done */
	XC_HOLD,	/* spin doing nothing */
	XC_SYNC_OP,	/* perform a synchronous operation */
	XC_CALL_OP,	/* perform a call operation */
	XC_WAIT,	/* capture/release. callee has seen wait */
	XC_ASYNC_OP,
};

static int	xc_initialized = 0;
extern cpuset_t	cpu_ready_set;

static kmutex_t	xc_mbox_lock;
static struct	xc_mbox xc_mbox;
static uint_t	xc_serv(caddr_t, caddr_t);
static uint_t	xc_poke(caddr_t, caddr_t);

void
xc_init()
{
	ASSERT(xc_initialized == 0);
	mutex_init(&xc_mbox_lock, NULL,  MUTEX_SPIN,
	    (void *)ipltospl(XC_HI_PIL));

	add_avintr((void *)NULL, XC_HI_PIL, xc_serv, "xc_intr", IRQ_IPI_HI,
	    NULL, NULL, NULL, NULL);
	add_avintr((void *)NULL, XC_CPUPOKE_PIL, xc_poke, "xc_poke",
	    IRQ_IPI_CPUPOKE, NULL, NULL, NULL, NULL);

	xc_initialized = 1;
}

/* We do nothing except be poked */
static uint_t
xc_poke(caddr_t arg0, caddr_t arg1)
{
	return (DDI_INTR_CLAIMED);
}

static uint_t
xc_serv(caddr_t arg0, caddr_t arg1)
{
	struct cpu *cpup = CPU;

	int xc_pend = cpup->cpu_m.xc_pend;
	dsb(ish);

	/*
	 * XXXARM: If there are no pending calls, it's not clear how we got
	 * here.
	 */
	if (xc_pend == 0) {
		return (DDI_INTR_UNCLAIMED);
	}

	int op = cpup->cpu_m.xc_state;

	xc_func_t func = xc_mbox.func;
	xc_arg_t a0 = xc_mbox.arg0;
	xc_arg_t a1 = xc_mbox.arg1;
	xc_arg_t a2 = xc_mbox.arg2;
	int ret;

	dsb(ish);
	cpup->cpu_m.xc_pend = 0;

	if (func != NULL)
		ret = (*func)(a0, a1, a2);
	else
		ret = 0;

	if (op == XC_ASYNC_OP)
		return (DDI_INTR_CLAIMED);

	cpup->cpu_m.xc_retval = ret;

	/*
	 * Acknowledge that we have completed the x-call operation.
	 */
	dsb(ish);
	cpup->cpu_m.xc_ack = 1;

	if (op == XC_CALL_OP) {
		return (DDI_INTR_CLAIMED);
	}

	dsb(ish);
	/*
	 * for (op == XC_SYNC_OP)
	 * Wait for the initiator of the x-call to indicate
	 * that all CPUs involved can proceed.
	 *
	 * XXXARM: It feels like there's much better things to do here, but
	 * likely not in high-level interrupt context.
	 */
	while (cpup->cpu_m.xc_wait) {
	}

	dsb(ish);

	/*
	 * Acknowledge that we have received the directive to continue.
	 */
	ASSERT(cpup->cpu_m.xc_ack == 0);
	dsb(ish);
	cpup->cpu_m.xc_ack = 1;

	return (DDI_INTR_CLAIMED);
}

static void
xc_common(
	xc_func_t func,
	xc_arg_t arg0,
	xc_arg_t arg1,
	xc_arg_t arg2,
	cpuset_t set,
	int op)
{
	int cix;
	int lcx = (int)(CPU->cpu_id);
	cpuset_t cpuset;

	/*
	 * Assert we haven't panicked and stopped the other CPUs.
	 *
	 * XXXARM: I'm deeply unhappy about using `panicstr` for this, but
	 * seemingly that's the done thing.
	 */
	ASSERT(panicstr == NULL);

	ASSERT(MUTEX_HELD(&xc_mbox_lock));

	/*
	 * XXXARM: I don't know what this guards against.  Us trying to to
	 * cross call when we ourselves aren't ready to get it?  There must be
	 * a story here at the very least.
	 */
	ASSERT(CPU->cpu_flags & CPU_READY);

	CPUSET_ZERO(cpuset);

	/*
	 * Set up the service definition mailbox.
	 */
	xc_mbox.func = func;
	xc_mbox.arg0 = arg0;
	xc_mbox.arg1 = arg1;
	xc_mbox.arg2 = arg2;

	/*
	 * Request service on all remote processors.
	 */
	cpuset = set;
	while (!CPUSET_ISNULL(cpuset)) {
		CPUSET_FIND(cpuset, cix);
		struct cpu *cpup = cpu[cix];
		if (cpup == NULL || (cpup->cpu_flags & CPU_READY) == 0) {
			CPUSET_DEL(set, cix);
		} else if (cix != lcx) {
			CPU_STATS_ADDQ(CPU, sys, xcalls, 1);

			ASSERT(cpup->cpu_m.xc_ack == 0);
			ASSERT(cpup->cpu_m.xc_wait == 0);
			ASSERT(cpup->cpu_m.xc_pend == 0);
			cpup->cpu_m.xc_wait = (op == XC_SYNC_OP);
			cpup->cpu_m.xc_state = op;
			cpup->cpu_m.xc_pend = 1;
		}
		CPUSET_DEL(cpuset, cix);
	}

	/*
	 * Send IPI to requested remote cpus in selected set.
	 */
	cpuset = set;
	CPUSET_DEL(cpuset, lcx);
	if (!CPUSET_ISNULL(cpuset)) {
		syspic_send_ipi(cpuset, IRQ_IPI_HI);
	}

	/*
	 * Run service locally if we're in the set
	 */
	if (CPU_IN_SET(set, lcx) && func != NULL)
		CPU->cpu_m.xc_retval = (*func)(arg0, arg1, arg2);

	/*
	 * Wait here until all remote calls acknowledge.
	 *
	 * XXXARM: Should we check if the cpu is quiesced as well, rather than
	 * forcing the ack in panic_idle?
	 */
	dsb(ish);
	cpuset = set;
	while (!CPUSET_ISNULL(cpuset)) {
		CPUSET_FIND(cpuset, cix);
		struct cpu *cpup = cpu[cix];
		if (cix != lcx) {
			for (;;) {
				if ((cpup->cpu_flags & CPU_READY) == 0 ||
				    cpup->cpu_m.xc_ack != 0 ||
				    (op == XC_ASYNC_OP &&
				    cpup->cpu_m.xc_pend == 0)) {
					cpup->cpu_m.xc_ack = 0;
					break;
				}
			}
		}
		CPUSET_DEL(cpuset, cix);
	}

	if (op == XC_ASYNC_OP || op == XC_CALL_OP)
		return;

	dsb(ish);
	cpuset = set;
	while (!CPUSET_ISNULL(cpuset)) {
		CPUSET_FIND(cpuset, cix);
		struct cpu *cpup = cpu[cix];
		if (cix != lcx) {
			cpup->cpu_m.xc_wait = 0;
		}
		CPUSET_DEL(cpuset, cix);
	}

	/*
	 * Wait here until all remote calls acknowledge.
	 */
	dsb(ish);
	cpuset = set;
	while (!CPUSET_ISNULL(cpuset)) {
		CPUSET_FIND(cpuset, cix);
		struct cpu *cpup = cpu[cix];
		if (cix != lcx) {
			for (;;) {
				if ((cpup->cpu_flags & CPU_READY) == 0 ||
				    cpup->cpu_m.xc_ack != 0) {
					cpup->cpu_m.xc_ack = 0;
					break;
				}
			}
		}
		CPUSET_DEL(cpuset, cix);
	}
}

void
xc_call(
	xc_arg_t arg0,
	xc_arg_t arg1,
	xc_arg_t arg2,
	cpuset_t set,
	xc_func_t func)
{
	mutex_enter(&xc_mbox_lock);
	xc_common(func, arg0, arg1, arg2, set, XC_CALL_OP);
	mutex_exit(&xc_mbox_lock);
}

void
xc_sync(
	xc_arg_t arg0,
	xc_arg_t arg1,
	xc_arg_t arg2,
	cpuset_t set,
	xc_func_t func)
{
	mutex_enter(&xc_mbox_lock);
	xc_common(func, arg0, arg1, arg2, set, XC_SYNC_OP);
	mutex_exit(&xc_mbox_lock);
}

void
xc_call_nowait(
	xc_arg_t arg0,
	xc_arg_t arg1,
	xc_arg_t arg2,
	cpuset_t set,
	xc_func_t func)
{
	mutex_enter(&xc_mbox_lock);
	xc_common(func, arg0, arg1, arg2, set, XC_ASYNC_OP);
	mutex_exit(&xc_mbox_lock);
}

/*
 * Wrapper for kmdb to capture other CPUs, causing them to enter the debugger.
 */
void
kdi_xc_others(int this_cpu, void (*func)(void))
{
	extern int IGNORE_KERNEL_PREEMPTION;
	int save_kernel_preemption;
	cpuset_t set;

	if (!xc_initialized)
		return;

	save_kernel_preemption = IGNORE_KERNEL_PREEMPTION;
	IGNORE_KERNEL_PREEMPTION = 1;
	CPUSET_ALL_BUT(set, this_cpu);
	/*
	 * XXXKDI: I think this should wait, but our xcall facilities are poor
	 */
	xc_call_nowait(0, 0, 0, set, (xc_func_t)func);
	IGNORE_KERNEL_PREEMPTION = save_kernel_preemption;
}
