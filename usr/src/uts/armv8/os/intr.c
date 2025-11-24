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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc.  All rights reserverd.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/cpuvar.h>
#include <sys/cpu_event.h>
#include <sys/regset.h>
#include <sys/psw.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/clock.h>
#include <sys/panic.h>
#include <sys/disp.h>
#include <vm/seg_kp.h>
#include <sys/stack.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/smp_impldefs.h>
#include <sys/pool_pset.h>
#include <sys/zone.h>
#include <sys/bitmap.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/ontrap.h>
#include <sys/promif.h>
#include <sys/syspic.h>
#include <sys/x_call.h>
#include <sys/xc_levels.h>
#include <sys/arch_timer.h>

/*
 * This is the equivalent of the x86 instruction BSRW.  We return the index
 * counting from the right of the most significant set bit in a 16bit "word".
 *
 * It could use a better name (on x86 too, honestly).
 */
static inline uint_t
bsrw_insn(uint16_t mask)
{
	return (31 - __builtin_clz(mask));
}

/*
 * Set cpu's base SPL level to the highest active interrupt level
 */
void
set_base_spl(void)
{
	struct cpu *cpu = CPU;
	uint16_t active = (uint16_t)cpu->cpu_intr_actv;

	cpu->cpu_base_spl = active == 0 ? 0 : bsrw_insn(active);
}

/*
 * Do all the work necessary to set up the cpu and thread structures
 * to dispatch a high-level interrupt.
 *
 * Returns 0 if we're -not- already on the high-level interrupt stack,
 * (and *must* switch to it), non-zero if we are already on that stack.
 *
 * Called with interrupts masked.
 * The 'pil' is already set to the appropriate level for rp->r_trapno.
 */
static int
hilevel_intr_prolog(struct cpu *cpu, uint_t pil, uint_t oldpil, struct regs *rp)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t mask;
	hrtime_t intrtime;
	hrtime_t now = arch_timer_count();

	ASSERT(pil > LOCK_LEVEL);

	if (pil == CBE_HIGH_PIL) {
		cpu->cpu_profile_pil = oldpil;
		if (USERMODE(rp->r_spsr)) {
			cpu->cpu_profile_pc = 0;
			cpu->cpu_profile_upc = rp->r_pc;
			cpu->cpu_cpcprofile_pc = 0;
			cpu->cpu_cpcprofile_upc = rp->r_pc;
		} else {
			cpu->cpu_profile_pc = rp->r_pc;
			cpu->cpu_profile_upc = 0;
			cpu->cpu_cpcprofile_pc = rp->r_pc;
			cpu->cpu_cpcprofile_upc = 0;
		}
	}

	mask = cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK;
	if (mask != 0) {
		int nestpil;

		/*
		 * We have interrupted another high-level interrupt.
		 * Load starting timestamp, compute interval, update
		 * cumulative counter.
		 */
		nestpil = bsrw_insn((uint16_t)mask);
		ASSERT(nestpil < pil);
		intrtime = now -
		    mcpu->pil_high_start[nestpil - (LOCK_LEVEL + 1)];
		mcpu->intrstat[nestpil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		/*
		 * Another high-level interrupt is active below this one, so
		 * there is no need to check for an interrupt thread.  That
		 * will be done by the lowest priority high-level interrupt
		 * active.
		 */
	} else {
		kthread_t *t = cpu->cpu_thread;

		/*
		 * See if we are interrupting a low-level interrupt thread.
		 * If so, account for its time slice only if its time stamp
		 * is non-zero.
		 */
		if ((t->t_flag & T_INTR_THREAD) != 0 && t->t_intr_start != 0) {
			intrtime = now - t->t_intr_start;
			mcpu->intrstat[t->t_pil][0] += intrtime;
			cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
			t->t_intr_start = 0;
		}
	}

	/*
	 * Store starting timestamp in CPU structure for this PIL.
	 */
	mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)] = now;

	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);

	mask = cpu->cpu_intr_actv;
	cpu->cpu_intr_actv |= (1 << pil)|CPU_INTR_ACTV_INTR_STACK_MASK;

	return (mask & CPU_INTR_ACTV_INTR_STACK_MASK);
}

/*
 * Does most of the work of returning from a high level interrupt.
 *
 * Returns 0 if there are no more high level interrupts (in which
 * case we must switch back to the interrupted thread stack) or
 * non-zero if there are more (in which case we should stay on it).
 *
 * Called with interrupts masked
 */
static int
hilevel_intr_epilog(struct cpu *cpu, uint_t pil, uint_t oldpil,
    intr_cookie_t ack)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t mask;
	hrtime_t intrtime;
	hrtime_t now = arch_timer_count();

	ASSERT(mcpu->mcpu_pri == pil);

	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));

	cpu->cpu_intr_actv &= ~(1 << pil);
	ASSERT(mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)] != 0);

	intrtime = now - mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)];
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	/*
	 * Check for lower-pil nested high-level interrupt beneath
	 * current one.  If so, place a starting timestamp in its
	 * pil_high_start entry.
	 */
	mask = cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK;
	if (mask != 0) {
		int nestpil;

		/*
		 * find PIL of nested interrupt
		 */
		nestpil = bsrw_insn((uint16_t)mask);
		ASSERT(nestpil < pil);
		mcpu->pil_high_start[nestpil - (LOCK_LEVEL + 1)] = now;
		/*
		 * (Another high-level interrupt is active below this one,
		 * so there is no need to check for an interrupt
		 * thread.  That will be done by the lowest priority
		 * high-level interrupt active.)
		 */
	} else {
		/*
		 * Check to see if there is a low-level interrupt active.
		 * If so, place a starting timestamp in the thread
		 * structure.
		 */
		kthread_t *t = cpu->cpu_thread;

		if (t->t_flag & T_INTR_THREAD)
			t->t_intr_start = now;
	}

	if ((mask = cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK) == 0) {
		cpu->cpu_intr_actv &= ~CPU_INTR_ACTV_INTR_STACK_MASK;
	}

	mcpu->mcpu_pri = oldpil;
	syspic_intr_deactivate(ack);
	syspic_intr_exit(oldpil);

	return ((int)mask);
}

/*
 * Set up the cpu, thread and interrupt thread structures for
 * executing an interrupt thread.  The new stack pointer of the
 * interrupt thread (which *must* be switched to) is returned.
 */
static caddr_t
intr_thread_prolog(struct cpu *cpu, caddr_t stackptr, uint_t pil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t, *volatile it;
	hrtime_t now = arch_timer_count();

	ASSERT(pil > 0);
	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);
	cpu->cpu_intr_actv |= (1 << pil);

	/*
	 * Get set to run an interrupt thread.
	 * There should always be an interrupt thread, since we
	 * allocate one for each level on each CPU.
	 *
	 * t_intr_start could be zero due to cpu_intr_swtch_enter.
	 */
	t = cpu->cpu_thread;
	if ((t->t_flag & T_INTR_THREAD) && t->t_intr_start != 0) {
		hrtime_t intrtime = now - t->t_intr_start;
		mcpu->intrstat[t->t_pil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		t->t_intr_start = 0;
	}

	ASSERT(SA((uintptr_t)stackptr) == (uintptr_t)stackptr);

	t->t_sp = (uintptr_t)stackptr;	/* mark stack in curthread for resume */

	/*
	 * unlink the interrupt thread off the cpu
	 *
	 * Note that the code in kcpc_overflow_intr -relies- on the
	 * ordering of events here - in particular that t->t_lwp of
	 * the interrupt thread is set to the pinned thread *before*
	 * curthread is changed.
	 */
	it = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it->t_link;
	it->t_intr = t;
	it->t_lwp = t->t_lwp;

	/*
	 * (threads on the interrupt thread free list could have state
	 * preset to TS_ONPROC, but it helps in debugging if
	 * they're TS_FREE.)
	 */
	it->t_state = TS_ONPROC;

	write_tpidr_el1((uintptr_t)it);
	cpu->cpu_thread = it;		/* new curthread on this cpu */
	it->t_pil = (uchar_t)pil;
	it->t_pri = intr_pri + (pri_t)pil;
	it->t_intr_start = now;

	return (it->t_stk);
}


#ifdef DEBUG
int intr_thread_cnt;
#endif

/*
 * Called with interrupts disabled
 */
static void
intr_thread_epilog(struct cpu *cpu, intr_cookie_t ack, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t;
	kthread_t *it = cpu->cpu_thread;	/* curthread */
	uint_t pil, basespl;
	hrtime_t intrtime;
	hrtime_t now = arch_timer_count();

	pil = it->t_pil;
	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(it->t_intr_start != 0);
	intrtime = now - it->t_intr_start;
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));
	cpu->cpu_intr_actv &= ~(1 << pil);

	/*
	 * If there is still an interrupted thread underneath this one
	 * then the interrupt was never blocked and the return is
	 * fairly simple.  Otherwise it isn't.
	 */
	if ((t = it->t_intr) == NULL) {
		/*
		 * The interrupted thread is no longer pinned underneath
		 * the interrupt thread.  This means the interrupt must
		 * have blocked, and the interrupted thread has been
		 * unpinned, and has probably been running around the
		 * system for a while.
		 *
		 * Since there is no longer a thread under this one, put
		 * this interrupt thread back on the CPU's free list and
		 * resume the idle thread which will dispatch the next
		 * thread to run.
		 */
#ifdef DEBUG
		intr_thread_cnt++;
#endif
		cpu->cpu_stats.sys.intrblk++;
		/*
		 * Set CPU's base SPL based on active interrupts bitmask
		 */
		set_base_spl();
		basespl = cpu->cpu_base_spl;
		mcpu->mcpu_pri = basespl;
		syspic_intr_deactivate(ack);
		syspic_intr_exit(basespl);
		(void) splhigh();
		(void) enable_interrupts();

		it->t_state = TS_FREE;
		/*
		 * Return interrupt thread to pool
		 */
		it->t_link = cpu->cpu_intr_thread;
		cpu->cpu_intr_thread = it;
		swtch();
		panic("intr_thread_epilog: swtch returned");
		/*NOTREACHED*/
	}

	/*
	 * Return interrupt thread to the pool
	 */
	it->t_link = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it;
	it->t_state = TS_FREE;

	basespl = cpu->cpu_base_spl;
	pil = MAX(oldpil, basespl);
	mcpu->mcpu_pri = pil;
	syspic_intr_deactivate(ack);
	syspic_intr_exit(pil);
	t->t_intr_start = now;
	write_tpidr_el1((uintptr_t)t);
	cpu->cpu_thread = t;
}

/*
 * intr_get_time() is a resource for interrupt handlers to determine how
 * much time has been spent handling the current interrupt. Such a function
 * is needed because higher level interrupts can arrive during the
 * processing of an interrupt.  intr_get_time() only returns time spent in the
 * current interrupt handler.
 *
 * The caller must be calling from an interrupt handler running at a pil
 * below or at lock level. Timings are not provided for high-level
 * interrupts.
 *
 * The first time intr_get_time() is called while handling an interrupt,
 * it returns the time since the interrupt handler was invoked. Subsequent
 * calls will return the time since the prior call to intr_get_time(). Time
 * is returned as ticks. Use scalehrtimef() to convert ticks to nsec.
 *
 * Theory Of Intrstat[][]:
 *
 * uint64_t intrstat[pil][0..1] is an array indexed by pil level, with two
 * uint64_ts per pil.
 *
 * intrstat[pil][0] is a cumulative count of the number of ticks spent
 * handling all interrupts at the specified pil on this CPU. It is
 * exported via kstats to the user.
 *
 * intrstat[pil][1] is always a count of ticks less than or equal to the
 * value in [0]. The difference between [1] and [0] is the value returned
 * by a call to intr_get_time(). At the start of interrupt processing,
 * [0] and [1] will be equal (or nearly so). As the interrupt consumes
 * time, [0] will increase, but [1] will remain the same. A call to
 * intr_get_time() will return the difference, then update [1] to be the
 * same as [0]. Future calls will return the time since the last call.
 * Finally, when the interrupt completes, [1] is updated to the same as [0].
 *
 * Implementation:
 *
 * intr_get_time() works much like a higher level interrupt arriving. It
 * "checkpoints" the timing information by incrementing intrstat[pil][0]
 * to include elapsed running time, and by setting t_intr_start to rdtsc.
 * It then sets the return value to intrstat[pil][0] - intrstat[pil][1],
 * and updates intrstat[pil][1] to be the same as the new value of
 * intrstat[pil][0].
 *
 * In the normal handling of interrupts, after an interrupt handler returns
 * and the code in intr_thread() updates intrstat[pil][0], it then sets
 * intrstat[pil][1] to the new value of intrstat[pil][0]. When [0] == [1],
 * the timings are reset, i.e. intr_get_time() will return [0] - [1] which
 * is 0.
 *
 * Whenever interrupts arrive on a CPU which is handling a lower pil
 * interrupt, they update the lower pil's [0] to show time spent in the
 * handler that they've interrupted. This results in a growing discrepancy
 * between [0] and [1], which is returned the next time intr_get_time() is
 * called. Time spent in the higher-pil interrupt will not be returned in
 * the next intr_get_time() call from the original interrupt, because
 * the higher-pil interrupt's time is accumulated in intrstat[higherpil][].
 */
uint64_t
intr_get_time(void)
{
	struct cpu *cpu;
	struct machcpu *mcpu;
	kthread_t *t;
	uint64_t time, delta, ret;
	uint_t pil;

	uint64_t s = disable_interrupts();
	cpu = CPU;
	mcpu = &cpu->cpu_m;
	t = cpu->cpu_thread;
	pil = t->t_pil;
	ASSERT((cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK) == 0);
	ASSERT(t->t_flag & T_INTR_THREAD);
	ASSERT(pil != 0);
	ASSERT(t->t_intr_start != 0);

	time = arch_timer_count();
	delta = time - t->t_intr_start;
	t->t_intr_start = time;

	time = mcpu->intrstat[pil][0] + delta;
	ret = time - mcpu->intrstat[pil][1];
	mcpu->intrstat[pil][0] = time;
	mcpu->intrstat[pil][1] = time;
	cpu->cpu_intracct[cpu->cpu_mstate] += delta;

	restore_interrupts(s);
	return (ret);
}

static caddr_t
dosoftint_prolog(
	struct cpu *cpu,
	caddr_t stackptr,
	uint32_t st_pending,
	uint_t oldpil)
{
	kthread_t *t, *volatile it;
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t pil;
	hrtime_t now;

	ASSERT(st_pending == mcpu->mcpu_softinfo.st_pending);

	pil = bsrw_insn((uint16_t)st_pending);
	if (pil <= oldpil || pil <= cpu->cpu_base_spl)
		return (0);

	/*
	 * XX64	Sigh.
	 *
	 * This is a transliteration of the i386 assembler code for
	 * soft interrupts.  One question is "why does this need
	 * to be atomic?"  One possible race is -other- processors
	 * posting soft interrupts to us in set_pending() i.e. the
	 * CPU might get preempted just after the address computation,
	 * but just before the atomic transaction, so another CPU would
	 * actually set the original CPU's st_pending bit.  However,
	 * it looks like it would be simpler to disable preemption there.
	 * Are there other races for which preemption control doesn't work?
	 *
	 * The i386 assembler version -also- checks to see if the bit
	 * being cleared was actually set; if it wasn't, it rechecks
	 * for more.  This seems a bit strange, as the only code that
	 * ever clears the bit is -this- code running with interrupts
	 * disabled on -this- CPU.  This code would probably be cheaper:
	 *
	 * atomic_and_32((uint32_t *)&mcpu->mcpu_softinfo.st_pending,
	 *   ~(1 << pil));
	 *
	 * and t->t_preempt--/++ around set_pending() even cheaper,
	 * but at this point, correctness is critical, so we slavishly
	 * emulate the i386 port.
	 */
	atomic_and_32((uint32_t *)&mcpu->mcpu_softinfo.st_pending,
	    ~(1 << pil));

	mcpu->mcpu_pri = pil;
	syspic_intr_exit(pil);

	now = arch_timer_count();

	/*
	 * Get set to run interrupt thread.
	 * There should always be an interrupt thread since we
	 * allocate one for each level on the CPU.
	 */
	it = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it->t_link;

	/* t_intr_start could be zero due to cpu_intr_swtch_enter. */
	t = cpu->cpu_thread;
	if ((t->t_flag & T_INTR_THREAD) && t->t_intr_start != 0) {
		hrtime_t intrtime = now - t->t_intr_start;
		mcpu->intrstat[pil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		t->t_intr_start = 0;
	}

	/*
	 * Note that the code in kcpc_overflow_intr -relies- on the
	 * ordering of events here - in particular that t->t_lwp of
	 * the interrupt thread is set to the pinned thread *before*
	 * curthread is changed.
	 */
	it->t_lwp = t->t_lwp;
	it->t_state = TS_ONPROC;

	/*
	 * Push interrupted thread onto list from new thread.
	 * Set the new thread as the current one.
	 * Set interrupted thread's T_SP because if it is the idle thread,
	 * resume() may use that stack between threads.
	 */

	ASSERT(SA((uintptr_t)stackptr) == (uintptr_t)stackptr);
	t->t_sp = (uintptr_t)stackptr;

	it->t_intr = t;
	write_tpidr_el1((uintptr_t)it);
	cpu->cpu_thread = it;

	/*
	 * Set bit for this pil in CPU's interrupt active bitmask.
	 */
	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);
	cpu->cpu_intr_actv |= (1 << pil);

	/*
	 * Initialize thread priority level from intr_pri
	 */
	it->t_pil = (uchar_t)pil;
	it->t_pri = (pri_t)pil + intr_pri;
	it->t_intr_start = now;

	return (it->t_stk);
}

static void
dosoftint_epilog(struct cpu *cpu, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t, *it;
	uint_t pil, basespl;
	hrtime_t intrtime;
	hrtime_t now = arch_timer_count();

	it = cpu->cpu_thread;
	pil = it->t_pil;

	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));
	cpu->cpu_intr_actv &= ~(1 << pil);
	intrtime = now - it->t_intr_start;
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	/*
	 * If there is still an interrupted thread underneath this one
	 * then the interrupt was never blocked and the return is
	 * fairly simple.  Otherwise it isn't.
	 */
	if ((t = it->t_intr) == NULL) {
		/*
		 * Put thread back on the interrupt thread list.
		 * This was an interrupt thread, so set CPU's base SPL.
		 */
		set_base_spl();
		it->t_state = TS_FREE;
		it->t_link = cpu->cpu_intr_thread;
		cpu->cpu_intr_thread = it;
		(void) splhigh();
		(void) enable_interrupts();
		swtch();
		/*NOTREACHED*/
		panic("dosoftint_epilog: swtch returned");
	}
	it->t_link = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it;
	it->t_state = TS_FREE;
	write_tpidr_el1((uintptr_t)t);
	cpu->cpu_thread = t;
	if (t->t_flag & T_INTR_THREAD)
		t->t_intr_start = now;
	basespl = cpu->cpu_base_spl;
	pil = MAX(oldpil, basespl);
	mcpu->mcpu_pri = pil;
	syspic_intr_exit(pil);
}


/*
 * Make the interrupted thread 'to' be runnable.
 *
 * Since t->t_sp has already been saved, t->t_pc is all
 * that needs to be set in this function.
 *
 * Returns the interrupt level of the interrupt thread.
 */
int
intr_passivate(
	kthread_t *it,		/* interrupt thread */
	kthread_t *t)		/* interrupted thread */
{
	extern void _sys_rtt();

	ASSERT(it->t_flag & T_INTR_THREAD);
	ASSERT(SA(t->t_sp) == t->t_sp);

	t->t_pc = (uintptr_t)_sys_rtt;
	return (it->t_pil);
}

/*
 * Create interrupt kstats for this CPU.
 */
void
cpu_create_intrstat(cpu_t *cp)
{
	int		i;
	kstat_t		*intr_ksp;
	kstat_named_t	*knp;
	char		name[KSTAT_STRLEN];
	zoneid_t	zoneid;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (pool_pset_enabled())
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = ALL_ZONES;

	intr_ksp = kstat_create_zone("cpu", cp->cpu_id, "intrstat", "misc",
	    KSTAT_TYPE_NAMED, PIL_MAX * 2, 0, zoneid);

	/*
	 * Initialize each PIL's named kstat
	 */
	if (intr_ksp != NULL) {
		intr_ksp->ks_update = cpu_kstat_intrstat_update;
		knp = (kstat_named_t *)intr_ksp->ks_data;
		intr_ksp->ks_private = cp;
		for (i = 0; i < PIL_MAX; i++) {
			(void) snprintf(name, KSTAT_STRLEN, "level-%d-time",
			    i + 1);
			kstat_named_init(&knp[i * 2], name, KSTAT_DATA_UINT64);
			(void) snprintf(name, KSTAT_STRLEN, "level-%d-count",
			    i + 1);
			kstat_named_init(&knp[(i * 2) + 1], name,
			    KSTAT_DATA_UINT64);
		}
		kstat_install(intr_ksp);
	}
}

/*
 * Delete interrupt kstats for this CPU.
 */
void
cpu_delete_intrstat(cpu_t *cp)
{
	kstat_delete_byname_zone("cpu", cp->cpu_id, "intrstat", ALL_ZONES);
}

/*
 * Convert interrupt statistics from CPU ticks to nanoseconds and
 * update kstat.
 */
int
cpu_kstat_intrstat_update(kstat_t *ksp, int rw)
{
	kstat_named_t	*knp = ksp->ks_data;
	cpu_t		*cpup = (cpu_t *)ksp->ks_private;
	int		i;
	hrtime_t	hrt;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	for (i = 0; i < PIL_MAX; i++) {
		hrt = (hrtime_t)cpup->cpu_m.intrstat[i + 1][0];
		scalehrtime(&hrt);
		knp[i * 2].value.ui64 = (uint64_t)hrt;
		knp[(i * 2) + 1].value.ui64 = cpup->cpu_stats.sys.intr[i];
	}

	return (0);
}

/*
 * An interrupt thread is ending a time slice, so compute the interval it
 * ran for and update the statistic for its PIL.
 */
void
cpu_intr_swtch_enter(kthread_id_t t)
{
	uint64_t	interval;
	uint64_t	start;
	cpu_t		*cpu;

	ASSERT((t->t_flag & T_INTR_THREAD) != 0);
	ASSERT(t->t_pil > 0 && t->t_pil <= LOCK_LEVEL);

	/*
	 * We could be here with a zero timestamp. This could happen if:
	 * an interrupt thread which no longer has a pinned thread underneath
	 * it (i.e. it blocked at some point in its past) has finished running
	 * its handler. intr_thread() updated the interrupt statistic for its
	 * PIL and zeroed its timestamp. Since there was no pinned thread to
	 * return to, swtch() gets called and we end up here.
	 *
	 * Note that we use atomic ops below (atomic_cas_64 and
	 * atomic_add_64), which we don't use in the functions above,
	 * because we're not called with interrupts blocked, but the
	 * epilog/prolog functions are.
	 */
	if (t->t_intr_start) {
		do {
			start = t->t_intr_start;
			interval = arch_timer_count() - start;
		} while (atomic_cas_64(&t->t_intr_start, start, 0) != start);
		cpu = CPU;
		cpu->cpu_m.intrstat[t->t_pil][0] += interval;

		atomic_add_64((uint64_t *)&cpu->cpu_intracct[cpu->cpu_mstate],
		    interval);
	} else
		ASSERT(t->t_intr == NULL);
}

/*
 * An interrupt thread is returning from swtch(). Place a starting timestamp
 * in its thread structure.
 */
void
cpu_intr_swtch_exit(kthread_id_t t)
{
	uint64_t ts;

	ASSERT((t->t_flag & T_INTR_THREAD) != 0);
	ASSERT(t->t_pil > 0 && t->t_pil <= LOCK_LEVEL);

	do {
		ts = t->t_intr_start;
	} while (atomic_cas_64(&t->t_intr_start, ts, arch_timer_count()) != ts);
}

/*
 * Dispatch a high-level hardware interrupt.
 */
static void
dispatch_hilevel(uint64_t vector, uint64_t arg2 __unused)
{
	(void) enable_interrupts();
	av_dispatch_autovect(vector);
	(void) disable_interrupts();
}

/*
 * Dispatch a threaded hardware interrupt.
 */
static void
dispatch_hardint(intr_cookie_t ack, uint64_t oldipl)
{
	intr_intid_t vector = syspic_cookie_to_intid(ack);
	struct cpu *cpu = CPU;

	(void) enable_interrupts();
	av_dispatch_autovect((uint_t)vector);
	(void) disable_interrupts();

	/*
	 * Must run intr_thread_epilog() on the interrupt thread stack, since
	 * there may not be a return from it if the interrupt thread blocked.
	 */
	intr_thread_epilog(cpu, ack, oldipl);
}

/*
 * Dispatch a software interrupt.
 */
static void
dispatch_softint(uint64_t oldpil, uint64_t arg2 __unused)
{
	struct cpu *cpu = CPU;

	(void) enable_interrupts();
	av_dispatch_softvect((int)cpu->cpu_thread->t_pil);
	(void) disable_interrupts();

	/*
	 * Must run softint_epilog() on the interrupt thread stack, since
	 * there may not be a return from it if the interrupt thread blocked.
	 */
	dosoftint_epilog(cpu, oldpil);
}

/*
 * Deliver any softints the current interrupt priority allows.
 *
 * Called with interrupts disabled.
 */
void
dosoftint(struct regs *regs)
{
	struct cpu *cpu = CPU;
	int oldipl;
	caddr_t newsp;

	while (cpu->cpu_softinfo.st_pending) {
		oldipl = cpu->cpu_pri;
		newsp = dosoftint_prolog(cpu, (caddr_t)regs,
		    cpu->cpu_softinfo.st_pending, oldipl);
		/*
		 * If returned stack pointer is NULL, priority is too high
		 * to run any of the pending softints now.
		 * Break out and they will be run later.
		 */
		if (newsp == NULL)
			break;
		switch_sp_and_call(oldipl, 0, dispatch_softint, newsp);
	}
}

/*
 * Interrupt service routine, called with interrupts disabled.
 */
void
do_interrupt(struct regs *rp)
{
	struct cpu *cpu = CPU;
	int newipl, oldipl = cpu->cpu_pri;
	intr_intid_t vector;
	caddr_t newsp;
	intr_cookie_t ack;

	ASSERT(interrupts_disabled());

	cpu_idle_exit(CPU_IDLE_CB_FLAG_INTR);

	ack = syspic_iack();
	vector = syspic_cookie_to_intid(ack);

	if (syspic_is_spurious(vector))
		goto softints;

	/*
	 * Slew the interrupt priority and perform the running priority drop.
	 */
	newipl = syspic_intr_enter(vector);
	syspic_eoi(ack);

	/*
	 * If the new IPL is 0 we've hit a race, and there's no longer an
	 * interrupt handler registered for this vector, so we deactivate the
	 * interrupt and proceed to softints.
	 */
	if (newipl == 0) {
		syspic_intr_deactivate(ack);
		goto softints;
	}

	/*
	 * We have a valid hardware interrupt, process it.
	 */
	cpu->cpu_pri = newipl;

	if (newipl > LOCK_LEVEL) {
		/*
		 * High priority interrupts run on this cpu's interrupt stack.
		 *
		 * If we're not already on the interrupt stack, switch to it
		 * for the duration of the call.
		 *
		 * If we're not already on the interrupt stack we've
		 * interrupted a kernel thread, a user process while in
		 * userspace or a user process while in kernel space.
		 *
		 * If we're already on the interrupt stack we've preempted
		 * a lower level high-level hardware exception handler.
		 */
		if (hilevel_intr_prolog(cpu, newipl, oldipl, rp) == 0) {
			newsp = cpu->cpu_intr_stack;
			switch_sp_and_call(vector, 0, dispatch_hilevel, newsp);
		} else {
			dispatch_hilevel(vector, 0);
		}
		(void) hilevel_intr_epilog(cpu, newipl, oldipl, ack);
	} else {
		/*
		 * Run this interrupt in a separate thread.
		 *
		 * The stack used for running the handler is the interrupt
		 * thread's stack.  If the interrupt thread blocks it will
		 * never return here.
		 */
		newsp = intr_thread_prolog(cpu, (caddr_t)rp, newipl);
		switch_sp_and_call(ack, oldipl, dispatch_hardint, newsp);
	}

softints:
	/*
	 * Deliver any pending soft interrupts.
	 */
	if (cpu->cpu_softinfo.st_pending) {
		dosoftint(rp);
		ASSERT(interrupts_disabled());
	}
}

int
getpil(void)
{
	uint64_t s = disable_interrupts();
	int pil = CPU->cpu_m.mcpu_pri;
	restore_interrupts(s);
	return (pil);
}

static int
do_splx(int newpri)
{
	uint64_t s = disable_interrupts();

	cpu_t *cpu = CPU;
	int curpri = cpu->cpu_m.mcpu_pri;
	int basepri = cpu->cpu_base_spl;
	if (newpri < basepri)
		newpri = basepri;
	cpu->cpu_m.mcpu_pri = newpri;
	syspic_intr_exit(newpri);

	restore_interrupts(s);
	return (curpri);
}

void
splx(int newpri)
{
	do_splx(newpri);
}

int
splr(int newpri)
{
	uint64_t s = disable_interrupts();

	cpu_t *cpu = CPU;
	int curpri = cpu->cpu_m.mcpu_pri;
	if (newpri > curpri) {
		int basepri = cpu->cpu_base_spl;
		if (newpri < basepri)
			newpri = basepri;
		cpu->cpu_m.mcpu_pri = newpri;
		syspic_intr_exit(newpri);
	}

	restore_interrupts(s);
	return (curpri);
}

int
splhigh(void)
{
	return (splr(DISP_LEVEL));
}

int
splhi(void)
{
	return (splr(DISP_LEVEL));
}

int
spl6(void)
{
	return (splr(DISP_LEVEL));
}

int
spl0(void)
{
	return (do_splx(0));
}

int
splzs(void)
{
	return (do_splx(12));
}

int
spl7(void)
{
	return (splr(13));
}

int
spl8(void)
{
	return (splr(15));
}

int
spl_xcall(void)
{
	return (splr(ipltospl(XCALL_PIL)));
}

void
send_dirint(int cpuid, int irq)
{
	syspic_send_ipi_one_id(cpuid, (intr_intid_t)irq);
}
