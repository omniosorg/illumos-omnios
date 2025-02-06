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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/modctl.h>
#include <sys/clock.h>
#include <sys/archsystm.h>
#include <sys/stack.h>
#include <sys/systm.h>
#include <sys/panic.h>
#include <sys/irq.h>
#include <sys/privregs.h>
#include <sys/dumphdr.h>
#include <sys/sunddi.h>
#include <sys/machparam.h>
#include <sys/dtrace.h>
#include <sys/memlist.h>
#include <sys/clock_impl.h>
#include <sys/smp_impldefs.h>
#include <sys/hold_page.h>
#include <sys/callb.h>
#include <sys/controlregs.h>
#include <sys/x_call.h>
#include <sys/xc_levels.h>
#include <sys/consdev.h>
#include <sys/arch_timer.h>
#include <sys/reboot.h>
#include <sys/kdi_machimpl.h>

#include <c2/audit.h>

int maxphys = MMU_PAGESIZE * 16;	/* 128k */
int klustsize = MMU_PAGESIZE * 16;	/* 128k */

hrtime_t hres_last_tick;
volatile int hres_lock;
hrtime_t hrtime_base;

int64_t timedelta;
int64_t hrestime_adj;
// 2015/11/11 00:00 にしておく
volatile timestruc_t hrestime = { .tv_sec = 1447167600 };
int gethrtime_hires = 0;
char panicbuf[PANICBUFSIZE];
static cpuset_t	panic_idle_enter;
#define	PANIC_IDLE_MAXWAIT	0x100

int vac;

/*
 * Platform callback prior to writing crash dump.
 */
/*ARGSUSED*/
void
panic_dump_hw(int spl)
{
	/* Nothing to do here */
}

/*ARGSUSED*/
int
blacklist(int cmd, const char *scheme, nvlist_t *fmri, const char *class)
{
	return (ENOTSUP);
}

/*
 * The underlying console output routines are protected by raising IPL in case
 * we are still calling into the early boot services.  Once we start calling
 * the kernel console emulator, it will disable interrupts completely during
 * character rendering (see sysp_putchar, for example).  Refer to the comments
 * and code in common/os/console.c for more information on these callbacks.
 */
/*ARGSUSED*/
int
console_enter(int busy)
{
	return (splzs());
}

/*ARGSUSED*/
void
console_exit(int busy, int spl)
{
	splx(spl);
}

u_longlong_t
randtick(void)
{
	return (arch_timer_count());
}

void
tenmicrosec(void)
{
	extern int gethrtime_hires;

	if (gethrtime_hires) {
		hrtime_t end = gethrtime() + (10 * (NANOSEC / MICROSEC));
		while (gethrtime() < end)
			SMT_PAUSE();
	} else {
		uint64_t timer_freq = arch_timer_freq();
		uint64_t end_count = arch_timer_count() + timer_freq /
		    (MICROSEC / 10);

		while (arch_timer_count() < end_count)
			SMT_PAUSE();
	}
}

/*
 * Enter debugger.  Called when the user types ctrl-alt-d or whenever
 * code wants to enter the debugger and possibly resume later.
 */
void
debug_enter(char *msg)		/* message to print, possibly NULL */
{
	if (dtrace_debugger_init != NULL)
		(*dtrace_debugger_init)();

	if (msg != NULL || (boothowto & RB_DEBUG))
		prom_printf("\n");

	if (msg != NULL)
		prom_printf("%s\n", msg);

	if (boothowto & RB_DEBUG)
		kmdb_enter();

	if (dtrace_debugger_fini != NULL)
		(*dtrace_debugger_fini)();
}

/*
 * This routine is almost correct now, but not quite.  It still needs the
 * equivalent concept of "hres_last_tick", just like on the sparc side.
 * The idea is to take a snapshot of the hi-res timer while doing the
 * hrestime_adj updates under hres_lock in locore, so that the small
 * interval between interrupt assertion and interrupt processing is
 * accounted for correctly.  Once we have this, the code below should
 * be modified to subtract off hres_last_tick rather than hrtime_base.
 *
 * I'd have done this myself, but I don't have source to all of the
 * vendor-specific hi-res timer routines (grrr...).  The generic hook I
 * need is something like "gethrtime_unlocked()", which would be just like
 * gethrtime() but would assume that you're already holding CLOCK_LOCK().
 * This is what the GET_HRTIME() macro is for on sparc (although it also
 * serves the function of making time available without a function call
 * so you don't take a register window overflow while traps are disabled).
 */
void
pc_gethrestime(timespec_t *tp)
{
	int lock_prev;
	timestruc_t now;
	int nslt;		/* nsec since last tick */
	int adj;		/* amount of adjustment to apply */

loop:
	lock_prev = hres_lock;
	now = hrestime;
	nslt = (int)(gethrtime() - hres_last_tick);
	if (nslt < 0) {
		/*
		 * nslt < 0 means a tick came between sampling
		 * gethrtime() and hres_last_tick; restart the loop
		 */

		goto loop;
	}
	now.tv_nsec += nslt;
	if (hrestime_adj != 0) {
		if (hrestime_adj > 0) {
			adj = (nslt >> ADJ_SHIFT);
			if (adj > hrestime_adj)
				adj = (int)hrestime_adj;
		} else {
			adj = -(nslt >> ADJ_SHIFT);
			if (adj < hrestime_adj)
				adj = (int)hrestime_adj;
		}
		now.tv_nsec += adj;
	}
	while ((unsigned long)now.tv_nsec >= NANOSEC) {

		/*
		 * We might have a large adjustment or have been in the
		 * debugger for a long time; take care of (at most) four
		 * of those missed seconds (tv_nsec is 32 bits, so
		 * anything >4s will be wrapping around).  However,
		 * anything more than 2 seconds out of sync will trigger
		 * timedelta from clock() to go correct the time anyway,
		 * so do what we can, and let the big crowbar do the
		 * rest.  A similar correction while loop exists inside
		 * hres_tick(); in all cases we'd like tv_nsec to
		 * satisfy 0 <= tv_nsec < NANOSEC to avoid confusing
		 * user processes, but if tv_sec's a little behind for a
		 * little while, that's OK; time still monotonically
		 * increases.
		 */

		now.tv_nsec -= NANOSEC;
		now.tv_sec++;
	}
	if ((hres_lock & ~1) != lock_prev)
		goto loop;

	*tp = now;
}

void
gethrestime_lasttick(timespec_t *tp)
{
	int s;

	s = hr_clock_lock();
	*tp = hrestime;
	hr_clock_unlock(s);
}

time_t
gethrestime_sec(void)
{
	timestruc_t now;

	gethrestime(&now);
	return (now.tv_sec);
}

int
dtrace_panic_trigger(int *tp)
{
	if (atomic_swap_uint((uint_t *)tp, 0xdefacedd) == 0)
		return (1);
	return (0);
}

/*
 * get_cpu_mstate() is passed an array of timestamps, NCMSTATES
 * long, and it fills in the array with the time spent on cpu in
 * each of the mstates, where time is returned in nsec.
 *
 * No guarantee is made that the returned values in times[] will
 * monotonically increase on sequential calls, although this will
 * be true in the long run. Any such guarantee must be handled by
 * the caller, if needed. This can happen if we fail to account
 * for elapsed time due to a generation counter conflict, yet we
 * did account for it on a prior call (see below).
 *
 * The complication is that the cpu in question may be updating
 * its microstate at the same time that we are reading it.
 * Because the microstate is only updated when the CPU's state
 * changes, the values in cpu_intracct[] can be indefinitely out
 * of date. To determine true current values, it is necessary to
 * compare the current time with cpu_mstate_start, and add the
 * difference to times[cpu_mstate].
 *
 * This can be a problem if those values are changing out from
 * under us. Because the code path in new_cpu_mstate() is
 * performance critical, we have not added a lock to it. Instead,
 * we have added a generation counter. Before beginning
 * modifications, the counter is set to 0. After modifications,
 * it is set to the old value plus one.
 *
 * get_cpu_mstate() will not consider the values of cpu_mstate
 * and cpu_mstate_start to be usable unless the value of
 * cpu_mstate_gen is both non-zero and unchanged, both before and
 * after reading the mstate information. Note that we must
 * protect against out-of-order loads around accesses to the
 * generation counter. Also, this is a best effort approach in
 * that we do not retry should the counter be found to have
 * changed.
 *
 * cpu_intracct[] is used to identify time spent in each CPU
 * mstate while handling interrupts. Such time should be reported
 * against system time, and so is subtracted out from its
 * corresponding cpu_acct[] time and added to
 * cpu_acct[CMS_SYSTEM].
 */
void
get_cpu_mstate(cpu_t *cpu, hrtime_t *times)
{
	int i;
	hrtime_t now, start;
	uint16_t gen;
	uint16_t state;
	hrtime_t intracct[NCMSTATES];

	/*
	 * Load all volatile state under the protection of membar.
	 * cpu_acct[cpu_mstate] must be loaded to avoid double counting
	 * of (now - cpu_mstate_start) by a change in CPU mstate that
	 * arrives after we make our last check of cpu_mstate_gen.
	 */

	now = gethrtime_unscaled();
	gen = cpu->cpu_mstate_gen;

	membar_consumer();	/* guarantee load ordering */
	start = cpu->cpu_mstate_start;
	state = cpu->cpu_mstate;
	for (i = 0; i < NCMSTATES; i++) {
		intracct[i] = cpu->cpu_intracct[i];
		times[i] = cpu->cpu_acct[i];
	}
	membar_consumer();	/* guarantee load ordering */

	if (gen != 0 && gen == cpu->cpu_mstate_gen && now > start)
		times[state] += now - start;

	for (i = 0; i < NCMSTATES; i++) {
		if (i == CMS_SYSTEM)
			continue;
		times[i] -= intracct[i];
		if (times[i] < 0) {
			intracct[i] += times[i];
			times[i] = 0;
		}
		times[CMS_SYSTEM] += intracct[i];
		scalehrtime(&times[i]);
	}
	scalehrtime(&times[CMS_SYSTEM]);
}

/*
 * Initialize a kernel thread's stack
 */
caddr_t
thread_stk_init(caddr_t stk)
{
	ASSERT(((uintptr_t)stk & (STACK_ALIGN - 1)) == 0);
	return (stk - SA(MINFRAME));
}

caddr_t
lwp_stk_init(klwp_t *lwp, caddr_t stk)
{
	caddr_t oldstk;
	struct pcb *pcb = &lwp->lwp_pcb;

	oldstk = stk;
	stk -= SA(sizeof (struct regs) + SA(MINFRAME));
	stk = (caddr_t)((uintptr_t)stk & ~(STACK_ALIGN - 1ul));
	bzero(stk, oldstk - stk);
	lwp->lwp_regs = (void *)(stk + SA(MINFRAME));

	return (stk);
}

void
lwp_stk_fini(klwp_t *lwp)
{}

void
lwp_fp_init(klwp_t *lwp)
{}

pgcnt_t
num_phys_pages()
{
	pgcnt_t npages = 0;
	struct memlist *mp;

	for (mp = phys_install; mp != NULL; mp = mp->ml_next)
		npages += mp->ml_size >> PAGESHIFT;

	return (npages);
}

uint_t dump_plat_mincpu_default = DUMP_PLAT_AARCH64_MINCPU;

int
dump_plat_addr()
{
	return (0);
}

void
dump_plat_pfn()
{
}

int
dump_plat_data(void *dump_cbuf)
{
	return (0);
}

/*
 * If we're not the panic CPU, we wait in panic_idle for reboot.
 */
void
panic_idle(void)
{
	/*
	 * XXXARM: If we drop the SPL to CLOCK_LEVEL here we will take
	 * interrupts on this cpu as it spins in panic idle, because
	 * CLOCK_LEVEL is lower than both XC_HI_PIL and CBE_HIGH_PIL, we will
	 * take a nested interrupt from the cyclic back end at a lower level
	 * and trip an assertion.
	 *
	 * However, if we instead drop the SPL to the max of the running level
	 * and CLOCK_LEVEL, that level will also be XC_HI_PIL and nothing will
	 * happen, and all interrupts will remain masked, which is also bad.
	 *
	 * I _think_ we maybe dropping this so a keyboard can break into the
	 * debugger, but in that case I am not sure what keeps the cyclic
	 * backend away from us on other platforms.  This might represent a
	 * bug in the AArch64 cyclic backend.
	 *
	 * At the moment we thus drop to CBE_HIGH_PIL, which blocks the lower
	 * priority CBE interrupt coming in on top of us, but _allows_ another
	 * XC_HI_PIL xcall (such as the one we make to _also_ stop the CPUs to
	 * reboot).
	 */
	splx(ipltospl(CBE_HIGH_PIL));

	(void) setjmp(&curthread->t_pcb);

	/*
	 * XXXARM: This is a hack because our xcalls are not great right now.
	 * If we kick a cpu into a function which spins (like this), we never
	 * get chance to ack the xcall, and the caller waits for us forever.
	 *
	 * To break free of this, for right now, we ack the xcall ourselves as
	 * we know this will always happen to us.
	 */
	CPU->cpu_m.xc_ack = 1;
	dsb(ish);

	dumpsys_helper();

	/*
	 * XXXARM: We should have some symbolic way to say WFI, on intel it's
	 * i86_halt which does 'sti; hlt'
	 */
	for (;;)
		__asm__ __volatile__("wfi":::"memory");
}

/*
 * Stop the other CPUs by cross-calling them and forcing them to enter
 * the panic_idle() loop above.
 */
/*ARGSUSED*/
void
panic_stopcpus(cpu_t *cp, kthread_t *t, int spl)
{
	processorid_t	i;
	cpuset_t	xcset;

	(void) splzs();

	CPUSET_ALL_BUT(xcset, cp->cpu_id);
	xc_call(0, 0, 0, CPUSET2BV(xcset), (xc_func_t)panic_idle);

	for (i = 0; i < NCPU; i++) {
		if (i != cp->cpu_id && cpu[i] != NULL &&
		    (cpu[i]->cpu_flags & CPU_EXISTS))
			cpu[i]->cpu_flags |= CPU_QUIESCED;
	}
}

void
panic_enter_hw(int spl)
{
	/* Nothing to do here */
}

/*
 * Platform-specific code to execute after panicstr is set: we invoke
 * the PSM entry point to indicate that a panic has occurred.
 */
/*ARGSUSED*/
void
panic_quiesce_hw(panic_data_t *pdp)
{
}

int
panic_trigger(int *tp)
{
	if (atomic_swap_uint((uint_t *)tp, 0xdefacedd) == 0)
		return (1);
	return (0);
}

/*
 * set_idle_cpu is called from idle() when a CPU becomes idle.
 */
/*LINTED: static unused */
static uint_t last_idle_cpu;

/*ARGSUSED*/
void
set_idle_cpu(int cpun)
{
	last_idle_cpu = cpun;
}

/*
 * unset_idle_cpu is called from idle() when a CPU is no longer idle.
 */
/*ARGSUSED*/
void
unset_idle_cpu(int cpun)
{
}

/*
 * "Enter monitor."  Called via cross-call from stop_other_cpus().
 */
static int
mach_cpu_halt(xc_arg_t arg1 __unused, xc_arg_t arg2 __unused,
    xc_arg_t arg3 __unused)
{
	/*
	 * XXXARM: As in panic_idle is a hack because our xcalls are not great
	 * right now.  If we kick a cpu into a function which spins (like
	 * this), we never get chance to ack the xcall, and the caller waits
	 * for us forever.
	 *
	 * To break free of this, for right now, we ack the xcall ourselves as
	 * we know this will always happen to us.
	 */
	CPU->cpu_m.xc_ack = 1;

	for (;;)
		__asm__ volatile("wfe":::"memory");

	return (0);
}

static void
stop_other_cpus(void)
{
	cpuset_t xcset;

	CPUSET_ALL_BUT(xcset, CPU->cpu_id);
	xc_call_nowait(0, 0, 0, xcset, mach_cpu_halt);
}

/*
 * Halt the machine and return to the monitor
 */
void
halt(char *s)
{
	stop_other_cpus();	/* send stop signal to other CPUs */
	if (s)
		prom_printf("(%s) \n", s);
	prom_exit_to_mon();
	/*NOTREACHED*/
}

void
mdboot(int cmd, int fcn, char *mdep, boolean_t invoke_cb)
{
	if (!panicstr) {
		kpreempt_disable();
		affinity_set(CPU_CURRENT);
	}

	/*
	 * XXX - rconsvp is set to NULL to ensure that output messages
	 * are sent to the underlying "hardware" device using the
	 * monitor's printf routine since we are in the process of
	 * either rebooting or halting the machine.
	 */
	rconsvp = NULL;

	/* make sure there are no more changes to the device tree */
	devtree_freeze();

	if (invoke_cb)
		(void) callb_execute_class(CB_CL_MDBOOT, 0);

	/*
	 * Clear any unresolved UEs from memory.
	 */
	page_retire_mdboot();

	/*
	 * try and reset leaf devices.  reset_leaves() should only
	 * be called when there are no other threads that could be
	 * accessing devices
	 */
	reset_leaves();

	if (fcn == AD_HALT) {
		halt((char *)NULL);
	} else if (fcn == AD_POWEROFF) {
		stop_other_cpus();
		prom_power_off();
	} else {
		stop_other_cpus();
		prom_reboot("");
	}
	/* MAYBE REACHED */
}

/* mdpreboot - may be called prior to mdboot while root fs still mounted */
/*ARGSUSED*/
void
mdpreboot(int cmd, int fcn, char *mdep)
{
}

/*
 * These function are currently unused on aarch64.
 */
/*ARGSUSED*/
void
lwp_attach_brand_hdlrs(klwp_t *lwp)
{}

/*ARGSUSED*/
void
lwp_detach_brand_hdlrs(klwp_t *lwp)
{}

static ddi_softint_hdl_impl_t lbolt_softint_hdl =
	{0, 0, NULL, NULL, 0, NULL, NULL, NULL};
void
lbolt_softint_add(void)
{
	(void) add_avsoftintr((void *)&lbolt_softint_hdl, LOCK_LEVEL,
	    (avfunc)lbolt_ev_to_cyclic, "lbolt_ev_to_cyclic", NULL, NULL);
}

void
lbolt_softint_post(void)
{
	(*setsoftint)(CBE_LOCK_PIL, lbolt_softint_hdl.ih_pending);
}

/*
 * void
 * hres_tick(void)
 *	Tick process for high resolution timer, called once per clock tick.
 */
void
hres_tick(void)
{
	hrtime_t now;
	hrtime_t diff;
	int s;

	now = gethrtime();
	s = hr_clock_lock();
	diff = now - hres_last_tick;
	hrtime_base += diff;
	hrestime.tv_nsec += diff;
	hres_last_tick = now;
	__adj_hrestime();
	hr_clock_unlock(s);
}

void
kadb_uses_kernel()
{}

void
abort_sequence_enter(char *msg)
{
	if (abort_enable == 0) {
		if (AU_ZONE_AUDITING(GET_KCTX_GZ))
			audit_enterprom(0);
		return;
	}

	if (AU_ZONE_AUDITING(GET_KCTX_GZ))
		audit_enterprom(1);

	debug_enter(msg);

	if (AU_ZONE_AUDITING(GET_KCTX_GZ))
		audit_exitprom(1);
}

void
progressbar_key_abort(ldi_ident_t li)
{}

void
plat_idle_enter(processorid_t cpun)
{
}

void
plat_idle_exit(processorid_t cpun)
{
}

void
splash_key_abort(ldi_ident_t li)
{
}

int
plat_mem_do_mmio(struct uio *uio, enum uio_rw rw)
{
	return (ENOTSUP);
}

pfn_t
impl_obmem_pfnum(pfn_t pf)
{
	return (pf);
}

void
do_hotinlines(struct module *mp)
{
}
