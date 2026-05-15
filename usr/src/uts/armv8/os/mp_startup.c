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
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2026 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/cpu.h>
#include <sys/cpuid.h>
#include <sys/cpuvar.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/note.h>
#include <sys/asm_linkage.h>
#include <sys/x_call.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/vtrace.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <sys/kmem.h>
#include <sys/stack.h>
#include <sys/smp_impldefs.h>
#include <sys/machsystm.h>
#include <sys/clock.h>
#include <sys/cpc_impl.h>
#include <sys/pg.h>
#include <sys/cmt.h>
#include <sys/dtrace.h>
#include <sys/archsystm.h>
#include <sys/fp.h>
#include <sys/reboot.h>
#include <sys/kdi_machimpl.h>
#include <vm/vm_dep.h>
#include <sys/memnode.h>
#include <sys/sysmacros.h>
#include <sys/ontrap.h>
#include <sys/promif.h>
#include <sys/syspic.h>
#include <sys/platmod.h>
#include <sys/irq.h>
#include <sys/psci.h>
#include <sys/arm_features.h>
#include <sys/cpuinfo.h>


struct cpu	cpus[1];			/* CPU data */
struct cpu	*cpu[NCPU] = {&cpus[0]};	/* pointers to all CPUs */
struct cpu	*cpu_free_list;			/* list for released CPUs */
cpu_core_t	cpu_core[NCPU];			/* cpu_core structures */
cpuset_t	cpu_ready_set;
cpuset_t	mp_cpus;

static cpuset_t procset_slave, procset_master;

static struct cpu_startup_data cpu_startup_data = {
	.mair	= 0xdeadbeefdeadbeef,
	.tcr	= 0xdeadbeefdeadbeef,
	.ttbr0	= 0xdeadbeefdeadbeef,
	.ttbr1	= 0xdeadbeefdeadbeef,
	.sctlr	= 0xdeadbeefdeadbeef,
	.vbar	= 0xdeadbeefdeadbeef
};

static uint64_t secondary_vec_pa = 0xdeadbeefdeadbeef;
static uint64_t cpu_startup_data_pa = 0xdeadbeefdeadbeef;

static void
mp_startup_wait(cpuset_t *sp, processorid_t cpuid)
{
	cpuset_t tempset;

	for (tempset = *sp; !CPU_IN_SET(tempset, cpuid);
	    tempset = *(volatile cpuset_t *)sp) {
		__asm__ volatile("isb");
	}
	CPUSET_ATOMIC_DEL(*(cpuset_t *)sp, cpuid);
}

static void
mp_startup_signal(cpuset_t *sp, processorid_t cpuid)
{
	cpuset_t tempset;

	CPUSET_ATOMIC_ADD(*(cpuset_t *)sp, cpuid);
	for (tempset = *sp; CPU_IN_SET(tempset, cpuid);
	    tempset = *(volatile cpuset_t *)sp) {
		__asm__ volatile("isb");
	}
}

void
init_cpu_info(struct cpu *cp)
{
	processor_info_t *pi = &cp->cpu_type_info;

	cp->cpu_m.mcpu_midr = read_midr();
	cp->cpu_m.mcpu_revidr = read_revidr();

	/* set maximum supported CPU clock frequency */
	if (&plat_set_max_cpu_clock != NULL)
		plat_set_max_cpu_clock(cp->cpu_id);

	/* Get clock-frequency property and current frequency for the CPU. */
	if (&plat_get_cpu_clock != NULL) {
		uint64_t clk = plat_get_cpu_clock(cp->cpu_id);
		pi->pi_clock = (clk + 500000) / 1000000;
		cp->cpu_curr_clock = clk;
	} else {
		pi->pi_clock = 1000;
		cp->cpu_curr_clock = 1000 * 1000 * 1000;
	}

	strlcpy(pi->pi_processor_type, "AArch64", PI_TYPELEN);

	if (has_arm_feature(arm_features, ARM_FEAT_SME2))
		strlcat(pi->pi_fputypes, "SME2", PI_FPUTYPE);
	else if (has_arm_feature(arm_features, ARM_FEAT_SME))
		strlcat(pi->pi_fputypes, "SME", PI_FPUTYPE);
	else if (has_arm_feature(arm_features, ARM_FEAT_SVE2))
		strlcat(pi->pi_fputypes, "SVE2", PI_FPUTYPE);
	else if (has_arm_feature(arm_features, ARM_FEAT_SVE))
		strlcat(pi->pi_fputypes, "SVE", PI_FPUTYPE);
	else if (has_arm_feature(arm_features, ARM_FEAT_AdvSIMD))
		strlcat(pi->pi_fputypes, "AdvSIMD", PI_FPUTYPE);
	else if (has_arm_feature(arm_features, ARM_FEAT_FP))
		strlcat(pi->pi_fputypes, "FP", PI_FPUTYPE);
	else
		strlcat(pi->pi_fputypes, "missing", PI_FPUTYPE);

	cp->cpu_idstr = kmem_zalloc(CPU_IDSTRLEN, KM_SLEEP);
	snprintf(cp->cpu_idstr, CPU_IDSTRLEN - 1,
	    "AArch64 (midr %08lx revidr %08lx)",
	    cp->cpu_m.mcpu_midr,
	    cp->cpu_m.mcpu_revidr);

	cp->cpu_brandstr = kmem_zalloc(CPU_IDSTRLEN, KM_SLEEP);
	cpuid_brandstr(cp, cp->cpu_brandstr, CPU_IDSTRLEN);

	cp->cpu_implementer = kmem_zalloc(16, KM_SLEEP);
	cpuid_implementer(cp, cp->cpu_implementer, 16);

	cp->cpu_partname = kmem_zalloc(32, KM_SLEEP);
	cpuid_partname(cp, cp->cpu_partname, 32);

	cp->cpu_revision = kmem_zalloc(16, KM_SLEEP);
	sprintf(cp->cpu_revision, "%ld", MIDR_REVISION(cp->cpu_m.mcpu_midr));

	/* Supported frequencies */
	if (&plat_set_cpu_supp_freqs != NULL)
		plat_set_cpu_supp_freqs(cp);
	if (cp->cpu_supp_freqs == NULL)
		cpu_set_supp_freqs(cp, NULL);
}

/*
 * Dummy functions - no aarch64 platforms support dynamic cpu allocation.
 */
/*ARGSUSED*/
int
mp_cpu_configure(int cpuid)
{
	return (ENOTSUP);		/* not supported */
}

/*ARGSUSED*/
int
mp_cpu_unconfigure(int cpuid)
{
	return (ENOTSUP);		/* not supported */
}

/*
 * Power on CPU.
 */
/*ARGSUSED*/
int
mp_cpu_poweron(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (ENOTSUP);		/* not supported */
}

/*
 * Power off CPU.
 */
/*ARGSUSED*/
int
mp_cpu_poweroff(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (ENOTSUP);		/* not supported */
}

/*
 * Start CPU on user request.
 */
/* ARGSUSED */
int
mp_cpu_start(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (0);
}

/*
 * Stop CPU on user request.
 */
/* ARGSUSED */
int
mp_cpu_stop(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (0);
}

void
mp_cpu_faulted_enter(struct cpu *cp)
{
}

void
mp_cpu_faulted_exit(struct cpu *cp)
{
}

/*
 * Take the specified CPU out of participation in interrupts.
 */
int
cpu_disable_intr(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return (EBUSY);
}

/*
 * Allow the specified CPU to participate in interrupts.
 */
void
cpu_enable_intr(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	cp->cpu_flags |= CPU_ENABLE;
	ncpus_intr_enabled++;
}

/*
 * Awaken a CPU using a CPU_ON PSCI call.
 */
static int
wakeup_cpu(cpu_t *cp)
{
	VERIFY3U(cpu_startup_data.ttbr1, !=, 0xdeadbeefdeadbeef);
	VERIFY3U(cpu_startup_data_pa, !=, 0xdeadbeefdeadbeef);
	VERIFY3U(secondary_vec_pa, !=, 0xdeadbeefdeadbeef);
	VERIFY3P(cp, !=, NULL);
	VERIFY3P(cp->cpu_m.mcpu_ci, !=, NULL);
	VERIFY3U(cp->cpu_m.mcpu_ci->ci_ppver, ==, CPUINFO_ENABLE_METHOD_PSCI);

	if (psci_cpu_on(cp->cpu_m.affinity,
	    secondary_vec_pa, cpu_startup_data_pa) != PSCI_SUCCESS) {
		return (-1);
	}

	return (0);
}

void
unlock_oslock(void)
{
	__asm__ __volatile__("msr oslar_el1, %0"
	    :
	    :"r" (0)
	    :"memory");
}

static void
mp_startup_boot(void)
{
	cpu_t *cp = CPU;

	extern void cpu_event_init_cpu(cpu_t *);
	extern void exception_vector(void);
	extern void kdi_exception_vector(void);
	extern void kdi_restore_debugging_state(void);
	extern void kdi_cpu_init(void);

	/* Let the control CPU continue into tsc_sync_master() */
	mp_startup_signal(&procset_slave, cp->cpu_id);

	/*
	 * If kmdb is loaded we have to do the equivalent of
	 * kdi_cpu_activate() to each appearing CPU, and sync the debug
	 * registers.
	 */
	if (boothowto & RB_KMDB) {
		kdi_cpu_init();
		kdi_restore_debugging_state();
	} else {
		write_vbar((uintptr_t)exception_vector);
	}

	isb();

	/* Set up the system interrupt controller for the new additional CPU */
	syspic_cpu_init(cp);

	/*
	 * Enable interrupts with spl set to LOCK_LEVEL. LOCK_LEVEL is the
	 * highest level at which a routine is permitted to block on
	 * an adaptive mutex (allows for cpu poke interrupt in case
	 * the cpu is blocked on a mutex and halts). Setting LOCK_LEVEL blocks
	 * device interrupts that may end up in the hat layer issuing cross
	 * calls before CPU_READY is set.
	 */
	splx(ipltospl(LOCK_LEVEL));

	/*
	 * We can touch cpu_flags here without acquiring the cpu_lock here
	 * because the cpu_lock is held by the control CPU which is running
	 * mp_start_cpu_common().
	 * Need to clear CPU_QUIESCED flag before calling any function which
	 * may cause thread context switching, such as kmem_alloc() etc.
	 * The idle thread checks for CPU_QUIESCED flag and loops for ever if
	 * it's set. So the startup thread may have no chance to switch back
	 * again if it's switched away with CPU_QUIESCED set.
	 */
	cp->cpu_flags &= ~(CPU_POWEROFF | CPU_QUIESCED);

	uchar_t our_features[BT_SIZEOFMAP(NUM_ARM_FEATURES)];
	bzero(our_features, BT_SIZEOFMAP(NUM_ARM_FEATURES));

	cpuid_gather_arm_features(our_features);

	/*
	 * All PEs in the system much have the same features.
	 *
	 * XXXARM: Note this currently depends on arm_features not having
	 * non-PE features in it yet, but we can't assert that.
	 */
	if (compare_arm_features(arm_features, our_features) == B_FALSE) {
		cmn_err(CE_CONT, "cpu%d: features\n", cp->cpu_id);
		print_arm_features(our_features);
		cmn_err(CE_PANIC, "cpu%d: mismatch\n", cp->cpu_id);
	}

	init_cpu_info(cp);

	cp->cpu_flags |= CPU_RUNNING | CPU_EXISTS;

	cpu_event_init_cpu(cp);

	/*
	 * Enable preemption here so that contention for any locks acquired
	 * later in mp_startup_common may be preempted if the thread owning
	 * those locks is continuously executing on other CPUs (for example,
	 * this CPU must be preemptible to allow other CPUs to pause it during
	 * their startup phases).  It's safe to enable preemption here because
	 * the CPU state is pretty-much fully constructed.
	 */
	curthread->t_preempt = 0;

	/* The base spl should still be at LOCK LEVEL here */
	ASSERT(cp->cpu_base_spl == ipltospl(LOCK_LEVEL));
	set_base_spl();		/* Restore the spl to its proper value */
	clear_daif(DAIF_SETCLEAR_IRQ);

	pghw_physid_create(cp);
	/*
	 * Delegate initialization tasks, which need to access the cpu_lock,
	 * to mp_start_cpu_common() because we can't acquire the cpu_lock here
	 * during CPU DR operations.
	 */
	mp_startup_signal(&procset_slave, cp->cpu_id);
	mp_startup_wait(&procset_master, cp->cpu_id);
	pg_cmt_cpu_startup(cp);

	mutex_enter(&cpu_lock);
	cp->cpu_flags &= ~CPU_OFFLINE;
	cp->cpu_flags |= CPU_READY;
	cpu_enable_intr(cp);
	cpu_add_active(cp);
	mutex_exit(&cpu_lock);

	/* Enable interrupts */
	(void) spl0();

	/*
	 * Setting the bit in cpu_ready_set must be the last operation in
	 * processor initialization; the boot CPU will continue to boot once
	 * it sees this bit set for all active CPUs.
	 */
	CPUSET_ATOMIC_ADD(cpu_ready_set, cp->cpu_id);

	cmn_err(CE_CONT, "?cpu%d: %s\n", cp->cpu_id, cp->cpu_brandstr);
	cmn_err(CE_CONT, "?cpu%d initialization complete - online\n",
	    cp->cpu_id);

	unlock_oslock();
	write_cntkctl(read_cntkctl() | 0x3);

	/*
	 * Now we are done with the startup thread, so free it up.
	 */
	thread_exit();
	panic("mp_startup: cannot return");
	/*NOTREACHED*/
}

static void
mp_cpu_configure_common(struct cpuinfo *ci)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(ci->ci_id < NCPU && cpu[ci->ci_id] == NULL);
	extern void idle();

	struct cpu *cp;
	kthread_id_t tp;
	caddr_t	sp;

	/*
	 * CPU structure basics.
	 */
	cp = kmem_zalloc(sizeof (*cp), KM_SLEEP);
	cp->cpu_id = ci->ci_id;
	cp->cpu_self = cp;
	cp->cpu_lwp = NULL;
	cp->cpu_m.mcpu_ci = ci;
	cp->cpu_m.affinity = ci->ci_mpidr;
	cp->cpu_base_spl = ipltospl(LOCK_LEVEL);

	/*
	 * Hook into the scheduler and VM subsystem.
	 */
	disp_cpu_init(cp);
	cpu_vm_data_init(cp);

	/*
	 * Set up the startup thread for this CPU.
	 */
	tp = thread_create(NULL, 0, NULL, NULL, 0, &p0, TS_STOPPED,
	    maxclsyspri);
	THREAD_ONPROC(tp, cp);

	tp->t_preempt = 1;
	tp->t_bound_cpu = cp;
	tp->t_affinitycnt = 1;
	tp->t_cpu = cp;
	tp->t_disp_queue = cp->cpu_disp;

	sp = tp->t_stk;
	tp->t_sp = (uintptr_t)(sp - MINFRAME);
	tp->t_sp -= STACK_ENTRY_ALIGN;		/* fake a call */
	tp->t_pc = (uintptr_t)mp_startup_boot;

	/*
	 * Hook the startup thread up as the current thread.
	 */
	cp->cpu_thread = tp;
	cp->cpu_dispthread = tp;
	cp->cpu_dispatch_pri = DISP_PRIO(tp);

	/*
	 * Set up the idle thread for this CPU.
	 */
	tp = thread_create(NULL, PAGESIZE, idle, NULL, 0, &p0, TS_ONPROC, -1);
	cp->cpu_idle_thread = tp;

	tp->t_preempt = 1;
	tp->t_bound_cpu = cp;
	tp->t_affinitycnt = 1;
	tp->t_cpu = cp;
	tp->t_disp_queue = cp->cpu_disp;

	/*
	 * Finish CPU hookup.
	 */
	pg_cpu_bootstrap(cp);
	kcpc_hw_init(cp);
	cpu_intr_alloc(cp, NINTR_THREADS);
	cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_POWEROFF;
	cpu_set_state(cp);

	/*
	 * Finally, add the CPU to the CPU array.
	 *
	 * This is added at index cp->cpu_id, which corresponds to the
	 * ci->ci_id value in the passed-in cpuinfo.
	 */
	cpu_add_unit(cp);
}

int
mach_cpucontext_init(void)
{
	pfn_t pfn;
	uintptr_t va;
	uint64_t pa_hvc_stub;
	uintptr_t addr;
	size_t data_line_size;
	extern void secondary_vec_start(void);
	extern void hyp_stub_vectors(void);

	va = (uintptr_t)hyp_stub_vectors;
	if ((pfn = hat_getpfnum(kas.a_hat, (caddr_t)va)) == PFN_INVALID) {
		return (-1);
	}
	pa_hvc_stub = ptob(pfn) | (va & MMU_PAGEOFFSET);

	va = (uintptr_t)secondary_vec_start;
	if ((pfn = hat_getpfnum(kas.a_hat, (caddr_t)va)) == PFN_INVALID) {
		return (-1);
	}
	secondary_vec_pa = ptob(pfn) | (va & MMU_PAGEOFFSET);

	va = (uintptr_t)&cpu_startup_data;
	if ((pfn = hat_getpfnum(kas.a_hat, (caddr_t)va)) == PFN_INVALID) {
		return (-1);
	}
	cpu_startup_data_pa = ptob(pfn) | (va & MMU_PAGEOFFSET);

	cpu_startup_data.mair = read_mair();
	cpu_startup_data.tcr = read_tcr();
	cpu_startup_data.ttbr0 = read_ttbr0();
	cpu_startup_data.ttbr1 = read_ttbr1();
	cpu_startup_data.sctlr = read_sctlr();
	cpu_startup_data.vbar = pa_hvc_stub;

	data_line_size = CTR_DMINLINE_SIZE(read_ctr_el0());
	for (addr = P2ALIGN((uintptr_t)&cpu_startup_data, data_line_size);
	    addr < (uintptr_t)&cpu_startup_data + sizeof (cpu_startup_data);
	    addr += data_line_size) {
		flush_data_cache(addr);
	}
	dsb(ish);

	return (0);
}

static int
mp_start_cpu_common(cpu_t *cp)
{
	int delays;
	int error = 0;
	cpuset_t tempset;
	processorid_t cpuid;

	ASSERT(cp != NULL);
	cpuid = cp->cpu_id;

	error = wakeup_cpu(cp);
	if (error != 0) {
		cmn_err(CE_WARN,
		    "cpu%d: failed to start, error %d", cp->cpu_id, error);
		return (error);
	}

	for (delays = 0, tempset = procset_slave; !CPU_IN_SET(tempset, cpuid);
	    delays++) {
		if (delays == 500) {
			/*
			 * After five seconds, things are probably looking
			 * a bit bleak - explain the hang.
			 */
			cmn_err(CE_NOTE, "cpu%d: started, "
			    "but not running in the kernel yet", cpuid);
		} else if (delays > 2000) {
			/*
			 * We waited at least 20 seconds, bail ..
			 */
			error = ETIMEDOUT;
			cmn_err(CE_WARN, "cpu%d: timed out", cpuid);
			return (error);
		}

		/*
		 * wait at least 10ms, then check again..
		 */
		delay(USEC_TO_TICK_ROUNDUP(10000));
		tempset = *((volatile cpuset_t *)&procset_slave);
	}
	CPUSET_ATOMIC_DEL(procset_slave, cpuid);

	mp_startup_wait(&procset_slave, cpuid);

	(void) pg_cpu_init(cp, B_FALSE);
	cpu_set_state(cp);
	mp_startup_signal(&procset_master, cpuid);

	return (0);
}

static int
start_cpu(struct cpuinfo *ci)
{
	int error = 0;
	cpuset_t tempset;

	ASSERT(ci->ci_id != 0);

	error = mp_start_cpu_common(cpu[ci->ci_id]);
	if (error != 0) {
		return (error);
	}

	mutex_exit(&cpu_lock);
	tempset = cpu_ready_set;
	while (!CPU_IN_SET(tempset, ci->ci_id)) {
		drv_usecwait(1);
		tempset = *((volatile cpuset_t *)&cpu_ready_set);
	}
	mutex_enter(&cpu_lock);

	return (0);
}

void
start_other_cpus(int flag __unused)
{
	/*
	 * XXXARM: Note that while we're `start_other_cpus` we're running on
	 * the boot CPU and initializing _for_ the boot CPU right now,
	 * confusingly.
	 */
	cpuid_gather_arm_features(arm_features);
	cpuid_features_to_hwcap(arm_features, &auxv_hwcap, &auxv_hwcap_2,
	    &auxv_hwcap_3);

	init_cpu_info(CPU);

	cmn_err(CE_CONT, "?cpu%d: %s\n", CPU->cpu_id, CPU->cpu_brandstr);
	print_arm_features(arm_features);

	unlock_oslock();
	write_cntkctl(read_cntkctl() | 0x3);

	processorid_t bootcpu = CPU->cpu_id;

	CPUSET_DEL(mp_cpus, bootcpu);
	CPUSET_ADD(cpu_ready_set, bootcpu);

	cpu_pause_init();

	xc_init();

	if (mach_cpucontext_init() != 0)
		prom_panic("mach_cpucontext_init fail");

	affinity_set(CPU_CURRENT);

	mutex_enter(&cpu_lock);

	/*
	 * Set up CPU structures for each CPU we're going to start.
	 */
	for (struct cpuinfo *ci = cpuinfo_first_enabled();
	    ci != cpuinfo_end(); ci = cpuinfo_next_enabled(ci)) {
		if (ci->ci_id == bootcpu || !CPU_IN_SET(mp_cpus, ci->ci_id))
			continue;
		mp_cpu_configure_common(ci);
	}

	/*
	 * Start any enabled non-boot CPUs.
	 */
	for (struct cpuinfo *ci = cpuinfo_first_enabled();
	    ci != cpuinfo_end(); ci = cpuinfo_next_enabled(ci)) {
		if (ci->ci_id == bootcpu || !CPU_IN_SET(mp_cpus, ci->ci_id))
			continue;
		/*
		 * XXXARM: The error path here needs to be tightened up, as
		 * when this fails we will crash shortly thereafter.
		 */
		if (start_cpu(ci) != 0)
			CPUSET_DEL(mp_cpus, ci->ci_id);
		cpu_state_change_notify(ci->ci_id, CPU_SETUP);
		mutex_exit(&cpu_lock);
		mutex_enter(&cpu_lock);
	}

	mutex_exit(&cpu_lock);

	affinity_clear();
}
