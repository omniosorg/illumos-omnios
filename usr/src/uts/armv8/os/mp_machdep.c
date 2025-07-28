
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
 * Copyright 2024 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

#define	PSMI_1_7
#include <sys/smp_impldefs.h>
#include <sys/cmn_err.h>
#include <sys/strlog.h>
#include <sys/clock.h>
#include <sys/debug.h>
#include <sys/cpupart.h>
#include <sys/cpuvar.h>
#include <sys/cpu_event.h>
#include <sys/cmt.h>
#include <sys/cpu.h>
#include <sys/disp.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/memlist.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/cpu_pm.h>
#include <sys/controlregs.h>
#include <sys/irq.h>
#include <sys/cpuinfo.h>

extern void return_instr(void);

uint_t cp_haltset_fanout = 0;
int (*addintr)(void *, int, avfunc, char *, int, caddr_t, caddr_t, uint64_t *,
    dev_info_t *) = NULL;
void (*remintr)(void *, int, avfunc, int) = NULL;
void (*setsoftint)(int, struct av_softinfo *) =
	(void (*)(int, struct av_softinfo *))return_instr;
void (*kdisetsoftint)(int, struct av_softinfo *) =
	(void (*)(int, struct av_softinfo *))return_instr;
int (*slvltovect)(int) = (int (*)(int))return_instr;

static int
mach_softlvl_to_vect(int ipl)
{
	setsoftint = av_set_softint_pending;
	kdisetsoftint = kdi_av_set_softint_pending;

	return (-1);
}

int
pg_plat_hw_shared(cpu_t *cp, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CHIP:
		return (1);
	case PGHW_CACHE:
		return (1);
	default:
		return (0);
	}
}

/*
 * Compare two CPUs and see if they have a pghw_type_t sharing relationship
 * If pghw_type_t is an unsupported hardware type, then return -1
 */
int
pg_plat_cpus_share(cpu_t *cpu_a, cpu_t *cpu_b, pghw_type_t hw)
{
	id_t pgp_a, pgp_b;

	pgp_a = pg_plat_hw_instance_id(cpu_a, hw);
	pgp_b = pg_plat_hw_instance_id(cpu_b, hw);

	if (pgp_a == -1 || pgp_b == -1)
		return (-1);

	return (pgp_a == pgp_b);
}


/*
 * Return a physical instance identifier for known hardware sharing
 * relationships
 */
id_t
pg_plat_hw_instance_id(cpu_t *cpu, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CACHE:
		return (read_mpidr() & 0xFF);
	case PGHW_CHIP:
		return (((read_mpidr() >> 16) |
		    (read_mpidr() >> 8)) & 0xFFFFFF);
	default:
		return (-1);
	}
}

/*
 * Override the default CMT dispatcher policy for the specified
 * hardware sharing relationship
 */
pg_cmt_policy_t
pg_plat_cmt_policy(pghw_type_t hw)
{
	switch (hw) {
	case PGHW_CACHE:
		return (CMT_BALANCE|CMT_AFFINITY);
	default:
		return (CMT_NO_POLICY);
	}
}

id_t
pg_plat_get_core_id(cpu_t *cpu)
{
	return (read_mpidr() & 0xFF);
}

pghw_type_t
pg_plat_hw_rank(pghw_type_t hw1, pghw_type_t hw2)
{
	int i, rank1, rank2;

	static pghw_type_t hw_hier[] = {
		PGHW_CACHE,
		PGHW_CHIP,
		PGHW_NUM_COMPONENTS
	};

	for (i = 0; hw_hier[i] != PGHW_NUM_COMPONENTS; i++) {
		if (hw_hier[i] == hw1)
			rank1 = i;
		if (hw_hier[i] == hw2)
			rank2 = i;
	}

	if (rank1 > rank2)
		return (hw1);
	else
		return (hw2);
}

void
cmp_set_nosteal_interval(void)
{
	/* Set the nosteal interval (used by disp_getbest()) to 100us */
	nosteal_nsec = 100000UL;
}

int
cu_plat_cpc_init(cpu_t *cp, kcpc_request_list_t *reqs, int nreqs)
{
	return (-1);
}

void
mach_cpu_pause(volatile char *safe)
{
	/*
	 * This cpu is now safe.
	 */
	*safe = PAUSE_WAIT;
	membar_enter(); /* make sure stores are flushed */

	/*
	 * Now we wait.  When we are allowed to continue, safe
	 * will be set to PAUSE_IDLE.
	 */
	while (*safe != PAUSE_IDLE)
		SMT_PAUSE();
}

void
cpu_halt(void)
{
	cpu_t *cpup = CPU;
	processorid_t cpu_sid = cpup->cpu_seqid;
	cpupart_t *cp = cpup->cpu_part;
	int hset_update = 1;
	volatile int *p = &cpup->cpu_disp->disp_nrunnable;
	uint_t s;

	/*
	 * If this CPU is online then we should note our halting
	 * by adding ourselves to the partition's halted CPU
	 * bitset. This allows other CPUs to find/awaken us when
	 * work becomes available.
	 */
	if (CPU->cpu_flags & CPU_OFFLINE)
		hset_update = 0;

	/*
	 * Add ourselves to the partition's halted CPUs bitset
	 * and set our HALTED flag, if necessary.
	 *
	 * When a thread becomes runnable, it is placed on the queue
	 * and then the halted cpu bitset is checked to determine who
	 * (if anyone) should be awoken. We therefore need to first
	 * add ourselves to the halted bitset, and then check if there
	 * is any work available.  The order is important to prevent a race
	 * that can lead to work languishing on a run queue somewhere while
	 * this CPU remains halted.
	 *
	 * Either the producing CPU will see we're halted and will awaken us,
	 * or this CPU will see the work available in disp_anywork()
	 */
	if (hset_update) {
		cpup->cpu_disp_flags |= CPU_DISP_HALTED;
		membar_producer();
		bitset_atomic_add(&cp->cp_haltset, cpu_sid);
	}

	/*
	 * Check to make sure there's really nothing to do.
	 * Work destined for this CPU may become available after
	 * this check. We'll be notified through the clearing of our
	 * bit in the halted CPU bitset, and a poke.
	 */
	if (disp_anywork()) {
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			bitset_atomic_del(&cp->cp_haltset, cpu_sid);
		}
		return;
	}

	/*
	 * We're on our way to being halted.  Wait until something becomes
	 * runnable locally or we are awakened (i.e. removed from the halt
	 * set).  Note that the call to hv_cpu_yield() can return even if we
	 * have nothing to do.
	 *
	 * Disable interrupts now, so that we'll awaken immediately
	 * after halting if someone tries to poke us between now and
	 * the time we actually halt.
	 *
	 * We check for the presence of our bit after disabling interrupts.
	 * If it's cleared, we'll return. If the bit is cleared after
	 * we check then the poke will pop us out of the halted state.
	 * Also, if the offlined CPU has been brought back on-line, then
	 * we return as well.
	 *
	 * The ordering of the poke and the clearing of the bit by cpu_wakeup
	 * is important.
	 * cpu_wakeup() must clear, then poke.
	 * cpu_halt() must disable interrupts, then check for the bit.
	 *
	 * The check for anything locally runnable is here for performance
	 * and isn't needed for correctness. disp_nrunnable ought to be
	 * in our cache still, so it's inexpensive to check, and if there
	 * is anything runnable we won't have to wait for the poke.
	 *
	 * Any interrupt will awaken the cpu from halt. Looping here
	 * will filter spurious interrupts that wake us up, but don't
	 * represent a need for us to head back out to idle().  This
	 * will enable the idle loop to be more efficient and sleep in
	 * the processor pipeline for a larger percent of the time,
	 * which returns useful cycles to the peer hardware strand
	 * that shares the pipeline.
	 */
	s = disable_interrupts();
	while (*p == 0 &&
	    ((hset_update && bitset_in_set(&cp->cp_haltset, cpu_sid)) ||
	    (!hset_update && (CPU->cpu_flags & CPU_OFFLINE)))) {
		__asm__ volatile("wfi");
		restore_interrupts(s);
		s = disable_interrupts();
	}

	/*
	 * We're no longer halted
	 */
	restore_interrupts(s);
	if (hset_update) {
		cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
		bitset_atomic_del(&cp->cp_haltset, cpu_sid);
	}
}

static void
cpu_wakeup(cpu_t *cpu, int bound)
{
	uint_t		cpu_found;
	processorid_t	cpu_sid;
	cpupart_t	*cp;

	cp = cpu->cpu_part;
	cpu_sid = cpu->cpu_seqid;
	if (bitset_in_set(&cp->cp_haltset, cpu_sid)) {
		/*
		 * Clear the halted bit for that CPU since it will be
		 * poked in a moment.
		 */
		bitset_atomic_del(&cp->cp_haltset, cpu_sid);
		/*
		 * We may find the current CPU present in the halted cpu bitset
		 * if we're in the context of an interrupt that occurred
		 * before we had a chance to clear our bit in cpu_halt().
		 * Poking ourself is obviously unnecessary, since if
		 * we're here, we're not halted.
		 */
		if (cpu != CPU)
			poke_cpu(cpu->cpu_id);
		return;
	} else {
		/*
		 * This cpu isn't halted, but it's idle or undergoing a
		 * context switch. No need to awaken anyone else.
		 */
		if (cpu->cpu_thread == cpu->cpu_idle_thread ||
		    cpu->cpu_disp_flags & CPU_DISP_DONTSTEAL)
			return;
	}

	/*
	 * No need to wake up other CPUs if this is for a bound thread.
	 */
	if (bound)
		return;

	/*
	 * The CPU specified for wakeup isn't currently halted, so check
	 * to see if there are any other halted CPUs in the partition,
	 * and if there are then awaken one.
	 *
	 * If possible, try to select a CPU close to the target, since this
	 * will likely trigger a migration.
	 */
	do {
		cpu_found = bitset_find(&cp->cp_haltset);
		if (cpu_found == (uint_t)-1)
			return;
	} while (bitset_atomic_test_and_del(&cp->cp_haltset, cpu_found) < 0);

	if (cpu_found != CPU->cpu_seqid)
		poke_cpu(cpu_seq[cpu_found]->cpu_id);
}

void
mach_init()
{
	cpuset_t cpumask;

	slvltovect = mach_softlvl_to_vect;

	idle_cpu = cpu_halt;
	disp_enq_thread = cpu_wakeup;

	/*
	 * Add all enabled CPUs to the mp_cpus cpuset.
	 */
	CPUSET_ZERO(cpumask);

	for (struct cpuinfo *ci = cpuinfo_first_enabled();
	    ci != cpuinfo_end(); ci = cpuinfo_next_enabled(ci)) {
		CPUSET_ADD(cpumask, ci->ci_id);
	}

	mp_cpus = cpumask;
}
