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

/* Copyright 2023 Richard Lowe */

#include <sys/cpuvar.h>
#include <sys/kdi_regs.h>
#include <sys/processor.h>
#include <sys/stdbool.h>
#include <sys/systm.h>
#include <sys/trap.h>

extern kdi_cpusave_t *kdi_cpusave;

/* Return the KDI save area for the current cpu */
kdi_cpusave_t *
kdi_get_cpusave(void)
{
	return (&kdi_cpusave[CPU->cpu_id]);
}

/* Return the ID of the current CPU */
processorid_t
kdi_get_cpuid(void)
{
	return (CPU->cpu_id);
}

kdi_cpusave_t *
kdi_advance_crumb_pointer(kdi_cpusave_t *save)
{
	if (save->krs_curcrumbidx == (KDI_NCRUMBS - 1)) {
		save->krs_curcrumbidx = 0;
		save->krs_curcrumb = save->krs_crumbs;
	} else {
		save->krs_curcrumbidx++;
		save->krs_curcrumb++;
	}

	memset(save->krs_curcrumb, 0, sizeof (kdi_crumb_t));
	return (save);
}

/*
 * We receive all breakpoints and single step traps.  Some of them, including
 * those from userland and those induced by DTrace providers, are intended for
 * the kernel, and must be processed there.  We adopt this
 * ours-until-proven-otherwise position due to the painful consequences of
 * sending the kernel an unexpected breakpoint or single step.  Unless someone
 * can prove to us that the kernel is prepared to handle the trap, we'll assume
 * there's a problem and will give the user a chance to debug it.
 *
 * If we return false, handle this trap ourselves.
 * If we return true, pass this trap to the kernel
 */
int
kdi_trap_pass(kdi_cpusave_t *cpusave)
{
	greg_t spsr = cpusave->krs_gregs[KDIREG_SPSR];
	greg_t trapno = cpusave->krs_gregs[KDIREG_TRAPNO];

	/*
	 * An invalid trapno means we reached here via a cross call from
	 * another cpu, and have a fake trap frame.  It is toxic, never pass
	 * it along.
	 */
	if (trapno == -1)
		return (0);

	/*
	 * This will be the SVC that got us into the debugger, or otherwise
	 * destined for us.
	 */
	if (trapno == T_SVC)
		return (0);

	if (USERMODE(spsr))
		return (1);

	if (trapno == T_SOFTWARE_STEP_EL)
		return (0);
	else if (trapno == T_SOFTWARE_BREAKPOINT)
		return (0);
	else if ((trapno == T_NV2_WATCHPOINT) || (trapno == T_WATCHPOINT))
		return (0);

	return (1);
}

void
kdi_reboot(void)
{
	extern void _reset(bool);
	_reset(false);
}
