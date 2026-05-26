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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>
#include <sys/errno.h>
#include "assym.h"

#define CPUP_THREADP(cp_reg, tp_reg)		\
	   mrs tp_reg, tpidr_el1;		\
	   ldr cp_reg, [tp_reg, #T_CPU]

	/*
	 * +-----------
	 * |  lr (0)
	 * +-----------
	 * |  fp (0)
	 * +----------- <- SP, FP when calling func
	 * |  dummy(0)
	 * +-----------
	 * |  func
	 * +-----------
	 * |  arg1
	 * +-----------
	 * |  arg0
	 * +----------- <- SP
	 */
	ENTRY(thread_start)
	ldp	x0, x1,   [sp], #16
	ldp	x16, x17, [sp], #16

	mov	x29, sp

	ldr	x30, =thread_exit
	br	x16
	SET_SIZE(thread_start)

	ENTRY(resume)
	CPUP_THREADP(x1, x2)

	mov	x3, sp
	stp	x30, x3,  [x2, #T_LABEL_PC]
	stp	x19, x20, [x2, #T_LABEL_X19]
	stp	x21, x22, [x2, #T_LABEL_X21]
	stp	x23, x24, [x2, #T_LABEL_X23]
	stp	x25, x26, [x2, #T_LABEL_X25]
	stp	x27, x28, [x2, #T_LABEL_X27]
	str	x29,      [x2, #T_LABEL_X29]

	mov	x19, x0		// x19 <- new thread
	mov	x20, x1		// x20 <- CPU
	mov	x21, x2		// x21 <- curthread

1:
	bl	__dtrace_probe___sched_off__cpu
	.pushsection .probepoint, "aw"
	.xword 1b
	.popsection


	// Call savectx if thread has installed context ops.
	ldr	x9, [x21, #T_CTX]
	cbz	x9, .nosavectx
	mov	x0, x21
	bl	savectx
.nosavectx:

	bl	kernel_fpu_no_swtch

	// Call savepctx if process has installed context ops.
	ldr	x0, [x21, #T_PROCP]
	ldr	x1, [x0, #P_PCTX]
	cbz	x1, .nosavepctx
	bl	savepctx
.nosavepctx:

	// Save tpidr_el0
	ldr	x0,  [x21, #T_LWP]
	cbz	x0, .nosave_tpidr
	mrs	x1, tpidr_el0
	str	x1,  [x0, #LWP_PCB_TPIDR]
.nosave_tpidr:


	// Temporarily switch to the idle thread's stack
	ldr	x0, [x20, #CPU_IDLE_THREAD]
	msr	tpidr_el1, x0
	str	x0, [x20, #CPU_THREAD]
	ldr	x1, [x0, #T_LABEL_SP]
	mov	sp, x1

	// get hatp of new thread
	ldr	x0, [x19, #T_PROCP]
	ldr	x0, [x0, #P_AS]
	ldr	x0, [x0, #A_HAT]
	bl	hat_switch

	// Clear and unlock previous thread's t_lock
	add	x0, x21, #T_LOCK
	stlrb	wzr, [x0]

	ALTENTRY(_resume_from_idle)
	clrex

	/*
	 * spin until dispatched thread's mutex has
	 * been unlocked. this mutex is unlocked when
	 * it becomes safe for the thread to run.
	 */
	add	x0, x19, #T_LOCK
	mov	w2, #LOCK_HELD_VALUE
	sevl
1:	wfe
	ldaxrb	w3, [x0]
	cbnz	w3, 1b
	stxrb	w3, w2, [x0]
	cbnz	w3, 1b

	ldr	x0, [x19, T_CPU]
	cmp	x0, x20
	b.eq	.nocpumigrate

	// cp->cpu_stats.sys.cpumigrate++
	ldr	x0, [x20, #CPU_STATS_SYS_CPUMIGRATE]
	add	x0, x0, #1
	str	x0, [x20, #CPU_STATS_SYS_CPUMIGRATE]
	str	x20, [x19, #T_CPU]

.nocpumigrate:
	msr	tpidr_el1, x19
	str	x19, [x20, #CPU_THREAD]
	ldr	x0,  [x19, #T_LWP]
	str	x0,  [x20, #CPU_LWP]

	// Restore tpidr_el0
	cbz	x0, .norestore_tpidr
	ldr	x1,  [x0, #LWP_PCB_TPIDR]
	msr	tpidr_el0, x1
.norestore_tpidr:

	 // Switch to new thread's stack
	ldr	x0, [x19, #T_LABEL_SP]
	mov	sp, x0

	// Call restorectx if thread has installed context ops.
	ldr	x9, [x19, #T_CTX]
	cbz	x9, .norestorectx
	mov	x0, x19
	bl	restorectx
.norestorectx:

	// Call restorepctx if process has installed context ops.
	ldr	x0, [x19, #T_PROCP]
	ldr	x1, [x0, #P_PCTX]
	cbz	x1, .norestorepctx
	bl	restorepctx
.norestorepctx:

	// store t_intr_start
	ldrh	w0, [x19, #T_FLAG]
	ands	w0, w0, #T_INTR_THREAD
	b.eq	1f
	bl	arch_timer_count
	str	x0, [x19, #T_INTR_START]
1:
	bl	__dtrace_probe___sched_on__cpu
	.pushsection .probepoint, "aw"
	.xword 1b
	.popsection

	mov	x2, x19
	ldp	x30, x1,  [x2, #T_LABEL_PC]
	ldp	x19, x20, [x2, #T_LABEL_X19]
	ldp	x21, x22, [x2, #T_LABEL_X21]
	ldp	x23, x24, [x2, #T_LABEL_X23]
	ldp	x25, x26, [x2, #T_LABEL_X25]
	ldp	x27, x28, [x2, #T_LABEL_X27]
	ldr	x29,      [x2, #T_LABEL_X29]
	b	spl0

	SET_SIZE(_resume_from_idle)
	SET_SIZE(resume)


	ENTRY(resume_from_zombie)
	CPUP_THREADP(x1, x2)

	mov	x3, sp
	stp	x30, x3,  [x2, #T_LABEL_PC]
	stp	x19, x20, [x2, #T_LABEL_X19]
	stp	x21, x22, [x2, #T_LABEL_X21]
	stp	x23, x24, [x2, #T_LABEL_X23]
	stp	x25, x26, [x2, #T_LABEL_X25]
	stp	x27, x28, [x2, #T_LABEL_X27]
	str	x29,      [x2, #T_LABEL_X29]

	mov	x19, x0		// x19 <- new thread
	mov	x20, x1		// x20 <- CPU
	mov	x21, x2		// x21 <- curthread
1:
	bl	__dtrace_probe___sched_off__cpu
	.pushsection .probepoint, "aw"
	.xword 1b
	.popsection

	// Disable FPU
	isb
	mrs	x0, cpacr_el1
	bic	x0, x0, #CPACR_FPEN_MASK
	msr	cpacr_el1, x0
	isb

	// Temporarily switch to the idle thread's stack
	ldr	x0, [x20, #CPU_IDLE_THREAD]
	msr	tpidr_el1, x0
	str	x0, [x20, #CPU_THREAD]
	ldr	x1, [x0, #T_LABEL_SP]
	mov	sp, x1

	// get hatp of new thread
	ldr	x0, [x19, #T_PROCP]
	ldr	x0, [x0, #P_AS]
	ldr	x0, [x0, #A_HAT]
	bl	hat_switch

	/* 
	 * Put the zombie on death-row.
	 */
	mov	x0, x21
	bl	reapq_add

	b	_resume_from_idle
	SET_SIZE(resume_from_zombie)


	ENTRY(resume_from_intr)
	CPUP_THREADP(x1, x2)

	mov	x3, sp
	stp	x30, x3,  [x2, #T_LABEL_PC]
	stp	x19, x20, [x2, #T_LABEL_X19]
	stp	x21, x22, [x2, #T_LABEL_X21]
	stp	x23, x24, [x2, #T_LABEL_X23]
	stp	x25, x26, [x2, #T_LABEL_X25]
	stp	x27, x28, [x2, #T_LABEL_X27]
	str	x29,      [x2, #T_LABEL_X29]

	mov	x19, x0		// x19 <- new thread
	mov	x20, x1		// x20 <- CPU
	mov	x21, x2		// x21 <- curthread

1:
	bl	__dtrace_probe___sched_off__cpu
	.pushsection .probepoint, "aw"
	.xword 1b
	.popsection

	msr	tpidr_el1, x19
	str	x19, [x20, #CPU_THREAD]
	ldr	x0, [x19, #T_LABEL_SP]
	mov	sp, x0

	add	x0, x21, #T_LOCK
	stlrb	wzr, [x0]

	clrex

	// store t_intr_start
	ldrh	w0, [x19, #T_FLAG]
	ands	w0, w0, #T_INTR_THREAD
	b.eq	1f
	bl	arch_timer_count
	str	x0, [x19, #T_INTR_START]
1:
	bl	__dtrace_probe___sched_on__cpu
	.pushsection .probepoint, "aw"
	.xword 1b
	.popsection

	mov	x2, x19
	ldp	x30, x1,  [x2, #T_LABEL_PC]
	ldp	x19, x20, [x2, #T_LABEL_X19]
	ldp	x21, x22, [x2, #T_LABEL_X21]
	ldp	x23, x24, [x2, #T_LABEL_X23]
	ldp	x25, x26, [x2, #T_LABEL_X25]
	ldp	x27, x28, [x2, #T_LABEL_X27]
	ldr	x29,      [x2, #T_LABEL_X29]
	b	spl0
	SET_SIZE(resume_from_intr)

