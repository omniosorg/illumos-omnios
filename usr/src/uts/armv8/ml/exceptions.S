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
 * Copyright 2024 Michael van der Westhuizen
 */

#include <sys/asm_linkage.h>
#include <sys/errno.h>
#include <sys/privregs.h>

#include "assym.h"

#define	SYSENT_SHIFT	5
#if (1 << SYSENT_SHIFT) != SYSENT_SIZE
#error	"SYSENT_SHIFT does not correspond to size of sysent structure"
#endif

#define CPUP_THREADP(cp_reg, tp_reg)		\
	   mrs tp_reg, tpidr_el1;		\
	   ldr cp_reg, [tp_reg, #T_CPU]

#define CPUP(cp_reg)			\
	   mrs cp_reg, tpidr_el1;	\
	   ldr cp_reg, [cp_reg, #T_CPU]

#define THREADP(tp_reg)			\
	   mrs tp_reg, tpidr_el1

/* Each entry in the exception vector is 128 bytes / 32 instruction long */
#define VECTOR_ENTRY_SIZE	128

/* Fail the assembly if a vector entry is too large */
#define	CHECK_VECTOR_ENTRY(name)		\
	.if (. - name) > VECTOR_ENTRY_SIZE;	\
	.err;					\
	.endif

	.data
.unexpected_exception:	.asciz "unexpected exception type"

#define UNEXPECTED()				\
	clrex;					\
	adrp x0, .unexpected_exception;		\
	add x0, x0, :lo12:.unexpected_exception;	\
	bl panic

/*
 * This is the AArch64 exception vector used by the hardware, each entry is
 * 128 byte aligned, and 32 instructions (128 bytes) long.
 *
 * We represent this as a single large function (exception_vector), which we
 * can put in VBAR, and a nested function per-entry to make things easier to
 * refer to while debugging.
 *
 * It is important that ALTENTRY is used, so alignment is not altered, and the
 * vector keeps it specified shape.
 */
	.text
	.balign	2048
	ENTRY(exception_vector)
	/*
	 * From Current Exception level with SP_EL0
	 */
	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_current_el_sp0_sync)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_current_el_sp0_sync)
SET_SIZE(from_current_el_sp0_sync)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_current_el_sp0_irq)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_current_el_sp0_irq)
SET_SIZE(from_current_el_sp0_irq)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_current_el_sp0_fiq)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_current_el_sp0_fiq)
	SET_SIZE(from_current_el_sp0_fiq)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_current_el_sp0_error)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_current_el_sp0_error)
SET_SIZE(from_current_el_sp0_error)

	/*
	 * From Current Exception level with SP_ELx
	 */
	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_current_el_sync)
	clrex
	__SAVE_REGS_EL1
	__SAVE_FRAME
	b	from_current_el_sync_handler
	CHECK_VECTOR_ENTRY(from_current_el_sync)
SET_SIZE(from_current_el_sync)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_current_el_irq)
	clrex
	b	from_current_el_irq_handler
	CHECK_VECTOR_ENTRY(from_current_el_irq)
	SET_SIZE(from_current_el_irq)
	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_current_el_fiq)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_current_el_fiq)
SET_SIZE(from_current_el_fiq)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_current_el_error)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_current_el_error)
SET_SIZE(from_current_el_error)

	/*
	 * From Lower Exception level using aarch64
	 */
	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_lower_el_aarch64_sync)
	clrex
	__SAVE_REGS_EL0
	__TERMINATE_FRAME

	b from_lower_el_aarch64_sync_handler
	CHECK_VECTOR_ENTRY(from_lower_el_aarch64_sync)
SET_SIZE(from_lower_el_aarch64_sync)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_lower_el_aarch64_irq)
	clrex
	__SAVE_REGS_EL0
	__TERMINATE_FRAME

	// Disable single-stepping when coming back from userland
	mrs	x1, mdscr_el1
	and	x1, x1, #~MDSCR_SS
	msr	mdscr_el1, x1

	// Enable debug exceptions
	msr DAIFClr, #DAIF_SETCLEAR_DEBUG

	mov	x0, sp
	bl	do_interrupt
	b	_sys_rtt
	CHECK_VECTOR_ENTRY(from_lower_el_aarch64_irq)
SET_SIZE(from_lower_el_aarch64_irq)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_lower_el_aarch64_fiq)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_lower_el_aarch64_fiq)
SET_SIZE(from_lower_el_aarch64_fiq)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_lower_el_aarch64_error)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_lower_el_aarch64_error)
SET_SIZE(from_lower_el_aarch64_error)

	/*
	 * From Lower Exception level using aarch32
	 */
	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_lower_el_aarch32_sync)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_lower_el_aarch32_sync)
SET_SIZE(from_lower_el_aarch32_sync)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_lower_el_aarch32_irq)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_lower_el_aarch32_irq)
SET_SIZE(from_lower_el_aarch32_irq)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_lower_el_aarch32_fiq)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_lower_el_aarch32_fiq)
SET_SIZE(from_lower_el_aarch32_fiq)

	.balign	VECTOR_ENTRY_SIZE
ALTENTRY(from_lower_el_aarch32_error)
	UNEXPECTED()
	CHECK_VECTOR_ENTRY(from_lower_el_aarch32_error)
SET_SIZE(from_lower_el_aarch32_error)

	.balign VECTOR_ENTRY_SIZE
	SET_SIZE(exception_vector)

	ENTRY(from_current_el_sync_handler)
	mrs	x1, esr_el1
	lsr	w0, w1, #ESR_EC_SHIFT	// w0 <- EC, no need to mask.
	mrs	x2, far_el1
	mov	x3, sp
	mov	x29, sp
	bl	trap
	ALTENTRY(dtrace_invop_callsite)
	cbz	x0, 1f
	b	_sys_rtt
1:
	__RESTORE_REGS_EL1
	eret
	SET_SIZE(from_current_el_sync_handler)

	ENTRY(from_current_el_irq_handler)
	__SAVE_REGS_EL1
	__SAVE_FRAME
	mov	x0, sp
	bl	do_interrupt
	b	_sys_rtt
	SET_SIZE(from_current_el_irq_handler)

	ENTRY_NP(from_lower_el_aarch64_sync_handler)
	// Disable single-stepping when coming back from userland
	mrs	x1, mdscr_el1
	and	x1, x1, #~MDSCR_SS
	msr	mdscr_el1, x1

	// Enable debug exceptions
	msr DAIFClr, #DAIF_SETCLEAR_DEBUG

	mrs	x1, esr_el1
	lsr	w0, w1, #ESR_EC_SHIFT	// w0 <- EC, no need to mask
	cmp	w0, #T_SVC
	b.eq	syscall_handler

	mrs	x2, far_el1
	mov	x3, sp

	bl	trap
	b	user_rtt
	SET_SIZE(from_lower_el_aarch64_sync_handler)

	/*
	 * Supervisor call Handler From AArch64 EL0 (system calls)
	 */
	ENTRY(syscall_handler)
	// w0: ESR_EL1.EC
	// w1: ESR_EL1

	mov	x29, sp

	and	w20, w1, #ESR_ISS_MASK	// w20 <- syscall number
	cbnz	w20, 1f
	mov	w20, w9

	// XXXARM: #15/0x8000 needs to be symbolic
1:	tbnz	w20, #15, _fasttrap	// if (w20 & 0x8000) goto _fasttrap
	CPUP(x0)

	// cpu_stats.sys.syscall++
	ldr	x9, [x0, #CPU_STATS_SYS_SYSCALL]
	add	x9, x9, #1
	str	x9, [x0, #CPU_STATS_SYS_SYSCALL]

	THREADP(x21)	// x21 <- thread
	ldr	x1, [x21, #T_LWP]	// x1 <- lwp

	// lwp->lwp_state = LWP_SYS
	mov	w10, #LWP_SYS
	strb	w10, [x1, #LWP_STATE]

	// lwp->lwp_ru.sysc++
	ldr	x9, [x1, #LWP_RU_SYSC]
	add	x9, x9, #1
	str	x9, [x1, #LWP_RU_SYSC]

	msr	DAIFClr, #DAIF_SETCLEAR_IRQ

	// syscall_mstate(LMS_USER, LMS_SYSTEM);
	mov	w0, #LMS_USER
	mov	w1, #LMS_SYSTEM
	bl	syscall_mstate

	strh	w20, [x21, #T_SYSNUM]
	ldrb	w9, [x21, #T_PRE_SYS]
	cbnz	w9, _syscall_pre

_syscall_invoke:
	ldr	x1, =sysent
	cmp	w20, #NSYSCALL
	b.hs	_syscall_ill

	add	x20, x1, x20, lsl #SYSENT_SHIFT	// x20 <- sysent
	ldr	x16, [x20, #SY_CALLC]
	ldp	x0, x1, [sp, #REGOFF_X0]
	ldp	x2, x3, [sp, #REGOFF_X2]
	ldp	x4, x5, [sp, #REGOFF_X4]
	ldp	x6, x7, [sp, #REGOFF_X6]
	blr	x16
	mov	x1, xzr

	ldrh	w9, [x20, #SY_FLAGS]
	ands	w9, w9, #SE_32RVAL2
	b.eq	2f
	lsr	x1, x0, #32
	mov	w0, w0
	mov	w1, w1
	sxtw	x0, w0
	sxtw	x1, w1
2:
	mov	x22, x0
	mov	x23, x1

	// syscall_mstate(LMS_SYSTEM, LMS_USER);
	mov	w0, #LMS_SYSTEM
	mov	w1, #LMS_USER
	bl	syscall_mstate

	msr	DAIFSet, #DAIF_SETCLEAR_IRQ

	ldr	w9, [x21, #T_POST_SYS_AST]
	cbnz	w9, _syscall_post

	ldr	x2, [sp, #REGOFF_SPSR]
	bic	x2, x2, #PSR_C
	str	x2, [sp, #REGOFF_SPSR]

	ldr	x2, [x21, #T_LWP]	// x2 <- lwp
	mov	w10, #LWP_USER
	strb	w10, [x2, #LWP_STATE]
	stp	x22, x23, [sp, #REGOFF_X0]
	strh	wzr, [x21, #T_SYSNUM]

	__RESTORE_REGS_EL0
	eret

_user_rtt:
	msr	DAIFSet, #(DAIF_SETCLEAR_IRQ | DAIF_SETCLEAR_DEBUG)

	// if we've been requested to single-step in user-land, set this now
	// that debug exceptions are masked and won't be taken in the kernel
	ldr	x0, [sp, #REGOFF_SPSR]
	tbz	x0, PSR_SS_BIT, 1f
	mrs	x0, mdscr_el1
	orr	x0, x0, MDSCR_SS
	msr	mdscr_el1, x0

1:
	// Check for deferred register updates (e.g., FPU reload)
	ldr	x0, [x21, #T_LWP]
	cbz	x0, 2f
	ldrb	w9, [x0, #LWP_PCB_RUPDATE]
	cbz	w9, 2f
	bl	pcb_return_check
2:
	ldrb	w9, [x21, #T_ASTFLAG]
	cbnz	w9, 3f

	__RESTORE_REGS_EL0
	eret

3:
	mov	x0, #T_AST
	mov	x1, #0
	mov	x2, #0
	mov	x3, sp

	bl	trap
	b	_user_rtt

_syscall_pre:
	bl	pre_syscall
	mov	x22, x0
	mov	x23, xzr
	cbnz	w0, _syscall_post_call
	ldrh	w20, [x21, #T_SYSNUM]
	b	_syscall_invoke

_syscall_ill:
	bl	nosys
	mov	x22, x0
	mov	x23, xzr
	b	_syscall_post_call

_syscall_post:
	msr	DAIFClr, #DAIF_SETCLEAR_IRQ

	// syscall_mstate(LMS_USER, LMS_SYSTEM);
	mov	w0, #LMS_USER
	mov	w1, #LMS_SYSTEM
	bl	syscall_mstate
_syscall_post_call:
	mov	x0, x22
	mov	x1, x23
	bl	post_syscall

	// syscall_mstate(LMS_SYSTEM, LMS_USER);
	mov	w0, #LMS_SYSTEM
	mov	w1, #LMS_USER
	bl	syscall_mstate
	b	_sys_rtt

	ALTENTRY(user_rtt)
	THREADP(x21)
	b	_user_rtt
	SET_SIZE(_user_rtt)

_fasttrap:
	// XXXARM: #14 needs to be symbolic, and 0x7fff
	tbnz	w20, #14, .L_dtrace_pid	// if (w20 & 0x4000) goto .L_dtrace_pid
	and	w20, w20, #0x7fff
	cmp	w20, #T_LASTFAST
	b.cc	1f
	mov	w20, #0
1:
	ldr	x8, =fasttrap_table
	lsl	w20, w20, #3
	ldr	x9, [x8, x20]

	ldp	x0, x1, [sp, #REGOFF_X0]
	ldp	x2, x3, [sp, #REGOFF_X2]

	msr	DAIFClr, #DAIF_SETCLEAR_IRQ
	blr	x9
	msr	DAIFSet, #DAIF_SETCLEAR_IRQ

	ldp	x17, x18, [sp, #REGOFF_PC]
	msr	elr_el1, x17
	msr	spsr_el1, x18
	ldr	x29, [sp, #REGOFF_X29]
	ldp	x30, x16, [sp, #REGOFF_X30]
	msr	sp_el0, x16
	ldr	x20, [sp, #REGOFF_X20]
	add	sp, sp, #REG_FRAME
	eret
.L_dtrace_pid:
	adr	x30, user_rtt
	msr	DAIFClr, #DAIF_SETCLEAR_IRQ
	mov	x0, sp
	mov	w1, w20
	b	dtrace_user_probe
	SET_SIZE(syscall_handler)

	ENTRY(getlgrp)
	CPUP_THREADP(x3, x2)

	ldr	x3, [x2, #T_LPL]
	ldr	w1, [x3, #LPL_LGRPID]	/* x1 = t->t_lpl->lpl_lgrpid */
	ldr	x3, [x2, #T_CPU]
	ldr	w0, [x3, #CPU_ID]	/* x0 = t->t_cpu->cpu_id */
	ret
	SET_SIZE(getlgrp)

	ENTRY(fasttrap_gethrestime)
	stp	x29, x30, [sp, #-(8*2)]!
	sub	sp, sp, #TIMESPEC_SIZE

	mov	x0, sp
	bl	gethrestime

	ldr	x0, [sp, #TV_SEC]
	ldr	x1, [sp, #TV_NSEC]

	add	sp, sp, #TIMESPEC_SIZE
	ldp	x29, x30, [sp], #(8*2)
	ret
	SET_SIZE(fasttrap_gethrestime)

	ENTRY(_sys_rtt)
	ldr	x2, [sp, #REGOFF_SPSR]
	and	x2, x2, #PSR_M_MASK
	cmp	x2, #PSR_M_EL0t
	b.eq	user_rtt

	msr	DAIFSet, #DAIF_SETCLEAR_IRQ

	CPUP(x21)
	ldrb	w0, [x21, #CPU_KPRUNRUN]
	cbnz	w0, _sys_rtt_preempt

_sys_rtt_preempt_ret:
	ldr	x0, [sp, #REGOFF_PC]

	ldr	x1, = mutex_owner_running_critical_start
	ldr	x2, = mutex_owner_running_critical_size
	ldr	x2, [x2]
	sub	x3, x0, x1
	cmp	x3, x2
	b.lo	2f
1:
	__RESTORE_REGS_EL0
	eret

2:	str	x1, [sp, #REGOFF_PC]
	b	1b

_sys_rtt_preempt:
	THREADP(x20)
	ldrb	w0, [x20, #T_PREEMPT_LK]
	cbnz	w0, _sys_rtt_preempt_ret
	mov	w0, #1
	strb	w0, [x20, #T_PREEMPT_LK]

	msr	DAIFClr, #DAIF_SETCLEAR_IRQ
	bl	kpreempt
	msr	DAIFSet, #DAIF_SETCLEAR_IRQ

	strb	wzr, [x20, #T_PREEMPT_LK]
	b	_sys_rtt_preempt_ret
	SET_SIZE(_sys_rtt)

	ENTRY(lwp_rtt_initial)
	THREADP(x0)
	ldr	x9, [x0, #T_STACK]			// switch stack
	mov	sp, x9
1:
	bl	__dtrace_probe___proc_start
	.pushsection .probepoint, "aw"
	.xword 1b
	.popsection

	b	1f

	ALTENTRY(lwp_rtt)
	THREADP(x0)
	ldr	x9, [x0, #T_STACK]			// switch stack
	mov	sp, x9
1:
	bl	__dtrace_probe___proc_lwp__start
	.pushsection .probepoint, "aw"
	.xword 1b
	.popsection
	bl	dtrace_systrace_rtt

	ldr	x0, [sp, #REGOFF_X0]
	ldr	x1, [sp, #REGOFF_X1]
	adr	x30, user_rtt
	b	post_syscall
	SET_SIZE(lwp_rtt)
	SET_SIZE(lwp_rtt_initial)

	.data
	.globl t1stack
	.type t1stack, @object
	.size t1stack, DEFAULTSTKSZ
	.align MMU_PAGESHIFT
t1stack:
	.zero DEFAULTSTKSZ
