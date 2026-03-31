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
 * Copyright 2026 Michael van der Westhuizen
 */

	.file	"efirt_call.S"

/*
 * Assembly trampoline for UEFI runtime service calls.
 *
 * Switches to a dedicated EFI stack before calling firmware, and
 * switches back to the kernel stack on return.  This isolates the
 * kernel thread stack from firmware stack consumption.
 *
 * If the firmware faults, the on_trap/longjmp mechanism (set up by
 * the C caller) restores SP from the setjmp buffer that was saved
 * on the kernel stack before this function was called.  The UEFI
 * stack is simply abandoned - no explicit cleanup is needed here.
 */

#include <sys/asm_linkage.h>

/*
 * uint64_t efirt_call_asm(uint64_t func, uint64_t a0, uint64_t a1,
 *     uint64_t a2, uint64_t a3, uint64_t a4, uint64_t stack_top)
 *
 * Arguments:
 * - x0  function pointer (EFI runtime service)
 * - x1  arg0
 * - x2  arg1
 * - x3  arg2
 * - x4  arg3
 * - x5  arg4
 * - x6  top of the dedicated EFI stack (grows downward)
 *
 * Returns:
 *   x0  EFI_STATUS from the firmware call
 */
	ENTRY(efirt_call_asm)

	/* Save frame pointer and return address on the kernel stack */
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp

	/* Switch to the dedicated EFI stack */
	mov	sp, x6

	/* Save the kernel SP on the EFI stack */
	stp	x29, xzr, [sp, #-16]!

	/*
	 * Shuffle arguments: move the function pointer to x8 (a
	 * scratch register under AAPCS64) and shift the five
	 * arguments down into x0-x4.
	 */
	mov	x8, x0
	mov	x0, x1
	mov	x1, x2
	mov	x2, x3
	mov	x3, x4
	mov	x4, x5

	/* Call the firmware runtime service */
	blr	x8

	/* Recover kernel SP from the EFI stack */
	ldp	x29, xzr, [sp], #16

	/* Switch back to the kernel stack and restore the frame */
	mov	sp, x29
	ldp	x29, x30, [sp], #16

	/* x0 holds the EFI_STATUS return value */
	ret

	SET_SIZE(efirt_call_asm)
