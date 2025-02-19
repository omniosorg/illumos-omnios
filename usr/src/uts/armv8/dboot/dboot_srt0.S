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
 * Copyright 2025 Michael van der Westhuizen
 */
#include <sys/asm_linkage.h>
#include "assym.h"

	.text
/*
 * void _start(void)
 */
	ENTRY(_start)
	bl	1f
	sub	x28, lr, #0x4
	// bic	x28, x28, #0xfff
	// brk	#0
	b	2f
1:	ret
2:
1:
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x18

	// flush cache (data/inst)
	bl	dcache_flush_all
	ic	iallu
	dsb	sy
	isb

	mrs	x0, CurrentEL
	cmp	x0, #0xc
	b.eq	el3

	cmp	x0, #0x8
	b.eq	el2

	b	el1
el3:
	// not supported
	b	el3

el2:
	bl	0f
	b	el1
0:
	ldr	x0, =SCTLR_EL1_RES1
	msr	sctlr_el1, x0
	ldr	x0, =SCTLR_EL2_RES1
	msr	sctlr_el2, x0
	dsb	sy
	isb

	ldr	x0, =(CNTHCTL_EL1PCEN | CNTHCTL_EL1PCTEN)
	msr	cnthctl_el2, x0
	msr	cntvoff_el2, xzr

	ldr	x0, =CPTR_EL2_RES1
	msr	cptr_el2, x0

	msr	vttbr_el2, xzr
	msr	vbar_el2, xzr

	mrs	x0, midr_el1
	msr	vpidr_el2, x0

	mrs	x0, mpidr_el1
	msr	vmpidr_el2, x0

	ldr	x0, =HCR_RW
	msr	hcr_el2, x0
	mrs	x0, hcr_el2

	msr	hstr_el2, xzr
	msr	cptr_el2, xzr

	mrs	x0, midr_el1
	mov	w0, w0
	lsr	w1, w0, #24	// Implementor
	cmp	w1, #0x41	// ARM
	b.ne	not_cortex_0
	ubfx	w1, w0, #16, #4	// Architecture
	cmp	w1, #0xF
	b.ne	not_cortex_0
	ubfx	w1, w0, #4, #12	// Part
	cmp	w1, #0xD08	// -A72
	b.eq	cortex_a72_0
	cmp	w1, #0xD07	// -A57
	b.eq	cortex_a57_0
				// *not* -A55
	cmp	w1, #0xD03	// -A53
	b.eq	cortex_a53_0
	b	not_cortex_0
cortex_a72_0:
cortex_a57_0:
cortex_a53_0:
	// access L2ACTLR L2ECTLR L2CTLR CPUECTLR CPUACTLR
	mrs	x0, actlr_el2
	orr	x0, x0, #0x70
	orr	x0, x0, #0x3
	msr	actlr_el2, x0
not_cortex_0:

	ldr	x0, =(PSR_F | PSR_I | PSR_M_EL1h)
	msr	spsr_el2, x0
	msr	elr_el2, x30

	dsb sy
	isb
	eret

el1:
	bl	dcache_clean_all

	/*
	 * disable mmu, cache
	 *
	 * but save the current value so we can turn it all on later
	 */
	mrs	x27, sctlr_el1
	ldr	x0, =SCTLR_EL1_RES1
	msr	sctlr_el1, x0
	dsb	sy
	isb

	// enable cache coherence on Cortex-A5x
	mrs	x0, midr_el1
	mov	w0, w0
	lsr	w1, w0, #24	// Implementor
	cmp	w1, #0x41	// ARM Inc.
	b.ne	not_cortex_1
	ubfx	w1, w0, #16, #4	// Architecture
	cmp	w1, #0xF
	b.ne	not_cortex_1
	ubfx	w1, w0, #4, #12	// Part
	// XXXARM: The -A72 TRM is wishy washy about whether this is
	// necessary, but it is _possible_.
	cmp	w1, #0xD08	// Cortex-A72
	b.eq	cortex_a72_1
	cmp	w1, #0xD07	// Cortex-A57
	b.eq	cortex_a57_1
	// NB: Explicitly _not_ A55
	cmp	w1, #0xD03	// Cortex-A53
	b.eq	cortex_a53_1
	b	not_cortex_1

cortex_a72_1:
cortex_a57_1:
cortex_a53_1:
	// CPUECTLR_EL1.SMPEN -> 1 (enable cache coherence)
	mrs	x0, s3_1_c15_c2_1
	tbnz	x0, #6, not_cortex_1
	orr	x0, x0, #(1<<6)
	msr	s3_1_c15_c2_1, x0
	dsb	sy
	isb
not_cortex_1:

	/*
	 * Re-enable MMU and caches, disable alignment errors.
	 *
	 * UEFI boots us with caches on and the MMU configured, so there's
	 * no need to leave it off.
	 *
	 * XXXARM: this is a bit sketchy, should probably remove it
	 */
	and	x27, x27, #(SCTLR_I)
	and	x27, x27, #(SCTLR_C)
	and	x27, x27, #(SCTLR_M)
	bic	x27, x27, #(SCTLR_A)
	mrs	x27, sctlr_el1

	mrs	x0, cpacr_el1
	bic	x0, x0, #CPACR_FPEN_MASK
	//orr	x0, x0, #CPACR_FPEN_DIS
	msr	cpacr_el1, x0

	/*
	 * The stack still points to the loader stack
	 */
	mov	x0, x28
	adrp	x1, _DYNAMIC
	add	x1, x1, :lo12:_DYNAMIC
	bl	self_reloc

	ldr	x1, =_BootStackTop
	mov	sp, x1

	mov	x0, x19
	bl	main

	b	_reset
	SET_SIZE(_start)

	ENTRY(dcache_flush_all)
	mrs	x0, clidr_el1
	and	w3, w0, #0x07000000
	lsr	w3, w3, #23
	cbz	w3, 4f
	mov	w10, #0
	mov	w8, #1
0:	add	w2, w10, w10, lsr #1
	lsr	w1, w0, w2
	and	w1, w1, #0x7
	cmp	w1, #2
	b.lt	3f
	msr	csselr_el1, x10
	isb
	mrs	x1, ccsidr_el1
	and	w2, w1, #7
	add	w2, w2, #4
	ubfx	w4, w1, #3, #10
	clz	w5, w4
	lsl	w9, w4, w5
	lsl	w16, w8, w5
1:	ubfx	w7, w1, #13, #15
	lsl	w7, w7, w2
	lsl	w17, w8, w2
2:	orr	w11, w10, w9
	orr	w11, w11, w7
	dc	cisw, x11
	subs	w7, w7, w17
	b.ge	2b
	subs	x9, x9, x16
	b.ge	1b
3:	add	w10, w10, #2
	cmp	w3, w10
	dsb	sy
	b.gt	0b
4:	ret
	SET_SIZE(dcache_flush_all)

	ENTRY(dcache_clean_all)
	mrs	x0, clidr_el1
	and	w3, w0, #0x07000000
	lsr	w3, w3, #23
	cbz	w3, 4f
	mov	w10, #0
	mov	w8, #1
0:	add	w2, w10, w10, lsr #1
	lsr	w1, w0, w2
	and	w1, w1, #0x7
	cmp	w1, #2
	b.lt	3f
	msr	csselr_el1, x10
	isb
	mrs	x1, ccsidr_el1
	and	w2, w1, #7
	add	w2, w2, #4
	ubfx	w4, w1, #3, #10
	clz	w5, w4
	lsl	w9, w4, w5
	lsl	w16, w8, w5
1:	ubfx	w7, w1, #13, #15
	lsl	w7, w7, w2
	lsl	w17, w8, w2
2:	orr	w11, w10, w9
	orr	w11, w11, w7
	dc	csw, x11
	subs	w7, w7, w17
	b.ge	2b
	subs	x9, x9, x16
	b.ge	1b
3:	add	w10, w10, #2
	cmp	w3, w10
	dsb	sy
	b.gt	0b
4:	ret
	SET_SIZE(dcache_clean_all)

	ENTRY(dcache_invalidate_all)
	mrs	x0, clidr_el1
	and	w3, w0, #0x07000000
	lsr	w3, w3, #23
	cbz	w3, 4f
	mov	w10, #0
	mov	w8, #1
0:	add	w2, w10, w10, lsr #1
	lsr	w1, w0, w2
	and	w1, w1, #0x7
	cmp	w1, #2
	b.lt	3f
	msr	csselr_el1, x10
	isb
	mrs	x1, ccsidr_el1
	and	w2, w1, #7
	add	w2, w2, #4
	ubfx	w4, w1, #3, #10
	clz	w5, w4
	lsl	w9, w4, w5
	lsl	w16, w8, w5
1:	ubfx	w7, w1, #13, #15
	lsl	w7, w7, w2
	lsl	w17, w8, w2
2:	orr	w11, w10, w9
	orr	w11, w11, w7
	dc	isw, x11
	subs	w7, w7, w17
	b.ge	2b
	subs	x9, x9, x16
	b.ge	1b
3:	add	w10, w10, #2
	cmp	w3, w10
	dsb	sy
	b.gt	0b
4:	ret
	SET_SIZE(dcache_invalidate_all)

	.balign	2048
	ENTRY(exception_vector)
	/*
	 * From Current Exception level with SP_EL0
	 */
	.balign	0x80
from_current_el_sp0_sync:
0:	b	0b

	.balign	0x80
from_current_el_sp0_irq:
0:	b	0b

	.balign	0x80
from_current_el_sp0_fiq:
0:	b	0b

	.balign	0x80
from_current_el_sp0_error:
0:	b	0b

	/*
	 * From Current Exception level with SP_ELx
	 */
	.balign	0x80
from_current_el_sync:
	b	from_current_el_sync_handle

	.balign	0x80
from_current_el_irq:
0:
	ldr	x0, =0x021c0600
	mov	w1, #'X'
	strb	w1, [x0]
	b	0b

	.balign	0x80
from_current_el_fiq:
0:
	ldr	x0, =0x021c0600
	mov	w1, #'Y'
	strb	w1, [x0]
	b	0b

	.balign	0x80
from_current_el_error:
0:
	ldr	x0, =0x021c0600
	mov	w1, #'Z'
	strb	w1, [x0]
	b	0b


	/*
	 * From Lower Exception level using aarch64
	 */
	.balign	0x80
from_lower_el_aarch64_sync:
0:	b	0b

	.balign	0x80
from_lower_el_aarch64_irq:
0:	b	0b

	.balign	0x80
from_lower_el_aarch64_fiq:
0:	b	0b

	.balign	0x80
from_lower_el_aarch64_error:
0:	b	0b


	/*
	 * From Lower Exception level using aarch32
	 */
	.balign	0x80
from_lower_el_aarch32_sync:
0:	b	0b

	.balign	0x80
from_lower_el_aarch32_irq:
0:	b	0b

	.balign	0x80
from_lower_el_aarch32_fiq:
0:	b	0b

	.balign	0x80
from_lower_el_aarch32_error:
0:	b	0b

	.balign	0x80
from_current_el_sync_handle:
	sub	sp, sp, #(16 * 16)
	stp	x0, x1, [sp, #(0 * 16)]
	stp	x2, x3, [sp, #(1 * 16)]
	stp	x4, x5, [sp, #(2 * 16)]
	stp	x6, x7, [sp, #(3 * 16)]
	stp	x8, x9, [sp, #(4 * 16)]
	stp	x10, x11, [sp, #(5 * 16)]
	stp	x12, x13, [sp, #(6 * 16)]
	stp	x14, x15, [sp, #(7 * 16)]
	stp	x16, x17, [sp, #(8 * 16)]
	stp	x18, x19, [sp, #(9 * 16)]
	stp	x20, x21, [sp, #(10 * 16)]
	stp	x22, x23, [sp, #(11 * 16)]
	stp	x24, x25, [sp, #(12 * 16)]
	stp	x26, x27, [sp, #(13 * 16)]
	stp	x28, x29, [sp, #(14 * 16)]
	str	x30,      [sp, #(15 * 16)]
	mov	x0, sp
	bl	dump_exception
0:	b	0b
	SET_SIZE(exception_vector)
