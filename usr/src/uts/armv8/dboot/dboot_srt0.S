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
 * void _start(caddr_t modulep)
 *
 * - x28 contains our physical entry address, used for relocation.
 * - x27 contains our booted exception level, used to select the
 *       correct initialisation sequence.
 * - x26 contains our argument, the loader(7) modules pointer.
 * - x25 contains a boolean, indicating that the kernel should make
 *       a hypervisor call to replace hypervisor trap stubs.
 */
	ENTRY(_start)
	/* this little dance leaves the physical entry address in x28 */
	bl	1f
	sub	x28, lr, #0x4
	b	2f
1:	ret
2:
1:
	/*
	 * Stash the booted exception-level to x27, then ensure that it's
	 * EL1 or EL2.
	 */
	mrs	x27, CurrentEL
	ubfx	x27, x27, #2, #2
	cmp	x27, #0x2
	b.eq	1f
	cmp	x27, #0x1
	b.eq	1f
2:	b	2b

1:	/*
	 * At this point we're in either EL1 or EL2. Our entry address is in
	 * x28 and our booted EL is in x27.
	 *
	 * Save our argument to x26.
	 */
	mov	x26, x0

	/*
	 * Flush the data and instruction caches.
	 */
	bl	dcache_flush_all
	ic	iallu
	dsb	sy
	isb

	/*
	 * Choose our initialisation sequence.
	 * EL1 is straightforward and simply initialises the EL1 environemnt.
	 * EL2 is a little more complicated, as it leaves us in a unified EL2
	 * environment when VHE is present, but drops us to EL1 with a stub
	 * HVC trap table in place when VHE is not present.
	 */
	cmp	x27, #0x1
	b.ne	2f
	bl	.Lel1_entry
	b	.Lrun_dboot
2:
	bl	.Lel2_entry
	b	.Lrun_dboot

.Lel1_entry:
	/* el1 initialisation */
	ldr	x2, =INIT_SCTLR_EL1
	msr	sctlr_el1, x2
	isb

	/*
	 * Apply known errata applicable at EL1.
	 */

	/*
	 * Ensure that PSTATE and SPSR_EL1 are in sync. We do this by updating
	 * SPSR_EL1 and executing an exception return (to EL1), which then
	 * transfers us to the code that runs dboot.
	 */
	mov	x2, #(PSR_D | PSR_A | PSR_I | PSR_F | PSR_M_EL1h)
	msr	spsr_el1, x2
	msr	elr_el1, lr
	eret

.Lel2_entry:
	/* el2 initialisation */
	dsb	sy

	ldr	x2, =(SCTLR_EL2_RES1 | SCTLR_EL2_EIS | SCTLR_EL2_EOS)
	msr	sctlr_el2, x2
	isb

	/* hypervisor configuration */
	ldr	x2, =(HCR_RW | HCR_APK | HCR_API | HCR_E2H)
	msr	hcr_el2, x2
	/* we might tweak hcr_el2 later, so save it */
	isb
	mrs	x4, hcr_el2

	/*
	 * Load the Virtualization Processor ID Register from the Main ID
	 * Register.
	 */
	mrs	x2, midr_el1
	msr	vpidr_el2, x2

	/*
	 * Load the Virtualization Multiprocessor ID Register from the
	 * Multiprocessor Affinity Register.
	 */
	mrs	x2, mpidr_el1
	msr	vmpidr_el2, x2

	/*
	 * Set SCTLR_EL1 to a known value so that we can successfully drop
	 * to EL1 if/when needed.
	 */
	ldr	x2, =INIT_SCTLR_EL1
	msr	sctlr_el1, x2

	/*
	 * Check if the E2H flag is set in the Hypervisor Control Register.
	 *
	 * We attempted to set this bit above, and if it stuck we can use
	 * virtualisation host extensions (FEAT_VHE) and run the kernel at
	 * EL2 - otherwise we'll run at EL1.
	 */
	tst	x4, #HCR_E2H
	b.eq	.Lno_vhe
	mov	x25, #0		/* no HVC stubs necessary */

	/*
	 * We'll be running the kernel at EL2. Route exceptions that would
	 * normally be delivered to EL1 to EL2.
	 */
	orr	x4, x4, #(HCR_TGE)
	msr	hcr_el2, x4
	isb

	/* x2 still contains the value we set in sctlr_el1 */
	msr	s3_5_c1_c0_0, x2	/* sctlr_el12 */
	isb
	ldr	x2, =(INIT_CPTR_EL2_E2H)
	ldr	x3, =(CNTHCTL_E2H_EL1PCTEN | CNTHCTL_E2H_EL1PTEN)
	ldr	x5, =(PSR_D | PSR_A | PSR_I | PSR_F | PSR_M_EL2h)
	b	.Ldone_vhe

.Lno_vhe:
	/*
	 * Install a stub Hypervisor trap table that can replace itself
	 * with a proper function once the kernel is up.
	 */
	adrp	x2, hyp_stub_vectors
	add	x2, x2, :lo12:hyp_stub_vectors
	msr	vbar_el2, x2
	mov	x25, #1		/* HVC stubs are installed */

	ldr	x2, =(INIT_CPTR_EL2_NO_E2H)
	ldr	x3, =(CNTHCTL_EL1PCTEN | CNTHCTL_EL1PCEN)
	ldr	x5, =(PSR_D | PSR_A | PSR_I | PSR_F | PSR_M_EL1h)

.Ldone_vhe:
	msr	cptr_el2, x2
	msr	cnthctl_el2, x3
	msr	spsr_el2, x5

	/*
	 * Configure the Extended Hypervisor Configuration Register when
	 * FEAT_HCX is available.
	 */
	mrs	x2, id_aa64mmfr1_el1
	ubfx	x2, x2, #40, #4
	cmp	x2, #0
	b.eq	2f
	mov	x2, xzr
	msr	s3_4_c1_c2_2, x2
	isb

2:
	/* don't trap to EL2 for CP15 traps */
	msr	hstr_el2, xzr

	/* set the counter offset to a known value */
	msr	cntvoff_el2, xzr

	/*
	 * There's no vttbr in our setup - we're either a small stub at EL2
	 * that dispatches to the host at EL1 or we're a unified EL1/EL2, in
	 * which case we use the EL1 TTBR[01].
	 */
	msr	vttbr_el2, xzr

	/*
	 * Enable GICv3+ system register access where that's applicable.
	 */
	mrs	x2, id_aa64pfr0_el1
	ubfx	x2, x2, #24, #4
	cmp	x2, #0
	b.eq	3f
	mrs	x2, icc_sre_el2
	orr	x2, x2, #ICC_SRE_EL2_EN
	orr	x2, x2, #ICC_SRE_EL2_SRE
	msr	icc_sre_el2, x2

3:
	/*
	 * Apply known errata applicable at EL2.
	 */
	mrs	x0, midr_el1
	/* examine implementer, must be Arm (0x41) */
	ubfx	x1, x0, #24, #8
	cmp	x1, #(MIDR_IMPL_ARM)
	b.ne	.Lnot_cortex_a5x_0
	/* examine the architecture, must be 0xf */
	ubfx	x1, x0, #15, #4
	cmp	x1, #0xF
	b.ne	.Lnot_cortex_a5x_0
	/* examine the part */
	ubfx	x1, x0, #4, #12
	cmp	x1, #(MIDR_PART_ARM_CORTEX_A72)
	b.eq	.Lcortex_a72_0
	cmp	x1, #(MIDR_PART_ARM_CORTEX_A57)
	b.eq	.Lcortex_a57_0
	/* Explicitly _not_ Cortex-A55 */
	cmp	x1, #(MIDR_PART_ARM_CORTEX_A53)
	b.eq	.Lcortex_a53_0
	b	.Lnot_cortex_a5x_0

.Lcortex_a72_0:
.Lcortex_a57_0:
.Lcortex_a53_0:
	// access L2ACTLR L2ECTLR L2CTLR CPUECTLR CPUACTLR
	mrs	x0, actlr_el2
	orr	x0, x0, #0x70
	orr	x0, x0, #0x3
	msr	actlr_el2, x0
.Lnot_cortex_a5x_0:

	/*
	 * Set up and execute an exception return to our target exception
	 * level, which is either EL1 or EL2. This also synchronises PSTATE.
	 */
	msr	elr_el2, x30
	isb
	eret

.Lrun_dboot:
	/*
	 * Apply known errata applicable at EL1 or unified EL1/EL2.
	 */
	mrs	x0, midr_el1
	/* examine implementer, must be Arm (0x41) */
	ubfx	x1, x0, #24, #8
	cmp	x1, #(MIDR_IMPL_ARM)
	b.ne	.Lnot_cortex_a5x_1
	/* examine the architecture, must be 0xf */
	ubfx	x1, x0, #15, #4
	cmp	x1, #0xF
	b.ne	.Lnot_cortex_a5x_1
	/* examine the part */
	ubfx	x1, x0, #4, #12
	cmp	x1, #(MIDR_PART_ARM_CORTEX_A72)
	b.eq	.Lcortex_a72_1
	cmp	x1, #(MIDR_PART_ARM_CORTEX_A57)
	b.eq	.Lcortex_a57_1
	/* explicitly _not_ Cortex-A55 */
	cmp	x1, #(MIDR_PART_ARM_CORTEX_A53)
	b.eq	.Lcortex_a53_1
	b	.Lnot_cortex_a5x_1

.Lcortex_a72_1:
.Lcortex_a57_1:
.Lcortex_a53_1:
	/* CPUECTLR_EL1.SMPEN -> 1 (enable cache coherence) */
	mrs	x0, s3_1_c15_c2_1
	tbnz	x0, #6, .Lnot_cortex_a5x_1
	orr	x0, x0, #(1<<6)
	msr	s3_1_c15_c2_1, x0
	dsb	sy
	isb
.Lnot_cortex_a5x_1:

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

	mov	x0, x26
	mov	x1, x25
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

	/*
	 * This set of Hypervisor stub vectors is used during early boot to
	 * install the kernel's Hypervisor vectors.
	 *
	 * The only implemented trap is Synchronous 64-bit EL1, and the only
	 * thing this does is to install the address passed in x0 to vbar_el2.
	 */
	.align	11
	ENTRY(hyp_stub_vectors)
	.align	7	/* Synchronous EL2t */
1:	b	1b
	.align	7	/* IRQ EL2t */
1:	b	1b
	.align	7	/* FIQ EL2t */
1:	b	1b
	.align	7	/* SError EL2t */
1:	b	1b

	.align	7	/* Synchronous EL2h */
1:	b	1b
	.align	7	/* IRQ EL2h */
1:	b	1b
	.align	7	/* FIQ EL2h */
1:	b	1b
	.align	7	/* SError EL2h */
1:	b	1b

	.align	7	/* Synchronous 64-bit EL1 */
	msr	vbar_el2, x0
	eret
	.align	7	/* IRQ 64-bit EL1 */
1:	b	1b
	.align	7	/* FIQ 64-bit EL1 */
1:	b	1b
	.align	7	/* SError 64-bit EL1 */
1:	b	1b

	.align	7	/* Synchronous 32-bit EL1 */
1:	b	1b
	.align	7	/* IRQ 32-bit EL1 */
1:	b	1b
	.align	7	/* FIQ 32-bit EL1 */
1:	b	1b
	.align	7	/* SError 32-bit EL1 */
1:	b	1b
	SET_SIZE(hyp_stub_vectors)
