/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

	.data
	.globl t0stack
	.type t0stack, @object
	.size t0stack, DEFAULTSTKSZ
	.align MMU_PAGESHIFT
t0stack:
	.zero DEFAULTSTKSZ

	.globl t0
	.type t0, @object
	.size t0, MMU_PAGESIZE
	.align MMU_PAGESHIFT
t0:
	.zero MMU_PAGESIZE

	ENTRY(_start)
	mov	x1, #1
	msr	SPSel, x1
	ldr	x1, =t0stack
	ldr	x2, =DEFAULTSTKSZ
	add	x1, x1, x2
	mov	x29, x1
	mov	sp, x1

	stp	x0, xzr, [sp, #-0x10]!
	bl	kobj_start
	ldp	x1, xzr, [sp], #0x10
	mov	x0, sp
	bl	mlsetup
	bl	main
1:	b	1b

	SET_SIZE(_start)

	.balign 4096
	ENTRY(secondary_vec_start)
	/*
	 * Stash the booted exception-level to x27, then ensure that it's
	 * EL1 or EL2.
	 */
	mrs	x27, CurrentEL
	ubfx	x27, x27, #2, #2
	cmp	x27, #0x2
	b.eq	.Lel2_entry
	cmp	x27, #0x1
	b.eq	1f
3:	b	3b

.Lel2_entry:
	bl	.Lel2_body
	b	.Lel_agnostic
.Lel2_body:
	/*
	 * We're at EL2.
	 */
	dsb	sy
	ldr	x2, =(SCTLR_EL2_RES1 | SCTLR_EL2_EIS | SCTLR_EL2_EOS)
	msr	sctlr_el2, x2
	isb

	/*
	 * Invalidate all caches and the TLB.
	 */
	mov	x19, lr
	bl	dcache_invalidate_all
	ic	iallu
	dsb	ish
	isb
	tlbi	vmalle1is
	dsb	ish
	isb
	mov	x30, x19

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
	 *
	 * The kernel itself will run at EL1.
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
	 * Set up and execute an exception return to our target exception
	 * level, which is either EL1 or EL2. This also synchronises PSTATE.
	 */
	msr	elr_el2, x30
	isb
	eret

.Lel1_entry:
	bl	.Lel1_body
	b	.Lel_agnostic
.Lel1_body:
	ldr	x2, =INIT_SCTLR_EL1
	msr	sctlr_el1, x2
	isb

	/*
	 * Ensure that PSTATE and SPSR_EL1 are in sync. We do this by updating
	 * SPSR_EL1 and executing an exception return (to EL1), which then
	 * transfers us to the EL-agnostic CPU startup.
	 */
	mov	x2, #(PSR_D | PSR_A | PSR_I | PSR_F | PSR_M_EL1h)
	msr	spsr_el1, x2
	msr	elr_el1, lr
	eret

.Lel_agnostic:
	/*
	 * Invalidate all caches and the TLB.
	 */
	mov	x19, lr
	bl	dcache_invalidate_all
	ic	iallu
	dsb	ish
	isb
	tlbi	vmalle1is
	dsb	ish
	isb
	mov	x30, x19

	/*
	 * Enable GICv3+ system register access where that's applicable.
	 */
	mrs	x2, id_aa64pfr0_el1
	ubfx	x2, x2, #24, #4
	cmp	x2, #0
	b.eq	1f
	mrs	x2, icc_sre_el1
	orr	x2, x2, #ICC_SRE_EL1_SRE
	msr	icc_sre_el1, x2
1:

	/*
	 * Enable SMP cache coherence.
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

	/*
	 * NOTE: we don't set cpacr_el1 here, which is something we do in
	 * dboot for the boot processor. Might need to revisit this as we
	 * get deeper into the bootstrap process, but for now we're booting
	 * into a kernel that has the correct traps in place already, so it
	 * is unlikely we'll need this.
	 */
#if 0
	mrs	x0, cpacr_el1
	bic	x0, x0, #CPACR_FPEN_MASK
	//orr	x0, x0, #CPACR_FPEN_DIS
	msr	cpacr_el1, x0
#endif

	/*
	 * Invalidate all caches and the TLB (again).
	 */
	mov	x19, lr
	bl	dcache_invalidate_all
	ic	iallu
	dsb	ish
	isb
	tlbi	vmalle1is
	dsb	ish
	isb
	mov	x30, x19

	/*
	 * Load up system registers stashed by mp_startup.
	 *
	 * These are stored in a `struct cpu_startup_data` that is placed
	 * at `secondary_vec_end`.
	 */
	adr	x0, secondary_vec_end

	/* memory attribute indirection */
	ldr	x1, [x0, #STARTUP_MAIR]
	msr	mair_el1, x1

	/* translation control */
	ldr	x1, [x0, #STARTUP_TCR]
	msr	tcr_el1, x1

	/* translation table base address for lower mappings */
	ldr	x1, [x0, #STARTUP_TTBR0]
	msr	ttbr0_el1, x1

	/* translation table base address for upper mappings */
	ldr	x1, [x0, #STARTUP_TTBR1]
	msr	ttbr1_el1, x1

	/* system control */
	ldr	x1, [x0, #STARTUP_SCTLR]
	isb
	msr	sctlr_el1, x1
	isb

	/* replace the hypervisor stub if appropriate */
	cbz	x25, 1f
	ldr	x1, [x0, #STARTUP_VBAR]
	cbz	x1, 1f
	mov	x0, x1
	hvc	#0
1:

	/*
	 * We can now access kernel data, but we can't jump into KVA yet,
	 * as this code has been copied to a CPU startup page. The jump to
	 * KVA happens once we've found our CPU and as we return from this
	 * function into the kernel code.
	 */
	ldr	x0, =cpu
	mov	x1, #0

1:	cmp	x1, #NCPU
	b.eq	faild
	ldr	x2, [x0]	// x2 (struct cpu *)

	cbz	x2, 2f
	ldr	x3, [x2, #CPU_AFFINITY]
	mrs	x4, mpidr_el1
	ldr	x5, =MPIDR_AFF_MASK
	and	x4, x4, x5
	cmp	x3, x4
	b.eq	cpu_found

2:	add	x0, x0, #8
	add	x1, x1, #1
	b	1b

cpu_found:
	ldr	x1, [x2, #CPU_THREAD]
	msr	tpidr_el1, x1

	ldr	x29, [x1, #T_LABEL_X29]
	ldr	x30, [x1, #T_LABEL_PC]
	ldr	x0,  [x1, #T_LABEL_SP]
	mov	sp, x0
	/* return to the entry point with the new stack */
	ret

faild:
	wfi
	b	faild

dcache_invalidate_all:
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
	dsb	ish
	b.gt	0b
4:	ret
	.ltorg

	.globl secondary_vec_end
secondary_vec_end:
	.balign 4096
SET_SIZE(secondary_vec_start)

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
