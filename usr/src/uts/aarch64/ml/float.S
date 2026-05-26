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
 */

#include <sys/asm_linkage.h>
#include <sys/errno.h>
#include "assym.h"

/*
 * void fp_restore_hw(kfpu_t *)
 *
 * Load V0-V31, FPCR, and FPSR from the given kfpu_t.
 * The FPU must be enabled (CPACR_EL1.FPEN) before calling.
 */
	ENTRY(fp_restore_hw)
	ldp	q0, q1,   [x0, #((0 * 32) + KFPU_REGS)]
	ldp	q2, q3,   [x0, #((1 * 32) + KFPU_REGS)]
	ldp	q4, q5,   [x0, #((2 * 32) + KFPU_REGS)]
	ldp	q6, q7,   [x0, #((3 * 32) + KFPU_REGS)]
	ldp	q8, q9,   [x0, #((4 * 32) + KFPU_REGS)]
	ldp	q10, q11, [x0, #((5 * 32) + KFPU_REGS)]
	ldp	q12, q13, [x0, #((6 * 32) + KFPU_REGS)]
	ldp	q14, q15, [x0, #((7 * 32) + KFPU_REGS)]
	ldp	q16, q17, [x0, #((8 * 32) + KFPU_REGS)]
	ldp	q18, q19, [x0, #((9 * 32) + KFPU_REGS)]
	ldp	q20, q21, [x0, #((10 * 32) + KFPU_REGS)]
	ldp	q22, q23, [x0, #((11 * 32) + KFPU_REGS)]
	ldp	q24, q25, [x0, #((12 * 32) + KFPU_REGS)]
	ldp	q26, q27, [x0, #((13 * 32) + KFPU_REGS)]
	ldp	q28, q29, [x0, #((14 * 32) + KFPU_REGS)]
	ldp	q30, q31, [x0, #((15 * 32) + KFPU_REGS)]

	ldr	w1, [x0, #KFPU_CR]
	msr	fpcr, x1
	ldr	w2, [x0, #KFPU_SR]
	msr	fpsr, x2

	ret
	SET_SIZE(fp_restore_hw)


/*
 * void fp_save_hw(kfpu_t *)
 *
 * Store V0-V31, FPCR, and FPSR into the given kfpu_t.
 * The FPU must be enabled (CPACR_EL1.FPEN) before calling.
 */
	ENTRY(fp_save_hw)
	stp	q0, q1,   [x0, #((0 * 32) + KFPU_REGS)]
	stp	q2, q3,   [x0, #((1 * 32) + KFPU_REGS)]
	stp	q4, q5,   [x0, #((2 * 32) + KFPU_REGS)]
	stp	q6, q7,   [x0, #((3 * 32) + KFPU_REGS)]
	stp	q8, q9,   [x0, #((4 * 32) + KFPU_REGS)]
	stp	q10, q11, [x0, #((5 * 32) + KFPU_REGS)]
	stp	q12, q13, [x0, #((6 * 32) + KFPU_REGS)]
	stp	q14, q15, [x0, #((7 * 32) + KFPU_REGS)]
	stp	q16, q17, [x0, #((8 * 32) + KFPU_REGS)]
	stp	q18, q19, [x0, #((9 * 32) + KFPU_REGS)]
	stp	q20, q21, [x0, #((10 * 32) + KFPU_REGS)]
	stp	q22, q23, [x0, #((11 * 32) + KFPU_REGS)]
	stp	q24, q25, [x0, #((12 * 32) + KFPU_REGS)]
	stp	q26, q27, [x0, #((13 * 32) + KFPU_REGS)]
	stp	q28, q29, [x0, #((14 * 32) + KFPU_REGS)]
	stp	q30, q31, [x0, #((15 * 32) + KFPU_REGS)]

	mrs	x1, fpcr
	str	w1, [x0, #KFPU_CR]
	mrs	x2, fpsr
	str	w2, [x0, #KFPU_SR]

	ret
	SET_SIZE(fp_save_hw)
