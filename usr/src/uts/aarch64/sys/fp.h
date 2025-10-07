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

#ifndef _SYS_FP_H
#define	_SYS_FP_H

#ifdef __cplusplus
extern "C" {
#endif


/*
 * All names/etc here are derived from:
 *
 * Arm® Architecture Registers for A-profile architecture
 */

/*
 * FPCR, Floating-point Control Register pp. 754
 */

/* [26] Alternate half precision? (rather than IEEE) */
#define	FPCR_AHP	(1 << 26)

/* [25] Default NaN rather than propagation? */
#define	FPCR_DN		(1 << 25)

/* [24] Flush denormalized numbers to 0? */
#define	FPCR_FZ		(1 << 24)

/* [23:22] Rounding mode */
#define	FPCR_RM_SHIFT	22
#define	FPCR_RM_MASK	(0x3 << FPCR_RM_SHIFT)
#define	FPCR_RM(fpcr)	((fpcr & FPCR_RM_MASK) >> FPCR_RM_SHIFT)

#define	FPCR_RM_RN	0	/* Round to Nearest */
#define	FPCR_RM_RP	1	/* Round towards Plus Infinity */
#define	FPCR_RM_RM	2	/* Round towards Minus Infinity */
#define	FPCR_RM_RZ	3	/* Round towards Zero */

/* [21:20] Stride: only used for AArch32 code, where it shouldn't be used */

/* [19] Flush denormalized half-precision floats to 0? */
#define	FPCR_FZ16	(1 << 19)		\

/* [18:16] Len: only used for AArch32 code, where it shouldn't be used  */

/* [15] Input Denormal exception trap enable? */
#define	FPCR_IDE	(1 << 15)

/* [13] extended BFloat16 dot-product? */
#define	FPCR_EBF	(1 << 14)

/* [12] Inexact exception trap enable */
#define	FPCR_IXE	(1 << 12)

/* [11] Underflow exception trap enable */
#define	FPCR_UFE	(1 << 11)

/* [10] Overflow exception trap enable */
#define	FPCR_OFE	(1 << 10)

/* [9]  Division by Zero exception trap enable */
#define	FPCR_DZE	(1 << 9)

/* [8] Invalid Operation exception trap enable */
#define	FPCR_IOE	(1 << 8)

/* [2] Controls how vectors are read, 0 is normal */
#define	FPCR_NEP	(1 << 2)

/* [1] Alternate handling? */
#define	FPCR_AFP	(1 << 1)

/* [0] flush denormalized inputs to zero? */
#define	FPCR_FIZ	(1 << 0)

/*
 * FPSR, Floating-point Status Register pp. 771
 */

/* [31] AArch32 negative? */
#define	FPSR_N		(1 << 31)

/* [30] AArch32 zero? */
#define	FPSR_Z		(1 << 30)

/* [29] AArch32 carry? */
#define	FPSR_C		(1 << 29)

/* [28] AArch32 overflow? */
#define	FPSR_V		(1 << 28)

/* [27] cumulative saturation since last cleared? */
#define	FPSR_QC		(1 << 27)

/* [7] input denormal cumulative exception since last cleared? */
#define	FPSR_IDC	(1 << 7)

/* [4] inexact cumulative exception since last cleared? */
#define	FPSR_IXC	(1 << 4)

/* [3] underflow cumulative exception since last cleared? */
#define	FPSR_UFC	(1 << 3)

/* [2] overflow cumulative exception since last cleared? */
#define	FPSR_OFC	(1 << 2)

/* [1] divide by zero cumulative exception since last cleared? */
#define	FPSR_DZC	(1 << 1)

/* [0] invalid operation cumulative exception since last cleared? */
#define	FPSR_IOC	(1 << 0)

#define	FPCR_INIT	(FPCR_RM_RN << FPCR_RM_SHIFT)

#ifndef _ASM
typedef upad128_t fpreg_t;

/*
 * Kernel's FPU save area
 */
typedef struct {
	fpreg_t			kfpu_regs[32];
	uint32_t		kfpu_cr;
	uint32_t		kfpu_sr;
} kfpu_t;

typedef struct fpu_ctx {
	kfpu_t		fpu_regs;	/* kernel save area for FPU */
} fpu_ctx_t;

extern void fp_save(fpu_ctx_t *ctx);
extern void fp_restore(fpu_ctx_t *ctx);
extern void fp_init(void);
extern int fp_fenflt(void);
#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FP_H */
