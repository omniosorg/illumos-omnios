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

/*
 * Mask of FPCR bits that userland is permitted to set.  Used to sanitise
 * user-supplied FPCR values in setfpregs (signal return, /proc, etc.).
 *
 * Permitted: AHP, DN, FZ, RM, FZ16, exception trap enables (IDE..IOE).
 * Excluded: reserved bits, NEP, AFP, FIZ, EBF (require optional features
 * and could cause unexpected trapping or behavioural changes).
 */
#define	FPCR_USER_MASK	(FPCR_AHP | FPCR_DN | FPCR_FZ | FPCR_RM_MASK | \
			    FPCR_FZ16 | FPCR_IDE | FPCR_IXE | FPCR_UFE | \
			    FPCR_OFE | FPCR_DZE | FPCR_IOE)

/*
 * Mask of FPSR bits that userland is permitted to set.
 *
 * Permitted: condition flags (N, Z, C, V), cumulative saturation (QC),
 * and cumulative exception flags (IDC, IXC, UFC, OFC, DZC, IOC).
 */
#define	FPSR_USER_MASK	(FPSR_N | FPSR_Z | FPSR_C | FPSR_V | FPSR_QC | \
			    FPSR_IDC | FPSR_IXC | FPSR_UFC | FPSR_OFC | \
			    FPSR_DZC | FPSR_IOC)

/*
 * fpu_flags values.  These mirror the intel/sys/pcb.h definitions so
 * that the two implementations are conceptually similar.
 *
 * FPU_EN	Thread has used the FPU (ctxops installed).
 * FPU_VALID	fpu_regs contains valid saved state (hardware may differ).
 * FPU_KERNEL	Kernel is currently using the FPU via kernel_fpu_begin.
 */
#define	FPU_EN		0x01
#define	FPU_VALID	0x02
#define	FPU_KERNEL	0x08

#ifndef _ASM
typedef upad128_t fpreg_t;

/*
 * Hardware FPU save area -- 32 x 128-bit SIMD/FP registers + FPCR + FPSR.
 */
typedef struct {
	fpreg_t			kfpu_regs[32];
	uint32_t		kfpu_cr;
	uint32_t		kfpu_sr;
} kfpu_t;

/*
 * Per-LWP FPU context.  The fpu_flags field drives all save/restore
 * decisions -- see the flag definitions above.
 */
typedef struct fpu_ctx {
	kfpu_t		fpu_regs;	/* kernel save area for FPU */
	uint_t		fpu_flags;	/* FPU state flags */
} fpu_ctx_t;

extern void fp_save_hw(kfpu_t *);
extern void fp_restore_hw(kfpu_t *);
extern void fp_save(fpu_ctx_t *);
extern void fp_restore(fpu_ctx_t *);
extern void fp_exec(void);
extern int fp_fenflt(void);
#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FP_H */
