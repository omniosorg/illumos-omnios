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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * The GCC used for illumos on aarch64 is patched with the -msave-args option.
 * When the option is specified, INTEGER type function arguments passed via
 * registers will be saved on the stack immediately after %fp, and will not
 * be modified through out the life of the routine.
 *
 *				+-------+
 *		fp	-->     |  %fp  |
 *				+-------+
 *		[fp, #8]	|  %x0  |
 *				+-------+
 *		[fp, #16]	|  %x1  |
 *				+-------+
 *		[fp, #24]	|  %r2  |
 *				+-------+
 *		...
 *				+-------+
 *		[fp, #64]	|  %r7  |
 *				+-------+
 *
 * For example, for the following function,
 *
 * void
 * foo(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9)
 * {
 * ...
 * }
 *
 * Disassembled code will look something like the following:
 *
 *	stp	x29, x30, [sp, #-112]!
 *	mov	x29, sp
 *	stp	x0, x1, [sp, #16]
 *	stp	x2, x3, [sp, #32]
 *	stp	x4, x5, [sp, #48]
 *	stp	x6, x7, [sp, #64]
 *
 * or:
 *
 *	sub	sp, sp, #0xd0
 *	stp	x29, x30, [sp, #16]
 *	add	x29, sp, #0x10	<--- X
 *	stp	x0, x1, [sp, #32]
 *	stp	x2, x3, [sp, #48]
 *	stp	x4, x5, [sp, #64]
 *	stp	x6, x7, [sp, #80]
 *
 * Where the immediate X is variable.
 *
 * NB: The `add` and the 'mov fp, sp` are
 * actually the same instruction.  The latter being an alias.
 *
 * We loop through the first SAVEARGS_INSN_SEQ_LEN bytes of the function
 * looking for each argument saving instruction we would expect to see.
 */

#include <sys/bitext.h>
#include <sys/regset.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <string.h>
#include <saveargs.h>


static inline int32_t
signextend32(uint32_t x, unsigned int bits)
{
	return ((int32_t)(x << (32 - bits))) >> (32 - bits);
}

typedef struct {
	enum {
		STP_POST_INDEX,
		STP_PRE_INDEX,
		STP_SIGNED_OFFSET
	} stp_immmode;
	uint32_t stp_imm7;
	uint8_t stp_rn;
	uint8_t stp_rt;
	uint8_t stp_rt2;
} stp_insn_t;

#define	STP_IMM7(x)	(signextend32(bitx32(x, 22, 15), 7) * 8)
#define	STP_RT(x)	bitx32(x, 4, 0)
#define	STP_RT2(x)	bitx32(x, 14, 10)
#define	STP_RN(x)	bitx32(x, 9, 5)

#define	INSN_STP_MASK		0xffc00000
#define	INSN_STP_POST_INDEX	0xa8800000
#define	INSN_STP_PRE_INDEX	0xa9800000
#define	INSN_STP_SIGNED_OFFSET	0xa9000000

static inline boolean_t
decode_stp(uint32_t instr, stp_insn_t *ret)
{
	if ((instr & INSN_STP_MASK) == INSN_STP_POST_INDEX) {
		ret->stp_immmode = STP_POST_INDEX;
	} else if ((instr & INSN_STP_MASK) == INSN_STP_PRE_INDEX) {
		ret->stp_immmode = STP_PRE_INDEX;
	} else if ((instr & INSN_STP_MASK) == INSN_STP_SIGNED_OFFSET) {
		ret->stp_immmode = STP_SIGNED_OFFSET;
	} else {
		return (B_FALSE);
	}

	ret->stp_imm7 = STP_IMM7(instr);
	ret->stp_rt = STP_RT(instr);
	ret->stp_rt2 = STP_RT2(instr);
	ret->stp_rn = STP_RN(instr);

	return (B_TRUE);
}

typedef struct {
	uint16_t str_imm12;
	uint8_t str_rn;
	uint8_t str_rt;
} str_insn_t;

/*
 * This is str (immediate) with an unsigned offset, explicitly, no other str
 * varieties.  (even the mask is specific)
 */
#define	INSN_STR_MASK		0xffc00000
#define	INSN_STR_IMM_UO		0xf9000000

#define	STR_IMM12(x)	(bitx32(x, 21, 10) * 8)
#define	STR_RN(x)	bitx32(x, 9, 5)
#define	STR_RT(x)	bitx32(x, 4, 0)

static inline boolean_t
decode_str(uint32_t instr, str_insn_t *ret)
{
	if ((instr & INSN_STR_MASK) != INSN_STR_IMM_UO)
		return (B_FALSE);

	ret->str_imm12 = STR_IMM12(instr);
	ret->str_rn = STR_RN(instr);
	ret->str_rt = STR_RT(instr);

	return (B_TRUE);
}

typedef struct {
	uint16_t add_imm;
	uint8_t add_rd;
	uint8_t add_rn;
} add_insn_t;

/* 64bit add immediate */
#define	INSN_ADD_MASK		0xff800000
#define	INSN_ADD_IMM		0x91000000

#define	ADD_IMM12(x)	bitx32(x, 21, 10)
#define	ADD_RN(x)	bitx32(x, 9, 5)
#define	ADD_RD(x)	bitx32(x, 4, 0)

static inline boolean_t
decode_add(uint32_t insn, add_insn_t *ret)
{
	if ((insn & INSN_ADD_MASK) == INSN_ADD_IMM) {
		ret->add_imm = ADD_IMM12(insn);
		ret->add_rn = ADD_RN(insn);
		ret->add_rd = ADD_RD(insn);

		return (B_TRUE);
	}

	return (B_FALSE);
}

/* Each register should be deposited at [#sp, N+2*8] */
#define	reg_to_offset(x) ((x + 2) * 8)

/*
 * Checking we saved a frame pointer is hard, the best we can do is look for
 * instructions writing the register.  Even then, the range of instructions it
 * might be seems high.
 */
int
saveargs_has_args(uint8_t *ins, size_t size, uint_t argc, int start_index)
{
	uint16_t found = 0;
	boolean_t have_fp_save = B_FALSE;
	uint16_t fp_sp_offset = 0;

	argc = MIN(argc, 8);

	if (size <= sizeof (uint32_t))
		return (SAVEARGS_NO_ARGS);

	for (int i = 0; i <= (size - sizeof (uint32_t));
	    i += sizeof (uint32_t)) {
		uint32_t *instr = (uint32_t *)&ins[i];

		if (!have_fp_save) {
			add_insn_t add;

			if ((decode_add(*instr, &add) == B_TRUE) &&
			    (add.add_rn == REG_SP) &&
			    (add.add_rd == REG_FP)) {
				have_fp_save = B_TRUE;
				fp_sp_offset = add.add_imm;
			} else {
				continue;
			}
		}

		str_insn_t str;
		if (decode_str(*instr, &str) == B_TRUE) {
			/* Saved arguments are offsets of the stack pointer */
			if (str.str_rn != REG_SP)
				continue;

			if ((str.str_rt <= REG_X7) &&
			    (str.str_imm12 == (reg_to_offset(str.str_rt) +
			    fp_sp_offset))) {
				found |= (1 << str.str_rt);
			}
		}

		stp_insn_t stp;
		if (decode_stp(*instr, &stp) == B_TRUE) {
			/*
			 * Saved arguments should be plain offsets of the
			 * stack pointer
			 */
			if ((stp.stp_immmode != STP_SIGNED_OFFSET) ||
			    (stp.stp_rn != REG_SP)) {
				continue;
			}

			if ((stp.stp_rt <= REG_X7) &&
			    (stp.stp_imm7 == (reg_to_offset(stp.stp_rt) +
			    fp_sp_offset))) {
				found |= (1 << stp.stp_rt);
			}

			if ((stp.stp_rt2 <= REG_X7) &&
			    (stp.stp_imm7 == ((reg_to_offset(stp.stp_rt2) +
			    fp_sp_offset) - 8))) {
				found |= (1 << stp.stp_rt2);
			}
		}

		if ((found & ((1 << argc) - 1)) == ((1 << argc) - 1))
			return (SAVEARGS_TRAD_ARGS);
	}

	return (SAVEARGS_NO_ARGS);
}
