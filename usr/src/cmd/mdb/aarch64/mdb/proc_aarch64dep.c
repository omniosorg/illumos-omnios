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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2022 Richard Lowe
 */

/*
 * User Process Target for AArch64
 *
 * This file provides the ISA-dependent portion of the user process target.
 * For more details on the implementation refer to mdb_proc.c.
 */

#include <sys/frame.h>
#include <sys/fp.h>

#include <stddef.h>

#include <mdb/mdb_proc.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb.h>

const mdb_tgt_regdesc_t pt_regdesc[] = {
	{ "r0", REG_X0, MDB_TGT_R_EXPORT },
	{ "x0", REG_X0, MDB_TGT_R_EXPORT },
	{ "w0", REG_X0, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r1", REG_X1, MDB_TGT_R_EXPORT },
	{ "x1", REG_X1, MDB_TGT_R_EXPORT },
	{ "w1", REG_X1, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r2", REG_X2, MDB_TGT_R_EXPORT },
	{ "x2", REG_X2, MDB_TGT_R_EXPORT },
	{ "w2", REG_X2, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r3", REG_X3, MDB_TGT_R_EXPORT },
	{ "x3", REG_X3, MDB_TGT_R_EXPORT },
	{ "w3", REG_X3, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r4", REG_X4, MDB_TGT_R_EXPORT },
	{ "x4", REG_X4, MDB_TGT_R_EXPORT },
	{ "w4", REG_X4, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r5", REG_X5, MDB_TGT_R_EXPORT },
	{ "x5", REG_X5, MDB_TGT_R_EXPORT },
	{ "w5", REG_X5, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r6", REG_X6, MDB_TGT_R_EXPORT },
	{ "x6", REG_X6, MDB_TGT_R_EXPORT },
	{ "w6", REG_X6, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r7", REG_X7, MDB_TGT_R_EXPORT },
	{ "x7", REG_X7, MDB_TGT_R_EXPORT },
	{ "w7", REG_X7, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r8", REG_X8, MDB_TGT_R_EXPORT },
	{ "x8", REG_X8, MDB_TGT_R_EXPORT },
	{ "w8", REG_X8, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r9", REG_X9, MDB_TGT_R_EXPORT },
	{ "x9", REG_X9, MDB_TGT_R_EXPORT },
	{ "w9", REG_X9, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r10", REG_X10, MDB_TGT_R_EXPORT },
	{ "x10", REG_X10, MDB_TGT_R_EXPORT },
	{ "w10", REG_X10, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r11", REG_X11, MDB_TGT_R_EXPORT },
	{ "x11", REG_X11, MDB_TGT_R_EXPORT },
	{ "w11", REG_X11, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r12", REG_X12, MDB_TGT_R_EXPORT },
	{ "x12", REG_X12, MDB_TGT_R_EXPORT },
	{ "w12", REG_X12, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r13", REG_X13, MDB_TGT_R_EXPORT },
	{ "x13", REG_X13, MDB_TGT_R_EXPORT },
	{ "w13", REG_X13, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r14", REG_X14, MDB_TGT_R_EXPORT },
	{ "x14", REG_X14, MDB_TGT_R_EXPORT },
	{ "w14", REG_X14, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r15", REG_X15, MDB_TGT_R_EXPORT },
	{ "x15", REG_X15, MDB_TGT_R_EXPORT },
	{ "w15", REG_X15, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r16", REG_X16, MDB_TGT_R_EXPORT },
	{ "x16", REG_X16, MDB_TGT_R_EXPORT },
	{ "w16", REG_X16, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r17", REG_X17, MDB_TGT_R_EXPORT },
	{ "x17", REG_X17, MDB_TGT_R_EXPORT },
	{ "w17", REG_X17, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r18", REG_X18, MDB_TGT_R_EXPORT },
	{ "x18", REG_X18, MDB_TGT_R_EXPORT },
	{ "w18", REG_X18, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r19", REG_X19, MDB_TGT_R_EXPORT },
	{ "x19", REG_X19, MDB_TGT_R_EXPORT },
	{ "w19", REG_X19, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r20", REG_X20, MDB_TGT_R_EXPORT },
	{ "x20", REG_X20, MDB_TGT_R_EXPORT },
	{ "w20", REG_X20, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r21", REG_X21, MDB_TGT_R_EXPORT },
	{ "x21", REG_X21, MDB_TGT_R_EXPORT },
	{ "w21", REG_X21, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r22", REG_X22, MDB_TGT_R_EXPORT },
	{ "x22", REG_X22, MDB_TGT_R_EXPORT },
	{ "w22", REG_X22, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r23", REG_X23, MDB_TGT_R_EXPORT },
	{ "x23", REG_X23, MDB_TGT_R_EXPORT },
	{ "w23", REG_X23, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r24", REG_X24, MDB_TGT_R_EXPORT },
	{ "x24", REG_X24, MDB_TGT_R_EXPORT },
	{ "w24", REG_X24, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r25", REG_X25, MDB_TGT_R_EXPORT },
	{ "x25", REG_X25, MDB_TGT_R_EXPORT },
	{ "w25", REG_X25, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r26", REG_X26, MDB_TGT_R_EXPORT },
	{ "x26", REG_X26, MDB_TGT_R_EXPORT },
	{ "w26", REG_X26, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r27", REG_X27, MDB_TGT_R_EXPORT },
	{ "x27", REG_X27, MDB_TGT_R_EXPORT },
	{ "w27", REG_X27, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r28", REG_X28, MDB_TGT_R_EXPORT },
	{ "x28", REG_X28, MDB_TGT_R_EXPORT },
	{ "w28", REG_X28, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r29", REG_X29, MDB_TGT_R_EXPORT },
	{ "fp", REG_X29, MDB_TGT_R_EXPORT },
	{ "x29", REG_X29, MDB_TGT_R_EXPORT },
	{ "w29", REG_X29, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r30", REG_X30, MDB_TGT_R_EXPORT },
	{ "lr", REG_X30, MDB_TGT_R_EXPORT },
	{ "x30", REG_X30, MDB_TGT_R_EXPORT },
	{ "w30", REG_X30, MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "sp", REG_SP, MDB_TGT_R_EXPORT },
	{ "pc", REG_PC, MDB_TGT_R_EXPORT },
	{ "spsr", REG_SPSR, MDB_TGT_R_EXPORT },
	{ "tp", REG_TP, MDB_TGT_R_EXPORT },
	{ NULL, 0, 0 },
};

int
pt_frameregs(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs, boolean_t pc_faked)
{
	return (set_errno(ENOTSUP));
}

const char *
pt_disasm(const GElf_Ehdr *ehp)
{
	return ("a64");
}

static const char *
fpcr2str(uint64_t fpcr, char *buf, size_t nbytes)
{
	char *end = buf + nbytes;
	char *p = buf;

	buf[0] = '\0';

	if (fpcr & FPCR_AHP)
		p += mdb_snprintf(p, (size_t)(end - p), "|AHP");
	if (fpcr & FPCR_DN)
		p += mdb_snprintf(p, (size_t)(end - p), "|DN");
	if (fpcr & FPCR_FZ)
		p += mdb_snprintf(p, (size_t)(end - p), "|FZ");

	switch (FPCR_RM(fpcr)) {
	case FPCR_RM_RN:
		p += mdb_snprintf(p, (size_t)(end - p), "|RTN");
		break;
	case FPCR_RM_RP:
		p += mdb_snprintf(p, (size_t)(end - p), "|RU");
		break;
	case FPCR_RM_RM:
		p += mdb_snprintf(p, (size_t)(end - p), "|RD");
		break;
	case FPCR_RM_RZ:
		p += mdb_snprintf(p, (size_t)(end - p), "|RTZ");
		break;
	default:
		p += mdb_snprintf(p, (size_t)(end - p), "|RT?");
	}

	if (fpcr & FPCR_FZ16)
		p += mdb_snprintf(p, (size_t)(end - p), "|FZ16");
	if (fpcr & FPCR_IDE)
		p += mdb_snprintf(p, (size_t)(end - p), "|IDE");
	if (fpcr & FPCR_EBF)
		p += mdb_snprintf(p, (size_t)(end - p), "|EBF");
	if (fpcr & FPCR_IXE)
		p += mdb_snprintf(p, (size_t)(end - p), "|IXE");
	if (fpcr & FPCR_UFE)
		p += mdb_snprintf(p, (size_t)(end - p), "|UFE");
	if (fpcr & FPCR_OFE)
		p += mdb_snprintf(p, (size_t)(end - p), "|OFE");
	if (fpcr & FPCR_DZE)
		p += mdb_snprintf(p, (size_t)(end - p), "|DZE");
	if (fpcr & FPCR_IOE)
		p += mdb_snprintf(p, (size_t)(end - p), "|IOE");
	if (fpcr & FPCR_NEP)
		p += mdb_snprintf(p, (size_t)(end - p), "|NEP");
	if (fpcr & FPCR_AFP)
		p += mdb_snprintf(p, (size_t)(end - p), "|AFP");
	if (fpcr & FPCR_FIZ)
		p += mdb_snprintf(p, (size_t)(end - p), "|FIZ");

	if (buf[0] == '|')
		return (buf + 1);

	return ("0");
}

static const char *
fpsr2str(uint64_t fpsr, char *buf, size_t nbytes)
{
	char *end = buf + nbytes;
	char *p = buf;

	buf[0] = '\0';

	if (fpsr & FPSR_N)
		p += mdb_snprintf(p, (size_t)(end - p), "|N");
	if (fpsr & FPSR_Z)
		p += mdb_snprintf(p, (size_t)(end - p), "|Z");
	if (fpsr & FPSR_C)
		p += mdb_snprintf(p, (size_t)(end - p), "|C");
	if (fpsr & FPSR_V)
		p += mdb_snprintf(p, (size_t)(end - p), "|V");
	if (fpsr & FPSR_QC)
		p += mdb_snprintf(p, (size_t)(end - p), "|QC");
	if (fpsr & FPSR_IDC)
		p += mdb_snprintf(p, (size_t)(end - p), "|IDC");
	if (fpsr & FPSR_IXC)
		p += mdb_snprintf(p, (size_t)(end - p), "|IXC");
	if (fpsr & FPSR_UFC)
		p += mdb_snprintf(p, (size_t)(end - p), "|UFC");
	if (fpsr & FPSR_OFC)
		p += mdb_snprintf(p, (size_t)(end - p), "|OFC");
	if (fpsr & FPSR_DZC)
		p += mdb_snprintf(p, (size_t)(end - p), "|DZC");
	if (fpsr & FPSR_IOC)
		p += mdb_snprintf(p, (size_t)(end - p), "|IOC");

	if (buf[0] == '|')
		return (buf + 1);

	return ("0");
}

int
pt_fpregs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_tid_t tid;
	prfpregset_t fprs;
	char buf[256];
	uint_t top;
	int i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) == PS_UNDEAD) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	if (Pstate(t->t_pshandle) == PS_LOST) {
		mdb_warn("debugger has lost control of process\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC)
		tid = (mdb_tgt_tid_t)addr;
	else
		tid = PTL_TID(t);

	/*
	 * XXXARM: This needs real work to account for different hardware
	 * support, from procfs on up.  Also, we need to do something about
	 * SME.
	 */

	if (PTL_GETFPREGS(t, tid, &fprs) != 0) {
		mdb_warn("failed to get floating point registers");
		return (DCMD_ERR);
	}

	for (int i = 0; i < 32; i++) {
		/*
		 * XXXARM: I'd like to find a useful way to print these in a
		 * vector view, but have so far failed, and just stuck to
		 * Vn.4S because of circumstance.
		 */
		mdb_printf("%%q%-2d  0x%08x %08x %08x %08x\n", i,
		    fprs.d_fpregs[i]._l[3], fprs.d_fpregs[i]._l[2],
		    fprs.d_fpregs[i]._l[1], fprs.d_fpregs[i]._l[0]);
	}

	mdb_printf("fpcr    0x%04x (%s)\n", fprs.fp_cr,
	    fpcr2str(fprs.fp_cr, buf, sizeof (buf)));
	mdb_printf("fpsr    0x%04x (%s)\n", fprs.fp_sr,
	    fpsr2str(fprs.fp_sr, buf, sizeof (buf)));

	return (DCMD_OK);
}

/*
 * We cannot rely on pr_instr, because if we hit a breakpoint or the user has
 * artificially modified memory, it will no longer be correct.
 */
static uint32_t
pt_read_instr(mdb_tgt_t *t)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	uint32_t ret = 0;

	(void) mdb_tgt_aread(t, MDB_TGT_AS_VIRT_I, &ret, sizeof (ret),
	    psp->pr_reg[REG_PC]);

	return (ret);
}

int
pt_next(mdb_tgt_t *t, uintptr_t *p)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;

	if (Pstate(t->t_pshandle) != PS_STOP)
		return (set_errno(EMDB_TGTBUSY));

	return (mdb_isa_next(t, p, psp->pr_reg[REG_PC], pt_read_instr(t)));
}

int
pt_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_tid_t tid;
	prgregset_t grs;
	prgreg_t rflags;
	boolean_t from_ucontext = B_FALSE;

	if (mdb_getopts(argc, argv,
	    'u', MDB_OPT_SETBITS, B_TRUE, &from_ucontext, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (from_ucontext) {
		int off;
		int o0, o1;

		if (!(flags & DCMD_ADDRSPEC)) {
			mdb_warn("-u requires a ucontext_t address\n");
			return (DCMD_ERR);
		}

		o0 = mdb_ctf_offsetof_by_name("ucontext_t", "uc_mcontext");
		o1 = mdb_ctf_offsetof_by_name("mcontext_t", "gregs");
		if (o0 == -1 || o1 == -1) {
			off = offsetof(ucontext_t, uc_mcontext) +
			    offsetof(mcontext_t, gregs);
		} else {
			off = o0 + o1;
		}

		if (mdb_vread(&grs, sizeof (grs), addr + off) != sizeof (grs)) {
			mdb_warn("failed to read from ucontext_t %p", addr);
			return (DCMD_ERR);
		}
		goto print_regs;
	}

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) == PS_UNDEAD) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	if (Pstate(t->t_pshandle) == PS_LOST) {
		mdb_warn("debugger has lost control of process\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC)
		tid = (mdb_tgt_tid_t)addr;
	else
		tid = PTL_TID(t);

	if (PTL_GETREGS(t, tid, grs) != 0) {
		mdb_warn("failed to get current register set");
		return (DCMD_ERR);
	}

print_regs:
	mdb_printf("%%x0 = 0x%0?p\t%%x1 = 0x%0?p\n",
	    grs[REG_X0], grs[REG_X1]);
	mdb_printf("%%x2 = 0x%0?p\t%%x3 = 0x%0?p\n",
	    grs[REG_X2], grs[REG_X3]);
	mdb_printf("%%x4 = 0x%0?p\t%%x5 = 0x%0?p\n",
	    grs[REG_X4], grs[REG_X5]);
	mdb_printf("%%x6 = 0x%0?p\t%%x7 = 0x%0?p\n",
	    grs[REG_X6], grs[REG_X7]);
	mdb_printf("%%x8 = 0x%0?p\t%%x9 = 0x%0?p\n",
	    grs[REG_X8], grs[REG_X9]);
	mdb_printf("%%x10 = 0x%0?p\t%%x11 = 0x%0?p\n",
	    grs[REG_X10], grs[REG_X11]);
	mdb_printf("%%x12 = 0x%0?p\t%%x13 = 0x%0?p\n",
	    grs[REG_X12], grs[REG_X13]);
	mdb_printf("%%x14 = 0x%0?p\t%%x15 = 0x%0?p\n",
	    grs[REG_X14], grs[REG_X15]);
	mdb_printf("%%x16 = 0x%0?p\t%%x17 = 0x%0?p\n",
	    grs[REG_X16], grs[REG_X17]);
	mdb_printf("%%x18 = 0x%0?p\t%%x19 = 0x%0?p\n",
	    grs[REG_X18], grs[REG_X19]);
	mdb_printf("%%x20 = 0x%0?p\t%%x21 = 0x%0?p\n",
	    grs[REG_X20], grs[REG_X21]);
	mdb_printf("%%x22 = 0x%0?p\t%%x23 = 0x%0?p\n",
	    grs[REG_X22], grs[REG_X23]);
	mdb_printf("%%x24 = 0x%0?p\t%%x25 = 0x%0?p\n",
	    grs[REG_X24], grs[REG_X25]);
	mdb_printf("%%x26 = 0x%0?p\t%%x27 = 0x%0?p\n",
	    grs[REG_X26], grs[REG_X27]);
	mdb_printf("%%x28 = 0x%0?p\t%%x29 = 0x%0?p\n",
	    grs[REG_X28], grs[REG_X29]);
	mdb_printf("%%x30 = 0x%0?p\n", grs[REG_X30]);
	mdb_printf("\n");

	mdb_printf("%%sp = 0x%0?p\t%%pc = 0x%0?p\n",
	    grs[REG_SP], grs[REG_PC]);
	mdb_printf("%%tp = 0x%0?p\t%%spsr = 0x%0?p\n",
	    grs[REG_TP], grs[REG_SPSR]);

	return (DCMD_OK);
}

/*
 * Determine the return address for the current frame.
 *
 * XXXARM: On x86 we're kind and try to deal with the case where we haven't
 * yet set up the frame, here we don't and just give you back the saved frame
 * pointer, at the moment.
 *
 * XXXARM: It's possible we could just return %lr directly, but there's no
 * inherent reason you can't use that as scratch as long as you fix it before
 * you ret, so in the name of safety we don't trust it.
 */
int
pt_step_out(mdb_tgt_t *t, uintptr_t *p)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	struct frame fr;

	if (Pstate(t->t_pshandle) != PS_STOP)
		return (set_errno(EMDB_TGTBUSY));

	if (mdb_tgt_aread(t, MDB_TGT_AS_VIRT_S, &fr, sizeof (fr),
	    psp->pr_reg[REG_FP]) == sizeof (fr)) {
		*p = fr.fr_savpc;
		return (0);
	}

	return (-1);
}

int
pt_getfpreg(mdb_tgt_t *t, mdb_tgt_tid_t tid, ushort_t rd_num,
    ushort_t rd_flags, mdb_tgt_reg_t *rp)
{
	return (set_errno(ENOTSUP));
}

int
pt_putfpreg(mdb_tgt_t *t, mdb_tgt_tid_t tid, ushort_t rd_num,
    ushort_t rd_flags, mdb_tgt_reg_t rval)
{
	return (set_errno(ENOTSUP));
}

void
pt_addfpregs(mdb_tgt_t *t)
{
	/* not implemented */
}
