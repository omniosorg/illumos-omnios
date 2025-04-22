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
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * isa-dependent portions of the kmdb target
 */

#include <kmdb/kvm.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_asmutil.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_stack.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_list.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb.h>

#include <sys/types.h>
#include <sys/frame.h>
#include <sys/trap.h>
#include <sys/bitmap.h>
#include <sys/pci_impl.h>
#include <sys/sysmacros.h>

/* Higher than the highest trap number for which we have a defined specifier */
#define	KMT_MAXTRAPNO	0x40

const char *
kmt_def_dismode(void)
{
	return ("a64");
}

/*
 * Determine the return address for the current frame.
 */
int
kmt_step_out(mdb_tgt_t *t, uintptr_t *p)
{
	kreg_t fp;
	struct frame fr;

	(void) kmdb_dpi_get_register("fp", &fp);

	if (mdb_tgt_vread(t, &fr, sizeof (fr), fp) != sizeof (fr))
		return (-1);	/* errno is set for us */

	*p = fr.fr_savpc;
	return (0);
}

/*
 * Return the address of the next instruction following a call, or return -1
 * and set errno to EAGAIN if the target should just single-step.
 */
int
kmt_next(mdb_tgt_t *t, uintptr_t *p)
{
	kreg_t pc;
	mdb_instr_t instr;

	(void) kmdb_dpi_get_register("pc", &pc);

	if (mdb_tgt_vread(t, &instr, sizeof (mdb_instr_t), pc) !=
	    sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */


	return (mdb_isa_next(t, p, pc, instr));
}

static int
kmt_stack_common(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    int cpuid, mdb_stack_frame_flags_t sflags, mdb_tgt_stack_f *func)
{
	mdb_tgt_t *t = mdb.m_target;
	const mdb_tgt_gregset_t *grp = NULL;
	mdb_tgt_gregset_t gregs;
	mdb_stack_frame_hdl_t *hdl;
	uint_t arglim = mdb.m_nargs;
	int i;

	if (flags & DCMD_ADDRSPEC) {
		bzero(&gregs, sizeof (gregs));
		gregs.kregs[KREG_FP] = addr;
		grp = &gregs;
	} else {
		grp = kmdb_dpi_get_gregs(cpuid);
	}

	if (grp == NULL) {
		warn("failed to retrieve registers for cpu %d", cpuid);
		return (DCMD_ERR);
	}

	i = mdb_getopts(argc, argv,
	    's', MDB_OPT_SETBITS, MSF_SIZES, &sflags,
	    't', MDB_OPT_SETBITS, MSF_TYPES, &sflags,
	    'v', MDB_OPT_SETBITS, MSF_VERBOSE, &sflags,
	    NULL);

	argc -= i;
	argv += i;

	if (argc != 0) {
		if (argv->a_type == MDB_TYPE_CHAR || argc > 1)
			return (DCMD_USAGE);

		arglim = mdb_argtoull(argv);
	}

	if ((hdl = mdb_stack_frame_init(t, arglim, sflags)) == NULL) {
		mdb_warn("failed to init stack frame\n");
		return (DCMD_ERR);
	}

	(void) mdb_isa_kvm_stack_iter(t, grp, func, (void *)hdl);

	return (DCMD_OK);
}

int
kmt_cpustack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    int cpuid, uint_t verbose)
{
	return (kmt_stack_common(addr, flags, argc, argv, cpuid,
	    (verbose != 0 ? MSF_VERBOSE : 0), mdb_isa_kvm_frame));
}

int
kmt_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    0, mdb_isa_kvm_frame));
}

int
kmt_stackv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    MSF_VERBOSE, mdb_isa_kvm_frame));
	return (0);
}

int
kmt_stackr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    MSF_VERBOSE, mdb_isa_kvm_frame));
}

const char *
aarch64_el_name(uint_t el)
{
	static char *elnames[] = {
		[PSR_M_EL3h] = "3h",
		[PSR_M_EL3t] = "3t",
		[PSR_M_EL2h] = "2h",
		[PSR_M_EL2t] = "2t",
		[PSR_M_EL1h] = "1h",
		[PSR_M_EL1t] = "1t",
		[PSR_M_EL0t] = "0t"
	};

	if ((el >= ARRAY_SIZE(elnames)) || elnames[el] == NULL)
		return ("unknown");

	return (elnames[el]);
}

void
kmt_printregs(const mdb_tgt_gregset_t *gregs)
{
	const kreg_t *kregs = &gregs->kregs[0];
	const kreg_t psr = gregs->kregs[KREG_SPSR];

#define	GETREG2(x) ((uintptr_t)kregs[(x)]), ((uintptr_t)kregs[(x)])

	mdb_printf("%%x0  = 0x%0?p %15A %%x16 = 0x%0?p %A\n",
	    GETREG2(KREG_X0), GETREG2(KREG_X16));
	mdb_printf("%%x1  = 0x%0?p %15A %%x17 = 0x%0?p %A\n",
	    GETREG2(KREG_X1), GETREG2(KREG_X17));
	mdb_printf("%%x2  = 0x%0?p %15A %%x18 = 0x%0?p %A\n",
	    GETREG2(KREG_X2), GETREG2(KREG_X18));
	mdb_printf("%%x3  = 0x%0?p %15A %%x19 = 0x%0?p %A\n",
	    GETREG2(KREG_X3), GETREG2(KREG_X19));
	mdb_printf("%%x4  = 0x%0?p %15A %%x20 = 0x%0?p %A\n",
	    GETREG2(KREG_X4), GETREG2(KREG_X20));
	mdb_printf("%%x5  = 0x%0?p %15A %%x21 = 0x%0?p %A\n",
	    GETREG2(KREG_X5), GETREG2(KREG_X21));
	mdb_printf("%%x6  = 0x%0?p %15A %%x22 = 0x%0?p %A\n",
	    GETREG2(KREG_X6), GETREG2(KREG_X22));
	mdb_printf("%%x7  = 0x%0?p %15A %%x23 = 0x%0?p %A\n",
	    GETREG2(KREG_X7), GETREG2(KREG_X23));
	mdb_printf("%%x8  = 0x%0?p %15A %%x24 = 0x%0?p %A\n",
	    GETREG2(KREG_X8), GETREG2(KREG_X24));
	mdb_printf("%%x9  = 0x%0?p %15A %%x25 = 0x%0?p %A\n",
	    GETREG2(KREG_X9), GETREG2(KREG_X25));
	mdb_printf("%%x10 = 0x%0?p %15A %%x26 = 0x%0?p %A\n",
	    GETREG2(KREG_X10), GETREG2(KREG_X26));
	mdb_printf("%%x11 = 0x%0?p %15A %%x27 = 0x%0?p %A\n",
	    GETREG2(KREG_X11), GETREG2(KREG_X27));
	mdb_printf("%%x12 = 0x%0?p %15A %%x28 = 0x%0?p %A\n",
	    GETREG2(KREG_X12), GETREG2(KREG_X28));
	mdb_printf("%%x13 = 0x%0?p %15A %%x29 = 0x%0?p %A\n",
	    GETREG2(KREG_X13), GETREG2(KREG_X29));
	mdb_printf("%%x14 = 0x%0?p %15A %%x30 = 0x%0?p %A\n",
	    GETREG2(KREG_X14), GETREG2(KREG_X30));
	mdb_printf("%%x15 = 0x%0?p %15A\n\n", GETREG2(KREG_X15));

	mdb_printf("%%sp = 0x%0?p %15A %%pc = 0x%0?p %A\n",
	    GETREG2(KREG_SP), GETREG2(KREG_PC));
	mdb_printf("%%tp = 0x%0?p %15A\n\n", GETREG2(KREG_TP));

	mdb_printf("%%far    = 0x%0?p %15A\n", GETREG2(KREG_FAR));
	mdb_printf("%%spsr   = 0x%0?p ", psr);
	mdb_printf("  <%c,%c,%c,%c,%s,%s,%c,%c,%c,%c,el=%s>\n",
	    (psr & PSR_N ? 'N' : 'n'),
	    (psr & PSR_Z ? 'Z' : 'z'),
	    (psr & PSR_C ? 'C' : 'c'),
	    (psr & PSR_V ? 'V' : 'v'),
	    (psr & PSR_SS ? "SS" : "ss"),
	    (psr & PSR_IL ? "IL" : "il"),
	    (psr & PSR_D ? 'D' : 'd'),
	    (psr & PSR_A ? 'A' : 'a'),
	    (psr & PSR_I ? 'I' : 'i'),
	    (psr & PSR_F ? 'F' : 'f'),
	    aarch64_el_name(psr & PSR_M_MASK));

	mdb_printf("%%esr    = 0x%0?p\n", gregs->kregs[KREG_ESR]);
	mdb_printf("%%trapno = %0?p\n", gregs->kregs[KREG_TRAPNO]);
}

ssize_t
kmt_write(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	if (!(t->t_flags & MDB_TGT_F_ALLOWIO) &&
	    (nbytes = kmdb_kdi_range_is_nontoxic(addr, nbytes, 1)) == 0)
		return (set_errno(EMDB_NOMAP));

	/*
	 * No writes to user space are allowed.  If we were to allow it, we'd
	 * be in the unfortunate situation where kmdb could place a breakpoint
	 * on a userspace executable page; this dirty page would end up being
	 * flushed back to disk, incurring sadness when it's next executed.
	 * Besides, we can't allow trapping in from userspace anyway.
	 */
	if (addr < kmdb_kdi_get_userlimit())
		return (set_errno(EMDB_TGTNOTSUP));

	return (kmt_rw(t, (void *)buf, nbytes, addr, kmt_writer));
}


/*ARGSUSED*/
ssize_t
kmt_ioread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	return (set_errno(EMDB_TGTHWNOTSUP));
}

/*ARGSUSED*/
ssize_t
kmt_iowrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (set_errno(EMDB_TGTHWNOTSUP));
}

/* XXXKDI: These are in the kernel trap handler too, commonize them? */
/* Note that these tables are sparse */
static const char *trap_type_mnemonic[] = {
	[T_UNKNOWN] = "UNKNOWN",
	[T_WFx] = "WFx",
	[T_CP15RT] = "CP15RT",
	[T_CP15RRT] = "CP15RRT",
	[T_CP14RT] = "CP14RT",
	[T_CP14DT] = "CP14DT",
	[T_SIMDFP_ACCESS] = "SIMDFP_ACCESS",
	[T_FPID] = "FPID",
	[T_PAC] = "PAC",
	[T_LDST64B] = "LDST64B",
	[T_CP14RRT] = "CP14RRT",
	[T_BRANCH_TARGET] = "BRANCH_TARGET",
	[T_ILLEGAL_STATE] = "ILLEGAL_STATE",
	[T_SVC32] = "SVC32",
	[T_HVC32] = "HVC32",
	[T_MONITOR_CALL32] = "MONITOR_CALL32",
	[T_SVC] = "SVC",
	[T_HVC] = "HVC",
	[T_MONITOR_CALL] = "MONITOR_CALL",
	[T_SYSTEM_REGISTER] = "SYSTEM_REGISTER",
	[T_SVE_ACCESS] = "SVE_ACCESS",
	[T_ERET] = "ERET",
	[T_TSTART_ACCESS] = "TSTART_ACCESS",
	[T_PAC_FAIL] = "PAC_FAIL",
	[T_SME_ACCESS] = "SME_ACCESS",
	[T_GPC] = "GPC",
	[T_INSTRUCTION_ABORT] = "INSTRUCTION_ABORT",
	[T_INSTRUCTION_ABORT_EL] = "INSTRUCTION_ABORT_EL",
	[T_PC_ALIGNMENT] = "PC_ALIGNMENT",
	[T_DATA_ABORT] = "DATA_ABORT",
	[T_NV2_DATA_ABORT] = "NV2_DATA_ABORT",
	[T_SP_ALIGNMENT] = "SP_ALIGNMENT",
	[T_MEMCPY_MEMSET] = "MEMCPY_MEMSET",
	[T_FP_EXCEPTION32] = "FP_EXCEPTION32",
	[T_FP_EXCEPTION] = "FP_EXCEPTION",
	[T_SERROR] = "SERROR",
	[T_BREAKPOINT] = "BREAKPOINT",
	[T_BREAKPOINT_EL] = "BREAKPOINT_EL",
	[T_SOFTWARE_STEP] = "SOFTWARE_STEP",
	[T_SOFTWARE_STEP_EL] = "SOFTWARE_STEP_EL",
	[T_WATCHPOINT] = "WATCHPOINT",
	[T_NV2_WATCHPOINT] = "NV2_WATCHPOINT",
	[T_SOFTWARE_BREAKPOINT32] = "SOFTWARE_BREAKPOINT32",
	[T_VECTOR_CATCH] = "VECTOR_CATCH",
	[T_SOFTWARE_BREAKPOINT] = "SOFTWARE_BREAKPOINT",
	[T_PMU] = "PMU",
};

static const char *trap_type[] = {
	[T_UNKNOWN] = "Unknown exception",
	[T_WFx] = "Trapped WFI/WFE instruction",
	[T_CP15RT] = "Trapped AArch32 MCR/MRC access (coproc=0xf)",
	[T_CP15RRT] = "Trapped AArch32 MCRR/MRRC access (coproc=0xf)",
	[T_CP14RT] = "Trapped AArch32 MCR/MRC access (coproc=0xe)",
	[T_CP14DT] = "Trapped AArch32 LDC/STC access (coproc=0xe)",
	[T_SIMDFP_ACCESS] = "SIMD/FPU access",
	[T_FPID] = "SIMD/FPU ID register access",
	[T_PAC] = "Invalid PAC use",
	[T_LDST64B] = "Invalid use of 64byte instruction",
	[T_CP14RRT] = "Trapped AArch32 MRRC access (coproc=0xe)",
	[T_BRANCH_TARGET] = "Branch Target Indentification",
	[T_ILLEGAL_STATE] = "Illegal execution state",
	[T_SVC32] = "AArch32 supervisor call",
	[T_HVC32] = "AArch32 hypervisor call",
	[T_MONITOR_CALL32] = "AArch32 monitor call",
	[T_SVC] = "Supervisor call",
	[T_HVC] = "Hypervisor call",
	[T_MONITOR_CALL] = "Monitor call",
	[T_SYSTEM_REGISTER] = "Illegal system register access",
	[T_SVE_ACCESS] = "SVE access",
	[T_ERET] = "Invalid ERET use",
	[T_TSTART_ACCESS] = "TSTART access",
	[T_PAC_FAIL] = "PAC authentication failure",
	[T_SME_ACCESS] = "SME access",
	[T_GPC] = "Granule protection check",
	[T_INSTRUCTION_ABORT] = "Instruction abort",
	[T_INSTRUCTION_ABORT_EL] = "Instruction abort",
	[T_PC_ALIGNMENT] = "PC alignment",
	[T_DATA_ABORT] = "Data abort",
	[T_NV2_DATA_ABORT] = "Data abort",
	[T_SP_ALIGNMENT] = "SP alignment",
	[T_MEMCPY_MEMSET] = "CPY*/SET* exception",
	[T_FP_EXCEPTION32] = "AArch32 Trapped IEEE FP exception",
	[T_FP_EXCEPTION] = "Trapped IEEE FP exception",
	[T_SERROR] = "SError interrupt",
	[T_BREAKPOINT] = "Hardware breakpoint",
	[T_BREAKPOINT_EL] = "Hardware breakpoint",
	[T_SOFTWARE_STEP] = "Software step",
	[T_SOFTWARE_STEP_EL] = "Software step",
	[T_WATCHPOINT] = "Watchpoint",
	[T_NV2_WATCHPOINT] = "Watchpoint",
	[T_SOFTWARE_BREAKPOINT32] = "AArch32 software breakpoint",
	[T_VECTOR_CATCH] = "AArch32 vector catch",
	[T_SOFTWARE_BREAKPOINT] = "Software breakpoint",
	[T_PMU] = "PMU exception",
};

#define	TRAP_TYPES	ARRAY_SIZE(trap_type)

const char *
kmt_trapname(int trapnum)
{
	const char *trap_name = NULL;
	/* XXXKDI: Apparently this is safe, at least intel does it */
	static char badname[11];

	if (trapnum < TRAP_TYPES) {
		trap_name = trap_type[trapnum];
	}

	if (trap_name != NULL) {
		return (trap_name);
	} else {
		(void) mdb_snprintf(badname, sizeof (badname), "trap %#x",
		    trapnum);
		return (badname);
	}
}

void
kmt_init_isadep(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;

	kmt->kmt_rds = mdb_isa_kregs;

	kmt->kmt_trapmax = KMT_MAXTRAPNO;
	kmt->kmt_trapmap = mdb_zalloc(BT_SIZEOFMAP(kmt->kmt_trapmax), UM_SLEEP);

	/* Traps for which we want to provide an explicit message */
	(void) mdb_tgt_add_fault(t, T_PAC, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_BRANCH_TARGET, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_ILLEGAL_STATE, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_ERET, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_PAC_FAIL, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_GPC, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_INSTRUCTION_ABORT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_INSTRUCTION_ABORT_EL,
	    MDB_TGT_SPEC_INTERNAL, no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_DATA_ABORT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_NV2_DATA_ABORT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_SP_ALIGNMENT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_FP_EXCEPTION, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_SERROR, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_PMU, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);

	/*
	 * Traps which will be handled elsewhere, and which therefore don't
	 * need the trap-based message.
	 */
	BT_SET(kmt->kmt_trapmap, T_SOFTWARE_STEP_EL);
	BT_SET(kmt->kmt_trapmap, T_SOFTWARE_BREAKPOINT);
	BT_SET(kmt->kmt_trapmap, T_NV2_WATCHPOINT);

	/* Catch-all for traps not explicitly listed here */
	(void) mdb_tgt_add_fault(t, KMT_TRAP_NOTENUM, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
}

void
kmt_startup_isadep(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;

	/*
	 * XXXKDI: The ::step code on intel has heuristics about interrupt
	 * frames, and needs to know the addresses of functions that create
	 * them so that one doesn't ::step out erroneously
	 *
	 * Skip that for right now.  For ARM this would be anything that
	 * returns with an `eret`, directly or otherwise.
	 */
}
