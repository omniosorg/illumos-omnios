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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc.  All rights reserverd.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2024 Michael van der Westhuizen
 */

#include <sys/cpuvar.h>
#include <sys/cpu_event.h>
#include <sys/regset.h>
#include <sys/psw.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/clock.h>
#include <sys/panic.h>
#include <sys/disp.h>
#include <vm/seg_kp.h>
#include <sys/stack.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/smp_impldefs.h>
#include <sys/pool_pset.h>
#include <sys/zone.h>
#include <sys/bitmap.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/ontrap.h>
#include <sys/promif.h>
#include <sys/fault.h>
#include <sys/procfs.h>
#include <sys/fp.h>
#include <sys/contract/process_impl.h>
#include <sys/aio_impl.h>
#include <sys/prsystm.h>
#include <vm/hat_aarch64.h>
#include <sys/frame.h>
#include <sys/dtrace.h>
#include <sys/x_call.h>
#include <sys/xc_levels.h>
#include <sys/spl.h>

extern void print_msg_hwerr(ctid_t ct_id, proc_t *p);
extern int dtrace_invop(uintptr_t addr, uintptr_t *stack, uintptr_t eax);
extern faultcode_t pagefault(caddr_t, enum fault_type, enum seg_rw, int);

static void dumpregs(const struct regs *);
static void showregs(uint32_t, const struct regs *, const caddr_t, uint64_t);

/*
 * Note that these tables are sparse!
 */
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

/*
 * XXXARM: A lot of this could be shared with the instruction side, but we're
 * being probably unnecessarily cautious, because it doesn't seem to be
 * _documented_ that they're the same where they overlap, they just are the
 * same through documented values as of now.
 */
static const char *dfsc_name[] = {
	[ISS_DABORT_DFSC_ADDRSIZE_LN2] = "Address size fault (level -2)",
	[ISS_DABORT_DFSC_ADDRSIZE_LN1] = "Address size fault (level -1)",
	[ISS_DABORT_DFSC_ADDRSIZE_L0] = "Address size fault (level 0)",
	[ISS_DABORT_DFSC_ADDRSIZE_L1] = "Address size fault (level 1)",
	[ISS_DABORT_DFSC_ADDRSIZE_L2] = "Address size fault (level 2)",
	[ISS_DABORT_DFSC_ADDRSIZE_L3] = "Address size fault (level 3)",
	[ISS_DABORT_DFSC_TRANS_LN2] = "Translation fault (level -2)",
	[ISS_DABORT_DFSC_TRANS_LN1] = "Translation fault (level -1)",
	[ISS_DABORT_DFSC_TRANS_L0] = "Translation fault (level 0)",
	[ISS_DABORT_DFSC_TRANS_L1] = "Translation fault (level 1)",
	[ISS_DABORT_DFSC_TRANS_L2] = "Translation fault (level 2)",
	[ISS_DABORT_DFSC_TRANS_L3] = "Translation fault (level 3)",
	[ISS_DABORT_DFSC_ACCESS_L0] = "Access fault (level 0)",
	[ISS_DABORT_DFSC_ACCESS_L1] = "Access fault (level 1)",
	[ISS_DABORT_DFSC_ACCESS_L2] = "Access fault (level 2)",
	[ISS_DABORT_DFSC_ACCESS_L3] = "Access fault (level 3)",
	[ISS_DABORT_DFSC_PERM_L0] = "Permission fault (level 0)",
	[ISS_DABORT_DFSC_PERM_L1] = "Permission fault (level 1)",
	[ISS_DABORT_DFSC_PERM_L2] = "Permission fault (level 2)",
	[ISS_DABORT_DFSC_PERM_L3] = "Permission fault (level 3)",
	[ISS_DABORT_DFSC_SYNCH_TAG] = "Synch tag check fault",
	[ISS_DABORT_DFSC_SYNCH_EXT] = "Synch external abort",
	[ISS_DABORT_DFSC_SYNCH_EXT_LN2] = "Synch external abort (level -2)",
	[ISS_DABORT_DFSC_SYNCH_EXT_LN1] = "Synch external abort (level -1)",
	[ISS_DABORT_DFSC_SYNCH_EXT_L0] = "Synch external abort (level 0)",
	[ISS_DABORT_DFSC_SYNCH_EXT_L1] = "Synch external abort (level 1)",
	[ISS_DABORT_DFSC_SYNCH_EXT_L2] = "Synch external abort (level 2)",
	[ISS_DABORT_DFSC_SYNCH_EXT_L3] = "Synch external abort (level 3)",
	[ISS_DABORT_DFSC_PARECC] = "Parity/ECC error",
	[ISS_DABORT_DFSC_PARECC_LN1] = "Parity/ECC error (level -1)",
	[ISS_DABORT_DFSC_PARECC_L0] = "Parity/ECC error (level 0)",
	[ISS_DABORT_DFSC_PARECC_L1] = "Parity/ECC error (level 1)",
	[ISS_DABORT_DFSC_PARECC_L2] = "Parity/ECC error (level 2)",
	[ISS_DABORT_DFSC_PARECC_L3] = "Parity/ECC error (level 3)",
	[ISS_DABORT_DFSC_ALIGNMENT] = "Alignment fault",
	[ISS_DABORT_DFSC_GPF_LN2] = "Granule Protection fault (level -2)",
	[ISS_DABORT_DFSC_GPF_LN1] = "Granule Protection fault (level -1)",
	[ISS_DABORT_DFSC_GPF_L0] = "Granule Protection fault (level 0)",
	[ISS_DABORT_DFSC_GPF_L1] = "Granule Protection fault (level 1)",
	[ISS_DABORT_DFSC_GPF_L2] = "Granule Protection fault (level 2)",
	[ISS_DABORT_DFSC_GPF_L3] = "Granule Protection fault (level 3)",
	[ISS_DABORT_DFSC_TLB_CONFLICT] = "TLB conflict",
	[ISS_DABORT_DFSC_ATOMIC_HW_UNSUP] =
	    "Unsupported atomic hardware update",
	[ISS_DABORT_DFSC_LOCKDOWN] = "Lockdown",
	[ISS_DABORT_DFSC_ATOMIC] = "Unsupported exclusive/atomic access",
};
#define	DFSC_NAMES	ARRAY_SIZE(dfsc_name)

static const char *ifsc_name[] = {
	[ISS_IABORT_IFSC_ADDRSIZE_LN2] = "Address size fault (level -2)",
	[ISS_IABORT_IFSC_ADDRSIZE_LN1] = "Address size fault (level -1)",
	[ISS_IABORT_IFSC_ADDRSIZE_L0] = "Address size fault (level 0)",
	[ISS_IABORT_IFSC_ADDRSIZE_L1] = "Address size fault (level 1)",
	[ISS_IABORT_IFSC_ADDRSIZE_L2] = "Address size fault (level 2)",
	[ISS_IABORT_IFSC_ADDRSIZE_L3] = "Address size fault (level 3)",
	[ISS_IABORT_IFSC_TRANS_LN2] = "Translation fault (level -2)",
	[ISS_IABORT_IFSC_TRANS_LN1] = "Translation fault (level -1)",
	[ISS_IABORT_IFSC_TRANS_L0] = "Translation fault (level 0)",
	[ISS_IABORT_IFSC_TRANS_L1] = "Translation fault (level 1)",
	[ISS_IABORT_IFSC_TRANS_L2] = "Translation fault (level 2)",
	[ISS_IABORT_IFSC_TRANS_L3] = "Translation fault (level 3)",
	[ISS_IABORT_IFSC_ACCESS_L0] = "Access fault (level 0)",
	[ISS_IABORT_IFSC_ACCESS_L1] = "Access fault (level 1)",
	[ISS_IABORT_IFSC_ACCESS_L2] = "Access fault (level 2)",
	[ISS_IABORT_IFSC_ACCESS_L3] = "Access fault (level 3)",
	[ISS_IABORT_IFSC_PERM_L0] = "Permission fault (level 0)",
	[ISS_IABORT_IFSC_PERM_L1] = "Permission fault (level 1)",
	[ISS_IABORT_IFSC_PERM_L2] = "Permission fault (level 2)",
	[ISS_IABORT_IFSC_PERM_L3] = "Permission fault (level 3)",
	[ISS_IABORT_IFSC_SYNCH_EXT] = "Synch external abort",
	[ISS_IABORT_IFSC_SYNCH_EXT_LN2] = "Synch external abort (level -2)",
	[ISS_IABORT_IFSC_SYNCH_EXT_LN1] = "Synch external abort (level -1)",
	[ISS_IABORT_IFSC_SYNCH_EXT_L0] = "Synch external abort (level 0)",
	[ISS_IABORT_IFSC_SYNCH_EXT_L1] = "Synch external abort (level 1)",
	[ISS_IABORT_IFSC_SYNCH_EXT_L2] = "Synch external abort (level 2)",
	[ISS_IABORT_IFSC_SYNCH_EXT_L3] = "Synch external abort (level 3)",
	[ISS_IABORT_IFSC_PARECC] = "Parity/ECC error",
	[ISS_IABORT_IFSC_PARECC_LN1] = "Parity/ECC error (level -1)",
	[ISS_IABORT_IFSC_PARECC_L0] = "Parity/ECC error (level 0)",
	[ISS_IABORT_IFSC_PARECC_L1] = "Parity/ECC error (level 1)",
	[ISS_IABORT_IFSC_PARECC_L2] = "Parity/ECC error (level 2)",
	[ISS_IABORT_IFSC_PARECC_L3] = "Parity/ECC error (level 3)",
	[ISS_IABORT_IFSC_GPF_LN2] = "Granule Protection fault (level -2)",
	[ISS_IABORT_IFSC_GPF_LN1] = "Granule Protection fault (level -1)",
	[ISS_IABORT_IFSC_GPF_L0] = "Granule Protection fault (level 0)",
	[ISS_IABORT_IFSC_GPF_L1] = "Granule Protection fault (level 1)",
	[ISS_IABORT_IFSC_GPF_L2] = "Granule Protection fault (level 2)",
	[ISS_IABORT_IFSC_GPF_L3] = "Granule Protection fault (level 3)",
	[ISS_IABORT_IFSC_TLB_CONFLICT] = "TLB conflict",
	[ISS_IABORT_IFSC_ATOMIC_HW_UNSUP] =
	    "Unsupported atomic hardware update",
};
#define	IFSC_NAMES	ARRAY_SIZE(ifsc_name)

static void
print_dabort_esr(uint64_t esr, caddr_t addr)
{
	uint32_t iss = ESR_ISS(esr);
	uint8_t dfsc = ISS_DABORT_DFSC(iss);

	printf("data abort esr=%lx:", esr);

	if ((dfsc <= DFSC_NAMES) && dfsc_name[dfsc] != NULL)
		printf(" %s", dfsc_name[dfsc]);
	else
		printf(" Unknown (%d)", dfsc);

	if (ISS_DABORT_FNV(iss) == ISS_DABORT_FAR_VALID) {
		if (!ISS_DABORT_ISV(iss) &&
		    (ISS_DABORT_BIT15(iss) == ISS_DABORT_FNP_PRECISE)) {
			printf(" addr=0x%p", addr);
		} else {
			printf(" addr=0x%p (imprecise)", addr);
		}
	}

	if (ISS_DABORT_WNR(iss) == ISS_DABORT_WNR_READ)
		printf(" direction=read");
	else
		printf(" direction=write");

	printf("\n");
}

static void
print_iabort_esr(uint64_t esr, caddr_t addr)
{
	uint32_t iss = ESR_ISS(esr);
	uint8_t ifsc = ISS_IABORT_IFSC(iss);

	printf("instruction abort esr=%lx:", esr);

	if ((ifsc <= IFSC_NAMES) && ifsc_name[ifsc] != NULL)
		printf(" %s", ifsc_name[ifsc]);
	else
		printf(" Unknown (%d)", ifsc);

	if (ISS_IABORT_FNV(iss) == ISS_IABORT_FAR_VALID) {
		printf(" addr=0x%p", addr);
	}

	printf("\n");
}

void
panic_showtrap(struct panic_trap_info *tip)
{
	showregs(tip->trap_type, tip->trap_regs, tip->trap_addr,
	    tip->trap_esr);
}

void
panic_savetrap(panic_data_t *pdp, struct panic_trap_info *tip)
{
	panic_saveregs(pdp, tip->trap_regs);
}

/*
 * XXXARM: usually we'd just raise the SPL here,
 * but the old code disables interrupts and locks itself out
 */
lock_t showregs_lock;

static void
showregs(uint32_t type, const struct regs *rp, const caddr_t addr,
    uint64_t esr)
{
	static volatile int exclusion;
	const char *trap_name = NULL, *trap_mnemonic = NULL;
	ushort_t old;

	lock_set_spl(&showregs_lock, ipltospl(XC_HI_PIL), &old);

	if (PTOU(curproc)->u_comm[0])
		printf("%s: ", PTOU(curproc)->u_comm);

	if (type < TRAP_TYPES) {
		trap_name = trap_type[type];
		trap_mnemonic = trap_type_mnemonic[type];
	}

	if ((trap_name != NULL) && (trap_mnemonic != NULL)) {
		printf("#%s %s\n", trap_mnemonic, trap_name);
	} else {
		switch (type) {
		case T_SYSCALL:
			printf("Syscall trap:\n");
			break;
		case T_AST:
			printf("AST:\n");
			break;
		default:
			printf("Bad trap = %d\n", type);
		}
	}

	if ((type == T_DATA_ABORT) || (type == T_NV2_DATA_ABORT)) {
		print_dabort_esr(esr, addr);
	} else if (addr != 0) {
		printf("addr=0x%p\n", addr);
	}

	printf("pid=%d, pc=0x%lx, sp=0x%lx, spsr=0x%lx\n",
	    (ttoproc(curthread) && ttoproc(curthread)->p_pidp) ?
	    ttoproc(curthread)->p_pid : 0, rp->r_pc, rp->r_sp,
	    rp->r_spsr);

	dumpregs(rp);

	lock_clear(&showregs_lock);
	splx(old);
}

static void
dumpregs(const struct regs *rp)
{
	const char fmt[] = "\t%3s: %16lx %3s: %16lx %3s: %16lx\n";

	printf(fmt, "x0", rp->r_x0, "x1", rp->r_x1, "x2", rp->r_x2);
	printf(fmt, "x3", rp->r_x3, "x4", rp->r_x4, "x5", rp->r_x5);
	printf(fmt, "x6", rp->r_x6, "x7", rp->r_x7, "x8", rp->r_x8);
	printf(fmt, "x9", rp->r_x9, "x10", rp->r_x10, "x11", rp->r_x11);
	printf(fmt, "x12", rp->r_x12, "x13", rp->r_x13, "x14", rp->r_x14);
	printf(fmt, "x15", rp->r_x15, "x16", rp->r_x16, "x17", rp->r_x17);
	printf(fmt, "x18", rp->r_x18, "x19", rp->r_x19, "x20", rp->r_x20);
	printf(fmt, "x21", rp->r_x21, "x22", rp->r_x22, "x23", rp->r_x23);
	printf(fmt, "x24", rp->r_x24, "x25", rp->r_x25, "x26", rp->r_x26);
	printf(fmt, "x27", rp->r_x27, "x28", rp->r_x28, "x29", rp->r_x29);
	printf("\tx30: %16lx\n", rp->r_x30);

	printf(fmt, "sp", rp->r_sp, "pc", rp->r_pc, "spsr", rp->r_spsr);
}

static void
die(uint32_t ec, uint64_t esr, caddr_t addr, struct regs *rp)
{
	struct panic_trap_info ti;
	const char *trap_name = NULL, *trap_mnemonic = NULL;

	if (ec < TRAP_TYPES) {
		trap_mnemonic = trap_type_mnemonic[ec];
		trap_name = trap_type[ec];
	}

	if (trap_mnemonic == NULL)
		trap_mnemonic = "-";
	if (trap_name == NULL)
		trap_name = "trap";

	/* XXXARM: no trap trace yet, but here's where we should freeze */

	ti.trap_regs = rp;
	ti.trap_type = ec;
	ti.trap_addr = addr;
	ti.trap_esr = esr;

	curthread->t_panic_trap = &ti;

	panic("BAD TRAP: type=%x (#%s %s) rp=%p addr=%p esr=%lx",
	    ec, trap_mnemonic, trap_name, (void *)rp, (void *)addr, esr);
}

/*
 * Called from the trap handler when a processor trap occurs.
 *
 * Note: All user-level traps that might call stop() must exit
 * trap() by 'goto out' or by falling through.
 *
 * XXXARM: I'm not sure the below is also true on ARM, but it probably is.
 *
 * Note Also: trap() is usually called with interrupts enabled however, there
 * are paths that arrive here with them disabled, so special care must be
 * taken in those cases.
 */
int
trap(uint16_t ec, uint64_t esr, caddr_t addr, struct regs *rp)
{
	kthread_t *ct = curthread;
	enum seg_rw rw;
	proc_t *p = ttoproc(ct);
	klwp_t *lwp = ttolwp(ct);
	uintptr_t lofault;
	label_t *onfault;
	faultcode_t res, errcode;
	enum fault_type fault_type;
	k_siginfo_t siginfo;
	uint_t fault = 0;
	int mstate;
	int sicode = 0;
	int watchcode;
	int watchpage;
	caddr_t vaddr;
	int singlestep_twiddle;
	size_t sz;
	int ta;
	uint32_t iss = ESR_ISS(esr);

	ASSERT((ec == T_AST) || (ec == ESR_EC(esr)));

	/*
	 * XXXARM: Why are these DTrace bits handled here?
	 */
	ASSERT(interrupts_disabled());

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT)) {
		ASSERT(!USERMODE(rp->r_spsr));
		switch (ec) {
		case T_DATA_ABORT:
		case T_NV2_DATA_ABORT:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval =
			    (uintptr_t)addr;
			break;
		default:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			break;
		}
		rp->r_pc += 4;
		return (0);
	}

	if (!USERMODE(rp->r_spsr)) {
		if ((ec == T_SOFTWARE_BREAKPOINT) &&
		    (ISS_BREAKPOINT_COMMENT(iss) == 0x11)) {
			int r = dtrace_invop(rp->r_pc,
			    (uintptr_t *)rp, rp->r_x0);
			if (r == DTRACE_INVOP_RET) {
				rp->r_pc = rp->r_x30;
				return (0);
			}
			if (r == DTRACE_INVOP_NOP) {
				rp->r_pc += 4;
				return (0);
			}
		}
	}

	(void) enable_interrupts();

	ASSERT_STACK_ALIGNED();

	CPU_STATS_ADDQ(CPU, sys, trap, 1);
	ASSERT(ct->t_schedflag & TS_DONT_SWAP);

	switch (ec) {
	case T_INSTRUCTION_ABORT:
	case T_INSTRUCTION_ABORT_EL: {
		mstate = LMS_TFAULT;
		rw = S_EXEC;

		if (ISS_IABORT_FNV(iss) != ISS_IABORT_FAR_VALID) {
			/*
			 * fault address is invalid, make it ~0 so that's more
			 * obvious
			 */
			addr = ((caddr_t)-1);
		}

		uint32_t fsc = ISS_IABORT_IFSC(iss);

		/*
		 * XXXARM: The original code said (0x9 <= fsc && fsc <= 0xc)
		 * which seems like a typo, as this covers:
		 *
		 * 0x9 ACCESS_L1
		 * 0xa ACCESS_L2
		 * 0xb ACCESS_L3
		 * 0xc PERM_L0
		 *
		 * and misses ACCESS_L0
		 */
		if (ISS_IABORT_IFSC_ACCESS(fsc) &&
		    (ISS_IABORT_FNV(iss) == ISS_IABORT_FAR_VALID) &&
		    ((ec == T_INSTRUCTION_ABORT_EL) || (addr < (caddr_t)kernelbase)) &&
		    hat_page_fault(addr < (caddr_t)kernelbase ? curproc->p_as->a_hat : kas.a_hat, addr) == 0) {
			return (1);
		} else if (ISS_IABORT_IFSC_PERM(fsc)) {
			/*
			 * Access flag fault or Permission fault.
			 *
			 * XXXARM: The comment above is not actually true,
			 * The original code said: (0xd <= fsc && fsc <= 0xF)
			 *
			 * 0xd - PERM_L1,
			 * 0xe - PERM_L2
			 * 0xf - PERM_L3
			 *
			 * Access flag isn't covered here at all, nor is
			 * permission at L0.
			 */
			fault_type = F_PROT;
		} else {
			fault_type = F_INVAL;
		}
		break;
	}
	case T_DATA_ABORT:
	case T_NV2_DATA_ABORT: {
		mstate = LMS_DFAULT;
		if (ISS_DABORT_WNR(iss) == ISS_DABORT_WNR_WRITE) {
			rw = S_WRITE;
		} else {
			rw = S_READ;
		}

		if (ISS_DABORT_FNV(iss) != ISS_DABORT_FAR_VALID) {
			/*
			 * fault address is invalid, make it ~0 so that's more
			 * obvious
			 */
			addr = ((caddr_t)-1);
		}

		uint32_t fsc = ISS_DABORT_DFSC(iss);

		/*
		 * XXXARM: The original code said (0x9 <= fsc && fsc <= 0xc)
		 * which seems like a typo, as this covers:
		 *
		 * 0x9 ACCESS_L1
		 * 0xa ACCESS_L2
		 * 0xb ACCESS_L3
		 * 0xc PERM_L0
		 *
		 * and misses ACCESS_L0
		 */
		if (ISS_DABORT_DFSC_ACCESS(fsc) &&
		    (ISS_DABORT_FNV(iss) == ISS_DABORT_FAR_VALID) &&
		    ((ec == T_NV2_DATA_ABORT) || (addr < (caddr_t)kernelbase)) &&
		    hat_page_fault(addr < (caddr_t)kernelbase ? curproc->p_as->a_hat : kas.a_hat, addr) == 0) {
			return (1);
		} else if (ISS_DABORT_DFSC_PERM(fsc)) {
			/*
			 * Access flag fault or Permission fault.
			 *
			 * XXXARM: The comment above is not actually true,
			 * The original code said: (0xd <= fsc && fsc <= 0xF)
			 *
			 * 0xd - PERM_L1,
			 * 0xe - PERM_L2
			 * 0xf - PERM_L3
			 *
			 * Access flag isn't covered here at all, nor is
			 * permission at L0.
			 */
			fault_type = F_PROT;
		} else {
			fault_type = F_INVAL;
		}
		break;
	}
	default:
		mstate = LMS_TRAP;
		break;
	}

	if (USERMODE(rp->r_spsr)) {
		/*
		 * Set up the current cred to use during this trap. u_cred
		 * no longer exists.  t_cred is used instead.
		 * The current process credential applies to the thread for
		 * the entire trap.  If trapping from the kernel, this
		 * should already be set up.
		 */
		if (ct->t_cred != p->p_cred) {
			cred_t *oldcred = ct->t_cred;

			/*
			 * DTrace accesses t_cred in probe context.  t_cred
			 * must always be either NULL, or point to a valid,
			 * allocated cred structure.
			 */
			ct->t_cred = crgetcred();
			crfree(oldcred);
		}

		ASSERT(lwp != NULL);
		ASSERT(lwptoregs(lwp) == rp);
		lwp->lwp_state = LWP_SYS;

		mstate = new_mstate(ct, mstate);

		bzero(&siginfo, sizeof (siginfo));

		switch (ec) {
		case T_INSTRUCTION_ABORT:
		case T_DATA_ABORT:
			ASSERT(!(curthread->t_flag & T_WATCHPT));
			res = pagefault(addr, fault_type, rw, 0);

			if (res == 0 ||
			    (res == FC_NOMAP && addr < p->p_usrstack && grow(addr))) {
				lwp->lwp_lastfault = FLTPAGE;
				lwp->lwp_lastfaddr = addr;
				if (prismember(&p->p_fltmask, FLTPAGE)) {
					siginfo.si_addr = addr;
					(void) stop_on_fault(FLTPAGE, &siginfo);
				}
				goto out;
			} else if ((res == FC_PROT) && (addr < p->p_usrstack) &&
			    (rw == S_EXEC)) {
				report_stack_exec(p, addr);
			}

			siginfo.si_addr = addr;
			switch (FC_CODE(res)) {
			case FC_HWERR:
			case FC_NOSUPPORT:
				siginfo.si_signo = SIGBUS;
				siginfo.si_code = BUS_ADRERR;
				fault = FLTACCESS;
				break;
			case FC_ALIGN:
				siginfo.si_signo = SIGBUS;
				siginfo.si_code = BUS_ADRALN;
				fault = FLTACCESS;
				break;
			case FC_OBJERR:
				if ((siginfo.si_errno =
				    FC_ERRNO(res)) != EINTR) {
					siginfo.si_signo = SIGBUS;
					siginfo.si_code = BUS_OBJERR;
					fault = FLTACCESS;
				}
				break;
			default:
				siginfo.si_signo = SIGSEGV;
				if (res == FC_NOMAP)
					siginfo.si_code = SEGV_MAPERR;
				else
					siginfo.si_code = SEGV_ACCERR;
				fault = FLTBOUNDS;
				break;
			}
			break;
		case T_FP_EXCEPTION:
			siginfo.si_signo = SIGFPE;
			siginfo.si_code  = FPE_INTDIV;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			fault = FLTIZDIV;
			break;
		case T_SIMDFP_ACCESS:
			/*
			 * If we trapped for reasons other than not having
			 * used the FPU _yet_, SIGILL.  Otherwise fp_fenflt
			 * will setup the fpu for this process.
			 */
			if (fp_fenflt()) {
				siginfo.si_signo = SIGILL;
				siginfo.si_code  = ILL_ILLOPC;
				siginfo.si_addr  = (caddr_t)rp->r_pc;
				fault = FLTILL;
			} else {
				goto out;
			}
			break;
		case T_PC_ALIGNMENT:
		case T_SP_ALIGNMENT:
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRALN;
			siginfo.si_addr = (caddr_t)rp->r_pc;
			fault = FLTACCESS;
			break;
		case T_SERROR:
			siginfo.si_addr = ((caddr_t)-1);
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRERR;
			fault = FLTACCESS;
			break;
		case T_ILLEGAL_STATE:
			siginfo.si_signo = SIGILL;
			siginfo.si_code  = ILL_ILLOPC;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			fault = FLTILL;
			break;
		case T_AST:
			if (lwp->lwp_pcb.pcb_flags & ASYNC_HWERR) {
				proc_t *p = ttoproc(curthread);

				lwp->lwp_pcb.pcb_flags &= ~ASYNC_HWERR;
				print_msg_hwerr(p->p_ct_process->conp_contract.ct_id, p);
				contract_process_hwerr(p->p_ct_process, p);
				siginfo.si_signo = SIGKILL;
				siginfo.si_code = SI_NOINFO;
			} else if (lwp->lwp_pcb.pcb_flags & CPC_OVERFLOW) {
				lwp->lwp_pcb.pcb_flags &= ~CPC_OVERFLOW;
				if (kcpc_overflow_ast()) {
					siginfo.si_signo = SIGEMT;
					siginfo.si_code = EMT_CPCOVF;
					siginfo.si_addr = (caddr_t)rp->r_pc;
					fault = FLTCPCOVF;
				}
			}
			break;
		case T_SOFTWARE_STEP: {
			pcb_t *pcb = &lwp->lwp_pcb;
			rp->r_spsr &= ~PSR_SS;

			if ((fault = undo_watch_step(&siginfo)) == 0 &&
			    ((pcb->pcb_flags & NORMAL_STEP) ||
			    !(pcb->pcb_flags & WATCH_STEP))) {
				siginfo.si_signo = SIGTRAP;
				siginfo.si_code = TRAP_TRACE;
				siginfo.si_addr = (caddr_t)rp->r_pc;
				fault = FLTTRACE;
			}
			pcb->pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
			break;
		}
		case T_SOFTWARE_BREAKPOINT:
			siginfo.si_signo = SIGTRAP;
			siginfo.si_code  = TRAP_BRKPT;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			fault = FLTBPT;
			break;
		default:
			siginfo.si_signo = SIGILL;
			siginfo.si_code  = ILL_ILLTRP;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			siginfo.si_trapno = ec;
			fault = FLTILL;
			break;
		}

		if (fault) {
			lwp->lwp_pcb.pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
			lwp->lwp_lastfault = fault;
			lwp->lwp_lastfaddr = siginfo.si_addr;

			if (siginfo.si_signo != SIGKILL &&
			    prismember(&p->p_fltmask, fault) &&
			    stop_on_fault(fault, &siginfo) == 0)
				siginfo.si_signo = 0;
		}

		if (siginfo.si_signo)
			trapsig(&siginfo,
			    ((fault != FLTFPE) && (fault != FLTCPCOVF)));

		if (lwp->lwp_oweupc)
			profil_tick(rp->r_pc);

		if (ct->t_astflag | ct->t_sig_check) {
			astoff(ct);

			if (lwp->lwp_pcb.pcb_flags & DEBUG_PENDING)
				deferred_singlestep_trap((caddr_t)rp->r_pc);

			ct->t_sig_check = 0;

	 		/*
	 		 * As in other code paths that check against
	 		 * TP_CHANGEBIND, we perform the check first without
	 		 * p_lock held -- only acquiring p_lock in the
	 		 * unlikely event that it is indeed set.  This is safe
	 		 * because we are doing this after the astoff(); if we
	 		 * are racing another thread setting TP_CHANGEBIND on
	 		 * us, we will pick it up on a subsequent lap through.
	 		 */
			if (curthread->t_proc_flag & TP_CHANGEBIND) {
				mutex_enter(&p->p_lock);
				if (curthread->t_proc_flag & TP_CHANGEBIND) {
					timer_lwpbind();
					curthread->t_proc_flag &= ~TP_CHANGEBIND;
				}
				mutex_exit(&p->p_lock);
			}

			if (p->p_aio)
				aio_cleanup(0);

			if (ISHOLD(p))
				holdlwp();

			if (ISSIG_PENDING(ct, lwp, p)) {
				if (issig(FORREAL))
					psig();
				ct->t_sig_check = 1;
			}

			if (ct->t_rprof != NULL) {
				realsigprof(0, 0, 0);
				ct->t_sig_check = 1;
			}

			if (lwp->lwp_pcb.pcb_flags & REQUEST_STEP) {
				lwp->lwp_pcb.pcb_flags &= ~REQUEST_STEP;
				rp->r_spsr |= PSR_SS;
			}
			if (lwp->lwp_pcb.pcb_flags & REQUEST_NOSTEP) {
				lwp->lwp_pcb.pcb_flags &= ~REQUEST_NOSTEP;
				rp->r_spsr &= ~PSR_SS;
			}
		}
out:
		if (ISHOLD(p))
			holdlwp();

		lwp->lwp_state = LWP_USER;

		if (ct->t_trapret) {
			ct->t_trapret = 0;
			thread_lock(ct);
			CL_TRAPRET(ct);
			thread_unlock(ct);
		}
		if (CPU->cpu_runrun || curthread->t_schedflag & TS_ANYWAITQ)
			preempt();
		prunstop();
		new_mstate(ct, mstate);
	} else {
		switch (ec) {
		case T_FP_EXCEPTION:
		case T_PC_ALIGNMENT:
		case T_SP_ALIGNMENT:
		case T_SERROR:
		case T_ILLEGAL_STATE:
		default:
			die(ec, esr, addr, rp);
			break;
		case T_SIMDFP_ACCESS:
			/*
			 * XXXARM: I'm not sure why this is conditional for a
			 * trap in kernel mode.
			 */
			if (fp_fenflt())
				die(ec, esr, addr, rp);
			break;
		case T_INSTRUCTION_ABORT_EL:
		case T_NV2_DATA_ABORT:
			{
				if ((ct->t_ontrap != NULL) &&
				    (ct->t_ontrap->ot_prot & OT_DATA_ACCESS)) {
					ct->t_ontrap->ot_trap |= OT_DATA_ACCESS;
					rp->r_pc = ct->t_ontrap->ot_trampoline;
					goto cleanup;
				}
				lofault = ct->t_lofault;
				ct->t_lofault = 0;

				mstate = new_mstate(ct, LMS_KFAULT);

				if (addr < (caddr_t)kernelbase) {
					res = pagefault(addr, fault_type, rw,
					    0);
					if ((res == FC_NOMAP) &&
					    (addr < p->p_usrstack) &&
					    grow(addr)) {
						res = 0;
					}
				} else {
					res = pagefault(addr, fault_type, rw,
					    1);
				}

				new_mstate(ct, mstate);

				ct->t_lofault = lofault;
				if (res == 0)
					goto cleanup;

				if (lofault == 0) {
					die(ec, esr, addr, rp);
				}

				if (FC_CODE(res) == FC_OBJERR)
					res = FC_ERRNO(res);
				else
					res = EFAULT;
				rp->r_x0 = res;
				rp->r_pc = ct->t_lofault;
				goto cleanup;
			}
			break;
		case T_AST:
			goto cleanup;
			break;
		}
	}
cleanup:
	return (1);
}

/*
 * Patch non-zero to disable preemption of threads in the kernel.
 */
int IGNORE_KERNEL_PREEMPTION = 0;	/* XXX - delete this someday */

struct kpreempt_cnts {		/* kernel preemption statistics */
	int	kpc_idle;	/* executing idle thread */
	int	kpc_intr;	/* executing interrupt thread */
	int	kpc_clock;	/* executing clock thread */
	int	kpc_blocked;	/* thread has blocked preemption (t_preempt) */
	int	kpc_notonproc;	/* thread is surrendering processor */
	int	kpc_inswtch;	/* thread has ratified scheduling decision */
	int	kpc_prilevel;	/* processor interrupt level is too high */
	int	kpc_apreempt;	/* asynchronous preemption */
	int	kpc_spreempt;	/* synchronous preemption */
} kpreempt_cnts;

/*
 * kernel preemption: forced rescheduling, preempt the running kernel thread.
 *	the argument is old PIL for an interrupt,
 *	or the distingished value KPREEMPT_SYNC.
 */
void
kpreempt(int asyncspl)
{
	kthread_t *ct = curthread;

	if (IGNORE_KERNEL_PREEMPTION) {
		aston(CPU->cpu_dispthread);
		return;
	}

	/*
	 * Check that conditions are right for kernel preemption
	 */
	do {
		if (ct->t_preempt) {
			/*
			 * either a privileged thread (idle, panic, interrupt)
			 * or will check when t_preempt is lowered
			 * We need to specifically handle the case where
			 * the thread is in the middle of swtch (resume has
			 * been called) and has its t_preempt set
			 * [idle thread and a thread which is in kpreempt
			 * already] and then a high priority thread is
			 * available in the local dispatch queue.
			 * In this case the resumed thread needs to take a
			 * trap so that it can call kpreempt. We achieve
			 * this by using siron().
			 * How do we detect this condition:
			 * idle thread is running and is in the midst of
			 * resume: curthread->t_pri == -1 && CPU->dispthread
			 * != CPU->thread
			 * Need to ensure that this happens only at high pil
			 * resume is called at high pil
			 * Only in resume_from_idle is the pil changed.
			 */
			if (ct->t_pri < 0) {
				kpreempt_cnts.kpc_idle++;
				if (CPU->cpu_dispthread != CPU->cpu_thread)
					siron();
			} else if (ct->t_flag & T_INTR_THREAD) {
				kpreempt_cnts.kpc_intr++;
				if (ct->t_pil == CLOCK_LEVEL)
					kpreempt_cnts.kpc_clock++;
			} else {
				kpreempt_cnts.kpc_blocked++;
				if (CPU->cpu_dispthread != CPU->cpu_thread)
					siron();
			}
			aston(CPU->cpu_dispthread);
			return;
		}
		if (ct->t_state != TS_ONPROC ||
		    ct->t_disp_queue != CPU->cpu_disp) {
			/* this thread will be calling swtch() shortly */
			kpreempt_cnts.kpc_notonproc++;
			if (CPU->cpu_thread != CPU->cpu_dispthread) {
				/* already in swtch(), force another */
				kpreempt_cnts.kpc_inswtch++;
				siron();
			}
			return;
		}
		if (getpil() >= DISP_LEVEL) {
			/*
			 * We can't preempt this thread if it is at
			 * a PIL >= DISP_LEVEL since it may be holding
			 * a spin lock (like sched_lock).
			 */
			siron();	/* check back later */
			kpreempt_cnts.kpc_prilevel++;
			return;
		}
		if (interrupts_disabled()) {
			/*
			 * Can't preempt while running with ints disabled
			 */
			kpreempt_cnts.kpc_prilevel++;
			return;
		}
		if (asyncspl != KPREEMPT_SYNC)
			kpreempt_cnts.kpc_apreempt++;
		else
			kpreempt_cnts.kpc_spreempt++;

		ct->t_preempt++;
		preempt();
		ct->t_preempt--;
	} while (CPU->cpu_kprunrun);
}


static uint64_t fasttrap_null(void)
{
	return ((uint64_t)-1);
}

static uint64_t fasttrap_gethrtime(void)
{
	return ((uint64_t)gethrtime());
}

static uint64_t fasttrap_gethrvtime(void)
{
	hrtime_t hrt = gethrtime_unscaled();
	kthread_t *ct = curthread;
	klwp_t *lwp = ttolwp(ct);
	hrt -= lwp->lwp_mstate.ms_state_start;
	hrt += lwp->lwp_mstate.ms_acct[LMS_USER];

	scalehrtime(&hrt);

	return ((uint64_t)hrt);
}

extern uint64_t fasttrap_gethrestime(void);
extern uint64_t getlgrp(void);

uint64_t (*fasttrap_table[])() = {
	fasttrap_null,
	fasttrap_gethrtime,
	fasttrap_gethrvtime,
	fasttrap_gethrestime,
	getlgrp,
};
