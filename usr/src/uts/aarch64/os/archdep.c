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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/vmparam.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/machlock.h>
#include <sys/panic.h>
#include <sys/privregs.h>
#include <sys/regset.h>
#include <sys/pcb.h>
#include <sys/psw.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <sys/archsystm.h>
#include <sys/dtrace.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/spl.h>
#include <sys/fp.h>
#include <sys/time.h>
#include <sys/machlock.h>
#include <sys/kobj.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>
#include <sys/arch_timer.h>
#include <sys/trap.h>

uint_t adj_shift;

static void
clean_dcache_impl(caddr_t addr, uint_t len)
{
	uint64_t data_line_size = CTR_DMINLINE_SIZE(read_ctr_el0());

	for (uintptr_t v = P2ALIGN((uintptr_t)addr, data_line_size);
	    v < (uintptr_t)addr + len; v += data_line_size) {
		clean_data_cache_pou(v);
	}
	dsb(ish);
}

static void
flush_dcache_impl(caddr_t addr, uint_t len)
{
	uint64_t data_line_size = CTR_DMINLINE_SIZE(read_ctr_el0());

	for (uintptr_t v = P2ALIGN((uintptr_t)addr, data_line_size);
	    v < (uintptr_t)addr + len; v += data_line_size) {
		flush_data_cache(v);
	}
	dsb(ish);
}

void
sync_icache(caddr_t addr, uint_t len)
{
	clean_dcache_impl(addr, len);

	// for VIPT
	invalidate_instruction_cache_allis();
	dsb(ish);
	isb();
}

void
sync_data_memory(caddr_t addr, size_t len)
{
	flush_dcache_impl(addr, len);
}

extern char *dump_stack_scratch;

void
traceback(caddr_t fpreg)
{
	struct frame	*fp = (struct frame *)fpreg;
	struct frame	*nextfp;
	uintptr_t	pc, nextpc;
	ulong_t		off;
	uint_t		offset = 0;
	uint_t		next_offset = 0;
	char		stack_buffer[1024];
	char		*sym;

	if (!panicstr)
		printf("traceback: %%fp = %p\n", (void *)fp);

	if (panicstr && !dump_stack_scratch) {
		printf("Warning - stack not written to the dump buffer\n");
	}

	if ((uintptr_t)fp < KERNELBASE)
		goto out;

	pc = fp->fr_savpc;
	fp = (struct frame *)fp->fr_savfp;

	while ((uintptr_t)fp >= KERNELBASE) {
		/*
		 * XX64 Until port is complete tolerate 8-byte aligned
		 * frame pointers but flag with a warning so they can
		 * be fixed.
		 */
		if (((uintptr_t)fp & (STACK_ALIGN - 1)) != 0) {
			printf(
			    "  >> mis-aligned %%fp = %p\n", (void *)fp);
			break;
		}

		nextpc = (uintptr_t)fp->fr_savpc;
		nextfp = (struct frame *)fp->fr_savfp;
		if ((sym = kobj_getsymname(pc, &off)) != NULL) {
			printf("%016lx %s:%s+%lx\n", (uintptr_t)fp,
			    mod_containing_pc((caddr_t)pc), sym, off);
			(void) snprintf(stack_buffer, sizeof (stack_buffer),
			    "%s:%s+%lx | ",
			    mod_containing_pc((caddr_t)pc), sym, off);
		} else {
			printf("%016lx %lx\n",
			    (uintptr_t)fp, pc);
			(void) snprintf(stack_buffer, sizeof (stack_buffer),
			    "%lx | ", pc);
		}

		if (panicstr && dump_stack_scratch) {
			next_offset = offset + strlen(stack_buffer);
			if (next_offset < STACK_BUF_SIZE) {
				bcopy(stack_buffer, dump_stack_scratch + offset,
				    strlen(stack_buffer));
				offset = next_offset;
			} else {
				/*
				 * In attempting to save the panic stack
				 * to the dumpbuf we have overflowed that area.
				 * Print a warning and continue to printf the
				 * stack to the msgbuf
				 */
				printf("Warning: stack in the dump buffer"
				    " may be incomplete\n");
				offset = next_offset;
			}
		}

		pc = nextpc;
		fp = nextfp;
	}
out:
	if (!panicstr) {
		printf("end of traceback\n");
		DELAY(2 * MICROSEC);
	} else if (dump_stack_scratch) {
		dump_stack_scratch[offset] = '\0';
	}
}

void
traceregs(struct regs *rp)
{
	traceback((caddr_t)rp->r_x29);
}

void
exec_set_sp(size_t stksize)
{
	klwp_t *lwp = ttolwp(curthread);

	lwptoregs(lwp)->r_sp = (uintptr_t)curproc->p_usrstack - stksize;
}

void
hrtime_init(void)
{
	extern int gethrtime_hires;
	gethrtime_hires = 1;
}

hrtime_t
gethrtime_waitfree(void)
{
	return (dtrace_gethrtime());
}

hrtime_t
gethrtime(void)
{
	uint64_t ct = arch_timer_count();
	uint64_t timer_freq = arch_timer_freq();

	uint64_t x = ct / timer_freq;
	uint64_t y = ct % timer_freq;
	hrtime_t nsec = x * NANOSEC + y * NANOSEC / timer_freq;
	return (nsec);
}

hrtime_t
gethrtime_unscaled(void)
{
	return (hrtime_t)arch_timer_count();
}

void
scalehrtime(hrtime_t *hrt)
{
	hrtime_t pct = *hrt;
	uint64_t timer_freq = arch_timer_freq();

	uint64_t x = pct / timer_freq;
	uint64_t y = pct % timer_freq;
	hrtime_t nsec = x * NANOSEC + y * NANOSEC / timer_freq;
	*hrt = nsec;
}

uint64_t
unscalehrtime(hrtime_t nsec)
{
	uint64_t timer_freq = arch_timer_freq();

	uint64_t x = nsec / NANOSEC;
	uint64_t y = nsec % NANOSEC;
	uint64_t pct = x * timer_freq + y * timer_freq / NANOSEC;
	return (pct);
}

void
gethrestime(timespec_t *tp)
{
	pc_gethrestime(tp);
}

hrtime_t
dtrace_gethrtime(void)
{
	uint64_t ct = arch_timer_count();
	uint64_t timer_freq = arch_timer_freq();

	uint64_t x = ct / timer_freq;
	uint64_t y = ct % timer_freq;
	hrtime_t nsec = x * NANOSEC + y * NANOSEC / timer_freq;
	return (nsec);
}

extern int one_sec;
extern int max_hres_adj;

void
__adj_hrestime(void)
{
	long long adj;

	if (hrestime_adj == 0)
		adj = 0;
	else if (hrestime_adj > 0) {
		if (hrestime_adj < max_hres_adj)
			adj = hrestime_adj;
		else
			adj = max_hres_adj;
	} else {
		if (hrestime_adj < -max_hres_adj)
			adj = -max_hres_adj;
		else
			adj = hrestime_adj;
	}

	timedelta -= adj;
	hrestime_adj = timedelta;
	hrestime.tv_nsec += adj;

	while (hrestime.tv_nsec >= NANOSEC) {
		one_sec++;
		hrestime.tv_sec++;
		hrestime.tv_nsec -= NANOSEC;
	}
}

/*
 * The panic code invokes panic_saveregs() to record the contents of a
 * regs structure into the specified panic_data structure for debuggers.
 */
void
panic_saveregs(panic_data_t *pdp, struct regs *rp)
{
	panic_nv_t *pnv = PANICNVGET(pdp);
	uint64_t esr = read_esr_el1();

	PANICNVADD(pnv, "x0", rp->r_x0);
	PANICNVADD(pnv, "x1", rp->r_x1);
	PANICNVADD(pnv, "x2", rp->r_x2);
	PANICNVADD(pnv, "x3", rp->r_x3);
	PANICNVADD(pnv, "x4", rp->r_x4);
	PANICNVADD(pnv, "x5", rp->r_x5);
	PANICNVADD(pnv, "x6", rp->r_x6);
	PANICNVADD(pnv, "x7", rp->r_x7);
	PANICNVADD(pnv, "x8", rp->r_x8);
	PANICNVADD(pnv, "x9", rp->r_x9);
	PANICNVADD(pnv, "x10", rp->r_x10);
	PANICNVADD(pnv, "x11", rp->r_x11);
	PANICNVADD(pnv, "x12", rp->r_x12);
	PANICNVADD(pnv, "x13", rp->r_x13);
	PANICNVADD(pnv, "x14", rp->r_x14);
	PANICNVADD(pnv, "x15", rp->r_x15);
	PANICNVADD(pnv, "x16", rp->r_x16);
	PANICNVADD(pnv, "x17", rp->r_x17);
	PANICNVADD(pnv, "x18", rp->r_x18);
	PANICNVADD(pnv, "x19", rp->r_x19);
	PANICNVADD(pnv, "x20", rp->r_x20);
	PANICNVADD(pnv, "x21", rp->r_x21);
	PANICNVADD(pnv, "x22", rp->r_x22);
	PANICNVADD(pnv, "x23", rp->r_x23);
	PANICNVADD(pnv, "x24", rp->r_x24);
	PANICNVADD(pnv, "x25", rp->r_x25);
	PANICNVADD(pnv, "x26", rp->r_x26);
	PANICNVADD(pnv, "x27", rp->r_x27);
	PANICNVADD(pnv, "x28", rp->r_x28);
	PANICNVADD(pnv, "x29", rp->r_x29);
	PANICNVADD(pnv, "x30", rp->r_x30);
	PANICNVADD(pnv, "sp", rp->r_sp);
	PANICNVADD(pnv, "pc", rp->r_pc);
	PANICNVADD(pnv, "spsr", rp->r_spsr);
	PANICNVADD(pnv, "tp", read_tpidr_el1());
	PANICNVADD(pnv, "esr", esr);
	PANICNVADD(pnv, "far", read_far_el1());
	PANICNVADD(pnv, "trapno", ESR_EC(esr));

	PANICNVADD(pnv, "tpidr_el0", read_tpidr_el0());
	PANICNVADD(pnv, "tpidr_el1", read_tpidr_el1());
	PANICNVADD(pnv, "ttbr0", read_ttbr0());
	PANICNVADD(pnv, "ttbr1", read_ttbr1());
	PANICNVADD(pnv, "tcr", read_tcr());

	PANICNVSET(pdp, pnv);
}

/*
 * Set floating-point registers from a native fpregset_t.
 */
void
setfpregs(klwp_t *lwp, fpregset_t *fp)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;

	kpreempt_disable();

	/*
	 * If FPU is enabled and state is live in hardware, save first
	 * so we don't lose any non-legacy state.
	 */
	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == FPU_EN) {
		if (curthread == lwptot(lwp)) {
			ASSERT(!(curthread->t_flag & T_KFPU));
			fp_save(fpu);
		}
	}

	/*
	 * Sanitise user-supplied FPCR and FPSR: mask off reserved and
	 * feature-gated bits to prevent unexpected trapping behaviour
	 * or enabling of unsupported features.
	 */
	fpu->fpu_regs.kfpu_cr = fp->fp_cr & FPCR_USER_MASK;
	fpu->fpu_regs.kfpu_sr = fp->fp_sr & FPSR_USER_MASK;
	bcopy(fp->d_fpregs, fpu->fpu_regs.kfpu_regs,
	    sizeof (fpu->fpu_regs.kfpu_regs));

	/*
	 * If the thread has never used the FPU (e.g., a debugger is
	 * writing FPU state via /proc), install ctxops so the state
	 * gets managed across context switches and reloaded on
	 * return to userland.
	 */
	if (!(fpu->fpu_flags & FPU_EN)) {
		fp_lwp_init(lwp);
	}

	fpu->fpu_flags |= FPU_VALID;
	PCB_SET_UPDATE_FPU(&lwp->lwp_pcb);

	kpreempt_enable();
}

/*
 * Get floating-point registers into a native fpregset_t.
 */
void
getfpregs(klwp_t *lwp, fpregset_t *fp)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;

	kpreempt_disable();

	/*
	 * If FPU is enabled and state is live in hardware, save first.
	 */
	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == FPU_EN) {
		if (curthread == lwptot(lwp)) {
			ASSERT(!(curthread->t_flag & T_KFPU));
			fp_save(fpu);
		}
	}

	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == 0) {
		/* FPU never used -- return zeroes */
		bzero(fp, sizeof (*fp));
		kpreempt_enable();
		return;
	}

	/* FPU_VALID must not be set without FPU_EN */
	ASSERT(fpu->fpu_flags & FPU_EN);

	fp->fp_cr = fpu->fpu_regs.kfpu_cr;
	fp->fp_sr = fpu->fpu_regs.kfpu_sr;
	bcopy(fpu->fpu_regs.kfpu_regs, fp->d_fpregs, sizeof (fp->d_fpregs));

	kpreempt_enable();
}

/*
 * Return the user-level PC.
 * If in a system call, return the address of the syscall trap.
 */
greg_t
getuserpc()
{
	greg_t upc = lwptoregs(ttolwp(curthread))->r_pc;

	if (curthread->t_sysnum != 0)
		upc -= 4;

	return (upc);
}

/*
 * Get a pc-only stacktrace.  Used for kmem_alloc() buffer ownership tracking.
 * Returns MIN(current stack depth, pcstack_limit).
 */
int
getpcstack(pc_t *pcstack, int pcstack_limit)
{
	struct frame *fp = (struct frame *)getfp();
	struct frame *nextfp, *minfp, *stacktop;
	int depth = 0;
	int on_intr;
	uintptr_t pc;

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)(CPU->cpu_intr_stack + SA(MINFRAME));
	else
		stacktop = (struct frame *)curthread->t_stk;
	minfp = fp;

	pc = ((struct regs *)fp)->r_pc;

	while (depth < pcstack_limit) {
		nextfp = (struct frame *)fp->fr_savfp;
		pc = fp->fr_savpc;
		if (nextfp <= minfp || nextfp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				stacktop = (struct frame *)curthread->t_stk;
				minfp = (struct frame *)curthread->t_stkbase;
				on_intr = 0;
				continue;
			}
			break;
		}
		pcstack[depth++] = (pc_t)pc;
		fp = nextfp;
		minfp = fp;
	}
	return (depth);
}


/*
 * Return the general registers
 */
void
getgregs(klwp_t *lwp, gregset_t grp)
{
	struct regs *rp = lwptoregs(lwp);

	grp[REG_X0] = rp->r_x0;
	grp[REG_X1] = rp->r_x1;
	grp[REG_X2] = rp->r_x2;
	grp[REG_X3] = rp->r_x3;
	grp[REG_X4] = rp->r_x4;
	grp[REG_X5] = rp->r_x5;
	grp[REG_X6] = rp->r_x6;
	grp[REG_X7] = rp->r_x7;
	grp[REG_X8] = rp->r_x8;
	grp[REG_X9] = rp->r_x9;
	grp[REG_X10] = rp->r_x10;
	grp[REG_X11] = rp->r_x11;
	grp[REG_X12] = rp->r_x12;
	grp[REG_X13] = rp->r_x13;
	grp[REG_X14] = rp->r_x14;
	grp[REG_X15] = rp->r_x15;
	grp[REG_X16] = rp->r_x16;
	grp[REG_X17] = rp->r_x17;
	grp[REG_X18] = rp->r_x18;
	grp[REG_X19] = rp->r_x19;
	grp[REG_X20] = rp->r_x20;
	grp[REG_X21] = rp->r_x21;
	grp[REG_X22] = rp->r_x22;
	grp[REG_X23] = rp->r_x23;
	grp[REG_X24] = rp->r_x24;
	grp[REG_X25] = rp->r_x25;
	grp[REG_X26] = rp->r_x26;
	grp[REG_X27] = rp->r_x27;
	grp[REG_X28] = rp->r_x28;
	grp[REG_X29] = rp->r_x29;
	grp[REG_X30] = rp->r_x30;
	grp[REG_SP] = rp->r_sp;
	grp[REG_PC] = rp->r_pc;
	grp[REG_SPSR] = rp->r_spsr;

	if (ttolwp(curthread) == lwp) {
		grp[REG_TP] = read_tpidr_el0();
	} else {
		grp[REG_TP] = lwp->lwp_pcb.pcb_tpidr;
	}
}

/*
 * Set general registers.
 */
void
setgregs(klwp_t *lwp, gregset_t grp)
{
	struct regs *rp = lwptoregs(lwp);

	rp->r_x0 = grp[REG_X0];
	rp->r_x1 = grp[REG_X1];
	rp->r_x2 = grp[REG_X2];
	rp->r_x3 = grp[REG_X3];
	rp->r_x4 = grp[REG_X4];
	rp->r_x5 = grp[REG_X5];
	rp->r_x6 = grp[REG_X6];
	rp->r_x7 = grp[REG_X7];
	rp->r_x8 = grp[REG_X8];
	rp->r_x9 = grp[REG_X9];
	rp->r_x10 = grp[REG_X10];
	rp->r_x11 = grp[REG_X11];
	rp->r_x12 = grp[REG_X12];
	rp->r_x13 = grp[REG_X13];
	rp->r_x14 = grp[REG_X14];
	rp->r_x15 = grp[REG_X15];
	rp->r_x16 = grp[REG_X16];
	rp->r_x17 = grp[REG_X17];
	rp->r_x18 = grp[REG_X18];
	rp->r_x19 = grp[REG_X19];
	rp->r_x20 = grp[REG_X20];
	rp->r_x21 = grp[REG_X21];
	rp->r_x22 = grp[REG_X22];
	rp->r_x23 = grp[REG_X23];
	rp->r_x24 = grp[REG_X24];
	rp->r_x25 = grp[REG_X25];
	rp->r_x26 = grp[REG_X26];
	rp->r_x27 = grp[REG_X27];
	rp->r_x28 = grp[REG_X28];
	rp->r_x29 = grp[REG_X29];
	rp->r_x30 = grp[REG_X30];
	rp->r_sp = grp[REG_SP];
	rp->r_pc = grp[REG_PC];
	rp->r_spsr = (rp->r_spsr & ~PSR_USERMASK) |
	    (grp[REG_SPSR] & PSR_USERMASK);

	if (ttolwp(curthread) == lwp) {
		write_tpidr_el0(grp[REG_TP]);
	} else {
		lwp->lwp_pcb.pcb_tpidr = grp[REG_TP];
	}
}

/*
 * The following ELF header fields are defined as processor-specific
 * in the AArch64 ABI:
 *
 *	e_ident[EI_DATA]	encoding of the processor-specific
 *				data in the object file
 *	e_machine		processor identification
 *	e_flags			processor-specific flags associated
 *				with the file
 */

/*
 * The value of at_flags reflects a platform's cpu module support.
 * at_flags is used to check for allowing a binary to execute and
 * is passed as the value of the AT_FLAGS auxiliary vector.
 */
int at_flags = 0;

/*
 * Check the processor-specific fields of an ELF header.
 *
 * returns 1 if the fields are valid, 0 otherwise
 */
int
elfheadcheck(
	unsigned char e_data,
	Elf32_Half e_machine,
	Elf32_Word e_flags)
{
	if (e_data != ELFDATA2LSB)
		return (0);
	return (e_machine == EM_AARCH64);
}
uint_t auxv_hwcap_include = 0;	/* patch to enable unrecognized features */
uint_t auxv_hwcap_exclude = 0;	/* patch for broken cpus, debugging */

int
scanc(size_t length, uchar_t *string, uchar_t table[], uchar_t mask)
{
	const uchar_t *end = &string[length];

	while (string < end && (table[*string] & mask) == 0)
		string++;
	return (end - string);
}

int
__ipltospl(int ipl)
{
	return (ipltospl(ipl));
}
