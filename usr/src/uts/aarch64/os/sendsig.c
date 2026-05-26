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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*	All Rights Reserved   */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/class.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/archsystm.h>
#include <sys/vmparam.h>
#include <sys/prsystm.h>
#include <sys/reboot.h>
#include <sys/uadmin.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/session.h>
#include <sys/ucontext.h>
#include <sys/dnlc.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/thread.h>
#include <sys/vtrace.h>
#include <sys/consdev.h>
#include <sys/psw.h>
#include <sys/regset.h>
#include <sys/frame.h>
#include <sys/privregs.h>

#include <sys/stack.h>
#include <sys/swap.h>
#include <vm/hat.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <sys/exec.h>
#include <sys/acct.h>
#include <sys/core.h>
#include <sys/corectl.h>
#include <sys/modctl.h>
#include <sys/tuneable.h>
#include <c2/audit.h>
#include <sys/bootconf.h>
#include <sys/dumphdr.h>
#include <sys/promif.h>
#include <sys/systeminfo.h>
#include <sys/kdi.h>
#include <sys/contract_impl.h>

/*
 * Construct the execution environment for the user's signal
 * handler and arrange for control to be given to it on return
 * to userland.  The library code now calls setcontext() to
 * clean up after the signal handler, so sigret() is no longer
 * needed.
 *
 * (The various 'volatile' declarations are need to ensure that values
 * are correct on the error return from on_fault().)
 */

/*
 * An AArch64 signal frame looks like this on the stack, after the prologue of
 * sigacthandler in libc has executed.
 *
 *	 .---------------------------.
 *	 |	  register	     |
 *	 |	    save	     |
 *	 |	    area	     |
 *	 +---------------------------+	   <- interrupted frame
 *	 | saved return address	     | ----.
 *	 +---------------------------+	   |
 *   .-> | saved frame pointer	     | <-. |
 *   |	 `--------------------------'	 | |	  Backtrace innermost last
 *   |					 | |   .---------------------------.
 *   |	 .---------------------------.	 | |   |	   ...		   |
 *   |	 | optional siginfo_t	     |	 | `-- |	  caller	   |
 *   |	 +---------------------------+	 |     +---------------------------+
 *   |	 |       ucontext_t	     |	 | .-- |    interrupted_ func()	   |
 *   |	 |           ...	     |	 | |   +---------------------------+
 *   |	 |           REG_FP	     | --' |   |      invalid		   | --.
 *   |	 |           ...	     |	   |   +---------------------------+   |
 *   |	 +---------------------------+	   |   | libc.so.1`sigacthandler() |   |
 *   |	 |          siginfo_t *      |	   |   +---------------------------+   |
 *   |	 +---------------------------+	   |   .   user signal handler	   .   |
 *   |	 |       signal number	     |	   |   .	 ...		   .   |
 *   |	 +---------------------------+	   |   `...........................'   |
 *   |	 |    saved return address   | ---'				       |
 *   |	 +---------------------------+	 <- signal frame		       |
 *   `-- |			     |	    pushed by sendsig()		       |
 *   .-> |    saved frame pointer    |					       |
 *   |	 `--------------------------'					       |
 *   |									       |
 *   |	 .---------------------------.					       |
 *   |	 |	  register	     |	<- sigacthandler frame		       |
 *   |	 |	    save	     |	   pushed by libc.so.1`sigacthandler   |
 *   |	 |	    area	     |					       |
 *   |	 +---------------------------+					       |
 *   |	 | invalid return address -1 | ----------------------------------------'
 *   |	 +---------------------------+
 *   `-- |			     |
 * .---> |    saved frame pointer    |
 * | .-> |			     |
 * | |	 `--------------------------'
 * | |
 * | |			      Registers
 * | |			 .---------------.
 * | |			 |	%lr	 |
 * | |			 +---------------+
 * | `------------------ |	%fp	 |
 * |			 +---------------+
 * `-------------------- |     %sp	 |
 *			 `--------------'
 *
 *
 * This is a little weird, and unlike our other platforms.  This is because a
 * common AArch64 function prologue starts like this.
 *
 *    sigacthandler:	   fd 7b bd a9	stp x29, x30, [sp, #-48]!
 *    sigacthandler+0x4:   fd 03 00 91	mov x29, sp
 *
 * This pre-increments sp to form the register save area, then stores the
 * frame pointer and return address at the new sp.  This means that without
 * knowledge of the size of sigacthandler's register save area we have no way
 * to discover the sigframe using only the %fp and %sp in the sigacthandler
 * frame.
 *
 * Instead, we point sigacthandler's saved frame pointer to a fake frame
 * constructed entirely by the kernel which is immediately followed by our
 * signal data.
 *
 * When walking the stack, if a frame with pc == -1 is seen the signal
 * information can be read by dereferencing that frame's saved frame pointer,
 * and the stack walk continued from the registers in the ucontext.
 *
 * A naive walker that doesn't care about the signal context can skip printing
 * the frame with pc == -1 and continue following the frame pointers.
 *
 * An even more naive walker can just walk the stack normally, albeit with a
 * confusing frame.
 *
 * The actual return of libc.so.1`sigacthandler() is via setcontext(2) of the
 * saved ucontext and so does not encounter the fake frame.
 */

/*
 * This ABSOLUTELY MUST be kept in sync with libproc's `Pstack_iter` and
 * libc's `walkcontext`
 */
struct sigframe {
	struct frame fr;
	long	signo;
	siginfo_t *sip;
};

int
sendsig(int sig, k_siginfo_t *sip, void (*hdlr)())
{
	volatile int minstacksz;
	int newstack;
	label_t ljb;
	volatile caddr_t sp;
	caddr_t fp;
	volatile struct regs *rp;
	volatile greg_t upc;
	volatile proc_t *p = ttoproc(curthread);
	struct as *as = p->p_as;
	klwp_t *lwp = ttolwp(curthread);
	ucontext_t *volatile tuc = NULL;
	ucontext_t *uc;
	siginfo_t *sip_addr;
	volatile int watched;

	rp = lwptoregs(lwp);
	upc = rp->r_pc;

	/*
	 * Signals are delivered on the return-to-user path, so the kernel
	 * must not be actively using the FPU.  If FPU_KERNEL is set here,
	 * a kernel_fpu_begin/end pair was not balanced before signal
	 * delivery, and savecontext would save kernel FPU state as the
	 * user's state.
	 */
	ASSERT(!(lwp->lwp_pcb.pcb_fpu.fpu_flags & FPU_KERNEL));

	ASSERT((sizeof (struct sigframe) % STACK_ENTRY_ALIGN) == 0);

	minstacksz = sizeof (struct sigframe) + SA(sizeof (*uc));
	if (sip != NULL)
		minstacksz += SA(sizeof (siginfo_t));
	ASSERT((minstacksz & (STACK_ENTRY_ALIGN - 1ul)) == 0);

	/*
	 * Figure out whether we will be handling this signal on
	 * an alternate stack specified by the user.  Then allocate
	 * and validate the stack requirements for the signal handler
	 * context.  on_fault will catch any faults.
	 */
	newstack = sigismember(&PTOU(curproc)->u_sigonstack, sig) &&
	    !(lwp->lwp_sigaltstack.ss_flags & (SS_ONSTACK|SS_DISABLE));

	if (newstack) {
		fp = (caddr_t)(SA((uintptr_t)lwp->lwp_sigaltstack.ss_sp) +
		    SA(lwp->lwp_sigaltstack.ss_size) - STACK_ALIGN);
	} else {
		fp = (caddr_t)rp->r_sp;
	}

	/*
	 * Force proper stack pointer alignment, even in the face of a
	 * misaligned stack pointer from user-level before the signal.
	 */
	fp = (caddr_t)((uintptr_t)fp & ~(STACK_ENTRY_ALIGN - 1ul));

	sp = fp - minstacksz;
	ASSERT(((uintptr_t)sp & (STACK_ALIGN - 1ul)) == 0);

	/*
	 * Now, make sure the resulting signal frame address is sane
	 */
	if (sp >= as->a_userlimit || fp >= as->a_userlimit) {
#ifdef DEBUG
		printf("sendsig: bad signal stack cmd=%s, pid=%d, sig=%d\n",
		    PTOU(p)->u_comm, p->p_pid, sig);
		printf("sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
		    (void *)sp, (void *)hdlr, (uintptr_t)upc);
		printf("sp above USERLIMIT\n");
#endif
		return (0);
	}

	watched = watch_disable_addr((caddr_t)sp, minstacksz, S_WRITE);

	if (on_fault(&ljb))
		goto badstack;

	if (sip != NULL) {
		zoneid_t zoneid;

		fp -= SA(sizeof (siginfo_t));
		uzero(fp, sizeof (siginfo_t));
		if (SI_FROMUSER(sip) &&
		    (zoneid = p->p_zone->zone_id) != GLOBAL_ZONEID &&
		    zoneid != sip->si_zoneid) {
			k_siginfo_t sani_sip = *sip;

			sani_sip.si_pid = p->p_zone->zone_zsched->p_pid;
			sani_sip.si_uid = 0;
			sani_sip.si_ctid = -1;
			sani_sip.si_zoneid = zoneid;
			copyout_noerr(&sani_sip, fp, sizeof (sani_sip));
		} else {
			copyout_noerr(sip, fp, sizeof (*sip));
		}
		sip_addr = (siginfo_t *)fp;

		if (sig == SIGPROF &&
		    curthread->t_rprof != NULL &&
		    curthread->t_rprof->rp_anystate) {
			/*
			 * We stand on our head to deal with
			 * the real time profiling signal.
			 * Fill in the stuff that doesn't fit
			 * in a normal k_siginfo structure.
			 */
			int i = sip->si_nsysarg;
			while (--i >= 0) {
				sulword_noerr(
				    (ulong_t *)&(sip_addr->si_sysarg[i]),
				    (ulong_t)lwp->lwp_arg[i]);
			}
			copyout_noerr(curthread->t_rprof->rp_state,
			    sip_addr->si_mstate,
			    sizeof (curthread->t_rprof->rp_state));
		}
	} else {
		sip_addr = NULL;
	}

	/*
	 * save the current context on the user stack directly after the
	 * sigframe. Since sigframe is 8-byte-but-not-16-byte aligned,
	 * and since sizeof (struct sigframe) is 24, this guarantees
	 * 16-byte alignment for ucontext_t and its %xmm registers.
	 */
	uc = (ucontext_t *)(sp + sizeof (struct sigframe));
	tuc = kmem_alloc(sizeof (*tuc), KM_SLEEP);
	savecontext(tuc, &lwp->lwp_sigoldmask);
	copyout_noerr(tuc, uc, sizeof (*tuc));
	kmem_free(tuc, sizeof (*tuc));
	tuc = NULL;

	lwp->lwp_oldcontext = (uintptr_t)uc;

	if (newstack) {
		lwp->lwp_sigaltstack.ss_flags |= SS_ONSTACK;
		if (lwp->lwp_ustack)
			copyout_noerr(&lwp->lwp_sigaltstack,
			    (stack_t *)lwp->lwp_ustack, sizeof (stack_t));
	}

	/*
	 * Set up signal handler return and stack linkage
	 */
	{
		struct sigframe frame;

		frame.fr.fr_savfp = rp->r_fp;
		frame.fr.fr_savpc = rp->r_lr;
		frame.signo = sig;
		frame.sip = sip_addr;
		copyout_noerr(&frame, sp, sizeof (frame));
	}

	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, minstacksz, S_WRITE);

	/*
	 * Set up user registers for execution of signal handler.
	 */
	rp->r_fp = (greg_t)sp;
	rp->r_sp = (greg_t)sp;
	rp->r_pc = (greg_t)hdlr;
	rp->r_spsr = PSR_USERINIT;

	/*
	 * Mark the signal frame for consumers, and ensure we can't
	 * 'ret'.
	 */
	rp->r_lr = -1;

	rp->r_x0 = sig;
	rp->r_x1 = (uintptr_t)sip_addr;
	rp->r_x2 = (uintptr_t)uc;

	/*
	 * Don't set lwp_eosys here.  sendsig() is called via psig() after
	 * lwp_eosys is handled, so setting it here would affect the next
	 * system call.
	 */
	return (1);

badstack:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, minstacksz, S_WRITE);
	if (tuc)
		kmem_free(tuc, sizeof (*tuc));
#ifdef DEBUG
	printf("sendsig: bad signal stack cmd=%s, pid=%d, sig=%d\n",
	    PTOU(p)->u_comm, p->p_pid, sig);
	printf("on fault, sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
	    (void *)sp, (void *)hdlr, (uintptr_t)upc);
#endif
	return (0);
}
