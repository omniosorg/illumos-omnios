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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>
#include <sys/lockstat.h>
#include "assym.h"

#define THREADP(reg)		\
	   mrs reg, tpidr_el1

#define BR_LOCKSTAT_WRAPPER(lp, lsid) \
	mov	x1, lp; \
	mov	x0, #(lsid); \
	THREADP(x2); \
	b	lockstat_wrapper

#define BR_LOCKSTAT_WRAPPER_ARG0(lp, lsid, arg0) \
	mov	x1, lp; \
	mov	x0, #(lsid); \
	mov	x2, #(arg0); \
	THREADP(x3); \
	b	lockstat_wrapper_arg0

/************************************************************************
 *		MINIMUM LOCKS
 */

#if defined(lint)

/*
 * lock_try(lp), ulock_try(lp)
 *	- returns non-zero on success.
 *	- doesn't block interrupts so don't use this to spin on a lock.
 *	- uses "0xFF is busy, anything else is free" model.
 *
 *      ulock_try() is for a lock in the user address space.
 *      For all V7/V8 sparc systems they are same since the kernel and
 *      user are mapped in a user' context.
 *      For V9 platforms the lock_try and ulock_try are different impl.
 */

int
lock_try(lock_t *lp)
{
	return (0xFF ^ ldstub(lp));
}

int
lock_spin_try(lock_t *lp)
{
	return (0xFF ^ ldstub(lp));
}

void
lock_set(lock_t *lp)
{
	extern void lock_set_spin(lock_t *);

	if (!lock_try(lp))
		lock_set_spin(lp);
	membar_enter();
}

void
lock_clear(lock_t *lp)
{
	membar_exit();
	*lp = 0;
}

int
ulock_try(lock_t *lp)
{
	return (0xFF ^ ldstub(lp));
}

void
ulock_clear(lock_t *lp)
{
	membar_exit();
	*lp = 0;
}

#else	/* lint */

	ENTRY(lock_try)
	mov	w2, #LOCK_HELD_VALUE
1:	ldaxrb	w3, [x0]
	stxrb	w4, w2, [x0]
	cbnz	w4, 1b
	mov	x1, x0
	eor	w0, w3, w2
.lock_try_lockstat_patch_point:
	ret
	cbz	w0, .lock_try_lockstat_fail
	BR_LOCKSTAT_WRAPPER(x1, LS_LOCK_TRY_ACQUIRE)
.lock_try_lockstat_fail:
	ret
	SET_SIZE(lock_try)

	ENTRY(lock_spin_try)
	mov	w2, #LOCK_HELD_VALUE
1:	ldaxrb	w3, [x0]
	stxrb	w4, w2, [x0]
	cbnz	w4, 1b
	eor	w0, w3, w2
	ret
	SET_SIZE(lock_spin_try)

	ENTRY(ulock_try)
	mov	w2, #1
1:	ldaxrb	w3, [x0]
	stxrb	w4, w2, [x0]
	cbnz	w4, 1b
	eor	w0, w3, w2
	ret
	SET_SIZE(ulock_try)

	ENTRY(lock_clear)
	stlrb	wzr, [x0]
.lock_clear_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER(x0, LS_LOCK_CLEAR_RELEASE)
	SET_SIZE(lock_clear)

	ENTRY(ulock_clear)
	stlrb	wzr, [x0]
	ret
	SET_SIZE(ulock_clear)

	ENTRY(lock_set)
	mov	w2, #LOCK_HELD_VALUE
1:	ldaxrb	w3, [x0]
	stxrb	w4, w2, [x0]
	cbnz	w4, 1b
	cbnz	w3, .lock_set_miss
.lock_set_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER(x0, LS_LOCK_SET_ACQUIRE)
.lock_set_miss:
	b	lock_set_spin
	SET_SIZE(lock_set)

	ENTRY(lock_init)
	stlrb	wzr, [x0]
	ret
	SET_SIZE(lock_init)
#endif

/*
 * lock_set_spl(lp, new_pil, *old_pil_addr)
 * 	Sets pil to new_pil, grabs lp, stores old pil in *old_pil_addr.
 */

#if defined(lint)
void
lock_set_spl(lock_t *lp, int new_pil, u_short *old_pil_addr)
{
	extern int splr(int);
	extern void lock_set_spl_spin(lock_t *, int, u_short *, int);
	int old_pil;

	old_pil = splr(new_pil);
	if (!lock_try(lp)) {
		lock_set_spl_spin(lp, new_pil, old_pil_addr, old_pil);
	} else {
		*old_pil_addr = (u_short)old_pil;
		membar_enter();
	}
}
#else
	ENTRY(lock_set_spl)
	stp	x2, x30, [sp, #-(8*4)]!
	stp	x0, x1, [sp, #(8*2)]

	mov	w0, w1
	bl	splr
	mov	w3, w0

	ldp	x0, x1, [sp, #(8*2)]
	ldp	x2, x30, [sp], #(8*4)

	mov	w4, #LOCK_HELD_VALUE
1:	ldaxrb	w5, [x0]
	stxrb	w6, w4, [x0]
	cbnz	w6, 1b
	cbnz	w5, .lock_set_spl_miss
	strh	w3, [x2]
.lock_set_spl_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER(x0, LS_LOCK_SET_SPL_ACQUIRE)
.lock_set_spl_miss:
	b	lock_set_spl_spin
	SET_SIZE(lock_set_spl)
#endif


/*
 * lock_clear_splx(lp, s)
 */

#if defined(lint)

void
lock_clear_splx(lock_t *lp, int s)
{
	extern void splx(int);

	lock_clear(lp);
	splx(s);
}

#else	/* lint */

	ENTRY(lock_clear_splx)
	stp	x0, x30, [sp, #-(8*2)]!
	stlrb	wzr, [x0]

	mov	w0, w1
	bl	splx
	ldp	x0, x30, [sp], #(8*2)
.lock_clear_splx_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER(x0, LS_LOCK_CLEAR_SPLX_RELEASE)
	SET_SIZE(lock_clear_splx)
#endif	/* lint */

/*
 * mutex_enter() and mutex_exit().
 * 
 * These routines handle the simple cases of mutex_enter() (adaptive
 * lock, not held) and mutex_exit() (adaptive lock, held, no waiters).
 * If anything complicated is going on we punt to mutex_vector_enter().
 *
 * mutex_tryenter() is similar to mutex_enter() but returns zero if
 * the lock cannot be acquired, nonzero on success.
 *
 * If mutex_exit() gets preempted in the window between checking waiters
 * and clearing the lock, we can miss wakeups.  Disabling preemption
 * in the mutex code is prohibitively expensive, so instead we detect
 * mutex preemption by examining the trapped PC in the interrupt path.
 * If we interrupt a thread in mutex_exit() that has not yet cleared
 * the lock, pil_interrupt() resets its PC back to the beginning of
 * mutex_exit() so it will check again for waiters when it resumes.
 *
 * The lockstat code below is activated when the lockstat driver
 * calls lockstat_hot_patch() to hot-patch the kernel mutex code.
 * Note that we don't need to test lockstat_event_mask here -- we won't
 * patch this code in unless we're gathering ADAPTIVE_HOLD lockstats.
 */

#if defined (lint)

/* ARGSUSED */
void
mutex_enter(kmutex_t *lp)
{}

/* ARGSUSED */
int
mutex_tryenter(kmutex_t *lp)
{ return (0); }

/* ARGSUSED */
void
mutex_exit(kmutex_t *lp)
{}

/* ARGSUSED */
void *
mutex_owner_running(mutex_impl_t *lp)
{ return (NULL); }

#else
	ENTRY(mutex_enter)
	THREADP(x2)
1:	ldaxr	x1, [x0]
	cbnz	x1, .mutex_enter_fail
	stxr	w1, x2, [x0]
	cbnz	w1, 1b
.mutex_enter_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER(x0, LS_MUTEX_ENTER_ACQUIRE)
.mutex_enter_fail:
	clrex
	b	mutex_vector_enter
	SET_SIZE(mutex_enter)

	ENTRY(mutex_tryenter)
	THREADP(x2)
1:	ldaxr	x1, [x0]
	cbnz	x1, .mutex_tryenter_fail
	stxr	w1, x2, [x0]
	cbnz	w1, 1b
	mov	x1, x0
	mov	x0, #1
.mutex_tryenter_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER(x1, LS_MUTEX_ENTER_ACQUIRE)
.mutex_tryenter_fail:
	clrex
	b	mutex_vector_tryenter
	SET_SIZE(mutex_tryenter)

	ENTRY(mutex_adaptive_tryenter)
	THREADP(x2)
1:	ldaxr	x1, [x0]
	cbnz	x1, 2f
	stxr	w1, x2, [x0]
	cbnz	w1, 1b
	mov	x0, #1
	ret
2:
	clrex
	mov	x0, #0
	ret
	SET_SIZE(mutex_adaptive_tryenter)

	ENTRY(mutex_exit)
	THREADP(x3)
1:	ldxr	x1, [x0]
	cmp	x1, x3
	b.ne	.mutex_exit_fail
	stlxr	w2, xzr, [x0]
	cbnz	w2, 1b
.mutex_exit_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER(x0, LS_MUTEX_EXIT_RELEASE)
.mutex_exit_fail:
	clrex
	b	mutex_vector_exit
	SET_SIZE(mutex_exit)

	.globl	mutex_owner_running_critical_start
	ENTRY(mutex_owner_running)
mutex_owner_running_critical_start:
	ldar	x3, [x0]
	and	x3, x3, #MUTEX_THREAD		/* x3 = lp->m_owner */
	cbz	x3, 1f				/* if (owner == NULL) return NULL */
	ldr	x1, [x3, #T_CPU]		/* x1 = owner->t_cpu */
	ldr	x2, [x1, #CPU_THREAD]		/* x2 = owner->t_cpu->cpu_thread */
.mutex_owner_running_critical_end:
	cmp	x3, x2				/* owner == running thread ? */
	b.ne	1f				/* no: return NULL */
	mov	x0, x1				/* yes: return cpu */
	ret
1:	mov	x0, #0
	ret
	SET_SIZE(mutex_owner_running)

	.globl	mutex_owner_running_critical_size
	.type	mutex_owner_running_critical_size, @object
	.align	CPTRSHIFT
mutex_owner_running_critical_size:
	.quad	.mutex_owner_running_critical_end - mutex_owner_running_critical_start
	SET_SIZE(mutex_owner_running_critical_size)
#endif	/* lint */

/*
 * rw_enter() and rw_exit().
 * 
 * These routines handle the simple cases of rw_enter (write-locking an unheld
 * lock or read-locking a lock that's neither write-locked nor write-wanted)
 * and rw_exit (no waiters or not the last reader).  If anything complicated
 * is going on we punt to rw_enter_sleep() and rw_exit_wakeup(), respectively.
 */
#if defined(lint)

/* ARGSUSED */
void
rw_enter(krwlock_t *lp, krw_t rw)
{}

/* ARGSUSED */
void
rw_exit(krwlock_t *lp)
{}

#else
	ENTRY(rw_enter)
	THREADP(x3)
	cmp	w1, #RW_WRITER
	b.eq	.rw_write_enter

	/* Acquire reader lock */
1:	ldaxr	x2, [x0]			/* x2 = lp->rw_wwwh */
	ands	xzr, x2, #RW_WRITE_CLAIMED	/* if (x2 & RW_WRITE_CLAIMED) goto .rw_enter_sleep */
	b.ne	.rw_enter_sleep
	add	x2, x2, #RW_READ_LOCK		/* Increment hold count */
	stxr	w4, x2, [x0]			/* Install new rw_wwwh */
	cbnz	w4, 1b
.rw_read_enter_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER_ARG0(x0, LS_RW_ENTER_ACQUIRE, RW_READER)

	/* Acquire writer lock */
.rw_write_enter:
1:	ldaxr	x2, [x0]		/* x2 = lp->rw_wwwh */
	cbnz	x2, .rw_enter_sleep	/* if (x2 != 0) goto .rw_enter_sleep */
	orr	x2, x3, #RW_WRITE_LOCKED
	stxr	w4, x2, [x0]		/* Install writer lock */
	cbnz	w4, 1b
.rw_write_enter_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER_ARG0(x0, LS_RW_ENTER_ACQUIRE, RW_WRITER)
.rw_enter_sleep:
	clrex
	b	rw_enter_sleep
	SET_SIZE(rw_enter)


	ENTRY(rw_exit)
	ldar	x3, [x0]		/* Read lock value */
	sub	x1, x3, #RW_READ_LOCK	/* r1 = new lock value for reader */
	cbnz	x1, .rw_not_single_reader	/* if !(single-reader && no waiter) goto 10 */

	/* Try to release read lock here. */
.Lrw_read_release:
1:	ldxr	x2, [x0]
	cmp	x2, x3			/* if the lock has been changed */
	b.ne	.rw_exit_wakeup		/*   rw_exit_wakeup, return */
	stlxr	w2, x1, [x0]		/* Install new lock value */
	cbnz	w2, 1b
.rw_read_exit_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER_ARG0(x0, LS_RW_EXIT_RELEASE, RW_READER)

.rw_exit_wakeup:
	clrex
	b	rw_exit_wakeup

.rw_not_single_reader:
	/* Check whether we own this lock as writer mode. */
	ands	x3, x3, #RW_WRITE_LOCKED
	b.ne	.Lrw_write_release
	cmp	x1, #RW_READ_LOCK	/* if the lock would still be held */
	b.hs	.Lrw_read_release	/*   goto .Lrw_read_release */
	b	rw_exit_wakeup		/* Let rw_exit_wakeup() do the rest */

.Lrw_write_release:
	/* Try to release write lock here. */
	THREADP(x3)
	orr	x3, x3, #RW_WRITE_LOCKED
1:	ldxr	x2, [x0]
	cmp	x2, x3			/* if the lock has been changed */
	b.ne	.rw_exit_wakeup		/*   rw_exit_wakeup, return */
	stlxr	w2, xzr, [x0]		/* Install new lock value */
	cbnz	w2, 1b			/* Retry when fails */
.rw_write_exit_lockstat_patch_point:
	ret
	BR_LOCKSTAT_WRAPPER_ARG0(x0, LS_RW_EXIT_RELEASE, RW_WRITER)
	SET_SIZE(rw_exit)

/*
 * expects x0=lockstat event, x1=lock, x2=curthread()
 */
	ENTRY(lockstat_wrapper)
	stp	x29, x30, [sp, #-(8*2)]!
	ldrb	w9, [x2, #T_LOCKSTAT]
	add	w9, w9, #1
	strb	w9, [x2, #T_LOCKSTAT]

	ldr	x8, =lockstat_probemap
	lsl	x0, x0, #2
	ldr	w0, [x8, x0]
	cbz	w0, .lockstat_wrapper_skip

	ldr	x5, =lockstat_probe
	ldr	x5, [x5]
	blr	x5
	THREADP(x2)
.lockstat_wrapper_skip:
	ldrb	w9, [x2, #T_LOCKSTAT]
	sub	w9, w9, #1
	strb	w9, [x2, #T_LOCKSTAT]
	ldp	x29, x30, [sp], #(8*2)
	mov	x0, #1				// for tryenter
	ret
	SET_SIZE(lockstat_wrapper)

/*
 * expects x0=lockstat event, x1=lock, x2=arg0 x3=curthread()
 */
	ENTRY(lockstat_wrapper_arg0)
	stp	x29, x30, [sp, #-(8*2)]!
	ldrb	w9, [x3, #T_LOCKSTAT]
	add	w9, w9, #1
	strb	w9, [x3, #T_LOCKSTAT]

	ldr	x8, =lockstat_probemap
	lsl	x0, x0, #2
	ldr	w0, [x8, x0]
	cbz	w0, .lockstat_wrapper_arg0_skip

	ldr	x5, =lockstat_probe
	ldr	x5, [x5]
	blr	x5
	THREADP(x3)
.lockstat_wrapper_arg0_skip:
	ldrb	w9, [x3, #T_LOCKSTAT]
	sub	w9, w9, #1
	strb	w9, [x3, #T_LOCKSTAT]
	ldp	x29, x30, [sp], #(8*2)
	mov	x0, #1				// for tryenter
	ret
	SET_SIZE(lockstat_wrapper_arg0)
#endif

/*
 * void
 * lockstat_hotpatch_probe(int ls_probe)
 *
 * Given a lockstat probe identifier, hotpatch any associated lockstat
 * primitive routine(s) so they fall through into the lockstat_probe() call (if
 * the probe is enabled) or return normally (when the probe is disabled).
 */

#define	RET			0xd65f03c0
#define	NOP			0xd503201f

#define	HOT_PATCH_MATCH(label, event, reg)			\
	ldr	w0, =(event);					\
	cmp	reg, w0;					\
	b.ne	3f;						\
	ldr	x0, =lockstat_probemap;				\
	ldr	w1, =((event) * 4);				\
	ldr	w0, [x0, x1];	/* r0 = lockstat_probemap[event] */ \
	cbnz	w0, 1f;						\
	ldr	w1, =RET;					\
	b	2f;						\
1:	ldr	w1, =NOP;					\
2:;								\
	ldr	x0, =label;	/* r0 = Address to be patched */ \
	mov	w2, #4;			/* r2 = 4 (instruction size) */	\
	bl	hot_patch_kernel_text;	/* call hot_patch_kernel_text */ \
3:

	ENTRY(lockstat_hotpatch_probe)
	stp	x29, x30, [sp, #-(8*4)]!
	str	x19, [sp, #16]
	mov	w19, w0
	HOT_PATCH_MATCH(.lock_try_lockstat_patch_point, LS_LOCK_TRY_ACQUIRE, w19)
	HOT_PATCH_MATCH(.lock_clear_lockstat_patch_point, LS_LOCK_CLEAR_RELEASE, w19)
	HOT_PATCH_MATCH(.lock_set_lockstat_patch_point, LS_LOCK_SET_ACQUIRE, w19)
	HOT_PATCH_MATCH(.lock_set_spl_lockstat_patch_point, LS_LOCK_SET_SPL_ACQUIRE, w19)
	HOT_PATCH_MATCH(.lock_clear_splx_lockstat_patch_point, LS_LOCK_CLEAR_SPLX_RELEASE, w19)
	HOT_PATCH_MATCH(.mutex_enter_lockstat_patch_point, LS_MUTEX_ENTER_ACQUIRE, w19)
	HOT_PATCH_MATCH(.mutex_tryenter_lockstat_patch_point, LS_MUTEX_ENTER_ACQUIRE, w19)
	HOT_PATCH_MATCH(.mutex_exit_lockstat_patch_point, LS_MUTEX_EXIT_RELEASE, w19)
	HOT_PATCH_MATCH(.rw_read_enter_lockstat_patch_point, LS_RW_ENTER_ACQUIRE, w19)
	HOT_PATCH_MATCH(.rw_write_enter_lockstat_patch_point, LS_RW_ENTER_ACQUIRE, w19)
	HOT_PATCH_MATCH(.rw_read_exit_lockstat_patch_point, LS_RW_EXIT_RELEASE, w19)
	HOT_PATCH_MATCH(.rw_write_exit_lockstat_patch_point, LS_RW_EXIT_RELEASE, w19)
	ldr	x19, [sp, #16]
	ldp	x29, x30, [sp], #(8*4)
	ret
	SET_SIZE(lockstat_hotpatch_probe)

/*
 * thread_onproc()
 * Set thread in onproc state for the specified CPU.
 * Also set the thread lock pointer to the CPU's onproc lock.
 * Since the new lock isn't held, the store ordering is important.
 * If not done in assembler, the compiler could reorder the stores.
 */
#if defined(lint)

void
thread_onproc(kthread_id_t t, cpu_t *cp)
{
	t->t_state = TS_ONPROC;
	t->t_lockp = &cp->cpu_thread_lock;
}

#else	/* lint */

	ENTRY(thread_onproc)
	mov	w2, #TS_ONPROC
	str	w2, [x0, #T_STATE]
	add	x3, x1, #CPU_THREAD_LOCK
	add	x4, x0, #T_LOCKP
	stlr	x3, [x4]
	ret
	SET_SIZE(thread_onproc)

#endif	/* lint */

/*
 * mutex_delay_default(void)
 * Spins for approx a few hundred processor cycles and returns to caller.
 */
#if defined(lint)

void
mutex_delay_default(void)
{}

#else	/* lint */

	ENTRY(mutex_delay_default)
	mov	x0, #72
1:	sub	x0, x0, #1
	cbnz	x0, 1b
	ret
	SET_SIZE(mutex_delay_default)

#endif  /* lint */
