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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef	_SYS_PCB_H
#define	_SYS_PCB_H

#include <sys/cpu.h>
#include <sys/fp.h>
#include <sys/regset.h>
#include <sys/mcontext.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_ASM)
typedef struct pcb {
	fpu_ctx_t	pcb_fpu;
	uint_t		pcb_flags;	/* state flags; cleared on fork */
	uint_t		pcb_instr;	/* /proc: instruction at stop */
	uint64_t	pcb_tpidr;
} pcb_t;

#endif /* ! _ASM */

/* pcb_flags */
#define	DEBUG_PENDING	0x02	/* single-step of lcall for a sys call */
#define	PRSTOP_CALLED	0x04	/* prstop() has been called for this lwp */
#define	INSTR_VALID	0x08	/* value in pcb_instr is valid (/proc) */
#define	NORMAL_STEP	0x10	/* normal debugger-requested single-step */
#define	WATCH_STEP	0x20	/* single-stepping in watchpoint emulation */
#define	CPC_OVERFLOW	0x40	/* performance counters overflowed */
#define	REQUEST_STEP	0x100	/* request pending to single-step this lwp */
#define	REQUEST_NOSTEP	0x200	/* request pending to disable single-step */
#define	ASYNC_HWERR	0x400	/* hardware error has corrupted context  */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCB_H */
