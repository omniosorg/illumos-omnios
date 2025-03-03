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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2011 Joyent, Inc. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#ifndef _SYS_MACHCPUVAR_H
#define	_SYS_MACHCPUVAR_H

#ifndef	_ASM

#include <sys/types.h>
#include <sys/avintr.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct	machcpu {
	struct hat	*mcpu_current_hat;
	uint32_t	mcpu_asid;
	uint64_t	mcpu_asid_gen;
	int		mcpu_pri;

	volatile int	xc_pend;
	volatile int	xc_wait;
	volatile int	xc_ack;
	volatile int	xc_state;
	volatile int	xc_retval;

	struct softint	mcpu_softinfo;
	uint64_t	pil_high_start[HIGH_LEVELS];
	uint64_t	intrstat[PIL_MAX + 1][2];

	uint64_t	affinity;

	char		*mcpu_implementer;
	char		*mcpu_partname;
	char		*mcpu_revision;
	uint64_t	mcpu_midr;
	uint64_t	mcpu_revidr;

	uint64_t	mcpu_boot_el;

	struct cpuinfo	*mcpu_ci;
};

#ifndef NINTR_THREADS
#define	NINTR_THREADS	(LOCK_LEVEL)	/* number of interrupt threads */
#endif

#define	cpu_asid	cpu_m.mcpu_asid
#define	cpu_asid_gen	cpu_m.mcpu_asid_gen
#define	cpu_current_hat cpu_m.mcpu_current_hat
#define	cpu_implementer	cpu_m.mcpu_implementer
#define	cpu_partname	cpu_m.mcpu_partname
#define	cpu_pri		cpu_m.mcpu_pri
#define	cpu_revision	cpu_m.mcpu_revision
#define	cpu_softinfo	cpu_m.mcpu_softinfo

struct	cpu_startup_data {
	uint64_t	mair;
	uint64_t	tcr;
	uint64_t	ttbr0;
	uint64_t	ttbr1;
	uint64_t	sctlr;
	uint64_t	vbar;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _ASM */

#endif	/* _SYS_MACHCPUVAR_H */
