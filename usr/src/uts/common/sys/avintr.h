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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_AVINTR_H
#define	_SYS_AVINTR_H


#include <sys/mutex.h>
#include <sys/dditypes.h>
#include <sys/ddi_intr.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* XXXARM: This is way too low on ARM */
#ifdef __xpv
#define	MAX_VECT	NR_IRQS
#else
#define	MAX_VECT	256
#endif

/*
 * Period of autovector structures (add this in to get the next level).
 */
#define	MAXIPL	16
#define	INT_IPL(x) (x)
#define	AV_INT_SPURIOUS	-1

typedef uint_t (*avfunc)(caddr_t, caddr_t);

struct autovec {

	/*
	 * Interrupt handler and argument to pass to it.
	 */

	struct autovec *av_link;	/* pointer to next on in chain */
	uint_t av_vecnum;
	uint_t	(*av_vector)();
	caddr_t	av_intarg1;
	caddr_t	av_intarg2;
	uint64_t *av_ticksp;
	uint_t	av_prilevel;		/* priority level */

	/*
	 * Interrupt handle/id (like intrspec structure pointer) used to
	 * identify a specific instance of interrupt handler in case we
	 * have to remove the interrupt handler later.
	 *
	 */
	void	*av_intr_id;
	dev_info_t *av_dip;
	ushort_t	av_flags;	/* pending flags */
	struct autovec *av_ipl_link;	/* pointer to next on ipl chain */
};

#define	AV_PENTRY_VECTMASK	0xff	/* low 8 bit used for irqno */
#define	AV_PENTRY_PEND	0x100	/* pending hardware interrupt */
#define	AV_PENTRY_ONPROC	0x200	/* being serviced by CPU */
#define	AV_PENTRY_LEVEL	0x8000	/* level-triggered interrupt */

struct av_head {
	struct	autovec	*avh_link;
	ushort_t	avh_hi_pri;
	ushort_t	avh_lo_pri;
};

/* softing contains a bit field of software interrupts which are pending */
struct softint {
	int st_pending;
};

#ifdef _KERNEL

extern kmutex_t av_lock;
extern ddi_softint_hdl_impl_t softlevel_hdl[];
extern ddi_softint_hdl_impl_t softlevel1_hdl;
extern int add_avintr(void *intr_id, int lvl, avfunc xxintr, char *name,
	int vect, caddr_t arg1, caddr_t arg2, uint64_t *, dev_info_t *);
extern int add_nmintr(int lvl, avfunc nmintr, char *name, caddr_t arg);
extern int add_avsoftintr(void *intr_id, int lvl, avfunc xxintr,
	char *name, caddr_t arg1, caddr_t arg2);
extern int rem_avsoftintr(void *intr_id, int lvl, avfunc xxintr);
extern int av_softint_movepri(void *intr_id, int old_lvl);
extern void update_avsoftintr_args(void *intr_id, int lvl, caddr_t arg2);
extern void rem_avintr(void *intr_id, int lvl, avfunc xxintr, int vect);
extern void wait_till_seen(int ipl);
extern uint_t softlevel1(caddr_t, caddr_t);
extern int av_get_vec_lvl(uint_t vect, int *lvl);

#if defined(__aarch64__)

struct ddi_intr_handle_impl;	/* <sys/ddi_intr_impl.h> */

extern int av_get_shared(uint_t vecnum, uint_t *prip);
extern uint_t av_get_vector_info(uint_t vecnum,
    struct ddi_intr_handle_impl **hdlpp, dev_info_t **dips, uint_t dips_max);

#endif

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_AVINTR_H */
