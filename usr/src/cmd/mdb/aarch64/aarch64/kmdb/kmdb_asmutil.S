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
 */

#include <sys/asm_linkage.h>

	ENTRY(membar_producer)
	dmb	ish
	nop
	ret
	SET_SIZE(membar_producer)

	ENTRY(flush_instr)
	dc	cvau, x0
	dsb	ish
	ic	ivau, x0
	dsb	ish
	isb
	nop
	ret
	SET_SIZE(flush_instr)

	ENTRY(get_fp)
	mov	x0, fp
	ret
	SET_SIZE(get_fp)
