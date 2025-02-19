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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2025 Michael van der Westhuizen
 * Copyright 2017 Hayashi Naoyuki
 */

#include <sys/types.h>
#include <sys/null.h>
#include <sys/bootinfo.h>

#include "dboot.h"

static uint32_t pcsi_version_id = 0x84000000;
static uint32_t psci_system_off_id = 0x84000008;
static uint32_t psci_system_reset_id = 0x84000009;
boolean_t pcsi_method_is_hvc = B_FALSE;
boolean_t psci_initialized = B_FALSE;

static uint32_t psci_version(void);

static inline uint64_t
psci_smc64(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
	register uint64_t x0 __asm__("x0") = a0;
	register uint64_t x1 __asm__("x1") = a1;
	register uint64_t x2 __asm__("x2") = a2;
	register uint64_t x3 __asm__("x3") = a3;

	__asm__ volatile("smc #0"
	    : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
	    :
	    :
	    "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
	    "x12", "x13", "x14", "x15", "x16", "x17", "x18", "memory", "cc");

	return (x0);
}

static inline uint64_t
psci_hvc64(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
	register uint64_t x0 __asm__("x0") = a0;
	register uint64_t x1 __asm__("x1") = a1;
	register uint64_t x2 __asm__("x2") = a2;
	register uint64_t x3 __asm__("x3") = a3;

	__asm__ volatile("hvc #0"
	    : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
	    :
	    :
	    "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
	    "x12", "x13", "x14", "x15", "x16", "x17", "x18", "memory", "cc");

	return (x0);
}

static inline uint64_t
psci_call(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
	if (pcsi_method_is_hvc)
		return (psci_hvc64(a0, a1, a2, a3));
	else
		return (psci_smc64(a0, a1, a2, a3));
}

int
psci_init(struct xboot_info *bi)
{
	uint32_t val;

	if (bi == NULL)
		return (-1);

	pcsi_method_is_hvc = bi->bi_psci_conduit_hvc ? B_TRUE : B_FALSE;

	if ((val = psci_version()) & 0x80000000)
		return (-1);

	bi->bi_psci_version = val;
	psci_initialized = B_TRUE;
	return (0);
}

static uint32_t
psci_version(void)
{
	return (psci_call(pcsi_version_id, 0, 0, 0));
}

void
psci_system_off(void)
{
	if (psci_initialized != B_TRUE)
		for (;;)
			/* spin forever */;

	psci_call(psci_system_off_id, 0, 0, 0);
}

void
psci_system_reset(void)
{
	if (psci_initialized != B_TRUE)
		for (;;)
			/* spin forever */;

	psci_call(psci_system_reset_id, 0, 0, 0);
}
