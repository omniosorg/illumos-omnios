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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/cpuvar.h>
#include <sys/kdi_impl.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/bootconf.h>
#include <sys/cmn_err.h>
#include <vm/seg_kmem.h>
#include <vm/hat_aarch64.h>
#include <sys/bootinfo.h>
#include <sys/machsystm.h>

void
hat_boot_kdi_init(void)
{
}

void
hat_kdi_init(void)
{
}

int
kdi_vtop(uintptr_t vaddr, uint64_t *pap)
{
	uintptr_t va = ALIGN2PAGE(vaddr);

	write_s1e1r(va);
	isb();

	uint64_t par = read_par_el1();
	if (par & PAR_F)
		return (ENOENT);

	*pap = ((par & PAR_PA_MASK) | (vaddr & MMU_PAGEOFFSET));
	return (0);
}

int
kdi_pread(caddr_t buf, size_t nbytes, uint64_t addr, size_t *ncopiedp)
{
	caddr_t va = (caddr_t)(addr + SEGKPM_BASE);
	bcopy(va, buf, nbytes);
	*ncopiedp = nbytes;
	return (0);
}

int
kdi_pwrite(caddr_t buf, size_t nbytes, uint64_t addr, size_t *ncopiedp)
{
	caddr_t va = (caddr_t)(addr + SEGKPM_BASE);
	bcopy(buf, va, nbytes);
	*ncopiedp = nbytes;
	return (0);
}

size_t
kdi_range_is_nontoxic(uintptr_t va, size_t sz, int write)
{
	/*
	 * avoid any Virtual Address hole
	 */
	if (va + sz >= hole_start && va < hole_end)
		return (va < hole_start ? hole_start - va : 0);

	return (sz);
}
