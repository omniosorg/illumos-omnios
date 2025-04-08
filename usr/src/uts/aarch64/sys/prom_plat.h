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
 * Copyright (c) 1994-1996,1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
/*
 * Copyright 2025 Michael van der Westhuizen
 */

#ifndef	_SYS_PROM_PLAT_H
#define	_SYS_PROM_PLAT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * FDT-specific
 */
struct prom_hwclock {
	pnode_t node;
	uint32_t id;
};

extern int prom_fdt_get_reg(pnode_t node, int index, uint64_t *base);
extern int prom_fdt_get_clock_by_name(pnode_t node, const char *name,
    struct prom_hwclock *clock);
extern boolean_t prom_fdt_is_compatible(pnode_t node, const char *name);
extern pnode_t prom_fdt_find_compatible(pnode_t node, const char *compatible);
extern void prom_fdt_walk(void(*func)(pnode_t, void*), void *arg);
extern int prom_fdt_get_reg_address(pnode_t node, int index, uint64_t *reg);
extern int prom_fdt_get_reg_size(pnode_t node, int index, uint64_t *regsize);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PROM_PLAT_H */
