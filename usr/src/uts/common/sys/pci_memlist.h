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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 Michael van der Westhuizen
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_PCI_MEMLIST_H
#define	_SYS_PCI_MEMLIST_H

#include <sys/memlist.h>

#ifdef __cplusplus
extern "C" {
#endif

extern struct memlist *pci_memlist_alloc(void);
extern void pci_memlist_free(struct memlist *);
extern void pci_memlist_free_all(struct memlist **);
extern void pci_memlist_insert(struct memlist **, uint64_t, uint64_t);
extern int pci_memlist_remove(struct memlist **, uint64_t, uint64_t);
extern uint64_t pci_memlist_find(struct memlist **, uint64_t, int);
extern uint64_t pci_memlist_find_with_startaddr(struct memlist **, uint64_t,
    uint64_t, int);
extern void pci_memlist_dump(struct memlist *);
extern void pci_memlist_subsume(struct memlist **, struct memlist **);
extern void pci_memlist_merge(struct memlist **, struct memlist **);
extern struct memlist *pci_memlist_dup(struct memlist *);
extern int pci_memlist_count(struct memlist *);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_PCI_MEMLIST_H */
