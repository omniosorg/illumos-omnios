/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/bootinfo.h>
#include <sys/null.h>

#include "dboot.h"

struct efi_map_header *efi_map_header = NULL;

caddr_t _BootScratch;
caddr_t _BootScratchEnd;

struct memlist *pfreelistp = NULL;
struct memlist *pscratchlistp = NULL;
struct memlist *pinstalledp = NULL;
struct memlist *pmappablep = NULL;
struct memlist *piolistp = NULL;
struct memlist *pldriolistp = NULL;
struct memlist *ptmplistp = NULL;
struct memlist *pfwcodelistp = NULL;
struct memlist *pfwdatalistp = NULL;
struct memlist *prsvdlistp = NULL;

extern void init_memlists(void);
extern void init_memory(void);

int
dboot_uefi_init_mem(caddr_t memmap, caddr_t scratch_addr, uint64_t scratch_size)
{
	efi_map_header = (struct efi_map_header *)memmap;
	_BootScratch = scratch_addr;
	_BootScratchEnd = scratch_addr + scratch_size;

	init_memlists();
	init_memory();

	/* set the pointers */

	return (0);
}
