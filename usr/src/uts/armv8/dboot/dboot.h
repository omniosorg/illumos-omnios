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

#ifndef _DBOOT_DBOOT_H
#define	_DBOOT_DBOOT_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int boothowto;
extern int verbosemode;
extern int debug;
#define	dprintf	if (debug) dboot_printf

struct xboot_info;

struct efi_map_header {
	size_t		memory_size;
	size_t		descriptor_size;
	uint32_t	descriptor_version;
};

#define	efi_mmap_next(ptr, size) \
	((EFI_MEMORY_DESCRIPTOR *)(((uint8_t *)(ptr)) + (size)))

#define	RNDUP(x, y)	((x) + ((y) - 1ul) & ~((y) - 1ul))
#define	RNDDN(x, y)	((x) & ~((y) - 1ul))

struct memlist;

extern struct memlist *pfreelistp;
extern struct memlist *pscratchlistp;
extern struct memlist *pinstalledp;
extern struct memlist *pmappablep;
extern struct memlist *piolistp;
extern struct memlist *pldriolistp;
extern struct memlist *ptmplistp;
extern struct memlist *pfwcodelistp;
extern struct memlist *pfwdatalistp;
extern struct memlist *prsvdlistp;

/*
 * dboot_conf.c
 */
extern int dboot_configure(caddr_t modulep, struct xboot_info *xbi,
    caddr_t *pkernel, uint64_t *pkernel_size);
extern const char *dboot_getenv(const char *name);

/*
 * dboot_conf_fdt.c
 */
extern int dboot_configure_fdt(void);

/*
 * dboot_conf_acpi.c
 */
extern int dboot_configure_acpi(void);

/*
 * dboot_uefimem.c
 */
extern int dboot_uefi_init_mem(caddr_t memmap,
    caddr_t scratch_addr, uint64_t scratch_size);

extern void panic(const char *, ...) __attribute__((noreturn));

#ifdef __cplusplus
}
#endif

#endif /* _DBOOT_DBOOT_H */
