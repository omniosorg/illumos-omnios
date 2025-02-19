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

/*
 * EFI Direct Boot
 *
 * The EFI direct-boot shim is compiled as a position independent ELF
 * binary (i.e. PIE), then extracted into a binary file which is included
 * verbatim into `unix`, which sets the kernel entrypoint to the binary
 * extracted from this code.
 *
 * By the time the main function in this file is called the shim has been
 * relocated (see self_reloc), so we're in a fairly normal-looking standalone
 * environment.
 *
 * The main function is passed a modules pointer, which points to a module
 * table (FreeBSD-style) produced by loader(7). This table is parsed and
 * partially validated the `dboot_configure` routine. The configure routine
 * is responsible for all shim configuration, including bootstrapping
 * memory management.
 *
 * Once the configure routine returns the only remaining job is to load
 * the kernel that encloses this shim to it's final virtual addresses in
 * KVA and jump to it, passing the `xboot_info` constructed by the
 * configuration routine.
 */

#include <sys/types.h>
#include <sys/null.h>
#include <sys/stdbool.h>
#include <sys/bootinfo.h>
#include <sys/machparam.h>
#include <sys/psci.h>
#include <sys/boot_console.h>
#include <sys/bootsvcs.h>

#include "dboot.h"

#include "dboot_printf.h"

static struct xboot_info xboot_info;
struct xboot_info *bi = &xboot_info;

int verbosemode = 0;

#if defined(DEBUG)
int debug = 1;
#else
int debug = 0;
#endif

int boothowto = 0;

#define	LOAD_ELF_FAILED	((func_t)-1)
typedef int (*func_t)(struct xboot_info *);
extern func_t load_elf_payload(caddr_t payload, size_t payload_size, int print);
extern void exitto(func_t entrypoint, struct xboot_info *);

uintptr_t
pa_to_ttbr1(uintptr_t pa)
{
	return (SEGKPM_BASE + pa);
}

int
main(caddr_t modulesp)
{
	struct boot_modules *bm;
	caddr_t kernel;
	uint64_t kernel_size;
	uint32_t i;
	func_t func;

	kernel = NULL;
	kernel_size = 0;

	bcons_init(NULL);

	if (dboot_configure(modulesp, bi, &kernel, &kernel_size) != 0)
		panic("dboot: configuration failed\n");

	if (bi->bi_modules == 0 || bi->bi_module_cnt == 0)
		panic("dboot: no boot modules found\n");

	bm = (struct boot_modules *)bi->bi_modules;

	if (verbosemode) {
		dboot_printf("Kernel at 0x%p, size 0x%lx\n",
		    kernel, kernel_size);
		dboot_printf("Kernel arguments: '%s'\n",
		    (const char *)bi->bi_cmdline);

		for (i = 0; i < bi->bi_module_cnt; ++i) {
			dboot_printf("Module %u: %s (%u) 0x%lx 0x%lx\n",
			    i,
			    (const char *)bm[i].bm_name,
			    bm[i].bm_type,
			    bm[i].bm_addr,
			    bm[i].bm_size);
		}
	}

	func = load_elf_payload(kernel, kernel_size, verbosemode);
	if (func == LOAD_ELF_FAILED)
		panic("dboot: failed to load elf64 kernel\n");

	if (verbosemode)
		dboot_printf("Kernel entrypoint address is 0x%p\n", func);

	(void) exitto(func, bi);
	panic("dboot: kernel entrypoint returned\n");
}
