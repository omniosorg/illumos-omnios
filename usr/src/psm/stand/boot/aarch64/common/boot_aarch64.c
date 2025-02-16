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
 * Copyright 2025 Michael van der Westhuizen
 */
#include <libfdt.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/boot.h>
#include <sys/salib.h>
#include <sys/promif.h>
#include <sys/platform.h>
#include <sys/controlregs.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/sysmacros.h>
#include <sys/bootconf.h>
#include <sys/psci.h>
#include "prom_dev.h"
#include "boot_plat.h"

#ifndef rounddown
#define	rounddown(x, y)	(((x)/(y))*(y))
#endif

char *default_name = "armv8";
char *default_path = "/platform/armv8/kernel";
extern void exception_vector(void);
extern uint64_t boot_args[];
extern char _BootStart[];
extern char _BootEnd[];

#define	ENVBLOCK_SIZE	4096
char envblock[ENVBLOCK_SIZE] = {0};
size_t envblock_len = 0;

void
setenv(const char *name, const char *value)
{
	char *ptr;
	int needed;
	int written;

	ptr = envblock + envblock_len;
	needed = snprintf(ptr, 0, "%s=%s", name, value);
	if (needed < 0)
		prom_panic("setenv: snprintf failed\n");
	needed += 2;
	if (ENVBLOCK_SIZE - envblock_len < needed)
		prom_panic("setenv: no space\n");
	written = snprintf(ptr, needed, "%s=%s", name, value);
	if (written != needed - 2)
		prom_panic("setenv: write failed\n");
	ptr[written] = '\0';
	ptr[written + 1] = '\0';
	envblock_len += written;
	envblock_len++; /* include the NUL */
}

boolean_t
is_netdev(char *devpath)
{
	return (prom_is_netdev(devpath));
}

void
fiximp(void)
{
	extern int use_align;
	extern boolean_t psci_initialized;

	use_align = 1;

	write_vbar((uint64_t)&exception_vector);

	psci_init(NULL);

	if (!psci_initialized) {
		prom_printf("PSCI did not initialize successfully\n");
		for (;;) {}	/* we can't reset if PSCI is not up */
	}

	if ((4u << ((read_ctr_el0() >> 16) & 0xF)) != DCACHE_LINE) {
		prom_printf("CTR_EL0=%08x DCACHE_LINE=%ld\n",
		    (uint32_t)read_ctr_el0(), DCACHE_LINE);
		prom_reset();
	}

}

void
dump_exception(uint64_t *regs)
{
	uint64_t pc;
	uint64_t esr;
	uint64_t far;
	__asm__ volatile("mrs %0, elr_el1":"=r"(pc));
	__asm__ volatile("mrs %0, esr_el1":"=r"(esr));
	__asm__ volatile("mrs %0, far_el1":"=r"(far));
	prom_printf("%s\n", __func__);
	prom_printf("pc  = %016lx\n",  pc);
	prom_printf("esr = %016lx\n",  esr);
	prom_printf("far = %016lx\n",  far);
	for (int i = 0; i < 31; i++)
		prom_printf("x%d%s = %016lx\n", i, ((i >= 10)?" ":""), regs[i]);
	prom_reset();
}

static void
add_memory(uint64_t addr, uint64_t size)
{
	const size_t install_memory_size = 0x4000000;
	for (uint64_t begin = rounddown(addr, install_memory_size);
	    begin < roundup(addr + size, install_memory_size);
	    begin += install_memory_size) {
		if (memlist_find(pinstalledp, begin) == NULL) {
			memlist_add_span(
			    begin, install_memory_size, &pinstalledp);
		}
	}

	memlist_add_span(addr, size, &plinearlistp);
	memlist_add_span(addr, size, &pfreelistp);
}

void
init_physmem_common(void)
{
	int err;
	extern char _dtb_start[];
	void *fdtp = (void *)boot_args[0];

	if (get_fdtp() != 0) {
		prom_printf("%s() should be called before prom_node_init()\n");
		return;
	}

	err = fdt_check_header(fdtp);
	if (err) {
		prom_printf("fdt_check_header ng\n");
		return;
	}
	size_t total_size = fdt_totalsize(fdtp);
	if ((uintptr_t)_dtb_start != (uintptr_t)fdtp)
		memcpy(_dtb_start, fdtp, total_size);

	int address_cells = fdt_address_cells(_dtb_start, 0);
	int size_cells = fdt_size_cells(_dtb_start, 0);

	int nodeoffset = fdt_subnode_offset(_dtb_start, 0, "memory");
	if (nodeoffset < 0) {
		prom_printf("fdt memory not found\n");
		return;
	}
	if (!(address_cells == 2 || address_cells == 1)) {
		prom_printf("fdt invalid address_cells %d\n", address_cells);
		return;
	}
	if (!(size_cells == 2 || size_cells == 1)) {
		prom_printf("fdt invalid size_cells %d\n", size_cells);
		return;
	}

	int len;
	const volatile uint32_t *reg =
	    fdt_getprop(_dtb_start, nodeoffset, "reg", &len);
	for (int i = 0;
	    i < len / (sizeof (uint32_t) * (address_cells + size_cells));
	    i++) {
		uint64_t addr = 0;
		uint64_t size = 0;
		if (address_cells == 2) {
			addr =
			    ((uint64_t)(ntohl(*reg)) << 32) | ntohl(*(reg + 1));
			reg += 2;
		} else {
			addr = ntohl(*reg);
			reg += 1;
		}
		if (size_cells == 2) {
			size =
			    ((uint64_t)(ntohl(*reg)) << 32) | ntohl(*(reg + 1));
			reg += 2;
		} else {
			size = ntohl(*reg);
			reg += 1;
		}
		if (size != 0) {
			prom_printf("phys memory add %016lx - %016lx\n",
			    addr, addr + size - 1);
			add_memory(addr, size);
		}
	}
	for (int i = 0; ; i++) {
		uint64_t addr;
		uint64_t size;
		fdt_get_mem_rsv(_dtb_start, i, &addr, &size);
		if (size == 0)
			break;
		if ((uintptr_t)fdtp == addr &&
		    size == roundup(total_size, MMU_PAGESIZE)) {
			prom_printf(
			    "memory resv %016lx - %016lx (skip for dtb)\n",
			    addr, addr + size - 1);
			continue;
		}
		size = roundup(addr + size, MMU_PAGESIZE) -
		    rounddown(addr, MMU_PAGESIZE);
		addr = rounddown(addr, MMU_PAGESIZE);
		prom_printf("memory resv %016lx - %016lx\n",
		    addr, addr + size - 1);
		if (memlist_find(pfreelistp, addr))
			memlist_delete_span(addr, size, &pfreelistp);
		if (memlist_find(plinearlistp, addr))
			memlist_delete_span(addr, size, &plinearlistp);
	}
	nodeoffset = fdt_subnode_offset(_dtb_start, 0, "reserved-memory");
	if (nodeoffset > 0) {
		int child = fdt_first_subnode(_dtb_start, nodeoffset);
		while (child > 0) {
			reg = fdt_getprop(_dtb_start, child, "reg", &len);
			if (reg == NULL) {
				child = fdt_next_subnode(_dtb_start, child);
				continue;
			}

			for (int i = 0; i < len / (sizeof (uint32_t) *
			    (address_cells + size_cells)); i++) {
				uint64_t addr = 0;
				uint64_t size = 0;
				if (address_cells == 2) {
					addr =
					    ((uint64_t)(ntohl(*reg)) << 32) |
					    ntohl(*(reg + 1));
					reg += 2;
				} else {
					addr = ntohl(*reg);
					reg += 1;
				}
				if (size_cells == 2) {
					size =
					    ((uint64_t)(ntohl(*reg)) << 32) |
					    ntohl(*(reg + 1));
					reg += 2;
				} else {
					size = ntohl(*reg);
					reg += 1;
				}
				if (size != 0) {
					size =
					    roundup(addr + size, MMU_PAGESIZE) -
					    rounddown(addr, MMU_PAGESIZE);
					addr = rounddown(addr, MMU_PAGESIZE);
					prom_printf(
					    "memory resv %016lx - %016lx\n",
					    addr, addr + size - 1);
					if (memlist_find(pfreelistp, addr))
						memlist_delete_span(
						    addr, size, &pfreelistp);
					if (memlist_find(plinearlistp, addr))
						memlist_delete_span(
						    addr, size, &plinearlistp);
				}
			}
			child = fdt_next_subnode(_dtb_start, child);
		}
	}
	memlist_delete_span((uintptr_t)_BootStart,
	    (uintptr_t)_BootEnd - (uintptr_t)_BootStart, &pfreelistp);
	memlist_add_span((uintptr_t)_BootStart,
	    (uintptr_t)_BootEnd - (uintptr_t)_BootStart, &pscratchlistp);
	if (BOOT_TMP_MAP_SIZE > 0)
		memlist_add_span(
		    BOOT_TMP_MAP_BASE, BOOT_TMP_MAP_SIZE, &ptmplistp);
}
