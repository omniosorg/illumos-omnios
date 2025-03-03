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

#include <sys/types.h>
#include <sys/null.h>
#include <sys/controlregs.h>
#include <sys/bootinfo.h>
#include <sys/efifb.h>
#include <sys/framebuffer.h>

#include "dboot.h"
#include "dboot_printf.h"

extern void memlist_dump(struct memlist *);
extern void exception_vector(void);
extern void _reset(void);

void
dump_exception(uint64_t *regs)
{
	uint64_t pc;
	uint64_t esr;
	uint64_t far;
	__asm__ volatile("mrs %0, elr_el1":"=r"(pc));
	__asm__ volatile("mrs %0, esr_el1":"=r"(esr));
	__asm__ volatile("mrs %0, far_el1":"=r"(far));
	dboot_printf("%s\n", __func__);
	dboot_printf("pc  = %lx\n",  pc);
	dboot_printf("esr = %lx\n",  esr);
	dboot_printf("far = %lx\n",  far);
	for (int i = 0; i < 31; i++)
		dboot_printf("x%d%s = %lx\n", i, ((i >= 10)?" ":""), regs[i]);
	_reset();
}

void
exitto(int (*entrypoint)(struct xboot_info *), struct xboot_info *bi)
{
	uint64_t el;
	boot_framebuffer_t *fb;
	struct efi_fb *efifb;
	extern fb_info_t fb_info;

	efifb = NULL;

	bi->bi_phys_installed = (uint64_t)pinstalledp;
	bi->bi_phys_avail = (uint64_t)pfreelistp;
	bi->bi_boot_scratch = (uint64_t)pscratchlistp;
	bi->bi_fw_code = (uint64_t)pfwcodelistp;
	bi->bi_fw_data = (uint64_t)pfwdatalistp;
	bi->bi_fw_mmio = (uint64_t)piolistp;
	bi->bi_fw_rsvd = (uint64_t)prsvdlistp;

	el = read_CurrentEL();
	el >>= 2;
	el &= 0x3;

	if (verbosemode && debug) {
		dprintf("Installed Memory List:\n");
		memlist_dump(pinstalledp);

		dprintf("Free Memory List:\n");
		memlist_dump(pfreelistp);

		dprintf("Scratch Memory List:\n");
		memlist_dump(pscratchlistp);

		dprintf("Firmware Code Memory List:\n");
		memlist_dump(pfwcodelistp);

		dprintf("Firmware Data Memory List:\n");
		memlist_dump(pfwdatalistp);

		dprintf("Firmware MMIO List:\n");
		memlist_dump(piolistp);

		dprintf("Firmware Reserved Memory List:\n");
		memlist_dump(prsvdlistp);

		dprintf("Loader MMIO List:\n");
		memlist_dump(pldriolistp);

		dprintf("Boot Information:\n");
		dprintf("  %s: 0x%lx\n", "bi_fdt", bi->bi_fdt);
		dprintf("  %s: 0x%lx\n", "bi_uefi_systab", bi->bi_uefi_systab);
		dprintf("  %s: 0x%lx\n", "bi_cmdline", bi->bi_cmdline);
		dprintf("  %s: 0x%lx\n", "bi_modules", bi->bi_modules);
		dprintf("  %s: 0x%lx\n", "bi_phys_installed",
		    bi->bi_phys_installed);
		dprintf("  %s: 0x%lx\n", "bi_phys_avail", bi->bi_phys_avail);
		dprintf("  %s: 0x%lx\n", "bi_boot_scratch",
		    bi->bi_boot_scratch);
		dprintf("  %s: 0x%lx\n", "bi_fw_code", bi->bi_fw_code);
		dprintf("  %s: 0x%lx\n", "bi_fw_data", bi->bi_fw_data);
		dprintf("  %s: 0x%lx\n", "bi_fw_mmio", bi->bi_fw_mmio);
		dprintf("  %s: 0x%lx\n", "bi_fw_rsvd", bi->bi_fw_rsvd);
		dprintf("  %s: 0x%lx\n", "bi_bsvc_uart_mmio_base",
		    bi->bi_bsvc_uart_mmio_base);
		dprintf("  %s: 0x%lx\n", "bi_arch_timer_freq",
		    bi->bi_arch_timer_freq);
		dprintf("  %s: 0x%lx\n", "bi_framebuffer", bi->bi_framebuffer);
		dprintf("  %s: 0x%lx\n", "bi_hyp_stubs", bi->bi_hyp_stubs);
		dprintf("  %s: 0x%x\n", "bi_bsvc_uart_type",
		    bi->bi_bsvc_uart_type);
		dprintf("  %s: 0x%x\n", "bi_module_cnt", bi->bi_module_cnt);
		dprintf("  %s: 0x%x\n", "bi_psci_version", bi->bi_psci_version);
		dprintf("  %s: 0x%x\n", "bi_psci_conduit_hvc",
		    bi->bi_psci_conduit_hvc);
		dprintf("  %s: 0x%x\n", "bi_psci_cpu_suspend_id",
		    bi->bi_psci_cpu_suspend_id);
		dprintf("  %s: 0x%x\n", "bi_psci_cpu_off_id",
		    bi->bi_psci_cpu_off_id);
		dprintf("  %s: 0x%x\n", "bi_psci_cpu_on_id",
		    bi->bi_psci_cpu_on_id);
		dprintf("  %s: 0x%x\n", "bi_psci_migrate_id",
		    bi->bi_psci_migrate_id);
		dprintf("Exception Level: %lu\n", el);
		dprintf("Kernel Entrypoint: 0x%p\n", entrypoint);
	} else if (verbosemode) {
		dboot_printf("Boot Information:\n");
		dboot_printf("  %s: %s\n", "Firmware Tables",
		    bi->bi_fdt == 0 ? "ACPI" : "FDT");
		dboot_printf("  %s: %s\n", "Command Line",
		    bi->bi_cmdline == 0 ? "" : (const char *)bi->bi_cmdline);
		dboot_printf("  %s: %s\n", "Hypervisor Stubs",
		    bi->bi_hyp_stubs == 0 ? "Absent" : "Present");
		dboot_printf("  %s: %s\n", "Framebuffer",
		    bi->bi_framebuffer == 0 ? "Absent" : "Present");
		dboot_printf("  %s: %luHz\n", "Timer Frequency",
		    bi->bi_arch_timer_freq);
		dboot_printf("  %s: %u.%u\n", "PSCI Version",
		    bi->bi_psci_version >> 16, bi->bi_psci_version & 0xffff);
		dboot_printf("  %s: %s\n", "PSCI Conduit",
		    bi->bi_psci_conduit_hvc ? "Hypervisor" : "Secure Monitor");
		dboot_printf("Exception Level: %lu\n", el);
		dboot_printf("%s: 0x%p\n", "Kernel Entrypoint", entrypoint);
	}

	/*
	 * Flush the TLB and caches. This is not strictly necessary.
	 */
	isb();
	tlbi_allis();
	dsb(ish);
	isb();

	if (bi->bi_fdt == 0) {
		dboot_printf(
		    "dboot: ACPI kernel support is a work in progress\n");
		for (;;)
			/* spin forever */;
	}

	/*
	 * There can be no more screen output in the nominal case once we've
	 * copied out cursor information to the data structure the kernel
	 * will receive.
	 */
	if ((fb = (boot_framebuffer_t *)bi->bi_framebuffer) != NULL)
		efifb = (struct efi_fb *)fb->framebuffer;

	if (fb != NULL && efifb != NULL) {
		fb->cursor.origin.x = fb_info.cursor.origin.x;
		fb->cursor.origin.y = fb_info.cursor.origin.y;
		fb->cursor.pos.x = fb_info.cursor.pos.x;
		fb->cursor.pos.y = fb_info.cursor.pos.y;
		fb->cursor.visible = fb_info.cursor.visible;
	}

	/*
	 * ... and jump!
	 */
	entrypoint(bi);
}
