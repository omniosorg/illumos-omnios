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
 * Copyright 2020 Joyent, Inc.
 * Copyright 2025 Michael van der Westhuizen
 */

#ifndef	_SYS_BOOTINFO_H
#define	_SYS_BOOTINFO_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_BOOT_MODULES	99

typedef enum {
	XBI_BSVC_UART_NONE	= 0x0,
	XBI_BSVC_UART_PL011	= 0x0003,
	XBI_BSVC_UART_SBSA2X	= 0x000d,
	XBI_BSVC_UART_SBSA	= 0x000e,
	XBI_BSVC_UART_BCM2835	= 0x0010
} xbi_bsvc_uart_type_t;

/* BEGIN CSTYLED */
#if __STDC_VERSION__ - 0 >= 201112L && !defined(__cplusplus)
_Static_assert(sizeof (xbi_bsvc_uart_type_t) == sizeof (int),
    "UART type enum is not the same size as int");
#endif
/* END CSTYLED */

typedef enum {
	BI_PSCI_CONDUIT_UNKNOWN,
	BI_PSCI_CONDUIT_HVC,
	BI_PSCI_CONDUIT_SMC,
} bi_psci_conduit;

typedef enum boot_module_type {
	BMT_ROOTFS,
	BMT_FILE,
	BMT_HASH,
	BMT_ENV,
	BMT_FONT
} boot_module_type_t;

/*
 * The kernel needs to know how to find its modules.
 */
struct boot_modules {
	uint64_t		bm_addr;
	uint64_t		bm_name;
	uint64_t		bm_hash;
	uint64_t		bm_size;
	boot_module_type_t	bm_type;
};

/* To help to identify UEFI system. */
typedef enum uefi_arch_type {
	XBI_UEFI_ARCH_NONE,
	XBI_UEFI_ARCH_32,
	XBI_UEFI_ARCH_64
} uefi_arch_type_t;

/*
 *
 */
struct xboot_info {
	uint64_t		bi_fdt;
	uint64_t		bi_uefi_systab;
	uint64_t		bi_cmdline;
	uint64_t		bi_modules;
	uint64_t		bi_phys_installed;
	uint64_t		bi_phys_avail;
	uint64_t		bi_boot_scratch;
	uint64_t		bi_fw_code;
	uint64_t		bi_fw_data;
	uint64_t		bi_fw_mmio;
	uint64_t		bi_fw_rsvd;
	uint64_t		bi_bsvc_uart_mmio_base;
	uint64_t		bi_arch_timer_freq;
	uint64_t		bi_framebuffer;
	xbi_bsvc_uart_type_t	bi_bsvc_uart_type;
	uint32_t		bi_module_cnt;
	uint32_t		bi_psci_version;
	uint32_t		bi_psci_conduit_hvc;
	uint32_t		bi_psci_cpu_suspend_id;
	uint32_t		bi_psci_cpu_off_id;
	uint32_t		bi_psci_cpu_on_id;
	uint32_t		bi_psci_migrate_id;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BOOTINFO_H */
