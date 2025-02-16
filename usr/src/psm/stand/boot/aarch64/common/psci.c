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
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */
#include <sys/types.h>
#include <sys/psci.h>
#include <sys/promif.h>
#include <string.h>
#include <libfdt.h>
#include <sys/byteorder.h>

#include "boot_plat.h"

static uint32_t pcsi_version_id = 0x84000000;
uint32_t psci_cpu_suspend_id = 0xc4000001;
uint32_t psci_cpu_off_id = 0x84000002;
uint32_t psci_cpu_on_id = 0xc4000003;
static uint32_t psci_affinity_info_id = 0xc4000004;
uint32_t psci_migrate_id = 0xc4000005;
static uint32_t psci_migrate_info_type_id = 0x84000006;
static uint32_t psci_migrate_info_up_cpu_id = 0xc4000007;
static uint32_t psci_system_off_id = 0x84000008;
static uint32_t psci_system_reset_id = 0x84000009;
static uint32_t psci_features_id = 0x8400000a;
static uint32_t psci_cpu_freeze_id = 0x8400000b;
static uint32_t psci_cpu_default_suspend_id = 0xc400000c;
static uint32_t psci_node_hw_state_id = 0xc400000d;
static uint32_t psci_system_suspend_id = 0xc400000e;
static uint32_t psci_set_suspend_mode_id = 0x8400000f;
static uint32_t psci_stat_residency_id = 0xc4000010;
static uint32_t psci_stat_count_id = 0xc4000011;
boolean_t pcsi_method_is_hvc = B_FALSE;
boolean_t psci_initialized = B_FALSE;

extern uint64_t boot_args[];

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
psci_init(struct xboot_info *xbp __unused)
{
	int err;
	extern char _dtb_start[];
	void *fdtp = (void *)boot_args[0];

	if (psci_initialized)
		return (0);

	if (get_fdtp() != 0) {
		prom_printf("%s() should be called before prom_node_init()\n");
		return (-1);
	}

	err = fdt_check_header(fdtp);
	if (err) {
		prom_printf("fdt_check_header ng\n");
		return (-1);
	}
	size_t total_size = fdt_totalsize(fdtp);
	if ((uintptr_t)_dtb_start != (uintptr_t)fdtp)
		memcpy(_dtb_start, fdtp, total_size);

	int nodeoffset =
	    fdt_node_offset_by_compatible(_dtb_start, 0, "arm,psci");
	if (nodeoffset >= 0) {
		int len;
		const char *method =
		    fdt_getprop(_dtb_start, nodeoffset, "method", &len);
		if (method && strcmp(method, "hvc") == 0)
			pcsi_method_is_hvc = B_TRUE;
		const volatile uint32_t *cpu_suspend_id =
		    fdt_getprop(_dtb_start, nodeoffset, "cpu_suspend", &len);
		if (cpu_suspend_id)
			psci_cpu_suspend_id = ntohl(*cpu_suspend_id);
		const volatile uint32_t *cpu_off_id =
		    fdt_getprop(_dtb_start, nodeoffset, "cpu_off", &len);
		if (cpu_off_id)
			psci_cpu_off_id = ntohl(*cpu_off_id);
		const volatile uint32_t *cpu_on_id =
		    fdt_getprop(_dtb_start, nodeoffset, "cpu_on", &len);
		if (cpu_on_id)
			psci_cpu_on_id = ntohl(*cpu_on_id);
		const volatile uint32_t *migrate_id =
		    fdt_getprop(_dtb_start, nodeoffset, "migrate", &len);
		if (migrate_id)
			psci_migrate_id = ntohl(*migrate_id);
		psci_initialized = B_TRUE;
		return (0);
	}

	return (-1);
}

uint32_t
psci_version(void)
{
	return (psci_call(pcsi_version_id, 0, 0, 0));
}

int32_t
psci_cpu_suspend(uint32_t power_state,
    uint64_t entry_point_address, uint64_t context_id)
{
	return (psci_call(psci_cpu_suspend_id, power_state,
	    entry_point_address, context_id));
}

int32_t
psci_cpu_off(void)
{
	return (psci_call(psci_cpu_off_id, 0, 0, 0));
}

int32_t
psci_cpu_on(uint64_t target_cpu,
    uint64_t entry_point_address, uint64_t context_id)
{
	return (psci_call(
	    psci_cpu_on_id, target_cpu, entry_point_address, context_id));
}

int32_t
psci_affinity_info(uint64_t target_affinity, uint32_t lowest_affinity_level)
{
	return (psci_call(
	    psci_affinity_info_id, target_affinity, lowest_affinity_level, 0));
}

int32_t
psci_migrate(uint64_t target_cpu)
{
	return (psci_call(psci_migrate_id, target_cpu, 0, 0));
}

int32_t
psci_migrate_info_type(void)
{
	return (psci_call(psci_migrate_info_type_id, 0, 0, 0));
}

uint64_t
psci_migrate_info_up_cpu(void)
{
	return (psci_call(psci_migrate_info_up_cpu_id, 0, 0, 0));
}

void
psci_system_off(void)
{
	psci_call(psci_system_off_id, 0, 0, 0);
}

void
psci_system_reset(void)
{
	psci_call(psci_system_reset_id, 0, 0, 0);
}

int32_t
psci_features(uint32_t psci_func_id)
{
	return (psci_call(psci_features_id, psci_func_id, 0, 0));
}

int32_t
psci_cpu_freeze(void)
{
	return (psci_call(psci_cpu_freeze_id, 0, 0, 0));
}

int32_t
psci_cpu_default_suspend(uint64_t entry_point_address, uint64_t context_id)
{
	return (psci_call(
	    psci_cpu_default_suspend_id, entry_point_address, context_id, 0));
}

int32_t
psci_node_hw_state(uint64_t target_cpu, uint32_t power_level)
{
	return (psci_call(psci_node_hw_state_id, target_cpu, power_level, 0));
}

int32_t
psci_system_suspend(uint64_t entry_point_address, uint64_t context_id)
{
	return (psci_call(
	    psci_system_suspend_id, entry_point_address, context_id, 0));
}

int32_t
psci_set_suspend_mode(uint32_t mode)
{
	return (psci_call(psci_set_suspend_mode_id, mode, 0, 0));
}

uint64_t
psci_stat_residency(uint64_t target_cpu, uint32_t power_state)
{
	return (psci_call(psci_stat_residency_id, target_cpu, power_state, 0));
}

uint64_t
psci_stat_count(uint64_t target_cpu, uint32_t power_state)
{
	return (psci_call(psci_stat_count_id, target_cpu, power_state, 0));
}
