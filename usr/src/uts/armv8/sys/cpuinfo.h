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

#ifndef _CPUINFO_H
#define	_CPUINFO_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/cpuvar.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CPUINFO_ENABLED				0x1
#ifdef XXXARM
/*
 * XXXARM: See the "additional fields" comment below.
 */
#define	CPIINFO_PERF_VEC_MODE			0x2
#define	CPUINFO_VGIC_VEC_MODE			0x4
#endif
#define	CPUINFO_ONLINE_CAPABLE			0x8

typedef enum {
	/*
	 * PSCI CPU_ON.
	 */
	CPUINFO_ENABLE_METHOD_PSCI		= 0,
	/*
	 * XXXARM: we need support for the parking protocol referenced in the
	 * ACPI specification (the referenced document is called
	 * "Multiprocessor Startup for ARM Platforms").
	 */
	/*
	 * U-boot style WFE spin table.
	 */
	CPUINFO_ENABLE_METHOD_SPINTABLE_SIMPLE	= 42,
} cpuinfo_enable_method_t;

struct cpuinfo {
	list_node_t		ci_list_node;
	/*
	 * CPU index, 0 is always the boot processor.
	 */
	processorid_t		ci_id;
	/*
	 * GIC CPU Interface - as specified for ACPI and derived for FDT.
	 *
	 * Derivation is aligned with edk2.
	 */
	uint32_t		ci_cpuif;
	/*
	 * CPU flags - see CPUINFO_* above.
	 * If CPUINFO_ENABLED is set, the processor is ready for use
	 * immediately and CPUINFO_ONLINE_CAPABLE should be zero.. If
	 * CPUINFO_ENABLED is clear and CPUINFO_ONLINE_CAPABLE is set, then the
	 * processor can be enabled at runtime. If both are clear the processor
	 * should be ignored.
	 */
	uint32_t		ci_flags;
	/*
	 * Implementred Parking protocol version, or 0 for PSCI.
	 *
	 * See https://uefi.org/acpi (search for "Multiprocessor Startup for
	 * ARM Platforms") for parking protocol details.
	 */
	cpuinfo_enable_method_t	ci_ppver;
	/*
	 * ACPI Processor UID - used to match this informational object to a
	 * processor object in the DSDT once the OSPM is up.
	 *
	 * Only relevant for ACPI-based systems.
	 */
	uint32_t		ci_uid;
	/*
	 * The 64-bit physical address of the processor's Parking Protocol
	 * mailbox.
	 */
	uint64_t		ci_parked_addr;
	/*
	 * The Multiprocessor Identity Register, following the formatting of
	 * the MPIDR register in the ARM architecture, but containing only the
	 * affinity bits.
	 * - Bits [63:40] Must be zero
	 * - Bits [39:32] Aff3 : Match Aff3 of target processor MPIDR
	 * - Bits [31:24] Must be zero
	 * - Bits [23:16] Aff2 : Match Aff2 of target processor MPIDR
	 * - Bits [15:8] Aff1 : Match Aff1 of target processor MPIDR
	 * - Bits [7:0] Aff0 : Match Aff0 of target processor MPIDR
	 */
	uint64_t		ci_mpidr;

	/*
	 * The following additional fields are possible in an ACPI
	 * implementation, as that is based on GICC structures in the MADT.
	 *
	 * Once GIC configuration is abstracted we'll come back and revisit
	 * what could or should be derived for the CPU structure.
	 *
	 * uint32_t ci_perfmon_vec;
	 * uint64_t ci_cpuif_addr;
	 * uint64_t ci_gicv_addr;
	 * uint64_t ci_gich_addr;
	 * uint32_t ci_vgic_vec;
	 * uint64_t ci_gicr_addr;
	 * uint8_t  ci_efficiency_class;
	 * uint16_t ci_spe_overflow_vec;
	 * uint16_t ci_trbe_vec;
	 */
};

struct xboot_info;
extern void cpuinfo_bootstrap(cpu_t *cp, struct xboot_info *xbp);

extern int cpuinfo_init(void);

extern struct cpuinfo *cpuinfo_first(void);
extern struct cpuinfo *cpuinfo_first_enabled(void);
extern struct cpuinfo *cpuinfo_next(struct cpuinfo *ci);
extern struct cpuinfo *cpuinfo_next_enabled(struct cpuinfo *ci);
extern struct cpuinfo *cpuinfo_end(void);

extern struct cpuinfo *cpuinfo_for_affinity(uint64_t affinity);

#ifdef __cplusplus
}
#endif

#endif /* _CPUINFO_H */
