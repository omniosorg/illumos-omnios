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

#ifndef _GIC_REG_H
#define	_GIC_REG_H

/*
 * Arm Generic Interrupt Controller registers
 *
 * Covers GICv2 and GICv3+.
 *
 * Where secure and non-secure versions of the registers are available we only
 * capture the non-secure versions of the registers (since we expect to run in
 * the non-secure world).
 *
 * There are 32 per-CPU interrupts, half of which are software generated and
 * the other half are for per-CPU IP blocks (such as timers). These are broken
 * down into ranges: Software Generated Interrupts (SGI) and Private Peripheral
 * Interrupts (PPI). Arm recommends that half the SGI range is reserved for use
 * by the secure world.
 *
 * We then have Shared Peripheral Interrupts. In GICv2 these run up to 1023,
 * with 1020-1023 as special interrupts.
 *
 * In a GICv3.1 implementation the interrupt space is extended significantly,
 * introducing additional space for both PPI and SPI interrupts.
 *
 * Finally, Locality-specific Peripheral Interrupts (LPI) get a separate range
 * of their own. LPI was introduced in GICv3. If LPIs are supported there will
 * be at least 8192 LPIs available.
 *
 *    0 -    7: SGI for the non-secure world
 *    8 -   15: SGI or the secure world
 *   16 -   31: PPI
 *   32 - 1019: SPI
 * 1020 - 1023: Special
 * 1056 - 1119: Extended PPI (GICv3.1+)
 * 4096 - 5119: Extended SPI (GICv3.1+)
 * 8192 -     : LPI (max is at least 16384)
 *
 * From the point of view of an operating system, special interrupt 1023
 * indicates that the interrupt acknowledge is spurious, which can happen
 * when GIC maintenance operations race with interrupt handling or when the
 * non-secure world performs an interrupt acknowledge while the highest
 * priority pending interrupt is a group 0 (secure world) interrupt.
 *
 * The SGI split (0-7 for NS, 8-15 for S) comes from IHI0048 $2.2.1 and
 * IHI0069 $2.2, where it is stated that:
 *   Arm strongly recommends that software reserves:
 *   - INTID0 - INTID7 for Non-secure interrupts.
 *   - INTID8 - INTID15 for Secure interrupts.
 *
 * It is possible (and likely) that not all INTIDs in the SPI, Extended PPI and
 * Extended SPI space are implemented. When this is the case, the documentation
 * states:
 *   Arm strongly recommends that implemented interrupts are grouped to use
 *   the lowest INTID numbers and as small a range of INTIDs as possible. This
 *   reduces the size of the associated tables in memory that must be
 *   implemented, and that discovery routines must check.
 *
 * Document references:
 * IHI0069: Arm® Generic Interrupt Controller Architecture Specification
 *          GIC architecture version 3 and version 4
 * IHI0048: ARM® Generic Interrupt Controller Architecture version 2.0
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	GIC_INTID_MIN		0
#define	GIC_INTID_SGI_MIN	0
#define	GIC_INTID_SGI_NS_MIN	0
#define	GIC_INTID_SGI_NS_MAX	7
#define	GIC_INTID_SGI_S_MIN	8
#define	GIC_INTID_SGI_S_MAX	15
#define	GIC_INTID_SGI_MAX	15
#define	GIC_INTID_PPI_MIN	16
#define	GIC_INTID_PPI_MAX	31
#define	GIC_INTID_SPI_MIN	32
#define	GIC_INTID_SPI_MAX	1019
#define	GIC_INTID_SPECIAL_MIN	1020
#define	GIC_INTID_SPURIOUS	1023
#define	GIC_INTID_SPECIAL_MAX	1023
#define	GIC_INTID_EPPI_MIN	1056
#define	GIC_INTID_EPPI_MAX	1119
#define	GIC_INTID_ESPI_MIN	4096
#define	GIC_INTID_ESPI_MAX	5119
#define	GIC_INTID_LPI_MIN	8192

#define	GIC_INTID_IS_SGI(v)	((v) <= (GIC_INTID_SGI_MAX))
#define	GIC_INTID_IS_PPI(v)	((v) >= (GIC_INTID_PPI_MIN) && \
				(v) <= (GIC_INTID_PPI_MAX))
#define	GIC_INTID_IS_SPI(v)	((v) >= (GIC_INTID_SPI_MIN) && \
				(v) <= (GIC_INTID_SPI_MAX))
#define	GIC_INTID_IS_SPECIAL(v)	((v) >= (GIC_INTID_SPECIAL_MIN) && \
				(v) <= (GIC_INTID_SPECIAL_MAX))
#define	GIC_INTID_IS_EPPI(v)	((v) >= (GIC_INTID_EPPI_MIN) && \
				(v) <= (GIC_INTID_EPPI_MAX))
#define	GIC_INTID_IS_ESPI(v)	((v) >= (GIC_INTID_ESPI_MIN) && \
				(v) <= (GIC_INTID_ESPI_MAX))
#define	GIC_INTID_IS_LPI(v)	((v) >= (GIC_INTID_LPI_MIN))
#define	GIC_INTID_IS_ANY_PPI(v)	(GIC_INTID_IS_PPI((v)) || \
				GIC_INTID_IS_EPPI((v)))
#define	GIC_INTID_IS_ANY_SPI(v)	(GIC_INTID_IS_SPI((v)) || \
				GIC_INTID_IS_ESPI((v)))
#define	GIC_INTID_IS_PERCPU(v)	((v) <= (GIC_INTID_PPI_MAX))

/*
 * GIC Distributor Interface
 */

/*
 * Distributor Control Register
 */
#define	GICD_CTLR				0x0000
#define	GICD_CTLR_RWP				0x80000000
#define	GICD_CTLR_DS				0x80000040	/* secure */
#define	GICD_CTLR_ARE_NS			0x00000010
#define	GICD_CTLR_EnableGrp1A			0x00000002
#define	GICD_CTLR_EnableGrp1			0x00000001

/*
 * Interrupt Controller Type Register
 */
#define	GICD_TYPER				0x0004
#define	GICD_TYPER_ESPI_range			0xF8000000
#define	GICD_TYPER_RSS				0x04000000
#define	GICD_TYPER_No1N				0x02000000
#define	GICD_TYPER_A3V				0x01000000
#define	GICD_TYPER_IDbits			0x00F80000
#define	GICD_TYPER_DVIS				0x00040000
#define	GICD_TYPER_LPIS				0x00020000
#define	GICD_TYPER_MBIS				0x00010000
#define	GICD_TYPER_num_LPIs			0x0000F800
/* [10] Indicates that the GIC supports two security states */
#define	GICD_TYPER_SecurityExtn			0x00000400
#define	GICD_TYPER_NMI				0x00000200
#define	GICD_TYPER_ESPI				0x00000100
#define	GICD_TYPER_CPUNumber			0x000000E0
#define	GICD_TYPER_CPUNumber_SHIFT		5
#define	GICD_TYPER_ITLinesNumber		0x0000001F
#define	GICD_TYPER_LINES(n)			MIN(((32*(((n)&0x1F)+1))-1), \
						1020)

#define	GICD_TYPER_CPUNUMBER(n)			(((n)&(GICD_TYPER_CPUNumber)) \
						>> (GICD_TYPER_CPUNumber_SHIFT))

#define	GICD_IIDR				0x0008
#define	GICD_IIDR_ProductID			0xFF000000
#define	GICD_IIDR_Variant			0x000F0000
#define	GICD_IIDR_Revision			0x0000F000
#define	GICD_IIDR_Implementer			0x00000FFF

#define	GICD_TYPER2				0x000c
#define	GICD_TYPER2_nASSGIcap			0x00000100
#define	GICD_TYPER2_VIL				0x00000080
#define	GICD_TYPER2_VID				0x0000001F

#define	GICD_STATUSR				0x0010
#define	GICD_STATUSR_WROD			0x00000008
#define	GICD_STATUSR_RWOD			0x00000004
#define	GICD_STATUSR_WRD			0x00000002
#define	GICD_STATUSR_RRD			0x00000001

#define	GICD_SETSPI_NSR				0x0040
#define	GICD_SETSPI_NSR_INTID			0x00001FFF

#define	GICD_CLRSPI_NSR				0x0048
#define	GICD_CLRSPI_NSR_INTID			0x00001FFF

#define	GICD_SETSPI_SR				0x0050
#define	GICD_SETSPI_SR_INTID			0x00001FFF

#define	GICD_CLRSPI_SR				0x0058
#define	GICD_CLRSPI_SR_INTID			0x00001FFF

#define	GICD_IGROUPRn(n)			(0x0080+(4*(n)))
#define	GICD_IGROUPR_REGNUM(v)			((v)>>5)
#define	GICD_IGROUPR_REGBIT(v)			(1U<<((v)&0x1F))

#define	GICD_ISENABLERn(n)			(0x0100+(4*(n)))
#define	GICD_ICENABLERn(n)			(0x0180+(4*(n)))
#define	GICD_IENABLER_REGNUM(v)			(GICD_IGROUPR_REGNUM((v)))
#define	GICD_IENABLER_REGBIT(v)			(GICD_IGROUPR_REGBIT((v)))

#define	GICD_ISPENDRn(n)			(0x0200+(4*(n)))
#define	GICD_ICPENDRn(n)			(0x0280+(4*(n)))
#define	GICD_IPENDR_REGNUM(v)			(GICD_IGROUPR_REGNUM((v)))
#define	GICD_IPENDR_REGBIT(v)			(GICD_IGROUPR_REGBIT((v)))

#define	GICD_ISACTIVERn(n)			(0x0300+(4*(n)))
#define	GICD_ICACTIVERn(n)			(0x0380+(4*(n)))
#define	GICD_IACTIVER_REGNUM(v)			(GICD_IGROUPR_REGNUM((v)))
#define	GICD_IACTIVER_REGBIT(v)			(GICD_IGROUPR_REGBIT((v)))

#define	GICD_IPRIORITYRn(n)			(0x0400+(4*(n)))
#define	GICD_IPRIORITY_REGMASK			0xff
#define	GICD_IPRIORITY_REGNUM(n)		((n) >> 2)
#define	GICD_IPRIORITY_REGVAL(n, v)		(((v) & 0xff) << \
						(((n) & 0x3) << 3))
#define	GICD_IPRIORITY_SETPRIO(val, n, v)	(((val) & \
						~(GICD_IPRIORITY_REGVAL((n), \
						0xFF))) | \
						(GICD_IPRIORITY_REGVAL((n), \
						(v))))
/*
 * When GICv3 has a single security state the minimum required number of bits
 * of priority is 4, yielding 16 priority levels (240-0 in steps of 16).
 *
 * When GICv3 supports two security states the minimum required number of bits
 * of priority is 5, yielding 32 priority levels (248-0 in steps of 8), but
 * priorities with the top bit (0x80) clear are reserved for the secure world.
 * This leaves 16 priority levels (248-128 in steps of 8) available for the
 * non-secure world, which is exactly what we need.
 *
 * When we have only four bits of priority, use GIC_IPL_TO_PRIO16 to calculate
 * priority values from IPL values. When five or more bits are available, use
 * GIC_IPL_TO_PRIO.
 *
 * See §4.8 Interrupt Prioritization.
 *
 * GICv2 implementations use a lookup table approach to deriving PMR and
 * interrupt priority values from IPL, since v2 might have only 16 priority
 * levels when supporting two security states. In this case, sub-priority bits
 * are used to prioritise interrupts delivery, while the priority mask is more
 * coarse-grained than we'd like (as only 8 levels are available to the
 * non-secure world).
 */
#define	GIC_IPL_TO_PRIO(ipl)			(0xF8 - ((ipl) << 3))
#define	GIC_IPL_TO_PRIO16(ipl)			(0xF0 - ((ipl) << 4))

#define	GICD_ITARGETSRn(n)			(0x0800+(4*(n)))
#define	GICD_ITARGETSR_REGMASK			0xFF
#define	GICD_ITARGETSR_REGNUM(n)		((n) >> 2)
#define	GICD_ITARGETSR_REGVAL(n, v)		(((v) & 0xff) << \
						(((n) & 0x3) << 3))
#define	GICD_ITARGETSR_SETTARGETS(val, n, v)	(((val) & \
						~(GICD_ITARGETSR_REGVAL((n), \
						0xFF))) | \
						(GICD_ITARGETSR_REGVAL((n), \
						(v))))

#define	GICD_ICFGRn(n)				(0x0c00+(4*(n)))
#define	GICD_ICFGR_INT_CONFIG_MASK		0x3
#define	GICD_ICFGR_INT_CONFIG_LEVEL		0x0
#define	GICD_ICFGR_INT_CONFIG_EDGE		0x2
#define	GICD_ICFGR_REGNUM(irq)			((irq) >> 4)
#define	GICD_ICFGR_REGOFF(irq)			(((irq) & 0xf) << 1)
#define	GICD_ICFGR_REGVAL(irq, v)		(((v) & 0x3) << \
						(((irq) & 0xf) << 1))
#define	GICD_ICFGR_SETVAL(val, irq, v)		(((val) & \
						~(GICD_ICFGR_REGVAL((irq), \
						(GICD_ICFGR_INT_CONFIG_MASK))))\
						| (GICD_ICFGR_REGVAL((irq), \
						(v))))

/* GICv3+ only */
#define	GICD_IGRPMODRn(n)			(0x0d00+(4*(n)))

#define	GICD_NSACRn(n)				(0x0e00+(4*(n)))

#define	GICD_SGIR				0x0f00
#define	GICD_SGIR_TargetListFilter		0x03000000
#define	GICD_SGIR_TargetListSpecified		0x0
#define	GICD_SGIR_TargetListAllButMe		0x1
#define	GICD_SGIR_TargetListOnlyMe		0x2
#define	GICD_SGIR_TargetListReserved		0x3
#define	GICD_SGIR_TargetList_MASK		0x3
#define	GICD_SGIR_TargetList_SHIFT		24
#define	GICD_SGIR_CPUTargetList			0x00FF0000
#define	GICD_SGIR_CPUTargetList_MASK		0xFF
#define	GICD_SGIR_CPUTargetList_SHIFT		16
/*
 * This field is writable only by a Secure access. Any Non-secure write to the
 * GICD_SGIR generates an SGI only if the specified SGI is programmed as
 * Group 1, regardless of the value of bit[15] of the write.
 */
#define	GICD_SGIR_NSATT				0x00008000
#define	GICD_SGIR_NSATT_MASK			0x1
#define	GICD_SGIR_NSATT_SHIFT			15
#define	GICD_SGIR_INTID				0x0000000F
#define	GICD_SGIR_INTID_MASK			0xF
#define	GICD_SGIR_INTID_SHIFT			0

/*
 * Make the target list component of the software generated interrupt register.
 */
#define	GICD_MAKE_SGIR_TLF(f)			(((f) & \
						(GICD_SGIR_TargetList_MASK)) \
						<< (GICD_SGIR_TargetList_SHIFT))
/*
 * Make the CPU target list component of the software generated interrupt
 * register.
 */
#define	GICD_MAKE_SGIR_CTL(t)			(((t) & \
						(GICD_SGIR_CPUTargetList_MASK))\
						<< \
						(GICD_SGIR_CPUTargetList_SHIFT))
/*
 * Make the non-secure attribute component of the software generated interrupt
 * register.
 */
#define	GICD_MAKE_SGIR_NSATT(n)			(((n) & (GICD_SGIR_NSATT_MASK))\
						<< (GICD_SGIR_NSATT_SHIFT))
/*
 * Make the INTID component of the software generated interrupt register.
 */
#define	GICD_MAKE_SGIR_INTID(i)			((i) & (GICD_SGIR_INTID_MASK))
/*
 * Create the register value to write to the software generated interrupt
 * register.
 */
#define	GICD_MAKE_SGIR_REGVAL(f, t, n, i)	((GICD_MAKE_SGIR_TLF((f))) | \
						(GICD_MAKE_SGIR_CTL((t))) | \
						(GICD_MAKE_SGIR_NSATT((n))) | \
						(GICD_MAKE_SGIR_INTID((i))))

#define	GICD_CPENDSGIRn(n)			(0x0f10+(4*(n)))
#define	GICD_SPENDSGIRn(n)			(0x0f20+(4*(n)))

/* GICv3+ only (until GICD_PIDR2) */
#define	GICD_INMIRn(n)				(0x0f80+(4*(n)))
#define	GICD_IGROUPRnE(n)			(0x1000+(4*(n)))
#define	GICD_ISENABLERnE(n)			(0x1200+(4*(n)))
#define	GICD_ICENABLERnE(n)			(0x1400+(4*(n)))
#define	GICD_ISPENDRnE(n)			(0x1600+(4*(n)))
#define	GICD_ICPENDRnE(n)			(0x1800+(4*(n)))
#define	GICD_ISACTIVERnE(n)			(0x1a00+(4*(n)))
#define	GICD_ICACTIVERnE(n)			(0x1c00+(4*(n)))
#define	GICD_IPRIORITYRnE(n)			(0x2000+(4*(n)))
#define	GICD_ICFGRnE(n)				(0x3000+(4*(n)))
#define	GICD_IGRPMODRnE(n)			(0x3400+(4*(n)))
#define	GICD_NSACRnE(n)				(0x3600+(4*(n)))
#define	GICD_INMIRnE(n)				(0x3b00+(4*(n)))

#define	GICD_IROUTERn(n)			(0x6100+(8*(n)))
#define	GICD_IROUTERnE(n)			(0x8000+(8*(n)))
#define	GICD_IROUTER_Interrupt_Routing_Mode	0x0000000080000000

#define	GICD_PIDR2				0xffe8
#define	GICD_PIDR2_ArchRev			0x000000F0

/*
 * GIC Redistributor Interface
 *
 * The redistributor was introduced in GICv3.
 */
#define	GICR_CTLR				0x0000
#define	GICR_CTLR_UWP				0x80000000
#define	GICR_CTLR_DPG1S				0x04000000
#define	GICR_CTLR_DPG1NS			0x02000000
#define	GICR_CTLR_DPG0				0x01000000
#define	GICR_CTLR_RWP				0x00000008
#define	GICR_CTLR_IR				0x00000004
#define	GICR_CTLR_CES				0x00000002
#define	GICR_CTLR_EnableLPIs			0x00000001

#define	GICR_IIDR				0x0004
#define	GICR_IIDR_ProductID			0xFF000000
#define	GICR_IIDR_Variant			0x000F0000
#define	GICR_IIDR_Revision			0x0000F000
#define	GICR_IIDR_Implementer			0x00000FFF

#define	GICR_TYPER				0x0008
#define	GICR_TYPER_Affinity_Value		0xFFFFFFFF00000000
#define	GICR_TYPER_Affinity_Value_Aff3		0xFF00000000000000
#define	GICR_TYPER_Affinity_Value_Aff2		0x00FF000000000000
#define	GICR_TYPER_Affinity_Value_Aff1		0x0000FF0000000000
#define	GICR_TYPER_Affinity_Value_Aff0		0x000000FF00000000
#define	GICR_TYPER_PPInum			0xF8000000
#define	GICR_TYPER_VSGI				0x04000000
#define	GICR_TYPER_CommonLPIAff			0x03000000
#define	GICR_TYPER_Processor_Number		0x00FFFF00
#define	GICR_TYPER_RVPEID			0x00000080
#define	GICR_TYPER_MPAM				0x00000040
#define	GICR_TYPER_DPGS				0x00000020
#define	GICR_TYPER_Last				0x00000010
#define	GICR_TYPER_DirectLPI			0x00000008
#define	GICR_TYPER_Dirty			0x00000004
#define	GICR_TYPER_VLPIS			0x00000002
#define	GICR_TYPER_PLPIS			0x00000001

/*
 * Transform a redistributor typer affinity value to a normalized affinity
 * value.
 *
 * In GICR_TYPER the affinity 3-0 values are in bits [63:32], while the
 * normalized format has them in bits [31:0], so just mask them out and shift
 * them into place.
 */
#define	AFF_GICR_TYPER_TO_PACKED(v)		(((v) & \
						(GICR_TYPER_Affinity_Value)) \
						>> 32)

#define	GICR_STATUSR				0x0010
#define	GICR_STATUSR_WROD			0x00000008
#define	GICR_STATUSR_RWOD			0x00000004
#define	GICR_STATUSR_WRD			0x00000002
#define	GICR_STATUSR_RRD			0x00000001

#define	GICR_WAKER				0x0014
#define	GICR_WAKER_ChildrenAsleep		0x00000004
#define	GICR_WAKER_ProcessorSleep		0x00000002

#define	GICR_MPAMIDR				0x0018
#define	GICR_MPAMIDR_PMGmax			0x00FF0000
#define	GICR_MPAMIDR_PARTIDmax			0x0000FFFF

#define	GICR_PARTIDR				0x001c
#define	GICR_PARTIDR_PMG			0x00FF0000
#define	GICR_PARTIDR_PARTID			0x0000FFFF

#define	GICR_SETLPIR				0x0040
#define	GICR_SETLPIR_pINTID			0xffffffff

#define	GICR_CLRLPIR				0x0048
#define	GICR_CLRLPIR_pINTID			0xffffffff

#define	GICR_PROPBASER				0x0070
#define	GICR_PROPBASER_OuterCache		0x0700000000000000
#define	GICR_PROPBASER_Physical_Address		0x000FFFFFFFFFF000
#define	GICR_PROPBASER_Shareability		0x0000000000000C00
#define	GICR_PROPBASER_InnerCache		0x0000000000000380
#define	GICR_PROPBASER_IDbits			0x000000000000001F

#define	GICR_PENDBASER				0x0078
#define	GICR_PENDBASER_PTZ			0x4000000000000000
#define	GICR_PENDBASER_OuterCache		0x0700000000000000
#define	GICR_PENDBASER_Physical_Address		0x000FFFFFFFFF0000
#define	GICR_PENDBASER_Shareability		0x0000000000000C00
#define	GICR_PENDBASER_InnerCache		0x0000000000000380

#define	GICR_INVLPIR				0x00a0
#define	GICR_INVLPIR_V				0x8000000000000000
#define	GICR_INVLPIR_vPEID			0x0000FFFF00000000
#define	GICR_INVLPIR_INTID			0x00000000FFFFFFFF

#define	GICR_INVALLR				0x00b0
#define	GICR_INVALLR_V				0x8000000000000000
#define	GICR_INVALLR_vPEID			0x0000FFFF00000000

#define	GICR_SYNCR				0x00c0
#define	GICR_SYNCR_Busy				0x00000001

#define	GICR_PIDR2				0xffe8
#define	GICR_PIDR2_ArchRev			0x000000F0

#define	GICR_IGROUPR0				0x0080
#define	GICR_IGROUPRnE(n)			(0x0084+(4*(n)))

#define	GICR_ISENABLER0				0x0100
#define	GICR_IENABLER_REGBIT(v)			(GICD_IENABLER_REGBIT((v)))

#define	GICR_ISENABLERnE(n)			(0x0104+(4*(n)))
#define	GICR_ICENABLERnE(n)			(0x0184+(4*(n)))
#define	GICR_ICENABLER0				0x0180
#define	GICR_ISPENDR0				0x0200
#define	GICR_ISPENDRnE(n)			(0x0204+(4*(n)))
#define	GICR_ICPENDR0				0x0280
#define	GICR_ICPENDRnE(n)			(0x0284+(4*(n)))
#define	GICR_ISACTIVER0				0x0300
#define	GICR_ISACTIVERnE(n)			(0x0304+(4*(n)))
#define	GICR_ICACTIVER0				0x0380
#define	GICR_ICACTIVERnE(n)			(0x0384+(4*(n)))

#define	GICR_IPRIORITYRn(n)			(0x0400+(4*(n)))
#define	GICR_IPRIORITY_REGMASK			GICD_IPRIORITY_REGMASK
#define	GICR_IPRIORITY_REGNUM(n)		(GICD_IPRIORITY_REGNUM((n)))
#define	GICR_IPRIORITY_REGVAL(n, v)		(GICD_IPRIORITY_REGVAL((n), \
						(v)))

#define	GICR_IPRIORITYRnE(n)			(0x0420+(4*(n)))

#define	GICR_ICFGR0				0x0c00
#define	GICR_ICFGR1				0x0c04
#define	GICR_ICFGRn(n)				((GICR_ICFGR0)+(4*(n)))
#define	GICR_ICFGR_REGVAL(irq, v)		(GICD_ICFGR_REGVAL((irq), (v)))
#define	GICR_ICFGR_INT_CONFIG_MASK		GICD_ICFGR_INT_CONFIG_MASK
#define	GICR_ICFGR_INT_CONFIG_LEVEL		GICD_ICFGR_INT_CONFIG_LEVEL
#define	GICR_ICFGR_INT_CONFIG_EDGE		GICD_ICFGR_INT_CONFIG_EDGE

#define	GICR_ICFGRnE(n)				(0x0c08+(4*(n)))
#define	GICR_IGRPMODR0				0x0d00
#define	GICR_IGRPMODRnE(n)			(0x0d04+(4*(n)))
#define	GICR_NSACR				0x0e00
#define	GICR_INMIR0				0x0f80
#define	GICR_INMIRnE(n)				(0x0f84+(4*(n)))

#define	GICR_VPROPBASER				0x0070
#define	GICR_VPROPBASER_OuterCache		0x0700000000000000
#define	GICR_VPROPBASER_Physical_Address	0x000FFFFFFFFFF000
#define	GICR_VPROPBASER_Shareability		0x0000000000000C00
#define	GICR_VPROPBASER_InnerCache		0x0000000000000380
#define	GICR_VPROPBASER_IDbits			0x000000000000001F

#define	GICR_VPENDBASER				0x0078
/* Both FEAT_GICv4 and FEAT_GICv4p1 */
#define	GICR_VPENDBASER_Valid			0x8000000000000000
/* FEAT_GICv4 only */
#define	GICR_VPENDBASER_IDAI			0x4000000000000000
/* FEAT_GICv4p1 only */
#define	GICR_VPENDBASER_Doorbell		0x4000000000000000
/* Both FEAT_GICv4 and FEAT_GICv4p1 */
#define	GICR_VPENDBASER_PendingLast		0x2000000000000000
/* Both FEAT_GICv4 and FEAT_GICv4p1 */
#define	GICR_VPENDBASER_Dirty			0x1000000000000000
/* FEAT_GICv4p1 only */
#define	GICR_VPENDBASER_VGrp0En			0x0800000000000000
/* FEAT_GICv4p1 only */
#define	GICR_VPENDBASER_VGrp1En			0x0400000000000000
/* FEAT_GICv4 only */
#define	GICR_VPENDBASER_OuterCache		0x0700000000000000
/* FEAT_GICv4 only */
#define	GICR_VPENDBASER_Physical_Address	0x000FFFFFFFFF0000
/* FEAT_GICv4 only */
#define	GICR_VPENDBASER_Shareability		0x0000000000000C00
/* FEAT_GICv4 only */
#define	GICR_VPENDBASER_InnerCache		0x0000000000000380
/* FEAT_GICv4p1 only */
#define	GICR_VPENDBASER_vPEID			0x000000000000FFFF

#define	GICR_VSGIR				0x0080
#define	GICR_VSGIR_vPEID			0x0000FFFF

#define	GICR_VSGIPENDR				0x0088
#define	GICR_VSGIPENDR_Busy			0x80000000
#define	GICR_VSGIPENDR_Pending			0x0000FFFF

/*
 * GIC CPU Interface
 *
 * On GICv3 platforms these are commonly accesswed via the System Register
 * interface, but on GICv2 they are accessed via the MMIO interface.
 */

/*
 * CPU Interface Control Register
 */
#define	GICC_CTLR				0x0000
/* [9] if set EOI does priority drop and DIR is needed for deactivation */
#define	GICC_CTLR_EOImodeNS			0x00000200
#define	GICC_CTLR_IRQBypDisGrp1			0x00000040
#define	GICC_CTLR_FIQBypDisGrp1			0x00000020
/* [0] Enable signalling of group 1 interrupts to the PE */
#define	GICC_CTLR_EnableGrp1			0x00000001

#define	GICC_PMR				0x0004
/* If this bit is set the priority applies to non-secure accesses */
#define	GICC_PMR_NONSECURE			0x00000080
#define	GICC_PMR_Priority			0x000000FF

#define	GICC_BPR				0x0008
#define	GICC_BPR_Binary_Point			0x00000007

#define	GICC_IAR				0x000c
#define	GICC_IAR_CPUID				0x00001C00
#define	GICC_IAR_CPUID_MASK			0x00000007
#define	GICC_IAR_CPUID_SHIFT			10
#define	GICC_IAR_INTID_NO_ARE			0x000003FF
#define	GICC_IAR_INTID_NO_ARE_MASK		0x000003FF
#define	GICC_IAR_INTID_NO_ARE_SHIFT		0
#define	GICC_IAR_INTID				0x00FFFFFF
#define	GICC_IAR_INTID_MASK			0x00FFFFFF
#define	GICC_IAR_INTID_SHIFT			0

#define	GICC_EOIR				0x0010
#define	GICC_EOIR_INTID				0x00FFFFFF

#define	GICC_RPR				0x0014
#define	GICC_RPR_Priority			0x000000FF

#define	GICC_HPPIR				0x0018
#define	GICC_HPPIR_INTID			0x00FFFFFF

#define	GICC_ABPR				0x001c
#define	GICC_ABPR_Binary_Point			0x00000007

#define	GICC_AIAR				0x0020
#define	GICC_AIAR_INTID				0x00FFFFFF

#define	GICC_AEOIR				0x0024
#define	GICC_AEOIR_INTID			0x00FFFFFF

#define	GICC_AHPPIR				0x0028
#define	GICC_AHPPIR_INTID			0x00FFFFFF

/* GICv3+ only */
#define	GICC_STATUSR				0x002c
#define	GICC_STATUSR_ASV			0x00000010
#define	GICC_STATUSR_WROD			0x00000008
#define	GICC_STATUSR_RWOD			0x00000004
#define	GICC_STATUSR_WRD			0x00000002
#define	GICC_STATUSR_RRD			0x00000001

#define	GICC_APRn(n)				(0x00d0+(4*(n)))
#define	GICC_NSAPRn(n)				(0x00e0+(4*(n)))

#define	GICC_IIDR				0x00fc
#define	GICC_IIDR_ProductID			0xFF000000
#define	GICC_IIDR_Architecture_version		0x000F0000
#define	GICC_IIDR_Revision			0x0000F000
#define	GICC_IIDR_Implementer			0x00000FFF

#define	GICC_DIR				0x1000
#define	GICC_DIR_INTID				0x00FFFFFF

/*
 * GIC System Register CPU Interface
 *
 * The System Register interface was introduced with GICv3.
 */
#define	ICC_CTLR_EL1_ExtRange			0x0000000000080000
#define	ICC_CTLR_EL1_RSS			0x0000000000040000
#define	ICC_CTLR_EL1_A3V			0x0000000000008000
#define	ICC_CTLR_EL1_SEIS			0x0000000000004000
#define	ICC_CTLR_EL1_IDbits			0x0000000000003800
#define	ICC_CTLR_EL1_PRIbits			0x0000000000000700
#define	ICC_CTLR_EL1_PMHE			0x0000000000000040
#define	ICC_CTLR_EL1_EOImode			0x0000000000000002
#define	ICC_CTLR_EL1_CBPR			0x0000000000000001

/*
 * ICC_CTLR_EL1.PRIbits contains the number of bits of priority supported, less
 * one.
 */
#define	ICC_CTLR_NUM_PRI_BITS(v)		((((v) & \
						(ICC_CTLR_EL1_PRIbits)) >> 8) \
						+ 1)

#define	ICC_SGI0R_EL1_Aff3			0x00ff000000000000
#define	ICC_SGI0R_EL1_RS			0x0000f00000000000
#define	ICC_SGI0R_EL1_IRM			0x0000010000000000
#define	ICC_SGI0R_EL1_Aff2			0x000000ff00000000
#define	ICC_SGI0R_EL1_INTID			0x000000000f000000
#define	ICC_SGI0R_EL1_Aff1			0x0000000000ff0000
#define	ICC_SGI0R_EL1_TargetList		0x000000000000ffff

#define	ICC_SGI1R_EL1_Aff3			0x00ff000000000000
#define	ICC_SGI1R_EL1_RS			0x0000f00000000000
#define	ICC_SGI1R_EL1_IRM			0x0000010000000000
#define	ICC_SGI1R_EL1_Aff2			0x000000ff00000000
#define	ICC_SGI1R_EL1_INTID			0x000000000f000000
#define	ICC_SGI1R_EL1_Aff1			0x0000000000ff0000
#define	ICC_SGI1R_EL1_TargetList		0x000000000000ffff

/*
 * Transform a normalized affinity value (affinity 3-0 in bits [31:0]) to a
 * software generated interrupt routing format. The SGI routing format is:
 * [55:48]: Aff3
 * [47:44]: RS (this is Aff0/16)
 * [39:32]: Aff2
 * [27:24]: INTID (filled in later)
 * [23:16]: Aff1
 * [15:0] : TargetList (this has bit Aff0%16 set)
 *
 * TargetList has a set bit for the value of Aff0 MOD 16. This is scaled by
 * the value of RS (range selector) using the formula:
 *   TARGET = (RS*16)+BITPOS
 * This approach means that a single SGI register write can target up to 16
 * CPUs, with value ranges in sets of 16 (0-15, 16-31, ..., 240-255).
 */
#define	AFF_PACKED_TO_ICC_SGInR_EL1(v)			\
	((((v) & 0x00000000FF000000ul) << 24) |		\
	((((v) & 0x00000000000000FFul) >> 4) << 44) |	\
	(((v) & 0x0000000000FF0000ul) << 16) |		\
	(((v) & 0x000000000000FF00ul) << 8) |		\
	(1UL << ((v) & 0x000000000000000F)))
/*
 * Transform an INTID (interrupt vector) to a value suitable for ORing into
 * an SGI trigger write.
 *
 * The vector is typically a (signed) integer, but is cast to an unsigned value
 * here.
 */
#define	ICC_SGInR_EL1_MAKE_INTID(v)		(((uint64_t)((v) & 0xF)) << 24)
/*
 * Check whether the range selector field of an SGI trigger value has been set.
 *
 * When ICC_CTLR_EL1.RSS=0 a write to ICC_SGInR_EL1 can only write zeroes
 * to the RS field (limiting Aff0 values to 0-15).
 */
#define	ICC_SGInR_EL1_HAS_RS(v)			(((v) & (0xFul << 44)) != 0)

#define	ICC_SRE_EL1_DIB				0x0000000000000004
#define	ICC_SRE_EL1_DFB				0x0000000000000002
#define	ICC_SRE_EL1_SRE				0x0000000000000001

#define	ICC_SRE_EL2_EN				(1U << 3)
#define	ICC_SRE_EL2_SRE				(1U << 0)

#define	ICC_IGRPEN0_EL1_Enable			0x0000000000000001

#define	ICC_IGRPEN1_EL1_Enable			0x0000000000000001

#define	ICC_IAR1_INTID				0x0000000000FFFFFF

/*
 * GIC Virtual CPU Interface
 */
#define	GICV_CTLR				0x0000
#define	GICV_CTLR_EOImode			0x00000200
#define	GICV_CTLR_CBPR				0x00000010
#define	GICV_CTLR_FIQEn				0x00000008
#define	GICV_CTLR_AckCtl			0x00000004
#define	GICV_CTLR_EnableGrp1			0x00000002
#define	GICV_CTLR_EnableGrp0			0x00000001

#define	GICV_PMR				0x0004
#define	GICV_PMR_Priority			0x000000FF

#define	GICV_BPR				0x0008
#define	GICV_BPR_Binary_Point			0x00000007

#define	GICV_IAR				0x000c
#define	GICV_IAR_INTID				0x00FFFFFF

#define	GICV_EOIR				0x0010
#define	GICV_EOIR_INTID				0x00FFFFFF

#define	GICV_RPR				0x0014
#define	GICV_RPR_Priority			0x000000FF

#define	GICV_HPPIR				0x0018
#define	GICV_HPPIR_INTID			0x00FFFFFF

#define	GICV_ABPR				0x001c
#define	GICV_ABPR_Binary_Point			0x00000007

#define	GICV_AIAR				0x0020
#define	GICV_AIAR_INTID				0x00FFFFFF

#define	GICV_AEOIR				0x0024
#define	GICV_AEOIR_INTID			0x00FFFFFF

#define	GICV_AHPPIR				0x0028
#define	GICV_AHPPIR_INTID			0x00FFFFFF

#define	GICV_STATUSR				0x002c
#define	GICV_STATUSR_WROD			0x00000008
#define	GICV_STATUSR_RWOD			0x00000004
#define	GICV_STATUSR_WRD			0x00000002
#define	GICV_STATUSR_RRD			0x00000001

#define	GICV_APRn(n)				(0x00d0+(4*(n)))

#define	GICV_IIDR				0x00fc
#define	GICC_IIDR_ProductID			0xFF000000
#define	GICC_IIDR_Architecture_version		0x000F0000
#define	GICC_IIDR_Revision			0x0000F000
#define	GICC_IIDR_Implementer			0x00000FFF

#define	GICV_DIR				0x1000
#define	GICV_DIR_INTID				0x00FFFFFF

/*
 * GIC Virtual Interface Control
 */
#define	GICH_HCR				0x0000
#define	GICH_HCR_EOICount			0xF8000000
#define	GICH_HCR_VGrp1DIE			0x00000080
#define	GICH_HCR_VGrp1EIE			0x00000040
#define	GICH_HCR_VGrp0DIE			0x00000020
#define	GICH_HCR_VGrp0EIE			0x00000010
#define	GICH_HCR_NPIE				0x00000008
#define	GICH_HCR_LRENPIE			0x00000004
#define	GICH_HCR_UIE				0x00000002
#define	GICH_HCR_En				0x00000001

#define	GICH_VTR				0x0004
#define	GICH_VTR_PRIbits			0xE0000000
#define	GICH_VTR_PREbits			0x1C000000
#define	GICH_VTR_IDbits				0x03800000
#define	GICH_VTR_SEIS				0x00400000
#define	GICH_VTR_A3V				0x00200000
#define	GICH_VTR_ListRegs			0x0000001F

#define	GICH_VMCR				0x0008
#define	GICH_VMCR_VPMR				0xFF000000
#define	GICH_VMCR_VBPR0				0x00E00000
#define	GICH_VMCR_VBPR1				0x001C0000
#define	GICH_VMCR_VEOIM				0x00000200
#define	GICH_VMCR_VCBPR				0x00000010
#define	GICH_VMCR_VFIQEn			0x00000008
#define	GICH_VMCR_VAckCtl			0x00000004
#define	GICH_VMCR_VENG1				0x00000002
#define	GICH_VMCR_VENG0				0x00000001

#define	GICH_MISR				0x0010
#define	GICH_MISR_VGrp1D			0x00000080
#define	GICH_MISR_VGrp1E			0x00000040
#define	GICH_MISR_VGrp0D			0x00000020
#define	GICH_MISR_VGrp0E			0x00000010
#define	GICH_MISR_NP				0x00000008
#define	GICH_MISR_LRENP				0x00000004
#define	GICH_MISR_U				0x00000002
#define	GICH_MISR_EOI				0x00000001

#define	GICH_EISR				0x0020
#define	GICH_ELRSR				0x0030
#define	GICH_APRn(n)				(0x00f0+(4*(n)))

#define	GICH_LRn(n)				(0x0100+(4*(n)))
#define	GICH_LRn_HW				0x80000000
#define	GICH_LRn_Group				0x40000000
#define	GICH_LRn_State				0x30000000
#define	GICH_LRn_Priority			0x0F800000
#define	GICH_LRn_pINTID				0x000FFC00
#define	GICH_LRn_vINTID				0x000003FF

/*
 * GIC Interrupt Translation Service Interface
 *
 * The ITS was introduced with GICv3.
 */
#define	GITS_CTLR				0x0000
#define	GITS_CTLR_Quiescent			0x80000000
#define	GITS_CTLR_UMSIirq			0x00000100
#define	GITS_CTLR_ITS_Number			0x000000F0
#define	GITS_CTLR_ImDe				0x00000002
#define	GITS_CTLR_Enabled			0x00000001

#define	GITS_IIDR				0x0004
#define	GITS_IIDR_ProductID			0xFF000000
#define	GITS_IIDR_Variant			0x000F0000
#define	GITS_IIDR_Revision			0x0000F000
#define	GITS_IIDR_Implementer			0x00000FFF

#define	GITS_TYPER				0x0008
#define	GITS_TYPER_INV				0x0000400000000000
#define	GITS_TYPER_UMSIirq			0x0000200000000000
#define	GITS_TYPER_UMSI				0x0000100000000000
#define	GITS_TYPER_nID				0x0000080000000000
#define	GITS_TYPER_SVPET			0x0000060000000000
#define	GITS_TYPER_VMAPP			0x0000010000000000
#define	GITS_TYPER_VSGI				0x0000008000000000
#define	GITS_TYPER_MPAM				0x0000004000000000
#define	GITS_TYPER_VMOVP			0x0000002000000000
#define	GITS_TYPER_CIL				0x0000001000000000
#define	GITS_TYPER_CIDbits			0x0000000F00000000
#define	GITS_TYPER_HCC				0x00000000FF000000
#define	GITS_TYPER_PTA				0x0000000000080000
#define	GITS_TYPER_SEIS				0x0000000000040000
#define	GITS_TYPER_Devbits			0x000000000003E000
#define	GITS_TYPER_ID_bits			0x0000000000001F00
#define	GITS_TYPER_ITT_entry_size		0x00000000000000F0
#define	GITS_TYPER_CCT				0x0000000000000004
#define	GITS_TYPER_Virtual			0x0000000000000002
#define	GITS_TYPER_Physical			0x0000000000000001

#define	GITS_MPAMIDR				0x0010
#define	GITS_MPAMIDR_PMGmax			0x00FF0000
#define	GITS_MPAMIDR_PARTIDmax			0x0000FFFF

#define	GITS_PARTIDR				0x0014
#define	GITS_PARTIDR_PMG			0x00FF0000
#define	GITS_PARTIDR_PARTID			0x0000FFFF

#define	GITS_MPIDR				0x0018
#define	GITS_MPIDR_Affinity			0xFFFFFF00
#define	GITS_MPIDR_Affinity_Aff3		0xFF000000
#define	GITS_MPIDR_Affinity_Aff2		0x00FF0000
#define	GITS_MPIDR_Affinity_Aff1		0x0000FF00

#define	GITS_STATUSR				0x0040
#define	GITS_STATUSR_Syndrome			0x000003C0
#define	GITS_STATUSR_Overflow			0x00000020
#define	GITS_STATUSR_UMSI			0x00000010
#define	GITS_STATUSR_WROD			0x00000008
#define	GITS_STATUSR_RWOD			0x00000004
#define	GITS_STATUSR_WRD			0x00000002
#define	GITS_STATUSR_RRD			0x00000001

#define	GITS_UMSIR				0x0048
#define	GITS_UMSIR_DeviceID			0xFFFFFFFF00000000
#define	GITS_UMSIR_EventID			0x00000000FFFFFFFF

#define	GITS_CBASER				0x0080
#define	GITS_CBASER_Valid			0x8000000000000000
#define	GITS_CBASER_InnerCache			0x3800000000000000
#define	GITS_CBASER_OuterCache			0x00E0000000000000
#define	GITS_CBASER_Physical_Address		0x000FFFFFFFFFF000
#define	GITS_CBASER_Shareability		0x0000000000000C00
#define	GITS_CBASER_Size			0x00000000000000FF

#define	GITS_CWRITER				0x0088
#define	GITS_CWRITER_Offset			0x00000000000FFFE0
#define	GITS_CWRITER_Retry			0x0000000000000001

#define	GITS_CREADR				0x0090
#define	GITS_CREADR_Offset			0x00000000000FFFE0
#define	GITS_CREADR_Stalled			0x0000000000000001

#define	GITS_BASERn(n)				(0x0100+(4*(n)))
#define	GITS_BASERn_Valid			0x8000000000000000
#define	GITS_BASERn_Indirect			0x4000000000000000
#define	GITS_BASERn_InnerCache			0x3800000000000000
#define	GITS_BASERn_Type			0x0700000000000000
#define	GITS_BASERn_OuterCache			0x00E0000000000000
#define	GITS_BASERn_Entry_Size			0x001F000000000000
#define	GITS_BASERn_Physical_Address		0x0000FFFFFFFFF000
#define	GITS_BASERn_Shareability		0x0000000000000C00
#define	GITS_BASERn_Page_Size			0x0000000000000300
#define	GITS_BASERn_Size			0x00000000000000FF

#define	GITS_PIDR2				0xffe8
#define	GITS_PIDR2_ArchRev			0x000000F0

#ifdef __cplusplus
}
#endif

#endif /* _GIC_REG_H */
