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

#ifndef _SYS_CONTROLREGS_H
#define	_SYS_CONTROLREGS_H

#if !defined(_ASM)
#include <sys/bitext.h>
#include <sys/types.h>
#include <asm/controlregs.h>

/*
 * System Control Register (EL2)
 */
#define	SCTLR_EL2_TIDCP		(0x1ul << 63)
#define	SCTLR_EL2_SPINTMASK	(0x1ul << 62)
#define	SCTLR_EL2_NMI		(0x1ul << 61)
#define	SCTLR_EL2_EnTP2		(0x1ul << 60)
#define	SCTLR_EL2_TCSO		(0x1ul << 59)
#define	SCTLR_EL2_TCSO0		(0x1ul << 58)
#define	SCTLR_EL2_EPAN		(0x1ul << 57)
#define	SCTLR_EL2_EnALS		(0x1ul << 56)
#define	SCTLR_EL2_EnAS0		(0x1ul << 55)
#define	SCTLR_EL2_EnASR		(0x1ul << 54)
#define	SCTLR_EL2_TME		(0x1ul << 53)
#define	SCTLR_EL2_TME0		(0x1ul << 52)
#define	SCTLR_EL2_TMT		(0x1ul << 51)
#define	SCTLR_EL2_TMT0		(0x1ul << 50)
#define	SCTLR_EL2_TWEDEL	(0xful << 46)
#define	SCTLR_EL2_TWEDEn	(0x1ul << 45)
#define	SCTLR_EL2_DSSBS		(0x1ul << 44)
#define	SCTLR_EL2_ATA		(0x1ul << 43)
#define	SCTLR_EL2_ATA0		(0x1ul << 42)
#define	SCTLR_EL2_TCF		(0x3ul << 40)
#define	SCTLR_EL2_TCF0		(0x3ul << 38)
#define	SCTLR_EL2_ITFSB		(0x1ul << 37)
#define	SCTLR_EL2_BT		(0x1ul << 36)
#define	SCTLR_EL2_BT0		(0x1ul << 35)
#define	SCTLR_EL2_EnFPM		(0x1ul << 34)
#define	SCTLR_EL2_MSCEn		(0x1ul << 33)
#define	SCTLR_EL2_CMOW		(0x1ul << 32)
#define	SCTLR_EL2_EnIA		(0x1ul << 31)
#define	SCTLR_EL2_EnIB		(0x1ul << 30)
#define	SCTLR_EL2_LSMAOE	(0x1ul << 29)
#define	SCTLR_EL2_nTLSMD	(0x1ul << 28)
#define	SCTLR_EL2_EnDA		(0x1ul << 27)
#define	SCTLR_EL2_UCI		(0x1ul << 26)
#define	SCTLR_EL2_EE		(0x1ul << 25)
#define	SCTLR_EL2_E0E		(0x1ul << 24)
#define	SCTLR_EL2_SPAN		(0x1ul << 23)
#define	SCTLR_EL2_EIS		(0x1ul << 22)
#define	SCTLR_EL2_IESB		(0x1ul << 21)
#define	SCTLR_EL2_TSCXT		(0x1ul << 20)
#define	SCTLR_EL2_WXN		(0x1ul << 19)
#define	SCTLR_EL2_nTWE		(0x1ul << 18)
/* bit 17 is reserved */
#define	SCTLR_EL2_nTWI		(0x1ul << 16)
#define	SCTLR_EL2_UCT		(0x1ul << 15)
#define	SCTLR_EL2_DZE		(0x1ul << 14)
#define	SCTLR_EL2_EnDB		(0x1ul << 13)
#define	SCTLR_EL2_I		(0x1ul << 12)
#define	SCTLR_EL2_EOS		(0x1ul << 11)
#define	SCTLR_EL2_EnRCTX	(0x1ul << 10)
/* bit 9 is reserved in EL2 */
#define	SCTLR_EL2_SED		(0x1ul << 8)
#define	SCTLR_EL2_ITD		(0x1ul << 7)
#define	SCTLR_EL2_nAA		(0x1ul << 6)
#define	SCTLR_EL2_CP15BEN	(0x1ul << 5)
#define	SCTLR_EL2_SA0		(0x1ul << 4)
#define	SCTLR_EL2_SA		(0x1ul << 3)
#define	SCTLR_EL2_C		(0x1ul << 2)
#define	SCTLR_EL2_A		(0x1ul << 1)
#define	SCTLR_EL2_M		(0x1ul << 0)

#define	SCTLR_EL2_RES1		(SCTLR_EL2_LSMAOE | SCTLR_EL2_nTLSMD | \
	SCTLR_EL2_SPAN | SCTLR_EL2_EIS | SCTLR_EL2_nTWE | SCTLR_EL2_nTWI | \
	SCTLR_EL2_EOS | SCTLR_EL2_CP15BEN | SCTLR_EL2_SA0)

/*
 * System Control Register (EL1)
 */
#define	SCTLR_EL1_TIDCP		(0x1ul << 63)
#define	SCTLR_EL1_SPINTMASK	(0x1ul << 62)
#define	SCTLR_EL1_NMI		(0x1ul << 61)
#define	SCTLR_EL1_EnTP2		(0x1ul << 60)
#define	SCTLR_EL1_TCSO		(0x1ul << 59)
#define	SCTLR_EL1_TCSO0		(0x1ul << 58)
#define	SCTLR_EL1_EPAN		(0x1ul << 57)
#define	SCTLR_EL1_EnALS		(0x1ul << 56)
#define	SCTLR_EL1_EnAS0		(0x1ul << 55)
#define	SCTLR_EL1_EnASR		(0x1ul << 54)
#define	SCTLR_EL1_TME		(0x1ul << 53)
#define	SCTLR_EL1_TME0		(0x1ul << 52)
#define	SCTLR_EL1_TMT		(0x1ul << 51)
#define	SCTLR_EL1_TMT0		(0x1ul << 50)
#define	SCTLR_EL1_TWEDEL	(0xful << 46)
#define	SCTLR_EL1_TWEDEn	(0x1ul << 45)
#define	SCTLR_EL1_DSSBS		(0x1ul << 44)
#define	SCTLR_EL1_ATA		(0x1ul << 43)
#define	SCTLR_EL1_ATA0		(0x1ul << 42)
#define	SCTLR_EL1_TCF		(0x3ul << 40)
#define	SCTLR_EL1_TCF0		(0x3ul << 38)
#define	SCTLR_EL1_ITFSB		(0x1ul << 37)
#define	SCTLR_EL1_BT1		(0x1ul << 36)
#define	SCTLR_EL1_BT0		(0x1ul << 35)
#define	SCTLR_EL1_EnFPM		(0x1ul << 34)
#define	SCTLR_EL1_MSCEn		(0x1ul << 33)
#define	SCTLR_EL1_CMOW		(0x1ul << 32)
#define	SCTLR_EL1_EnIA		(0x1ul << 31)
#define	SCTLR_EL1_EnIB		(0x1ul << 30)
#define	SCTLR_EL1_LSMAOE	(0x1ul << 29)
#define	SCTLR_EL1_nTLSMD	(0x1ul << 28)
#define	SCTLR_EL1_EnDA		(0x1ul << 27)
#define	SCTLR_EL1_UCI		(0x1ul << 26)
#define	SCTLR_EL1_EE		(0x1ul << 25)
#define	SCTLR_EL1_E0E		(0x1ul << 24)
#define	SCTLR_EL1_SPAN		(0x1ul << 23)
#define	SCTLR_EL1_EIS		(0x1ul << 22)
#define	SCTLR_EL1_IESB		(0x1ul << 21)
#define	SCTLR_EL1_TSCXT		(0x1ul << 20)
#define	SCTLR_EL1_WXN		(0x1ul << 19)
#define	SCTLR_EL1_nTWE		(0x1ul << 18)
/* bit 17 is reserved */
#define	SCTLR_EL1_nTWI		(0x1ul << 16)
#define	SCTLR_EL1_UCT		(0x1ul << 15)
#define	SCTLR_EL1_DZE		(0x1ul << 14)
#define	SCTLR_EL1_EnDB		(0x1ul << 13)
#define	SCTLR_EL1_I		(0x1ul << 12)
#define	SCTLR_EL1_EOS		(0x1ul << 11)
#define	SCTLR_EL1_EnRCTX	(0x1ul << 10)
#define	SCTLR_EL1_EL1_UMA	(0x1ul << 9)
#define	SCTLR_EL1_SED		(0x1ul << 8)
#define	SCTLR_EL1_ITD		(0x1ul << 7)
#define	SCTLR_EL1_nAA		(0x1ul << 6)
#define	SCTLR_EL1_CP15BEN	(0x1ul << 5)
#define	SCTLR_EL1_SA0		(0x1ul << 4)
#define	SCTLR_EL1_SA		(0x1ul << 3)
#define	SCTLR_EL1_C		(0x1ul << 2)
#define	SCTLR_EL1_A		(0x1ul << 1)
#define	SCTLR_EL1_M		(0x1ul << 0)

#define	SCTLR_EL1_RES1		(SCTLR_EL1_LSMAOE | SCTLR_EL1_nTLSMD | \
	SCTLR_EL1_SPAN | SCTLR_EL1_EIS | SCTLR_EL1_TSCXT | SCTLR_EL1_EOS)

#define	INIT_SCTLR_EL1		(SCTLR_EL1_LSMAOE | SCTLR_EL1_nTLSMD | \
	SCTLR_EL1_EIS | SCTLR_EL1_TSCXT | SCTLR_EL1_EOS)

/*
 * Hypervisor Configuration Register
 */
#define	HCR_TWEDEL		(0xful << 60)
#define	HCR_TWEDEn		(0x1ul << 59)
#define	HCR_TID5		(0x1ul << 58)
#define	HCR_DCT			(0x1ul << 57)
#define	HCR_ATA			(0x1ul << 56)
#define	HCR_TTLBOS		(0x1ul << 55)
#define	HCR_TTLBIS		(0x1ul << 54)
#define	HCR_EnSCXT		(0x1ul << 53)
#define	HCR_TOCU		(0x1ul << 52)
#define	HCR_AMVOFFEN		(0x1ul << 51)
#define	HCR_TICAB		(0x1ul << 50)
#define	HCR_TID4		(0x1ul << 49)
#define	HCR_GPF			(0x1ul << 48)
#define	HCR_FIEN		(0x1ul << 47)
#define	HCR_FWB			(0x1ul << 46)
#define	HCR_NV2			(0x1ul << 45)
#define	HCR_AT			(0x1ul << 44)
#define	HCR_NV1			(0x1ul << 43)
#define	HCR_NV			(0x1ul << 42)
#define	HCR_API			(0x1ul << 41)
#define	HCR_APK			(0x1ul << 40)
#define	HCR_TME			(0x1ul << 39)
#define	HCR_MIOCNCE		(0x1ul << 38)
#define	HCR_TEA			(0x1ul << 37)
#define	HCR_TERR		(0x1ul << 36)
#define	HCR_TLOR		(0x1ul << 35)
#define	HCR_E2H			(0x1ul << 34)
#define	HCR_ID			(0x1ul << 33)
#define	HCR_CD			(0x1ul << 32)
#define	HCR_RW			(0x1ul << 31)
#define	HCR_TRVM		(0x1ul << 30)
#define	HCR_HCD			(0x1ul << 29)
#define	HCR_TDZ			(0x1ul << 28)
#define	HCR_TGE			(0x1ul << 27)
#define	HCR_TVM			(0x1ul << 26)
#define	HCR_TTLB		(0x1ul << 25)
#define	HCR_TPU			(0x1ul << 24)
#define	HCR_TPCP		(0x1ul << 23)
#define	HCR_TSW			(0x1ul << 22)
#define	HCR_TACR		(0x1ul << 21)
#define	HCR_TIDCP		(0x1ul << 20)
#define	HCR_TSC			(0x1ul << 19)
#define	HCR_TID3		(0x1ul << 18)
#define	HCR_TID2		(0x1ul << 17)
#define	HCR_TID1		(0x1ul << 16)
#define	HCR_TID0		(0x1ul << 15)
#define	HCR_TWE			(0x1ul << 14)
#define	HCR_TWI			(0x1ul << 13)
#define	HCR_DC			(0x1ul << 12)
#define	HCR_BSU			(0x3ul << 10)
#define	HCR_FB			(0x1ul << 9)
#define	HCR_VSE			(0x1ul << 8)
#define	HCR_VI			(0x1ul << 7)
#define	HCR_VF			(0x1ul << 6)
#define	HCR_AMO			(0x1ul << 5)
#define	HCR_IMO			(0x1ul << 4)
#define	HCR_FMO			(0x1ul << 3)
#define	HCR_PTW			(0x1ul << 2)
#define	HCR_SWIO		(0x1ul << 1)
#define	HCR_VM			(0x1ul << 0)

/*
 * Counter-timer Hypervisor Control Register
 */
#define	CNTHCTL_CNTPMASK	(0x1ul << 19)
#define	CNTHCTL_CNTVMASK	(0x1ul << 18)
#define	CNTHCTL_EVNTIS		(0x1ul << 17)
#define	CNTHCTL_EL1NVVCT	(0x1ul << 16)
#define	CNTHCTL_EL1NVPCT	(0x1ul << 15)
#define	CNTHCTL_EL1TVCT		(0x1ul << 14)
#define	CNTHCTL_EL1TVT		(0x1ul << 13)
#define	CNTHCTL_ECV		(0x1ul << 12)
/* valid when HCR_EL2.E2H is 1 */
#define	CNTHCTL_E2H_EL1PTEN	(0x1ul << 11)
#define	CNTHCTL_E2H_EL1PCTEN	(0x1ul << 10)
#define	CNTHCTL_E2H_EL0PTEN	(0x1ul << 9)
#define	CNTHCTL_E2H_EL0VTEN	(0x1ul << 8)
/* always valid */
#define	CNTHCTL_EVNTI		(0xful << 4)
#define	CNTHCTL_EVNTDIR		(0x1ul << 3)
#define	CNTHCTL_EVNTEN		(0x1ul << 2)
/* valid when HCR_EL2.E2H is 1 */
#define	CNTHCTL_E2H_EL0VCTEN	(0x1ul << 1)
#define	CNTHCTL_E2H_EL0PCTEN	(0x1ul << 0)
/* valid when HCR_EL2.E2H is 0 */
#define	CNTHCTL_EL1PCEN		(0x1ul << 1)
#define	CNTHCTL_EL1PCTEN	(0x1ul << 0)

/*
 * Architectural Feature Trap Register (EL2)
 */
#define	CPTR_EL2_TCPAC		(0x1ul << 31)
#define	CPTR_EL2_TAM		(0x1ul << 30)
#define	CPTR_EL2_E0POE		(0x1ul << 29)
#define	CPTR_EL2_TTA		(0x1ul << 28)
#define	CPTR_EL2_SMEN		(0x3ul << 24)
#define	CPTR_EL2_FPEN		(0x3ul << 20)
#define	CPTR_EL2_ZEN		(0x3ul << 16)

/*
 * XXXARM: cptr_el2 initialisation is sketchy at best, and can easily set
 * res0 bits when certain features are not implemented. We should do this
 * a little bit better, in code and querying features.
 *
 * For now we just assume that it's ok to set these bits, which is what
 * FreeBSD does.
 */

/*
 * CPTR_EL2 when E2H is enabled.
 *
 * Does not cause any known activity to be trapped to EL2 via these control.
 * This is necessary (for now), since we're not really doing anything special
 * at EL2 yet.
 */
#define	INIT_CPTR_EL2_E2H	(0x23330000ul)

/*
 * CPTR_EL2 value when E2H is not enabled.
 *
 * This was defined as 0x33ff, which causes SVE and SME to be trapped (via
 * bits 8 and 12 respectively), which is not our intention at all.
 *
 * FreeBSD seems to be unaware of SME at present.
 */
#define	CPTR_EL2_NO_E2H_TCPAC	(0x1ul << 31)
#define	CPTR_EL2_NO_E2H_TAM	(0x1ul << 30)
#define	CPTR_EL2_NO_E2H_TTA	(0x1ul << 20)
#define	CPTR_EL2_NO_E2H_TSM	(0x1ul << 12)
#define	CPTR_EL2_NO_E2H_TFP	(0x1ul << 10)
#define	CPTR_EL2_NO_E2H_TZ	(0x1ul << 8)
#define	CPTR_EL2_NO_E2H_RES1	(0x22fful)
#define	INIT_CPTR_EL2_NO_E2H	(CPTR_EL2_NO_E2H_RES1)

#define	CPUECTLR_SMP	(1<<6)

#define	TCR_AS		(1ul<<36)
#define	TCR_IPS_4G	(0ul<<32)
#define	TCR_IPS_64G	(1ul<<32)
#define	TCR_IPS_1T	(2ul<<32)
#define	TCR_IPS_4T	(3ul<<32)
#define	TCR_IPS_16T	(4ul<<32)
#define	TCR_IPS_256T	(5ul<<32)
#define	TCR_IPS_SHIFT	32
#define	TCR_TG1_16K	(1ul<<30)
#define	TCR_TG1_4K	(2ul<<30)
#define	TCR_TG1_64K	(3ul<<30)
#define	TCR_SH1_NSH	(0ul<<28)
#define	TCR_SH1_OSH	(2ul<<28)
#define	TCR_SH1_ISH	(3ul<<28)
#define	TCR_ORGN1_NC	(0ul<<26)
#define	TCR_ORGN1_WBWA	(1ul<<26)
#define	TCR_ORGN1_WT	(2ul<<26)
#define	TCR_ORGN1_WBNA	(3ul<<26)
#define	TCR_IRGN1_NC	(0ul<<24)
#define	TCR_IRGN1_WBWA	(1ul<<24)
#define	TCR_IRGN1_WT	(2ul<<24)
#define	TCR_IRGN1_WBNA	(3ul<<24)
#define	TCR_EPD1	(1ul<<23)
#define	TCR_A1		(1ul<<22)
#define	TCR_T1SZ_256T	(16ul<<16)
#define	TCR_TG0_4K	(0ul<<14)
#define	TCR_TG0_64K	(1ul<<14)
#define	TCR_TG0_16K	(2ul<<14)
#define	TCR_SH0_NSH	(0ul<<12)
#define	TCR_SH0_OSH	(2ul<<12)
#define	TCR_SH0_ISH	(3ul<<12)
#define	TCR_ORGN0_NC	(0ul<<10)
#define	TCR_ORGN0_WBWA	(1ul<<10)
#define	TCR_ORGN0_WT	(2ul<<10)
#define	TCR_ORGN0_WBNA	(3ul<<10)
#define	TCR_IRGN0_NC	(0ul<<8)
#define	TCR_IRGN0_WBWA	(1ul<<8)
#define	TCR_IRGN0_WT	(2ul<<8)
#define	TCR_IRGN0_WBNA	(3ul<<8)
#define	TCR_EPD0	(1ul<<7)
#define	TCR_T0SZ_256T	(16ul<<0)


#define	TTBR_ASID_SHIFT		48
#define	TTBR_ASID_MASK		(0xFFull<<TTBR_ASID_SHIFT)
#define	TTBR_BADDR48_SHIFT	12
#define	TTBR_BADDR48_MASK	(0xfffffffffull << TTBR_BADDR48_SHIFT)
#define	TTBR_CNP_SHIFT		0
#define	TTBR_CNP_MASK		(0x1ull << TTBR_CNP_SHIFT)


#define	PSR_N		(1u<<31)
#define	PSR_Z		(1u<<30)
#define	PSR_C		(1u<<29)
#define	PSR_V		(1u<<28)
#define	PSR_SS		(1u<<21)
#define	PSR_SS_BIT	21
#define	PSR_IL		(1u<<20)
#define	PSR_D		(1u<<9)
#define	PSR_A		(1u<<8)
#define	PSR_I		(1u<<7)
#define	PSR_F		(1u<<6)
#define	PSR_M_MASK	(0xF)
#define	PSR_M_EL3h	(0xD)
#define	PSR_M_EL3t	(0xC)
#define	PSR_M_EL2h	(0x9)
#define	PSR_M_EL2t	(0x8)
#define	PSR_M_EL1h	(0x5)
#define	PSR_M_EL1t	(0x4)
#define	PSR_M_EL0t	(0x0)

#define	PSR_USERINIT	PSR_M_EL0t
#define	PSR_USERMASK	(PSR_N | PSR_Z | PSR_C | PSR_V | PSR_SS)

#define	CPACR_FPEN_MASK	(0x3ul << 20)
#define	CPACR_FPEN_EN	(0x3ul << 20)
#define	CPACR_FPEN_DIS	(0x0ul << 20)

#define	PAR_ATTR_MASK	(0xFF00000000000000ul)
#define	PAR_PA_MASK	(0x0000FFFFFFFFF000ul)
#define	PAR_NS_MASK	(0x0000000000000200ul)
#define	PAR_SH_MASK	(0x0000000000000180ul)
#define	PAR_F		(0x0000000000000001ul)

/*
 * Arm Architecture Reference Manual for A-profile architecture
 *    D17.2.34 CTR_EL0, Cache Type Register
 *    (ARM DDI 0487I.a)
 */
#define	CTR_TMINLINE(ctr)	bitx64(ctr, 37, 32)
#define	CTR_TMINLINE_SIZE(ctr)	(4 << CTR_TMINLINE(ctr))
#define	CTR_DIC(ctr)		bitx64(ctr, 29, 29)
#define	CTR_IDC(ctr)		bitx64(ctr, 28, 28)
#define	CTR_CWG(ctr)		bitx64(ctr, 27, 24)
#define	CTR_ERG(ctr)		bitx64(ctr, 23, 20)
#define	CTR_DMINLINE(ctr)	bitx64(ctr, 19, 16)
#define	CTR_DMINLINE_SIZE(ctr)	(4 << CTR_DMINLINE(ctr))
#define	CTR_L1IP(ctr)		bitx64(ctr, 15, 14)
#define	CTR_IMINLINE(ctr)	bitx64(ctr, 3, 0)
#define	CTR_IMINLINE_SIZE(ctr)	(4 << CTR_IMINLINE(ctr))

#define	MPIDR_AFF0_MASK	(0x00000000000000FFul)
#define	MPIDR_AFF1_MASK	(0x000000000000FF00ul)
#define	MPIDR_AFF2_MASK	(0x0000000000FF0000ul)
#define	MPIDR_AFF3_MASK	(0x000000FF00000000ul)
#define	MPIDR_AFF_MASK	(MPIDR_AFF0_MASK | MPIDR_AFF1_MASK | \
			MPIDR_AFF2_MASK | MPIDR_AFF3_MASK)

/*
 * Transform an MPIDR-style affinity to/from a normalized representation,
 * which is defined as:
 * [63:32]: Reserved (0)
 * [31:24]: Affinity level 3
 * [23:16]: Affinity level 2
 * [15:8]: Affinity level 1
 * [7:0]: Affinity level 0
 */
#define	AFF_MPIDR_TO_PACKED(v)	((((v) & MPIDR_AFF3_MASK) >> 8) | \
				((v) & (MPIDR_AFF2_MASK | MPIDR_AFF1_MASK | \
				MPIDR_AFF0_MASK)))
#define	AFF_PACKED_TO_MPIDR(v)	((((v) & 0x00000000FF000000) << 8) | \
				((v) & 0x0000000000FFFFFF))

#define	MAIR_ATTR_IWB_OWB	(0xFFul)
#define	MAIR_ATTR_IWT_OWT	(0xBBul)
#define	MAIR_ATTR_IWB_ONC	(0x4Ful)
#define	MAIR_ATTR_IWT_ONC	(0x4Bul)
#define	MAIR_ATTR_INC_ONC	(0x44ul)
#define	MAIR_ATTR_nGnRE		(0x04ul)
#define	MAIR_ATTR_nGnRnE	(0x00ul)
#define	MAIR_ATTR_nGRE		(0x08ul)

#define	MDSCR_RXfull		(1ul << 30)
#define	MDSCR_TXfull		(1ul << 29)
#define	MDSCR_RXO		(1ul << 27)
#define	MDSCR_TXU		(1ul << 26)
#define	MDSCR_INTdis_MASK	(3ul << 22)
#define	MDSCR_TDA		(1ul << 21)
#define	MDSCR_MDE		(1ul << 15)
#define	MDSCR_HDE		(1ul << 14)
#define	MDSCR_KDE		(1ul << 13)
#define	MDSCR_TDCC		(1ul << 12)
#define	MDSCR_ERR		(1ul << 6)
#define	MDSCR_SS		(1ul << 0)

/* hypervisor.h in FreeBSD */
#define	CPTR_RES1		(0x000033ff)

#define	SCTLR_RES1		0x30d00800	/* Reserved ARMv8.0, write 1 */

#endif	/* !_ASM */
#endif	/* _SYS_CONTROLREGS_H */
