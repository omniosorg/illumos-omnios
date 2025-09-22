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
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef _ELF_AARCH64_H
#define	_ELF_AARCH64_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These are taken from the ARM psABI
 * ELF for the ARM 64-bit Architecture (AArch64) 2022Q1.
 *
 * Note that in the ARM ABI relocations are non-consecutive and grouped, so
 * R_AARCH64_NUM is not equal to the number of actual possible relocations,
 * but covers up to the maximum we understand.
 *
 * Note also that the ABI documents them in sections, and so these definitions
 * are most unfortunately not contiguous, but grouped as the ABI documented does
 */

/* ABI: Static miscellaneous relocations */
#define	R_AARCH64_NONE		0
#define	R_AARCH64_ALSO_NONE	256 /* Defined to be the same as _NONE */

/* ABI: Static Data relocations */
#define	R_AARCH64_ABS64		257
#define	R_AARCH64_ABS32		258
#define	R_AARCH64_ABS16		259
#define	R_AARCH64_PREL64	260
#define	R_AARCH64_PREL32	261
#define	R_AARCH64_PREL16	262
/* XXXARM: gap */
#define	R_AARCH64_PLT32		314

/*
 * ABI: Static AArch64 relocations
 *
 * (unsigned inline)
 */
#define	R_AARCH64_MOVW_UABS_G0		263
#define	R_AARCH64_MOVW_UABS_G0_NC	264
#define	R_AARCH64_MOVW_UABS_G1		265
#define	R_AARCH64_MOVW_UABS_G1_NC	266
#define	R_AARCH64_MOVW_UABS_G2		267
#define	R_AARCH64_MOVW_UABS_G2_NC	268
#define	R_AARCH64_MOVW_UABS_G3		269

/*
 * ABI: Static AArch64 relocations
 *
 * (signed inline)
 */
#define	R_AARCH64_MOVW_SABS_G0	270
#define	R_AARCH64_MOVW_SABS_G1	271
#define	R_AARCH64_MOVW_SABS_G2	272


/*
 * ABI: Static AArch64 relocations
 *
 * (PC relative)
 */
#define	R_AARCH64_LD_PREL_LO19		273
#define	R_AARCH64_ADR_PREL_LO21		274
#define	R_AARCH64_ADR_PREL_PG_HI21	275
#define	R_AARCH64_ADR_PREL_PG_HI21_NC	276
#define	R_AARCH64_ADD_ABS_LO12_NC	277
#define	R_AARCH64_LDST8_ABS_LO12_NC	278
/* XXXARM: gap */
#define	R_AARCH64_LDST16_ABS_LO12_NC	284
#define	R_AARCH64_LDST32_ABS_LO12_NC	285
#define	R_AARCH64_LDST64_ABS_LO12_NC	286
/* XXXARM: gap */
#define	R_AARCH64_LDST128_ABS_LO12_NC	299

/*
 * ABI: Static AArch64 relocations
 *
 * (control-flow instructions)
 */
#define	R_AARCH64_TSTBR14	279
#define	R_AARCH64_CONDBR19	280
/* XXXARM: gap */
#define	R_AARCH64_JUMP26	282
#define	R_AARCH64_CALL26	283

/*
 * ABI: Static AArch64 relocations
 *
 * (pc-relative inline relocations)
 */
#define	R_AARCH64_MOVW_PREL_G0		287
#define	R_AARCH64_MOVW_PREL_G0_NC	288
#define	R_AARCH64_MOVW_PREL_G1		289
#define	R_AARCH64_MOVW_PREL_G1_NC	290
#define	R_AARCH64_MOVW_PREL_G2		291
#define	R_AARCH64_MOVW_PREL_G2_NC	292
#define	R_AARCH64_MOVW_PREL_G3		293

/*
 * ABI: Static AArch64 relocations
 *
 * (GOT-relative inline relocations)
 */
#define	R_AARCH64_MOVW_GOTOFF_G0	300
#define	R_AARCH64_MOVW_GOTOFF_G0_NC	301
#define	R_AARCH64_MOVW_GOTOFF_G1	302
#define	R_AARCH64_MOVW_GOTOFF_G1_NC	303
#define	R_AARCH64_MOVW_GOTOFF_G2	304
#define	R_AARCH64_MOVW_GOTOFF_G2_NC	305
#define	R_AARCH64_MOVW_GOTOFF_G3	306

/*
 * ABI: Static AArch64 relocations
 *
 * (GOT-relative data relocations)
 */
#define	R_AARCH64_GOTREL64	307
#define	R_AARCH64_GOTREL32	308

/*
 * ABI: Static AArch64 relocations
 *
 * (GOT-relative instruction relocations)
 */
#define	R_AARCH64_GOT_LD_PREL19		309
#define	R_AARCH64_LD64_GOTOFF_LO15	310
#define	R_AARCH64_ADR_GOT_PAGE		311
#define	R_AARCH64_LD64_GOT_LO12_NC	312
#define	R_AARCH64_LD64_GOTPAGE_LO15	313

/*
 * ABI: General Dynamic TLS relocations
 */
#define	R_AARCH64_TLSGD_ADR_PREL21	512
#define	R_AARCH64_TLSGD_ADR_PAGE21	513
#define	R_AARCH64_TLSGD_ADD_LO12_NC	514
#define	R_AARCH64_TLSGD_MOVW_G1		515
#define	R_AARCH64_TLSGD_MOVW_G0_NC	516

/*
 * ABI: Local Dynamic TLS relocations
 */
#define	R_AARCH64_TLSLD_ADR_PREL21		517
#define	R_AARCH64_TLSLD_ADR_PAGE21		518
#define	R_AARCH64_TLSLD_ADD_LO12_NC		519
#define	R_AARCH64_TLSLD_MOVW_G1			520
#define	R_AARCH64_TLSLD_MOVW_G0_NC		521
#define	R_AARCH64_TLSLD_LD_PREL19		522
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G2		523
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G1		524
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC	525
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G0		526
#define	R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC	527
#define	R_AARCH64_TLSLD_ADD_DTPREL_HI12		528
#define	R_AARCH64_TLSLD_ADD_DTPREL_LO12		529
#define	R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC	530
#define	R_AARCH64_TLSLD_LDST8_DTPREL_LO12	531
#define	R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC	532
#define	R_AARCH64_TLSLD_LDST16_DTPREL_LO12	533
#define	R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC	534
#define	R_AARCH64_TLSLD_LDST32_DTPREL_LO12	535
#define	R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC	536
#define	R_AARCH64_TLSLD_LDST64_DTPREL_LO12	537
#define	R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC	538
/* XXXARM: gap */
#define	R_AARCH64_TLSLD_LDST128_DTPREL_LO12	572
#define	R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC	573

/*
 * ABI: Initial Exec TLS relocations
 */
#define	R_AARCH64_TLSIE_MOVW_GOTTPREL_G1	539
#define	R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC	540
#define	R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21	541
#define	R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC	542
#define	R_AARCH64_TLSIE_LD_GOTTPREL_PREL19	543

/*
 * ABI: Local Exec TLS relocations
 */
#define	R_AARCH64_TLSLE_MOVW_TPREL_G2		544
#define	R_AARCH64_TLSLE_MOVW_TPREL_G1		545
#define	R_AARCH64_TLSLE_MOVW_TPREL_G1_NC	546
#define	R_AARCH64_TLSLE_MOVW_TPREL_G0		547
#define	R_AARCH64_TLSLE_MOVW_TPREL_G0_NC	548
#define	R_AARCH64_TLSLE_ADD_TPREL_HI12		549
#define	R_AARCH64_TLSLE_ADD_TPREL_LO12		550
#define	R_AARCH64_TLSLE_ADD_TPREL_LO12_NC	551
#define	R_AARCH64_TLSLE_LDST8_TPREL_LO12	552
#define	R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC	553
#define	R_AARCH64_TLSLE_LDST16_TPREL_LO12	554
#define	R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC	555
#define	R_AARCH64_TLSLE_LDST32_TPREL_LO12	556
#define	R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC	557
#define	R_AARCH64_TLSLE_LDST64_TPREL_LO12	558
#define	R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC	559
/* XXXARM: gap */
#define	R_AARCH64_TLSLE_LDST128_TPREL_LO12	570
#define	R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC	571

/*
 * ABI: TLS descriptor relocations
 */
#define	R_AARCH64_TLSDESC_LD_PREL19	560
#define	R_AARCH64_TLSDESC_ADR_PREL21	561
#define	R_AARCH64_TLSDESC_ADR_PAGE21	562
#define	R_AARCH64_TLSDESC_LD64_LO12	563
#define	R_AARCH64_TLSDESC_ADD_LO12	564
#define	R_AARCH64_TLSDESC_OFF_G1	565
#define	R_AARCH64_TLSDESC_OFF_G0_NC	566
#define	R_AARCH64_TLSDESC_LDR		567
#define	R_AARCH64_TLSDESC_ADD		568
#define	R_AARCH64_TLSDESC_CALL		569

/*
 * ABI: Dynamic relocations
 */
/* R_AARCH64_ABS64 is also in this table */
#define	R_AARCH64_COPY		1024
#define	R_AARCH64_GLOB_DAT	1025
#define	R_AARCH64_JUMP_SLOT	1026
#define	R_AARCH64_RELATIVE	1027
/*
 * XXXARM: The ABI says we have to choose which of the following two is which.
 * The choice I have made here is arbitrary
 */
#define	R_AARCH64_TLS_DTPMOD	1028
#define	R_AARCH64_TLS_DTPREL	1029
#define	R_AARCH64_TLS_TPREL	1030
#define	R_AARCH64_TLSDESC	1031
#define	R_AARCH64_IRELATIVE	1032

#define	R_AARCH64_NUM	1033	/* R_AARCH64_IRELATIVE + 1 */

#define	R_AARCH64_TLS_DTPMOD64	R_AARCH64_TLS_DTPMOD
#define	R_AARCH64_TLS_DTPREL64	R_AARCH64_TLS_DTPREL
#define	R_AARCH64_TLS_TPREL64	R_AARCH64_TLS_TPREL

/*
 * Processor specific section types
 */
#define	SHF_AARCH64_PURECODE	0x20000000
#define	SHF_ORDERED		0x40000000
#define	SHF_EXCLUDE		0x80000000
#define	SHN_BEFORE		0xff00
#define	SHN_AFTER		0xff01

/*
 * Processor specific dynamic tags
 */
#define	DT_AARCH64_BTI_PLT	0x70000001
#define	DT_AARCH64_PAC_PLT	0x70000003
#define	DT_AARCH64_VARIANT_PCS	0x70000005

/* XXXARM: There's probably a define for this */
#define	ELF_AARCH64_MAXPGSZ	0x100000	/* maximum page size */

/*
 * There are consumers of this file that want to include elf defines for
 * all architectures.  This is a problem for the defines below, because
 * while they are architecture specific they have common names.  Hence to
 * prevent attempts to redefine these variables we'll check if any of
 * the other elf architecture header files have been included.  If
 * they have then we'll just stick with the existing definitions.
 */
#if !defined(_SYS_ELF_MACH_COMMON)
#define	_SYS_ELF_MACH_COMMON

/*
 * Plt and Got information; the first few .got and .plt entries are reserved
 *	PLT[0]	jump to dynamic linker
 *	GOT[0]	address of _DYNAMIC
 */
/* XXXARM: Are these true?! */
#define	M_PLT_INSSIZE		4	/* single plt instruction size */
#define	M_GOT_XDYNAMIC		0	/* got index for _DYNAMIC */
#define	M_GOT_XNumber		3	/* reserved no. of got entries */

/*
 * ELF64 bit PLT constants
 */
/* XXXARM: Why do these have the wrong names? */
#define	M64_WORD_ALIGN		8
#define	M64_PLT_ENTSIZE		16	/* plt entry size in bytes */
#define	M64_PLT_ALIGN		16	/* alignment of .plt section */
#define	M64_GOT_ENTSIZE		8	/* got entry size in bytes */
#define	M64_PLT_RESERVSZ	32

/*
 * Make common alias for the 64 bit specific defines based on _ELF64
 */
/* architecture common defines */
#define	M_WORD_ALIGN		M64_WORD_ALIGN
#define	M_PLT_ENTSIZE		M64_PLT_ENTSIZE
#define	M_PLT_ALIGN		M64_PLT_ALIGN
#define	M_PLT_RESERVSZ		M64_PLT_RESERVSZ
#define	M_GOT_ENTSIZE		M64_GOT_ENTSIZE

#endif /* !_SYS_ELF_MACH_COMMON */

#ifdef	__cplusplus
}
#endif

#endif	/* _ELF_AARCH64_H */
