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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 */

#include	<sys/sysmacros.h>

#if	defined(_KERNEL)
#include	<sys/types.h>
#include	"reloc.h"
#else
#define	ELF_TARGET_AARCH64
#if defined(DO_RELOC_LIBLD)
#undef DO_RELOC_LIBLD
#define	DO_RELOC_LIBLD_AARCH64
#endif
#include	<stdio.h>
#include	"sgs.h"
#include	"machdep.h"
#include	"libld.h"
#include	"reloc.h"
#include	"conv.h"
#include	"msg.h"
#endif

/*
 * We need to build this code differently when it is used for
 * cross linking:
 *	- Data alignment requirements can differ from those
 *		of the running system, so we can't access data
 *		in units larger than a byte
 *	- We have to include code to do byte swapping when the
 *		target and linker host use different byte ordering,
 *		but such code is a waste when running natively.
 */
#if !defined(DO_RELOC_LIBLD) || defined(__aarch64__)
#define	DORELOC_NATIVE
#endif

/*
 * This table represents the current relocations that do_reloc() is able to
 * process.  The relocations below that are marked SPECIAL are relocations that
 * take special processing and shouldn't actually ever be passed to do_reloc().
 */
const Rel_entry	reloc_table[R_AARCH64_NUM] = {
	[R_AARCH64_NONE] = {0, FLG_RE_NOTREL, 0, 0, 0}, /* 0 */
	[1] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[2] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[3] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[4] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[5] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[6] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[7] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[8] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[9] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[10] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[11] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[12] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[13] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[14] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[15] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[16] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[17] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[18] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[19] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[20] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[21] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[22] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[23] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[24] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[25] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[26] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[27] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[28] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[29] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[30] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[31] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[32] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[33] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[34] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[35] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[36] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[37] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[38] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[39] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[40] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[41] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[42] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[43] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[44] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[45] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[46] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[47] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[48] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[49] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[50] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[51] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[52] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[53] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[54] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[55] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[56] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[57] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[58] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[59] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[60] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[61] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[62] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[63] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[64] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[65] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[66] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[67] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[68] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[69] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[70] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[71] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[72] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[73] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[74] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[75] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[76] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[77] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[78] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[79] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[80] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[81] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[82] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[83] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[84] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[85] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[86] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[87] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[88] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[89] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[90] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[91] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[92] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[93] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[94] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[95] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[96] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[97] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[98] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[99] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[100] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[101] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[102] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[103] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[104] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[105] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[106] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[107] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[108] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[109] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[110] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[111] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[112] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[113] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[114] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[115] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[116] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[117] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[118] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[119] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[120] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[121] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[122] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[123] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[124] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[125] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[126] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[127] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[128] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[129] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[130] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[131] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[132] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[133] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[134] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[135] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[136] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[137] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[138] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[139] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[140] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[141] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[142] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[143] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[144] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[145] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[146] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[147] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[148] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[149] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[150] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[151] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[152] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[153] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[154] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[155] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[156] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[157] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[158] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[159] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[160] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[161] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[162] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[163] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[164] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[165] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[166] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[167] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[168] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[169] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[170] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[171] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[172] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[173] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[174] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[175] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[176] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[177] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[178] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[179] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[180] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[181] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[182] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[183] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[184] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[185] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[186] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[187] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[188] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[189] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[190] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[191] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[192] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[193] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[194] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[195] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[196] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[197] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[198] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[199] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[200] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[201] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[202] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[203] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[204] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[205] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[206] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[207] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[208] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[209] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[210] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[211] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[212] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[213] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[214] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[215] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[216] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[217] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[218] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[219] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[220] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[221] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[222] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[223] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[224] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[225] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[226] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[227] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[228] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[229] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[230] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[231] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[232] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[233] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[234] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[235] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[236] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[237] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[238] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[239] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[240] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[241] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[242] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[243] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[244] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[245] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[246] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[247] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[248] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[249] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[250] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[251] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[252] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[253] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[254] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[255] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[R_AARCH64_ALSO_NONE] = { 0, FLG_RE_NOTREL, 0, 0, 0 }, /* 256 */
	[R_AARCH64_ABS64] = {0, FLG_RE_NOTREL, 8, 0, 0},       /* 257 */
	[R_AARCH64_ABS32] = {0, FLG_RE_NOTREL, 4, 0, 0},       /* 258 */
	[R_AARCH64_ABS16] = {0, FLG_RE_NOTREL, 4, 0, 0},       /* 259 */
	[R_AARCH64_PREL64] = {0, FLG_RE_PCREL, 8, 0, 0},      /* 260 */
	[R_AARCH64_PREL32] = {0, FLG_RE_PCREL, 4, 0, 0},       /* 261 */
	[R_AARCH64_PREL16] = {0, FLG_RE_NOTSUP, 0, 0, 0},      /* 262 */
	[R_AARCH64_MOVW_UABS_G0] = {0, FLG_RE_NOTREL, 4, 0, 0},	   /* 263 */
	[R_AARCH64_MOVW_UABS_G0_NC] = {0, FLG_RE_NOTREL, 4, 0, 0}, /* 264 */
	[R_AARCH64_MOVW_UABS_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0},	   /* 265 */
	[R_AARCH64_MOVW_UABS_G1_NC] = {0, FLG_RE_NOTREL, 4, 0, 0}, /* 266 */
	[R_AARCH64_MOVW_UABS_G2] = {0, FLG_RE_NOTREL, 4, 0, 0},	   /* 267 */
	[R_AARCH64_MOVW_UABS_G2_NC] = {0, FLG_RE_NOTREL, 4, 0, 0}, /* 268 */
	[R_AARCH64_MOVW_UABS_G3] = {0, FLG_RE_NOTREL, 4, 0, 0},	   /* 269 */
	[R_AARCH64_MOVW_SABS_G0] = {0, FLG_RE_NOTSUP, 0, 0, 0},	   /* 270 */
	[R_AARCH64_MOVW_SABS_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0},	   /* 271 */
	[R_AARCH64_MOVW_SABS_G2] = {0, FLG_RE_NOTSUP, 0, 0, 0},	   /* 272 */
	[R_AARCH64_LD_PREL_LO19] = {0, FLG_RE_NOTSUP, 0, 0, 0},	   /* 273 */
	[R_AARCH64_ADR_PREL_LO21] = {0, FLG_RE_PCREL, 4, 0, 0},	   /* 274 */
	[R_AARCH64_ADR_PREL_PG_HI21] = {0, FLG_RE_PAGE|FLG_RE_PCREL, 4, 0, 0}, /* 275 */
	[R_AARCH64_ADR_PREL_PG_HI21_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 276 */
	[R_AARCH64_ADD_ABS_LO12_NC] = {0, FLG_RE_NOTREL, 4, 0, 0},     /* 277 */
	[R_AARCH64_LDST8_ABS_LO12_NC] = {0, FLG_RE_NOTREL, 4, 0, 0},   /* 278 */
	[R_AARCH64_TSTBR14] = {0, FLG_RE_NOTSUP, 0, 0, 0},	       /* 279 */
	[R_AARCH64_CONDBR19] = {0, FLG_RE_PLTREL|FLG_RE_PCREL, 4, 0, 0},       /* 280 */
	[281] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[R_AARCH64_JUMP26] = { 0, FLG_RE_PCREL | FLG_RE_PLTREL, 4, 0, 0 }, /* 282 */
	[R_AARCH64_CALL26] = { 0, FLG_RE_PCREL | FLG_RE_PLTREL, 4, 0, 0 }, /* 283 */
	[R_AARCH64_LDST16_ABS_LO12_NC] = {0, FLG_RE_NOTREL, 4, 0, 0}, /* 284 */
	[R_AARCH64_LDST32_ABS_LO12_NC] = {0, FLG_RE_NOTREL, 4, 0, 0}, /* 285 */
	[R_AARCH64_LDST64_ABS_LO12_NC] = {0, FLG_RE_NOTREL, 4, 0, 0}, /* 286 */
	[R_AARCH64_MOVW_PREL_G0] = {0, FLG_RE_NOTSUP, 0, 0, 0},	      /* 287 */
	[R_AARCH64_MOVW_PREL_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},    /* 288 */
	[R_AARCH64_MOVW_PREL_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0},	      /* 289 */
	[R_AARCH64_MOVW_PREL_G1_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},    /* 290 */
	[R_AARCH64_MOVW_PREL_G2] = {0, FLG_RE_NOTSUP, 0, 0, 0},	      /* 291 */
	[R_AARCH64_MOVW_PREL_G2_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},    /* 292 */
	[R_AARCH64_MOVW_PREL_G3] = {0, FLG_RE_NOTSUP, 0, 0, 0},	      /* 293 */
	[294] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[295] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[296] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[297] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[298] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[R_AARCH64_LDST128_ABS_LO12_NC] = {0, FLG_RE_NOTREL, 4, 0, 0},	   /* 299 */
	[R_AARCH64_MOVW_GOTOFF_G0] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 300 */
	[R_AARCH64_MOVW_GOTOFF_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 301 */
	[R_AARCH64_MOVW_GOTOFF_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0},    /* 302 */
	[R_AARCH64_MOVW_GOTOFF_G1_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 303 */
	[R_AARCH64_MOVW_GOTOFF_G2] = {0, FLG_RE_NOTSUP, 0, 0, 0},    /* 304 */
	[R_AARCH64_MOVW_GOTOFF_G2_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 305 */
	[R_AARCH64_MOVW_GOTOFF_G3] = {0, FLG_RE_NOTSUP, 0, 0, 0},    /* 306 */
	[R_AARCH64_GOTREL64] = {0, FLG_RE_NOTSUP, 0, 0, 0},	     /* 307 */
	[R_AARCH64_GOTREL32] = {0, FLG_RE_NOTSUP, 0, 0, 0},	     /* 308 */
	[R_AARCH64_GOT_LD_PREL19] = {0, FLG_RE_NOTSUP, 0, 0, 0},     /* 309 */
	[R_AARCH64_LD64_GOTOFF_LO15] = {0, FLG_RE_NOTSUP, 0, 0, 0},  /* 310 */
	[R_AARCH64_ADR_GOT_PAGE] = {0, FLG_RE_GOTADD|FLG_RE_PAGE|FLG_RE_PCREL, 4, 0, 0},	   /* 311 */
	[R_AARCH64_LD64_GOT_LO12_NC] = {0, FLG_RE_GOTADD|FLG_RE_GOTABS, 4, 0, 0},	   /* 312 */
	[R_AARCH64_LD64_GOTPAGE_LO15] = {0, FLG_RE_GOTADD|FLG_RE_PAGE, 4, 0, 0},	   /* 313 */
	[R_AARCH64_PLT32] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 314 */
	[R_AARCH64_GOTPCREL32] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 315 */
	[316] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[317] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[318] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[319] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[320] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[321] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[322] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[323] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[324] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[325] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[326] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[327] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[328] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[329] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[330] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[331] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[332] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[333] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[334] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[335] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[336] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[337] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[338] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[339] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[340] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[341] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[342] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[343] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[344] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[345] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[346] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[347] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[348] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[349] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[350] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[351] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[352] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[353] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[354] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[355] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[356] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[357] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[358] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[359] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[360] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[361] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[362] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[363] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[364] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[365] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[366] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[367] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[368] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[369] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[370] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[371] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[372] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[373] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[374] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[375] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[376] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[377] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[378] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[379] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[380] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[381] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[382] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[383] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[384] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[385] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[386] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[387] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[388] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[389] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[390] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[391] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[392] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[393] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[394] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[395] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[396] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[397] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[398] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[399] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[400] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[401] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[402] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[403] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[404] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[405] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[406] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[407] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[408] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[409] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[410] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[411] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[412] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[413] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[414] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[415] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[416] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[417] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[418] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[419] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[420] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[421] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[422] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[423] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[424] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[425] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[426] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[427] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[428] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[429] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[430] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[431] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[432] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[433] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[434] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[435] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[436] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[437] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[438] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[439] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[440] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[441] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[442] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[443] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[444] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[445] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[446] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[447] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[448] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[449] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[450] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[451] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[452] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[453] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[454] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[455] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[456] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[457] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[458] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[459] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[460] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[461] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[462] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[463] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[464] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[465] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[466] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[467] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[468] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[469] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[470] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[471] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[472] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[473] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[474] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[475] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[476] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[477] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[478] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[479] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[480] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[481] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[482] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[483] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[484] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[485] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[486] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[487] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[488] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[489] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[490] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[491] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[492] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[493] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[494] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[495] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[496] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[497] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[498] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[499] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[500] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[501] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[502] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[503] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[504] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[505] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[506] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[507] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[508] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[509] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[510] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[511] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[R_AARCH64_TLSGD_ADR_PREL21] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 512 */
	[R_AARCH64_TLSGD_ADR_PAGE21] = {0, FLG_RE_GOTADD | FLG_RE_PAGE | FLG_RE_PCREL | FLG_RE_TLSGD, 4, 0, 0}, /* 513 */
	[R_AARCH64_TLSGD_ADD_LO12_NC] = {0, FLG_RE_GOTADD | FLG_RE_GOTABS | FLG_RE_TLSGD, 4, 0, 0}, /* 514 */
	[R_AARCH64_TLSGD_MOVW_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0},     /* 515 */
	[R_AARCH64_TLSGD_MOVW_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},  /* 516 */
	[R_AARCH64_TLSLD_ADR_PREL21] = {0, FLG_RE_NOTSUP, 0, 0, 0},  /* 517 */
	[R_AARCH64_TLSLD_ADR_PAGE21] = {0, FLG_RE_NOTSUP, 0, 0, 0},  /* 518 */
	[R_AARCH64_TLSLD_ADD_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 519 */
	[R_AARCH64_TLSLD_MOVW_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0},     /* 520 */
	[R_AARCH64_TLSLD_MOVW_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},  /* 521 */
	[R_AARCH64_TLSLD_LD_PREL19] = {0, FLG_RE_NOTSUP, 0, 0, 0},   /* 522 */
	[R_AARCH64_TLSLD_MOVW_DTPREL_G2] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 523 */
	[R_AARCH64_TLSLD_MOVW_DTPREL_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 524 */
	[R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 525 */
	[R_AARCH64_TLSLD_MOVW_DTPREL_G0] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 526 */
	[R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 527 */
	[R_AARCH64_TLSLD_ADD_DTPREL_HI12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 528 */
	[R_AARCH64_TLSLD_ADD_DTPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 529 */
	[R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 530 */
	[R_AARCH64_TLSLD_LDST8_DTPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 531 */
	[R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 532 */
	[R_AARCH64_TLSLD_LDST16_DTPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 533 */
	[R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 534 */
	[R_AARCH64_TLSLD_LDST32_DTPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 535 */
	[R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 536 */
	[R_AARCH64_TLSLD_LDST64_DTPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 537 */
	[R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 538 */
	[R_AARCH64_TLSIE_MOVW_GOTTPREL_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 539 */
	[R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 540 */
	[R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21] = {0, FLG_RE_GOTADD|FLG_RE_TLSIE|FLG_RE_PAGE|FLG_RE_PCREL, 4, 0, 0}, /* 541 */
	[R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC] = {0, FLG_RE_GOTADD|FLG_RE_GOTABS|FLG_RE_TLSIE, 4, 0, 0}, /* 542 */
	[R_AARCH64_TLSIE_LD_GOTTPREL_PREL19] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 543 */
	[R_AARCH64_TLSLE_MOVW_TPREL_G2] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 544 */
	[R_AARCH64_TLSLE_MOVW_TPREL_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 545 */
	[R_AARCH64_TLSLE_MOVW_TPREL_G1_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 546 */
	[R_AARCH64_TLSLE_MOVW_TPREL_G0] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 547 */
	[R_AARCH64_TLSLE_MOVW_TPREL_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 548 */
	[R_AARCH64_TLSLE_ADD_TPREL_HI12] = {0, FLG_RE_TLSLE, 4, 0, 0}, /* 549 */
	[R_AARCH64_TLSLE_ADD_TPREL_LO12] = {0, FLG_RE_NOTSUP, 4, 0, 0}, /* 550 */
	[R_AARCH64_TLSLE_ADD_TPREL_LO12_NC] = {0, FLG_RE_TLSLE, 4, 0, 0}, /* 551 */
	[R_AARCH64_TLSLE_LDST8_TPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 552 */
	[R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 553 */
	[R_AARCH64_TLSLE_LDST16_TPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 554 */
	[R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 555 */
	[R_AARCH64_TLSLE_LDST32_TPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 556 */
	[R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 557 */
	[R_AARCH64_TLSLE_LDST64_TPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 558 */
	[R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 559 */
	[R_AARCH64_TLSDESC_LD_PREL19] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 560 */
	[R_AARCH64_TLSDESC_ADR_PREL21] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 561 */
	[R_AARCH64_TLSDESC_ADR_PAGE21] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 562 */
	[R_AARCH64_TLSDESC_LD64_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0},  /* 563 */
	[R_AARCH64_TLSDESC_ADD_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0},   /* 564 */
	[R_AARCH64_TLSDESC_OFF_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0},     /* 565 */
	[R_AARCH64_TLSDESC_OFF_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},  /* 566 */
	[R_AARCH64_TLSDESC_LDR] = {0, FLG_RE_NOTSUP, 0, 0, 0},	      /* 567 */
	[R_AARCH64_TLSDESC_ADD] = {0, FLG_RE_NOTSUP, 0, 0, 0},	      /* 568 */
	[R_AARCH64_TLSDESC_CALL] = {0, FLG_RE_NOTSUP, 0, 0, 0},	      /* 569 */
	[R_AARCH64_TLSLE_LDST128_TPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 570 */
	[R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 571 */
	[R_AARCH64_TLSLD_LDST128_DTPREL_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 572 */
	[R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 573 */
	[574] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[575] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[576] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[577] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[578] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[579] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[R_AARCH64_AUTH_ABS64] = {0, FLG_RE_NOTSUP, 0, 0, 0},			/* 580 */
	[R_AARCH64_AUTH_MOVW_GOTOFF_G0] = {0, FLG_RE_NOTSUP, 0, 0, 0},		/* 581 */
	[R_AARCH64_AUTH_MOVW_GOTOFF_G0_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 582 */
	[R_AARCH64_AUTH_MOVW_GOTOFF_G1] = {0, FLG_RE_NOTSUP, 0, 0, 0},		/* 583 */
	[R_AARCH64_AUTH_MOVW_GOTOFF_G1_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 584 */
	[R_AARCH64_AUTH_MOVW_GOTOFF_G2] = {0, FLG_RE_NOTSUP, 0, 0, 0},		/* 585 */
	[R_AARCH64_AUTH_MOVW_GOTOFF_G2_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 586 */
	[R_AARCH64_AUTH_MOVW_GOTOFF_G3] = {0, FLG_RE_NOTSUP, 0, 0, 0},		/* 587 */
	[R_AARCH64_AUTH_GOT_LD_PREL19] = {0, FLG_RE_NOTSUP, 0, 0, 0},		/* 588 */
	[R_AARCH64_AUTH_LD64_GOTOFF_LO15] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 589 */
	[R_AARCH64_AUTH_ADR_GOT_PAGE] = {0, FLG_RE_NOTSUP, 0, 0, 0},		/* 590 */
	[R_AARCH64_AUTH_LD64_GOT_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 591 */
	[R_AARCH64_AUTH_LD64_GOTPAGE_LO15] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 592 */
	[R_AARCH64_AUTH_GOT_ADD_LO12_NC] = {0, FLG_RE_NOTSUP, 0, 0, 0},		/* 593 */
	[R_AARCH64_AUTH_GOT_ADR_PREL_LO21] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 594 */
	[R_AARCH64_AUTH_TLSDESC_ADR_PAGE21] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 595 */
	[R_AARCH64_AUTH_TLSDESC_LD64_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 596 */
	[R_AARCH64_AUTH_TLSDESC_ADD_LO12] = {0, FLG_RE_NOTSUP, 0, 0, 0},	/* 597 */
	[598] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[599] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[600] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[601] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[602] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[603] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[604] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[605] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[606] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[607] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[608] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[609] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[610] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[611] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[612] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[613] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[614] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[615] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[616] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[617] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[618] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[619] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[620] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[621] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[622] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[623] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[624] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[625] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[626] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[627] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[628] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[629] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[630] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[631] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[632] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[633] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[634] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[635] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[636] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[637] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[638] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[639] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[640] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[641] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[642] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[643] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[644] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[645] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[646] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[647] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[648] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[649] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[650] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[651] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[652] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[653] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[654] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[655] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[656] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[657] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[658] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[659] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[660] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[661] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[662] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[663] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[664] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[665] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[666] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[667] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[668] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[669] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[670] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[671] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[672] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[673] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[674] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[675] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[676] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[677] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[678] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[679] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[680] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[681] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[682] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[683] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[684] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[685] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[686] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[687] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[688] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[689] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[690] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[691] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[692] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[693] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[694] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[695] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[696] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[697] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[698] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[699] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[700] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[701] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[702] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[703] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[704] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[705] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[706] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[707] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[708] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[709] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[710] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[711] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[712] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[713] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[714] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[715] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[716] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[717] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[718] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[719] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[720] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[721] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[722] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[723] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[724] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[725] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[726] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[727] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[728] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[729] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[730] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[731] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[732] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[733] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[734] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[735] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[736] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[737] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[738] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[739] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[740] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[741] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[742] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[743] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[744] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[745] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[746] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[747] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[748] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[749] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[750] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[751] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[752] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[753] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[754] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[755] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[756] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[757] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[758] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[759] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[760] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[761] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[762] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[763] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[764] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[765] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[766] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[767] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[768] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[769] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[770] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[771] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[772] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[773] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[774] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[775] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[776] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[777] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[778] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[779] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[780] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[781] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[782] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[783] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[784] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[785] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[786] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[787] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[788] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[789] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[790] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[791] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[792] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[793] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[794] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[795] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[796] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[797] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[798] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[799] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[800] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[801] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[802] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[803] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[804] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[805] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[806] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[807] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[808] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[809] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[810] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[811] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[812] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[813] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[814] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[815] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[816] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[817] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[818] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[819] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[820] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[821] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[822] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[823] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[824] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[825] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[826] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[827] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[828] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[829] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[830] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[831] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[832] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[833] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[834] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[835] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[836] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[837] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[838] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[839] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[840] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[841] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[842] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[843] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[844] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[845] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[846] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[847] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[848] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[849] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[850] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[851] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[852] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[853] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[854] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[855] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[856] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[857] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[858] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[859] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[860] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[861] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[862] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[863] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[864] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[865] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[866] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[867] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[868] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[869] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[870] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[871] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[872] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[873] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[874] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[875] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[876] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[877] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[878] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[879] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[880] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[881] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[882] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[883] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[884] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[885] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[886] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[887] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[888] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[889] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[890] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[891] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[892] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[893] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[894] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[895] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[896] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[897] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[898] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[899] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[900] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[901] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[902] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[903] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[904] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[905] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[906] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[907] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[908] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[909] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[910] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[911] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[912] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[913] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[914] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[915] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[916] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[917] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[918] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[919] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[920] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[921] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[922] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[923] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[924] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[925] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[926] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[927] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[928] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[929] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[930] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[931] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[932] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[933] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[934] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[935] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[936] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[937] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[938] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[939] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[940] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[941] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[942] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[943] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[944] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[945] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[946] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[947] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[948] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[949] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[950] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[951] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[952] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[953] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[954] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[955] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[956] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[957] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[958] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[959] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[960] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[961] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[962] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[963] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[964] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[965] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[966] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[967] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[968] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[969] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[970] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[971] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[972] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[973] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[974] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[975] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[976] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[977] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[978] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[979] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[980] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[981] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[982] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[983] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[984] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[985] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[986] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[987] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[988] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[989] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[990] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[991] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[992] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[993] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[994] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[995] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[996] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[997] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[998] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[999] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1000] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1001] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1002] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1003] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1004] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1005] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1006] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1007] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1008] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1009] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1010] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1011] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1012] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1013] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1014] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1015] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1016] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1017] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1018] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1019] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1020] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1021] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1022] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[1023] = {0, FLG_RE_NOTSUP, 0, 0, 0},
	[R_AARCH64_COPY] = {0, FLG_RE_NOTREL, 0, 0, 0}, /* 1024 */
	[R_AARCH64_GLOB_DAT] = {0, FLG_RE_NOTREL, 8, 0, 0}, /* 1025 */
	[R_AARCH64_JUMP_SLOT] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* SPECIAL */ /* 1026 */
	[R_AARCH64_RELATIVE] = {0, FLG_RE_NOTREL, 8, 0, 0},  /* 1027 */
	[R_AARCH64_TLS_DTPREL] = {0, FLG_RE_NOTREL, 8, 0, 0}, /* 1028 */
	[R_AARCH64_TLS_DTPMOD] = {0, FLG_RE_NOTREL, 8, 0, 0}, /* 1029 */
	[R_AARCH64_TLS_TPREL] = {0, FLG_RE_NOTREL, 8, 0, 0},  /* 1030 */
	[R_AARCH64_TLSDESC] = {0, FLG_RE_NOTSUP, 0, 0, 0},    /* 1031 */
	[R_AARCH64_IRELATIVE] = {0, FLG_RE_NOTSUP, 0, 0, 0},  /* 1032 */
	[1033] = {0, FLG_RE_NOTSUP, 0, 0, 0},		      /* 1033 */
	[1034] = {0, FLG_RE_NOTSUP, 0, 0, 0},		      /* 1034 */
	[1035] = {0, FLG_RE_NOTSUP, 0, 0, 0},		      /* 1035 */
	[1036] = {0, FLG_RE_NOTSUP, 0, 0, 0},		      /* 1036 */
	[1037] = {0, FLG_RE_NOTSUP, 0, 0, 0},		      /* 1037 */
	[1038] = {0, FLG_RE_NOTSUP, 0, 0, 0},		      /* 1038 */
	[1039] = {0, FLG_RE_NOTSUP, 0, 0, 0},		      /* 1039 */
	[1040] = {0, FLG_RE_NOTSUP, 0, 0, 0},		      /* 1040 */
	[R_AARCH64_AUTH_RELATIVE] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 1041 */
	[R_AARCH64_AUTH_GLOB_DAT] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 1042 */
	[R_AARCH64_AUTH_TLSDESC] = {0, FLG_RE_NOTSUP, 0, 0, 0},	 /* 1043 */
	[R_AARCH64_AUTH_IRELATIVE] = {0, FLG_RE_NOTSUP, 0, 0, 0}, /* 1044 */
};

static inline int64_t
signextend64(uint64_t x, unsigned int bits)
{
	return ((int64_t)(x << (64 - bits))) >> (64 - bits);
}

/*
 * Write a single relocated value to its reference location.  We assume we
 * wish to add the relocation amount, value, to the value of the address
 * already present at the offset.
 *
 * NAME			VALUE	FIELD	CALCULATION
 * R_AARCH64_PREL32	261	imm32	S+A-P
 * R_AARCH64_CALL26	283	imm26	(((S+A-P) >> 2) & 0x3ffffff)
 *
 * These are taken from ELF for the ARM 64-bit Architecture (AArch64) 2022Q1
 *
 * Relocation calculations:
 *
 * CALCULATION uses the following notation:
 *
 *	A	The addend used to compute the value of the relocatable field
 *
 *	S	The symbol whos index resides in the relocation entry
 *
 *	P	The place (section offset or address) of the storage unit being
 *		relocated (computed using r_offset).
 */
#if defined(_KERNEL)
#define	lml	0		/* Needed by arglist of REL_ERR_* macros */
int
do_reloc_krtld(Word rtype, uchar_t *off, Xword *value, const char *sym,
    const char *file)
#elif defined(DO_RELOC_LIBLD)
/*ARGSUSED5*/
int
do_reloc_ld(Rel_desc *rdesc, uchar_t *off, Xword *value,
    rel_desc_sname_func_t rel_desc_sname_func,
    const char *file, int bswap, void *lml)
#else
int
do_reloc_rtld(Word rtype, uchar_t *off, Xword *value, const char *sym,
    const char *file, void *lml)
#endif
{
#ifdef DO_RELOC_LIBLD
#define	sym (* rel_desc_sname_func)(rdesc)
	Word	rtype = rdesc->rel_rtype;
#endif
	Xword	base = 0, uvalue = 0;

	const	Rel_entry	*rep;

	rep = &reloc_table[rtype];

	/* XXXARM: This needs byte-swapping support */
	switch (rep->re_fsize) {
	case 1:
		base = *((uchar_t *)off);
		break;
	case 2:
		base = *((Half *)off);
		break;
	case 4:
		base = *((Word *)off);
		break;
	case 8:
		base = *((Xword *)off);
		break;
	default:
		/*
		 * To keep chkmsg() happy: MSG_INTL(MSG_REL_UNSUPSZ)
		 */
		REL_ERR_UNSUPSZ(lml, file, sym, rtype, rep->re_fsize);
		return (0);
	}

	switch (rtype) {
	case R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
	case R_AARCH64_TLSDESC_ADR_PAGE21:
	case R_AARCH64_ADR_GOT_PAGE:
	case R_AARCH64_ADR_PREL_PG_HI21:
	case R_AARCH64_TLSGD_ADR_PAGE21:
		if (signextend64(*value, 33) != *value) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}

		/* FALLTHROUGH */
	case R_AARCH64_ADR_PREL_PG_HI21_NC:
	{
		uvalue = *value >> 12; /* bshift */
		uint32_t lo = (uvalue & 0x3) << 29;
		uint32_t hi = (uvalue & 0x1ffffc) << 3;
		uint64_t mask = (0x3 << 29) | (0x1ffffc << 3); /* bmask */

		uvalue = (base & ~mask) | lo | hi;

		base = 0;
		break;
	}
	case R_AARCH64_ADR_PREL_LO21: {
		uvalue = *value;
		uint32_t lo = (uvalue & 0x3) << 29;
		uint32_t hi = (uvalue & 0x1ffffc) << 3;
		uint64_t mask = (0x3 << 29) | (0x1ffffc << 3); /* bmask */

		if (signextend64(*value, 21) != *value) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}

		uvalue = (base & ~mask) | lo | hi;

		base = 0;
		break;
	}

	case R_AARCH64_ADD_ABS_LO12_NC: {
		uvalue = *value;
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;
	}

	case R_AARCH64_LDST64_ABS_LO12_NC:
	case R_AARCH64_LD64_GOT_LO12_NC:
	case R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
	case R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC:
	case R_AARCH64_TLSDESC_LD64_LO12:
	{
		if (!IS_P2ALIGNED(*value, 8)) {
			REL_ERR_VALNONALIGN(lml, file, sym, rtype, off);
			return (0);
		}

		uvalue = *value;
		uvalue = (uvalue >> 3) & 0x1ff;
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;
	}

	case R_AARCH64_MOVW_UABS_G0:
		if ((signextend64(*value, 16) != *value) ||
		    ((*value >> 16) != 0)) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}
		/* FALLTHROUGH */
	case R_AARCH64_MOVW_UABS_G0_NC:
		uvalue = *value;
		uvalue = base | ((uvalue & 0xffff) << 5);
		base = 0;
		break;

	case R_AARCH64_MOVW_UABS_G1:
		if ((signextend64(*value, 32) != *value) ||
		    ((*value >> 32) != 0)) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}
		/* FALLTHROUGH */
	case R_AARCH64_MOVW_UABS_G1_NC:
		uvalue = *value;
		uvalue = base | ((uvalue & 0xffff0000) >> 11);
		base = 0;
		break;

	case R_AARCH64_MOVW_UABS_G2:
		if ((signextend64(*value, 48) != *value) ||
		    ((*value >> 48) != 0)) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}
		/* FALLTHROUGH */
	case R_AARCH64_MOVW_UABS_G2_NC:
		uvalue = *value;
		uvalue = base | ((uvalue & 0xffff00000000) >> 27);
		base = 0;
		break;

	case R_AARCH64_MOVW_UABS_G3:
		uvalue = *value;
		uvalue = base | ((uvalue & 0xffff000000000000) >> 43);
		base = 0;
		break;

	case R_AARCH64_LDST8_ABS_LO12_NC:
	case R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC:
		uvalue = *value;
		uvalue = uvalue & 0xfff;
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;

	case R_AARCH64_LDST32_ABS_LO12_NC:
	case R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC:
		uvalue = *value;
		uvalue = (uvalue >> 2) & 0x3ff;
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;

	case R_AARCH64_LD64_GOTPAGE_LO15:
		if (!IS_P2ALIGNED(*value, 8)) {
			REL_ERR_VALNONALIGN(lml, file, sym, rtype, off);
			return (0);
		}

		uvalue = *value;
		uvalue = (uvalue >> 3) & 0xfff;
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;

	case R_AARCH64_LDST128_ABS_LO12_NC:
	case R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC:
		if (!IS_P2ALIGNED(*value, 16)) {
			REL_ERR_VALNONALIGN(lml, file, sym, rtype, off);
			return (0);
		}

		uvalue = *value;
		uvalue = (uvalue >> 4) & 0xff;
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;

	case R_AARCH64_LDST16_ABS_LO12_NC:
	case R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC:
		if (!IS_P2ALIGNED(*value, 2)) {
			REL_ERR_VALNONALIGN(lml, file, sym, rtype, off);
			return (0);
		}

		uvalue = *value;
		uvalue = (uvalue >> 1) & 0x7ff;
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;

	case R_AARCH64_LD_PREL_LO19:
	case R_AARCH64_CONDBR19:
		if (!IS_P2ALIGNED(*value, 4)) {
			REL_ERR_VALNONALIGN(lml, file, sym, rtype, off);
			return (0);
		}

		if (signextend64(*value, 21) != *value) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}

		uvalue = *value;
		uvalue = base | ((uvalue & 0x1ffffc) << 3);
		base = 0;
		break;

	/* XXXARM: Apparently there may be errata here */
	case R_AARCH64_JUMP26:
	case R_AARCH64_CALL26:
		if (signextend64(*value, 28) != *value) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}

		uvalue = *value;
		uvalue = base | ((uvalue & 0x0ffffffc) >> 2);
		base = 0;
		break;

	/*
	 * XXXARM: I'm doubtful the behaviour of signed relocations is correct
	 * for negative values
	 */
	case R_AARCH64_ABS16:
	case R_AARCH64_PREL16:
		if ((signextend64(*value, 16) != *value) ||
		    (((*value >> 16) != 0) &&
		    ((*value >> 16) != 0xffffffffffff))) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}
		uvalue = *value;
		break;

	/*
	 * XXXARM: I'm doubtful the behaviour of signed relocations is correct
	 * for negative values
	 */
	case R_AARCH64_ABS32:
	case R_AARCH64_PREL32:
		if ((signextend64(*value, 32) != *value) ||
		    (((*value >> 32) != 0) && ((*value >> 32) != 0xffffffff))) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}
		uvalue = *value;
		break;

	case R_AARCH64_TLSLE_ADD_TPREL_HI12:
		if ((signextend64(*value, 24) != *value) ||
		    ((*value >> 24) != 0)) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}

		uvalue = *value;
		uvalue = (uvalue >> 12);
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;

	case R_AARCH64_TLSLE_ADD_TPREL_LO12:
		if ((signextend64(*value, 12) != *value) ||
		    ((*value >> 12) != 0)) {
			REL_ERR_NOFIT(lml, file, sym, rtype, *value);
			return (0);
		}
		/* FALLTHROUGH */
	case R_AARCH64_TLSLE_ADD_TPREL_LO12_NC:
	case R_AARCH64_TLSGD_ADD_LO12_NC:
		uvalue = *value;
		uvalue = base | ((uvalue & 0xfff) << 10);
		base = 0;
		break;

	case R_AARCH64_ABS64:
	case R_AARCH64_PREL64:
		uvalue = *value;
		break;

	case R_AARCH64_TLSDESC:
		/* XXXARM: Apparently we have to write off+8 for this */
#if defined(DO_RELOC_LIBLD)
		assert(0 && "R_AARCH64_TLSDESC is weird");
#endif
		break;

	case R_AARCH64_GLOB_DAT:
	case R_AARCH64_JUMP_SLOT:
	case R_AARCH64_RELATIVE:
	case R_AARCH64_COPY:
	case R_AARCH64_TLS_DTPREL:
	case R_AARCH64_TLS_DTPMOD:
	case R_AARCH64_TLS_TPREL:
	case R_AARCH64_IRELATIVE:
		uvalue = *value;
		break;
	default:
#if defined(DO_RELOC_LIBLD)
		assert(0 && "Relocation improperly added");
#endif
		break;
	}

	switch (rep->re_fsize) {
	case 1:
		*((uchar_t *)off) = (base + uvalue);
		break;
	case 2:
		*((Half *)off) = (base + uvalue);
		break;
	case 4:
		*((Word *)off) = (base + uvalue);
		break;
	case 8:
		*((Xword *)off) = (base + uvalue);
		break;
	}
	return (1);

#ifdef DO_RELOC_LIBLD
#undef sym
#endif
}
