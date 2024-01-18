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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2022 Racktop Systems, Inc.
 */

#define	KEYMAP_SIZE_VARIABLE

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/kbd.h>
#include <sys/kbtrans.h>
#include <sys/sunddi.h>
#include <sys/consdev.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>
#include "hv_kbd.h"

/*
 * This is largely copied from usr/src/uts/common/io/kb8042/at_keyprocess.c
 * and the USB conversion table from kb8042/kb8042.c.
 *
 * The scan codes emitted by the Hyper-V keyboard driver appear (from
 * inspection) to match the PS/2 AT scan codes, however due to a lack of
 * documentation, there is no way to confirm that it follows exactly.
 *
 * As such, we duplicate the keymapping from kb8042 so if any divergence
 * is discovered, it can be fixed easily.
 */

/*
 * A note on the use of prom_printf here:  Most of these routines can be
 * called from "polled mode", where we're servicing I/O requests from kmdb.
 * Normal system services are not available from polled mode; cmn_err will
 * not work.  prom_printf is the only safe output mechanism.
 */

#define	KEYBAD		0xff		/* should generate an error */
#define	KEYIGN		0xfe		/* ignore this sequence */

#define	KEY(code)	(code)
#define	INVALID		KEYBAD
#define	IGNORE		KEYIGN

/*
 * These are the states of our parsing machine:
 */
#define	STATE_IDLE	0x00000001 /* Awaiting the start of a sequence */
#define	STATE_E0	0x00000002 /* Rec'd an E0 */
#define	STATE_E1	0x00000004 /* Rec'd an E1 (Pause key only) */
#define	STATE_E1_1D	0x00000008 /* Rec'd an E1 1D (Pause key only) */
#define	STATE_E1_14	0x00000010 /* Rec'd an E1 14 (Pause key only) */
#define	STATE_E1_14_77			0x00000020
#define	STATE_E1_14_77_E1		0x00000040
#define	STATE_E1_14_77_E1_F0		0x00000080
#define	STATE_E1_14_77_E1_F0_14		0x00000100
#define	STATE_E1_14_77_E1_F0_14_F0	0x00000200

static const unsigned char keytab_base_set[] = {
	/* scan		key number	keycap */
	/* 00 */	INVALID,
	/* 01 */	KEY(110),	/* Esc */
	/* 02 */	KEY(2),		/* 1 */
	/* 03 */	KEY(3),		/* 2 */
	/* 04 */	KEY(4),		/* 3 */
	/* 05 */	KEY(5),		/* 4 */
	/* 06 */	KEY(6),		/* 5 */
	/* 07 */	KEY(7),		/* 6 */
	/* 08 */	KEY(8),		/* 7 */
	/* 09 */	KEY(9),		/* 8 */
	/* 0a */	KEY(10),	/* 9 */
	/* 0b */	KEY(11),	/* 0 */
	/* 0c */	KEY(12),	/* - */
	/* 0d */	KEY(13),	/* = */
	/* 0e */	KEY(15),	/* backspace */
	/* 0f */	KEY(16),	/* tab */

	/* 10 */	KEY(17),	/* Q */
	/* 11 */	KEY(18),	/* W */
	/* 12 */	KEY(19),	/* E */
	/* 13 */	KEY(20),	/* R */
	/* 14 */	KEY(21),	/* T */
	/* 15 */	KEY(22),	/* Y */
	/* 16 */	KEY(23),	/* U */
	/* 17 */	KEY(24),	/* I */
	/* 18 */	KEY(25),	/* O */
	/* 19 */	KEY(26),	/* P */
	/* 1a */	KEY(27),	/* [ */
	/* 1b */	KEY(28),	/* ] */
	/* 1c */	KEY(43),	/* Enter (main) */
	/* 1d */	KEY(58),	/* L Ctrl */
	/* 1e */	KEY(31),	/* A */
	/* 1f */	KEY(32),	/* S */

	/* 20 */	KEY(33),	/* D */
	/* 21 */	KEY(34),	/* F */
	/* 22 */	KEY(35),	/* G */
	/* 23 */	KEY(36),	/* H */
	/* 24 */	KEY(37),	/* J */
	/* 25 */	KEY(38),	/* K */
	/* 26 */	KEY(39),	/* L */
	/* 27 */	KEY(40),	/* ; */
	/* 28 */	KEY(41),	/* ' */
	/* 29 */	KEY(1),		/* ` */
	/* 2a */	KEY(44),	/* L Shift */
	/* 2b */	KEY(29),	/* \ */
	/* 2c */	KEY(46),	/* Z */
	/* 2d */	KEY(47),	/* X */
	/* 2e */	KEY(48),	/* C */
	/* 2f */	KEY(49),	/* V */

	/* 30 */	KEY(50),	/* B */
	/* 31 */	KEY(51),	/* N */
	/* 32 */	KEY(52),	/* M */
	/* 33 */	KEY(53),	/* , */
	/* 34 */	KEY(54),	/* . */
	/* 35 */	KEY(55),	/* / */
	/* 36 */	KEY(57),	/* R Shift */
	/* 37 */	KEY(100),	/* * (num) */
	/* 38 */	KEY(60),	/* L Alt */
	/* 39 */	KEY(61),	/* Space */
	/* 3a */	KEY(30),	/* CapsLock */
	/* 3b */	KEY(112),	/* F1 */
	/* 3c */	KEY(113),	/* F2 */
	/* 3d */	KEY(114),	/* F3 */
	/* 3e */	KEY(115),	/* F4 */
	/* 3f */	KEY(116),	/* F5 */

	/* 40 */	KEY(117),	/* F6 */
	/* 41 */	KEY(118),	/* F7 */
	/* 42 */	KEY(119),	/* F8 */
	/* 43 */	KEY(120),	/* F9 */
	/* 44 */	KEY(121),	/* F10 */
	/* 45 */	KEY(90),	/* NumLock */
	/* 46 */	KEY(125),	/* Scroll Lock */
	/* 47 */	KEY(91),	/* 7 (num) */
	/* 48 */	KEY(96),	/* 8 (num) */
	/* 49 */	KEY(101),	/* 9 (num) */
	/* 4a */	KEY(105),	/* - (num) */
	/* 4b */	KEY(92),	/* 4 (num) */
	/* 4c */	KEY(97),	/* 5 (num) */
	/* 4d */	KEY(102),	/* 6 (num) */
	/* 4e */	KEY(106),	/* + (num) */
	/* 4f */	KEY(93),	/* 1 (num) */

	/* 50 */	KEY(98),	/* 2 (num) */
	/* 51 */	KEY(103),	/* 3 (num) */
	/* 52 */	KEY(99),	/* 0 (num) */
	/* 53 */	KEY(104),	/* . (num) */
	/* 54 */	KEY(124),	/* PrintScreen (with Alt) */
	/* 55 */	INVALID,
	/* 56 */	KEY(45),	/* not labled (102-key only) */
	/* 57 */	KEY(122),	/* F11 */
	/* 58 */	KEY(123),	/* F12 */
	/* 59 */	INVALID,
	/* 5a */	INVALID,
	/* 5b */	INVALID,
	/* 5c */	INVALID,
	/* 5d */	INVALID,
	/* 5e */	INVALID,
	/* 5f */	INVALID,

	/* 60 */	INVALID,
	/* 61 */	INVALID,
	/* 62 */	INVALID,
	/* 63 */	INVALID,
	/* 64 */	INVALID,
	/* 65 */	INVALID,
	/* 66 */	INVALID,
	/* 67 */	INVALID,
	/* 68 */	INVALID,
	/* 69 */	INVALID,
	/* 6a */	INVALID,
	/* 6b */	INVALID,
	/* 6c */	INVALID,
	/* 6d */	INVALID,
	/* 6e */	INVALID,
	/* 6f */	INVALID,

	/* 70 */	KEY(133),	/* Japanese 106-key keyboard */
	/* 71 */	INVALID,
	/* 72 */	INVALID,
	/* 73 */	KEY(56),	/* Japanese 106-key keyboard */
	/* 74 */	INVALID,
	/* 75 */	INVALID,
	/* 76 */	INVALID,
	/* 77 */	INVALID,
	/* 78 */	INVALID,
	/* 79 */	KEY(132),	/* Japanese 106-key keyboard */
	/* 7a */	INVALID,
	/* 7b */	KEY(131),	/* Japanese 106-key keyboard */
	/* 7c */	INVALID,
	/* 7d */	KEY(14),	/* Japanese 106-key keyboard */
	/* 7e */	INVALID,
	/* 7f */	INVALID,
};

/*
 * Parse table after receiving an E0 prefix code.
 *
 * Generally speaking, keys that were added on the 101-key keyboard are
 * represented as an E0 followed by the code for an 84-key key.  Software
 * ignorant of the 101-key keyboard ignores the E0 and so is handled
 * compatibly.  Many of these variants involve "fake" shift presses
 * and releases for compatibility; these are also prefixed with E0.
 * We ignore these fake shifts.
 */
static const unsigned char keytab_e0_set[] = {
	/* 00 */	INVALID,
	/* 01 */	INVALID,
	/* 02 */	INVALID,
	/* 03 */	INVALID,
	/* 04 */	INVALID,
	/* 05 */	INVALID,
	/* 06 */	INVALID,
	/* 07 */	INVALID,
	/* 08 */	INVALID,
	/* 09 */	INVALID,
	/* 0a */	INVALID,
	/* 0b */	INVALID,
	/* 0c */	INVALID,
	/* 0d */	INVALID,
	/* 0e */	INVALID,
	/* 0f */	INVALID,

	/* 10 */	INVALID,
	/* 11 */	INVALID,
	/* 12 */	INVALID,
	/* 13 */	INVALID,
	/* 14 */	INVALID,
	/* 15 */	INVALID,
	/* 16 */	INVALID,
	/* 17 */	INVALID,
	/* 18 */	INVALID,
	/* 19 */	INVALID,
	/* 1a */	INVALID,
	/* 1b */	INVALID,
	/* 1c */	KEY(108),	/* Enter (num) */
	/* 1d */	KEY(64),	/* R Ctrl */
	/* 1e */	INVALID,
	/* 1f */	INVALID,

	/* 20 */	KEY(235),	/* Mute */
	/* 21 */	INVALID,
	/* 22 */	INVALID,
	/* 23 */	INVALID,
	/* 24 */	INVALID,
	/* 25 */	INVALID,
	/* 26 */	INVALID,
	/* 27 */	INVALID,
	/* 28 */	INVALID,
	/* 29 */	INVALID,
	/* 2a */	INVALID,
	/* 2b */	INVALID,
	/* 2c */	INVALID,
	/* 2d */	INVALID,
	/* 2e */	KEY(234),	/* Volume Down */
	/* 2f */	INVALID,

	/* 30 */	KEY(233),	/* Volume Up */
	/* 31 */	INVALID,
	/* 32 */	INVALID,
	/* 33 */	INVALID,
	/* 34 */	INVALID,
	/* 35 */	KEY(95),	/* / (num) */
	/* 36 */	INVALID,
	/* 37 */	KEY(124),	/* PrintScreen (no Alt) */
	/* 38 */	KEY(62),	/* R Alt */
	/* 39 */	INVALID,
	/* 3a */	INVALID,
	/* 3b */	INVALID,
	/* 3c */	INVALID,
	/* 3d */	INVALID,
	/* 3e */	INVALID,
	/* 3f */	INVALID,

	/* 40 */	INVALID,
	/* 41 */	INVALID,
	/* 42 */	INVALID,
	/* 43 */	INVALID,
	/* 44 */	INVALID,
	/* 45 */	INVALID,
	/* 46 */	KEY(126),	/* Pause (with Cntl) */
	/* 47 */	KEY(80),	/* Home (arrow) */
	/* 48 */	KEY(83),	/* Up (arrow) */
	/* 49 */	KEY(85),	/* PgUp (arrow) */
	/* 4a */	INVALID,
	/* 4b */	KEY(79),	/* Left (arrow) */
	/* 4c */	INVALID,
	/* 4d */	KEY(89),	/* Right (arrow) */
	/* 4e */	INVALID,
	/* 4f */	KEY(81),	/* End (arrow) */

	/* 50 */	KEY(84),	/* Down (arrow) */
	/* 51 */	KEY(86),	/* PgDn (arrow) */
	/* 52 */	KEY(75),	/* Insert (arrow) */
	/* 53 */	KEY(76),	/* Delete (arrow) */
	/* 54 */	INVALID,
	/* 55 */	INVALID,
	/* 56 */	INVALID,
	/* 57 */	INVALID,
	/* 58 */	INVALID,
	/* 59 */	INVALID,
	/* 5a */	INVALID,
	/* 5b */	KEY(59),	/* L Window (104-key) */
	/* 5c */	KEY(63),	/* R Window (104-key) */
	/* 5d */	KEY(65),	/* Menu (104-key) */
	/* 5e */	INVALID,
	/* 5f */	INVALID,

	/* 60 */	INVALID,
	/* 61 */	INVALID,
	/* 62 */	INVALID,
	/* 63 */	INVALID,
	/* 64 */	INVALID,
	/* 65 */	INVALID,
	/* 66 */	INVALID,
	/* 67 */	INVALID,
	/* 68 */	INVALID,
	/* 69 */	INVALID,
	/* 6a */	INVALID,
	/* 6b */	INVALID,
	/* 6c */	INVALID,
	/* 6d */	INVALID,
	/* 6e */	INVALID,
	/* 6f */	INVALID,

	/* 70 */	INVALID,
	/* 71 */	INVALID,
	/* 72 */	INVALID,
	/* 73 */	INVALID,
	/* 74 */	INVALID,
	/* 75 */	INVALID,
	/* 76 */	INVALID,
	/* 77 */	INVALID,
	/* 78 */	INVALID,
	/* 79 */	INVALID,
	/* 7a */	INVALID,
	/* 7b */	INVALID,
	/* 7c */	INVALID,
	/* 7d */	INVALID,
	/* 7e */	INVALID,
};


/*
 * For any keyboard, there is a unique code describing the position
 * of the key on a keyboard. We refer to the code as "station number".
 * The following table is used to map the station numbers from ps2
 * AT/XT keyboards to that of a USB one.
 *
 * A mapping was added for entry K8042_STOP, to map to USB key code 120 (which
 * maps to the STOP key) when in KB_USB mode, and maps to a HOLE entry
 * when in KB_PC mode.  Note that this does not need to be made conditional
 * on the architecture for which this module is complied because there are no
 * keys that map to K8042_STOP on non-SPARC platforms.
 */
static kbtrans_key_t keytab_hv2usb[KBTRANS_KEYNUMS_MAX] = {
/*  0 */	0,	53,	30,	31,	32,	33,	34,	35,
/*  8 */	36,	37,	38,	39,	45,	46,	137,	42,
/* 16 */	43,	20,	26,	8,	21,	23,	28,	24,
/* 24 */	12,	18,	19,	47,	48,	49,	57,	4,
/* 32 */	22,	7,	9,	10,	11,	13,	14,	15,
/* 40 */	51,	52,	50,	40,	225,	100,	29,	27,
/* 48 */	6,	25,	5,	17,	16,	54,	55,	56,
/* 56 */	135,	229,	224,	227,	226,	44,	230,	231,
/* 64 */	228,	101,	0,	0,	0,	0,	0,	0,
/* 72 */	0,	0,	0,	73,	76,	0,	0,	80,
/* 80 */	74,	77,	0,	82,	81,	75,	78,	0,
/* 88 */	0,	79,	83,	95,	92,	89,	0,	84,
/* 96 */	96,	93,	90,	98,	85,	97,	94,	91,
/* 104 */	99,	86,	87,	133,	88,	0,	41,	0,
/* 112 */	58,	59,	60,	61,	62,	63,	64,	65,
/* 120 */	66,	67,	68,	69,	70,	71,	72,	0,
/* 128 */	0,	0,	0,	139,	138,	136,	0,	0,
/* 136 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 144 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 152 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 160 */	120,	0,	0,	0,	0,	0,	0,	0,
/* 168 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 176 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 184 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 192 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 200 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 208 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 216 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 224 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 232 */	0,	128,	129,	127,	0,	0,	0,	0,
/* 240 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 248 */	0,	0,	0,	0
};

boolean_t
hv_kbd_convert_scan(hv_kbd_sc_t *sc, const hv_keystroke_t *ks, int *keynum,
    enum keystate *state)
{
	uint16_t scancode = KS_SCANCODE(ks);

	*state = KS_IS_BREAK(ks) ? KEY_RELEASED : KEY_PRESSED;

	if (KS_IS_E0(ks)) {
		if (scancode < ARRAY_SIZE(keytab_e0_set))
			*keynum = keytab_e0_set[scancode];
		else
			*keynum = INVALID;
	} else if (KS_IS_E1(ks)) {
		/* XXX ignore for now -- E1 1D 45 -> KEY(126) -- pause */
	} else if (KS_IS_UNICODE(ks)) {
		/*
		 * The Hyper-V keyboard driver can convert a paste in the
		 * console window into keystrokes. Unicode characters pasted
		 * in the window will have this flag set. For now we just
		 * ignore.
		 */
		return (B_FALSE);
	} else {
		if (scancode < ARRAY_SIZE(keytab_base_set))
			*keynum = keytab_base_set[scancode];
		else
			*keynum = INVALID;
	}

	if (sc->hk_vkbd_type == KB_USB && *keynum != INVALID) {
		VERIFY3S(*keynum, >=, 0);
		VERIFY3S(*keynum, <=, 255);
		*keynum = keytab_hv2usb[*keynum];
	}

	return (B_TRUE);
}
