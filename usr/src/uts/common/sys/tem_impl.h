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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2021 RackTop Systems, Inc.
 */

#ifndef	_SYS_TEM_IMPL_H
#define	_SYS_TEM_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/font.h>
#include <sys/rgb.h>
#if !defined(_BOOT)
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/visual_io.h>
#include <sys/list.h>
#include <sys/tem.h>
#include <sys/note.h>
#endif

/*
 * Definitions for ANSI x3.64 terminal control language parser.
 * With UTF-8 support we use 32-bit value for Unicode codepoints.
 *
 * However, as we only need 21 bits for unicode char, we will use the
 * rest of the bits for attributes, so we can save memory and
 * have combined attribute+char in screen buffer. This will also allow us
 * to keep better track about attributes and apply other optimizations.
 *
 * This setup will give us 11 bits for attributes (mask 0x7FF).
 *  Bits  Meaning
 *  0-20  char
 * 21-31  attributes
 *
 * The current implementation is building the screen buffer in three parts,
 * tvs_screen_buf is implementing the character array and the foreground
 * and the background colors have tvs_fg_color and tvs_bg_color arrays.
 * The character and color arrays are currently only used to restore the
 * screen from tem switch (vt switch, or switch from Xorg session).
 * To implement the console history, this buffering needs to be reviewed.
 */

#define	TEM_ATTR_MASK		0x7FF
#define	TEM_CHAR(c)		((c) & 0x1fffff)
#define	TEM_CHAR_ATTR(c)	(((c) >> 21) & TEM_ATTR_MASK)
#define	TEM_ATTR(c)		(((c) & TEM_ATTR_MASK) << 21)
#define	TEM_ATTR_ISSET(c, a)	((TEM_CHAR_ATTR(c) & (a)) == (a))

#define	TEM_MAXPARAMS	32	/* maximum number of ANSI paramters */
#define	TEM_MAXFKEY	30	/* max length of function key with <ESC>Q */

#define	TEM_SCROLL_UP		0
#define	TEM_SCROLL_DOWN		1
#define	TEM_SHIFT_LEFT		0
#define	TEM_SHIFT_RIGHT		1

/* Attributes 0-0x7ff */
#define	TEM_ATTR_NORMAL		0x0000
#define	TEM_ATTR_REVERSE	0x0001
#define	TEM_ATTR_BOLD		0x0002
#define	TEM_ATTR_BLINK		0x0004
#define	TEM_ATTR_UNDERLINE	0x0008
#define	TEM_ATTR_SCREEN_REVERSE	0x0010
#define	TEM_ATTR_BRIGHT_FG	0x0020
#define	TEM_ATTR_BRIGHT_BG	0x0040
#define	TEM_ATTR_TRANSPARENT	0x0080
#define	TEM_ATTR_IMAGE		0x0100
#define	TEM_ATTR_RGB_FG		0x0200
#define	TEM_ATTR_RGB_BG		0x0400

#define	ANSI_COLOR_BLACK	0
#define	ANSI_COLOR_RED		1
#define	ANSI_COLOR_GREEN	2
#define	ANSI_COLOR_BROWN	3
#define	ANSI_COLOR_BLUE		4
#define	ANSI_COLOR_MAGENTA	5
#define	ANSI_COLOR_CYAN		6
#define	ANSI_COLOR_WHITE	7

#define	TEM_TEXT_WHITE		0
#define	TEM_TEXT_BLACK		1
#define	TEM_TEXT_BLACK24_RED	0x00
#define	TEM_TEXT_BLACK24_GREEN	0x00
#define	TEM_TEXT_BLACK24_BLUE	0x00
#define	TEM_TEXT_WHITE24_RED	0xff
#define	TEM_TEXT_WHITE24_GREEN	0xff
#define	TEM_TEXT_WHITE24_BLUE	0xff

#define	A_STATE_START			0
#define	A_STATE_ESC			1
#define	A_STATE_CSI			2
#define	A_STATE_CSI_QMARK		3
#define	A_STATE_CSI_EQUAL		4

/*
 * Default number of rows and columns
 */
#ifdef _HAVE_TEM_FIRMWARE
#define	TEM_DEFAULT_ROWS	34
#define	TEM_DEFAULT_COLS	80
#else
#define	TEM_DEFAULT_ROWS	25
#define	TEM_DEFAULT_COLS	80
#endif

/*
 * Default foreground/background color
 */

#define	DEFAULT_ANSI_FOREGROUND	ANSI_COLOR_WHITE
#define	DEFAULT_ANSI_BACKGROUND	ANSI_COLOR_BLACK

typedef uint32_t tem_char_t;	/* 32bit char to support UTF-8 */
typedef union {
	uint32_t n;
	struct bgra {
		uint8_t b;
		uint8_t g;
		uint8_t r;
		uint8_t a;
	} rgb;
} text_color_t;
typedef uint16_t text_attr_t;

#if !defined(_BOOT)
typedef struct tem_color {
	text_color_t	fg_color;
	text_color_t	bg_color;
	text_attr_t	a_flags;
} tem_color_t;

enum called_from { CALLED_FROM_NORMAL, CALLED_FROM_STANDALONE };

struct tem_pix_pos {
	screen_pos_t	x;
	screen_pos_t	y;
};

struct tem_char_pos {
	screen_pos_t	col;
	screen_pos_t	row;
};

struct tem_size {
	screen_size_t	width;
	screen_size_t	height;
};

/* Combined color and 32bit tem char */
typedef struct term_char {
	text_color_t	tc_fg_color;
	text_color_t	tc_bg_color;
	tem_char_t	tc_char;
} term_char_t;

/*
 * Values for tvs_stateflags.
 */
#define	TVS_AUTOWRAP	0x00000001	/* autowrap is on by default */
#define	TVS_WRAPPED	0x00000002	/* line wrap in progress */

/*
 * State structure for each virtual terminal emulator
 */
struct tem_vt_state {
	queue_t		*tvs_queue;	/* read queue for console */
	kmutex_t	tvs_lock;
	uchar_t		tvs_fbmode;	/* framebuffer mode */
	uchar_t		tvs_alpha;	/* rgb alpha channel */
	text_attr_t	tvs_flags;	/* flags for this x3.64 terminal */
	int		tvs_state;	/* state in output esc seq processing */
	uint_t		tvs_stateflags;	/* state of some features */
	boolean_t	tvs_gotparam;	/* does output esc seq have a param */

	int	tvs_curparam;	/* current param # of output esc seq */
	int	tvs_paramval;	/* value of current param */
	int	tvs_params[TEM_MAXPARAMS];  /* parameters of output esc seq */
	screen_pos_t	*tvs_tabs;	/* tab stops */
	size_t	tvs_maxtab;		/* maximum number of tab stops */
	size_t	tvs_ntabs;		/* number of tabs used */
	int	tvs_nscroll;		/* number of lines to scroll */

	struct tem_char_pos tvs_s_cursor;	/* start cursor position */
	struct tem_char_pos tvs_c_cursor;	/* current cursor position */
	struct tem_char_pos tvs_r_cursor;	/* remembered cursor position */

	term_char_t	*tvs_outbuf;	/* place to keep incomplete lines */
	size_t		tvs_outbuf_size;
	size_t		tvs_outindex;	/* index into a_outbuf */
	void		*tvs_pix_data;	/* pointer to tmp bitmap area */
	size_t		tvs_pix_data_size;

	text_color_t	tvs_fg_color;	/* console foreground */
	text_color_t	tvs_bg_color;	/* console background */

	int		tvs_first_line;	/* kernel console output begins */

	term_char_t	*tvs_screen_buf;	/* whole screen buffer */
	term_char_t	**tvs_screen_rows;	/* screen buffer rows */
	size_t		tvs_screen_buf_size;
	size_t		tvs_screen_history_size;

	unsigned	tvs_utf8_left;		/* UTF-8 code points */
	tem_char_t	tvs_utf8_partial;	/* UTF-8 char being completed */

	boolean_t	tvs_isactive;
	boolean_t	tvs_initialized;	/* initialization flag */
	boolean_t	tvs_cursor_hidden;

	list_node_t	tvs_list_node;
};
_NOTE(MUTEX_PROTECTS_DATA(tem_vt_state::tvs_lock, tem_vt_state))

typedef struct tem_safe_callbacks {
	void (*tsc_display)(struct tem_vt_state *, term_char_t *, int,
	    screen_pos_t, screen_pos_t, cred_t *, enum called_from);
	void (*tsc_copy)(struct tem_vt_state *,
	    screen_pos_t, screen_pos_t, screen_pos_t, screen_pos_t,
	    screen_pos_t, screen_pos_t, cred_t *, enum called_from);
	void (*tsc_cursor)(struct tem_vt_state *, short, cred_t *,
	    enum called_from);
	void (*tsc_bit2pix)(struct tem_vt_state *, term_char_t *);
	void (*tsc_cls)(struct tem_vt_state *, int,
	    screen_pos_t, screen_pos_t, cred_t *, enum called_from);
} tem_safe_callbacks_t;

/*
 * common term soft state structure shared by all virtual terminal emulators
 */
typedef struct tem_state {
	ldi_handle_t	ts_hdl;	/* Framework handle for layered on dev */
	screen_size_t	ts_linebytes;	/* Layered on bytes per scan line */

	int	ts_display_mode;	/* What mode we are in */
	struct	vis_polledio	*ts_fb_polledio;

	struct tem_size ts_c_dimension;	/* window dimensions in characters */
	struct tem_size ts_p_dimension;	/* screen dimensions in pixels */
	struct tem_pix_pos ts_p_offset;	/* pix offset to center the display */

	int	ts_pix_data_size;	/* size of bitmap data areas */
	int	ts_pdepth;		/* pixel depth */
	struct font	ts_font;	/* font table */

	term_char_t	*ts_blank_line;	/* a blank line for scrolling */
	tem_safe_callbacks_t	*ts_callbacks;	/* internal output functions */

	int	ts_initialized;		/* initialization flag */

	tem_modechg_cb_t	ts_modechg_cb;
	tem_modechg_cb_arg_t	ts_modechg_arg;

	color_map_fn_t	ts_color_map;

	tem_color_t	ts_init_color; /* initial color and attributes */

	struct tem_vt_state	*ts_active;
	kmutex_t	ts_lock;
	list_t		ts_list;	/* chain of all tems */
} tem_state_t;

extern tem_state_t tems;
extern tem_safe_callbacks_t tem_safe_text_callbacks;
extern tem_safe_callbacks_t tem_safe_pix_callbacks;


/*
 * tems_* fuctions mean that they just operate on the common soft state
 * (tem_state_t), and tem_* functions mean that they operate on the
 * per-tem structure (tem_vt_state). All "safe" interfaces are in tem_safe.c.
 */
int	tems_cls_layered(struct vis_consclear *, cred_t *);
void	tems_display_layered(struct vis_consdisplay *, cred_t *);
void	tems_copy_layered(struct vis_conscopy *, cred_t *);
void	tems_cursor_layered(struct vis_conscursor *, cred_t *);
void	tems_safe_copy(struct vis_conscopy *, cred_t *, enum called_from);

void	tem_align(struct tem_vt_state *, cred_t *, enum called_from);
void	tem_safe_check_first_time(struct tem_vt_state *tem, cred_t *,
	    enum called_from);
void	tem_safe_reset_display(struct tem_vt_state *, cred_t *,
	    enum called_from, boolean_t, boolean_t);
void	tem_safe_terminal_emulate(struct tem_vt_state *, uchar_t *, int,
	    cred_t *, enum called_from);
void	tem_safe_text_display(struct tem_vt_state *, term_char_t *,
	    int, screen_pos_t, screen_pos_t, cred_t *, enum called_from);
void	tem_safe_text_copy(struct tem_vt_state *,
	    screen_pos_t, screen_pos_t,
	    screen_pos_t, screen_pos_t,
	    screen_pos_t, screen_pos_t,
	    cred_t *, enum called_from);
void	tem_safe_text_cursor(struct tem_vt_state *, short, cred_t *,
	    enum called_from);
void	tem_safe_text_cls(struct tem_vt_state *,
	    int count, screen_pos_t row, screen_pos_t col,
	    cred_t *credp, enum called_from called_from);
void	tem_safe_pix_display(struct tem_vt_state *, term_char_t *,
	    int, screen_pos_t, screen_pos_t, cred_t *, enum called_from);
void	tem_safe_pix_copy(struct tem_vt_state *,
	    screen_pos_t, screen_pos_t,
	    screen_pos_t, screen_pos_t,
	    screen_pos_t, screen_pos_t,
	    cred_t *, enum called_from);
void	tem_safe_pix_cursor(struct tem_vt_state *, short, cred_t *,
	    enum called_from);
void	tem_safe_pix_bit2pix(struct tem_vt_state *, term_char_t *);
void	tem_safe_pix_cls(struct tem_vt_state *, int, screen_pos_t, screen_pos_t,
	    cred_t *, enum called_from);
void	tem_safe_pix_cls_range(struct tem_vt_state *,
	    screen_pos_t, int, int,
	    screen_pos_t, int, int,
	    boolean_t, cred_t *, enum called_from);

void	tem_safe_pix_clear_entire_screen(struct tem_vt_state *,
	    cred_t *, enum called_from);

void	tem_safe_get_attr(struct tem_vt_state *, text_color_t *,
	    text_color_t *, text_attr_t *, uint8_t);

void	tem_safe_blank_screen(struct tem_vt_state *, cred_t *,
	    enum called_from);
void	tem_safe_unblank_screen(struct tem_vt_state *, cred_t *,
	    enum called_from);
#endif	/* _BOOT */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TEM_IMPL_H */
