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
 * Copyright (c) 2012 Gary Mills
 * Copyright 2020 Joyent, Inc.
 * Copyright 2025 Michael van der Westhuizen
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Boot console support.  Most of the file is shared between dboot, and the
 * early kernel / fakebop.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/boot_console.h>
#include <sys/bootsvcs.h>
#include <sys/ctype.h>
#include <sys/framebuffer.h>
#include <sys/bootconf.h>
#include <sys/vgareg.h>
#include <sys/ascii.h>
#if defined(_STANDALONE)
#include <string.h>
#include <stdlib.h>
#else
extern int strncmp(const char *, const char *, size_t);
#endif
#include "boot_console_impl.h"

fb_info_t fb_info;
static int console = CONS_SCREEN_TEXT;
static int diag = CONS_INVALID;
static bcons_dev_t bcons_dev;

static char *boot_line;
static struct boot_env {
	char	*be_env;	/* ends with double ascii nul */
	size_t	be_size;	/* size of the environment, including nul */
} boot_env;

/*
 * Simple console terminal emulator for early boot.
 * We need this to support kmdb, all other console output is supposed
 * to be simple text output.
 */
typedef enum btem_state_type {
	A_STATE_START,
	A_STATE_ESC,
	A_STATE_CSI,
	A_STATE_CSI_QMARK,
	A_STATE_CSI_EQUAL
} btem_state_type_t;

#define	BTEM_MAXPARAMS	5
typedef struct btem_state {
	btem_state_type_t btem_state;
	boolean_t btem_gotparam;
	int btem_curparam;
	int btem_paramval;
	int btem_params[BTEM_MAXPARAMS];
} btem_state_t;

static btem_state_t boot_tem;

/* Advance str pointer past white space */
#define	EAT_WHITE_SPACE(str)	{			\
	while ((*str != '\0') && ISSPACE(*str))		\
		str++;					\
}

extern int boot_uart_ischar(void);
extern int boot_uart_getchar(void);
extern void boot_uart_putchar(int c);

#if !defined(_BOOT)
static void defcons_putchar(int);
static char *defcons_buf;
static char *defcons_cur;
static boolean_t bootprop_set_tty_mode;
#endif

/*
 * boot_line is set when we call here.  Search it for the argument name,
 * and if found, return a pointer to it.
 */
static char *
find_boot_line_prop(const char *name)
{
	char *ptr;
	char *ret = NULL;
	char end_char;
	size_t len;

	if (boot_line == NULL)
		return (NULL);

	len = strlen(name);

	/*
	 * We have two nested loops here: the outer loop discards all options
	 * except -B, and the inner loop parses the -B options looking for
	 * the one we're interested in.
	 */
	for (ptr = boot_line; *ptr != '\0'; ptr++) {
		EAT_WHITE_SPACE(ptr);

		if (*ptr == '-') {
			ptr++;
			while ((*ptr != '\0') && (*ptr != 'B') &&
			    !ISSPACE(*ptr))
				ptr++;
			if (*ptr == '\0')
				goto out;
			else if (*ptr != 'B')
				continue;
		} else {
			while ((*ptr != '\0') && !ISSPACE(*ptr))
				ptr++;
			if (*ptr == '\0')
				goto out;
			continue;
		}

		do {
			ptr++;
			EAT_WHITE_SPACE(ptr);

			if ((strncmp(ptr, name, len) == 0) &&
			    (ptr[len] == '=')) {
				ptr += len + 1;
				if ((*ptr == '\'') || (*ptr == '"')) {
					ret = ptr + 1;
					end_char = *ptr;
					ptr++;
				} else {
					ret = ptr;
					end_char = ',';
				}
				goto consume_property;
			}

			/*
			 * We have a property, and it's not the one we're
			 * interested in.  Skip the property name.  A name
			 * can end with '=', a comma, or white space.
			 */
			while ((*ptr != '\0') && (*ptr != '=') &&
			    (*ptr != ',') && (!ISSPACE(*ptr)))
				ptr++;

			/*
			 * We only want to go through the rest of the inner
			 * loop if we have a comma.  If we have a property
			 * name without a value, either continue or break.
			 */
			if (*ptr == '\0')
				goto out;
			else if (*ptr == ',')
				continue;
			else if (ISSPACE(*ptr))
				break;
			ptr++;

			/*
			 * Is the property quoted?
			 */
			if ((*ptr == '\'') || (*ptr == '"')) {
				end_char = *ptr;
				ptr++;
			} else {
				/*
				 * Not quoted, so the string ends at a comma
				 * or at white space.  Deal with white space
				 * later.
				 */
				end_char = ',';
			}

			/*
			 * Now, we can ignore any characters until we find
			 * end_char.
			 */
consume_property:
			for (; (*ptr != '\0') && (*ptr != end_char); ptr++) {
				if ((end_char == ',') && ISSPACE(*ptr))
					break;
			}
			if (*ptr && (*ptr != ',') && !ISSPACE(*ptr))
				ptr++;
		} while (*ptr == ',');
	}
out:
	return (ret);
}

/*
 * Find prop from boot env module. The data in module is list of C strings
 * name=value, the list is terminated by double nul.
 */
static const char *
find_boot_env_prop(const char *name)
{
	char *ptr;
	size_t len;
	uintptr_t size;

	if (boot_env.be_env == NULL)
		return (NULL);

	ptr = boot_env.be_env;
	len = strlen(name);

	/*
	 * Make sure we have at least len + 2 bytes in the environment.
	 * We are looking for name=value\0 constructs, and the environment
	 * itself is terminated by '\0'.
	 */
	if (boot_env.be_size < len + 2)
		return (NULL);

	do {
		if ((strncmp(ptr, name, len) == 0) && (ptr[len] == '=')) {
			ptr += len + 1;
			return (ptr);
		}
		/* find the first '\0' */
		while (*ptr != '\0') {
			ptr++;
			size = (uintptr_t)ptr - (uintptr_t)boot_env.be_env;
			if (size > boot_env.be_size)
				return (NULL);
		}
		ptr++;

		/* If the remainder is shorter than name + 2, get out. */
		size = (uintptr_t)ptr - (uintptr_t)boot_env.be_env;
		if (boot_env.be_size - size < len + 2)
			return (NULL);
	} while (*ptr != '\0');
	return (NULL);
}

/*
 * Get prop value from either command line or boot environment.
 * We always check kernel command line first, as this will keep the
 * functionality and will allow user to override the values in environment.
 */
const char *
find_boot_prop(const char *name)
{
	const char *value = find_boot_line_prop(name);

	if (value == NULL)
		value = find_boot_env_prop(name);

	return (value);
}

/*
 * TODO.
 * quick and dirty local atoi. Perhaps should build with strtol, but
 * dboot & early boot mix does overcomplicate things much.
 * Stolen from libc anyhow.
 */
static int
atoi(const char *p)
{
	int n, c, neg = 0;
	unsigned char *up = (unsigned char *)p;

	if (!isdigit(c = *up)) {
		while (isspace(c))
			c = *++up;
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *++up;
		}
		if (!isdigit(c))
			return (0);
	}
	for (n = '0' - c; isdigit(c = *++up); ) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	return (neg ? n : -n);
}

static void
bcons_init_fb(void)
{
	const char *propval;
	int intval;

	/* initialize with explicit default values */
	fb_info.fg_color = CONS_COLOR;
	fb_info.bg_color = 0;
	fb_info.inverse = B_FALSE;
	fb_info.inverse_screen = B_FALSE;

	/* color values are 0 - 255 */
	propval = find_boot_prop("tem.fg_color");
	if (propval != NULL) {
		intval = atoi(propval);
		if (intval >= 0 && intval <= 255)
			fb_info.fg_color = intval;
	}

	/* color values are 0 - 255 */
	propval = find_boot_prop("tem.bg_color");
	if (propval != NULL && ISDIGIT(*propval)) {
		intval = atoi(propval);
		if (intval >= 0 && intval <= 255)
			fb_info.bg_color = intval;
	}

	/* get inverses. allow 0, 1, true, false */
	propval = find_boot_prop("tem.inverse");
	if (propval != NULL) {
		if (*propval == '1' || strcmp(propval, "true") == 0)
			fb_info.inverse = B_TRUE;
	}

	propval = find_boot_prop("tem.inverse-screen");
	if (propval != NULL) {
		if (*propval == '1' || strcmp(propval, "true") == 0)
			fb_info.inverse_screen = B_TRUE;
	}

#if defined(_BOOT)
	/*
	 * Load cursor position from bootloader only in dboot,
	 * dboot will pass cursor position to kernel via xboot info.
	 */
	propval = find_boot_prop("tem.cursor.row");
	if (propval != NULL) {
		intval = atoi(propval);
		if (intval >= 0 && intval <= 0xFFFF)
			fb_info.cursor.pos.y = intval;
	}

	propval = find_boot_prop("tem.cursor.col");
	if (propval != NULL) {
		intval = atoi(propval);
		if (intval >= 0 && intval <= 0xFFFF)
			fb_info.cursor.pos.x = intval;
	}
#endif
}

int
boot_fb(struct xboot_info *xbi, int console)
{
	if (xbi_fb_init(xbi, &bcons_dev) == B_FALSE)
		return (console);

	/* FB address is not set, fall back to serial terminal. */
	if (fb_info.paddr == 0)
		return (CONS_TTY);

	fb_info.terminal.x = VGA_TEXT_COLS;
	fb_info.terminal.y = VGA_TEXT_ROWS;
	boot_fb_init(CONS_FRAMEBUFFER);

	if (console == CONS_SCREEN_TEXT)
		return (CONS_FRAMEBUFFER);
	return (console);
}

static void
bcons_init_env(struct xboot_info *xbi)
{
	uint32_t i;
	struct boot_modules *modules;

	modules = (struct boot_modules *)(uintptr_t)xbi->bi_modules;
	for (i = 0; i < xbi->bi_module_cnt; i++) {
		if (modules[i].bm_type == BMT_ENV)
			break;
	}
	if (i == xbi->bi_module_cnt)
		return;

	boot_env.be_env = (char *)(uintptr_t)modules[i].bm_addr;
	boot_env.be_size = modules[i].bm_size;
}

static int
lookup_console_device(struct xboot_info *xbi, const char *cons_str)
{
	int cons;
	const char *ttyp;
	const char *txtp;

	cons = CONS_INVALID;
	if (cons_str != NULL) {
		ttyp = strstr(cons_str, "tty");
		txtp = strstr(cons_str, "text");

		if (ttyp != NULL && txtp != NULL) {
			if (ttyp < txtp && xbi->bi_bsvc_uart_mmio_base != 0) {
				cons = CONS_TTY;
			} else if (txtp < ttyp && xbi->bi_framebuffer != 0) {
				cons = CONS_SCREEN_TEXT;
			}
		} else if (ttyp != NULL && txtp == NULL) {
			if (xbi->bi_bsvc_uart_mmio_base != 0) {
				cons = CONS_TTY;
			}
		} else if (txtp != NULL && ttyp == NULL) {
			if (xbi->bi_framebuffer != 0) {
				cons = CONS_SCREEN_TEXT;
			}
		}

		if (cons == CONS_TTY) {
			if (xbi->bi_bsvc_uart_mmio_base == 0 ||
			    xbi->bi_bsvc_uart_type == XBI_BSVC_UART_NONE) {
				cons == CONS_SCREEN_TEXT;
			}
		}

		if (cons == CONS_SCREEN_TEXT) {
			if (xbi->bi_framebuffer == 0) {
				if (xbi->bi_bsvc_uart_mmio_base != 0 &&
				    xbi->bi_bsvc_uart_type !=
				    XBI_BSVC_UART_NONE) {
					cons = CONS_TTY;
				} else {
					cons = CONS_INVALID;
				}
			}
		} else {
			cons = CONS_INVALID;
		}
	}

	return (cons);
}

void
bcons_init(struct xboot_info *xbi)
{
	const char *cons_str;
	extern void boot_uart_init(struct xboot_info *);

	if (xbi == NULL) {
#if defined(_BOOT)
		/* This is very early dboot console, set up bcons */
		diag = console = CONS_TTY;
		boot_uart_init(NULL);
#endif
		return;
	}

	boot_uart_init(xbi);
	if (xbi->bi_bsvc_uart_mmio_base != 0)
		diag = CONS_TTY;

	/* Set up data to fetch properties from commad line and boot env. */
	boot_line = (char *)(uintptr_t)xbi->bi_cmdline;
	bcons_init_env(xbi);
	console = CONS_INVALID;

	/* set up initial fb_info */
	bcons_init_fb();

	cons_str = find_boot_prop("console");
	if (cons_str == NULL)
		cons_str = find_boot_prop("output-device");

	console = lookup_console_device(xbi, cons_str);

	/* make sure the FB is set up if present */
	console = boot_fb(xbi, console);
	switch (console) {
	case CONS_TTY:
		break;
	case CONS_HYPERVISOR:
		break;
#if !defined(_BOOT)
	case CONS_USBSER:
		/*
		 * We can't do anything with the usb serial
		 * until we have memory management.
		 */
		break;
#endif
	case CONS_SCREEN_GRAPHICS:	/* fallthrough */
	case CONS_SCREEN_TEXT:		/* fallthrough */
	case CONS_FRAMEBUFFER:		/* fallthrough */
	default:
		kb_init();
		break;
	}

	/*
	 * Initialize diag device unless already done.
	 */
	switch (diag) {
	case CONS_TTY:
		break;
	case CONS_SCREEN_GRAPHICS:	/* fallthrough */
	case CONS_SCREEN_TEXT:		/* fallthrough */
	case CONS_FRAMEBUFFER:
		if (console != CONS_SCREEN_GRAPHICS &&
		    console != CONS_SCREEN_TEXT &&
		    console != CONS_FRAMEBUFFER)
			kb_init();
		break;
	default:
		break;
	}

	sysp->bsvc_getchar = bcons_getchar;
	sysp->bsvc_putchar = bcons_putchar;
#if !defined(_BOOT)
	sysp->bsvc_ischar = bcons_ischar;
#endif
}

int
boot_console_type(int *tnum)
{
	if (tnum != NULL)
		*tnum = 0;

	return (console);
}

static void
btem_control(btem_state_t *btem, int c)
{
	int y, rows, cols;

	rows = fb_info.cursor.pos.y;
	cols = fb_info.cursor.pos.x;

	btem->btem_state = A_STATE_START;
	switch (c) {
	case A_BS:
		bcons_dev.bd_setpos(rows, cols - 1);
		break;

	case A_HT:
		cols += 8 - (cols % 8);
		if (cols >= fb_info.terminal.x)
			cols = fb_info.terminal.x - 1;
		bcons_dev.bd_setpos(rows, cols);
		break;

	case A_CR:
		bcons_dev.bd_setpos(rows, 0);
		break;

	case A_FF:
		for (y = 0; y < fb_info.terminal.y; y++) {
			bcons_dev.bd_setpos(y, 0);
			bcons_dev.bd_eraseline();
		}
		bcons_dev.bd_setpos(0, 0);
		break;

	case A_ESC:
		btem->btem_state = A_STATE_ESC;
		break;

	default:
		bcons_dev.bd_putchar(c);
		break;
	}
}

/*
 * if parameters [0..count - 1] are not set, set them to the value
 * of newparam.
 */
static void
btem_setparam(btem_state_t *btem, int count, int newparam)
{
	int i;

	for (i = 0; i < count; i++) {
		if (btem->btem_params[i] == -1)
			btem->btem_params[i] = newparam;
	}
}

static void
btem_chkparam(btem_state_t *btem, int c)
{
	int rows, cols;

	rows = fb_info.cursor.pos.y;
	cols = fb_info.cursor.pos.x;
	switch (c) {
	case '@':			/* insert char */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_shift(btem->btem_params[0]);
		break;

	case 'A':			/* cursor up */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_setpos(rows - btem->btem_params[0], cols);
		break;

	case 'B':			/* cursor down */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_setpos(rows + btem->btem_params[0], cols);
		break;

	case 'C':			/* cursor right */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_setpos(rows, cols + btem->btem_params[0]);
		break;

	case 'D':			/* cursor left */
		btem_setparam(btem, 1, 1);
		bcons_dev.bd_setpos(rows, cols - btem->btem_params[0]);
		break;

	case 'K':			/* erase line */
		bcons_dev.bd_eraseline();
		break;
	default:
		/* bcons_dev.bd_putchar(c); */
		break;
	}
	btem->btem_state = A_STATE_START;
}

static void
btem_chkparam_qmark(btem_state_t *btem, int c)
{
	/*
	 * This code is intentionally NOP, we do process
	 * \E[?25h and \E[?25l, but our cursor is always shown.
	 */
	switch (c) {
	case 'h': /* DEC private mode set */
		btem_setparam(btem, 1, 1);
		switch (btem->btem_params[0]) {
		case 25: /* show cursor */
			break;
		}
		break;
	case 'l':
		/* DEC private mode reset */
		btem_setparam(btem, 1, 1);
		switch (btem->btem_params[0]) {
		case 25: /* hide cursor */
			break;
		}
		break;
	}
	btem->btem_state = A_STATE_START;
}

static void
btem_getparams(btem_state_t *btem, int c)
{
	if (isdigit(c)) {
		btem->btem_paramval = btem->btem_paramval * 10 + c - '0';
		btem->btem_gotparam = B_TRUE;
		return;
	}

	if (btem->btem_curparam < BTEM_MAXPARAMS) {
		if (btem->btem_gotparam == B_TRUE) {
			btem->btem_params[btem->btem_curparam] =
			    btem->btem_paramval;
		}
		btem->btem_curparam++;
	}

	if (c == ';') {
		/* Restart parameter search */
		btem->btem_gotparam = B_FALSE;
		btem->btem_paramval = 0;
	} else {
		if (btem->btem_state == A_STATE_CSI_QMARK)
			btem_chkparam_qmark(btem, c);
		else
			btem_chkparam(btem, c);
	}
}

/* Simple boot terminal parser. */
static void
btem_parse(btem_state_t *btem, int c)
{
	int i;

	/* Normal state? */
	if (btem->btem_state == A_STATE_START) {
		if (c == A_CSI || c < ' ')
			btem_control(btem, c);
		else
			bcons_dev.bd_putchar(c);
		return;
	}

	/* In <ESC> sequence */
	if (btem->btem_state != A_STATE_ESC) {
		if (btem->btem_state != A_STATE_CSI) {
			btem_getparams(btem, c);
			return;
		}

		switch (c) {
		case '?':
			btem->btem_state = A_STATE_CSI_QMARK;
			return;
		default:
			btem_getparams(btem, c);
			return;
		}
	}

	/* Previous char was <ESC> */
	switch (c) {
	case '[':
		btem->btem_curparam = 0;
		btem->btem_paramval = 0;
		btem->btem_gotparam = B_FALSE;
		/* clear the parameters */
		for (i = 0; i < BTEM_MAXPARAMS; i++)
			btem->btem_params[i] = -1;
		btem->btem_state = A_STATE_CSI;
		return;

	case 'Q':	/* <ESC>Q */
	case 'C':	/* <ESC>C */
		btem->btem_state = A_STATE_START;
		return;

	default:
		btem->btem_state = A_STATE_START;
		break;
	}

	if (c < ' ')
		btem_control(btem, c);
	else
		bcons_dev.bd_putchar(c);
}

static void
_doputchar(int device, int c)
{
	switch (device) {
	case CONS_TTY:
		boot_uart_putchar(c);
		return;
	case CONS_SCREEN_TEXT:		/* fallthrough */
	case CONS_FRAMEBUFFER:
		bcons_dev.bd_cursor(B_FALSE);
		btem_parse(&boot_tem, c);
		bcons_dev.bd_cursor(B_TRUE);
		return;
	case CONS_SCREEN_GRAPHICS:	/* fallthrough */
#if !defined(_BOOT)
	case CONS_USBSER:
		defcons_putchar(c);
		/* fallthrough */
#endif	/* _BOOT */
	default:
		return;
	}
}

void
bcons_putchar(int c)
{
	if (c == '\n') {
		_doputchar(console, '\r');
		if (diag != console)
			_doputchar(diag, '\r');
	}
	_doputchar(console, c);
	if (diag != console)
		_doputchar(diag, c);
}

/*
 * kernel character input functions
 */
int
bcons_getchar(void)
{
	for (;;) {
		if (console == CONS_TTY || diag == CONS_TTY) {
			if (boot_uart_ischar())
				return (boot_uart_getchar());
		}

		if (console != CONS_INVALID || diag != CONS_INVALID) {
			if (kb_ischar())
				return (kb_getchar());
		}
	}
}

/*
 * Nothing below is used by dboot.
 */
#if !defined(_BOOT)

int
bcons_ischar(void)
{
	int c = 0;

	switch (console) {
	case CONS_TTY:
		c = boot_uart_ischar();
		break;

	case CONS_INVALID:
		break;

	default:
		c = kb_ischar();
	}
	if (c != 0)
		return (c);

	switch (diag) {
	case CONS_TTY:
		c = boot_uart_ischar();
		break;

	case CONS_INVALID:
		break;

	default:
		c = kb_ischar();
	}

	return (c);
}

/*
 * 2nd part of console initialization: we've now processed bootenv.rc; update
 * console settings as appropriate. This only really processes serial console
 * modifications.
 */
void
bcons_post_bootenvrc(struct xboot_info *xbi,
    char *inputdev, char *outputdev, char *consoledev)
{
	int cons = CONS_INVALID;
	char *devnames[] = { consoledev, outputdev, inputdev, NULL };
	int i;

	/*
	 * USB serial and GRAPHICS console: we just collect data into a buffer.
	 */
	if (console == CONS_USBSER || console == CONS_SCREEN_GRAPHICS) {
		extern void *defcons_init(size_t);
		defcons_buf = defcons_cur = defcons_init(MMU_PAGESIZE);
		return;
	}

	for (i = 0; devnames[i] != NULL; i++) {
		cons = lookup_console_device(xbi, devnames[i]);
		if (cons != CONS_INVALID)
			break;
	}

	if (cons == CONS_INVALID)
		return;

	console = cons;
}

static void
defcons_putchar(int c)
{
	if (defcons_buf != NULL &&
	    defcons_cur + 1 - defcons_buf < MMU_PAGESIZE) {
		*defcons_cur++ = c;
		*defcons_cur = 0;
	}
}

#endif	/* _BOOT */
