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
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

/*
 * console configuration routines
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/modctl.h>
#include <sys/termios.h>
#include <sys/obpdefs.h>
#include <sys/boot_console.h>
#include <sys/framebuffer.h>

char *plat_fbpath(void);

static int
console_type(int *tnum)
{
	static int boot_console = CONS_INVALID;
	static int tty_num = 0;

	char *cons;
	dev_info_t *root;

	/* If we already have determined the console, just return it. */
	if (boot_console != CONS_INVALID) {
		if (tnum != NULL)
			*tnum = tty_num;
		return (boot_console);
	}

	/*
	 * The console is defined by the "console" property. This is
	 * documented as being overridden by the "os_console" property,
	 * but there is absolutely no code in unix for any platform
	 * that implements that, so we don't either.
	 *
	 * `console` will have been trimmed to exactly one element
	 * by the early kernel code.
	 *
	 * If the console is a TTY, we deviate from i86pc by allowing
	 * `ttya`-`ttyz` (where i86pc does `ttya`-`ttyd`). This is done
	 * because there is no architected limit to the number of TTY
	 * lines we may have.
	 */
	root = ddi_root_node();
	ASSERT3P(root, !=, NULL);
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, root,
	    DDI_PROP_DONTPASS, "console", &cons) == DDI_SUCCESS) {
		if (strlen(cons) == 4 && strncmp(cons, "tty", 3) == 0 &&
		    cons[3] >= 'a' && cons[3] <= 'z') {
			boot_console = CONS_TTY;
			tty_num = cons[3] - 'a';
		} else if (strcmp(cons, "usb-serial") == 0) {
			(void) i_ddi_attach_hw_nodes("xhci");
			(void) i_ddi_attach_hw_nodes("ehci");
			(void) i_ddi_attach_hw_nodes("uhci");
			(void) i_ddi_attach_hw_nodes("ohci");

			/*
			 * USB device enumerate asynchronously.
			 * Wait 2 seconds for USB serial devices to attach.
			 */
			delay(drv_usectohz(2000000));
			boot_console = CONS_USBSER;
		} else if (strcmp(cons, "text") == 0) {
			boot_console = CONS_SCREEN_TEXT;
		}

		ddi_prop_free(cons);
	}

	/*
	 * If we don't yet have a console type, or if we have a framebuffer
	 * type and there's no framebuffer available then we fall back to
	 * the bootloader-provided default UART or boot console UART.
	 *
	 * If these are not available then we are out of ideas.
	 */
	if (boot_console == CONS_INVALID ||
	    (boot_console == CONS_SCREEN_TEXT && plat_fbpath() == NULL)) {
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, root,
		    DDI_PROP_DONTPASS, "default-uart-name", &cons) ==
		    DDI_SUCCESS || ddi_prop_lookup_string(DDI_DEV_T_ANY, root,
		    DDI_PROP_DONTPASS, "bcons.uart.name", &cons) ==
		    DDI_SUCCESS) {
			if (strlen(cons) == 4 && strncmp(cons, "tty", 3) == 0 &&
			    cons[3] >= 'a' && cons[3] <= 'z') {
				boot_console = CONS_TTY;
				tty_num = cons[3] - 'a';
			} else {
				boot_console = CONS_INVALID;
			}

			ddi_prop_free(cons);
		} else {
			boot_console = CONS_INVALID;
		}
	}

	if (tnum != NULL)
		*tnum = tty_num;

	return (boot_console);
}

int
plat_use_polled_debug()
{
	return (0);
}

int
plat_support_serial_kbd_and_ms()
{
	return (0);
}

int
plat_stdin_is_keyboard(void)
{
	return (console_type(NULL) == CONS_SCREEN_TEXT);
}

int
plat_stdout_is_framebuffer(void)
{
	return (console_type(NULL) == CONS_SCREEN_TEXT);
}

static char *
plat_devpath(char *name, char *path)
{
	major_t major;
	dev_info_t *dip, *pdip;

	if ((major = ddi_name_to_major(name)) == (major_t)-1)
		return (NULL);

	if ((dip = devnamesp[major].dn_head) == NULL)
		return (NULL);

	pdip = ddi_get_parent(dip);
	if (i_ddi_attach_node_hierarchy(pdip) != DDI_SUCCESS)
		return (NULL);
	if (ddi_initchild(pdip, dip) != DDI_SUCCESS)
		return (NULL);

	(void) ddi_pathname(dip, path);

	return (path);
}

char *
plat_kbdpath(void)
{
	static char kbpath[MAXPATHLEN];

	if (plat_devpath("kb8042", kbpath) == NULL)
		return (NULL);

	return (kbpath);
}

/*
 * For now we're going to keep this very simple and simply find the efifb
 * device hanging off the root node.
 */
char *
plat_fbpath(void)
{
	static char *fbpath = NULL;
	static char fbpath_buf[MAXPATHLEN];

	dev_info_t *dip;
	char *cname;

	if (fbpath != NULL)
		return (fbpath);

	for (dip = ddi_get_child(ddi_root_node()); dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {
		if ((cname = ddi_node_name(dip)) == NULL)
			continue;
		if (strcmp(cname, "efifb") != 0)
			continue;
		if (i_ddi_attach_node_hierarchy(dip) != DDI_SUCCESS)
			return (NULL);

		(void) ddi_pathname(dip, fbpath_buf);
		if (fbpath_buf[0] == '\0')
			return (NULL);

		fbpath = fbpath_buf;
		return (fbpath);
	}

	return (NULL);
}

char *
plat_mousepath(void)
{
	static char mpath[MAXPATHLEN];

	if (plat_devpath("mouse8042", mpath) == NULL)
		return (NULL);

	return (mpath);
}

static char *
plat_ttypath(int inum)
{
	static char path[MAXPATHLEN];
	char *bp;
	major_t major;
	dev_info_t *dip;

	if (inum < 0 || inum > 25)
		return (NULL);

	/* XXXARM: we really need to work on asy */
	if ((major = ddi_name_to_major("ns16550a")) == (major_t)-1)
		return (NULL);

	if ((dip = devnamesp[major].dn_head) == NULL)
		return (NULL);

	for (; dip != NULL; dip = ddi_get_next(dip)) {
		if (i_ddi_attach_node_hierarchy(dip) != DDI_SUCCESS)
			continue;

		if (DEVI(dip)->devi_minor->ddm_name[0] == ('a' + (char)inum))
			break;
	}

	if (dip == NULL)
		return (NULL);

	(void) ddi_pathname(dip, path);
	if (path[0] == '\0')
		return (NULL);

	bp = path + strlen(path);
	(void) snprintf(bp, 3, ":%s", DEVI(dip)->devi_minor->ddm_name);

	return (path);
}

/* return path of first usb serial device */
static char *
plat_usbser_path(void)
{
	/* XXXARM: let's get USB working before we try to implement this */
	return (NULL);
}

char *
plat_stdinpath(void)
{
	int tty_num = 0;

	switch (console_type(&tty_num)) {
	case CONS_TTY:
		return (plat_ttypath(tty_num));
	case CONS_USBSER:
		return (plat_usbser_path());
	case CONS_SCREEN_TEXT:
		break;
	default:
		break;
	}

	return (plat_kbdpath());
}

char *
plat_stdoutpath(void)
{
	int tty_num = 0;

	switch (console_type(&tty_num)) {
	case CONS_TTY:
		return (plat_ttypath(tty_num));
	case CONS_USBSER:
		return (plat_usbser_path());
	case CONS_SCREEN_TEXT:
		break;
	default:
		break;
	}

	return (plat_fbpath());
}

char *
plat_diagpath(void)
{
	dev_info_t *root;
	char *diag;
	int tty_num = -1;

	root = ddi_root_node();

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, root, DDI_PROP_DONTPASS,
	    "diag-device", &diag) == DDI_SUCCESS) {
		if (strlen(diag) == 4 && strncmp(diag, "tty", 3) == 0 &&
		    diag[3] >= 'a' && diag[3] <= 'z') {
			tty_num = diag[3] - 'a';
		}

		ddi_prop_free(diag);
	}

	if (tty_num != -1)
		return (plat_ttypath(tty_num));

	return (NULL);
}

void
plat_tem_get_colors(uint8_t *fg, uint8_t *bg)
{
	*fg = fb_info.fg_color;
	*bg = fb_info.bg_color;
}

void
plat_tem_get_inverses(int *inverse, int *inverse_screen)
{
	*inverse = fb_info.inverse == B_TRUE? 1 : 0;
	*inverse_screen = fb_info.inverse_screen == B_TRUE? 1 : 0;
}

void
plat_tem_get_prom_font_size(int *charheight, int *windowtop)
{
	*charheight = fb_info.font_height;
	*windowtop = fb_info.terminal_origin.y;
}

void
plat_tem_get_prom_size(size_t *height, size_t *width)
{
	*height = fb_info.terminal.y;
	*width = fb_info.terminal.x;
}

void
plat_tem_hide_prom_cursor(void)
{
	if (boot_console_type(NULL) == CONS_FRAMEBUFFER)
		boot_fb_cursor(B_FALSE);
}

void
plat_tem_get_prom_pos(uint32_t *row, uint32_t *col)
{
	*row = fb_info.cursor.pos.y;
	*col = fb_info.cursor.pos.x;
}
