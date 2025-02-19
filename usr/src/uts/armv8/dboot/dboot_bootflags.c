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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/bootconf.h>
#include <sys/reboot.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <util/getoptstr.h>

#include "dboot.h"
#include "dboot_printf.h"

/*
 * Parse the boot arguments, adding the options found to the existing boothowto
 * value (if any) or other state.  Then rewrite the buffer with arguments for
 * the standalone.
 *
 * NOTE: boothowto may already have bits set when this function is called
 *
 * To pass properties to the kernel you'll need to do things the usual
 * UNIX way, passing the '-B' options after a '--'.
 */
void
bootflags(const char *args, size_t argsz, char *out, size_t outsz)
{
	static char newargs[OBP_MAXPATHLEN];
	struct gos_params params;
	const char *cp;
	char *np;
	size_t npres;
	int c;

	params.gos_opts = "VadvhkD:B:";
	params.gos_strp = args;
	getoptstr_init(&params);
	while ((c = getoptstr(&params)) != -1) {
		switch (c) {
		/*
		 * Boot flags.
		 */
		case 'V':
			verbosemode = 1;
			break;
		case 'a':
			boothowto |= RB_ASKNAME;
			break;
		case 'd':
			boothowto |= RB_DEBUGENTER;
			break;
		case 'v':
			boothowto |= RB_VERBOSE;
			verbosemode = 1;
			break;
		case 'h':
			boothowto |= RB_HALT;
			break;

		/* Consumed by the kernel */
		case 'k':
			boothowto |= RB_KMDB;
			break;

		/*
		 * Unrecognized flags: stop.
		 */
		case 'D':
		case '?':
			break;
		default:
			dboot_printf("dboot: Ignoring unimplemented "
			    "option -%c.\n", c);
		}
	}

	/*
	 * Construct the arguments for the standalone.
	 */

	*newargs = '\0';
	np = newargs;

	/*
	 * We need a dash if we encountered an unrecognized option or if we
	 * need to pass flags on.
	 */
	if (c == '?' || (boothowto &
	    /* These flags are to be passed to the standalone. */
	    (RB_ASKNAME | RB_DEBUGENTER | RB_VERBOSE | RB_HALT | RB_KMDB))) {
		*np++ = '-';

		/*
		 * boot(8) says to pass these on.
		 */
		if (boothowto & RB_ASKNAME)
			*np++ = 'a';

		/*
		 * boot isn't documented as consuming these flags, so pass
		 * them on.
		 */
		if (boothowto & RB_DEBUGENTER)
			*np++ = 'd';
		if (boothowto & RB_KMDB)
			*np++ = 'k';
		if (boothowto & RB_VERBOSE)
			*np++ = 'v';
		if (boothowto & RB_HALT)
			*np++ = 'h';

		/*
		 * If we didn't encounter an unrecognized flag and there's
		 * more to copy, add a space to separate these flags.
		 * (Otherwise, unrecognized flags can be appended since we
		 * started this word with a dash.)
		 */
		if (c == -1 && params.gos_strp[0] != '\0')
			*np++ = ' ';
	}

	npres = sizeof (newargs) - (size_t)(np - newargs);

	if (c == '?') {
		/*
		 * Unrecognized flag: Copy gos_errp to end of line or a "--"
		 * word.
		 */
		cp = params.gos_errp;
		while (*cp && npres > 0) {
			if (cp[0] == '-' && cp[1] == '-' &&
			    (cp[2] == '\0' || ISSPACE(cp[2]))) {
				cp += 2;
				SKIP_SPC(cp);
				break;
			} else {
				const char *sp = cp;
				size_t sz;

				/* Copy until the next word. */
				while (*cp && !ISSPACE(*cp))
					cp++;
				while (ISSPACE(*cp))
					cp++;

				sz = MIN(npres, (size_t)(cp - sp));
				npres -= sz;
				bcopy(sp, np, sz);
				np += sz;
			}
		}
	} else {
		cp = params.gos_strp;
	}

	while (npres > 0 && (*np++ = *cp++) != '\0')
		npres--;

	newargs[sizeof (newargs) - 1] = '\0';
	(void) strlcpy(out, newargs, outsz + 1);
}
