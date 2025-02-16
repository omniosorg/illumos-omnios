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

/*
 * Stubs for keyboard support.
 *
 * Once we figure out how to do this so early in bootup under aarch64
 * these can be filled out. Until then they exist to keep
 * boot_console.c looking good.
 */

void
kb_init(void)
{
}

int
kb_ischar(void)
{
	return (0);
}

int
kb_getchar(void)
{
	return (0);
}
