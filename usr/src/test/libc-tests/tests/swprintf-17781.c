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
 * Copyright 2026 Hans Rosenfeld
 */

/*
 * Regression test for illumos #17781. The refactoring of the various *printf
 * functions in #17182 missed a corner case of [v]swprintf(), which need to go
 * through a special code path in _ndoprnt() using wmemcpy() for output into
 * string rather than wctomb(). This is indicated by the _IOREAD flag on the
 * temporary FILE created by vswprintf() for the output string, but the check
 * in _ndoprnt() erroneously insisted that this is the only flag set.
 *
 * As a result, [v]swprintf() write multibyte characters according to the
 * LC_CTYPE of the current locale, instead of wchar_t as they ought to.
 */

#include <sys/sysmacros.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>

wchar_t foo[] = L"bl0rg";
wchar_t bar[6];

void
hexdump(char *buf, int len)
{
	int i;

	for (i = 0; i != len; i++)
		fprintf(stderr, "%02x ", buf[i]);
}

int
main(int argc, char **argv)
{
	int len;

	len = swprintf(bar, ARRAY_SIZE(bar), L"%ls", foo);

	if (len != ARRAY_SIZE(foo) - 1) {
		fprintf(stderr, "length mismatch: expected %d != actual %d",
		    ARRAY_SIZE(foo) - 1, len);
		return (1);
	}

	if (memcmp(foo, bar, sizeof (foo)) != 0) {
		fprintf(stderr, "output mismatch:\n");
		fprintf(stderr, "expected: ");
		hexdump((char *)foo, sizeof (foo));
		fprintf(stderr, "\n");
		fprintf(stderr, "actual:   ");
		hexdump((char *)bar, sizeof (bar));
		fprintf(stderr, "\n");

		return (1);
	}

	return (0);
}
