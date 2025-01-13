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

#include <stand.h>

void
bi_isadir(void)
{
	int rc;

	rc = setenv("ISADIR", "aarch64", 1);
	if (rc != 0) {
		printf("Warning: failed to set ISADIR environment "
		    "variable: %d\n", rc);
	}
}

void
bi_basearch(void)
{
	int rc;

	if ((rc = setenv("BASEARCH", "armv8", 1)) != 0) {
		printf("Warning: failed to set BASEARCH environment "
		    "variable: %d\n", rc);
	}
}

void
bi_implarch(void)
{
	int rc;

	if ((rc = setenv("IMPLARCH", "armv8", 1)) != 0) {
		printf("Warning: failed to set IMPLARCH environment "
		    "variable: %d\n", rc);
	}
}
