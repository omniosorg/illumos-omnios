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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * This program is a small test harness for libdhcputil.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <netinet/in.h>
#include <sys/sysmacros.h>

#include <netinet/dhcp.h>
#include <dhcp_inittab.h>

typedef struct {
	uint8_t *tc_binary;
	size_t tc_binlen;
	const char *tc_string;
} testcase_t;

#define	CASE(s, ...)	{					\
	.tc_binary = (uint8_t[]) { __VA_ARGS__ },		\
	.tc_binlen = sizeof ((uint8_t[]) { __VA_ARGS__ }),	\
	.tc_string = s,						\
}

testcase_t such_cases[] = {
	/*
	 * A zero-length value should result in the empty string:
	 */
	CASE(""),

	/*
	 * Confirm that we can support each possible prefix length:
	 */
	CASE("128.0.0.0/1:1.2.3.4",
	    1,		128,			1, 2, 3, 4),
	CASE("128.0.0.0/2:1.2.3.4",
	    2,		128,			1, 2, 3, 4),
	CASE("128.0.0.0/3:1.2.3.4",
	    3,		128,			1, 2, 3, 4),
	CASE("128.0.0.0/4:1.2.3.4",
	    4,		128,			1, 2, 3, 4),
	CASE("10.0.0.0/5:1.2.3.4",
	    5,		10,			1, 2, 3, 4),
	CASE("10.0.0.0/6:1.2.3.4",
	    6,		10,			1, 2, 3, 4),
	CASE("10.0.0.0/7:1.2.3.4",
	    7,		10,			1, 2, 3, 4),
	CASE("10.0.0.0/8:1.2.3.4",
	    8,		10,			1, 2, 3, 4),
	CASE("10.128.0.0/9:1.2.3.4",
	    9,		10, 128,		1, 2, 3, 4),
	CASE("10.128.0.0/10:1.2.3.4",
	    10,		10, 128,		1, 2, 3, 4),
	CASE("10.128.0.0/11:1.2.3.4",
	    11,		10, 128,		1, 2, 3, 4),
	CASE("10.128.0.0/12:1.2.3.4",
	    12,		10, 128,		1, 2, 3, 4),
	CASE("10.128.0.0/13:1.2.3.4",
	    13,		10, 128,		1, 2, 3, 4),
	CASE("10.128.0.0/14:1.2.3.4",
	    14,		10, 128,		1, 2, 3, 4),
	CASE("10.128.0.0/15:1.2.3.4",
	    15,		10, 128,		1, 2, 3, 4),
	CASE("1.255.0.0/16:1.2.3.4",
	    16,		1, 255,			1, 2, 3, 4),
	CASE("1.255.128.0/17:1.2.3.4",
	    17,		1, 255, 128,		1, 2, 3, 4),
	CASE("1.255.128.0/18:1.2.3.4",
	    18,		1, 255, 128,		1, 2, 3, 4),
	CASE("1.255.128.0/19:1.2.3.4",
	    19,		1, 255, 128,		1, 2, 3, 4),
	CASE("1.255.128.0/20:1.2.3.4",
	    20,		1, 255, 128,		1, 2, 3, 4),
	CASE("1.255.128.0/21:1.2.3.4",
	    21,		1, 255, 128,		1, 2, 3, 4),
	CASE("1.255.128.0/22:1.2.3.4",
	    22,		1, 255, 128,		1, 2, 3, 4),
	CASE("1.255.128.0/23:1.2.3.4",
	    23,		1, 255, 128,		1, 2, 3, 4),
	CASE("1.255.255.0/24:1.2.3.4",
	    24,		1, 255, 255,		1, 2, 3, 4),

	CASE("1.77.99.128/25:1.2.3.4",
	    25,		1, 77, 99, 128,		1, 2, 3, 4),
	CASE("1.77.99.128/26:1.2.3.4",
	    26,		1, 77, 99, 128,		1, 2, 3, 4),
	CASE("1.77.99.128/27:1.2.3.4",
	    27,		1, 77, 99, 128,		1, 2, 3, 4),
	CASE("1.77.99.128/28:1.2.3.4",
	    28,		1, 77, 99, 128,		1, 2, 3, 4),
	CASE("1.77.99.128/29:1.2.3.4",
	    29,		1, 77, 99, 128,		1, 2, 3, 4),
	CASE("1.77.99.128/30:1.2.3.4",
	    30,		1, 77, 99, 128,		1, 2, 3, 4),
	CASE("1.77.99.128/31:1.2.3.4",
	    31,		1, 77, 99, 128,		1, 2, 3, 4),
	CASE("1.77.99.128/32:1.2.3.4",
	    32,		1, 77, 99, 128,		1, 2, 3, 4),

	/*
	 * Check that interface routes work:
	 */
	CASE("1.2.3.0/24:0.0.0.0",
	    24,		1, 2, 3,		0, 0, 0, 0),
	CASE("1.2.3.0/24:0.0.0.0,4.5.0.0/15:0.0.0.0",
	    24,		1, 2, 3,		0, 0, 0, 0,
	    15,		4, 5,			0, 0, 0, 0),

	/*
	 * This is the common pattern used for off-subnet gateways:
	 */
	CASE("9.10.11.12/32:0.0.0.0,0.0.0.0/0:9.10.11.12",
	    32,		9, 10, 11, 12,		0, 0, 0, 0,
	    0,					9, 10, 11, 12),

	/*
	 * Shortest and longest possible single route string:
	 */
	CASE("255.255.255.255/32:255.255.255.255",
	    32,		255, 255, 255, 255,	255, 255, 255, 255),
	CASE("0.0.0.0/0:0.0.0.0",
	    0,					0, 0, 0, 0),

	/*
	 * Lots of routes:
	 */
	CASE("255.255.255.255/32:255.255.255.255,"
	    "0.0.0.0/32:0.0.0.0,"
	    "255.255.255.255/32:255.255.255.255,"
	    "0.0.0.0/0:0.0.0.0,"
	    "0.0.0.0/32:255.255.255.255,"
	    "255.255.255.255/32:0.0.0.0,"
	    "255.255.255.255/32:255.255.255.255,"
	    "0.0.0.0/32:0.0.0.0",
	    32,		255, 255, 255, 255,	255, 255, 255, 255,
	    32,		0, 0, 0, 0,		0, 0, 0, 0,
	    32,		255, 255, 255, 255,	255, 255, 255, 255,
	    0,					0, 0, 0, 0,
	    32,		0, 0, 0, 0,		255, 255, 255, 255,
	    32,		255, 255, 255, 255,	0, 0, 0, 0,
	    32,		255, 255, 255, 255,	255, 255, 255, 255,
	    32,		0, 0, 0, 0,		0, 0, 0, 0),
};

int
main(int argc, char **argv)
{
	int rc = EXIT_FAILURE;

	dhcp_symbol_t *sym = inittab_getbycode(ITAB_CAT_STANDARD,
	    ITAB_CONS_INFO, CD_CLASSLESS_ROUTES);
	if (sym == NULL) {
		errx(1, "could not locate Classless Routes option");
	}

	/*
	 * Confirm that we can decode binary representations into
	 * human-readable strings:
	 */
	for (uint_t n = 0; n < ARRAY_SIZE(such_cases); n++) {
		testcase_t *tc = &such_cases[n];

		int ierrno = 0;
		char *o = inittab_decode_e(sym, tc->tc_binary, tc->tc_binlen,
		    B_TRUE, &ierrno);

		if (o == NULL) {
			errx(1, "test case #%u: decode failure: %s", n,
			    inittab_errstr(ierrno));
		}

		if (strcmp(o, tc->tc_string) != 0) {
			errx(1, "test case #%u: wanted \"%s\", got \"%s\"\n",
			    n, tc->tc_string, o);
		}

		printf("test case #%u: ok! (%s)\n", n, o);
		free(o);
	}

	/*
	 * Make sure we can also encode strings into binary:
	 */
	for (uint_t n = 0; n < ARRAY_SIZE(such_cases); n++) {
		testcase_t *tc = &such_cases[n];

		int ierrno = 0;
		uint16_t olen = 0;
		uint8_t *o = inittab_encode_e(sym, tc->tc_string, &olen,
		    B_TRUE, &ierrno);

		if (o == NULL) {
			errx(1, "test case #%u (%s): encode failure: %s", n,
			    tc->tc_string, inittab_errstr(ierrno));
		}

		if (olen != tc->tc_binlen) {
			errx(1, "test case #%u (%s): encoded len %u != %u", n,
			    tc->tc_string, olen, (uint_t)tc->tc_binlen);
		}

		if (memcmp(o, tc->tc_binary, olen) != 0) {
			errx(1, "test case #%u (%s): encoded output is wrong",
			    n, tc->tc_string);
		}

		printf("test case #%u: ok! (%s) [len %u]\n", n, tc->tc_string,
		    olen);
		free(o);
	}

	warnx("ok");
	rc = EXIT_SUCCESS;

	return (rc);
}
