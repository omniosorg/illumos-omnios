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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <libcustr.h>
#include "cron.h"

char *
next_field(int lower, int upper, char *line, int *cursorp, cfield_error_t *errp)
{
	/*
	 * next_field returns a pointer to a string which holds the next
	 * field of a line of a crontab file.
	 *   if (numbers in this field are out of range (lower..upper),
	 *	or there is a syntax error) then
	 *	NULL is returned, and errp is updated providing it is
	 *	not NULL.
	 */

	/* Large enough to hold all possible elements for a field. */
#define	MAX_ELEMENTS 60
	uint_t elements[MAX_ELEMENTS];
	uint_t eindex = 0, i;
	custr_t *cs = NULL;
	cfield_error_t err;
	int cursor = *cursorp;
	char *s = NULL;

	err = CFIELD_NOERROR;

	assert(upper - lower <= MAX_ELEMENTS);

	while (line[cursor] == ' ' || line[cursor] == '\t')
		cursor++;

	if (line[cursor] == '\0') {
		err = CFIELD_EOLN;
		goto out;
	}

	for (;;) {
		int num = 0, num2 = 0, step = 0;

		if (line[cursor] == '*') {
			cursor++;

			/* Short circuit for plain '*' */
			if (line[cursor] == ' ' || line[cursor] == '\t') {
				s = xstrdup("*");
				goto out;
			}

			/* Otherwise, treat it as a range covering all values */
			num = lower;
			num2 = upper;
		} else {
			if (!isdigit(line[cursor])) {
				err = CFIELD_UNEXPECT;
				goto out;
			}

			do {
				num = num * 10 + (line[cursor] - '0');
			} while (isdigit(line[++cursor]));

			if (num < lower || num > upper) {
				err = CFIELD_OUTOFBOUND;
				goto out;
			}

			if (line[cursor] == '-') {
				if (!isdigit(line[++cursor])) {
					err = CFIELD_UNEXPECT;
					goto out;
				}

				do {
					num2 = num2 * 10 + (line[cursor] - '0');
				} while (isdigit(line[++cursor]));

				if (num2 < num || num2 < lower ||
				    num2 > upper) {
					err = CFIELD_OUTOFBOUND;
					goto out;
				}
			} else {
				if (eindex >= MAX_ELEMENTS) {
					err = CFIELD_EOVERFLOW;
					goto out;
				}
				elements[eindex++] = num;
				goto next;
			}
		}

		/* Look for a step definition */
		if (line[cursor] == '/') {
			if (!isdigit(line[++cursor])) {
				err = CFIELD_UNEXPECT;
				goto out;
			}

			do {
				step = step * 10 + (line[cursor] - '0');
			} while (isdigit(line[++cursor]));

			if (step == 0 || step >= upper - lower) {
				err = CFIELD_OUTOFBOUND;
				goto out;
			}
		}

		for (i = num; i <= num2; i++) {
			if (step == 0 || (i - num) % step == 0) {
				if (eindex >= MAX_ELEMENTS) {
					err = CFIELD_EOVERFLOW;
					goto out;
				}
				elements[eindex++] = i;
			}
		}

next:

		if (line[cursor] != ',')
			break;

		cursor++;
	}

	if (line[cursor] != ' ' && line[cursor] != '\t') {
		err = CFIELD_UNEXPECT;
		goto out;
	}

	if (custr_alloc(&cs) != 0) {
		err = CFIELD_ENOMEM;
		goto out;
	}

	for (i = 0; i < eindex; i++) {
		if (custr_len(cs) > 0) {
			if (custr_appendc(cs, ',') != 0) {
				err = CFIELD_ENOMEM;
				goto out;
			}
		}
		if (custr_append_printf(cs, "%u", elements[i]) != 0) {
			err = CFIELD_ENOMEM;
			goto out;
		}
	}

	if (custr_len(cs) != 0)
		s = xstrdup(custr_cstr(cs));

out:

	if (cs != NULL)
		custr_free(cs);

	if (errp != NULL)
		*errp = err;

	*cursorp = cursor;

	return (s);
}
