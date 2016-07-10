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
 * Copyright 2015 Mohamed A. Khalfella <khalfella@gmail.com>
 */

/*
 * General pidnode routines are stored in this file.
 */

#include <sys/pidnode.h>


/*
 * Compare two pid_node_t elements. Used by AVL trees.
 */

int
pid_node_comparator(const void *l, const void *r)
{
	const pid_node_t *li = l;
	const pid_node_t *ri = r;

	if (li->pn_pid > ri->pn_pid)
		return (1);
	if (li->pn_pid < ri->pn_pid)
		return (-1);
	return (0);
}
