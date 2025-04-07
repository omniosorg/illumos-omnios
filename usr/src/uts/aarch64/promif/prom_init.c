/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/promif.h>
#ifndef _KMDB
#include <sys/promimpl.h>
#include <sys/prom_emul.h>
#include <sys/bootconf.h>
#include <sys/obpdefs.h>
#include <sys/kmem.h>
#endif

int	promif_debug = 0;	/* debug */

/*
 *  Every standalone that wants to use this library must call
 *  prom_init() before any of the other routines can be called.
 */
/*ARGSUSED*/
void
prom_init(char *pgmname, void *cookie)
{
#ifndef _KMDB
	promif_init(pgmname, cookie);
#endif
}

#ifndef _KMDB
/*
 * This mirrors a compatibility-only set of functionality from i86pc when
 * backed by the ACPI prom implementation. When backed by the FDT
 * implementation this is a no-op, since a properly constructed,
 * firmware-backed tree already exists.
 */
void
prom_setup()
{
	promif_setup();
}
#endif
