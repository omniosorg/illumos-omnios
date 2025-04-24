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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.  All rights reserved.
 * Copyright 2022 Oxide Computer Company
 */

#include <devfsadm.h>

static int ln_minor_name(di_minor_t minor, di_node_t node);

static devfsadm_create_t misc_cbt[] = {
	{ "pseudo", "ddi_pseudo", "devfdt",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_1, ln_minor_name,
	},
	{ "pseudo", "ddi_pseudo", "smbios",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_1, ln_minor_name,
	},
};

DEVFSADM_CREATE_INIT_V0(misc_cbt);

static devfsadm_remove_t misc_remove_cbt[] = {
};

DEVFSADM_REMOVE_INIT_V0(misc_remove_cbt);

/*
 * Any /dev/foo entry named after the minor name such as
 * /devices/.../driver@0:foo
 */
static int
ln_minor_name(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink(di_minor_name(minor), node, minor, 0);
	return (DEVFSADM_CONTINUE);
}
