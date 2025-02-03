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
 * Board information support for FDT systems.
 */

#include <stand.h>
#include <libfdt.h>
#include <fdt.h>

typedef struct {
	const char *bi_compat;
	const char *bi_impl_name;
	const char *bi_mfg_name;
	const char *bi_hw_provider;
} board_info_t;

static const board_info_t board_info[] = {
	{
		.bi_compat = "raspberrypi,4-model-b",
		.bi_impl_name = "RaspberryPi,4",
		.bi_mfg_name = "RaspberryPi,4",
		.bi_hw_provider = "Raspberry Pi Foundation"
	},
	{
		.bi_compat = "linux,dummy-virt",
		.bi_impl_name = "QEMU,virt",
		.bi_mfg_name = "QEMU,virt",
		.bi_hw_provider = "QEMU"
	},
	{
		.bi_compat = NULL
	}
};

static const char *
get_board_compatible(const void *fdtp)
{
	const char *n;
	int len;

	if (fdt_getprop(fdtp, 0, "compatible", NULL) == NULL)
		return (NULL);
	if (fdt_stringlist_count(fdtp, 0, "compatible") < 1)
		return (NULL);
	if ((n = fdt_stringlist_get(fdtp, 0, "compatible", 0, &len)) == NULL)
		return (NULL);
	if (len <= 0)
		return (NULL);

	return (n);
}

static const board_info_t *
get_board_info(const void *fdtp, const char **compat)
{
	const board_info_t *bi;
	*compat = get_board_compatible(fdtp);

	if (*compat == NULL)
		return (NULL);

	for (bi = &board_info[0]; bi->bi_compat != NULL; ++bi) {
		if (strcmp(*compat, bi->bi_compat) == 0)
			return (bi);
	}

	return (NULL);
}

void
bi_implarch_fdt(const void *fdtp)
{
	const board_info_t *bi;
	const char *compat;
	int rc;
	bool update_compat;
	int clen;
	int plen;
	const struct fdt_property *prop;
	char *compatible;

	update_compat = false;
	compat = NULL;
	bi = get_board_info(fdtp, &compat);
	if (bi == NULL && compat == NULL) {
		if ((rc = setenv("IMPLARCH", "armv8", 1)) != 0) {
			printf("Warning: failed to set IMPLARCH environment "
			    "variable: %d\n", rc);
		}

		return;
	}

	if (bi != NULL && bi->bi_impl_name != NULL) {
		compat = bi->bi_impl_name;
		update_compat = true;
	}

	if (bi != NULL && bi->bi_impl_name != NULL) {
		if ((rc = setenv("impl-arch-name", bi->bi_impl_name, 1)) != 0) {
			printf("Warning: failed to set impl-arch-name "
			    "environment variable: %d\n", rc);
		}

		if ((rc = setenv("IMPLARCH", bi->bi_impl_name, 1)) != 0) {
			printf("Warning: failed to set IMPLARCH environment "
			    "variable: %d\n", rc);
		}
	} else if (compat != NULL) {
		if ((rc = setenv("impl-arch-name", compat, 1)) != 0) {
			printf("Warning: failed to set impl-arch-name "
			    "environment variable: %d\n", rc);
		}

		if ((rc = setenv("IMPLARCH", compat, 1)) != 0) {
			printf("Warning: failed to set IMPLARCH environment "
			    "variable: %d\n", rc);
		}
	} else {
		if ((rc = setenv("impl-arch-name", "armv8", 1)) != 0) {
			printf("Warning: failed to set impl-arch-name "
			    "environment variable: %d\n", rc);
		}

		if ((rc = setenv("IMPLARCH", "armv8", 1)) != 0) {
			printf("Warning: failed to set IMPLARCH environment "
			    "variable: %d\n", rc);
		}
	}

	if (bi != NULL && bi->bi_mfg_name != NULL) {
		if ((rc = setenv("mfg-name", bi->bi_mfg_name, 1)) != 0) {
			printf("Warning: failed to set mfg-name "
			    "environment variable: %d\n", rc);
		}
	}

	if (bi != NULL && bi->bi_hw_provider != NULL) {
		if ((rc = setenv("si-hw-provider",
		    bi->bi_hw_provider, 1)) != 0) {
			printf("Warning: failed to set si-hw-provider "
			    "environment variable: %d\n", rc);
		}
	}

	if (!update_compat)
		return;

	plen = 0;
	if ((prop = fdt_get_property(
	    fdtp, 0, "compatible", &plen)) == NULL || plen < 1)
		return;	/* impossible, but ok... */
	/*
	 * New compat, comma, old compat, NUL.
	 */
	clen = strlen(compat) + 1 + plen + 1;
	if ((compatible = malloc(clen)) == NULL)
		return;
	memset(compatible, 0, clen);
	strcpy(compatible, compat);
	strcat(compatible, ",");
	memcpy(compatible + strlen(compat) + 1, prop->data, plen);
	(void) fdt_setprop((void *)fdtp, 0, "compatible", compatible, clen);
	free(compatible);
}

size_t
fdtutil_fdt_size(const void *fdtp)
{
	return (fdt_totalsize(fdtp));
}
