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
 * Utilities to set board properties from FDT.
 */

#include <sys/types.h>
#include <sys/obpdefs.h>
#include <libfdt.h>

extern void setenv(const char *name, const char *value);
extern const void *get_fdtp(void);

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

	if (fdt_getprop(fdtp, 0, OBP_COMPATIBLE, NULL) == NULL)
		return (NULL);
	if (fdt_stringlist_count(fdtp, 0, OBP_COMPATIBLE) < 1)
		return (NULL);
	if ((n = fdt_stringlist_get(fdtp, 0, OBP_COMPATIBLE, 0, &len)) == NULL)
		return (NULL);
	if (len <= 0)
		return (NULL);

	return (n);
}

const board_info_t *
get_board_info(const void *fdtp, const char **compat)
{
	const board_info_t *bi;
	*compat = get_board_compatible(fdtp);

	if (*compat == NULL)
		return (NULL);

	for (bi = &board_info[0]; bi->bi_compat; ++bi) {
		if (strcmp(*compat, bi->bi_compat) == 0)
			return (bi);
	}

	return (NULL);
}

/*
 * Set the `si-hw-provider', `impl-arch-name' and `mfg-name' from the FDT.
 *
 * Substitutes a handful of known boards with normalised values.
 *
 * When no substitution is available, sets:
 *  si-hw-provider: Unknown
 *  impl-arch-name: The first compatible entry on the root FDT node, or
 *                  "Unknown" when that cannot be determined.
 *  mfg-name      : The first compatible entry on the root FDT node, or
 *                  "Unknown" when that cannot be determined.
 */
void
set_board_info(const void *fdtp)
{
	const char *compat;
	const board_info_t *bi = get_board_info(fdtp, &compat);

	if (bi == NULL) {
		setenv("si-hw-provider", "Unknown");

		if (compat == NULL) {
			setenv("impl-arch-name", "Unknown");
			setenv("mfg-name", "Unknown");
		} else {
			setenv("impl-arch-name", compat);
			setenv("mfg-name", compat);
		}

		return;
	}

	setenv("si-hw-provider", bi->bi_hw_provider);
	setenv("impl-arch-name", bi->bi_impl_name);
	setenv("mfg-name", bi->bi_mfg_name);
}

/*
 * Retrieve the implementation architecture, or "Unknown" on any error.
 */
const char *
get_impl_arch(void)
{
	const char *compat = NULL;
	static const char def_impl_arch[] = "Unknown";
	const board_info_t *bi = get_board_info(get_fdtp(), &compat);

	if (bi == NULL) {
		if (compat != NULL)
			return (compat);

		return (def_impl_arch);
	}

	return (bi->bi_impl_name);
}

/*
 * Retrieve the system manufacturer name, or "Unknown" on any error.
 */
char *
get_mfg_name(void)
{
	const char *compat = NULL;
	static const char def_mfg_name[] = "Unknown";
	const board_info_t *bi = get_board_info(get_fdtp(), &compat);

	if (bi == NULL) {
		if (compat != NULL)
			return ((char *)compat);

		return ((char *)def_mfg_name);
	}

	return ((char *)bi->bi_mfg_name);
}
