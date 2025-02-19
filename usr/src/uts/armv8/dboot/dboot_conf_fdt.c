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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/null.h>
#include <sys/bootinfo.h>
#include <sys/psci.h>
#include <libfdt.h>

#include "dboot.h"

extern void boot_psci_init(struct xboot_info *);

static const void *
get_fdtp(void)
{
	static const void *fdtp;
	extern struct xboot_info *bi;

	if (fdtp != NULL)
		return (fdtp);

	if (bi == NULL)
		return (NULL);

	if (bi->bi_fdt == 0)
		return (NULL);

	if (fdt_check_header((const void *)bi->bi_fdt) != 0)
		return (NULL);

	fdtp = (const void *)bi->bi_fdt;
	return (fdtp);
}

int
dboot_configure_fdt(void)
{
	const void *fdtp;
	int nodeoff;
	const char *method;
	const uint32_t *pval;
	int plen;
	extern struct xboot_info *bi;

	if (bi == NULL)
		return (-1);

	if ((fdtp = get_fdtp()) == NULL)
		return (-1);

	/*
	 * Extract PSCI configuration from the FDT.
	 *
	 * The mandatory configuration here is the PSCI conduit (HVC or SMC),
	 * while the legacy function identifiers are optional.
	 */

	nodeoff = fdt_node_offset_by_compatible(fdtp, -1, "arm,psci");
	if (nodeoff < 0)
		return (-1);

	if ((method = fdt_getprop(fdtp, nodeoff, "method", &plen)) == NULL ||
	    plen == 0) {
		return (-1);
	}

	bi->bi_psci_conduit_hvc = strcmp(method, "hvc") == 0 ? 1 : 0;

	if ((pval = fdt_getprop(fdtp, nodeoff, "cpu_suspend", &plen)) != NULL) {
		bi->bi_psci_cpu_suspend_id =
		    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	if ((pval = fdt_getprop(fdtp, nodeoff, "cpu_off", &plen)) != NULL) {
		bi->bi_psci_cpu_off_id =
		    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	if ((pval = fdt_getprop(fdtp, nodeoff, "cpu_on", &plen)) != NULL) {
		bi->bi_psci_cpu_on_id =
		    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	if ((pval = fdt_getprop(fdtp, nodeoff, "migrate", &plen)) != NULL) {
		bi->bi_psci_migrate_id =
		    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	boot_psci_init(bi);

	/*
	 * Extract architected timer configuration from the FDT.
	 *
	 * On FDT systems this might not not programmed into cntfrq, so we
	 * try to read it from FDT first. If it's there we use that value.
	 *
	 * If not present in firmware, the caller sets the value from cntfrq
	 * and claims success if that value is non-zero.
	 */

	nodeoff = fdt_node_offset_by_compatible(fdtp, -1, "arm,armv8-timer");
	if (nodeoff >= 0) {
		if ((pval = fdt_getprop(fdtp, nodeoff,
		    "clock-frequency", &plen)) != NULL)
			bi->bi_arch_timer_freq =
			    fdt32_to_cpu(*((const uint32_t *)pval));
	}

	return (0);
}
