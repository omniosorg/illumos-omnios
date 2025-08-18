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
#include <sys/obpdefs.h>
#include <sys/cpuinfo.h>
#include <asm/controlregs.h>
#include <sys/promif.h>
#include <sys/cpuvar.h>
#include <sys/byteorder.h>
#include <sys/systm.h>
#include <sys/stddef.h>
#include <sys/bootinfo.h>

static list_t				ci_lst;
static struct cpuinfo			ci0;
static struct xboot_info		*boot_xbp;
static const struct xboot_cpu_info	*boot_ci;

struct cpuinfo *
cpuinfo_first(void)
{
	return (list_head(&ci_lst));
}

struct cpuinfo *
cpuinfo_next(struct cpuinfo *ci)
{
	return (list_next(&ci_lst, ci));
}

struct cpuinfo *
cpuinfo_first_enabled(void)
{
	struct cpuinfo *ci;

	ci = cpuinfo_first();
	if (ci == cpuinfo_end())
		return (ci);

	do {
		if (ci->ci_flags & CPUINFO_ENABLED)
			break;
	} while ((ci = cpuinfo_next(ci)) != cpuinfo_end());

	return (ci);
}

struct cpuinfo *
cpuinfo_next_enabled(struct cpuinfo *ci)
{
	if (ci == cpuinfo_end())
		return (ci);

	while ((ci = cpuinfo_next(ci)) != cpuinfo_end()) {
		if (ci->ci_flags & CPUINFO_ENABLED)
			break;
	}

	return (ci);
}

struct cpuinfo *
cpuinfo_end(void)
{
	return (NULL);
}

/*
 * Returns the cpuinfo matching the requested affinity (in MPIDR format), or
 * NULL when none was found.
 */
struct cpuinfo *
cpuinfo_for_affinity(uint64_t affinity)
{
	struct cpuinfo *ci;

	for (ci = cpuinfo_first(); ci != cpuinfo_end(); ci = cpuinfo_next(ci))
		if (ci->ci_mpidr == affinity)
			return (ci);

	return (NULL);
}

static int
fill_cpuinfo(const struct xboot_cpu_info *xci, struct cpuinfo *ci)
{
	ci->ci_flags =
	    xci->xci_flags & (CPUINFO_ENABLED|CPUINFO_ONLINE_CAPABLE);
	ci->ci_mpidr = xci->xci_mpidr;
	ci->ci_ppver = xci->xci_ppver;
	ci->ci_parked_addr = xci->xci_parked_addr;
	ci->ci_cpuif = xci->xci_cpuif;
	ci->ci_uid = xci->xci_uid;
	return (0);
}

static struct cpuinfo *
create_cpuinfo(const struct xboot_cpu_info *xci)
{
	struct cpuinfo		*ci;

	ci = kmem_zalloc(sizeof (*ci), KM_SLEEP);

	if (fill_cpuinfo(xci, ci) != 0) {
		kmem_free(ci, sizeof (*ci));
		ci = NULL;
	}

	return (ci);
}

/*
 * Initialize the CPU information list, incorporating the boot CPU already set
 * up by a prior call to cpuinfo_bootstrap.
 *
 * After calling this function you can use the iterator functions
 * cpuinfo_first/cpuinfo_first_enabled, cpuinfo_next/cpuinfo_next_enabled and
 * cpuinfo_end.
 */
int
cpuinfo_init(void)
{
	int		idx;
	struct cpuinfo	*ci;

	VERIFY3P(boot_xbp, !=, NULL);
	VERIFY3P(boot_ci, !=, NULL);
	VERIFY3U(boot_xbp->bi_cpuinfo_cnt, !=, 0);

	list_create(&ci_lst, sizeof (struct cpuinfo),
	    offsetof(struct cpuinfo, ci_list_node));
	list_insert_head(&ci_lst, &ci0);

	for (idx = 1; idx < boot_xbp->bi_cpuinfo_cnt; ++idx) {
		ci = create_cpuinfo(&boot_ci[idx]);
		if (ci == NULL) {
			while ((ci = list_remove_tail(&ci_lst)) != NULL) {
				if (ci->ci_id != 0)
					kmem_free(ci, sizeof (*ci));
			}

			list_destroy(&ci_lst);
			boot_ci = NULL;
			boot_xbp = NULL;
			return (-1);
		}

		ci->ci_id = idx;
		list_insert_tail(&ci_lst, ci);
	}

	boot_ci = NULL;
	boot_xbp = NULL;
	return (0);
}

/*
 * Bootstrap the boot processor CPU information, attach it to the passed boot
 * processor structure (which must have cpu_id zero) and set the boot_ncpus,
 * boot_max_ncpus and max_ncpus values.
 */
void
cpuinfo_bootstrap(cpu_t *cp, struct xboot_info *xbp)
{
	const struct xboot_cpu_info	*xci;
	int				cpu_count;
	int				cpu_possible_count;
	int				idx;

	VERIFY3P(cp, !=, NULL);
	VERIFY3P(xbp, !=, NULL);
	VERIFY3U(cp->cpu_id, ==, 0);
	VERIFY3U(xbp->bi_cpuinfo_cnt, !=, 0);
	VERIFY3U(xbp->bi_cpuinfo, !=, 0);
	cpu_count = cpu_possible_count = 0;

	xci = (const struct xboot_cpu_info *)xbp->bi_cpuinfo;
	boot_xbp = xbp;
	boot_ci = xci;

	for (idx = 0; idx < xbp->bi_cpuinfo_cnt; ++idx) {
		if (xci[idx].xci_flags & CPUINFO_ENABLED) {
			cpu_count++;
			cpu_possible_count++;
		} else if (xci[idx].xci_flags & CPUINFO_ONLINE_CAPABLE) {
			cpu_possible_count++;
		}

		if (idx == 0) {
			VERIFY(xci[0].xci_flags & CPUINFO_ENABLED);
			if (fill_cpuinfo(&xci[idx], &ci0) != 0)
				prom_panic("CPUINFO: failed to fill cpuinfo "
				    "for the boot processor");
			ci0.ci_id = 0;
			cp->cpu_m.mcpu_ci = &ci0;
		}
	}

	VERIFY3P(cp->cpu_m.mcpu_ci, !=, NULL);

	/*
	 * cpu_count is guaranteed to be greater than zero due to the check
	 * for the boot processor cpuinfo having been set.
	 */
	boot_ncpus = cpu_count;
	boot_max_ncpus = max_ncpus = cpu_possible_count;
}
