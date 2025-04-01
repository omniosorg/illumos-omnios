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
 * Copyright 2017 Hayashi Naoyuki
 */

#include <sys/clock.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/rtc.h>
#include <sys/smp_impldefs.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/time.h>

typedef struct {
	void	*tod_base;
	size_t  tod_size;
} todpl031_conf_t;

static todpl031_conf_t todpl031_conf;

#define	RTCDR	(*(volatile uint32_t *)(todpl031_conf.tod_base))
#define	RTCLR	(*(volatile uint32_t *)(todpl031_conf.tod_base + 0x08))
#define	RTCCR	(*(volatile uint32_t *)(todpl031_conf.tod_base + 0x0c))

static void
init_rtc(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	/* Already configured */
	if (todpl031_conf.tod_base != 0)
		return;

	pnode_t node = prom_fdt_find_compatible(prom_rootnode(), "arm,pl031");
	if (node <= 0)
		return;

	uint64_t tod_base, tod_size;
	if (prom_fdt_get_reg(node, 0, &tod_base) != 0) {
		prom_panic("arm,pl031 with no registers?");
	}

	if (prom_fdt_get_reg_size(node, 0, &tod_size) != 0) {
		prom_panic("arm,pl031 with no registers?");
	}

	caddr_t addr = psm_map_phys(tod_base, tod_size, PROT_READ|PROT_WRITE);
	if (addr == NULL) {
		prom_panic("failed to map todpl031");
	}

	todpl031_conf.tod_base = addr;
	todpl031_conf.tod_size = tod_size;

	if ((RTCCR & 0x1) == 0)
		RTCCR |= 0x1;
}

static void
todpl031_set(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	init_rtc();

	if (todpl031_conf.tod_base == 0)
		return;

	uint32_t sec = ts.tv_sec - ggmtl();
	RTCLR = sec;
}

static timestruc_t
todpl031_get(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	init_rtc();

	if (todpl031_conf.tod_base == 0) {
		timestruc_t ts = {0};
		tod_status_set(TOD_GET_FAILED);
		return (ts);
	}

	tod_status_clear(TOD_GET_FAILED);

	uint32_t sec = RTCDR;

	timestruc_t ts = { .tv_sec = sec + ggmtl(), .tv_nsec = 0 };
	return (ts);
}

static struct modlmisc modlmisc = {
	&mod_miscops, "Arm PrimeCell Real Time Clock (PL031)"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	extern tod_ops_t tod_ops;
	if (strcmp(tod_module_name, "pl03one") == 0) {
		tod_ops.tod_get = todpl031_get;
		tod_ops.tod_set = todpl031_set;
		tod_ops.tod_set_watchdog_timer = NULL;
		tod_ops.tod_clear_watchdog_timer = NULL;
		tod_ops.tod_set_power_alarm = NULL;
		tod_ops.tod_clear_power_alarm = NULL;
	}

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
