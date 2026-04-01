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
 * Copyright 2026 Michael van der Westhuizen
 */

/*
 * UEFI Runtime Services Time-of-Day Driver.
 *
 * Implements the illumos tod_ops interface using UEFI Runtime Services
 * GetTime and SetTime calls.  This driver is suitable for any platform
 * where the hardware RTC is accessible through UEFI firmware interfaces.
 *
 * The driver assumes the firmware RTC stores UTC.  If EFI_TIME
 * includes a timezone offset, it is ignored - the conversion between
 * UTC and local time is handled by the kernel via ggmtl. This is
 * a common expectation across platforms.
 *
 * To use this driver, set the following in /etc/system (or arrange
 * for the platform code to set tod_module_name):
 *
 *   set tod_module_name="efitod"
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/clock.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/efi.h>
#include <sys/efirt.h>
#include <sys/machsystm.h>

/*
 * Convert an EFI_TIME (broken-down UTC) to a todinfo_t.
 *
 * todinfo_t.tod_year is years since 1900 (matching struct tm).
 * EFI_TIME.Year is the absolute year (e.g. 2026).
 * todinfo_t.tod_dow is not used by tod_to_utc(), so we leave it 0.
 *
 * Nanoseconds are ignored, and are integrated into the timestruc_t
 * by the caller.
 */
static todinfo_t
efitod_to_todinfo(EFI_TIME *etime)
{
	todinfo_t tod;

	tod.tod_year = etime->Year - 1900;
	tod.tod_month = etime->Month;
	tod.tod_day = etime->Day;
	tod.tod_hour = etime->Hour;
	tod.tod_min = etime->Minute;
	tod.tod_sec = etime->Second;
	tod.tod_dow = 0;

	return (tod);
}

/*
 * Convert a todinfo_t to an EFI_TIME.
 *
 * We always store UTC with an unspecified timezone, matching the
 * convention used by most UEFI firmware implementations.
 *
 * Nanoseconds are ignored, and are integrated from the timestruc_t
 * by the caller.
 */
static void
todinfo_to_efitime(todinfo_t *tod, EFI_TIME *etime)
{
	bzero(etime, sizeof (*etime));

	etime->Year = tod->tod_year + 1900;
	etime->Month = tod->tod_month;
	etime->Day = tod->tod_day;
	etime->Hour = tod->tod_hour;
	etime->Minute = tod->tod_min;
	etime->Second = tod->tod_sec;
	etime->TimeZone = EFI_UNSPECIFIED_TIMEZONE;
	etime->Daylight = 0;
}

/*
 * Read the current time from the firmware RTC.
 *
 * Must be called with tod_lock held.
 */
static timestruc_t
efitod_get(void)
{
	EFI_TIME	etime;
	todinfo_t	tod;
	timestruc_t	ts;
	uint64_t	status;

	ASSERT(MUTEX_HELD(&tod_lock));

	status = efi_get_time(&etime, NULL);
	if (status != EFI_SUCCESS) {
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
		tod_status_set(TOD_GET_FAILED);
		return (ts);
	}

	tod_status_clear(TOD_GET_FAILED);

	tod = efitod_to_todinfo(&etime);
	ts.tv_sec = tod_to_utc(tod) + ggmtl();
	ts.tv_nsec = etime.Nanosecond;

	return (ts);
}

/*
 * Write the specified time to the firmware RTC.
 *
 * Must be called with tod_lock held.
 */
static void
efitod_set(timestruc_t ts)
{
	EFI_TIME	etime;
	todinfo_t	tod;

	ASSERT(MUTEX_HELD(&tod_lock));

	tod = utc_to_tod(ts.tv_sec - ggmtl());
	todinfo_to_efitime(&tod, &etime);
	etime.Nanosecond = ts.tv_nsec;

	(void) efi_set_time(&etime);
}

static struct modlmisc modlmisc = {
	.misc_modops	= &mod_miscops,
	.misc_linkinfo	= "EFI Runtime Services TOD"
};

static struct modlinkage modlinkage = {
	.ml_rev		= MODREV_1,
	.ml_linkage	= {&modlmisc, NULL}
};

int
_init(void)
{
	extern tod_ops_t tod_ops;

	if (strcmp(tod_module_name, "efitod") == 0) {
		/*
		 * Only install our ops if EFI runtime services
		 * are actually available.  If not, fall through
		 * to mod_install() without replacing the default
		 * (non-functional) tod_ops - the kernel will use
		 * hrestime as a fallback.
		 */
		if (efirt_is_active()) {
			tod_ops.tod_get = efitod_get;
			tod_ops.tod_set = efitod_set;
			tod_ops.tod_set_watchdog_timer = NULL;
			tod_ops.tod_clear_watchdog_timer = NULL;
			tod_ops.tod_set_power_alarm = NULL;
			tod_ops.tod_clear_power_alarm = NULL;
		} else {
			cmn_err(CE_WARN,
			    "!efitod: EFI runtime services not available");
		}
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
