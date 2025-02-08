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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * /dev/sensors/temperature/cpu/soc
 * a device exposing the SoC temperature of the Raspberry Pi 4
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/sensors.h>
#include <sys/stdbool.h>
#include <sys/bcm2835_mbox.h>
#include <sys/bcm2835_vcprop.h>
#include <sys/bcm2835_vcio.h>

/*
 * The measurements are in 1000ths of a degree C.
 */
#define	SOCTEMP_GRANULARITY	1000

typedef struct soctemp_sensor {
	struct soctemp	*st_soctemp;
	id_t		st_sensor;
	uint_t		st_temperature;
} soctemp_sensor_t;

typedef struct soctemp {
	dev_info_t		*soctemp_dip;
	soctemp_sensor_t	*soctemp_sensor;
	kmutex_t		soctemp_mutex;
} soctemp_t;

static soctemp_t *soctemp = NULL;

static int
soctemp_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	soctemp_sensor_t *sensor = arg;
	soctemp_t *st = sensor->st_soctemp;
	mutex_enter(&st->soctemp_mutex);

	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_temperature	vbt_temperature;
		struct vcprop_tag end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof (vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_temperature = {
			.tag = {
				.vpt_tag = VCPROPTAG_GET_TEMPERATURE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_temperature),
			},
			.id = VCPROP_TEMP_SOC,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL,
		},
	};

	bcm2835_mbox_prop_send(&vb, sizeof (vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr)) {
		mutex_exit(&st->soctemp_mutex);
		return (EIO);
	}
	if (!vcprop_tag_success_p(&vb.vbt_temperature.tag)) {
		mutex_exit(&st->soctemp_mutex);
		return (EIO);
	}

	sensor->st_temperature = vb.vbt_temperature.value;
	scalar->sis_unit = SENSOR_UNIT_CELSIUS;
	scalar->sis_value = sensor->st_temperature;
	scalar->sis_gran = SOCTEMP_GRANULARITY;
	scalar->sis_prec = 0;
	mutex_exit(&st->soctemp_mutex);

	return (0);
}

static const ksensor_ops_t soctemp_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = soctemp_read,
};

static void
soctemp_destroy(soctemp_t *st)
{
	(void) ksensor_remove(st->soctemp_dip, KSENSOR_ALL_IDS);

	kmem_free(st->soctemp_sensor, sizeof (soctemp_sensor_t));
	mutex_destroy(&st->soctemp_mutex);
	kmem_free(st, sizeof (soctemp_t));
}

static int
soctemp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	soctemp_t *st = NULL;
	int err;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (soctemp != NULL) {
		return (DDI_FAILURE);
	}

	st = kmem_zalloc(sizeof (soctemp_t), KM_SLEEP);
	st->soctemp_dip = dip;

	mutex_init(&st->soctemp_mutex, NULL, MUTEX_DRIVER, NULL);
	st->soctemp_sensor = kmem_zalloc(sizeof (soctemp_sensor_t), KM_SLEEP);
	st->soctemp_sensor->st_soctemp = st;

	mutex_enter(&st->soctemp_mutex);
	err = ksensor_create(st->soctemp_dip, &soctemp_temp_ops,
	    st->soctemp_sensor, "soc", DDI_NT_SENSOR_TEMP_CPU,
	    &st->soctemp_sensor->st_sensor);

	if (err != 0) {
		dev_err(st->soctemp_dip, CE_WARN, "failed to create ksensor "
		    "for SoC: %d", err);

		mutex_exit(&st->soctemp_mutex);
		soctemp_destroy(st);
		return (DDI_FAILURE);
	}

	soctemp = st;
	mutex_exit(&st->soctemp_mutex);
	return (DDI_SUCCESS);
}

static int
soctemp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (soctemp == NULL) {
		return (DDI_FAILURE);
	}

	soctemp_t *st = soctemp;
	mutex_enter(&st->soctemp_mutex);
	soctemp = NULL;
	mutex_exit(&st->soctemp_mutex);
	soctemp_destroy(st);
	return (DDI_SUCCESS);
}

static struct dev_ops soctemp_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = soctemp_attach,
	.devo_detach = soctemp_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv soctemp_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Raspberry Pi 4 SoC thermal sensor",
	.drv_dev_ops = &soctemp_dev_ops
};

static struct modlinkage soctemp_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &soctemp_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&soctemp_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&soctemp_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&soctemp_modlinkage));
}
