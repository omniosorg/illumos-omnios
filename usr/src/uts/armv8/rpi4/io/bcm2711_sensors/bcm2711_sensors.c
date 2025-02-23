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
 * /dev/sensors/voltage/...
 * a device exposing the SoC temperature of the Raspberry Pi 4
 * as well as voltages
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/sensors.h>
#include <sys/stdbool.h>
#include <sys/sysmacros.h>
#include <sys/platmod.h>
#include <sys/bcm2835_mbox.h>
#include <sys/bcm2835_vcprop.h>
#include <sys/bcm2835_vcio.h>

/*
 * The temperature measurements are in 1000ths of a degree C.
 */
#define	SOCTEMP_GRANULARITY	1000
/*
 * The voltage measurements are in microvolts.
 */
#define	VOLTAGE_GRANULARITY	1000000

typedef struct bcm2711_sensors {
	uint_t		id;
	int		unit;
	int		gran;
	const char	*name;
	const char	*class;
} bcm2711_sensors_t;

static const bcm2711_sensors_t bcm2711_sensors[] = {
	{
		.id	= VCPROP_TEMP_SOC,
		.unit	= SENSOR_UNIT_CELSIUS,
		.gran	= SOCTEMP_GRANULARITY,
		.name	= "soc",
		.class	= DDI_NT_SENSOR_TEMP_CPU,
	},
	{
		.id	= VCPROP_VOLTAGE_CORE,
		.unit	= SENSOR_UNIT_VOLTS,
		.gran	= VOLTAGE_GRANULARITY,
		.name	= "core",
		.class	= DDI_NT_SENSOR_VOLT_CPU,
	},
	{
		.id	= VCPROP_VOLTAGE_SDRAM_C,
		.unit	= SENSOR_UNIT_VOLTS,
		.gran	= VOLTAGE_GRANULARITY,
		.name	= "controller",
		.class	= DDI_NT_SENSOR_VOLT_SDRAM,
	},
	{
		.id	= VCPROP_VOLTAGE_SDRAM_P,
		.unit	= SENSOR_UNIT_VOLTS,
		.gran	= VOLTAGE_GRANULARITY,
		.name	= "phy",
		.class	= DDI_NT_SENSOR_VOLT_SDRAM,
	},
	{
		.id	= VCPROP_VOLTAGE_SDRAM_I,
		.unit	= SENSOR_UNIT_VOLTS,
		.gran	= VOLTAGE_GRANULARITY,
		.name	= "io",
		.class	= DDI_NT_SENSOR_VOLT_SDRAM,
	}
};

static const int nsensors = ARRAY_SIZE(bcm2711_sensors);

typedef struct bcm2711_sensor {
	struct bcmsensors	*bs_bcmsensors;
	id_t			bs_sensor;
	uint_t			bs_unit;
	uint_t			bs_vcprop_id;
	int			bs_gran;
	uint_t			bs_value;
} bcm2711_sensor_t;

typedef struct bcmsensors {
	dev_info_t		*bcmsensor_dip;
	bcm2711_sensor_t	*bcmsensor_sensors;
	kmutex_t		bcmsensor_mutex;
} bcmsensors_t;

static bcmsensors_t *bcmsensors;

static int
bcmsensor_get_temperature(uint_t sens_id)
{
	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_temperature	vbt_temperature;
		struct vcprop_tag		end;
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
			.id = sens_id,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL,
		},
	};

	bcm2835_mbox_prop_send(&vb, sizeof (vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return (-1);
	if (!vcprop_tag_success_p(&vb.vbt_temperature.tag))
		return (-1);

	return (vb.vbt_temperature.value);
}

static int
bcmsensor_get_voltage(uint_t sens_id)
{
	struct {
		struct vcprop_buffer_hdr	vb_hdr;
		struct vcprop_tag_voltage	vbt_voltage;
		struct vcprop_tag		end;
	} vb = {
		.vb_hdr = {
			.vpb_len = sizeof (vb),
			.vpb_rcode = VCPROP_PROCESS_REQUEST,
		},
		.vbt_voltage = {
			.tag = {
				.vpt_tag = VCPROPTAG_GET_VOLTAGE,
				.vpt_len = VCPROPTAG_LEN(vb.vbt_voltage),
			},
			.id = sens_id,
		},
		.end = {
			.vpt_tag = VCPROPTAG_NULL,
		},
	};

	bcm2835_mbox_prop_send(&vb, sizeof (vb));

	if (!vcprop_buffer_success_p(&vb.vb_hdr))
		return (-1);
	if (!vcprop_tag_success_p(&vb.vbt_voltage.tag))
		return (-1);

	return (vb.vbt_voltage.value);
}

static int
bcmsensor_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	bcm2711_sensor_t *sensor = arg;
	bcmsensors_t *bs = sensor->bs_bcmsensors;
	mutex_enter(&bs->bcmsensor_mutex);

	int val = sensor->bs_unit == SENSOR_UNIT_CELSIUS ?
	    bcmsensor_get_temperature(sensor->bs_vcprop_id) :
	    bcmsensor_get_voltage(sensor->bs_vcprop_id);

	if (val == -1) {
		mutex_exit(&bs->bcmsensor_mutex);
		return (EIO);
	}

	sensor->bs_value = val;
	scalar->sis_unit = sensor->bs_unit;
	scalar->sis_value = sensor->bs_value;
	scalar->sis_gran = sensor->bs_gran;
	scalar->sis_prec = 0;
	mutex_exit(&bs->bcmsensor_mutex);

	return (0);
}

static const ksensor_ops_t bcmsensor_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = bcmsensor_read,
};

static const ksensor_ops_t bcmsensor_volt_ops = {
	.kso_kind = ksensor_kind_voltage,
	.kso_scalar = bcmsensor_read,
};

static void
bcmsensor_destroy(bcmsensors_t *bs)
{
	(void) ksensor_remove(bs->bcmsensor_dip, KSENSOR_ALL_IDS);

	kmem_free(bs->bcmsensor_sensors, sizeof (bcm2711_sensor_t) * nsensors);
	mutex_destroy(&bs->bcmsensor_mutex);
	kmem_free(bs, sizeof (bcmsensors_t));
}

static int
bcmsensor_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	bcmsensors_t *bs = NULL;
	int err;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (bcmsensors != NULL) {
		return (DDI_FAILURE);
	}

	bs = kmem_zalloc(sizeof (bcmsensors_t), KM_SLEEP);
	bs->bcmsensor_dip = dip;

	mutex_init(&bs->bcmsensor_mutex, NULL, MUTEX_DRIVER, NULL);
	bs->bcmsensor_sensors =
	    kmem_zalloc(sizeof (bcm2711_sensor_t) * nsensors, KM_SLEEP);

	mutex_enter(&bs->bcmsensor_mutex);
	for (int i = 0; i < nsensors; i++) {
		bs->bcmsensor_sensors[i].bs_bcmsensors = bs;
		bs->bcmsensor_sensors[i].bs_vcprop_id = bcm2711_sensors[i].id;
		bs->bcmsensor_sensors[i].bs_unit = bcm2711_sensors[i].unit;
		bs->bcmsensor_sensors[i].bs_gran = bcm2711_sensors[i].gran;

		const ksensor_ops_t *kops;
		switch (bcm2711_sensors[i].unit) {
		case SENSOR_UNIT_CELSIUS:
			kops = &bcmsensor_temp_ops;
			break;
		case SENSOR_UNIT_VOLTS:
			kops = &bcmsensor_volt_ops;
			break;
		default:
			dev_err(bs->bcmsensor_dip, CE_WARN, "unsupported "
			    "sensor unit: %d", bcm2711_sensors[i].unit);

			mutex_exit(&bs->bcmsensor_mutex);
			bcmsensor_destroy(bs);
			return (DDI_FAILURE);
		}

		err = ksensor_create(bs->bcmsensor_dip, kops,
		    &bs->bcmsensor_sensors[i], bcm2711_sensors[i].name,
		    bcm2711_sensors[i].class,
		    &bs->bcmsensor_sensors[i].bs_sensor);

		if (err != 0) {
			dev_err(bs->bcmsensor_dip, CE_WARN, "failed to create "
			    "ksensor for %s: %d", bcm2711_sensors[i].name, err);

			mutex_exit(&bs->bcmsensor_mutex);
			bcmsensor_destroy(bs);
			return (DDI_FAILURE);
		}
	}

	bcmsensors = bs;
	mutex_exit(&bs->bcmsensor_mutex);
	return (DDI_SUCCESS);
}

static int
bcmsensor_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (bcmsensors == NULL) {
		return (DDI_FAILURE);
	}

	bcmsensors_t *bs = bcmsensors;
	mutex_enter(&bs->bcmsensor_mutex);
	bcmsensors = NULL;
	mutex_exit(&bs->bcmsensor_mutex);
	bcmsensor_destroy(bs);
	return (DDI_SUCCESS);
}

static struct dev_ops bcmsensor_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = bcmsensor_attach,
	.devo_detach = bcmsensor_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv bcmsensor_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Raspberry Pi 4 sensors",
	.drv_dev_ops = &bcmsensor_dev_ops
};

static struct modlinkage bcmsensor_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &bcmsensor_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&bcmsensor_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&bcmsensor_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&bcmsensor_modlinkage));
}
