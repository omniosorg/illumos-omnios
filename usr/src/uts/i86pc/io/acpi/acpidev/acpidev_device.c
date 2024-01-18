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
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2024 Racktop Systems, Inc.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_impl.h>
#include <sys/pci.h>
#include <sys/x86_archext.h>
#include <sys/sysmacros.h>
#include <sys/framebuffer.h>

static ACPI_STATUS acpidev_device_probe(acpidev_walk_info_t *infop);
static acpidev_filter_result_t acpidev_device_filter(acpidev_walk_info_t *infop,
    char *devname, int maxlen);
static acpidev_filter_result_t acpidev_device_filter_usb(acpidev_walk_info_t *,
    ACPI_HANDLE, acpidev_filter_rule_t *, char *, int);
static acpidev_filter_result_t acpidev_device_filter_hyperv(
    acpidev_walk_info_t *, ACPI_HANDLE, acpidev_filter_rule_t *, char *, int);
static ACPI_STATUS acpidev_device_init(acpidev_walk_info_t *infop);

static uint32_t acpidev_device_unitaddr = 0;

/*
 * Default class driver for ACPI DEVICE objects.
 * The default policy for DEVICE objects is to scan child objects without
 * creating device nodes. But some special DEVICE objects will have device
 * nodes created for them.
 */
acpidev_class_t acpidev_class_device = {
	0,				/* adc_refcnt */
	ACPIDEV_CLASS_REV1,		/* adc_version */
	ACPIDEV_CLASS_ID_DEVICE,	/* adc_class_id */
	"ACPI Device",			/* adc_class_name */
	ACPIDEV_TYPE_DEVICE,		/* adc_dev_type */
	NULL,				/* adc_private */
	NULL,				/* adc_pre_probe */
	NULL,				/* adc_post_probe */
	acpidev_device_probe,		/* adc_probe */
	acpidev_device_filter,		/* adc_filter */
	acpidev_device_init,		/* adc_init */
	NULL,				/* adc_fini */
};

/*
 * List of class drivers which will be called in order when handling
 * children of ACPI DEVICE objects.
 */
acpidev_class_list_t *acpidev_class_list_device = NULL;

/* Filter rule table for boot. */
static acpidev_filter_rule_t acpidev_device_filters[] = {
	{	/* _SB_ object type is hardcoded to DEVICE by acpica */
		NULL,
		0,
		ACPIDEV_FILTER_DEFAULT,
		&acpidev_class_list_device,
		1,
		1,
		ACPIDEV_OBJECT_NAME_SB,
		ACPIDEV_NODE_NAME_MODULE_SBD,
	},
	{	/* Ignore other device objects under ACPI root object */
		NULL,
		0,
		ACPIDEV_FILTER_SKIP,
		NULL,
		1,
		1,
		NULL,
		NULL,
	},
	{	/* Scan a device attempting to find a USB node */
		acpidev_device_filter_usb,
		0,
		ACPIDEV_FILTER_SCAN,
		&acpidev_class_list_usbport,
		2,
		INT_MAX,
		NULL,
		NULL
	},
	{
		acpidev_device_filter_hyperv,
		0,
		ACPIDEV_FILTER_SKIP,
		&acpidev_class_list_device,
		2,
		3,
		NULL,
		NULL,
	},
	{	/* Scan other device objects not directly under ACPI root */
		NULL,
		0,
		ACPIDEV_FILTER_SCAN,
		&acpidev_class_list_device,
		2,
		INT_MAX,
		NULL,
		NULL,
	}
};

static ACPI_STATUS
acpidev_device_probe(acpidev_walk_info_t *infop)
{
	ACPI_STATUS rc = AE_OK;
	int flags;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);

	if (infop->awi_info->Type != ACPI_TYPE_DEVICE) {
		return (AE_OK);
	}

	flags = ACPIDEV_PROCESS_FLAG_SCAN;
	switch (infop->awi_op_type) {
	case ACPIDEV_OP_BOOT_PROBE:
		flags |= ACPIDEV_PROCESS_FLAG_CREATE;
		break;

	case ACPIDEV_OP_BOOT_REPROBE:
		break;

	case ACPIDEV_OP_HOTPLUG_PROBE:
		flags |= ACPIDEV_PROCESS_FLAG_CREATE |
		    ACPIDEV_PROCESS_FLAG_SYNCSTATUS |
		    ACPIDEV_PROCESS_FLAG_HOLDBRANCH;
		break;

	default:
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: unknown operation type %u in "
		    "acpi_device_probe().", infop->awi_op_type);
		rc = AE_BAD_PARAMETER;
		break;
	}

	if (rc == AE_OK) {
		rc = acpidev_process_object(infop, flags);
	}
	if (ACPI_FAILURE(rc) && rc != AE_NOT_EXIST && rc != AE_ALREADY_EXISTS) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to process device object %s.",
		    infop->awi_name);
	} else {
		rc = AE_OK;
	}

	return (rc);
}

/*
 * Attempt to determine which devices here correspond to an HCI for a USB
 * controller.
 */
static acpidev_filter_result_t
acpidev_device_filter_usb(acpidev_walk_info_t *infop, ACPI_HANDLE hdl,
    acpidev_filter_rule_t *afrp, char *devname, int len)
{
	dev_info_t *dip;
	char **compat;
	uint_t ncompat, i;

	if (infop->awi_op_type != ACPIDEV_OP_BOOT_REPROBE)
		return (ACPIDEV_FILTER_SKIP);

	/*
	 * If we don't find a dip that matches this one, then let's not worry
	 * about it. This means that it may not be a device we care about in any
	 * way.
	 */
	if (ACPI_FAILURE(acpica_get_devinfo(hdl, &dip))) {
		return (ACPIDEV_FILTER_SKIP);
	}

	/*
	 * To determine if this is a PCI USB class controller, we grab its
	 * compatible array and look for an instance of pciclass,0c03 or
	 * pciexclass,0c03. The class code 0c03 is used to indicate a USB
	 * controller.
	 */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "compatible", &compat, &ncompat) != DDI_SUCCESS) {
		return (ACPIDEV_FILTER_SKIP);
	}

	for (i = 0; i < ncompat; i++) {
		if (strcmp(compat[i], "pciclass,0c03") == 0 ||
		    strcmp(compat[i], "pciexclass,0c03") == 0) {
			ddi_prop_free(compat);
			/*
			 * We've found a PCI based USB controller. Switch to the
			 * USB specific parser.
			 */
			return (ACPIDEV_FILTER_SCAN);
		}
	}

	ddi_prop_free(compat);
	return (ACPIDEV_FILTER_SKIP);
}

static acpidev_filter_result_t
acpidev_device_filter_hyperv(acpidev_walk_info_t *infop, ACPI_HANDLE hdl,
    acpidev_filter_rule_t *afrp, char *devname, int len)
{
	ACPI_DEVICE_INFO	*ainfo = infop->awi_info;

	if ((get_hwenv() & HW_MICROSOFT) == 0)
		return (ACPIDEV_FILTER_SKIP);

	if (devname == NULL)
		return (ACPIDEV_FILTER_SKIP);

	/*
	 * We've encountered devnames (so far) of 'VMBS' and 'VMB8' in
	 * the field. In all instances, the _HID for the VMBus device has
	 * been "VMBus", so that appears to be the safer value to use
	 * to identify if the VMBus is present. Similarly, the _DDN is
	 * 'VMBUS'. In some instances AcpiGetObjectInfo() seems to set
	 * HardwareId.String to the _DDN instead of the _HID, so we
	 * check for either.
	 */
	if ((ainfo->Valid & ACPI_VALID_HID) == 0 ||
	    (strcmp(ainfo->HardwareId.String, "VMBus") != 0 &&
	    (strcmp(ainfo->HardwareId.String, "VMBUS") != 0)))
		return (ACPIDEV_FILTER_SKIP);

	/*
	 * For historical reasons, the vmbus lives off the root nexus. As a
	 * result, we have to create the node ourself and not let the acpidev
	 * framework create it under the fw tree so device paths do not change.
	 * Certain vmbus children (e.g. hv_netvsc) will cause undesirable
	 * behavior if their device paths move across an update.
	 */
	dev_info_t *vmb_dip = NULL;
	dev_info_t *root_dip = ddi_root_node();
	boolean_t is_gen2 = B_FALSE;

	/*
	 * Per some conversations with people at Microsoft on Hyper-V,
	 * most platforms distinguish between Gen1 and Gen2 VMs
	 * based on how they boot. Gen2 VMs always use EFI while
	 * Gen1 VMs always use BIOS. Looking for an EFI property
	 * on the root nexus is the best way we have to tell if
	 * we booted via EFI or not.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, root_dip, DDI_PROP_DONTPASS,
	    "efi-version")) {
		is_gen2 = B_TRUE;
	}

	ndi_devi_enter(root_dip);

	if (is_gen2) {
		dev_info_t *fb_dip = NULL;
		dev_info_t *isa_dip = NULL;
		char *compat[] = { "vgatext" };
		struct regspec reg = {
			.regspec_bustype = 0,	/* MMIO */
			.regspec_addr = fb_info.paddr,
			.regspec_size = fb_info.fb_size,
		};

		/* Create the EFI fb console off the root nexus */
		ndi_devi_alloc_sleep(root_dip, OBP_DISPLAY,
		    (pnode_t)DEVI_SID_NODEID, &fb_dip);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, fb_dip,
		    OBP_DEVICETYPE, OBP_DISPLAY);
		(void) ndi_prop_update_string_array(DDI_DEV_T_NONE,
		    fb_dip, OBP_COMPATIBLE, compat, ARRAY_SIZE(compat));
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, fb_dip,
		    "model", "Hyper-V EFI Virtual Frame Buffer");
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, fb_dip,
		    OBP_REG, (int *)&reg, 3);
		(void) ndi_devi_bind_driver(fb_dip, 0);

		/* There shouldn't be an PCI-LPC bridge in a Gen2 VM */
		VERIFY3P(ddi_find_devinfo("isa", -1, 0), ==, NULL);

		/* Create an isa bridge off the root nexus */
		ndi_devi_alloc_sleep(root_dip, "isa", (pnode_t)DEVI_SID_NODEID,
		    &isa_dip);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, isa_dip,
		    OBP_DEVICETYPE, "isa");
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, isa_dip,
		    "bus-type", "isa");
		(void) ndi_devi_bind_driver(isa_dip, 0);
	}

	ndi_devi_alloc_sleep(root_dip, "hv_vmbus",
	    (pnode_t)DEVI_SID_NODEID, &vmb_dip);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, vmb_dip,
	    OBP_DEVICETYPE, "vmbus");
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, vmb_dip, "model",
	    "Hyper-V Virtual Machine Bus");
	(void) ndi_devi_bind_driver(vmb_dip, 0);

	ndi_devi_exit(root_dip);

	/*
	 * Since we're doing our own thing with creating nodes here,
	 * we tell the framework not to do anything else with this
	 * node.
	 */
	return (ACPIDEV_FILTER_SKIP);
}

static acpidev_filter_result_t
acpidev_device_filter(acpidev_walk_info_t *infop, char *devname, int maxlen)
{
	acpidev_filter_result_t res;

	ASSERT(infop != NULL);
	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE ||
	    infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE ||
	    infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		res = acpidev_filter_device(infop, infop->awi_hdl,
		    ACPIDEV_ARRAY_PARAM(acpidev_device_filters),
		    devname, maxlen);
	} else {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: unknown operation type %u "
		    "in acpidev_device_filter().", infop->awi_op_type);
		res = ACPIDEV_FILTER_FAILED;
	}

	return (res);
}

static ACPI_STATUS
acpidev_device_init(acpidev_walk_info_t *infop)
{
	char unitaddr[32];
	char *compatible[] = {
		ACPIDEV_TYPE_DEVICE,
		ACPIDEV_HID_VIRTNEX,
		ACPIDEV_TYPE_VIRTNEX,
	};

	if (ACPI_FAILURE(acpidev_set_compatible(infop,
	    ACPIDEV_ARRAY_PARAM(compatible)))) {
		return (AE_ERROR);
	}
	(void) snprintf(unitaddr, sizeof (unitaddr), "%u",
	    atomic_inc_32_nv(&acpidev_device_unitaddr) - 1);
	if (ACPI_FAILURE(acpidev_set_unitaddr(infop, NULL, 0, unitaddr))) {
		return (AE_ERROR);
	}

	return (AE_OK);
}
