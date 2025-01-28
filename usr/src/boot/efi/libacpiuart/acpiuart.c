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
 * UEFI/ACPI UART implementation.
 */

#include <acpi.h>
#include <aclocal.h>
#include <acobject.h>
#include <acstruct.h>
#include <acnamesp.h>
#include <acutils.h>
#include <acmacros.h>
#include <acevents.h>
#include <actbl.h>
#include <actbl1.h>
#include <actbl3.h>

#include <acpi_efi.h>
#include <mmio_uart.h>
#include <pl011.h>
#include <bootstrap.h>
#include <limits.h>
#include <stdio.h>

/*
 * ACPICA is woefully out of date, so for now we define our own copy of the SPCR
 */
typedef struct
{
	ACPI_TABLE_HEADER	Header;
	UINT8			InterfaceType;
	UINT8			Reserved[3];
	ACPI_GENERIC_ADDRESS	SerialPort;
	UINT8			InterruptType;
	UINT8			PcInterrupt;
	UINT32			Interrupt;
	UINT8			BaudRate;
	UINT8			Parity;
	UINT8			StopBits;
	UINT8			FlowControl;
	UINT8			TerminalType;
	UINT8			Reserved1;
	UINT16			PciDeviceId;
	UINT16			PciVendorId;
	UINT8			PciBus;
	UINT8			PciDevice;
	UINT8			PciFunction;
	UINT32			PciFlags;
	UINT8			PciSegment;
	UINT32			ClockFrequency;
	UINT32			PreciseBaudRate;
	UINT16			NamepathLength;
	UINT16			NamepathOffset;
	/* NamespaceString[] */
} ACPI_TABLE_SPCR_V4;

typedef struct {
	char			sd_acpi_name[128];
	uint64_t		sd_addr;
	uint64_t		sd_addr_size;
	mmio_uart_speed_t	sd_speed;
	mmio_uart_type_t	sd_type;
	uint64_t		sd_frequency;
	mmio_uart_data_bits_t	sd_data_bits;
	mmio_uart_parity_t	sd_parity;
	mmio_uart_stop_bits_t	sd_stop_bits;
	bool			sd_ignore_cd;
	bool			sd_rtsdtr_off;
} spcr_data_t;

typedef struct {
	char			*uad_hid;
	char			*uad_uid_str;
	char			*uad_name_stem;
	char			*uad_name_tail;
	uint32_t		uad_name_idx;
	uint32_t		uad_uid;
} uart_aux_data_t;

#define	MAX_UARTS	26

typedef struct {
	uint32_t	data1;
	uint16_t	data2;
	uint16_t	data3;
	uint8_t		data4[8];
} compat_guid_t;

typedef struct {
	const char		aum_hid[32];
	size_t			aum_hid_len;
	mmio_uart_type_t	aum_type;
} acpi_uart_match_t;

static acpi_uart_match_t acpi_uart_match[] = {
	{
		.aum_hid = "ARMH0011",
		.aum_hid_len = 9,	/* includes NUL */
		.aum_type = MMIO_UART_TYPE_PL011
	},
};
static size_t num_acpi_uart_match =
    sizeof (acpi_uart_match) / sizeof (acpi_uart_match[0]);

static mmio_uart_t mmio_uart[MAX_UARTS];
static size_t num_mmio_uart;

static pl011_info_t pl011_info[MAX_UARTS];
static size_t num_pl011_info;

static uart_aux_data_t uart_aux_data[MAX_UARTS];
static size_t num_uart_aux_data;

static const compat_guid_t acpi_dsd_uuid = {
	.data1 = 0xdaffd814,
	.data2 = 0x6eba,
	.data3 = 0x4d8c,
	.data4 = {0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a, 0xa3, 0x01}
};

static bool
acpiuart_node_is_compatible_uart(const char *name, size_t len,
    mmio_uart_type_t *uart_type)
{
	size_t i;

	for (i = 0; i < num_acpi_uart_match; ++i) {
		if (len != acpi_uart_match[i].aum_hid_len)
			continue;

		if (memcmp(name, acpi_uart_match[i].aum_hid, len) != 0)
			continue;

		if (uart_type != NULL)
			*uart_type = acpi_uart_match[i].aum_type;

		return (true);
	}

	return (false);
}

static ACPI_STATUS
armh0011_set_memory32(pl011_info_t *pl011, ACPI_RESOURCE *rp)
{
	if (pl011 == NULL || rp == NULL)
		return (AE_ERROR);
	if (rp->Type != ACPI_RESOURCE_TYPE_MEMORY32)
		return (AE_ERROR);
	if (pl011->pl_addr != 0 && pl011->pl_addr_len != 0)
		return (AE_SUPPORT);
	if (rp->Data.Memory32.WriteProtect != ACPI_READ_WRITE_MEMORY)
		return (AE_OK);
	if (rp->Data.Memory32.AddressLength == 0)
		return (AE_OK);

	pl011->pl_addr = rp->Data.Memory32.Minimum;
	pl011->pl_addr_len = rp->Data.Memory32.AddressLength;
	return (AE_OK);
}

static ACPI_STATUS
armh0011_set_fixed_memory32(pl011_info_t *pl011, ACPI_RESOURCE *rp)
{
	if (pl011 == NULL || rp == NULL)
		return (AE_ERROR);
	if (rp->Type != ACPI_RESOURCE_TYPE_FIXED_MEMORY32)
		return (AE_ERROR);
	if (pl011->pl_addr != 0 && pl011->pl_addr_len != 0)
		return (AE_SUPPORT);
	if (rp->Data.FixedMemory32.WriteProtect != ACPI_READ_WRITE_MEMORY)
		return (AE_OK);
	if (rp->Data.FixedMemory32.AddressLength == 0)
		return (AE_OK);

	pl011->pl_addr = rp->Data.FixedMemory32.Address;
	pl011->pl_addr_len = rp->Data.FixedMemory32.AddressLength;
	return (AE_OK);
}

static ACPI_STATUS
armh0011_set_addressx(pl011_info_t *pl011, ACPI_RESOURCE *rp)
{
	ACPI_RESOURCE_ADDRESS64 addr64;
	ACPI_STATUS st;

	if (pl011 == NULL || rp == NULL)
		return (AE_ERROR);

	if (rp->Type != ACPI_RESOURCE_TYPE_ADDRESS16 &&
	    rp->Type != ACPI_RESOURCE_TYPE_ADDRESS32 &&
	    rp->Type != ACPI_RESOURCE_TYPE_ADDRESS64)
		return (AE_ERROR);

	st = AcpiResourceToAddress64(rp, &addr64);
	if (ACPI_FAILURE(st))
		return (st);

	if (addr64.ResourceType != ACPI_MEMORY_RANGE)
		return (AE_SUPPORT);

	if (addr64.Address.AddressLength == 0)
		return (AE_OK);

	pl011->pl_addr = addr64.Address.Minimum;
	pl011->pl_addr_len = addr64.Address.AddressLength;
	return (AE_OK);
}

static ACPI_STATUS
armh0011_set_extaddress64(pl011_info_t *pl011, ACPI_RESOURCE *rp)
{
	if (pl011 == NULL || rp == NULL)
		return (AE_ERROR);

	if (rp->Type != ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64)
		return (AE_ERROR);

	if (rp->Data.ExtAddress64.Address.AddressLength == 0)
		return (AE_OK);

	pl011->pl_addr = rp->Data.ExtAddress64.Address.Minimum;
	pl011->pl_addr_len = rp->Data.ExtAddress64.Address.AddressLength;
	return (AE_OK);
}

static ACPI_STATUS
armh0011_crs_cb(ACPI_RESOURCE *rp, void *context)
{
	ACPI_STATUS status = AE_OK;
	pl011_info_t *pl011 = context;

	switch (rp->Type) {
	case ACPI_RESOURCE_TYPE_MEMORY32:
		status = armh0011_set_memory32(pl011, rp);
		break;
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
		status = armh0011_set_fixed_memory32(pl011, rp);
		break;
	case ACPI_RESOURCE_TYPE_ADDRESS16:	/* fallthrough */
	case ACPI_RESOURCE_TYPE_ADDRESS32:	/* fallthrough */
	case ACPI_RESOURCE_TYPE_ADDRESS64:
		status = armh0011_set_addressx(pl011, rp);
		break;
	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
		status = armh0011_set_extaddress64(pl011, rp);
		break;
	default:
		break;
	}

	return (status);
}

static bool
is_good_dsd(const ACPI_OBJECT *guid, const ACPI_OBJECT *dsd_pkg)
{
	if (guid == NULL || dsd_pkg == NULL)
		return (false);

	if (guid->Type != ACPI_TYPE_BUFFER ||
	    dsd_pkg->Type != ACPI_TYPE_PACKAGE)
		return (false);

	if (guid->Buffer.Length != sizeof (acpi_dsd_uuid))
		return (false);

	return (memcmp(guid->Buffer.Pointer,
	    &acpi_dsd_uuid, sizeof (acpi_dsd_uuid)) == 0);
}

static bool
acpi_node_status_ok(ACPI_HANDLE handle)
{
	ACPI_STATUS status;
	ACPI_BUFFER sta_buf;
	ACPI_OBJECT sta_obj;

	sta_buf.Pointer = &sta_obj;
	sta_buf.Length = sizeof (sta_obj);

	status = AcpiEvaluateObjectTyped(handle,
	    METHOD_NAME__STA, NULL, &sta_buf, ACPI_TYPE_INTEGER);
	if (ACPI_FAILURE(status))
		return ((status == AE_NOT_FOUND) ? true : false);

	if (sta_obj.Integer.Value < 0)
		return (false);

	/*
	 * We want devices that are present, enabled _and_ functioning.
	 */
	if ((sta_obj.Integer.Value & (ACPI_STA_DEVICE_PRESENT|
	    ACPI_STA_DEVICE_FUNCTIONING|ACPI_STA_DEVICE_ENABLED)) ==
	    (ACPI_STA_DEVICE_PRESENT|ACPI_STA_DEVICE_FUNCTIONING|
	    ACPI_STA_DEVICE_ENABLED))
		return (true);

	return (false);
}

static ACPI_STATUS
process_armh0011(ACPI_HANDLE handle, ACPI_DEVICE_INFO *obj,
    spcr_data_t *spcr, mmio_uart_type_t uart_type)
{
	ACPI_STATUS status;
	ACPI_BUFFER buf;
	ACPI_BUFFER dsd_buf;
	pl011_info_t *pl011;
	mmio_uart_t *uart;
	uart_aux_data_t *aux;
	char devpath[128] = {0};
	char devname[128] = {0};
	size_t n;
	size_t i;

	if (num_mmio_uart >= MAX_UARTS || num_pl011_info >= MAX_UARTS ||
	    num_uart_aux_data >= MAX_UARTS)
		return (AE_CTRL_TERMINATE);

	if (obj->Type != ACPI_TYPE_DEVICE)
		return (AE_OK);

	if (!acpi_node_status_ok(handle))
		return (AE_OK);

	buf.Pointer = devpath;
	buf.Length = sizeof (devpath) - 1;
	status = AcpiGetName(handle, ACPI_FULL_PATHNAME, &buf);
	if (ACPI_FAILURE(status))
		return (status);
	devpath[buf.Length] = '\0';

	buf.Pointer = devname;
	buf.Length = sizeof (devname) - 1;
	status = AcpiGetName(handle, ACPI_SINGLE_NAME, &buf);
	if (ACPI_FAILURE(status))
		return (status);
	devname[buf.Length] = '\0';

	pl011 = &pl011_info[num_pl011_info];
	memset(pl011, 0, sizeof (*pl011));

	/*
	 * Use the _CSR method to get the address and size.
	 */
	status = AcpiWalkResources(handle, "_CRS", armh0011_crs_cb, pl011);
	if (ACPI_FAILURE(status))
		return (status);

	if (pl011->pl_addr == 0 || pl011->pl_addr_len == 0)
		return (AE_SUPPORT);

	/*
	 * Use _DSD to get the clock frequency when available.
	 */
	dsd_buf.Length = ACPI_ALLOCATE_BUFFER;
	dsd_buf.Pointer = NULL;
	status = AcpiEvaluateObjectTyped(handle, "_DSD", NULL, &dsd_buf,
	    ACPI_TYPE_PACKAGE);
	if (ACPI_SUCCESS(status)) {
		const ACPI_OBJECT	*dsd;
		const ACPI_OBJECT	*guid;
		const ACPI_OBJECT	*dsd_pkg;

		dsd = dsd_buf.Pointer;
		guid = &dsd->Package.Elements[0];
		dsd_pkg = &dsd->Package.Elements[1];

		if (is_good_dsd(guid, dsd_pkg)) {
			int i;

			for (i = 0; i < dsd_pkg->Package.Count; i ++) {
				ACPI_OBJECT *pkg;
				ACPI_OBJECT *name;
				ACPI_OBJECT *val;

				pkg = &dsd_pkg->Package.Elements[i];
				if (pkg->Type != ACPI_TYPE_PACKAGE ||
				    pkg->Package.Count != 2)
					continue;

				name = &pkg->Package.Elements[0];
				val = &pkg->Package.Elements[1];

				if (name->Type != ACPI_TYPE_STRING ||
				    val->Type != ACPI_TYPE_INTEGER)
					continue;

				if (strncmp("clock-frequency",
				    name->String.Pointer,
				    name->String.Length) != 0)
					continue;

				if (val->Integer.Value) {
					pl011->pl_frequency =
					    val->Integer.Value;
					break;
				}
			}
		}

		AcpiOsFree(dsd_buf.Pointer);
	}

	pl011->pl_variant = uart_type;
	uart = &mmio_uart[num_mmio_uart];
	memset(uart, 0, sizeof (*uart));

	uart->mu_flags = 0;
	uart->mu_base = pl011->pl_addr;
	uart->mu_type = uart_type;
	uart->mu_ctx = pl011;
	uart->mu_ops = &mmio_uart_pl011_ops;

	uart->mu_speed = MMIO_UART_DEFAULT_COMSPEED;
	uart->mu_data_bits = MMIO_UART_DATA_BITS_8;
	uart->mu_parity = MMIO_UART_PARITY_NONE;
	uart->mu_stop_bits = MMIO_UART_STOP_BITS_1;
	uart->mu_ignore_cd = true;
	uart->mu_rtsdtr_off = false;

	/*
	 * v4 SPCR lets us match on the namespace name, but earlier
	 * versions don't have that information, so we match the
	 * MMIO base address as well.
	 *
	 * When we are SPCR-configured we set ourselves as the stdout,
	 * note that we've been configured by firmware and mark the
	 * configuration as locked.
	 */
	if ((strcmp(devpath, spcr->sd_acpi_name) == 0) ||
	    (pl011->pl_addr == spcr->sd_addr)) {
		if (pl011->pl_frequency == 0 && spcr->sd_frequency != 0)
			pl011->pl_frequency = spcr->sd_frequency;

		uart->mu_flags |= MMIO_UART_STDOUT;

		uart->mu_speed = spcr->sd_speed;
		uart->mu_data_bits = spcr->sd_data_bits;
		uart->mu_parity = spcr->sd_parity;
		uart->mu_stop_bits = spcr->sd_stop_bits;
		uart->mu_ignore_cd = spcr->sd_ignore_cd;
		uart->mu_rtsdtr_off = spcr->sd_rtsdtr_off;

		uart->mu_flags |= MMIO_UART_CONFIG_FW_SPECIFIED;
		uart->mu_flags |= MMIO_UART_CONFIG_LOCKED;
	}

	uart->mu_serial_idx = 0xFFFFFFFF;

	if ((uart->mu_fwpath = strdup(devpath)) == NULL)
		return (AE_SUPPORT);

	if ((uart->mu_fwname = strdup(devname)) == NULL) {
		free(uart->mu_fwpath);
		return (AE_SUPPORT);
	}

	aux = &uart_aux_data[num_uart_aux_data];

	aux->uad_uid_str = NULL;
	aux->uad_uid = 0;

	if (obj->Valid & ACPI_VALID_UID) {
		long uid;
		char *ep;

		if ((aux->uad_uid_str = strdup(obj->UniqueId.String)) == NULL) {
			free(uart->mu_fwpath);
			free(uart->mu_fwname);
			return (AE_SUPPORT);
		}

		uid = strtol(aux->uad_uid_str, &ep, 10);
		if (uid >= 0 &&
		    uid != LONG_MIN && uid != LONG_MAX && *ep == '\0') {
			aux->uad_uid = uid;
		} else {
			aux->uad_uid = 0xFFFFFFFF;
		}
	} else {
		aux->uad_uid = 0;
	}

	if (obj->Valid & ACPI_VALID_HID) {
		if ((aux->uad_hid = strdup(obj->HardwareId.String)) == NULL) {
			if (aux->uad_uid_str != NULL)
				free(aux->uad_uid_str);
			free(uart->mu_fwpath);
			free(uart->mu_fwname);
			return (AE_SUPPORT);
		}
	}

	if ((aux->uad_name_stem = strdup(uart->mu_fwname)) == NULL) {
		if (aux->uad_hid != NULL)
			free(aux->uad_hid);
		if (aux->uad_uid_str != NULL)
			free(aux->uad_uid_str);
		free(uart->mu_fwpath);
		free(uart->mu_fwname);
		return (AE_SUPPORT);
	}

	n = strlen(aux->uad_name_stem);
	for (i = 0; i < n; ++i) {
		if (!isalpha(aux->uad_name_stem[i])) {
			aux->uad_name_stem[i] = '\0';
			break;
		}
	}

	if (strlen(aux->uad_name_stem) != n) {
		aux->uad_name_tail =
		    strdup(&uart->mu_fwname[strlen(aux->uad_name_stem)]);
		if (aux->uad_name_tail == NULL) {
			free(aux->uad_name_stem);
			if (aux->uad_hid != NULL)
				free(aux->uad_hid);
			if (aux->uad_uid_str != NULL)
				free(aux->uad_uid_str);
			free(uart->mu_fwpath);
			free(uart->mu_fwname);
			return (AE_SUPPORT);
		}
	}

	aux->uad_name_idx = 0xFFFFFFFF;
	if (aux->uad_name_tail != NULL) {
		long tail;
		char *ep;

		tail = strtol(aux->uad_name_tail, &ep, 10);
		if (tail >= 0 &&
		    tail != LONG_MIN && tail != LONG_MAX && *ep == '\0') {
			aux->uad_name_idx = tail;
		}
	}

	uart->mu_flags |= MMIO_UART_VALID;
	num_mmio_uart++;
	num_pl011_info++;
	num_uart_aux_data++;
	return (AE_OK);
}

static ACPI_STATUS
acpiuart_device_callback(ACPI_HANDLE handle, UINT32 level,
    void *context, void **b)
{
	ACPI_STATUS status;
	ACPI_DEVICE_INFO *obj;
	UINT32 n;
	mmio_uart_type_t uart_type;
	spcr_data_t *spcr = context;
	bool matched = false;

	status = AcpiGetObjectInfo(handle, &obj);
	if (ACPI_FAILURE(status))
		return (status);

	if (obj->Type != ACPI_TYPE_DEVICE) {
		AcpiOsFree(obj);
		return (AE_OK);
	}

	if (obj->Valid & ACPI_VALID_HID) {
		if (acpiuart_node_is_compatible_uart(obj->HardwareId.String,
		    obj->HardwareId.Length, &uart_type)) {
			matched = true;
		}
	}

	if (!matched && (obj->Valid & ACPI_VALID_CID)) {
		for (n = 0; n < obj->CompatibleIdList.Count; ++n) {
			if (acpiuart_node_is_compatible_uart(
			    obj->CompatibleIdList.Ids[n].String,
			    obj->CompatibleIdList.Ids[n].Length, &uart_type)) {
				matched = true;
				break;
			}
		}
	}

	if (!matched) {
		AcpiOsFree(obj);
		return (AE_OK);
	}

	/*
	 * We have a match, ingest the UART based on type.
	 */
	switch (uart_type) {
	case MMIO_UART_TYPE_PL011:	/* fallthrough */
	case MMIO_UART_TYPE_ARM_GENERIC:
		process_armh0011(handle, obj, spcr, uart_type);
		break;
	default:
		break;
	}

	AcpiOsFree(obj);
	return (AE_OK);
}

static void
acpiuart_parse_spcr(const ACPI_TABLE_SPCR_V4 *tab, spcr_data_t *spcr)
{
	memset(spcr, 0, sizeof (*spcr));

	if (!tab || tab->Header.Revision < 2)
		return;

	switch (tab->InterfaceType) {
	case ACPI_DBG2_ARM_PL011:
		spcr->sd_type = MMIO_UART_TYPE_PL011;
		break;
	case ACPI_DBG2_ARM_SBSA_32BIT:	/* fallthrough */
	case ACPI_DBG2_ARM_SBSA_GENERIC:
		spcr->sd_type = MMIO_UART_TYPE_ARM_GENERIC;
		break;
	default:
		return;
	}

	spcr->sd_acpi_name[0] = '.';
	spcr->sd_acpi_name[1] = '\0';

	if (tab->Header.Revision >= 4 &&
	    tab->NamepathOffset != 0 && tab->NamepathLength >= 2) {
		const char *nsstr = ((const char *)tab) + tab->NamepathOffset;
		if (nsstr[0] != '\0') {
			strncpy(spcr->sd_acpi_name, nsstr,
			    sizeof (spcr->sd_acpi_name) - 1);
			spcr->sd_acpi_name[
			    sizeof (spcr->sd_acpi_name) - 1] = '\0';
		}
	}

	/*
	 * We are quite picky about the UART register layout that we will
	 * accept. This covers the usual case on Arm platforms, but we
	 * might need to make things more complictated if we run across
	 * weird hardware in the wild.
	 */
	if (tab->SerialPort.SpaceId != 0x0 ||	/* system memory space */
	    tab->SerialPort.BitOffset != 0 ||	/* bit offset of the register */
	    tab->SerialPort.BitWidth != 32 ||	/* size of the register */
	    tab->SerialPort.AccessWidth != 3 ||	/* dword access */
	    tab->SerialPort.Address == 0) {	/* must have an address */
		return;
	}

	/*
	 * All other values are reserved. Note that this actually fires on
	 * Qemu's SBSA-REF machine, which should really be fully compliant.
	 *
	 * When Microsoft updates the SPCR specification we'll need to re-check
	 * this code.
	 */
	if (tab->Parity != 0) {
		mmio_uart_puts("WARNING: acpiuart: "
		    "Ignoring out-of-spec SPCR parity value 0x");
		mmio_uart_putn(tab->Parity, 16);
		mmio_uart_puts("\n");
	}
	spcr->sd_parity = MMIO_UART_PARITY_NONE;

	/*
	 * All other values are reserved.
	 */
	if (tab->StopBits != 1) {
		mmio_uart_puts("WARNING: acpiuart: "
		    "Ignoring out-of-spec SPCR stop bits value 0x");
		mmio_uart_putn(tab->StopBits, 16);
		mmio_uart_puts("\n");
	}
	spcr->sd_stop_bits = MMIO_UART_STOP_BITS_1;

	/*
	 * I assume (big assumption) that data bits is set to 8 - the spec
	 * makes no mention of this setting.
	 */
	spcr->sd_data_bits = MMIO_UART_DATA_BITS_8;

	/*
	 * Other bits are hardware flow control, which loader does not support.
	 */
	if (tab->FlowControl & 0x1)
		spcr->sd_ignore_cd = false;
	else
		spcr->sd_ignore_cd = true;

	spcr->sd_rtsdtr_off = false;

	if (tab->Header.Revision >= 3)
		spcr->sd_frequency = tab->ClockFrequency;

	if (tab->Header.Revision >= 4)
		spcr->sd_speed = (mmio_uart_speed_t)tab->PreciseBaudRate;

	if (!spcr->sd_speed) {
		switch (tab->BaudRate) {
		case 0:
			spcr->sd_speed = 0;	/* as-is (probe) */
			break;
		case 3:
			spcr->sd_speed = 9600;
			break;
		case 4:
			spcr->sd_speed = 19200;
			break;
		case 6:
			spcr->sd_speed = 57600;
			break;
		case 7:
			spcr->sd_speed = 115200;
			break;
		default:
			spcr->sd_speed = 0;	/* unrecognised */
			break;
		}
	}

	/* pl011 is a 4k frame, generic is close enough */
	spcr->sd_addr_size = 0x1000;
	spcr->sd_addr = tab->SerialPort.Address;
}

static bool
acpiuart_renumber_uarts(void)
{
	size_t idx;
	uart_aux_data_t *aux;
	const char *prev;
	bool use;

	/*
	 * If all of our ports have the same _HID value and have valid
	 * integer _UID values then we can use _UID as the console index.
	 *
	 * We rebase the _UID values to 0 so that we assign names starting
	 * from ttya.
	 */
	for (use = true, prev = NULL, idx = 0; idx < num_uart_aux_data; ++idx) {
		aux = &uart_aux_data[idx];

		if (aux->uad_hid == NULL || aux->uad_uid == 0xFFFFFFFF) {
			use = false;
			break;
		}

		if (prev != NULL) {
			if (strcmp(aux->uad_hid, prev) != 0) {
				use = false;
				break;
			}
		}

		prev = aux->uad_hid;
	}

	if (use) {
		uint32_t lowest = 0xffffffff;

		for (idx = 0; idx < num_uart_aux_data; ++idx)
			if (uart_aux_data[idx].uad_uid < lowest)
				lowest = uart_aux_data[idx].uad_uid;

		if (lowest != 0xffffffff) {
			for (idx = 0; idx < num_uart_aux_data; ++idx)
				mmio_uart[idx].mu_serial_idx =
				    (uart_aux_data[idx].uad_uid - lowest);

			return (true);
		}

		use = false;
	}

	/*
	 * If the object name for all uarts has the same stem and has trailing
	 * digits, then use the tail of the object name for the UART index.
	 *
	 * Like the _UID case, we rebase the integer values to 0 so that we
	 * assign names starting from ttya.
	 */
	for (use = true, prev = NULL, idx = 0; idx < num_uart_aux_data; ++idx) {
		aux = &uart_aux_data[idx];

		if (aux->uad_name_stem == NULL || aux->uad_name_tail == NULL ||
		    aux->uad_name_idx == 0xFFFFFFFF) {
			use = false;
			break;
		}

		if (prev != NULL) {
			if (strcmp(prev, aux->uad_name_stem) != 0) {
				use = false;
				break;
			}
		}

		prev = aux->uad_name_stem;
	}

	if (use) {
		uint32_t lowest = 0xffffffff;

		for (idx = 0; idx < num_uart_aux_data; ++idx)
			if (uart_aux_data[idx].uad_name_idx < lowest)
				lowest = uart_aux_data[idx].uad_name_idx;

		if (lowest != 0xffffffff) {
			for (idx = 0; idx < num_uart_aux_data; ++idx)
				mmio_uart[idx].mu_serial_idx =
				    (uart_aux_data[idx].uad_name_idx - lowest);

			return (true);
		}

		use = false;
	}

	return (false);
}

void
acpiuart_discover_uarts(void)
{
	ACPI_STATUS status;
	ACPI_HANDLE sysbus_hdl;
	ACPI_TABLE_HEADER *spcr_table;
	spcr_data_t spcr;
	size_t idx;
	size_t c;
	size_t n;
	struct console **tmp;
	struct console *tty;
	struct console *first_tty = NULL;

	status = AcpiGetTable(ACPI_SIG_SPCR, 1, &spcr_table);
	if (ACPI_FAILURE(status))
		spcr_table = NULL;

	(void) acpiuart_parse_spcr(
	    (ACPI_TABLE_SPCR_V4 *)spcr_table, &spcr);

	status = AcpiGetHandle(NULL, "\\_SB_", &sysbus_hdl);
	if (ACPI_FAILURE(status))
		return;

	status = AcpiWalkNamespace(ACPI_TYPE_DEVICE, sysbus_hdl, UINT32_MAX,
	    acpiuart_device_callback, NULL, &spcr, NULL);
	if (ACPI_FAILURE(status))
		return;

	if (num_mmio_uart == 0) {
		mmio_uart_puts("WARNING: acpiuart: no compatible MMIO UARTs\n");
		return;
	}

	if (!acpiuart_renumber_uarts()) {
		mmio_uart_puts("WARNING: acpiuart: Assigning indices in "
		    "discovery order\n");
		for (idx = 0; idx < num_mmio_uart; ++idx)
			mmio_uart[idx].mu_serial_idx = idx;
	}

	n = num_mmio_uart;
	c = cons_array_size();

	if (c == 0)
		n++;

	if ((tmp = realloc(consoles, (c + n) * sizeof (*consoles))) == NULL)
		return;

	consoles = tmp;
	if (c > 0)
		c--;

	for (idx = 0; idx < num_mmio_uart; ++idx) {
		mmio_uart_t *uart = &mmio_uart[idx];

		if ((tty = mmio_uart_make_tty(uart)) == NULL) {
			consoles[c] = tty;
			return;
		}

		if (idx == 0)
			first_tty = tty;

		if ((uart->mu_flags & MMIO_UART_STDOUT) &&
		    getenv("default-uart-name") == NULL) {
			setenv("default-uart-name", tty->c_name, 1);
		}

		consoles[c++] = tty;
	}

	if (getenv("default-uart-name") == NULL && first_tty != NULL)
		setenv("default-uart-name", first_tty->c_name, 1);

	consoles[c] = NULL;
}
