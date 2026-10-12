/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/param.h>
#ifdef	__FreeBSD__
#include <sys/endian.h>
#else
#include <endian.h>
#endif
#include <sys/stat.h>

#include <machine/vmm.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "acpi_device.h"
#include "bhyverun.h"
#include "config.h"
#include "inout.h"
#include "pci_lpc.h"
#include "qemu_fwcfg.h"

#define QEMU_FWCFG_ACPI_DEVICE_NAME "FWCF"
#define QEMU_FWCFG_ACPI_HARDWARE_ID "QEMU0002"

#define QEMU_FWCFG_SELECTOR_PORT_NUMBER 0x510
#define QEMU_FWCFG_SELECTOR_PORT_SIZE 1
#define QEMU_FWCFG_SELECTOR_PORT_FLAGS IOPORT_F_INOUT
#define QEMU_FWCFG_DATA_PORT_NUMBER 0x511
#define QEMU_FWCFG_DATA_PORT_SIZE 1
#define QEMU_FWCFG_DATA_PORT_FLAGS \
	IOPORT_F_INOUT /* QEMU v2.4+ ignores writes */

#define QEMU_FWCFG_ARCHITECTURE_MASK 0x0001
#define QEMU_FWCFG_INDEX_MASK 0x3FFF

#define QEMU_FWCFG_SELECT_READ 0
#define QEMU_FWCFG_SELECT_WRITE 1

#define QEMU_FWCFG_ARCHITECTURE_GENERIC 0
#define QEMU_FWCFG_ARCHITECTURE_SPECIFIC 1

#define QEMU_FWCFG_INDEX_SIGNATURE 0x00
#define QEMU_FWCFG_INDEX_ID 0x01
#define QEMU_FWCFG_INDEX_NB_CPUS 0x05
#define QEMU_FWCFG_INDEX_MAX_CPUS 0x0F
#define QEMU_FWCFG_INDEX_FILE_DIR 0x19

#define QEMU_FWCFG_FIRST_FILE_INDEX 0x20

#define QEMU_FWCFG_MIN_FILES 10

#pragma pack(1)

union qemu_fwcfg_selector {
	struct {
		uint16_t index : 14;
		uint16_t writeable : 1;
		uint16_t architecture : 1;
	};
	uint16_t bits;
};

struct qemu_fwcfg_signature {
	uint8_t signature[4];
};

struct qemu_fwcfg_id {
	uint32_t interface : 1; /* always set */
	uint32_t DMA : 1;
	uint32_t reserved : 30;
};

struct qemu_fwcfg_file {
	uint32_t be_size;
	uint16_t be_selector;
	uint16_t reserved;
	uint8_t name[QEMU_FWCFG_MAX_NAME];
};

struct qemu_fwcfg_directory {
	uint32_t be_count;
	struct qemu_fwcfg_file files[0];
};

#pragma pack()

struct qemu_fwcfg_softc {
	struct acpi_device *acpi_dev;

	uint32_t data_offset;
	union qemu_fwcfg_selector selector;
	struct qemu_fwcfg_item items[QEMU_FWCFG_MAX_ARCHS]
				    [QEMU_FWCFG_MAX_ENTRIES];
	struct qemu_fwcfg_directory *directory;
};

static struct qemu_fwcfg_softc fwcfg_sc;

static int
qemu_fwcfg_selector_port_handler(struct vmctx *const ctx __unused, const int in,
    const int port __unused, const int bytes, uint32_t *const eax,
    void *const arg __unused)
{
	if (bytes != sizeof(uint16_t)) {
		warnx("%s: invalid size (%d) of IO port access", __func__,
		    bytes);
		return (-1);
	}

	if (in) {
		*eax = htole16(fwcfg_sc.selector.bits);
		return (0);
	}

	fwcfg_sc.data_offset = 0;
	fwcfg_sc.selector.bits = le16toh(*eax);

	return (0);
}

static int
qemu_fwcfg_data_port_handler(struct vmctx *const ctx __unused, const int in,
    const int port __unused, const int bytes, uint32_t *const eax,
    void *const arg __unused)
{
	if (bytes != sizeof(uint8_t)) {
		warnx("%s: invalid size (%d) of IO port access", __func__,
		    bytes);
		return (-1);
	}

	if (!in) {
		warnx("%s: Writes to qemu fwcfg data port aren't allowed",
		    __func__);
		return (-1);
	}

	/* get fwcfg item */
	struct qemu_fwcfg_item *const item =
	    &fwcfg_sc.items[fwcfg_sc.selector.architecture]
			   [fwcfg_sc.selector.index];
	if (item->data == NULL) {
		warnx(
		    "%s: qemu fwcfg item doesn't exist (architecture %s index 0x%x)",
		    __func__,
		    fwcfg_sc.selector.architecture ? "specific" : "generic",
		    fwcfg_sc.selector.index);
		*eax = 0x00;
		return (0);
	} else if (fwcfg_sc.data_offset >= item->size) {
		warnx(
		    "%s: qemu fwcfg item read exceeds size (architecture %s index 0x%x size 0x%x offset 0x%x)",
		    __func__,
		    fwcfg_sc.selector.architecture ? "specific" : "generic",
		    fwcfg_sc.selector.index, item->size, fwcfg_sc.data_offset);
		*eax = 0x00;
		return (0);
	}

	/* return item data */
	*eax = item->data[fwcfg_sc.data_offset];
	fwcfg_sc.data_offset++;

	return (0);
}

static int
qemu_fwcfg_add_item(const uint16_t architecture, const uint16_t index,
    const uint32_t size, void *const data)
{
	/* truncate architecture and index to their desired size */
	const uint16_t arch = architecture & QEMU_FWCFG_ARCHITECTURE_MASK;
	const uint16_t idx = index & QEMU_FWCFG_INDEX_MASK;

	/* get pointer to item specified by selector */
	struct qemu_fwcfg_item *const fwcfg_item = &fwcfg_sc.items[arch][idx];

	/* check if item is already used */
	if (fwcfg_item->data != NULL) {
		warnx("%s: qemu fwcfg item exists (architecture %s index 0x%x)",
		    __func__, arch ? "specific" : "generic", idx);
		return (EEXIST);
	}

	/* save data of the item */
	fwcfg_item->size = size;
	fwcfg_item->data = data;

	return (0);
}

static int
qemu_fwcfg_add_item_file_dir(void)
{
	const size_t size = sizeof(struct qemu_fwcfg_directory) +
	    QEMU_FWCFG_MIN_FILES * sizeof(struct qemu_fwcfg_file);
#ifdef	__FreeBSD__
	struct qemu_fwcfg_directory *const fwcfg_directory = calloc(1, size);
#else
	// SMATCH: double check that we're allocating correct size: 4 vs 644
	void *ptr = calloc(1, size);
	struct qemu_fwcfg_directory *const fwcfg_directory =
	    (struct qemu_fwcfg_directory *)ptr;
#endif
	if (fwcfg_directory == NULL) {
		return (ENOMEM);
	}

	fwcfg_sc.directory = fwcfg_directory;

	return (qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_FILE_DIR, sizeof(struct qemu_fwcfg_directory),
	    (uint8_t *)fwcfg_sc.directory));
}

static int
qemu_fwcfg_add_item_id(void)
{
	struct qemu_fwcfg_id *const fwcfg_id = calloc(1,
	    sizeof(struct qemu_fwcfg_id));
	if (fwcfg_id == NULL) {
		return (ENOMEM);
	}

	fwcfg_id->interface = 1;
	fwcfg_id->DMA = 0;

	uint32_t *const le_fwcfg_id_ptr = (uint32_t *)fwcfg_id;
	*le_fwcfg_id_ptr = htole32(*le_fwcfg_id_ptr);

	return (qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_ID, sizeof(struct qemu_fwcfg_id),
	    (uint8_t *)fwcfg_id));
}

static int
qemu_fwcfg_add_item_max_cpus(void)
{
	uint16_t *fwcfg_max_cpus = calloc(1, sizeof(uint16_t));
	if (fwcfg_max_cpus == NULL) {
		return (ENOMEM);
	}

	/*
	 * We don't support cpu hotplug yet. For that reason, use guest_ncpus instead
	 * of maxcpus.
	 */
	*fwcfg_max_cpus = htole16(guest_ncpus);

	return (qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_MAX_CPUS, sizeof(uint16_t), fwcfg_max_cpus));
}

static int
qemu_fwcfg_add_item_nb_cpus(void)
{
	uint16_t *fwcfg_max_cpus = calloc(1, sizeof(uint16_t));
	if (fwcfg_max_cpus == NULL) {
		return (ENOMEM);
	}

	*fwcfg_max_cpus = htole16(guest_ncpus);

	return (qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_NB_CPUS, sizeof(uint16_t), fwcfg_max_cpus));
}

static int
qemu_fwcfg_add_item_signature(void)
{
	struct qemu_fwcfg_signature *const fwcfg_signature = calloc(1,
	    sizeof(struct qemu_fwcfg_signature));
	if (fwcfg_signature == NULL) {
		return (ENOMEM);
	}

	fwcfg_signature->signature[0] = 'Q';
	fwcfg_signature->signature[1] = 'E';
	fwcfg_signature->signature[2] = 'M';
	fwcfg_signature->signature[3] = 'U';

	return (qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_SIGNATURE, sizeof(struct qemu_fwcfg_signature),
	    (uint8_t *)fwcfg_signature));
}

static int
qemu_fwcfg_register_port(const char *const name, const int port, const int size,
    const int flags, const inout_func_t handler)
{
	struct inout_port iop;

	bzero(&iop, sizeof(iop));
	iop.name = name;
	iop.port = port;
	iop.size = size;
	iop.flags = flags;
	iop.handler = handler;

	return (register_inout(&iop));
}

int
qemu_fwcfg_add_file(const char *name, const uint32_t size, void *const data)
{
	if (strlen(name) >= QEMU_FWCFG_MAX_NAME)
		return (EINVAL);

	/*
	 * QEMU specifies count as big endian.
	 * Convert it to host endian to work with it.
	 */
	const uint32_t count = be32toh(fwcfg_sc.directory->be_count) + 1;

	/* add file to items list */
	const uint32_t index = QEMU_FWCFG_FIRST_FILE_INDEX + count - 1;
	const int error = qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    index, size, data);
	if (error != 0) {
		return (error);
	}

	/*
	 * files should be sorted alphabetical, get index for new file
	 */
	uint32_t file_index;
	for (file_index = 0; file_index < count - 1; ++file_index) {
#ifdef	__FreeBSD__
		if (strcmp(name, fwcfg_sc.directory->files[file_index].name) <
		    0)
			break;
#else
		if (strcmp((char *)name,
		    (char *)fwcfg_sc.directory->files[file_index].name) < 0) {
			break;
		}
#endif
	}

	if (count > QEMU_FWCFG_MIN_FILES) {
		/* alloc new file directory */
		const uint64_t new_size = sizeof(struct qemu_fwcfg_directory) +
		    count * sizeof(struct qemu_fwcfg_file);
		struct qemu_fwcfg_directory *const new_directory = calloc(1,
		    new_size);
		if (new_directory == NULL) {
			warnx(
			    "%s: Unable to allocate a new qemu fwcfg files directory (count %d)",
			    __func__, count);
			return (ENOMEM);
		}

		/* copy files below file_index to new directory */
		memcpy(new_directory->files, fwcfg_sc.directory->files,
		    file_index * sizeof(struct qemu_fwcfg_file));

		/* copy files above file_index to directory */
		memcpy(&new_directory->files[file_index + 1],
		    &fwcfg_sc.directory->files[file_index],
		    (count - file_index - 1) * sizeof(struct qemu_fwcfg_file));

		/* free old directory */
		free(fwcfg_sc.directory);

		/* set directory pointer to new directory */
		fwcfg_sc.directory = new_directory;

		/* adjust directory pointer */
		fwcfg_sc.items[0][QEMU_FWCFG_INDEX_FILE_DIR].data =
		    (uint8_t *)fwcfg_sc.directory;
	} else {
		/* shift files behind file_index */
		for (uint32_t i = QEMU_FWCFG_MIN_FILES - 1; i > file_index;
		     --i) {
			memcpy(&fwcfg_sc.directory->files[i],
			    &fwcfg_sc.directory->files[i - 1],
			    sizeof(struct qemu_fwcfg_file));
		}
	}

	/*
	 * QEMU specifies count, size and index as big endian.
	 * Save these values in big endian to simplify guest reads of these
	 * values.
	 */
	fwcfg_sc.directory->be_count = htobe32(count);
	fwcfg_sc.directory->files[file_index].be_size = htobe32(size);
	fwcfg_sc.directory->files[file_index].be_selector = htobe16(index);
#ifdef	__FreeBSD__
	strcpy(fwcfg_sc.directory->files[file_index].name, name);
#else
	strcpy((char *)fwcfg_sc.directory->files[file_index].name,
	    (char *)name);
#endif

	/* set new size for the fwcfg_file_directory */
	fwcfg_sc.items[0][QEMU_FWCFG_INDEX_FILE_DIR].size =
	    sizeof(struct qemu_fwcfg_directory) +
	    count * sizeof(struct qemu_fwcfg_file);

	return (0);
}

/*
 * Add a user defined fw_cfg file described by a "fwcfg.file.<N>" config node.
 * The node contains the file "name", a "type" and a "value". For a type of
 * "string", the value including the terminating NUL becomes the file data; for
 * a type of "file", the value is the path of a file whose content does.
 */
static int
qemu_fwcfg_add_user_file(const char *prefix __unused, const nvlist_t *parent,
    const char *node, int type, void *arg __unused)
{
	const nvlist_t *nvl;
	const char *ftype, *value;
	char *name, *path;
	struct stat sb;
	ssize_t bytes_read;
	uint32_t size;
	void *data;
	int error, fd;

	if (type != NV_TYPE_NVLIST) {
		warnx("fw_cfg: invalid user file configuration fwcfg.file.%s",
		    node);
		return (EINVAL);
	}
	nvl = nvlist_get_nvlist(parent, node);

	/*
	 * Expanded configuration values are only valid until the next fetch,
	 * so take copies.
	 */
	value = get_config_value_node(nvl, "name");
	if (value == NULL || strlen(value) >= QEMU_FWCFG_MAX_NAME) {
		warnx("fw_cfg: missing or invalid name for fwcfg.file.%s",
		    node);
		return (EINVAL);
	}
	if ((name = strdup(value)) == NULL)
		return (ENOMEM);

	data = NULL;
	path = NULL;
	error = 0;

	ftype = get_config_value_node(nvl, "type");
	if (ftype == NULL ||
	    (strcmp(ftype, "string") != 0 && strcmp(ftype, "file") != 0)) {
		warnx("fw_cfg: missing or invalid type for \"%s\"", name);
		error = EINVAL;
		goto done;
	}
	/* Fetching value invalidates ftype, so test it first. */
	if (strcmp(ftype, "string") == 0) {
		value = get_config_value_node(nvl, "value");
		if (value == NULL) {
			warnx("fw_cfg: missing value for \"%s\"", name);
			error = EINVAL;
			goto done;
		}
		if ((data = strdup(value)) == NULL) {
			warnx("Can't duplicate fw_cfg_user_file string \"%s\"",
			    value);
			error = ENOMEM;
			goto done;
		}
		size = strlen(data) + 1;
	} else {
		value = get_config_value_node(nvl, "value");
		if (value == NULL) {
			warnx("fw_cfg: missing value for \"%s\"", name);
			error = EINVAL;
			goto done;
		}
		if ((path = strdup(value)) == NULL) {
			error = ENOMEM;
			goto done;
		}

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			warn("Can't open fw_cfg_user_file file \"%s\"", path);
			error = EINVAL;
			goto done;
		}

		if (fstat(fd, &sb) < 0) {
			warn("Unable to get size of file \"%s\"", path);
			close(fd);
			error = -1;
			goto done;
		}

		data = malloc(sb.st_size);
		if (data == NULL) {
			warnx("Can't allocate fw_cfg_user_file file \"%s\" "
			    "(size: 0x%16lx)", path, sb.st_size);
			close(fd);
			error = ENOMEM;
			goto done;
		}
		bytes_read = read(fd, data, sb.st_size);
		close(fd);
		if (bytes_read < 0 || bytes_read != sb.st_size) {
			warn("Unable to read file \"%s\"", path);
			error = -1;
			goto done;
		}
		size = bytes_read;
	}

	error = qemu_fwcfg_add_file(name, size, data);

done:
	if (error != 0)
		free(data);
	free(path);
	free(name);
	return (error);
}

static int
qemu_fwcfg_add_user_files(void)
{
	const nvlist_t *nvl;

	nvl = find_config_node("fwcfg.file");
	if (nvl == NULL)
		return (0);

	return (walk_config_nodes("", nvl, NULL, qemu_fwcfg_add_user_file));
}

static const struct acpi_device_emul qemu_fwcfg_acpi_device_emul = {
	.name = QEMU_FWCFG_ACPI_DEVICE_NAME,
	.hid = QEMU_FWCFG_ACPI_HARDWARE_ID,
};

int
qemu_fwcfg_init(struct vmctx *const ctx)
{
	int error;

	/*
	 * Bhyve supports fwctl (bhyve) and fwcfg (qemu) as firmware interfaces.
	 * Both are using the same ports. So, it's not possible to provide both
	 * interfaces at the same time to the guest. Therefore, only create acpi
	 * tables and register io ports for fwcfg, if it's used.
	 */
	if (strcmp(lpc_fwcfg(), "qemu") == 0) {
		error = acpi_device_create(&fwcfg_sc.acpi_dev, &fwcfg_sc, ctx,
		    &qemu_fwcfg_acpi_device_emul);
		if (error) {
			warnx("%s: failed to create ACPI device for QEMU FwCfg",
			    __func__);
			goto done;
		}

		error = acpi_device_add_res_fixed_ioport(fwcfg_sc.acpi_dev,
		    QEMU_FWCFG_SELECTOR_PORT_NUMBER, 2);
		if (error) {
			warnx("%s: failed to add fixed IO port for QEMU FwCfg",
			    __func__);
			goto done;
		}

		/* add handlers for fwcfg ports */
		if ((error = qemu_fwcfg_register_port("qemu_fwcfg_selector",
		    QEMU_FWCFG_SELECTOR_PORT_NUMBER,
		    QEMU_FWCFG_SELECTOR_PORT_SIZE,
		    QEMU_FWCFG_SELECTOR_PORT_FLAGS,
		    qemu_fwcfg_selector_port_handler)) != 0) {
			warnx(
			    "%s: Unable to register qemu fwcfg selector port 0x%x",
			    __func__, QEMU_FWCFG_SELECTOR_PORT_NUMBER);
			goto done;
		}
		if ((error = qemu_fwcfg_register_port("qemu_fwcfg_data",
		    QEMU_FWCFG_DATA_PORT_NUMBER, QEMU_FWCFG_DATA_PORT_SIZE,
		    QEMU_FWCFG_DATA_PORT_FLAGS,
		    qemu_fwcfg_data_port_handler)) != 0) {
			warnx(
			    "%s: Unable to register qemu fwcfg data port 0x%x",
			    __func__, QEMU_FWCFG_DATA_PORT_NUMBER);
			goto done;
		}
	}

	/* add common fwcfg items */
	if ((error = qemu_fwcfg_add_item_signature()) != 0) {
		warnx("%s: Unable to add signature item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_id()) != 0) {
		warnx("%s: Unable to add id item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_nb_cpus()) != 0) {
		warnx("%s: Unable to add nb_cpus item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_max_cpus()) != 0) {
		warnx("%s: Unable to add max_cpus item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_file_dir()) != 0) {
		warnx("%s: Unable to add file_dir item", __func__);
		goto done;
	}

	/* add user defined fwcfg files */
	if ((error = qemu_fwcfg_add_user_files()) != 0) {
		warnx("%s: Unable to add user files", __func__);
		goto done;
	}

done:
	if (error) {
		acpi_device_destroy(fwcfg_sc.acpi_dev);
	}

	return (error);
}

static void
qemu_fwcfg_usage(const char *opt)
{
	warnx("Invalid fw_cfg option \"%s\"", opt);
	warnx("-f [name=]<name>,(string|file)=<value>");
}

/*
 * Store a value from the command line in the configuration such that it is
 * returned verbatim, by escaping the characters that configuration value
 * expansion treats specially.
 */
static void
qemu_fwcfg_set_literal(nvlist_t *nvl, const char *name, const char *value,
    size_t len)
{
	char *buf, *bp;

	buf = malloc(len * 2 + 1);
	if (buf == NULL)
		errx(4, "Failed to allocate memory");

	for (bp = buf; len > 0; len--, value++) {
		if (*value == '%' || *value == '\\')
			*bp++ = '\\';
		*bp++ = *value;
	}
	*bp = '\0';

	set_config_value_node(nvl, name, buf);
	free(buf);
}

/*
 * Parses the cmdline argument for user defined fw_cfg items. The cmdline
 * argument has the format:
 * "-f [name=]<name>,(string|file)=<value>"
 *
 * E.g.: "-f opt/com.page/example,string=Hello"
 *
 * Each item is recorded in the configuration as a "fwcfg.file.<N>" node
 * containing "name", "type" and "value", so that it is preserved when the
 * configuration is saved with config.dump and later loaded with -k.
 * The node is processed by qemu_fwcfg_add_user_file() during initialisation.
 */
int
qemu_fwcfg_parse_cmdline_arg(const char *opt)
{
	const char *opt_ptr, *opt_end, *name;
	char node_name[32];
	size_t name_len;
	nvlist_t *nvl;
	u_int idx;

	/* get pointer to <name> */
	opt_ptr = opt;
	/* If [name=] is specified, skip it */
	if (strncmp(opt_ptr, "name=", sizeof("name=") - 1) == 0) {
		opt_ptr += sizeof("name=") - 1;
	}

	/* get the end of <name> */
	opt_end = strchr(opt_ptr, ',');
	if (opt_end == NULL) {
		qemu_fwcfg_usage(opt);
		return (EINVAL);
	}

	/* check if <name> is too long */
	if (opt_end - opt_ptr >= QEMU_FWCFG_MAX_NAME) {
		warnx("fw_cfg name too long: \"%s\"", opt);
		return (EINVAL);
	}

	name = opt_ptr;
	name_len = opt_end - opt_ptr;

	/* set opt_ptr to <value> */
	opt_ptr = opt_end + 1;

	if (strncmp(opt_ptr, "string=", sizeof("string=") - 1) != 0 &&
	    strncmp(opt_ptr, "file=", sizeof("file=") - 1) != 0) {
		qemu_fwcfg_usage(opt);
		return (EINVAL);
	}

	/* find the next free fwcfg.file.<N> node */
	for (idx = 0; ; idx++) {
		snprintf(node_name, sizeof(node_name), "fwcfg.file.%u", idx);
		if (find_config_node(node_name) == NULL)
			break;
	}

	nvl = create_config_node(node_name);
	qemu_fwcfg_set_literal(nvl, "name", name, name_len);
	if (strncmp(opt_ptr, "string=", sizeof("string=") - 1) == 0) {
		opt_ptr += sizeof("string=") - 1;
		set_config_value_node(nvl, "type", "string");
	} else {
		opt_ptr += sizeof("file=") - 1;
		set_config_value_node(nvl, "type", "file");
	}
	qemu_fwcfg_set_literal(nvl, "value", opt_ptr, strlen(opt_ptr));

	return (0);
}
