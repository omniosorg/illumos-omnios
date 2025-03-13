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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2019 Toomas Soome <tsoome@me.com>
 * Copyright 2025 Michael van der Westhuizen
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <locale.h>
#include <strings.h>
#include <libfdisk.h>
#include <err.h>
#include <time.h>
#include <spawn.h>

#include <sys/dktp/fdisk.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/multiboot.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/efi_partition.h>
#include <sys/queue.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/wait.h>
#include <libfstyp.h>
#include <libgen.h>
#include <uuid/uuid.h>

#include "installboot.h"
#include "bblk_einfo.h"
#include "boot_utils.h"
#include "mboot_extra.h"
#include "getresponse.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

/*
 * Extensible Firmware Interface System Partition (ESP) Installation
 *
 * Installs the illumos loader to the ESP on a disk. The loader will be
 * installed to /EFI/Boot/bootaa64.efi and will be installed from
 * /boot/loader64.efi (unless overridden).
 */

static bool	force_update = false;
static bool	do_getinfo = false;
static bool	do_version = false;
static bool	do_mirror_bblk = false;
static bool	strip = false;
static bool	verbose_dump = false;
static size_t	sector_size = SECTOR_SIZE;

/* Versioning string, if present. */
static char		*update_str;

/* Default location of boot programs. */
static char		*boot_dir = "/boot";

/* Our boot programs */
#define	BOOTAA64	"bootaa64.efi"
#define	LOADER64	"loader64.efi"

static char *efi64;

/* Function prototypes. */
static void check_options(char *);
static int open_device(const char *);
static char *make_blkdev(const char *);

static int read_bootblock_from_file(const char *, ib_bootblock_t *);
static void add_bootblock_einfo(ib_bootblock_t *, char *);
static void prepare_bootblock(ib_data_t *, struct partlist *, char *);
static int handle_install(char *, int, char **);
static int handle_getinfo(char *, int, char **);
static int handle_mirror(char *, int, char **);
static void usage(char *, int) __NORETURN;

static char *
stagefs_mount(char *blkdev, struct partlist *plist)
{
	char *path;
	char optbuf[MAX_MNTOPT_STR] = { '\0', };
	char *template = strdup("/tmp/ibootXXXXXX");
	int ret;

	if (template == NULL)
		return (NULL);

	if ((path = mkdtemp(template)) == NULL) {
		free(template);
		return (NULL);
	}

	(void) snprintf(optbuf, MAX_MNTOPT_STR, "timezone=%d",
	    timezone);
	ret = mount(blkdev, path, MS_OPTIONSTR,
	    MNTTYPE_PCFS, NULL, 0, optbuf, MAX_MNTOPT_STR);
	if (ret != 0) {
		(void) rmdir(path);
		free(path);
		path = NULL;
	}
	plist->pl_device->stage.mntpnt = path;
	return (path);
}

static bool
mkfs_pcfs(const char *dev)
{
	pid_t pid, w;
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t file_actions;
	int status;
	char *cmd[7];

	if (posix_spawnattr_init(&attr))
		return (false);
	if (posix_spawn_file_actions_init(&file_actions)) {
		(void) posix_spawnattr_destroy(&attr);
		return (false);
	}

	if (posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_NOSIGCHLD_NP | POSIX_SPAWN_WAITPID_NP)) {
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&file_actions);
		return (false);
	}
	if (posix_spawn_file_actions_addopen(&file_actions, 0, "/dev/null",
	    O_RDONLY, 0)) {
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&file_actions);
		return (false);
	}

	cmd[0] = "/usr/sbin/mkfs";
	cmd[1] = "-F";
	cmd[2] = "pcfs";
	cmd[3] = "-o";
	cmd[4] = "fat=32";
	cmd[5] = (char *)dev;
	cmd[6] = NULL;

	if (posix_spawn(&pid, cmd[0], &file_actions, &attr, cmd, NULL))
		return (false);
	(void) posix_spawnattr_destroy(&attr);
	(void) posix_spawn_file_actions_destroy(&file_actions);

	do {
		w = waitpid(pid, &status, 0);
	} while (w == -1 && errno == EINTR);
	if (w == -1)
		status = -1;

	return (status != -1);
}

static void
install_esp_cb(void *data, struct partlist *plist)
{
	fstyp_handle_t fhdl;
	const char *fident;
	bool pcfs;
	char *blkdev, *path, *file;
	FILE *fp;
	struct mnttab mp, mpref = { 0 };
	ib_bootblock_t *bblock = plist->pl_src_data;
	int fd, ret;

	if ((fd = open_device(plist->pl_devname)) == -1)
		return;

	if (fstyp_init(fd, 0, NULL, &fhdl) != 0) {
		(void) close(fd);
		return;
	}

	pcfs = false;
	if (fstyp_ident(fhdl, NULL, &fident) == 0) {
		if (strcmp(fident, MNTTYPE_PCFS) == 0)
			pcfs = true;
	}
	fstyp_fini(fhdl);
	(void) close(fd);

	if (!pcfs) {
		(void) printf(gettext("Creating pcfs on ESP %s\n"),
		    plist->pl_devname);

		if (!mkfs_pcfs(plist->pl_devname)) {
			(void) fprintf(stderr, gettext("mkfs -F pcfs failed "
			    "on %s\n"), plist->pl_devname);
			return;
		}
	}
	blkdev = make_blkdev(plist->pl_devname);
	if (blkdev == NULL)
		return;

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		perror("fopen");
		free(blkdev);
		return;
	}

	mpref.mnt_special = blkdev;
	ret = getmntany(fp, &mp, &mpref);
	(void) fclose(fp);
	if (ret == 0)
		path = mp.mnt_mountp;
	else
		path = stagefs_mount(blkdev, plist);

	free(blkdev);
	if (path == NULL)
		return;

	if (asprintf(&file, "%s%s", path, "/EFI") < 0) {
		perror(gettext("Memory allocation failure"));
		return;
	}

	ret = mkdir(file, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret == 0 || errno == EEXIST) {
		free(file);
		if (asprintf(&file, "%s%s", path, "/EFI/Boot") < 0) {
			perror(gettext("Memory allocation failure"));
			return;
		}
		ret = mkdir(file,
		    S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		if (errno == EEXIST)
			ret = 0;
	}
	free(file);
	if (ret < 0) {
		perror("mkdir");
		return;
	}

	if (asprintf(&file, "%s%s", path, plist->pl_device->stage.path) < 0) {
		perror(gettext("Memory allocation failure"));
		return;
	}

	/* Write stage file. Should create temp file and rename. */
	(void) chmod(file, S_IRUSR | S_IWUSR);
	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd != -1) {
		ret = write_out(fd, bblock->buf, bblock->buf_size, 0);
		if (ret == BC_SUCCESS) {
			(void) fprintf(stdout,
			    gettext("bootblock written to %s\n\n"), file);
		} else {
			(void) fprintf(stdout,
			    gettext("error while writing %s\n"), file);
		}
		(void) fchmod(fd, S_IRUSR | S_IRGRP | S_IROTH);
		(void) close(fd);
	}
	free(file);
}

/*
 * Return true if we can update, false if not.
 */
static bool
compare_einfo_cb(struct partlist *plist)
{
	ib_bootblock_t *bblock, *bblock_file;
	bblk_einfo_t *einfo, *einfo_file;
	bblk_hs_t bblock_hs;
	bool rv;

	bblock_file = plist->pl_src_data;
	if (bblock_file == NULL)
		return (false);	/* source is missing, cannot update */

	bblock = plist->pl_stage;
	if (bblock == NULL ||
	    bblock->extra == NULL ||
	    bblock->extra_size == 0) {
		return (true);
	}

	einfo = find_einfo(bblock->extra, bblock->extra_size);
	if (einfo == NULL) {
		BOOT_DEBUG("No extended information available on disk\n");
		return (true);
	}

	einfo_file = find_einfo(bblock_file->extra, bblock_file->extra_size);
	if (einfo_file == NULL) {
		/*
		 * loader bootblock is versioned. missing version means
		 * probably incompatible block. installboot can not install
		 * grub, for example.
		 */
		(void) fprintf(stderr,
		    gettext("ERROR: non versioned bootblock in file\n"));
		return (false);
	} else {
		if (update_str == NULL) {
			update_str = einfo_get_string(einfo_file);
			do_version = true;
		}
	}

	if (!do_version || update_str == NULL) {
		(void) fprintf(stderr,
		    gettext("WARNING: target device %s has a "
		    "versioned bootblock that is going to be overwritten by a "
		    "non versioned one\n"), plist->pl_devname);
		return (true);
	}

	if (force_update) {
		BOOT_DEBUG("Forcing update of %s bootblock\n",
		    plist->pl_devname);
		return (true);
	}

	BOOT_DEBUG("Ready to check installed version vs %s\n", update_str);

	bblock_hs.src_buf = (unsigned char *)bblock_file->file;
	bblock_hs.src_size = bblock_file->file_size;

	rv = einfo_should_update(einfo, &bblock_hs, update_str);
	if (rv == false) {
		(void) fprintf(stderr, gettext("Bootblock version installed "
		    "on %s is more recent or identical to\n%s\n"
		    "Use -F to override or install without the -u option.\n\n"),
		    plist->pl_devname, plist->pl_src_name);
	} else {
		(void) printf("%s is newer than one in %s\n",
		    plist->pl_src_name, plist->pl_devname);
	}
	return (rv);
}

static bool
read_einfo_file_cb(struct partlist *plist)
{
	int rc;
	void *stage;

	stage = calloc(1, sizeof (ib_bootblock_t));
	if (stage == NULL)
		return (false);

	rc =  read_bootblock_from_file(plist->pl_devname, stage);
	if (rc != BC_SUCCESS) {
		free(stage);
		stage = NULL;
	}
	plist->pl_stage = stage;
	return (rc == BC_SUCCESS);
}

static bool
read_stage2_file_cb(struct partlist *plist)
{
	int rc;
	void *data;

	data = calloc(1, sizeof (ib_bootblock_t));
	if (data == NULL)
		return (false);

	rc = read_bootblock_from_file(plist->pl_src_name, data);
	if (rc != BC_SUCCESS) {
		free(data);
		data = NULL;
	}
	plist->pl_src_data = data;
	return (rc == BC_SUCCESS);
}

/*
 * convert /dev/rdsk/... to /dev/dsk/...
 */
static char *
make_blkdev(const char *path)
{
	char *tmp;
	char *ptr = strdup(path);

	if (ptr == NULL)
		return (ptr);

	tmp = strstr(ptr, "rdsk");
	if (tmp == NULL) {
		free(ptr);
		return (NULL); /* Something is very wrong */
	}
	/* This is safe because we do shorten the string */
	(void) memmove(tmp, tmp + 1, strlen(tmp));
	return (ptr);
}

/*
 * Try to mount ESP and read boot program.
 */
static bool
read_einfo_esp_cb(struct partlist *plist)
{
	fstyp_handle_t fhdl;
	const char *fident;
	char *blkdev, *path, *file;
	bool rv = false;
	FILE *fp;
	struct mnttab mp, mpref = { 0 };
	int fd, ret;

	if ((fd = open_device(plist->pl_devname)) == -1)
		return (rv);

	if (fstyp_init(fd, 0, NULL, &fhdl) != 0) {
		(void) close(fd);
		return (rv);
	}

	if (fstyp_ident(fhdl, NULL, &fident) != 0) {
		fstyp_fini(fhdl);
		(void) close(fd);
		(void) fprintf(stderr, gettext("Failed to detect file "
		    "system type\n"));
		return (rv);
	}

	/* We only do expect pcfs. */
	if (strcmp(fident, MNTTYPE_PCFS) != 0) {
		(void) fprintf(stderr,
		    gettext("File system %s is not supported.\n"), fident);
		fstyp_fini(fhdl);
		(void) close(fd);
		return (rv);
	}
	fstyp_fini(fhdl);
	(void) close(fd);

	blkdev = make_blkdev(plist->pl_devname);
	if (blkdev == NULL)
		return (rv);

	/* mount ESP if needed, read boot program(s) and unmount. */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		perror("fopen");
		free(blkdev);
		return (rv);
	}

	mpref.mnt_special = blkdev;
	ret = getmntany(fp, &mp, &mpref);
	(void) fclose(fp);
	if (ret == 0)
		path = mp.mnt_mountp;
	else
		path = stagefs_mount(blkdev, plist);

	free(blkdev);
	if (path == NULL)
		return (rv);

	if (asprintf(&file, "%s%s", path, plist->pl_device->stage.path) < 0) {
		return (rv);
	}

	plist->pl_stage = calloc(1, sizeof (ib_bootblock_t));
	if (plist->pl_stage == NULL) {
		free(file);
		return (rv);
	}
	if (read_bootblock_from_file(file, plist->pl_stage) != BC_SUCCESS) {
		free(plist->pl_stage);
		plist->pl_stage = NULL;
	} else {
		rv = true;
	}

	free(file);
	return (rv);
}

static void
print_einfo_cb(struct partlist *plist)
{
	uint8_t flags = 0;
	ib_bootblock_t *bblock;
	bblk_einfo_t *einfo = NULL;
	const char *filepath;

	/* No stage, get out. */
	bblock = plist->pl_stage;
	if (bblock == NULL)
		return;

	if (plist->pl_device->stage.path == NULL)
		filepath = "";
	else
		filepath = plist->pl_device->stage.path;

	printf("Boot block from %s:%s\n", plist->pl_devname, filepath);

	if (bblock->extra != NULL)
		einfo = find_einfo(bblock->extra, bblock->extra_size);

	if (einfo == NULL) {
		(void) fprintf(stderr,
		    gettext("No extended information found.\n\n"));
		return;
	}

	/* Print the extended information. */
	if (strip)
		flags |= EINFO_EASY_PARSE;
	if (verbose_dump)
		flags |= EINFO_PRINT_HEADER;

	print_einfo(flags, einfo, bblock->extra_size);
	printf("\n");
}

static size_t
get_media_info(int fd)
{
	struct dk_minfo disk_info;

	if ((ioctl(fd, DKIOCGMEDIAINFO, (caddr_t)&disk_info)) == -1)
		return (SECTOR_SIZE);

	return (disk_info.dki_lbsize);
}

static struct partlist *
partlist_alloc(void)
{
	struct partlist *pl;

	if ((pl = calloc(1, sizeof (*pl))) == NULL) {
		perror("calloc");
		return (NULL);
	}

	pl->pl_device = calloc(1, sizeof (*pl->pl_device));
	if (pl->pl_device == NULL) {
		perror("calloc");
		free(pl);
		return (NULL);
	}

	return (pl);
}

static void
partlist_free(struct partlist *pl)
{
	ib_bootblock_t *bblock;
	ib_device_t *device;

	switch (pl->pl_type) {
	case IB_BBLK_MBR:
	case IB_BBLK_STAGE1:
		free(pl->pl_stage);
		break;
	default:
		if (pl->pl_stage != NULL) {
			bblock = pl->pl_stage;
			free(bblock->buf);
			free(bblock);
		}
	}

	/* umount the stage fs. */
	if (pl->pl_device->stage.mntpnt != NULL) {
		if (umount(pl->pl_device->stage.mntpnt) == 0)
			(void) rmdir(pl->pl_device->stage.mntpnt);
		free(pl->pl_device->stage.mntpnt);
	}
	device = pl->pl_device;
	free(device->target.path);
	free(pl->pl_device);

	free(pl->pl_src_data);
	free(pl->pl_devname);
	free(pl);
}

static bool
probe_fstyp(ib_data_t *data)
{
	fstyp_handle_t fhdl;
	const char *fident;
	char *ptr;
	int fd;
	bool rv = false;

	/* Record partition id */
	ptr = strrchr(data->target.path, 'p');
	if (ptr == NULL)
		ptr = strrchr(data->target.path, 's');
	data->target.id = atoi(++ptr);
	if ((fd = open_device(data->target.path)) == -1)
		return (rv);

	if (fstyp_init(fd, 0, NULL, &fhdl) != 0) {
		(void) close(fd);
		return (rv);
	}

	if (fstyp_ident(fhdl, NULL, &fident) != 0) {
		fstyp_fini(fhdl);
		(void) fprintf(stderr, gettext("Failed to detect file "
		    "system type\n"));
		(void) close(fd);
		return (rv);
	}

	rv = true;
	if (strcmp(fident, MNTTYPE_PCFS) == 0) {
		data->target.fstype = IB_FS_PCFS;
	} else if (strcmp(fident, MNTTYPE_ZFS) == 0) {
		/*
		 * bootadm passes us a zfs device, but we'll find the
		 * associated ESP, so allow it.
		 */
		data->target.fstype = IB_FS_ZFS;
	} else {
		(void) fprintf(stderr, gettext("File system %s is not "
		    "supported by loader\n"), fident);
		rv = false;
	}
	fstyp_fini(fhdl);
	(void) close(fd);
	return (rv);
}

static bool
get_slice(ib_data_t *data, struct partlist *pl, struct dk_gpt *vtoc,
    uint16_t tag)
{
	uint_t i;
	ib_device_t *device = pl->pl_device;
	char *path, *ptr;

	if (tag != V_SYSTEM)
		return (false);

	for (i = 0; i < vtoc->efi_nparts; i++) {
		if (vtoc->efi_parts[i].p_tag == tag) {
			if ((path = strdup(data->target.path)) == NULL) {
				perror(gettext("Memory allocation failure"));
				return (false);
			}
			ptr = strrchr(path, 's');
			ptr++;
			*ptr = '\0';
			(void) asprintf(&ptr, "%s%d", path, i);
			free(path);
			if (ptr == NULL) {
				perror(gettext("Memory allocation failure"));
				return (false);
			}
			pl->pl_devname = ptr;
			device->stage.id = i;
			device->stage.devtype = IB_DEV_EFI;
			switch (vtoc->efi_parts[i].p_tag) {
			case V_SYSTEM:
				device->stage.fstype = IB_FS_PCFS;
				break;
			}
			device->stage.tag = vtoc->efi_parts[i].p_tag;
			device->stage.start = vtoc->efi_parts[i].p_start;
			device->stage.size = vtoc->efi_parts[i].p_size;
			break;
		}
	}
	return (true);
}

static bool
allocate_slice(ib_data_t *data, struct dk_gpt *vtoc, uint16_t tag,
    struct partlist **plp)
{
	struct partlist *pl;

	*plp = NULL;
	if ((pl = partlist_alloc()) == NULL)
		return (false);

	pl->pl_device = calloc(1, sizeof (*pl->pl_device));
	if (pl->pl_device == NULL) {
		perror("calloc");
		partlist_free(pl);
		return (false);
	}
	if (!get_slice(data, pl, vtoc, tag)) {
		partlist_free(pl);
		return (false);
	}

	/* tag was not found */
	if (pl->pl_devname == NULL)
		partlist_free(pl);
	else
		*plp = pl;

	return (true);
}

static bool
probe_gpt(ib_data_t *data)
{
	struct partlist *pl;
	struct dk_gpt *vtoc;
	int slice, fd;
	bool rv = false;

	if ((fd = open_device(data->target.path)) < 0)
		return (rv);

	slice = efi_alloc_and_read(fd, &vtoc);
	(void) close(fd);
	if (slice < 0)
		return (rv);

	data->device.devtype = IB_DEV_EFI;
	data->target.start = vtoc->efi_parts[slice].p_start;
	data->target.size = vtoc->efi_parts[slice].p_size;

	/* ESP can only have 64-bit boot code. */
	if (!allocate_slice(data, vtoc, V_SYSTEM, &pl))
		goto done;
	if (pl != NULL) {
		pl->pl_device->stage.path = "/EFI/Boot/" BOOTAA64;
		pl->pl_src_name = efi64;
		pl->pl_type = IB_BBLK_EFI;
		pl->pl_cb.compare = compare_einfo_cb;
		pl->pl_cb.install = install_esp_cb;
		pl->pl_cb.read = read_einfo_esp_cb;
		pl->pl_cb.read_bbl = read_stage2_file_cb;
		pl->pl_cb.print = print_einfo_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
	}

	rv = true;
done:
	efi_free(vtoc);
	return (rv);
}

static bool
probe_device(ib_data_t *data, const char *dev)
{
	struct partlist *pl;
	struct stat sb;
	const char *ptr;
	char *p0;
	int fd, len;

	if (dev == NULL)
		return (NULL);

	len = strlen(dev);

	if ((pl = partlist_alloc()) == NULL)
		return (false);

	if (stat(dev, &sb) == -1) {
		perror("stat");
		partlist_free(pl);
		return (false);
	}

	/* We have regular file, register it and we are done. */
	if (S_ISREG(sb.st_mode) != 0) {
		pl->pl_devname = (char *)dev;

		pl->pl_type = IB_BBLK_FILE;
		pl->pl_cb.read = read_einfo_file_cb;
		pl->pl_cb.print = print_einfo_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
		return (true);
	}

	/*
	 * This is block device.
	 * We do not allow to specify whole disk device (cXtYdZp0 or cXtYdZ).
	 */
	if ((ptr = strrchr(dev, '/')) == NULL)
		ptr = dev;
	if ((strrchr(ptr, 'p') == NULL && strrchr(ptr, 's') == NULL) ||
	    (dev[len - 2] == 'p' && dev[len - 1] == '0')) {
		(void) fprintf(stderr,
		    gettext("whole disk device is not supported\n"));
		partlist_free(pl);
		return (false);
	}

	data->target.path = (char *)dev;
	if (!probe_fstyp(data)) {
		partlist_free(pl);
		return (false);
	}

	/* We start from identifying the whole disk. */
	if ((p0 = strdup(dev)) == NULL) {
		perror("calloc");
		partlist_free(pl);
		return (false);
	}

	pl->pl_devname = p0;
	/* Change device name to p0 */
	if ((ptr = strrchr(p0, 'p')) == NULL)
		ptr = strrchr(p0, 's');
	p0 = (char *)ptr;
	p0[0] = 'p';
	p0[1] = '0';
	p0[2] = '\0';

	if ((fd = open_device(pl->pl_devname)) == -1) {
		partlist_free(pl);
		return (false);
	}

	sector_size = get_media_info(fd);
	(void) close(fd);

	if (probe_gpt(data))
		return (true);

	return (false);
}

static int
read_bootblock_from_file(const char *file, ib_bootblock_t *bblock)
{
	struct stat	sb;
	uint32_t	buf_size;
	uint32_t	mboot_off;
	int		fd = -1;
	int		retval = BC_ERROR;

	assert(bblock != NULL);
	assert(file != NULL);

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		BOOT_DEBUG("Error opening %s\n", file);
		goto out;
	}

	if (fstat(fd, &sb) == -1) {
		BOOT_DEBUG("Error getting information (stat) about %s", file);
		perror("stat");
		goto outfd;
	}

	/* loader bootblock has version built in */
	buf_size = sb.st_size;
	if (buf_size == 0)
		goto outfd;

	/* Round up to sector size for raw disk write */
	bblock->buf_size = P2ROUNDUP(buf_size, sector_size);
	BOOT_DEBUG("bootblock in-memory buffer size is %d\n",
	    bblock->buf_size);

	bblock->buf = malloc(bblock->buf_size);
	if (bblock->buf == NULL) {
		perror(gettext("Memory allocation failure"));
		goto outbuf;
	}
	bblock->file = bblock->buf;

	if (read(fd, bblock->file, buf_size) != buf_size) {
		BOOT_DEBUG("Read from %s failed\n", file);
		perror("read");
		goto outfd;
	}

	buf_size = MIN(buf_size, MBOOT_SCAN_SIZE);
	if (find_multiboot(bblock->file, buf_size, &mboot_off)
	    != BC_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("Unable to find multiboot header\n"));
		goto outfd;
	}

	bblock->mboot = (multiboot_header_t *)(bblock->file + mboot_off);
	bblock->mboot_off = mboot_off;

	bblock->file_size =
	    bblock->mboot->load_end_addr - bblock->mboot->load_addr;
	BOOT_DEBUG("bootblock file size is %d\n", bblock->file_size);

	bblock->extra = bblock->buf + P2ROUNDUP(bblock->file_size, 8);
	bblock->extra_size = bblock->buf_size - P2ROUNDUP(bblock->file_size, 8);

	BOOT_DEBUG("mboot at %p offset %d, extra at %p size %d, buf=%p "
	    "(size=%d)\n", bblock->mboot, bblock->mboot_off, bblock->extra,
	    bblock->extra_size, bblock->buf, bblock->buf_size);

	(void) close(fd);
	return (BC_SUCCESS);

outbuf:
	(void) free(bblock->buf);
	bblock->buf = NULL;
outfd:
	(void) close(fd);
out:
	if (retval == BC_ERROR) {
		(void) fprintf(stderr,
		    gettext("Error reading bootblock from %s\n"),
		    file);
	}

	if (retval == BC_NOEXTRA) {
		BOOT_DEBUG("No multiboot header found on %s, unable to "
		    "locate extra information area (old/non versioned "
		    "bootblock?) \n", file);
		(void) fprintf(stderr, gettext("No extended information"
		    " found\n"));
	}
	return (retval);
}

static void
add_bootblock_einfo(ib_bootblock_t *bblock, char *updt_str)
{
	bblk_hs_t	hs;
	uint32_t	avail_space;

	assert(bblock != NULL);

	if (updt_str == NULL) {
		BOOT_DEBUG("WARNING: no update string passed to "
		    "add_bootblock_einfo()\n");
		return;
	}

	/* Fill bootblock hashing source information. */
	hs.src_buf = (unsigned char *)bblock->file;
	hs.src_size = bblock->file_size;
	/* How much space for the extended information structure? */
	avail_space = bblock->buf_size - P2ROUNDUP(bblock->file_size, 8);
	/* Place the extended information structure. */
	add_einfo(bblock->extra, updt_str, &hs, avail_space);
}

static void
prepare_bootblock(ib_data_t *data, struct partlist *pl, char *updt_str)
{
	ib_bootblock_t		*bblock;
	uint64_t		*ptr;

	assert(pl != NULL);

	bblock = pl->pl_src_data;
	if (bblock == NULL)
		return;

	ptr = (uint64_t *)(&bblock->mboot->bss_end_addr);
	*ptr = data->target.start;

	/*
	 * the loader bootblock has built in version, if custom
	 * version was provided, update it.
	 */
	if (do_version)
		add_bootblock_einfo(bblock, updt_str);
}

static int
open_device(const char *path)
{
	struct stat	statbuf = {0};
	int		fd = -1;

	if (nowrite)
		fd = open(path, O_RDONLY);
	else
		fd = open(path, O_RDWR);

	if (fd == -1) {
		BOOT_DEBUG("Unable to open %s\n", path);
		perror("open");
		return (-1);
	}

	if (fstat(fd, &statbuf) != 0) {
		BOOT_DEBUG("Unable to stat %s\n", path);
		perror("stat");
		(void) close(fd);
		return (-1);
	}

	if (S_ISCHR(statbuf.st_mode) == 0) {
		(void) fprintf(stderr, gettext("%s: Not a character device\n"),
		    path);
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * We need to record stage2 location and size into pmbr/vbr.
 * We need to record target partiton LBA to stage2.
 */
static void
prepare_bblocks(ib_data_t *data)
{
	struct partlist *pl;
	uuid_t uuid;

	/*
	 * Create disk uuid. We only need reasonable amount of uniqueness
	 * to allow biosdev to identify disk based on mbr differences.
	 */
	uuid_generate(uuid);

	/*
	 * Walk list and pick up BIOS boot blocks. EFI boot programs
	 * can be set in place.
	 */
	STAILQ_FOREACH(pl, data->plist, pl_next) {
		switch (pl->pl_type) {
		case IB_BBLK_EFI:
			prepare_bootblock(data, pl, update_str);
			break;
		default:
			break;
		}
	}
}

/*
 * Install a new bootblock on the given device. handle_install() expects argv
 * to contain 3 parameters (the target device path and the path to the
 * bootblock.
 *
 * Returns:	BC_SUCCESS - if the installation is successful
 *		BC_ERROR   - if the installation failed
 *		BC_NOUPDT  - if no installation was performed because the
 *		             version currently installed is more recent than the
 *			     supplied one.
 *
 */
static int
handle_install(char *progname, int argc, char **argv)
{
	struct partlist	*pl;
	ib_data_t	data = { 0 };
	char		*device_path = NULL;
	int		ret = BC_ERROR;

	switch (argc) {
	case 1:
		if ((device_path = strdup(argv[0])) == NULL) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if (asprintf(&efi64, "%s/%s", boot_dir, LOADER64) < 0) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		break;
	default:
		usage(progname, ret);
	}

	data.plist = malloc(sizeof (*data.plist));
	if (data.plist == NULL) {
		perror(gettext("Memory Allocation Failure"));
		goto done;
	}
	STAILQ_INIT(data.plist);

	BOOT_DEBUG("device path: %s\n", device_path);

	if (probe_device(&data, device_path)) {
		/* Read all data. */
		STAILQ_FOREACH(pl, data.plist, pl_next) {
			if (!pl->pl_cb.read(pl)) {
				printf("\n");
			}
			if (!pl->pl_cb.read_bbl(pl)) {
				/*
				 * We will ignore ESP updates in case of
				 * older system where we are missing
				 * loader64.efi and loader32.efi.
				 */
				if (pl->pl_type != IB_BBLK_EFI)
					goto cleanup;
			}
		}

		/* Prepare data. */
		prepare_bblocks(&data);

		/* Commit data to disk. */
		while ((pl = STAILQ_LAST(data.plist, partlist, pl_next)) !=
		    NULL) {
			if (pl->pl_cb.compare != NULL &&
			    pl->pl_cb.compare(pl)) {
				if (pl->pl_cb.install != NULL)
					pl->pl_cb.install(&data, pl);
			}
			STAILQ_REMOVE(data.plist, pl, partlist, pl_next);
			partlist_free(pl);
		}
	}
	ret = BC_SUCCESS;

cleanup:
	while ((pl = STAILQ_LAST(data.plist, partlist, pl_next)) != NULL) {
		STAILQ_REMOVE(data.plist, pl, partlist, pl_next);
		partlist_free(pl);
	}
	free(data.plist);
done:
	free(efi64);
	free(device_path);
	return (ret);
}

/*
 * Retrieves from a device the extended information (einfo) associated with
 * the file or installed loader.
 * Expects one parameter, the device path, in the form: /dev/rdsk/c?[t?]d?s0
 * or file name.
 * Returns:
 *        - BC_SUCCESS (and prints out einfo contents depending on 'flags')
 *	  - BC_ERROR (on error)
 *        - BC_NOEINFO (no extended information available)
 */
static int
handle_getinfo(char *progname, int argc, char **argv)
{
	struct partlist	*pl;
	ib_data_t	data = { 0 };
	char		*device_path;

	if (argc != 1) {
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname, BC_ERROR);
	}

	if ((device_path = strdup(argv[0])) == NULL) {
		perror(gettext("Memory Allocation Failure"));
		return (BC_ERROR);
	}

	data.plist = malloc(sizeof (*data.plist));
	if (data.plist == NULL) {
		perror("malloc");
		free(device_path);
		return (BC_ERROR);
	}
	STAILQ_INIT(data.plist);

	if (probe_device(&data, device_path)) {
		STAILQ_FOREACH(pl, data.plist, pl_next) {
			if (pl->pl_cb.read(pl))
				pl->pl_cb.print(pl);
			else
				printf("\n");
		}
	}

	while ((pl = STAILQ_LAST(data.plist, partlist, pl_next)) != NULL) {
		STAILQ_REMOVE(data.plist, pl, partlist, pl_next);
		partlist_free(pl);
	}
	free(data.plist);

	return (BC_SUCCESS);
}

/*
 * Attempt to mirror (propagate) the current bootblock over the attaching disk.
 *
 * Returns:
 *	- BC_SUCCESS (a successful propagation happened)
 *	- BC_ERROR (an error occurred)
 *	- BC_NOEXTRA (it is not possible to dump the current bootblock since
 *			there is no multiboot information)
 */
static int
handle_mirror(char *progname, int argc, char **argv)
{
	ib_data_t src = { 0 };
	ib_data_t dest = { 0 };
	struct partlist *pl_src, *pl_dest;
	char		*curr_device_path = NULL;
	char		*attach_device_path = NULL;
	int		retval = BC_ERROR;

	if (argc == 2) {
		curr_device_path = strdup(argv[0]);
		attach_device_path = strdup(argv[1]);
	}

	if (!curr_device_path || !attach_device_path) {
		free(curr_device_path);
		free(attach_device_path);
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname, BC_ERROR);
	}
	BOOT_DEBUG("Current device path is: %s, attaching device path is: "
	    " %s\n", curr_device_path, attach_device_path);

	src.plist = malloc(sizeof (*src.plist));
	if (src.plist == NULL) {
		perror("malloc");
		return (BC_ERROR);
	}
	STAILQ_INIT(src.plist);

	dest.plist = malloc(sizeof (*dest.plist));
	if (dest.plist == NULL) {
		perror("malloc");
		goto out;
	}
	STAILQ_INIT(dest.plist);

	if (!probe_device(&src, curr_device_path)) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information from %s (current device)\n"),
		    curr_device_path);
		goto out;
	}

	if (!probe_device(&dest, attach_device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information from %s (attaching device)\n"),
		    attach_device_path);
		goto cleanup_src;
	}

	pl_dest = STAILQ_FIRST(dest.plist);
	STAILQ_FOREACH(pl_src, src.plist, pl_next) {
		if (pl_dest == NULL) {
			(void) fprintf(stderr,
			    gettext("Destination disk layout is different "
			    "from source, can not mirror.\n"));
			goto cleanup;
		}
		if (!pl_src->pl_cb.read(pl_src)) {
			(void) fprintf(stderr, gettext("Failed to read "
			    "boot block from %s\n"), pl_src->pl_devname);
			goto cleanup;
		}
		if (!pl_dest->pl_cb.read(pl_dest)) {
			(void) fprintf(stderr, gettext("Failed to read "
			    "boot block from %s\n"), pl_dest->pl_devname);
		}

		/* Set source pl_stage to destination source data */
		pl_dest->pl_src_data = pl_src->pl_stage;
		pl_src->pl_stage = NULL;

		pl_dest = STAILQ_NEXT(pl_dest, pl_next);
	}

	/* Prepare data. */
	prepare_bblocks(&dest);

	/* Commit data to disk. */
	while ((pl_dest = STAILQ_LAST(dest.plist, partlist, pl_next)) != NULL) {
		pl_dest->pl_cb.install(&dest, pl_dest);
		STAILQ_REMOVE(dest.plist, pl_dest, partlist, pl_next);
		partlist_free(pl_dest);

		/* Free source list */
		pl_src = STAILQ_LAST(src.plist, partlist, pl_next);
		STAILQ_REMOVE(src.plist, pl_src, partlist, pl_next);
		partlist_free(pl_src);
	}
	retval = BC_SUCCESS;

cleanup:
	while ((pl_dest = STAILQ_LAST(dest.plist, partlist, pl_next)) != NULL) {
		STAILQ_REMOVE(dest.plist, pl_dest, partlist, pl_next);
		partlist_free(pl_dest);
	}
	free(dest.plist);
cleanup_src:
	while ((pl_src = STAILQ_LAST(src.plist, partlist, pl_next)) != NULL) {
		STAILQ_REMOVE(src.plist, pl_src, partlist, pl_next);
		partlist_free(pl_src);
	}
	free(src.plist);
out:
	free(curr_device_path);
	free(attach_device_path);
	return (retval);
}

#define	USAGE_STRING	\
"Usage:\t%s [-Fn] [-b boot_dir] [-u verstr] raw-device\n"	\
"\t%s -M [-n] raw-device attach-raw-device\n"			\
"\t%s [-e|-V] -i raw-device | file\n"

#define	CANON_USAGE_STR	gettext(USAGE_STRING)

static void
usage(char *progname, int rc)
{
	(void) fprintf(stdout, CANON_USAGE_STR, progname, progname, progname);
	fini_yes();
	exit(rc);
}

int
main(int argc, char **argv)
{
	int	opt;
	int	ret;
	char	*progname;
	struct stat sb;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	if (init_yes() < 0)
		errx(BC_ERROR, gettext(ERR_MSG_INIT_YES), strerror(errno));

	/* Needed for mount pcfs. */
	tzset();

	/* Determine our name */
	progname = basename(argv[0]);

	while ((opt = getopt(argc, argv, "b:deFhiMnu:V")) != EOF) {
		switch (opt) {
		case 'b':
			boot_dir = strdup(optarg);
			if (boot_dir == NULL) {
				err(BC_ERROR,
				    gettext("Memory allocation failure"));
			}
			if (lstat(boot_dir, &sb) != 0) {
				err(BC_ERROR, boot_dir);
			}
			if (!S_ISDIR(sb.st_mode)) {
				errx(BC_ERROR, gettext("%s: not a directory"),
				    boot_dir);
			}
			break;
		case 'd':
			boot_debug = true;
			break;
		case 'e':
			strip = true;
			break;
		case 'F':
			force_update = true;
			break;
		case 'h':
			usage(progname, BC_SUCCESS);
			break;
		case 'i':
			do_getinfo = true;
			break;
		case 'M':
			do_mirror_bblk = true;
			break;
		case 'n':
			nowrite = true;
			break;
		case 'u':
			do_version = true;

			update_str = strdup(optarg);
			if (update_str == NULL) {
				perror(gettext("Memory allocation failure"));
				exit(BC_ERROR);
			}
			break;
		case 'V':
			verbose_dump = true;
			break;
		default:
			/* fall through to process non-optional args */
			break;
		}
	}

	/* check arguments */
	check_options(progname);

	if (nowrite)
		(void) fprintf(stdout, gettext("Dry run requested. Nothing will"
		    " be written to disk.\n"));

	if (do_getinfo) {
		ret = handle_getinfo(progname, argc - optind, argv + optind);
	} else if (do_mirror_bblk) {
		ret = handle_mirror(progname, argc - optind, argv + optind);
	} else {
		ret = handle_install(progname, argc - optind, argv + optind);
	}
	fini_yes();
	return (ret);
}

#define	MEANINGLESS_OPT gettext("%s specified but meaningless, ignoring\n")
static void
check_options(char *progname)
{
	if (do_getinfo && do_mirror_bblk) {
		(void) fprintf(stderr, gettext("Only one of -M and -i can be "
		    "specified at the same time\n"));
		usage(progname, BC_ERROR);
	}

	if (do_mirror_bblk) {
		/*
		 * -u and -F may actually reflect a user intent that is not
		 * correct with this command (mirror can be interpreted
		 * "similar" to install. Emit a message and continue.
		 * -e and -V have no meaning, be quiet here and only report the
		 * incongruence if a debug output is requested.
		 */
		if (do_version) {
			(void) fprintf(stderr, MEANINGLESS_OPT, "-u");
			do_version = false;
		}
		if (force_update) {
			(void) fprintf(stderr, MEANINGLESS_OPT, "-F");
			force_update = false;
		}
		if (strip || verbose_dump) {
			BOOT_DEBUG(MEANINGLESS_OPT, "-e|-V");
			strip = false;
			verbose_dump = false;
		}
	}

	if ((strip || verbose_dump) && !do_getinfo)
		usage(progname, BC_ERROR);

	if (do_getinfo) {
		if (do_version || force_update) {
			BOOT_DEBUG(MEANINGLESS_OPT, "-u|-F");
			do_version = false;
			force_update = false;
		}
	}
}
