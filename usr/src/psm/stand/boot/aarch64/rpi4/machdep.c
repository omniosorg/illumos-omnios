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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2020 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/boot.h>
#include <sys/bootinfo.h>
#include <sys/sysmacros.h>
#include <sys/machparam.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/controlregs.h>
#include <sys/saio.h>
#include <sys/bootsyms.h>
#include <sys/fcntl.h>
#include <sys/platform.h>
#include <sys/platnames.h>
#include <alloca.h>
#include <netinet/inetutil.h>
#include <sys/bootvfs.h>
#include <sys/psci.h>
#include <sys/arch_timer.h>
#include "arch_timer_private.h"
#include "ramdisk.h"
#include "boot_plat.h"
#include "genet.h"
#include "mmc.h"
#include <libfdt.h>
#include <sys/salib.h>

#include <sys/bcm2835_mbox.h>
#include <sys/bcm2835_mboxreg.h>
#include <sys/bcm2835_vcprop.h>
#include <sys/bcm2835_vcio.h>

#ifndef rounddown
#define	rounddown(x, y)	(((x)/(y))*(y))
#endif

extern char _BootScratch[];
extern char _RamdiskStart[];
extern char _RamdiskEnd[];
extern char filename[];
extern struct xboot_info xboot_info;
static char zfs_bootfs[256];	/* ZFS_MAXNAMELEN */
static char zfs_boot_pool_guid[256 * 2];
static char zfs_boot_vdev_guid[256 * 2];
char v2args_buf[V2ARGS_BUF_SZ];
char *v2args = v2args_buf;
extern char *bootp_response;

extern void set_board_info(const void *fdtp);
extern const char *get_impl_arch(void);
extern	int (*readfile(int fd, int print))();
extern	void kmem_init(void);
extern	void *kmem_alloc(size_t, int);
extern	void kmem_free(void *, size_t);
extern	void get_boot_args(char *buf);
extern	void setup_bootops(void);
extern	struct	bootops bootops;
extern	void exitto(int (*entrypoint)());
extern	int openfile(char *filename);
extern int determine_fstype_and_mountroot(char *);
extern	ssize_t xread(int, char *, size_t);
extern	void _reset(void);
extern	void init_physmem_common(void);
extern void setenv(const char *name, const char *value);
extern char envblock[];
extern size_t envblock_len;
extern uint32_t psci_cpu_suspend_id;
extern uint32_t psci_cpu_off_id;
extern uint32_t psci_cpu_on_id;
extern uint32_t psci_migrate_id;
extern boolean_t pcsi_method_is_hvc;

static struct boot_modules boot_modules[MAX_BOOT_MODULES] = {
	{ 0, 0, 0, BMT_ROOTFS },
};

static char cmdline[OBP_MAXPATHLEN] = {0};
static char rootfs_name[] = "rootfs";
static char environment_name[] = "environment";

void
setup_aux(void)
{
}

/*
 * Remove -D and the path from the boot args, look for the next "-" char
 */
void
fix_boot_args(char *str)
{
	char *s2;
	char *s3;
	int i;

	s2 = strstr(str, "-D");
	if (s2 != NULL) {
		s3 = s2 + 2;
		for (i = 0; s3[i] != 0 && s3[i] != '-'; i++)
			;
		s3 = s3 + i;
		memmove(s2, s3, strlen(s3) + 1);

	}
}

void
init_physmem(void)
{
	init_physmem_common();
}

void
init_iolist(void)
{
	memlist_add_span(PERIPHERAL0_PHYS, PERIPHERAL0_SIZE, &piolistp);
	memlist_add_span(PERIPHERAL1_PHYS, PERIPHERAL1_SIZE, &piolistp);
}

#define	MEMATTRS	(PTE_UXN | PTE_PXN | PTE_AF | PTE_SH_INNER |	\
			PTE_AP_KRWUNA | PTE_ATTR_NORMEM)
#define	PIOATTRS	(PTE_UXN | PTE_PXN | PTE_AF | PTE_SH_INNER |	\
			PTE_AP_KRWUNA | PTE_ATTR_DEVICE)

void
exitto(int (*entrypoint)())
{
	extern uint32_t psci_version(void);

	for (struct memlist *ml = plinearlistp; ml != NULL; ml = ml->ml_next) {
		uintptr_t pa = ml->ml_address;
		uintptr_t sz = ml->ml_size;
		map_phys((MEMATTRS), (caddr_t)(SEGKPM_BASE + pa), pa, sz);
	}
	for (struct memlist *ml = piolistp; ml != NULL; ml = ml->ml_next) {
		uintptr_t pa = ml->ml_address;
		uintptr_t sz = ml->ml_size;
		map_phys((PIOATTRS), (caddr_t)(SEGKPM_BASE + pa), pa, sz);
	}

	char *str;

	xboot_info.bi_arch_timer_freq = arch_timer_freq();
	xboot_info.bi_phys_avail = (uint64_t)pfreelistp;
	xboot_info.bi_phys_installed = (uint64_t)pinstalledp;
	xboot_info.bi_boot_scratch = (uint64_t)pscratchlistp;

	if (bootp_response)
		setenv("bootp-response", bootp_response);

	strncpy(cmdline, filename, sizeof (cmdline) - 1);
	str = prom_bootargs();
	fix_boot_args(str);
	if (strlen(str)) {
		strncat(cmdline, " ", sizeof (cmdline) - strlen(cmdline) - 1);
		strncat(cmdline, str, sizeof (cmdline) - strlen(cmdline) - 1);
	}
	xboot_info.bi_cmdline = (uint64_t)cmdline;

	setenv("ttya-mode", "115200,8,n,1,-");
	setenv("ttyb-mode", "115200,8,n,1,-");

	xboot_info.bi_fdt = SEGKPM_BASE + (uint64_t)get_fdtp();

	xboot_info.bi_psci_version = psci_version();
	if (xboot_info.bi_psci_version & 0x80000000)
		prom_panic("Failed to get PSCI version\n");
	xboot_info.bi_psci_conduit_hvc = pcsi_method_is_hvc;
	xboot_info.bi_psci_cpu_suspend_id = psci_cpu_suspend_id;
	xboot_info.bi_psci_cpu_off_id = psci_cpu_off_id;
	xboot_info.bi_psci_cpu_on_id = psci_cpu_on_id;
	xboot_info.bi_psci_migrate_id = psci_migrate_id;

	/*
	 * No calling setenv once our modules are set up.
	 */
	boot_modules[0].bm_type = BMT_ROOTFS;
	boot_modules[0].bm_name = (uint64_t)rootfs_name;
	boot_modules[0].bm_size =
	    ((uint64_t)_RamdiskEnd - (uint64_t)_RamdiskStart);
	boot_modules[0].bm_addr = (uint64_t)_RamdiskStart;

	boot_modules[1].bm_type = BMT_ENV;
	boot_modules[1].bm_name = (uint64_t)environment_name;
	boot_modules[1].bm_size = (uint64_t)envblock_len;
	boot_modules[1].bm_addr = (uint64_t)envblock;

	xboot_info.bi_module_cnt = 2;
	xboot_info.bi_modules = (uint64_t)&boot_modules[0];

	entrypoint(&xboot_info);
}

extern void get_boot_zpool(char *);
extern void get_boot_zpool_guid(char *);
extern void get_boot_vdev_guid(char *);

static void
set_zfs_bootfs(void)
{
	get_boot_zpool(zfs_bootfs);
	setenv("zfs-bootfs", zfs_bootfs);
	prom_printf("zfs-bootfs=%s\n", zfs_bootfs);

	get_boot_zpool_guid(zfs_boot_pool_guid);
	setenv("zfs-bootpool", zfs_boot_pool_guid);
	prom_printf("zfs-bootpool=%s\n", zfs_boot_pool_guid);

	get_boot_vdev_guid(zfs_boot_vdev_guid);
	setenv("zfs-bootvdev", zfs_boot_vdev_guid);
	prom_printf("zfs-bootvdev=%s\n", zfs_boot_vdev_guid);
}

static void
set_rootfs(char *bpath, char *fstype)
{
	char *str;
	if (strcmp(fstype, "nfs") == 0) {
		setenv("fstype", "nfsdyn");
	} else {
		setenv("fstype", fstype);
		/*
		 * We could set bootpath to the correct value here, but then
		 * when we go to mount root we trust the config in the label
		 * on that device, which will reflect the device where the
		 * disk was built.  Because that config is correct we'll then
		 * not do any more to search for the pool, and fail to mount
		 * it always.
		 *
		 * Instead, we do nothing, and let the system search for the
		 * pool based on using having set the GUIDs of both pool and
		 * vdev.  This is how things work on x86, where there is no
		 * notion of device paths.
		 */
	}
}

void
load_ramdisk(void *virt, const char *name)
{
	static char	tmpname[MAXPATHLEN];

	if (determine_fstype_and_mountroot(prom_bootpath()) == VFS_SUCCESS) {
		set_rootfs(prom_bootpath(), get_default_fs()->fsw_name);
		if (strcmp(get_default_fs()->fsw_name, "zfs") == 0)
			set_zfs_bootfs();

		strcpy(tmpname, name);
		int fd = openfile(tmpname);
		if (fd >= 0) {
			struct stat st;
			if (fstat(fd, &st) == 0) {
				xread(fd, (char *)virt, st.st_size);
			}
		} else {
			prom_printf("open failed %s\n", tmpname);
			prom_reset();
		}
		closeall(1);
		unmountroot();
	} else {
		prom_printf("mountroot failed\n");
		prom_reset();
	}
}

static char *
get_node_name(pnode_t nodeid)
{
	static char b[256];
	char *name = &b[0];
	strcpy(name, "");
	int namelen = prom_getproplen(nodeid, "name");
	if (namelen > 1) {
		strcpy(name, "/");
		name += strlen(name);
		prom_getprop(nodeid, "name", name);
		int reglen = prom_getproplen(nodeid, "reg");
		if (reglen > 0) {
			name += strlen(name);
			strcpy(name, "@");
			name += strlen(name);
			uint64_t base;
			prom_get_reg(nodeid, 0, &base);
			sprintf(name, "%lx", base);
		}
	}
	return (b);
}

static void
get_bootpath_cb(pnode_t node, void *arg)
{
	if (!prom_is_compatible(node, "brcm,bcm2711-genet-v5"))
		return;

	char *path = (char *)arg;
	strcpy(path, "");
	for (;;) {
		char *name = get_node_name(node);
		size_t namelen = strlen(name);
		memmove(path + namelen, path, strlen(path) + 1);
		memcpy(path, name, namelen);
		node = prom_parentnode(node);
		if (node == prom_rootnode())
			break;
	}
}

char *
get_default_bootpath(void)
{
	static char def_bootpath[80];

	prom_walk(get_bootpath_cb, def_bootpath);
	return (def_bootpath);
}

void
_reset(void)
{
	prom_printf("%s:%d\n", __func__, __LINE__);
	psci_system_reset();
	for (;;) {}
}

void
init_machdev(void)
{
	set_board_info(get_fdtp());

	const char *str = get_impl_arch();
	int namelen = prom_getproplen(prom_rootnode(), "compatible");
	namelen += strlen(str) + 1;
	char *compatible = __builtin_alloca(namelen);
	strcpy(compatible, str);
	prom_getprop(
	    prom_rootnode(), "compatible", compatible + strlen(str) + 1);
	prom_setprop(prom_rootnode(), "compatible", compatible, namelen);

	init_arch_timer(TMR_PHYS);
	init_genet();
	init_mmc();
}
