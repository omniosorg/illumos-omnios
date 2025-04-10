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
 * Boot shim configuration driven by FreeBSD-style modules.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/bootinfo.h>
#include <sys/framebuffer.h>
#include <sys/stdbool.h>
#include <sys/limits.h>
#include <asm/controlregs.h>
#include <sys/psci.h>
#include <sys/machparam.h>

#if !defined(DCACHE_LINE)
#define	DCACHE_LINE	64
#endif

#include <boot/boot_early_uart.h>

#include "dboot.h"
#include "dboot_printf.h"

#define	MODINFO_END		0x0000	/* End of list */
#define	MODINFO_NAME		0x0001	/* Name of module (string) */
#define	MODINFO_TYPE		0x0002	/* Type of module (string) */
#define	MODINFO_ADDR		0x0003	/* Loaded address */
#define	MODINFO_SIZE		0x0004	/* Size of module */
#define	MODINFO_EMPTY		0x0005	/* Has been deleted */
#define	MODINFO_ARGS		0x0006	/* Parameters string */
#define	MODINFO_METADATA	0x8000	/* Module-specfic */

#define	MODINFOMD_AOUTEXEC	0x0001	/* a.out exec header */
#define	MODINFOMD_ELFHDR	0x0002	/* ELF header */
#define	MODINFOMD_SSYM		0x0003	/* start of symbols */
#define	MODINFOMD_ESYM		0x0004	/* end of symbols */
#define	MODINFOMD_DYNAMIC	0x0005	/* _DYNAMIC pointer */
#define	MODINFOMD_MB2HDR	0x0006	/* MB2 header info */
#define	MODINFOMD_ENVP		0x0006	/* envp[] */
#define	MODINFOMD_HOWTO		0x0007	/* boothowto */
#define	MODINFOMD_KERNEND	0x0008	/* kernend */
#define	MODINFOMD_SHDR		0x0009	/* section header table */
#define	MODINFOMD_CTORS_ADDR	0x000a	/* address of .ctors */
#define	MODINFOMD_CTORS_SIZE	0x000b	/* size of .ctors */
#define	MODINFOMD_FW_HANDLE	0x000c	/* Firmware dependent handle */
#define	MODINFOMD_KEYBUF	0x000d	/* Crypto key intake buffer */
#define	MODINFOMD_FONT		0x000e	/* Console font */
#define	MODINFOMD_NOCOPY	0x8000	/* don't copy to the kernel */

#define	MODINFOMD_SMAP		0x1001	/* x86 SMAP */
#define	MODINFOMD_SMAP_XATTR	0x1002	/* x86 SMAP extended attrs */
#define	MODINFOMD_DTBP		0x1003	/* DTB pointer */
#define	MODINFOMD_EFI_MAP	0x1004	/* UEFI memory map */
#define	MODINFOMD_EFI_FB	0x1005	/* UEFI framebuffer */
#define	MODINFOMD_MODULEP	0x1006
#define	MODINFOMD_SCRATCH_ADDR	0x1007	/* address of scratch memory */
#define	MODINFOMD_SCRATCH_SIZE	0x1008	/* size of scratc memory */

#define	ENV_BOOTMOD_NAME	"environment"
#define	ROOTFS_BOOTMOD_NAME	"rootfs"
#define	FONT_BOOTMOD_NAME	"console-font"

static const char env_boot_module_name[] = ENV_BOOTMOD_NAME;
static const char rootfs_boot_module_name[] = ROOTFS_BOOTMOD_NAME;
static const char font_boot_module_name[] = FONT_BOOTMOD_NAME;

#define	PAYLOAD_CMDLINE_MAX	2048
static char payload_cmdline[PAYLOAD_CMDLINE_MAX];

#define	MOD_UINT64(x)	(*((uint64_t *)(&(x)[2])))

extern void * memset(void *sp1, int c, size_t n);

static boot_framebuffer_t framebuffer __aligned(16) = {
	0, /* framebuffer - efi_fb */
	/* origin.x, origin.y, pos.y, pos.y, visible */
	{ { 0, 0 }, { 0, 0 }, 0 }
};
static boot_framebuffer_t *fb = &framebuffer;

static struct boot_modules boot_modules[MAX_BOOT_MODULES] = {
	{ 0, 0, 0, BMT_ROOTFS },
};

static struct xboot_cpu_info cpu_info[NCPU];

extern void exception_vector(void);
extern void bcons_init(struct xboot_info *);
extern void bootflags(const char *args, size_t argsz,
    char *out, size_t outsz);

extern unsigned long strtoul(const char *, char **, int);

extern int errno;

struct module_data_t {
	uint64_t	maddr;
	uint64_t	msize;
	const char	*mtype;
	const char	*mname;
	const char	*margs;
	uint64_t	env_addr;
	uint64_t	map_addr;
#ifdef NOT_YET
	uint64_t	font_addr;
#endif
	uint64_t	fb_addr;
	uint64_t	systab_addr;
	uint64_t	fdt_addr;
	uint64_t	scratch_addr;
	uint64_t	scratch_size;
};

const char *
dboot_getenv(const char *name)
{
	const char *val;
	extern const char *find_boot_prop(const char *name);

	if (name == NULL)
		return (NULL);

	return (find_boot_prop(name));
}

static bool
find_boolean_boot_prop(const char *name)
{
	const char *val;
	extern const char *find_boot_prop(const char *name);

	if ((val = find_boot_prop(name)) == NULL)
		return (false);

	if (strcmp(val, "1") == 0 || strcmp(val, "true") == 0)
		return (true);

	return (false);
}

static uint64_t
find_u64_boot_prop(const char *name, uint64_t defval)
{
	const char *val;
	char *ep;
	unsigned long ul;
	extern const char *find_boot_prop(const char *name);

	if ((val = find_boot_prop(name)) == NULL)
		return (defval);

	errno = 0;
	ul = strtoul(val, &ep, 0);
	if (*val == '\0' || *ep != '\0')
		return (defval);
	if (errno == ERANGE && ul == ULONG_MAX)
		return (defval);

	return ((uint64_t)ul);
}

static int
prekern_process_module_info(caddr_t mi, struct module_data_t *md)
{
	caddr_t		curp;
	uint32_t	*hdrp;
	unsigned int	mlen;
	uint32_t	type;
	unsigned int	next;

	if (mi == NULL) {
		dboot_printf("dboot: null module info\n");
		return (-1);
	}

	curp = mi;
	type = 0;

	for (;;) {
		hdrp = (uint32_t *)curp;
		mlen = hdrp[1];

		/*
		 * End of module data? Let the caller deal with it.
		 */
		if (hdrp[0] == MODINFO_END && mlen == 0)
			break;

		/*
		 * We give up once we've looped back to the type what we were
		 * looking at first, which is a MODINFO_NAME.
		 */
		if (type == 0) {
			/*
			 * The first time around we ensure that we're looking
			 * at MODINFO_NAME, then track that we've seen
			 * the MODINFO_NAME type.
			 */
			if (hdrp[0] != MODINFO_NAME) {
				dboot_printf("dboot: starting module tag "
				    "is not a name\n");
				return (-1);
			}
			type = MODINFO_NAME;
		} else {
			/*
			 * On subsequent iterations we see if we've hit another
			 * MODINFO_NAME - if we have we bail so as to avoid
			 * looking at the next module.
			 */
			if (hdrp[0] == type)
				break;
		}

		switch (hdrp[0]) {
		case MODINFO_NAME:
			md->mname = (const char *)&hdrp[2];
			break;
		case MODINFO_TYPE:
			md->mtype = (const char *)&hdrp[2];
			break;
		case MODINFO_ARGS:
			md->margs = (const char *)&hdrp[2];
			break;
		case MODINFO_ADDR:
			md->maddr = MOD_UINT64(hdrp);
			break;
		case MODINFO_SIZE:
			md->msize = MOD_UINT64(hdrp);
			break;
		default:
			if (hdrp[0] & MODINFO_METADATA) {
				switch (hdrp[0] & ~MODINFO_METADATA) {
				/*
				 * MODINFOMD_AOUTEXEC
				 * MODINFOMD_ELFHDR
				 * MODINFOMD_SSYM
				 * MODINFOMD_ESYM
				 * MODINFOMD_DYNAMIC
				 * MODINFOMD_KERNEND
				 * MODINFOMD_SHDR
				 * MODINFOMD_CTORS_ADDR
				 * MODINFOMD_CTORS_SIZE
				 * MODINFOMD_KEYBUF
				 * MODINFOMD_NOCOPY
				 * MODINFOMD_HOWTO
				 * MODINFOMD_FONT
				 */
				case MODINFOMD_DTBP:
					md->fdt_addr = MOD_UINT64(hdrp);
					break;
				case MODINFOMD_FW_HANDLE:
					md->systab_addr = MOD_UINT64(hdrp);
					break;
				case MODINFOMD_EFI_FB:
					md->fb_addr = (uint64_t)&hdrp[2];
					break;
				case MODINFOMD_ENVP:
					md->env_addr = MOD_UINT64(hdrp);
					break;
				case MODINFOMD_EFI_MAP:
					md->map_addr = (uint64_t)&hdrp[2];
					break;
				case MODINFOMD_SCRATCH_ADDR:
					md->scratch_addr = MOD_UINT64(hdrp);
					break;
				case MODINFOMD_SCRATCH_SIZE:
					md->scratch_size = MOD_UINT64(hdrp);
					break;
				default:
					break;
				}
			}

			break;
		}

		next = sizeof (uint32_t) * 2 + mlen;
		next = roundup(next, sizeof (ulong_t));
		curp += next;
	}

	if (type == 0) {
		dboot_printf("dboot: no module processed\n");
		return (-1);
	}

	if (md->mtype == NULL || md->mname == NULL ||
	    md->maddr == 0 || md->msize == 0) {
		dboot_printf("dboot: malformed module\n");
		return (-1);
	}

	return (0);
}

static int64_t
prekern_calc_env_size(const char *env)
{
	const char	*menv;
	char		c;
	char		lastc;

	if (env == NULL)
		return (-1);

	menv = env;

	for (c = *menv, lastc = 0xff; ; c = *++menv) {
		if (c == '\0' && lastc == '\0')
			break;
		lastc = c;
	}

	return (int64_t)(((uint64_t)menv) - ((uint64_t)env));
}

int
dboot_configure(caddr_t modulep, struct xboot_info *xbi,
    caddr_t *pkernel, uint64_t *pkernel_size)
{
	caddr_t			curp;
	uint32_t		*hdrp;
	const char		*bootfile;
	const char		*cmdline;
	unsigned int		mlen;
	unsigned int		next;
	struct boot_modules	*bm;
	caddr_t			memmap;
	caddr_t			scratch_addr;
	uint64_t		scratch_size;

	extern uint64_t dboot_uefi_get_smbios3_address(void);

	if (modulep == NULL || xbi == NULL ||
	    pkernel == NULL || pkernel_size == NULL)
		panic("dboot: bad call to dboot_configure\n");

	fb = &framebuffer;
	memset(xbi, 0, sizeof (*xbi));
	memmap = NULL;
	bootfile = NULL;
	cmdline = NULL;
	*pkernel = NULL;
	*pkernel_size = 0;

	xbi->bi_cpuinfo = (uint64_t)&cpu_info[0];
	xbi->bi_cpuinfo_cnt = 0;
	xbi->bi_modules = (uint64_t)&boot_modules[0];
	xbi->bi_module_cnt = 0;
	xbi->bi_psci_cpu_suspend_id = PSCI_CPU_SUSPEND_ID;
	xbi->bi_psci_cpu_off_id = PSCI_CPU_OFF_ID;
	xbi->bi_psci_cpu_on_id = PSCI_CPU_ON_ID;
	xbi->bi_psci_migrate_id = PSCI_MIGRATE_ID;

	bm = (struct boot_modules *)xbi->bi_modules;

	curp = modulep;

	for (;;) {
		struct module_data_t moddata = {
			0, 0, NULL, NULL, NULL, 0, 0, 0,
		};

		hdrp = (uint32_t *)curp;
		mlen = hdrp[1];

		/*
		 * MODINFO_END signals the end of the TLV module list, so we
		 * use this as an additional input when calculating the last
		 * used address.
		 */
		if (hdrp[0] == MODINFO_END && mlen == 0)
			break;

		if (hdrp[0] == MODINFO_NAME) {
			if (prekern_process_module_info(curp, &moddata) != 0)
				return (-1);

			/*
			 * The environment is attached to the primary module,
			 * which is the kernel (unix), as module metadata.
			 */
			if (strcmp(moddata.mtype, "elf kernel") == 0 ||
			    strcmp(moddata.mtype, "elf64 kernel") == 0) {
				int64_t sz;

				/*
				 * Stash the module address and size, which is
				 * later used to load and start the ELF payload.
				 */
				*pkernel = (caddr_t)moddata.maddr;
				*pkernel_size = moddata.msize;

				/*
				 * It is mandatory for the kernel module to
				 * include an environment block as module
				 * metadata. This environment block becomes
				 * one of the boot modules passed to the
				 * kernel via bootinfo.
				 */

				if (moddata.env_addr == 0) {
					dboot_printf("dboot: no environment "
					    "attached to the kernel module\n");
					return (-1);
				}

				sz = prekern_calc_env_size(
				    (const char *)moddata.env_addr);
				if (sz <= 0) {
					dboot_printf("dboot: invalid or "
					    "zero-sized environment block\n");
					return (-1);
				}

				bm[xbi->bi_module_cnt].bm_addr =
				    moddata.env_addr;
				bm[xbi->bi_module_cnt].bm_name =
				    (uint64_t)&env_boot_module_name[0];
				bm[xbi->bi_module_cnt].bm_size = (uint64_t)sz;
				bm[xbi->bi_module_cnt].bm_type = BMT_ENV;
				xbi->bi_module_cnt++;

				/*
				 * The path to the kernel is passed via the
				 * module name, and is always present (already
				 * validated).
				 *
				 * The kernel command-line is passed as module
				 * metadata, and is optional.
				 *
				 * The two are stitched together by prepending
				 * the bootfile and a space to the payload
				 * command-line, then having bootflags strip
				 * out the dboot-specific flags and propagate
				 * what's left into the tail of the payload
				 * command-line buffer.
				 */
				bootfile = moddata.mname;
				cmdline = (const char *)(void *)moddata.margs;

				/*
				 * Now that we have both our bootfile and the
				 * command-line (if any), parse out our
				 * arguments, configuring dboot and producing
				 * the command-line for the kernel.
				 */
				payload_cmdline[0] = '\0';
				if (bootfile != NULL) {
					if (strlen(bootfile) >
					    (PAYLOAD_CMDLINE_MAX-2))
						panic("dboot: bootfile too long"
						    " (%u), maximum is %u\n",
						    strlen(bootfile),
						    (PAYLOAD_CMDLINE_MAX-2));
					strcpy(payload_cmdline, bootfile);
					if (cmdline != NULL)
						strcat(payload_cmdline, " ");
				}

				if (cmdline != NULL) {
					bootflags(cmdline, strlen(cmdline),
					    payload_cmdline +
					    strlen(payload_cmdline),
					    sizeof (payload_cmdline) - 1 -
					    strlen(payload_cmdline));
				}

				/*
				 * If we appended a space unnecessarily we
				 * strip that space now. "Unnecessarily" is
				 * defined as there being no arguments to
				 * pass on to the kernel.
				 */
				if (bootfile != NULL) {
					if (strlen(payload_cmdline) ==
					    (strlen(bootfile) + 1)) {
						if (payload_cmdline[strlen(
						    payload_cmdline) - 1] ==
						    ' ')
							payload_cmdline[strlen(
							    payload_cmdline) -
							    1] = '\0';
					}
				}

				xbi->bi_cmdline = (uint64_t)payload_cmdline;

				/*
				 * This is a no-op for the boot console itself,
				 * but has the side-effect of initialising the
				 * boot environment and command-line in the
				 * bcons code, which lets us use find_boot_prop
				 * to pick up any debug flags directed at dboot.
				 */
				bcons_init(xbi);

				/*
				 * Now that we have our environment we take
				 * the opportunity to configure our UART, which
				 * means that any further errors will have a
				 * chance of being seen.
				 */
				xbi->bi_bsvc_uart_mmio_base =
				    find_u64_boot_prop("bcons.uart.mmio_base",
				    EARLY_UART_PA);
				xbi->bi_bsvc_uart_type = find_u64_boot_prop(
				    "bcons.uart.type", EARLY_UART_TYPE);
				bcons_init(xbi);

				/*
				 * Turn on debugging if requested via the
				 * `dboot_debug` boolean property.
				 */
				if (find_boolean_boot_prop("dboot_debug")) {
					debug = 1;
					dprintf(
					    "dboot: debug output enabled\n");
				}

				/*
				 * It is mandatory for the elf kernel to have
				 * the UEFI memory map passed as module
				 * metadata.
				 *
				 * The memory map is used later in the
				 * configuration process to bootstrap memory
				 * management.
				 */
				if (moddata.map_addr == 0) {
					dboot_printf("dboot: no UEFI memory "
					    "map found\n");
					return (-1);
				}

				memmap = (caddr_t)moddata.map_addr;

				/*
				 * NOT_YET: we need to pick up the loader font
				 * and pass it on to the kernel. It is
				 * exceptionally vague how this works today.
				 */

				/*
				 * The optional UEFI framebuffer is passed as
				 * module metadata on the kernel module. If
				 * present, reinitialise the boot console to
				 * enable framebuffer output.
				 */
				if (moddata.fb_addr != 0) {
					framebuffer.framebuffer =
					    moddata.fb_addr;
					xbi->bi_framebuffer =
					    (uint64_t)((void *)(&framebuffer));
					bcons_init(xbi);
				}

				/*
				 * ... and since we now have a console of
				 * some type we can set up our exception
				 * vector so that any trap has meaningful
				 * information attached.
				 *
				 * We leave this fairly late as the UEFI
				 * environment will have left a handler
				 * in place, so we don't want to override
				 * that until we're fairly sure we can
				 * provide usable output.
				 */
				write_vbar((uint64_t)&exception_vector);

				/*
				 * The UEFI system table is passed via
				 * module metadata and is mandatory.
				 */
				if (moddata.systab_addr == 0) {
					dboot_printf("dboot: no UEFI "
					    "system table found\n");
					return (-1);
				}

				xbi->bi_uefi_systab = moddata.systab_addr;

				/*
				 * A flattened devicetree pointer is only
				 * present on FDT-based systems. The reason
				 * we don't pick this up from the UEFI
				 * system table pointer is that loader will
				 * have created a writable copy of the FDT,
				 * mutated it and passed the adjusted version
				 * to us.
				 */
				xbi->bi_fdt = moddata.fdt_addr;

				/*
				 * loader(7) provides us with a scratch memory
				 * block for use by the shim. This memory is
				 * allocated as loader data, so will be freed
				 * once the kernel has bootstrapped.
				 */
				if (moddata.scratch_addr == 0 ||
				    moddata.scratch_size == 0) {
					dboot_printf("dboot: no boot scratch "
					    "memory block found\n");
					return (-1);
				}

				scratch_addr = (caddr_t)moddata.scratch_addr;
				scratch_size = moddata.scratch_size;
			} else if (strcmp(moddata.mtype, "rootfs") == 0) {
				bm[xbi->bi_module_cnt].bm_addr = moddata.maddr;
				bm[xbi->bi_module_cnt].bm_name =
				    (uint64_t)&rootfs_boot_module_name[0];
				bm[xbi->bi_module_cnt].bm_size = moddata.msize;
				bm[xbi->bi_module_cnt].bm_type = BMT_ROOTFS;
				xbi->bi_module_cnt++;
			} else if (strcmp(moddata.mtype, "console-font") == 0) {
				bm[xbi->bi_module_cnt].bm_addr = moddata.maddr;
				bm[xbi->bi_module_cnt].bm_name =
				    (uint64_t)&font_boot_module_name[0];
				bm[xbi->bi_module_cnt].bm_size = moddata.msize;
				bm[xbi->bi_module_cnt].bm_type = BMT_FONT;
				xbi->bi_module_cnt++;
			} else {
				dprintf("dboot: ignoring unrecognised module "
				    "type \"%s\"\n", moddata.mtype);
			}
		}

		next = sizeof (uint32_t) * 2 + mlen;
		next = roundup(next, sizeof (ulong_t));
		curp += next;
	}

	if (bootfile == NULL || strlen(bootfile) == 0)
		panic("dboot: null bootfile passed\n");

	/*
	 * Make some assertions about our data cache line size.
	 *
	 * XXXARM: this is a weird limitation in the port, since all of
	 * this can be discovered at runtime and used to guide the various
	 * cache manipulation functions. We should spend some time on this
	 * in the future.
	 */
	if ((4u << ((read_ctr_el0() >> 16) & 0xF)) != DCACHE_LINE)
		panic("dboot: CTR_EL0=%08x DCACHE_LINE=%ld\n",
		    (uint32_t)read_ctr_el0(), DCACHE_LINE);

	/*
	 * Configuration from firmware tables
	 */
	if ((xbi->bi_smbios = dboot_uefi_get_smbios3_address()) == 0)
		dboot_printf("NOTICE: No SMBIOS3 configuration "
		    "table passed via UEFI\n");

	if (xbi->bi_fdt != 0) {
		if (dboot_configure_fdt() != 0) {
			dboot_printf("dboot: failed to perform early "
			    "configuration via FDT\n");
			return (-1);
		}
	} else {
		if (dboot_configure_acpi() != 0) {
			dboot_printf("dboot: failed to perform early "
			    "configuration via ACPI\n");
			return (-1);
		}
	}

	/*
	 * If firmware didn't set bi_arch_timer_freq we defer to the hardware,
	 * but check that a sensible value was set.
	 */
	if (xbi->bi_arch_timer_freq == 0)
		if ((xbi->bi_arch_timer_freq = read_cntfrq()) == 0)
			panic("dboot: could not determine "
			    "architected timer frequency\n");

	/*
	 * Process the UEFI memory map into our memlists.
	 *
	 * This uses the scratch regions provided by loader(7).
	 */
	if (dboot_uefi_init_mem(memmap, scratch_addr, scratch_size) != 0)
		panic("dboot: failed to initialise memory subsystem\n");

	return (0);
}
