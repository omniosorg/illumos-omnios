/*-
 * Copyright (c) 2006 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <stand.h>
#include <string.h>

#include <sys/param.h>
#include <sys/linker.h>
#include <machine/elf.h>
#include <machine/metadata.h>

#include <bootstrap.h>

#include <efi.h>
#include <efilib.h>
#include <Guid/Acpi.h>
#include <Guid/Fdt.h>

#include "loader_efi.h"
#include "cache.h"
#include "libzfs.h"

#include "platform/acfreebsd.h"
#include "acconfig.h"
#define	ACPI_SYSTEM_XFACE
#if !defined(ACPI_USE_SYSTEM_INTTYPES)
#define	ACPI_USE_SYSTEM_INTTYPES	1
#endif
#include "actypes.h"
#include "actbl.h"

/* #define	ELF_VERBOSE	1 */

extern int bi_load(char *args, vm_offset_t *modulep, vm_offset_t *kernendp);

static int elf64_exec(struct preloaded_file *amp);
static int elf64_loadfile_(char *filename, uint64_t dest,
    struct preloaded_file **result);

static
struct file_format arm64_elf = {
	elf64_loadfile_,
	elf64_exec
};

struct file_format *file_formats[] = {
	&arm64_elf,
	NULL
};

/*
 * illumos/aarch64 is a bit different to other platforms. The kernel is
 * compiled with VA set to the final KVA and PA set to 0. Embedded into the
 * kernel, and pointed to by the e_entry member of the ELF header, is dboot.
 * This is a self-relocating shim that decodes the FreeBSD-style bootinfo
 * passed by loader, sets up KPM, loads the kernel to the final VA and jumps
 * to the kernel itself. Of note is that dboot embeds an ELF loader that
 * copies the kernel data to suitably aligned memory pages prior to execution,
 * so loader doesn't even need to worry about BSS.
 *
 * This all means that the kernel is treated as a blob of data from the
 * point of view of loader, so it's loaded as such. Once in memory, the
 * ELF header is read to find the dboot entrypoint and the program headers
 * are inspected to find the physical address for that entrypoint.
 *
 * When loader executes the loaded kernel it hits the dboot entrypoint,
 * which discovers where it was loaded and relocates itself (it's an
 * embedded standalone) before proceeding with execution. The relocation
 * logic has a requirement that the entrypoint itself must be page-aligned.
 */

int
elf64_loadfile_(char *filename, uint64_t dest, struct preloaded_file **result)
{
	Elf_Ehdr *ehdr;
	Elf_Phdr *phdr;
	struct preloaded_file *fp;
	caddr_t firstpage;
	size_t firstlen;
	ssize_t nread;
	int fd;
	int err;
	ssize_t got;
	struct stat st;
	int i;
	uint64_t ldest = dest;
	size_t scratch_size;
	uint64_t scratch_addr;

	static const char kerneltype[] = "elf kernel";

	err = EFTYPE;	/* allow the next handler to run */
	firstpage = NULL;
	fd = -1;
	fp = NULL;

	/*
	 * We're always called with a fully qualified path, so no need to
	 * search for the file.
	 */

	if (filename == NULL)
		goto out;

	if ((fd = open(filename, O_RDONLY)) < 0)
		goto out;

	if ((firstpage = malloc(PAGE_SIZE)) == NULL) {
		err = ENOMEM;
		goto out;
	}

	nread = read(fd, firstpage, PAGE_SIZE);
	(void) close(fd);
	fd = -1;
	firstlen = (size_t)nread;
	if (nread < 0 || firstlen <= sizeof (*ehdr))
		goto out;
	ehdr = (Elf_Ehdr *)firstpage;

	if (!IS_ELF(*ehdr))
		goto out;

	/*
	 * We only load valid ELF files of type ET_EXEC with the Solaris
	 * OS ABI and that target aarch64. Furthermore, we only perform the
	 * loading when we are on aarch64.
	 */
	if (ehdr->e_ident[EI_CLASS] != ELF_TARG_CLASS ||
	    ehdr->e_ident[EI_DATA] != ELF_TARG_DATA ||
	    ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_version != EV_CURRENT ||
	    ehdr->e_type != ET_EXEC ||
	    ehdr->e_ident[EI_OSABI] != ELFOSABI_SOLARIS ||
	    ehdr->e_machine != EM_AARCH64 ||
	    ehdr->e_machine != ELF_TARG_MACH)
		goto out;

	if (file_findfile(NULL, kerneltype) != NULL) {
		err = EPERM;
		goto out;
	}

	if ((fd = open(filename, O_RDONLY)) < 0) {
		err = ENOENT;
		goto out;
	}

	if (fstat(fd, &st) < 0) {
		err = errno;
		goto out;
	}

	printf("%s", filename);

	/*
	 * Our load address (passed in dest) was allocated with an extra
	 * page to allow us to align the dboot entrypoint, which in turn
	 * let's the dboot embedded standalone easily self-relocate.
	 *
	 * For the sake of simplicity, assume that kernel program header
	 * addresses are page aligned (a safe assumption, given we
	 * maintain the mapfile). This means that we can assume that
	 * the offset can be determined with a simple mask, which means
	 * that it's trivial to calculate the load destination that will
	 * place the dboot entrypoint at a page-aligned address.
	 */
	ldest = dest + (PAGE_SIZE - (ehdr->e_entry & 0xfff));

	got = archsw.arch_readin(fd, ldest, st.st_size);
	if ((size_t)got != st.st_size) {
		err = errno;
		goto out;
	}

	fp = file_alloc();
	if (fp == NULL) {
		err = ENOMEM;
		goto out;
	}

	fp->f_name = strdup(filename);
	fp->f_type = strdup(kerneltype);
	fp->f_addr = ldest;	/* so that loader can find it */
	fp->f_size = st.st_size;

	if (fp->f_type == NULL || fp->f_name == NULL) {
		err = ENOMEM;
		goto out;
	}

	if ((ehdr->e_phoff + ehdr->e_phnum * sizeof (*phdr)) > firstlen)
		goto out;
	phdr = (Elf_Phdr *)(firstpage + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++) {
		/*
		 * We are only interested in loadable segments.
		 */
		if (phdr[i].p_type != PT_LOAD)
			continue;

		/*
		 * We're only interested in the segment that contains our
		 * entrypoint.
		 */
		if (ehdr->e_entry < phdr[i].p_vaddr ||
		    ehdr->e_entry + 4 >= phdr[i].p_vaddr + phdr[i].p_memsz)
			continue;

		/*
		 * Found the segment containing our entrypoint, adjust the
		 * entrypoint to point to an offset from the physical address
		 * the kernel was loaded at. When executed, dboot (the entry
		 * code) will self-relocate to this address.
		 */
		ehdr->e_entry = (ldest + phdr[i].p_offset) +
		    (ehdr->e_entry - phdr[i].p_vaddr);
		break;
	}

	/*
	 * Something is very wrong if we can't find the segment containing
	 * our entrypoint.
	 */
	if (i >= ehdr->e_phnum)
		goto out;

	/*
	 * 64MiB of scratch
	 *
	 * XXXARM: this seems generous - should it be configurable? What
	 * should the default be?
	 */
	scratch_size = (64 * 1024 * 1024);
	scratch_addr = archsw.arch_loadaddr(LOAD_MEM, &scratch_size, 0);
	if (scratch_addr == 0)
		panic("failed to allocate boot scratch\n");
	file_addmetadata(fp, MODINFOMD_SCRATCH_ADDR,
	    sizeof (scratch_addr), &scratch_addr);
	file_addmetadata(fp, MODINFOMD_SCRATCH_SIZE,
	    sizeof (scratch_size), &scratch_size);

	/*
	 * MODINFOMD_ELFHDR is used by elf64_exec to locate the entrypoint
	 * that it needs to jump to. There are no other uses of this
	 * metadata.
	 */
	file_addmetadata(fp, MODINFOMD_ELFHDR, sizeof (*ehdr), ehdr);

	err = 0;

out:
	if (err == 0) {
		*result = fp;
#ifdef ELF_VERBOSE
		printf(" loadaddr 0x%jx+0x%jx,",
		    (uintmax_t)ldest, (uintmax_t)st.st_size);
		printf(" entry at 0x%jx\n",
		    (uintmax_t)ehdr->e_entry);
#else
		printf("\n");
#endif
	} else {
		if (err != EFTYPE)
			printf(": %s\n", strerror(err));
		file_discard(fp);
	}

	if (firstpage != NULL)
		free(firstpage);

	if (fd != -1)
		(void) close(fd);

	return (err);
}

/*
 * Search the command line for named property.
 *
 * Return codes:
 *	0	The name is found, we return the data in value and len.
 *	ENOENT	The name is not found.
 *	EINVAL	The provided command line is badly formed.
 */
static int
find_property_value(const char *cmd, const char *name, const char **value,
    size_t *len)
{
	const char *namep, *valuep;
	size_t name_len, value_len;
	int quoted;

	*value = NULL;
	*len = 0;

	if (cmd == NULL)
		return (ENOENT);

	while (*cmd != '\0') {
		if (cmd[0] != '-' || cmd[1] != 'B') {
			cmd++;
			continue;
		}
		cmd += 2;	/* Skip -B */
		while (cmd[0] == ' ' || cmd[0] == '\t')
			cmd++;	/* Skip whitespaces. */
		while (*cmd != '\0' && cmd[0] != ' ' && cmd[0] != '\t') {
			namep = cmd;
			valuep = strchr(cmd, '=');
			if (valuep == NULL)
				break;
			name_len = valuep - namep;
			valuep++;
			value_len = 0;
			quoted = 0;
			for (; ; ++value_len) {
				if (valuep[value_len] == '\0')
					break;

				/* Is this value quoted? */
				if (value_len == 0 &&
				    (valuep[0] == '\'' || valuep[0] == '"')) {
					quoted = valuep[0];
					++value_len;
				}

				/*
				 * In the quote accept any character,
				 * but look for ending quote.
				 */
				if (quoted != 0) {
					if (valuep[value_len] == quoted)
						quoted = 0;
					continue;
				}

				/* A comma or white space ends the value. */
				if (valuep[value_len] == ',' ||
				    valuep[value_len] == ' ' ||
				    valuep[value_len] == '\t')
					break;
			}
			if (quoted != 0) {
				printf("Missing closing '%c' in \"%s\"\n",
				    quoted, valuep);
				return (EINVAL);
			}
			if (value_len != 0) {
				if (strncmp(namep, name, name_len) == 0) {
					*value = valuep;
					*len = value_len;
					return (0);
				}
			}
			cmd = valuep + value_len;
			while (*cmd == ',')
				cmd++;
		}
	}
	return (ENOENT);
}

static int
elf64_exec(struct preloaded_file *fp)
{
	vm_offset_t modulep, kernendp;
	vm_offset_t clean_addr;
	size_t clean_size;
	struct file_metadata *md;
	Elf_Ehdr *ehdr;
	int err;
	int rv;
	size_t len;
	void (*entry)(vm_offset_t);
	bool zfs_root = false;
	struct devdesc *rootdev;
	const char *fs;

	/*
	 * With multiple console devices and "os_console" variable not
	 * set, set os_console to last input device.
	 */
	rv = cons_inputdev();
	if (rv != -1)
		(void) setenv("os_console", consoles[rv]->c_name, 0);

	efi_getdev((void **)(&rootdev), NULL, NULL);
	if (rootdev == NULL) {
		printf("can't determine root device\n");
		return (EFTYPE);	/* XXX: need a better code */
	}
	if (rootdev->d_dev->dv_type == DEVT_ZFS)
		zfs_root = true;

	/* If we have fstype set in env, reset zfs_root if needed. */
	fs = getenv("fstype");
	if (fs != NULL && strcmp(fs, "zfs") != 0)
		zfs_root = false;

	/*
	 * If we have fstype set on the command line,
	 * reset zfs_root if needed.
	 */
	rv = find_property_value(fp->f_args, "fstype", &fs, &len);
	if (rv != 0 && rv != ENOENT)
		return (rv);

	if (fs != NULL && strncmp(fs, "zfs", len) != 0)
		zfs_root = false;

	/* zfs_bootfs() will set the environment, it must be called. */
	if (zfs_root == true)
		fs = zfs_bootfs(rootdev);

	/*
	 * aarch64 systems can only have ACPI 2.0 tables.
	 *
	 * We have to have either ACPI or FDT. If both are present we'll
	 * only present ACPI to the OS. This is aligned with EBBR.
	 */
	if (efi_get_table(&gEfiAcpi20TableGuid) == NULL) {
		if (efi_get_table(&gFdtTableGuid) == NULL) {
			printf("can't determine firmware table type\n");
			return (EFTYPE);
		} else {
			uint64_t dtbp;
			extern const void *efi_get_fdtp(void);

			if ((dtbp = (uint64_t)efi_get_fdtp()) == 0) {
				printf("can't retrieve FDT pointer\n");
				return (EFTYPE);
			}

			file_addmetadata(fp, MODINFOMD_DTBP,
			    sizeof (dtbp), &dtbp);
		}
	} else {
		if (efi_get_table(&gFdtTableGuid) != NULL) {
			printf("WARNING: Both FDT and ACPI configuration "
			    "tables detected. Only ACPI will be presented "
			    "to the kernel.\n");
		}
	}

	if ((md = file_findmetadata(fp, MODINFOMD_ELFHDR)) == NULL)
		return (EFTYPE);

	ehdr = (Elf_Ehdr *)&(md->md_data);
	entry = efi_translate(ehdr->e_entry);
#if defined(ELF_VERBOSE)
	printf("elf64_exec: Jumping to entrypoint %p\n", entry);
#endif

	efi_time_fini();
	err = bi_load(fp->f_args, &modulep, &kernendp);
	if (err != 0) {
		efi_time_init();
		return (err);
	}

	/*
	 * Thou shalt not print after bi_load.
	 */

	dev_cleanup();

	/* Clean D-cache under kernel area and invalidate whole I-cache */
	clean_addr = (vm_offset_t)efi_translate(fp->f_addr);
	clean_size = (vm_offset_t)efi_translate(kernendp) - clean_addr;

	cpu_flush_dcache((void *)clean_addr, clean_size);
	cpu_inval_icache(NULL, 0);

	(*entry)(modulep);
	panic("exec returned");
}
