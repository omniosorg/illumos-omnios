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
 *
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 *
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2020 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 * Copyright 2025 Michael van der Westhuizen
 */

/*
 * This file contains the functionality that mimics the boot operations
 * on SPARC systems or the old boot.bin/multiboot programs on x86 systems.
 * The armv8 kernel now does everything on its own.
 */

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>
#include <sys/multiboot.h>
#include <sys/bootvfs.h>
#include <sys/bootprops.h>
#include <sys/varargs.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/promif.h>
#include <sys/archsystm.h>
#include <sys/kobj.h>
#include <sys/privregs.h>
#include <sys/sysmacros.h>
#include <sys/ctype.h>
#include <vm/hat_pte.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/ddipropdefs.h>	/* For DDI prop types */
#include <netinet/inetutil.h>	/* for hexascii_to_octet */
#include <sys/boot_console.h>
#include <sys/sunddi.h>
#if defined(_USE_FDT)
#include <libfdt.h>
#endif

extern void bsvc_init(struct xboot_info *);

static void bmemlist_init(struct xboot_info *);
static void bmemlist_insert(struct memlist **, uint64_t, uint64_t);
static void bmemlist_remove(struct memlist **, uint64_t, uint64_t);
static uint64_t bmemlist_find(struct memlist **, uint64_t, int);
static struct memlist *bootmem_avail;
static caddr_t do_bsys_alloc(bootops_t *, caddr_t, size_t, int);
static paddr_t do_bop_phys_alloc(bootops_t *, size_t, int);
static void do_bsys_free(bootops_t *, caddr_t, size_t);
static char *do_bsys_nextprop(bootops_t *, char *);
static void bsetprops(char *, char *);
static void bsetprop32(char *, uint32_t);
static void bsetprop64(char *, uint64_t);
static void bsetpropsi(char *, int);
static void bsetprop(int, char *, int, void *, int);
static int parse_value(char *, uint64_t *);
static void build_boot_properties(struct xboot_info *);
static void boot_prop_display(char *);

static bootops_t bootop;
static struct xboot_info *xbootp;
static char *boot_args = "";
static char *whoami;
#define	BUFFERSIZE	256
static char buffer[BUFFERSIZE];

/*
 * stuff to store/report/manipulate boot property settings.
 */
typedef struct bootprop {
	struct bootprop	*bp_next;
	char		*bp_name;
	int		bp_flags;	/* DDI prop type */
	uint_t		bp_vlen;	/* 0 for boolean */
	char		*bp_value;
} bootprop_t;

static bootprop_t *bprops = NULL;
static char *curr_page = NULL;		/* ptr to avail bprop memory */
static size_t curr_space = 0;		/* amount of memory at curr_page */

/*
 * Debugging macros
 */
static uint_t kbm_debug = 0;
#define	DBG_MSG(s)	do {						\
	if (kbm_debug)							\
		bop_printf(NULL, "%s", (s));				\
	} while (0)
#define	DBG(x)		do {						\
	if (kbm_debug)							\
		bop_printf(NULL,					\
		    "%s is %" PRIx64 "\n", #x, (uint64_t)(x));		\
	} while (0)
#define	PUT_STRING(s)	do {						\
	char *cp;							\
	for (cp = (s); *cp; ++cp)					\
		BSVC_PUTCHAR(SYSP, *cp);				\
	} while (0)

static caddr_t
no_more_alloc(bootops_t *bop, caddr_t virthint, size_t size, int align)
{
	panic("Attempt to bsys_alloc() too late\n");
	return (NULL);
}

static void
no_more_free(bootops_t *bop, caddr_t virt, size_t size)
{
	panic("Attempt to bsys_free() too late\n");
}

static paddr_t
no_more_palloc(bootops_t *bop, size_t size, int align)
{
	panic("Attempt to bsys_palloc() too late\n");
	return (0);
}

void
bop_no_more_mem(void)
{
	bootops->bsys_alloc = no_more_alloc;
	bootops->bsys_free = no_more_free;
	bootops->bsys_palloc = no_more_palloc;
}

/*
 * Allocate a region of virtual address space, unmapped.
 * Stubbed out except on sparc, at least for now.
 */
void *
boot_virt_alloc(void *addr, size_t size)
{
	return (addr);
}

int
boot_compinfo(int fd, struct compinfo *cbp)
{
	cbp->iscmp = 0;
	cbp->blksize = MAXBSIZE;
	return (0);
}

static inline int
l1_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >>
	    (PAGESHIFT+3*NPTESHIFT)) & ((1<<NPTESHIFT)-1));
}

static inline int
l2_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >>
	    (PAGESHIFT+2*NPTESHIFT)) & ((1<<NPTESHIFT)-1));
}

static inline int
l3_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >>
	    (PAGESHIFT+1*NPTESHIFT)) & ((1<<NPTESHIFT)-1));
}

static inline int
l4_pteidx(caddr_t vaddr)
{
	return ((((uintptr_t)vaddr) >> (PAGESHIFT)) & ((1<<NPTESHIFT)-1));
}

static paddr_t
pt_alloc(bootops_t *bop)
{
	extern int physMemInit;
	paddr_t pa = do_bop_phys_alloc(bop, MMU_PAGESIZE, MMU_PAGESIZE);
	if (pa == 0)
		bop_panic("phy alloc error for L2 PT\n");
	if (physMemInit) {
		page_t *pp = page_numtopp(mmu_btop(pa), SE_EXCL);
		ASSERT(pp != NULL);
		page_pp_lock(pp, 0, 1);
		ASSERT(pp != NULL);
		ASSERT(!PP_ISFREE(pp));
		ASSERT(pp->p_lckcnt == 1);
		ASSERT(PAGE_EXCL(pp));
	}
	bzero((void *)(uintptr_t)pa, MMU_PAGESIZE);
	return (pa);
}

static void
map_phys(bootops_t *bop, pte_t pte_attr, caddr_t vaddr, uint64_t paddr)
{
	int l1_idx = l1_pteidx(vaddr);
	int l2_idx = l2_pteidx(vaddr);
	int l3_idx = l3_pteidx(vaddr);
	int l4_idx = l4_pteidx(vaddr);

	pte_t *l1_ptbl =
	    (pte_t *)((((uint64_t)vaddr) >> 63)? read_ttbr1(): read_ttbr0());

	if ((l1_ptbl[l1_idx] & PTE_TYPE_MASK) == 0) {
		paddr_t pa = pt_alloc(bop);
		dsb(ish);
		l1_ptbl[l1_idx] =
		    PTE_TABLE_UXNT | PTE_TABLE_APT_NOUSER | pa | PTE_TABLE;
	}

	if ((l1_ptbl[l1_idx] & PTE_VALID) == 0) {
		bop_panic("invalid L1 PT\n");
	}

	pte_t *l2_ptbl = (pte_t *)(uintptr_t)(l1_ptbl[l1_idx] & PTE_PFN_MASK);

	if ((l2_ptbl[l2_idx] & PTE_TYPE_MASK) == 0) {
		paddr_t pa = pt_alloc(bop);
		dsb(ish);
		l2_ptbl[l2_idx] =
		    PTE_TABLE_UXNT | PTE_TABLE_APT_NOUSER | pa | PTE_TABLE;
	}

	if ((l2_ptbl[l2_idx] & PTE_TYPE_MASK) != PTE_TABLE) {
		bop_panic("invalid L2 PT\n");
	}

	pte_t *l3_ptbl = (pte_t *)(uintptr_t)(l2_ptbl[l2_idx] & PTE_PFN_MASK);

	if ((l3_ptbl[l3_idx] & PTE_TYPE_MASK) == 0) {
		paddr_t pa = pt_alloc(bop);
		bzero((void *)(uintptr_t)pa, MMU_PAGESIZE);
		dsb(ish);
		l3_ptbl[l3_idx] =
		    PTE_TABLE_UXNT | PTE_TABLE_APT_NOUSER | pa | PTE_TABLE;
	}

	if ((l3_ptbl[l3_idx] & PTE_TYPE_MASK) != PTE_TABLE) {
		bop_panic("invalid L3 PT\n");
	}

	pte_t *l4_ptbl = (pte_t *)(uintptr_t)(l3_ptbl[l3_idx] & PTE_PFN_MASK);
	if (l4_ptbl[l4_idx] & PTE_VALID) {
		bop_panic("invalid L4 PT\n");
	}
	l4_ptbl[l4_idx] = paddr | pte_attr | PTE_PAGE;
	dsb(ish);
}

void
bop_relocate(void)
{
	caddr_t vaddr;

	if (xbootp == NULL)
		return;

	if (xbootp->bi_fdt != 0) {
#if defined(_USE_FDT)
		size_t sz;

		if (fdt_check_header((const void *)xbootp->bi_fdt) != 0)
			panic("provided FDT is invalid\n");

		/*
		 * This may be a little generous... we really should
		 * not be editing the FDT any further.
		 */
		sz = fdt_totalsize((const void *)xbootp->bi_fdt);
		sz += (MMU_PAGESIZE * 2) + MMU_PAGESIZE;
		sz &= ~(MMU_PAGESIZE - 1);

		vaddr = kmem_zalloc(sz, KM_SLEEP);
		ASSERT3P(vaddr, !=, NULL);

		if (fdt_open_into(
		    (const void *)xbootp->bi_fdt, vaddr, sz) != 0)
			panic("failed to relocate FDT to KVA\n");

		prom_init("kernel", vaddr);
#endif
	}
}

void
bop_init(struct xboot_info *xbp)
{
	extern void boot_fb_shadow_init(bootops_t *);

	bsvc_init(xbp);

	bootops = &bootop;
	xbootp = xbp;

	prom_init("kernel", (void *)xbp->bi_fdt);
	bmemlist_init(xbp);

	/*
	 * Fill in the bootops vector
	 */
	bootops->bsys_version = BO_VERSION;
	bootops->bsys_alloc = do_bsys_alloc;
	bootops->bsys_palloc = do_bop_phys_alloc;
	bootops->bsys_free = do_bsys_free;
	bootops->bsys_getproplen = do_bsys_getproplen;
	bootops->bsys_getprop = do_bsys_getprop;
	bootops->bsys_nextprop = do_bsys_nextprop;
	bootops->bsys_printf = bop_printf;

	bcons_init(xbp);

	/*
	 * enable debugging
	 */
	if (find_boot_prop("kbm_debug") != NULL)
		kbm_debug = 1;

	/* Set up the shadow fb for framebuffer console */
	boot_fb_shadow_init(bootops);

	/*
	 * Start building the boot properties from the command line
	 */
	DBG_MSG("Initializing boot properties:\n");
	build_boot_properties(xbp);

	if (find_boot_prop("prom_debug") || kbm_debug) {
		char *value;

		value = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, MMU_PAGESIZE);
		boot_prop_display(value);
	}

	/*
	 * We are called from kobj_start, which then jumps into krtld via
	 * kobj_init.
	 */
}

static uintptr_t
alloc_vaddr(size_t size, int align)
{
	uintptr_t va = bmemlist_find(&bootmem_avail, size, align);
	return (va);
}

static void
do_bsys_free(bootops_t *bop __unused, caddr_t virt, size_t size)
{
	bop_printf(NULL, "do_bsys_free(virt=0x%p, size=0x%lx) ignored\n",
	    (void *)virt, size);
}

static paddr_t
do_bop_phys_alloc(bootops_t *bop, size_t size, int align)
{
	extern struct memlist *phys_avail;
	extern int physMemInit;
	paddr_t pa = bmemlist_find(&phys_avail, size, align);
	if (pa == 0) {
		bop_panic("do_bop_phys_alloc(0x%lx, 0x%x) Out of memory\n",
		    size, align);
	}
	if (physMemInit) {
		page_t *pp;
#ifdef DEBUG
		pp = page_numtopp_nolock(mmu_btop(pa));
		ASSERT(pp != NULL);
		ASSERT(PP_ISFREE(pp));
#endif
		pp = page_numtopp(mmu_btop(pa), SE_EXCL);
		ASSERT(pp != NULL);
		ASSERT(!PP_ISFREE(pp));
		page_unlock(pp);
	}

	return (pa);
}

static caddr_t
do_bsys_alloc(bootops_t *bop, caddr_t virthint, size_t size, int align)
{
	paddr_t a = align;	/* same type as pa for masking */
	paddr_t pa;
	caddr_t va;
	ssize_t s;		/* the aligned size */

	if (a < MMU_PAGESIZE)
		a = MMU_PAGESIZE;
	else if (!ISP2(a))
		bop_panic("do_bsys_alloc() incorrect alignment");
	size = P2ROUNDUP(size, MMU_PAGESIZE);

	/*
	 * Use the next aligned virtual address if we weren't given one.
	 */
	if (virthint == NULL) {
		virthint = (caddr_t)alloc_vaddr(size, a);
	}

	/*
	 * allocate the physical memory
	 */
	pa = do_bop_phys_alloc(bop, size, a);

	/*
	 * Add the mappings to the page tables, try large pages first.
	 */
	va = virthint;
	s = size;
	while (s > 0) {
		/*
		 * XXXARM: These were marking the page non-executable with
		 * PTE_UXN and PTE_PXN -- not executable by either user or
		 * priv'd processes.
		 *
		 * We're disabling that, because we map genunix's text this
		 * way (I think?) and obviously that's very bad.
		 *
		 * But we need to do something better than this, somehow?
		 * If this even works
		 */
		map_phys(bop, PTE_NOCONSIST | PTE_AF | PTE_SH_INNER |
		    PTE_AP_KRWUNA | PTE_ATTR_NORMEM, va, pa);
		va += MMU_PAGESIZE;
		pa += MMU_PAGESIZE;
		s -= MMU_PAGESIZE;
	}
	memset(virthint, 0, size);
	return (virthint);
}

static void
bsetprop(int flags, char *name, int nlen, void *value, int vlen)
{
	ssize_t size;
	ssize_t need_size;
	bootprop_t *b;

	/*
	 * align the size to 16 byte boundary
	 */
	size = P2ALIGN(sizeof (bootprop_t) + nlen + 1 + vlen + 0xf, 0x10);
	if (size > curr_space) {
		need_size = (size + (MMU_PAGEOFFSET)) & MMU_PAGEMASK;
		curr_page = do_bsys_alloc(NULL, 0, need_size, MMU_PAGESIZE);
		curr_space = need_size;
	}

	/*
	 * use a bootprop_t at curr_page and link into list
	 */
	b = (bootprop_t *)curr_page;
	curr_page += sizeof (bootprop_t);
	curr_space -=  sizeof (bootprop_t);
	b->bp_next = bprops;
	bprops = b;

	/*
	 * follow by name and ending zero byte
	 */
	b->bp_name = curr_page;
	bcopy(name, curr_page, nlen);
	curr_page += nlen;
	*curr_page++ = 0;
	curr_space -= nlen + 1;

	/*
	 * set the property type
	 */
	b->bp_flags = flags & DDI_PROP_TYPE_MASK;

	/*
	 * copy in value, but no ending zero byte
	 */
	b->bp_value = curr_page;
	b->bp_vlen = vlen;
	if (vlen > 0) {
		bcopy(value, curr_page, vlen);
		curr_page += vlen;
		curr_space -= vlen;
	}

	/*
	 * align new values of curr_page, curr_space
	 */
	curr_page = (char *)P2ALIGN(((uintptr_t)curr_page) + 0xf, 0x10);
	curr_space = P2ALIGN(curr_space, 0x10);
}

static void
bsetprops(char *name, char *value)
{
	bsetprop(DDI_PROP_TYPE_STRING, name, strlen(name),
	    value, strlen(value) + 1);
}

static void
bsetprop32(char *name, uint32_t value)
{
	bsetprop(DDI_PROP_TYPE_INT, name, strlen(name),
	    (void *)&value, sizeof (value));
}

static void
bsetprop64(char *name, uint64_t value)
{
	bsetprop(DDI_PROP_TYPE_INT64, name, strlen(name),
	    (void *)&value, sizeof (value));
}

static void
bsetpropsi(char *name, int value)
{
	char prop_val[32];

	(void) snprintf(prop_val, sizeof (prop_val), "%d", value);
	bsetprops(name, prop_val);
}

/*
 * to find the type of the value associated with this name
 */
int
do_bsys_getproptype(bootops_t *bop __unused, const char *name)
{
	bootprop_t *b;

	for (b = bprops; b != NULL; b = b->bp_next) {
		if (strcmp(name, b->bp_name) != 0)
			continue;
		return (b->bp_flags);
	}

	return (-1);
}

/*
 * to find the size of the buffer to allocate
 */
ssize_t
do_bsys_getproplen(bootops_t *bop __unused, const char *name)
{
	bootprop_t *b;

	for (b = bprops; b; b = b->bp_next) {
		if (strcmp(name, b->bp_name) != 0)
			continue;
		return (b->bp_vlen);
	}

	return (-1);
}

/*
 * get the value associated with this name
 */
int
do_bsys_getprop(bootops_t *bop __unused, const char *name, void *value)
{
	bootprop_t *b;

	for (b = bprops; b; b = b->bp_next) {
		if (strcmp(name, b->bp_name) != 0)
			continue;
		bcopy(b->bp_value, value, b->bp_vlen);
		return (0);
	}

	return (-1);
}

/*
 * get the name of the next property in succession from the standalone
 */
static char *
do_bsys_nextprop(bootops_t *bop __unused, char *name)
{
	bootprop_t *b;

	/*
	 * A null name is a special signal for the first boot property
	 */
	if (name == NULL || strlen(name) == 0) {
		if (bprops == NULL)
			return (NULL);
		return (bprops->bp_name);
	}

	for (b = bprops; b; b = b->bp_next) {
		if (name != b->bp_name)
			continue;

		b = b->bp_next;
		if (b == NULL)
			return (NULL);

		return (b->bp_name);
	}

	return (NULL);
}

/*
 * Parse numeric value from a string. Understands decimal, hex, octal, - and ~
 */
static int
parse_value(char *p, uint64_t *retval)
{
	int rv;
	int adjust = 0;
	uint64_t tmp = 0;
	char *ep;

	*retval = 0;

	if (*p == '-' || *p == '~')
		adjust = *p++;

	rv = ddi_strtoul(p, &ep, 0, &tmp);
	if (rv != 0 || *p == '\0' || *ep != '\0')
		return (-1);

	if (adjust == '-')
		*retval = -tmp;
	else if (adjust == '~')
		*retval = ~tmp;
	else
		*retval = tmp;

	return (0);
}

static boolean_t
unprintable(char *value, int size)
{
	int i;

	if (size <= 0 || value[0] == '\0')
		return (B_TRUE);

	for (i = 0; i < size; i++) {
		if (value[i] == '\0')
			return (i != (size - 1));

		if (!isprint(value[i]))
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Print out information about all boot properties.
 * buffer is pointer to pre-allocated space to be used as temporary
 * space for property values.
 */
static void
boot_prop_display(char *buffer)
{
	char *name = "";
	int i, len, flags, *buf32;
	int64_t *buf64;

	bop_printf(NULL, "\nBoot properties:\n");

	while ((name = do_bsys_nextprop(NULL, name)) != NULL) {
		bop_printf(NULL, "\t0x%p %s = ", (void *)name, name);
		(void) do_bsys_getprop(NULL, name, buffer);
		len = do_bsys_getproplen(NULL, name);
		flags = do_bsys_getproptype(NULL, name);
		bop_printf(NULL, "len=%d ", len);

		switch (flags) {
		case DDI_PROP_TYPE_INT:
			len = len / sizeof (int);
			buf32 = (int *)buffer;
			for (i = 0; i < len; i++) {
				bop_printf(NULL, "%08x", buf32[i]);
				if (i < len - 1)
					bop_printf(NULL, ".");
			}
			break;
		case DDI_PROP_TYPE_STRING:
			bop_printf(NULL, "%s", buffer);
			break;
		case DDI_PROP_TYPE_INT64:
			len = len / sizeof (int64_t);
			buf64 = (int64_t *)buffer;
			for (i = 0; i < len; i++) {
				bop_printf(NULL, "%016" PRIx64, buf64[i]);
				if (i < len - 1)
					bop_printf(NULL, ".");
			}
			break;
		case DDI_PROP_TYPE_BYTE:
			for (i = 0; i < len; i++) {
				bop_printf(NULL, "%02x", buffer[i] & 0xff);
				if (i < len - 1)
					bop_printf(NULL, ".");
			}
			break;
		default:
			if (!unprintable(buffer, len)) {
				buffer[len] = 0;
				bop_printf(NULL, "%s", buffer);
				break;
			}
			for (i = 0; i < len; i++) {
				bop_printf(NULL, "%02x", buffer[i] & 0xff);
				if (i < len - 1)
					bop_printf(NULL, ".");
			}
			break;
		}
		bop_printf(NULL, "\n");
	}
}

/*
 * Second part of building the table of boot properties. This includes:
 * - values from /boot/solaris/bootenv.rc (ie. eeprom(8) values)
 *
 * lines look like one of:
 * ^$
 * ^# comment till end of line
 * setprop name 'value'
 * setprop name value
 * setprop name "value"
 *
 * we do single character I/O since this is really just looking at memory
 */
void
read_bootenvrc(void)
{
	int fd;
	char *line;
	int c;
	int bytes_read;
	char *name;
	int n_len;
	char *value;
	int v_len;
	char *inputdev; /* these override the command line if serial ports */
	char *outputdev;
	char *consoledev;
	uint64_t lvalue;
	extern int bootrd_debug;

	DBG_MSG("Opening /boot/solaris/bootenv.rc\n");
	fd = BRD_OPEN(bfs_ops, "/boot/solaris/bootenv.rc", 0);
	DBG(fd);

	line = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, MMU_PAGESIZE);
	while (fd >= 0) {

		/*
		 * get a line
		 */
		for (c = 0; ; ++c) {
			bytes_read = BRD_READ(bfs_ops, fd, line + c, 1);
			if (bytes_read == 0) {
				if (c == 0)
					goto done;
				break;
			}
			if (line[c] == '\n')
				break;
		}
		line[c] = 0;

		/*
		 * ignore comment lines
		 */
		c = 0;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] == '#' || line[c] == 0)
			continue;

		/*
		 * must have "setprop " or "setprop\t"
		 */
		if (strncmp(line + c, "setprop ", 8) != 0 &&
		    strncmp(line + c, "setprop\t", 8) != 0)
			continue;
		c += 8;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] == 0)
			continue;

		/*
		 * gather up the property name
		 */
		name = line + c;
		n_len = 0;
		while (line[c] && !ISSPACE(line[c]))
			++n_len, ++c;

		/*
		 * gather up the value, if any
		 */
		value = "";
		v_len = 0;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] != 0) {
			value = line + c;
			while (line[c] && !ISSPACE(line[c]))
				++v_len, ++c;
		}

		if (v_len >= 2 && value[0] == value[v_len - 1] &&
		    (value[0] == '\'' || value[0] == '"')) {
			++value;
			v_len -= 2;
		}
		name[n_len] = 0;
		if (v_len > 0)
			value[v_len] = 0;
		else
			continue;

		/*
		 * ignore "boot-file" property, it's now meaningless
		 */
		if (strcmp(name, "boot-file") == 0)
			continue;
		if (strcmp(name, "boot-args") == 0 &&
		    strlen(boot_args) > 0)
			continue;

		/*
		 * If a property was explicitly set on the command line
		 * it will override a setting in bootenv.rc. We make an
		 * exception for a property from the bootloader such as:
		 *
		 * console="text,ttya,ttyb,ttyc,ttyd"
		 *
		 * In such a case, picking the first value here (as
		 * lookup_console_devices() does) is at best a guess; if
		 * bootenv.rc has a value, it's probably better.
		 */
		if (strcmp(name, "console") == 0) {
			char propval[BP_MAX_STRLEN] = "";

			if (do_bsys_getprop(NULL, name, propval) == -1 ||
			    strchr(propval, ',') != NULL)
				bsetprops(name, value);
			continue;
		}

		if (do_bsys_getproplen(NULL, name) == -1)
			bsetprops(name, value);
	}
done:
	if (fd >= 0)
		(void) BRD_CLOSE(bfs_ops, fd);

	/*
	 * Check if we have to limit the boot time allocator
	 */
	if (do_bsys_getproplen(NULL, "physmem") != -1 &&
	    do_bsys_getprop(NULL, "physmem", line) >= 0 &&
	    parse_value(line, &lvalue) != -1) {
		if (0 < lvalue && (lvalue < physmem || physmem == 0)) {
			physmem = (pgcnt_t)lvalue;
			DBG(physmem);
		}
	}

	/*
	 * Check for bootrd_debug.
	 */
	if (find_boot_prop("bootrd_debug"))
		bootrd_debug = 1;

	/*
	 * check to see if we have to override the default value of the console
	 */
	inputdev = line;
	v_len = do_bsys_getproplen(NULL, "input-device");
	if (v_len > 0)
		(void) do_bsys_getprop(NULL, "input-device", inputdev);
	else
		v_len = 0;
	inputdev[v_len] = 0;

	outputdev = inputdev + v_len + 1;
	v_len = do_bsys_getproplen(NULL, "output-device");
	if (v_len > 0)
		(void) do_bsys_getprop(NULL, "output-device", outputdev);
	else
		v_len = 0;
	outputdev[v_len] = 0;

	consoledev = outputdev + v_len + 1;
	v_len = do_bsys_getproplen(NULL, "console");
	if (v_len > 0) {
		(void) do_bsys_getprop(NULL, "console", consoledev);
		if (strcmp(consoledev, "graphics") == 0) {
			bsetprops("console", "text");
			v_len = strlen("text");
			bcopy("text", consoledev, v_len);
		}
	} else {
		v_len = 0;
	}
	consoledev[v_len] = 0;

	ASSERT3P(xbootp, !=, NULL);
	bcons_post_bootenvrc(xbootp, inputdev, outputdev, consoledev);

	if (find_boot_prop("prom_debug") || kbm_debug)
		boot_prop_display(line);
}

/*
 * print formatted output
 */
void
vbop_printf(void *ptr __unused, const char *fmt, va_list ap)
{
	(void) vsnprintf(buffer, BUFFERSIZE, fmt, ap);
	PUT_STRING(buffer);
}

void
bop_printf(void *bop, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vbop_printf(bop, fmt, ap);
	va_end(ap);
}


/*
 * Another panic() variant; this one can be used even earlier during boot than
 * prom_panic().
 */
void
bop_panic(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	bop_printf(NULL, fmt, ap);
	va_end(ap);

	bop_printf(NULL, "\nPress any key to reboot.\n");
	while (BSVC_ISCHAR(SYSP) == 0) {}
	bop_printf(NULL, "Resetting...\n");
	for (;;) {}	/* XXXARM: spin forever, for now */
}

#if defined(_USE_FDT)
static void
build_firmware_properties_fdt(const void *fdtp)
{
	int property;
	int node;

	node = fdt_subnode_offset(fdtp, 0, "chosen");
	if (node < 0)
		return;

	fdt_for_each_property_offset(property, fdtp, node) {
		const char *pn;
		const void *pv;
		int pl;

		pv = fdt_getprop_by_offset(fdtp, property, &pn, &pl);
		if (pv == NULL)
			continue;
		if (do_bsys_getproplen(NULL, pn) >= 0)
			continue;

		if (strcmp(pn, "phandle") == 0 ||
		    strcmp(pn, "impl-arch-name") == 0 ||
		    strcmp(pn, "mfg-name") == 0) {
			continue;
		}

		if (pl == 0) {
			bsetprop(DDI_PROP_TYPE_ANY, (char *)pn, strlen(pn),
			    NULL, 0);
		} else if (strcmp((char *)pn, "display-edif-block") == 0 ||
		    strcmp((char *)pn, "kaslr-seed") == 0 ||
		    strcmp((char *)pn, "rng-seed") == 0) {
			bsetprop(DDI_PROP_TYPE_BYTE, (char *)pn, strlen(pn),
			    (void *)pv, pl);
		} else {
			bsetprop(DDI_PROP_TYPE_STRING, (char *)pn, strlen(pn),
			    (void *)pv, pl);
		}
	}
}
#endif

/*
 * Populate properties from firmware values.
 */
static void
build_firmware_properties(struct xboot_info *xbp __maybe_unused)
{
	if (xbp->bi_uefi_systab == 0)
		prom_panic("illumos/aarch64 requires UEFI\n");
	bsetprop64("efi-systab", xbp->bi_uefi_systab);

	if (xbp->bi_smbios != 0)
		bsetprop64("smbios-address", xbp->bi_smbios);

	if (xbp->bi_pcierc_cnt != 0)
		bsetprop32("num-known-pcierc", xbp->bi_pcierc_cnt);

#if defined(_USE_FDT)
	if (xbp->bi_fdt != 0) {
		const void *fdtp = (void *)xbp->bi_fdt;

		if (fdt_check_header(fdtp) == 0) {
			build_firmware_properties_fdt(fdtp);
		}
	}
#endif
}

/*
 * fake up a boot property for deferred early console output
 * this is used by both graphical boot and the (developer only)
 * USB serial console
 */
void *
defcons_init(size_t size)
{
	static char *p = NULL;

	p = do_bsys_alloc(NULL, NULL, size, MMU_PAGESIZE);
	*p = 0;
	bsetprop64("deferred-console-buf", (uint64_t)((uintptr_t)&p));
	return (p);
}

/*
 * Import boot environment module variables as properties, applying
 * blocklist filter for variables we know we will not use.
 *
 * Since the environment can be relatively large, containing many variables
 * used only for boot loader purposes, we will use a blocklist based filter.
 * To keep the blocklist from growing too large, we use prefix based filtering.
 * This is possible because in many cases, the loader variable names are
 * using a structured layout.
 *
 * We will not overwrite already set properties.
 *
 * Note that the menu items in particular can contain characters not
 * well-handled as bootparams, such as spaces, brackets, and the like, so that's
 * another reason.
 */
static struct bop_blocklist {
	const char *bl_name;
	int bl_name_len;
} bop_prop_blocklist[] = {
	{ "ISADIR", sizeof ("ISADIR") },
	{ "acpi", sizeof ("acpi") },
	{ "autoboot_delay", sizeof ("autoboot_delay") },
	{ "beansi_", sizeof ("beansi_") },
	{ "beastie", sizeof ("beastie") },
	{ "bemenu", sizeof ("bemenu") },
	{ "boot.", sizeof ("boot.") },
	{ "bootenv", sizeof ("bootenv") },
	{ "currdev", sizeof ("currdev") },
	{ "dhcp.", sizeof ("dhcp.") },
	{ "interpret", sizeof ("interpret") },
	{ "kernel", sizeof ("kernel") },
	{ "loaddev", sizeof ("loaddev") },
	{ "loader_", sizeof ("loader_") },
	{ "mainansi_", sizeof ("mainansi_") },
	{ "mainmenu_", sizeof ("mainmenu_") },
	{ "maintoggled_", sizeof ("maintoggled_") },
	{ "menu_timeout_command", sizeof ("menu_timeout_command") },
	{ "menuset_", sizeof ("menuset_") },
	{ "module_path", sizeof ("module_path") },
	{ "nfs.", sizeof ("nfs.") },
	{ "optionsansi_", sizeof ("optionsansi_") },
	{ "optionsmenu_", sizeof ("optionsmenu_") },
	{ "optionstoggled_", sizeof ("optionstoggled_") },
	{ "pcibios", sizeof ("pcibios") },
	{ "prompt", sizeof ("prompt") },
	{ "smbios", sizeof ("smbios") },
	{ "tem", sizeof ("tem") },
	{ "twiddle_divisor", sizeof ("twiddle_divisor") },
	{ "zfs_be", sizeof ("zfs_be") },
};

/*
 * Match the name against prefixes in above blocklist. If the match was
 * found, this name is blocklisted.
 */
static boolean_t
name_is_blocklisted(const char *name)
{
	int i, n;

	n = sizeof (bop_prop_blocklist) / sizeof (bop_prop_blocklist[0]);
	for (i = 0; i < n; i++) {
		if (strncmp(bop_prop_blocklist[i].bl_name, name,
		    bop_prop_blocklist[i].bl_name_len - 1) == 0) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static void
process_boot_environment(struct boot_modules *benv, char *space)
{
	char *env, *ptr, *name, *value;
	uint32_t size, name_len, value_len;

	if (benv == NULL || benv->bm_type != BMT_ENV)
		return;

	ptr = env = (char *)benv->bm_addr;
	size = benv->bm_size;
	do {
		name = ptr;
		/* find '=' */
		while (*ptr != '=') {
			ptr++;
			if (ptr > env + size) /* Something is very wrong. */
				return;
		}
		name_len = ptr - name;
		if (sizeof (buffer) <= name_len)
			continue;

		(void) strncpy(buffer, name, sizeof (buffer));
		buffer[name_len] = '\0';
		name = buffer;

		value_len = 0;
		value = ++ptr;
		while ((uintptr_t)ptr - (uintptr_t)env < size) {
			if (*ptr == '\0') {
				ptr++;
				value_len = (uintptr_t)ptr - (uintptr_t)env;
				break;
			}
			ptr++;
		}

		/* Did we reach the end of the module? */
		if (value_len == 0)
			return;

		if (*value == '\0')
			continue;

		/* Is this property already set? */
		if (do_bsys_getproplen(NULL, name) >= 0)
			continue;

		if (strcmp(name, "smbios.system.maker") == 0) {
			bsetprops("smbios.system.maker", value);
			continue;
		}

		/* Translate netboot variables */
		if (strcmp(name, "boot.netif.gateway") == 0) {
			bsetprops(BP_ROUTER_IP, value);
			continue;
		}
		if (strcmp(name, "boot.netif.hwaddr") == 0) {
			bsetprops(BP_BOOT_MAC, value);
			continue;
		}
		if (strcmp(name, "boot.netif.ip") == 0) {
			bsetprops(BP_HOST_IP, value);
			continue;
		}
		if (strcmp(name, "boot.netif.netmask") == 0) {
			bsetprops(BP_SUBNET_MASK, value);
			continue;
		}
		if (strcmp(name, "boot.netif.server") == 0) {
			bsetprops(BP_SERVER_IP, value);
			continue;
		}
		if (strcmp(name, "boot.netif.server") == 0) {
			if (do_bsys_getproplen(NULL, BP_SERVER_IP) < 0)
				bsetprops(BP_SERVER_IP, value);
			continue;
		}
		if (strcmp(name, "boot.nfsroot.server") == 0) {
			if (do_bsys_getproplen(NULL, BP_SERVER_IP) < 0)
				bsetprops(BP_SERVER_IP, value);
			continue;
		}
		if (strcmp(name, "boot.nfsroot.path") == 0) {
			bsetprops(BP_SERVER_PATH, value);
			continue;
		}
		if (strcmp(name, "bootp-response") == 0) {
			uint_t blen = (uint_t)value_len;
			if (hexascii_to_octet(
			    value, value_len, space, &blen) == 0)
				bsetprop(DDI_PROP_TYPE_BYTE,
				    name, name_len, space, blen);
			continue;
		}

		/*
		 * The loader allows multiple console devices to be specified
		 * as a comma-separated list, but the kernel does not yet
		 * support multiple console devices.  If a list is provided,
		 * ignore all but the first entry:
		 */
		if (strcmp(name, "console") == 0) {
			char propval[BP_MAX_STRLEN];

			for (uint32_t i = 0; i < BP_MAX_STRLEN; i++) {
				propval[i] = value[i];
				if (value[i] == ' ' ||
				    value[i] == ',' ||
				    value[i] == '\0') {
					propval[i] = '\0';
					break;
				}

				if (i + 1 == BP_MAX_STRLEN)
					propval[i] = '\0';
			}
			bsetprops(name, propval);
			continue;
		}
		if (name_is_blocklisted(name) == B_TRUE)
			continue;

		/* Create new property. */
		bsetprops(name, value);

		/* Avoid reading past the module end. */
		if (size <= (uintptr_t)ptr - (uintptr_t)env)
			return;
	} while (*ptr != '\0');
}

/*
 * First pass at building the table of boot properties. This includes:
 * - values set on the command line: -B a=x,b=y,c=z ....
 * - known values we just compute (ie. from xbp)
 * - values from /boot/solaris/bootenv.rc (ie. eeprom(8) values)
 *
 * the command-line looked like:
 * kernel boot-file [-B prop=value[,prop=value]...] [boot-args]
 *
 * whoami is the same as boot-file
 */
static void
build_boot_properties(struct xboot_info *xbp)
{
	char *name;
	int name_len;
	char *value;
	int value_len;
	struct boot_modules *bm, *rdbm, *benv = NULL;
	char *propbuf;
	int quoted = 0;
	int boot_arg_len;
	uint_t i, midx;
	char modid[32];
	static int stdout_val = 0;
	uchar_t boot_device;
	char str[3];

	/*
	 * These have to be done first, so that kobj_mount_root() works
	 */
	DBG_MSG("Building boot properties\n");
	propbuf = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, 0);
	DBG((uintptr_t)propbuf);
	if (xbp->bi_module_cnt > 0) {
		bm = (struct boot_modules *)xbp->bi_modules;
		rdbm = NULL;
		for (midx = i = 0; i < xbp->bi_module_cnt; i++) {
			if (bm[i].bm_type == BMT_ROOTFS) {
				rdbm = &bm[i];
				continue;
			}
			if (bm[i].bm_type == BMT_HASH ||
			    bm[i].bm_type == BMT_FONT ||
			    (char *)bm[i].bm_name == NULL)
				continue;

			if (bm[i].bm_type == BMT_ENV) {
				if (benv == NULL)
					benv = &bm[i];
				else
					continue;
			}

			(void) snprintf(modid, sizeof (modid),
			    "module-name-%u", midx);
			bsetprops(modid, (char *)bm[i].bm_name);
			(void) snprintf(modid, sizeof (modid),
			    "module-addr-%u", midx);
			bsetprop64(modid, (uint64_t)(uintptr_t)bm[i].bm_addr);
			(void) snprintf(modid, sizeof (modid),
			    "module-size-%u", midx);
			bsetprop64(modid, (uint64_t)bm[i].bm_size);
			++midx;
		}
		if (rdbm != NULL) {
			bsetprop64("ramdisk_start",
			    (uint64_t)(uintptr_t)rdbm->bm_addr);
			bsetprop64("ramdisk_end",
			    (uint64_t)(uintptr_t)rdbm->bm_addr + rdbm->bm_size);
		}
	}

	DBG_MSG("Parsing command line for boot properties\n");
	value = (char *)xbp->bi_cmdline;

	/*
	 * allocate memory to collect boot_args into
	 */
	boot_arg_len = strlen((char *)xbp->bi_cmdline) + 1;
	boot_args = do_bsys_alloc(NULL, NULL, boot_arg_len, MMU_PAGESIZE);
	boot_args[0] = 0;
	boot_arg_len = 0;

	while (ISSPACE(*value))
		++value;
	/*
	 * value now points at the boot-file
	 */
	value_len = 0;
	while (value[value_len] && !ISSPACE(value[value_len]))
		++value_len;
	if (value_len > 0) {
		whoami = propbuf;
		bcopy(value, whoami, value_len);
		whoami[value_len] = 0;
		bsetprops("boot-file", whoami);
		/*
		 * strip leading path stuff from whoami, so running from
		 * PXE/miniroot makes sense.
		 */
		if (strstr(whoami, "/platform/") != NULL)
			whoami = strstr(whoami, "/platform/");
		bsetprops("whoami", whoami);
	}

	/*
	 * Values forcibly set boot properties on the command line via -B.
	 * Allow use of quotes in values. Other stuff goes on kernel
	 * command line.
	 */
	name = value + value_len;
	while (*name != 0) {
		/*
		 * anything not " -B" is copied to the command line
		 */
		if (!ISSPACE(name[0]) || name[1] != '-' || name[2] != 'B') {
			boot_args[boot_arg_len++] = *name;
			boot_args[boot_arg_len] = 0;
			++name;
			continue;
		}

		/*
		 * skip the " -B" and following white space
		 */
		name += 3;
		while (ISSPACE(*name))
			++name;
		while (*name && !ISSPACE(*name)) {
			value = strstr(name, "=");
			if (value == NULL)
				break;
			name_len = value - name;
			++value;
			value_len = 0;
			quoted = 0;
			for (; ; ++value_len) {
				if (!value[value_len])
					break;

				/*
				 * is this value quoted?
				 */
				if (value_len == 0 &&
				    (value[0] == '\'' || value[0] == '"')) {
					quoted = value[0];
					++value_len;
				}

				/*
				 * In the quote accept any character,
				 * but look for ending quote.
				 */
				if (quoted) {
					if (value[value_len] == quoted)
						quoted = 0;
					continue;
				}

				/*
				 * a comma or white space ends the value
				 */
				if (value[value_len] == ',' ||
				    ISSPACE(value[value_len]))
					break;
			}

			if (value_len == 0) {
				bsetprop(DDI_PROP_TYPE_ANY, name, name_len,
				    NULL, 0);
			} else {
				char *v = value;
				int l = value_len;
				if (v[0] == v[l - 1] &&
				    (v[0] == '\'' || v[0] == '"')) {
					++v;
					l -= 2;
				}
				bcopy(v, propbuf, l);
				propbuf[l] = '\0';
				bsetprop(DDI_PROP_TYPE_STRING, name, name_len,
				    propbuf, l + 1);
			}
			name = value + value_len;
			while (*name == ',')
				++name;
		}
	}

	/*
	 * set boot-args property
	 * 1275 name is bootargs, so set
	 * that too
	 */
	bsetprops("boot-args", boot_args);
	bsetprops("bootargs", boot_args);

	process_boot_environment(benv, propbuf);

	bsetprop32("stdout", stdout_val);	/* where does this get set? */

	/*
	 * Build firmware-provided system properties
	 */
	build_firmware_properties(xbp);

	/*
	 * Unless provided by other means, set the default mfg-name,
	 * preferring the SMBIOS system maker if present.
	 */
	if (do_bsys_getproplen(NULL, "mfg-name") == -1) {
		int plen;

		if ((plen = do_bsys_getproplen(NULL,
		    "smbios.system.maker")) > 0 &&
		    do_bsys_getprop(NULL, "smbios.system.maker",
		    propbuf) == 0) {
			propbuf[plen] = '\0';
			/*
			 * This value is massaged prior to being used to name
			 * the DDI root node, so no need to massage it here.
			 */
			bsetprops("mfg-name", propbuf);
		} else {
			bsetprops("mfg-name", "Unknown");
		}
	}
}

#define	IN_RANGE(a, b, e) ((a) >= (b) && (a) <= (e))
static memlist_t *boot_free_memlist = NULL;


static memlist_t *
bmemlist_alloc()
{
	memlist_t *ptr;
	if (boot_free_memlist == 0) {
		bop_panic("bmemlist_alloc Out of memory\n");
	}
	ptr = boot_free_memlist;
	boot_free_memlist = ptr->ml_next;
	ptr->ml_address = 0;
	ptr->ml_size = 0;
	ptr->ml_prev = 0;
	ptr->ml_next = 0;
	return (ptr);
}

static void
bmemlist_free(memlist_t *ptr)
{
	ptr->ml_address = 0;
	ptr->ml_size = 0;
	ptr->ml_prev = 0;
	ptr->ml_next = boot_free_memlist;

	boot_free_memlist = ptr;
}

static struct memlist *
bmemlist_dup(struct memlist *listp)
{
	struct memlist *head = 0, *prev = 0;

	while (listp) {
		struct memlist *entry = bmemlist_alloc();
		entry->ml_address = listp->ml_address;
		entry->ml_size = listp->ml_size;
		entry->ml_next = 0;
		if (prev)
			prev->ml_next = entry;
		else
			head = entry;
		prev = entry;
		listp = listp->ml_next;
	}

	return (head);
}

static void
bmemlist_insert(struct memlist **listp, uint64_t addr, uint64_t size)
{
	int merge_left, merge_right;
	struct memlist *entry;
	struct memlist *prev = 0, *next;

	/* find the location in list */
	next = *listp;
	while (next && next->ml_address <= addr) {
		/*
		 * Drop if this entry already exists, in whole
		 * or in part
		 */
		if (next->ml_address <= addr &&
		    next->ml_address + next->ml_size >= addr + size) {
			/* next already contains this entire element; drop */
			return;
		}

		/* Is this a "grow block size" request? */
		if (next->ml_address == addr) {
			break;
		}
		prev = next;
		next = prev->ml_next;
	}

	merge_left = (prev && addr == prev->ml_address + prev->ml_size);
	merge_right = (next && addr + size == next->ml_address);
	if (merge_left && merge_right) {
		prev->ml_size += size + next->ml_size;
		prev->ml_next = next->ml_next;
		bmemlist_free(next);
		return;
	}

	if (merge_left) {
		prev->ml_size += size;
		return;
	}

	if (merge_right) {
		next->ml_address = addr;
		next->ml_size += size;
		return;
	}

	entry = bmemlist_alloc();
	entry->ml_address = addr;
	entry->ml_size = size;
	if (prev == 0) {
		entry->ml_next = *listp;
		*listp = entry;
	} else {
		entry->ml_next = next;
		prev->ml_next = entry;
	}
}

static void
bmemlist_remove(struct memlist **listp, uint64_t addr, uint64_t size)
{
	struct memlist *prev = 0;
	struct memlist *chunk;
	uint64_t rem_begin, rem_end;
	uint64_t chunk_begin, chunk_end;
	int begin_in_chunk, end_in_chunk;

	/* ignore removal of zero-length item */
	if (size == 0)
		return;

	/* also inherently ignore a zero-length list */
	rem_begin = addr;
	rem_end = addr + size - 1;
	chunk = *listp;
	while (chunk) {
		chunk_begin = chunk->ml_address;
		chunk_end = chunk->ml_address + chunk->ml_size - 1;
		begin_in_chunk = IN_RANGE(rem_begin, chunk_begin, chunk_end);
		end_in_chunk = IN_RANGE(rem_end, chunk_begin, chunk_end);

		if (rem_begin <= chunk_begin && rem_end >= chunk_end) {
			struct memlist *delete_chunk;

			/* spans entire chunk - delete chunk */
			delete_chunk = chunk;
			if (prev == 0)
				chunk = *listp = chunk->ml_next;
			else
				chunk = prev->ml_next = chunk->ml_next;

			bmemlist_free(delete_chunk);
			/* skip to start of while-loop */
			continue;
		} else if (begin_in_chunk && end_in_chunk &&
		    chunk_begin != rem_begin && chunk_end != rem_end) {
			struct memlist *new;
			/* split chunk */
			new = bmemlist_alloc();
			new->ml_address = rem_end + 1;
			new->ml_size = chunk_end - new->ml_address + 1;
			chunk->ml_size = rem_begin - chunk_begin;
			new->ml_next = chunk->ml_next;
			chunk->ml_next = new;
			/* done - break out of while-loop */
			break;
		} else if (begin_in_chunk || end_in_chunk) {
			/* trim chunk */
			chunk->ml_size -= MIN(chunk_end, rem_end) -
			    MAX(chunk_begin, rem_begin) + 1;
			if (rem_begin <= chunk_begin) {
				chunk->ml_address = rem_end + 1;
				break;
			}
			/* fall-through to next chunk */
		}
		prev = chunk;
		chunk = chunk->ml_next;
	}
}

static uint64_t
bmemlist_find(struct memlist **listp, uint64_t size, int align)
{
	uint64_t delta, total_size;
	uint64_t paddr;
	struct memlist *prev = 0, *next;

	/* find the chunk with sufficient size */
	next = *listp;
	while (next) {
		delta = next->ml_address & ((align != 0) ? (align - 1) : 0);
		if (delta != 0)
			total_size = size + align - delta;
		else
			total_size = size; /* the addr is already aligned */
		if (next->ml_size >= total_size)
			break;
		prev = next;
		next = prev->ml_next;
	}

	if (next == 0)
		return (0);	/* Not found */

	paddr = next->ml_address;
	if (delta)
		paddr += align - delta;
	(void) bmemlist_remove(listp, paddr, size);

	return (paddr);
}

static void
bmemlist_init(struct xboot_info *xbp)
{
	static memlist_t boot_list[MMU_PAGESIZE * 8 /sizeof (memlist_t)];
	int i;
	extern struct memlist *phys_install;
	extern struct memlist *phys_avail;
	extern struct memlist *boot_scratch;

	for (i = 0; i < sizeof (boot_list) / sizeof (boot_list[0]); i++) {
		bmemlist_free(&boot_list[i]);
	}
	memlist_t *ml;

	ml = (memlist_t *)xbp->bi_phys_avail;
	phys_avail = bmemlist_dup(ml);

	ml = (memlist_t *)xbp->bi_phys_installed;
	phys_install = bmemlist_dup(ml);

	ml = (memlist_t *)xbp->bi_boot_scratch;
	boot_scratch = bmemlist_dup(ml);

	bmemlist_insert(&bootmem_avail, MISC_VA_BASE, MISC_VA_SIZE);
}
