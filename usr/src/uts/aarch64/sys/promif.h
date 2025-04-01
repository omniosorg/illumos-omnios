/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2025 Michael van der Westhuizen
 */

#ifndef _SYS_PROMIF_H
#define	_SYS_PROMIF_H

#include <sys/types.h>
#include <sys/obpdefs.h>

#if defined(_KERNEL) || defined(_KMDB)
#include <sys/va_list.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *  These are for V0 ops only.  We sometimes have to specify
 *  to promif which type of operation we need to perform
 *  and since we can't get such a property from a V0 prom, we
 *  sometimes just assume it.  V2 and later proms do the right thing.
 */
#define	BLOCK	0
#define	NETWORK	1
#define	BYTE	2

#if defined(_KERNEL) || defined(_KMDB)

/*
 * Device tree and property group: OBP and IEEE 1275-1994.
 */
extern	pnode_t		prom_childnode(pnode_t nodeid);
extern	pnode_t		prom_parentnode(pnode_t nodeid);
extern	pnode_t		prom_nextnode(pnode_t nodeid);
extern	pnode_t		prom_optionsnode(void);
extern	pnode_t		prom_alias_node(void);
extern	pnode_t		prom_rootnode(void);
extern	int		prom_getproplen(pnode_t nodeid, const char *name);
extern	int		prom_getprop(pnode_t nodeid, const char *name,
    caddr_t value);
extern	char		*prom_nextprop(pnode_t nodeid, const char *previous,
    char *next);

extern	char		*prom_decode_composite_string(void *buf, size_t buflen,
    char *prev);
extern	pnode_t		prom_findnode_by_phandle(phandle_t phandle);

/*
 * Device tree and property group: IEEE 1275-1994 Only.
 */
extern	pnode_t		prom_finddevice(const char *path);

extern	int		prom_bounded_getprop(pnode_t nodeid, char *name,
    caddr_t buffer, int buflen);

/*
 * Device pathnames and pathname conversion: OBP and IEEE 1275-1994.
 */
extern	int		prom_devname_from_pathname(char *path, char *buffer);
extern	char		*prom_path_gettoken(char *from, char *to);

/*
 * Device pathnames and pathname conversion: IEEE 1275-1994 only.
 */

/*
 * Special device nodes: OBP and IEEE 1275-1994.
 */
extern	int		prom_stdin_is_keyboard(void);
extern	int		prom_stdout_is_framebuffer(void);
extern	void		prom_framebuffer_getpos(int *row, int *col);
extern	void		prom_framebuffer_getcolors(int *fg, int *bg);
extern	char		*prom_stdinpath(void);
extern	char		*prom_stdoutpath(void);
extern	void		prom_strip_options(char *from, char *to);
extern	void		prom_pathname(char *);

/*
 * Special device nodes: IEEE 1275-1994 only.
 */

/*
 * Administrative group: OBP and IEEE 1275-1994.
 */
extern	void		prom_enter_mon(void);
extern	void		prom_exit_to_mon(void) __NORETURN;
extern	void		prom_reboot(char *bootstr) __NORETURN;
extern	void		prom_reset(void) __NORETURN;
extern	void		prom_panic(char *string) __NORETURN;

extern	int		prom_is_openprom(void);
extern	int		prom_is_p1275(void);
extern	int		prom_version_name(char *buf, int buflen);
extern	int		prom_version_boot_syscalls(void);

extern	uint_t		prom_gettime(void);

extern	char		*prom_bootpath(void);
extern	char		*prom_bootargs(void);

/*
 * Administrative group: OBP only.
 */

/*
 * Administrative group: IEEE 1275-1994 only.
 */
extern pnode_t prom_chosennode(void);
/*
 * Administrative group: IEEE 1275 only.
 */

/*
 * Promif support group: Generic.
 */
extern	void		prom_init(char *progname, void *prom_cookie);
extern	void		prom_node_init(void);

typedef uint_t		prom_generation_cookie_t;

extern void prom_fixup(uintptr_t, uintptr_t);
extern	ihandle_t	prom_stdin_ihandle(void);
extern	ihandle_t	prom_stdout_ihandle(void);

#define	prom_tree_access(CALLBACK, ARG, GENP) (CALLBACK)((ARG), 0)

/*
 * I/O Group: OBP and IEEE 1275.
 */
extern	uchar_t	prom_getchar(void);
extern	void	prom_putchar(char c);
extern	int	prom_mayget(void);
extern	int	prom_mayput(char c);
extern	int	prom_open(char *name);
extern	int	prom_close(int fd);
extern	ssize_t	prom_read(ihandle_t fd, caddr_t buf, size_t len,
    uint_t startblk, char type);
extern  ssize_t	prom_write(ihandle_t fd, caddr_t buf, size_t len,
    uint_t startblk, char type);
extern	int	prom_seek(int fd, u_longlong_t offset);
extern	void	prom_writestr(const char *buf, size_t bufsize);
extern	void	prom_pnode_to_pathname(pnode_t, char *);
extern	void	prom_printf(const char *fmt, ...);
extern	void	prom_vprintf(const char *fmt, __va_list adx);
extern	char	*prom_sprintf(char *s, const char *fmt, ...);
extern	char	*prom_vsprintf(char *s, const char *fmt, __va_list adx);


/*
 * promif tree searching routines ... OBP and IEEE 1275-1994.
 */

extern	pnode_t		prom_findnode_byname(pnode_t id, char *name);
extern	char		*prom_get_extend_name(void);

extern	int		prom_devreset(int);
extern	int		OpenCount;
extern struct ihandle	*open_devices[];

#define	PROM_STOP	{	\
	prom_printf("File %s line %d\n", __FILE__, __LINE__); \
	prom_enter_mon();	\
}

/*
 * file IO
 */
extern	int		prom_fopen(ihandle_t, char *);
extern	int		prom_volopen(ihandle_t, char *);
extern	int		prom_fseek(ihandle_t, int, unsigned long long);
extern	int		prom_fread(ihandle_t, int, caddr_t, size_t);
extern	int		prom_fsize(ihandle_t, int, size_t *);
extern	int		prom_compinfo(ihandle_t, int, int *,
			    size_t *, size_t *);
extern	void		prom_fclose(ihandle_t, int);

#endif /* _KERNEL || _KMDB */

#ifdef _KERNEL

/*
 * Used by wrappers which bring up console frame buffer before prom_printf()
 * and other prom calls that may output to the console.  Struct is filled in
 * in prom_env.c and in sunpm.c
 */

typedef struct promif_owrap {
	void (*preout)(void);
	void (*postout)(void);
} promif_owrap_t;

extern	void		prom_suspend_prepost(void);
extern	void		prom_resume_prepost(void);

/*
 * WAN boot key storage interface
 */
int prom_set_security_key(char *keyname, caddr_t buf, int buflen, int *reslen,
    int *status);
int prom_get_security_key(char *keyname, caddr_t buf, int buflen, int *keylen,
    int *status);

struct prom_hwreset {
	pnode_t node;
	uint32_t id;
};

struct prom_hwclock {
	pnode_t node;
	uint32_t id;
};

struct prom_compat {
	char *compatible;
	void (*init)(pnode_t node);
};

extern int prom_get_reg(pnode_t node, int index, uint64_t *base);
extern int prom_get_clock_by_name(pnode_t node, const char *name,
    struct prom_hwclock *clock);
extern void prom_driver_register(const struct prom_compat *data);
extern boolean_t prom_is_compatible(pnode_t node, const char *name);
extern pnode_t prom_find_compatible(pnode_t node, const char *compatible);
extern void prom_walk(void(*func)(pnode_t, void*), void *arg);
extern int prom_get_reg_address(pnode_t node, int index, uint64_t *reg);
extern int prom_get_reg_size(pnode_t node, int index, uint64_t *regsize);
extern void prom_power_off(void);
extern int prom_get_bus_address(pnode_t node, uint64_t phys_addr,
    uint64_t *bus_addr);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROMIF_H */
