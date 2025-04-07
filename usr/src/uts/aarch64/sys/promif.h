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
extern	pnode_t		prom_nextnode(pnode_t nodeid);
extern	pnode_t		prom_optionsnode(void);
extern	pnode_t		prom_alias_node(void);
extern	pnode_t		prom_rootnode(void);
extern	int		prom_getproplen(pnode_t nodeid, caddr_t name);
extern	int		prom_getprop(pnode_t nodeid, caddr_t name,
    caddr_t value);
extern	char		*prom_nextprop(pnode_t nodeid, caddr_t previous,
    caddr_t next);

extern	char		*prom_decode_composite_string(void *buf, size_t buflen,
    char *prev);

/*
 * Device tree and property group: IEEE 1275-1994 Only.
 */
extern	pnode_t		prom_finddevice(char *path);

extern	int		prom_bounded_getprop(pnode_t nodeid, caddr_t name,
    caddr_t buffer, int buflen);

/*
 * Special device nodes: OBP and IEEE 1275-1994.
 */
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
extern	void		prom_panic(char *string) __NORETURN;

extern	int		prom_is_openprom(void);
extern	int		prom_version_name(char *buf, int buflen);

/*
 * Administrative group: IEEE 1275-1994 only.
 */
extern pnode_t prom_chosennode(void);

/*
 * Promif support group: Generic.
 */
extern	void		prom_init(char *progname, void *prom_cookie);

typedef uint_t		prom_generation_cookie_t;

#define	prom_tree_access(CALLBACK, ARG, GENP) (CALLBACK)((ARG), 0)

/*
 * I/O Group: OBP and IEEE 1275.
 */
extern	uchar_t	prom_getchar(void);
extern	void	prom_putchar(char c);
extern	int	prom_mayget(void);
extern	int	prom_mayput(char c);
extern	void	prom_writestr(const char *buf, size_t bufsize);
extern	void	prom_printf(const char *fmt, ...);
extern	void	prom_vprintf(const char *fmt, __va_list adx);
extern	char	*prom_sprintf(char *s, const char *fmt, ...);
extern	char	*prom_vsprintf(char *s, const char *fmt, __va_list adx);

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

extern void prom_power_off(void);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROMIF_H */
