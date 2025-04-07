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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2025 Michael van der Westhuizen
 */

#ifndef	_SYS_PROM_EMUL_H
#define	_SYS_PROM_EMUL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following structure describes a property attached to a node
 * in the in-kernel copy of the PROM device tree.
 */
struct prom_prop {
	struct prom_prop *pp_next;
	char		 *pp_name;
	int		 pp_len;
	void		 *pp_val;
};

/*
 * The following structure describes a node in the in-kernel copy
 * of the PROM device tree.
 */
struct prom_node {
	pnode_t	pn_nodeid;
	struct prom_prop *pn_propp;
	struct prom_node *pn_child;
	struct prom_node *pn_sibling;
};

typedef struct prom_node prom_node_t;

/*
 * These are promif emulation functions, intended only for promif use
 */
extern void promif_init(char *pgmname, void *cookie);
extern void promif_setup(void);

extern pnode_t promif_finddevice(const char *device);
extern pnode_t promif_rootnode(void);
extern pnode_t promif_nextnode(pnode_t n);
extern pnode_t promif_childnode(pnode_t n);
extern pnode_t promif_optionsnode(void);
extern pnode_t promif_chosennode(void);

extern int promif_getproplen(pnode_t n, char *name);
extern int promif_getprop(pnode_t n,  char *name, void *value);
extern int promif_bounded_getprop(pnode_t, char *name, void *value, int len);
char *promif_nextprop(pnode_t n, char *previous, char *next);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PROM_EMUL_H */
