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
 * Copyright 2026 Richard Lowe
 */

#ifndef _HTABLE_H
#define	_HTABLE_H

#ifdef __cplusplus
extern "C" {
#endif

extern int htables_walk_init(mdb_walk_state_t *);
extern int htables_walk_step(mdb_walk_state_t *);
extern void htables_walk_fini(mdb_walk_state_t *);

#ifdef __cplusplus
}
#endif

#endif /* _HTABLE_H */
