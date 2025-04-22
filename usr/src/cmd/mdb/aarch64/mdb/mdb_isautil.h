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
 * Copyright 2025 Richard Lowe
 */

#ifndef _MDB_ISAUTIL_H
#define	_MDB_ISAUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mdb/mdb_aarch64util.h>

typedef uint32_t mdb_instr_t;

#define	mdb_isa_kregs		mdb_aarch64_kregs

#define	mdb_isa_next		mdb_aarch64_next

#define	mdb_isa_kvm_stack_iter	mdb_aarch64_kvm_stack_iter

#define	mdb_isa_kvm_frame	mdb_aarch64_kvm_frame
#define	mdb_isa_prev_callcheck	mdb_aarch64_prev_callcheck

#ifdef __cplusplus
}
#endif

#endif /* _MDB_ISAUTIL_H */
