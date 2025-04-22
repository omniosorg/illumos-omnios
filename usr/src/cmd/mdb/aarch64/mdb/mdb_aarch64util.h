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

/* Copyright 2022 Richard Lowe */

#ifndef _MDB_AARCH64UTIL_H
#define	_MDB_AARCH64UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mdb/mdb_kreg.h>
#include <mdb/mdb_target_impl.h>

typedef uint32_t mdb_instr_t;

extern const mdb_tgt_regdesc_t mdb_aarch64_kregs[];

int mdb_aarch64_next(mdb_tgt_t *, uintptr_t *, kreg_t, mdb_instr_t);

extern int mdb_aarch64_kvm_stack_iter(mdb_tgt_t *, const mdb_tgt_gregset_t *,
    mdb_tgt_stack_f *, void *);
extern int mdb_aarch64_kvm_frame(void *, uintptr_t, uint_t, const long *,
    const mdb_tgt_gregset_t *);
extern boolean_t mdb_aarch64_prev_callcheck(uintptr_t);

#ifdef __cplusplus
}
#endif

#endif /* _MDB_AARCH64UTIL_H */
