#! /usr/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2026 Richard Lowe
#

# Test that the address translation dcmds form a (sort of) identity:
#     patova(vatopa(X)) ⊇ X

error() {
	print -u2 "ERROR: $@"
	exit 1;
}

fail() {
	print -u2 "FAIL: $@"
	exit 1;
}

address_of() {
	sym=$1

	mdb -ke "${sym}=K" || error "could't get address of '${sym}'"
}

vatopa_patova() {
	sym=$1

	mdb -ke "${sym}::vatopa | ::patova" || error "couldn't vatopa patova '${sym}'"
}

# Buffer stdin to stdout through a 4kB buffer, this is because mdb fails if
# writes to stdout fail, which they will if a later command in the pipeline
# such as `grep -q` exits early (when it short circuits successfully)
buffer() {
	dd bs=4096 conv=block 2>/dev/null
}

check() {
	sym=$1
	addr=$(address_of $sym)

	(vatopa_patova "${sym}" | buffer | grep -q $addr) || fail "${sym} doesn't map back to ${addr}"
}

check sched

exit 0
