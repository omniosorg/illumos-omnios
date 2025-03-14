#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2024 RackTop Systems, Inc.
#

MODULE = libfksmbfs.so
MDBTGT = proc

MODSRCS = smbfs.c avl.c

include ../../../../Makefile.cmd
include ../../Makefile.ia32
include ../../../Makefile.module

MODSRCS_DIR = ../../../common/modules/smbfs
GENUNIX_DIR = ../../../common/modules/genunix

# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
CPPFLAGS.first += -I$(SRC)/lib/smbclnt/libfksmbfs/common
CPPFLAGS.first += -I$(SRC)/lib/smbclnt/libfknsmb/common
CPPFLAGS.first += -I$(SRC)/lib/libfakekernel/common

CPPFLAGS += -I$(SRC)/uts/common/fs/smbclnt/
CPPFLAGS += -I$(SRC)/uts/common
# Note: -D_FAKE_KERNEL is in mdb:smbfs.c

CSTD=		$(CSTD_GNU99)

dmod/%.o: $(GENUNIX_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

dmod/%.ln: $(GENUNIX_DIR)/%.c
	$(LINT.c) -c $<
