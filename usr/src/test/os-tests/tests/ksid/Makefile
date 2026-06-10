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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2017 Gordon W. Ross
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2020 Tintri by DDN, Inc. All rights reserved.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG64 =	ksid.64
$(BUILD32)PROG32 += ksid.32

PROG= $(PROG64) $(PROG32)

LDLIBS += -lfakekernel
LDLIBS64 += -lfakekernel

CSTD = $(CSTD_GNU99)
CPPFLAGS.first += -I$(SRC)/lib/libfakekernel/common -D_FAKE_KERNEL

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/ksid

CMDS = $(PROG32:%=$(TESTDIR)/32/%) $(PROG64:%=$(TESTDIR)/64/%)
$(CMDS) := FILEMODE = 0555

all: $(PROG)

install: $(CMDS)

clobber: clean
	-$(RM) $(PROG)

clean:

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/32:
	$(INS.dir)

$(TESTDIR)/64:
	$(INS.dir)

$(TESTDIR)/32/%: % $(TESTDIR)/32
	$(INS.file)

$(TESTDIR)/64/%: % $(TESTDIR)/64
	$(INS.file)

$(TESTDIR)/%: %
	$(INS.file)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)
