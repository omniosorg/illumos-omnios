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
# Copyright 2025 Bill Sommerfeld
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG64 =	idmaptest.64
$(BUILD32)PROG32 += idmaptest.32

PROG = $(PROG64) $(PROG32)

SCRIPTS = idmap_init idmap_fini

LDLIBS += -lidmap
LDLIBS64 += -lidmap

CSTD = $(CSTD_GNU17)

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/idmap

CMDS = $(PROG32:%=$(TESTDIR)/32/%) $(PROG64:%=$(TESTDIR)/64/%) \
	$(SCRIPTS:%=$(TESTDIR)/%)
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

$(TESTDIR)/%: %.ksh
	$(INS.rename)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)
