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
# Copyright 2016 Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROGS = \
	runtests \
	acquire-lock

CSTD = $(CSTD_GNU99)

$(BUILD32)PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests/file-locking
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTDIR)/32/%) \
	$(PROGS64:%=$(ROOTOPTDIR)/64/%)

.KEEP_STATE:

install: $(ROOTOPTPROGS)

all: $(PROGS32) $(PROGS64)

clean:
	-rm $(PROGS32) $(PROGS64)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/32:
	$(INS.dir)

$(ROOTOPTDIR)/64:
	$(INS.dir)

$(ROOTOPTDIR)/32/%: % $(ROOTOPTDIR)/32
	$(INS.file)

$(ROOTOPTDIR)/64/%: % $(ROOTOPTDIR)/64
	$(INS.file)

$(ROOTOPTDIR)/%: %
	$(INS.file)

$(ROOTOPTDIR)/%: %.ksh
	$(INS.rename)

%.64.o: %.c
	$(COMPILE64.c) $< -o $@

%.32.o: %.c
	$(COMPILE.c) $< -o $@

%.64: %.64.o util.64.o
	$(LINK64.c) -o $@ $< util.64.o $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.32.o util.32.o
	$(LINK.c) -o $@ $< util.32.o $(LDLIBS)
	$(POST_PROCESS)

clobber:
	$(RM) $(PROGS32) $(PROGS64)

FRC:
