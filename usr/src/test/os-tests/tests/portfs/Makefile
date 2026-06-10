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
# Copyright 2025 Oxide Computer Company
#

include $(SRC)/Makefile.master

PROGS = \
	file_assoc

$(BUILD32)PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTPORTFS = $(ROOTOPTDIR)/portfs
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTPORTFS)/32/%) \
	$(PROGS64:%=$(ROOTOPTPORTFS)/64/%)

include $(SRC)/cmd/Makefile.cmd

CSTD=$(CSTD_GNU17)

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

clean:

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTPORTFS)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTPORTFS): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTPORTFS)/32: $(ROOTOPTPORTFS)
	$(INS.dir)

$(ROOTOPTPORTFS)/64: $(ROOTOPTPORTFS)
	$(INS.dir)

$(ROOTOPTPORTFS)/32/%: % $(ROOTOPTPORTFS)/32
	$(INS.file)

$(ROOTOPTPORTFS)/64/%: % $(ROOTOPTPORTFS)/64
	$(INS.file)

$(ROOTOPTPORTFS)/%: %
	$(INS.file)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

clobber:
	$(RM) $(PROGS32) $(PROGS64)

FRC:
