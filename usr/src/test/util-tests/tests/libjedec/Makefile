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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2025 Oxide Computer Company
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/

PROGS = libjedec_vendors libjedec_temp libjedec_spd
$(BUILD32)PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTPROGS = $(PROGS32:%=$(TESTDIR)/32/%) \
	$(PROGS64:%=$(TESTDIR)/64/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

SUBDIRS = hex2spd

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

LDLIBS += -ljedec
LDLIBS64 += -ljedec

libjedec_spd.32		:= LDLIBS += -lnvpair
libjedec_spd.64		:= LDLIBS64 += -lnvpair

CSTD = $(CSTD_GNU17)

#
# recursive support
#
all     :=      TARGET = all
install :=      TARGET = install
clean   :=      TARGET = clean
clobber :=      TARGET = clobber

$(SUBDIRS): FRC
	cd $@; pwd; $(MAKE) $(TARGET)

all: $(PROGS32) $(PROGS64) $(SUBDIRS)

$(ROOTOPTPROGS): all

install: all $(ROOTOPTPROGS) $(SUBDIRS)

clobber: clean $(SUBDIRS)
	-$(RM) $(PROGS32) $(PGROGS64)

clean: $(SUBDIRS)

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

FRC:
