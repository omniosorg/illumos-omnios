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
# Copyright 2026 Oxide Computer Company
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests

SRCS = libdhcputil.c
PROG = libdhcputil

PROG32 = $(PROG:%=%.32)
PROG64 = $(PROG:%=%.64)

OBJS32 = $(SRCS:%.c=%.32.o)
OBJS64 = $(SRCS:%.c=%.64.o)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf
include $(SRC)/test/Makefile.com

CMDS = $(PROG32:%=$(TESTDIR)/%) $(PROG64:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

CSTD = $(CSTD_GNU17)
CTF_MODE = link

LDLIBS += -ldhcputil
LDLIBS64 += -ldhcputil
CFLAGS += -_gcc=-Wall -_gcc=-Wextra
CFLAGS64 += -_gcc=-Wall -_gcc=-Wextra

all: $(PROG32) $(PROG64)

install: all $(CMDS)

clobber: clean
	-$(RM) $(PROG32) $(PROG64)

clean:
	-$(RM) $(OBJS32) $(OBJS64)

%.32.o: %.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE64.c) -o $@ -c $<
	$(POST_PROCESS_O)

$(PROG32): $(OBJS32)
	$(LINK.c) $(OBJS32) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(PROG64): $(OBJS64)
	$(LINK64.c) $(OBJS64) -o $@ $(LDLIBS64)
	$(POST_PROCESS)

$(CMDS): $(TESTDIR) $(PROG32) $(PROG64)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
