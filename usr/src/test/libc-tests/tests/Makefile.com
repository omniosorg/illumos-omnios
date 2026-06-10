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
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

$(OBJS_OVERRIDE)OBJS = $(PROG).o test_common.o
$(BUILD32)OBJS32 = $(OBJS:%.o=%.$(MACH).o)
$(BUILD32)PROG32 = $(PROG).$(MACH)

$(BUILD64)OBJS64 = $(OBJS:%.o=%.$(MACH64).o)
$(BUILD64)PROG64= $(PROG).$(MACH64)

$(OBJS_OVERRIDE)SRCS = $(PROG).c ../common/test_common.c

CSTD = $(CSTD_GNU99)
CPPFLAGS += -I$(ROOT)/usr/include -I../common

ROOTOPTPKG = $(ROOT)/opt/libc-tests
TESTDIR = $(ROOTOPTPKG)/tests/$(TESTSUBDIR)

CMDS = $(PROG32:%=$(TESTDIR)/32/%) $(PROG64:%=$(TESTDIR)/64/%) \
	$(KSHPROG:%=$(TESTDIR)/%) $(ARCHPROG:%=$(TESTDIR)/%) \
	$(EXTRAPROG:%=$(TESTDIR)/%)

$(CMDS) := FILEMODE = 0555

all: $(PROG32) $(PROG64) $(KSHPROG) $(ARCHPROG) $(SUBDIRS)

$(PROG32): $(OBJS32)
	$(LINK.c) $(OBJS32) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(PROG64): $(OBJS64)
	$(LINK64.c) $(OBJS64) -o $@ $(LDLIBS64)
	$(POST_PROCESS)

$(KSHPROG): $(KSHPROG).ksh
	$(RM) $@
	$(CP) $(KSHPROG).ksh $(@)
	$(CHMOD) +x $@

$(ARCHPROG): ../common/run_arch_tests.ksh
	$(RM) $@
	$(CP) ../common/run_arch_tests.ksh $(@)
	$(CHMOD) +x $@

# XXXARM: This is kind of horrid for BUILD32/64 but that's what you get for
# building both platforms in one directory.

$(BUILD32)%.$(MACH).o: %.c
$(BUILD32)	$(COMPILE.c) -o $@ $(CFLAGS_$(MACH)) -DARCH=\"$(MACH)\" $<

$(BUILD32)%.$(MACH).o: ../common/%.c
$(BUILD32)	$(COMPILE.c) -o $@ $(CFLAGS_$(MACH)) -DARCH=\"$(MACH)\" $<

$(BUILD64)%.$(MACH64).o: %.c
$(BUILD64)	$(COMPILE64.c) -o $@ $(CFLAGS_$(MACH64)) -DARCH=\"$(MACH64)\" $<

$(BUILD64)%.$(MACH64).o: ../common/%.c
$(BUILD64)	$(COMPILE64.c) -o $@ $(CFLAGS_$(MACH64)) -DARCH=\"$(MACH64)\" $<

install: $(SUBDIRS) $(CMDS)

clobber: clean
	-$(RM) $(PROG32) $(PROG64) $(KSHPROG) $(ARCHPROG)

clean:
	-$(RM) $(OBJS32) $(OBJS64)

$(CMDS): $(TESTDIR) $(PROG32) $(PROG64) $(KSHPROG) $(ARCHPROG)

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
