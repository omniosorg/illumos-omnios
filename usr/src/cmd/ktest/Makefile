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
# Copyright 2023 Oxide Computer Company
#

PROG = ktest
OBJS = ktest.o
SRCS =  $(OBJS:%.o=%.c)

CLEANFILES += $(OBJS)

include ../Makefile.cmd
$(BUILD64) include ../Makefile.cmd.64
include ../Makefile.ctf

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)

LDLIBS += -L$(ROOT)/lib -lumem -lgen -lofmt -lcmdutils -lktest

CSTD = $(CSTD_GNU99)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

install: all $(ROOTPROG)

clean:
	-$(RM) $(CLEANFILES)

include ../Makefile.targ
