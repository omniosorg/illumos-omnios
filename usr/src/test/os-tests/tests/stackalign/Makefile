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
# Copyright 2020 Oxide Computer Company
# Copyright 2021 Tintri by DDN, Inc. All rights reserved.
#

include $(SRC)/Makefile.master

PROGS = stackalign

$(BUILD32)PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

OBJS = $(PROGS32:%=%.o) $(PROGS64:%=%.o)
$(INTEL_BLD)OBJS += stack_i86.o stack_amd64.o
$(SPARC_BLD)OBJS += stack_sparcv7.o stack_sparcv9.o
$(AARCH64_BLD)OBJS += stack_aarch64.o

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTSTACK = $(ROOTOPTDIR)/stackalign
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTSTACK)/32/%) \
	$(PROGS64:%=$(ROOTOPTSTACK)/64/%)

include $(SRC)/cmd/Makefile.cmd

ASFLAGS += -D_ASM
ASFLAGS64 += -D_ASM
CFLAGS += -D_REENTRANT
LDFLAGS += -Wl,-zinitarray=get_stack_at_init

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

clean:
	-$(RM) $(OBJS)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTSTACK)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTSTACK): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTSTACK)/32: $(ROOTOPTSTACK)
	$(INS.dir)

$(ROOTOPTSTACK)/64: $(ROOTOPTSTACK)
	$(INS.dir)

$(ROOTOPTSTACK)/32/%: % $(ROOTOPTSTACK)/32
	$(INS.file)

$(ROOTOPTSTACK)/64/%: % $(ROOTOPTSTACK)/64
	$(INS.file)

$(ROOTOPTSTACK)/%: %
	$(INS.file)

%.64.o: %.c
	$(COMPILE64.c) $< -o $@

%.32.o: %.c
	$(COMPILE.c) $< -o $@

stack_$(MACH32).o: stack_$(MACH32).S
	$(COMPILE.s) $< -o $@

stack_$(MACH64).o: stack_$(MACH64).S
	$(COMPILE64.s) $< -o $@

%.64: %.64.o stack_$(MACH64).o
	$(LINK64.c) -o $@ $^ $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.32.o stack_$(MACH32).o
	$(LINK.c) -o $@ $^ $(LDLIBS)
	$(POST_PROCESS)

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)

FRC:
