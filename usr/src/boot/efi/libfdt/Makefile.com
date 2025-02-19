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
# Copyright 2025 Michael van der Westhuizen
#

include $(SRC)/boot/Makefile.master
include $(SRC)/boot/Makefile.inc

MACHINCLUDE = $(MACH64)

install:

SRCS +=					\
	fdt.c				\
	fdt_ro.c			\
	fdt_wip.c			\
	fdt_sw.c			\
	fdt_rw.c			\
	fdt_strerror.c			\
	fdt_empty_tree.c		\
	fdt_addresses.c			\
	fdt_overlay.c			\
	fdt_check.c

OBJS=	$(SRCS:%.c=%.o)

CPPFLAGS += -I.
CPPFLAGS += -I$(BOOTSRC)/sys
CPPFLAGS += -I$(BOOTSRC)/common
CPPFLAGS += -I$(BOOTSRC)/libsa
CPPFLAGS += -I$(BOOTSRC)/include
CPPFLAGS += -I$(SRC)/contrib/libfdt

include ../../Makefile.inc

CFLAGS +=       $(CFLAGS64)

libfdt.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS) libfdt.a

machine:
	$(RM) machine
	$(SYMLINK) ../../../sys/$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../sys/x86/include x86

%.o:	$(SRC)/contrib/libfdt/%.c
	$(COMPILE.c) $<
