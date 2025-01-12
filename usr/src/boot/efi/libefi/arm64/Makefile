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
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright 2016 RackTop Systems.
# Copyright 2025 Michael van der Westhuizen
#

MACHINE=	$(MACH64)

all:		libefi.a

OBJS=	time_event.o
include ../Makefile.com

CFLAGS +=	$(CFLAGS64)

CLEANFILES +=	machine

$(OBJS): machine
