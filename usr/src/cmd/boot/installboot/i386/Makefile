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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include ../Makefile.com

OBJS +=		getresponse.o
SRCS +=		$(SRC)/common/util/getresponse.c

CPPFLAGS +=	-I../../common -I$(SRC)/common/util
LDLIBS +=	-ladm -lfdisk -lefi -lfstyp -luuid -lumem

.KEEP_STATE:

all:

$(PROG): $(OBJS)

%.o:	$(SRC)/common/util/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<

include $(SRC)/cmd/boot/Makefile.targ
