#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG = dtrace
OBJS = dtrace.o

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf
include $(SRC)/tools/Makefile.tools
include $(SRC)/cmd/Makefile.cmd.64

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)
LDFLAGS += -L$(ROOTONBLDLIBMACH64) -R'$$ORIGIN/../../lib/$(NATIVE_MACH)/64'
LDLIBS += -ldtrace -lproc -lctf -lelf

ADJUNCT_LIBS += libproc.so libctf.so libelf.so

FILEMODE = 0555

CLEANFILES += $(OBJS)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTONBLDMACH64PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

clean:
	-$(RM) $(CLEANFILES)

%.o: $(SRC)/cmd/dtrace/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include $(SRC)/cmd/Makefile.targ
