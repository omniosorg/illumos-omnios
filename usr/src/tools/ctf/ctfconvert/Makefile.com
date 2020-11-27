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

PROG = ctfconvert
SRCS = ctfconvert.c

include ../../Makefile.ctf

CFLAGS += $(CCVERBOSE)
LDLIBS += -lctf -lelf
NATIVE_LIBS += libelf.so libc.so

# We can't directly build this component with CTF information as that presents
# something of a bootstrap problem. However, we can include
# DWARF debug data and avoid stripping the objects so they can be converted
# and re-installed via the 'installctf' target later.
CFLAGS += $(CTF_FLAGS)
STRIP_STABS = :

LDFLAGS = \
	-L$(ROOTONBLDLIBMACH) \
	'-R$$ORIGIN/../../lib/$(MACH)' \
	$(BDIRECT) $(ZLAZYLOAD)

CPPFLAGS += -include ../../common/ctf_headers.h

OBJS = $(SRCS:%.c=%.o)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: $(SRC)/cmd/ctfconvert/%.c
	$(COMPILE.c) $<

$(ROOTONBLDMACHPROG): $(PROG)

install_prog: $(ROOTONBLDMACHPROG)
install: all install_prog

ctfconvert_prog: FRC
	-$(CTFCONVERT) -k $(CTFCVTFLAGS) $(PROG)
	$(STRIP) -x $(PROG)
	$(TOUCH) $(PROG)

installctf: ctfconvert_prog install

clean:
	$(RM) $(OBJS)

FRC:

include $(SRC)/tools/Makefile.targ
