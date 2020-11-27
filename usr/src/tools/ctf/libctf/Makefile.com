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
# Copyright 2018 Joyent, Inc.
#

include $(SRC)/lib/libctf/Makefile.shared.com
include ../../Makefile.ctf

CSTD = $(CSTD_GNU99)
C99LMODE = -Xc99=%all

CPPFLAGS +=	-I$(SRC)/lib/libctf/common/ \
		-I$(SRC)/lib/libdwarf/common/ \
		-I$(SRC)/lib/mergeq \
		-include ../../common/ctf_headers.h \
		-DCTF_OLD_VERSIONS \
		-DCTF_TOOLS_BUILD
LDLIBS += -lc -lelf -L$(ROOTONBLDLIBMACH) -ldwarf -lavl
NATIVE_LIBS += libelf.so libavl.so libc.so
DYNFLAGS += '-R$$ORIGIN/../../lib/$(MACH)'

# We can't directly build this library with CTF information as the CTF tools
# themselves depend upon it, and so aren't built yet. However, we can include
# DWARF debug data and avoid stripping the objects so they can be converted
# and re-installed via the 'installctf' target later.
CTFCONVERT_O= :
$(DYNLIB) := CTFMERGE_POST= :
CFLAGS += $(CTF_FLAGS)
STRIP_STABS = :

.KEEP_STATE:

all: $(LIBS)

install_libs: $(ROOTONBLDLIBMACH)/libctf.so.1 $(ROOTONBLDLIBMACH)/libctf.so
install: all install_libs

ctfconvert_lib: FRC
	-$(CTFCONVERT) -k $(CTFCVTFLAGS) $(DYNLIB)
	$(STRIP) -x $(DYNLIB)
	$(TOUCH) $(DYNLIB)

installctf: ctfconvert_lib install

$(ROOTONBLDLIBMACH)/%: %
	$(INS.file)

$(ROOTONBLDLIBMACH)/$(LIBLINKS): $(ROOTONBLDLIBMACH)/$(LIBLINKS)$(VERS)
	$(INS.liblink)

FRC:

include $(SRC)/lib/Makefile.targ
include $(SRC)/lib/libctf/Makefile.shared.targ
