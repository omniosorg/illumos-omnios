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
# Copyright 2026 lex0de <lex0de@tuta.com>
#

UTSBASE		= ../..
FWDIR		= $(UTSBASE)/common/io/iwm/fw-iw
FWFILES		= iwm-8000C-36
MODULE		= iwm
OBJECTS		= $(IWM_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
ROOTFIRMWARE	= $(FWFILES:%=$(ROOT_FIRMWARE_DIR)/$(MODULE)/%)

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTFIRMWARE)

# Native MAC and net80211 module dependencies.
LDFLAGS		+= -Nmisc/mac -Nmisc/net80211

.KEEP_STATE:

def:		$(DEF_DEPS)
all:		$(ALL_DEPS)
clean:		$(CLEAN_DEPS)
clobber:	$(CLOBBER_DEPS)
install:	$(INSTALL_DEPS)

check:
	$(CSTYLE) -pP $(UTSBASE)/common/io/iwm/if_iwmfw.c
	$(CSTYLE) -pP $(UTSBASE)/common/io/iwm/if_iwmhw.c
	$(CSTYLE) -pP $(UTSBASE)/common/io/iwm/if_iwmfw.h
	$(HDRCHK) $(UTSBASE)/common/io/iwm/if_iwmfw.h
	$(CSTYLE) -pP $(UTSBASE)/common/io/iwm/if_iwm.c
	$(CSTYLE) -pP $(UTSBASE)/common/io/iwm/if_iwmreg.h
	$(CSTYLE) -pP $(UTSBASE)/common/io/iwm/if_iwmvar.h
	$(HDRCHK) $(UTSBASE)/common/io/iwm/if_iwmreg.h
	$(HDRCHK) $(UTSBASE)/common/io/iwm/if_iwmvar.h

include $(UTSBASE)/intel/Makefile.targ
