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
# Copyright (c) 2017 by Delphix. All rights reserved.
# Copyright 2023 RackTop Systems, Inc.

UTSBASE=	../..

MODULE=		hyperv
OBJECTS=	$(HV_HYPERV_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE=	$(ROOT_MISC_DIR)/$(MODULE)
CONF_SRCDIR=	$(UTSBASE)/intel/io/hyperv/vmbus

MAPFILE=	$(CONF_SRCDIR)/$(MODULE).mapfile

include		$(UTSBASE)/intel/Makefile.intel

ALL_TARGET=	$(BINARY)
INSTALL_TARGET=	$(BINARY) $(ROOTMODULE)

INC_PATH +=	-I$(UTSBASE)/intel/io/hyperv

LDFLAGS +=	-M $(MAPFILE)

.KEEP_STATE:

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

def:		$(DEF_DEPS)

install:	$(INSTALL_DEPS)

include		$(UTSBASE)/intel/Makefile.targ
