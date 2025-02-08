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
# Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= bcm2711_soctemp
OBJECTS		= $(BCM2711_SOCTEMP_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_RPI4_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/armv8/rpi4/io/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/armv8/rpi4/Makefile.rpi4

#
#       Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)

#
#	Default build targets.
#
.KEEP_STATE:

all:		$(ALL_DEPS)

def:		$(DEF_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)


#
#	Include common targets.
#
include $(UTSBASE)/armv8/rpi4/Makefile.targ
