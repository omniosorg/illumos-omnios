#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2017 Hayashi Naoyuki
# Copyright 2025 Michael van der Westhuizen
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Include common rules.
#
include $(UTSBASE)/armv8/rpi4/Makefile.rpi4

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
check		:=	TARGET= check

#
#	Default build targets.
#
.KEEP_STATE:

def all clean clobber: $(RPI4_KMODS)

IMPLEMENTED_PLATFORM	= RaspberryPi,4
PPLINKED_PLATFORMS	= raspberrypi,4-model-b

#
# $(USR_RPI4_DIR)
# $(USR_RPI4_SBIN_DIR)
# $(USR_RPI4_LIB_DIR)
# $(ROOT_RPI4_LIB_DIR)
# $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)
#
install:	$(ROOT_RPI4_DIR) \
		$(PPLINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%) \
		.WAIT $(RPI4_KMODS)

install_h check:

$(RPI4_KMODS):  FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

#
#
#	Include common targets.
#
include $(UTSBASE)/armv8/rpi4/Makefile.targ
