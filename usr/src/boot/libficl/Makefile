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
#

include $(SRC)/boot/Makefile.master

i386_SUBDIRS = $(MACH) $(MACH64)
aarch64_SUBDIRS = $(MACH64)
SUBDIRS = softcore $($(MACH)_SUBDIRS)

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber

all install: $(SUBDIRS)
clean clobber: $(SUBDIRS)

$($(MACH)_SUBDIRS): softcore

.PARALLEL:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
