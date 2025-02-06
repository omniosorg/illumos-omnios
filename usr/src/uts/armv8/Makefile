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
#	This makefile drives the production of all implementation architecture
#	dependent modules for the armv8 architecture.
#

UTSBASE = ..

include Makefile.armv8

def			:=	TARGET= def
def.prereq		:=	TARGET= def
all			:=	TARGET= all
all.prereq		:=	TARGET= all
install			:=	TARGET= install
install.prereq		:=	TARGET= install
install_h		:=	TARGET= install_h
install_h.prereq	:=	TARGET= install_h
clean			:=	TARGET= clean
clobber			:=	TARGET= clobber
check			:=	TARGET= check

.KEEP_STATE:

.PARALLEL:	$(PARALLEL_KMODS) $(XMODS) $(IMPLEMENTATIONS)

def all clean clobber: unix .WAIT \
	$(KMODS) $(XMODS) $(IMPLEMENTATIONS)

install: install_platforms unix .WAIT \
	$(KMODS) $(XMODS) $(IMPLEMENTATIONS)

unix $(KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(IMPLEMENTATIONS):	FRC
	@cd $@; pwd; THISIMPL=$@ $(MAKE) $(NO_STATE) $(TARGET)

$(XMODS):	FRC
	cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	install_platforms $(IMPLEMENTATIONS) FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

#
# Prerequisites
#
# The uts/Makefile defines build parallelism for arm platforms such that
# aarch64 and armv8 are built in parallel. Also this Makefile specifies that
# all IMPLEMENTATIONS armv8 sub-platforms are built in parallel. This requires
# building certain parts before the parallel build can start. The uts/Makefile
# appends the '.prereq' string to the original target and executes this
# Makefile to build any prerequisites needed before the full parallel build
# can start.  After that make continues with normal targets.
#
# Any build prerequisites for armv8 and IMPLEMENTATIONS builds should be
# described here.
#
# genunix is used by everyone to ctfmerge with. genunix is merged with aarch64/ip
#   so as a side effect this dependency builds aarch64/ip as part of the
#   prerequisites.
#
#
all.prereq def.prereq install.prereq: genunix

install_h.prereq:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

#
# Nothing to do with any other prerequisites
#
%.prereq:

#
# Rules for the /platforms directories.  This is hardwired here because
# the first stage of the project (KBI) only implements the userland
# changes, but the only reasonable place to record the aliases is
# here in kernel land.
#
$(ROOT_PLAT_DIRS): $(ROOT_PLAT_DIR)
	-$(INS.dir)

$(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%): $(ROOT_PLAT_DIR)
	$(INS.slink1)

#
# create directories in /usr/platform/ for the implementations that are
# defined in $(IMPLEMENTED_PLATFORM)
#

# Foreach $(IMPLEMENTED_PLATFORM) there can be a list of $(LINKED_PLATFORMS)
# that are linked to it.
#
$(USR_PLAT_DIR)/$(IMPLEMENTED_PLATFORM):	$(USR_PLAT_DIR)
	-$(INS.dir)

#
# create the links in /usr/platform/ foreach $(LINKED_PLATFORMS)
# to it's corresponding $(IMPLEMENTED_PLATFORM).
#
PLATFORMS	= $(LINKED_PLATFORMS)

$(USR_PLAT_DIRS): $(USR_PLAT_DIR)
	$(INS.slink3)

PLATFORMS	+= $(IMPLEMENTED_PLATFORM)


#
# Make the /platforms directories.  This is hardwired here because
# the first stage of the project (KBI) only implements the userland
# changes, but the only reasonable place to record the aliases is
# here in kernel land.
#

install_platforms:	$(ROOT_PSM_DIR) $(USR_PSM_DIR) \
			$(ROOT_PLAT_DIRS) $(USR_PLAT_DIRS) \
			$(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%) \
			$(USR_DESKTOP_DIR) $(USR_DESKTOP_INC_DIR) \
			$(USR_DESKTOP_SBIN_DIR) $(USR_DESKTOP_LIB_DIR)

#
# rules for making include, sbin, lib dirs/links in
# /usr/platform/$(PLATFORM)/ for desktop platforms
#
$(USR_DESKTOP_INC_DIR):		$(USR_DESKTOP_DIR)
	$(INS.slink4)

$(USR_DESKTOP_SBIN_DIR):	$(USR_DESKTOP_DIR)
	$(INS.slink5)

$(USR_DESKTOP_LIB_DIR):		$(USR_DESKTOP_DIR)
	-$(INS.dir)

include ../Makefile.targ

#
# Cross-reference customization: build a cross-reference over all of the
# armv8-related directories.
#
XRDIRS	= ../aarch64 ../common
XRPRUNE = i86pc sun4u sun4v sun4 intel sparc sun

cscope.out tags: FRC
	$(XREF) -x $@
