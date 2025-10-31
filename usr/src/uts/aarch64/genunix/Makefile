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
# Copyright 2017 Hayashi Naoyuki
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the generic
#	unix kernel module.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= genunix
GENUNIX		= $(OBJS_DIR)/$(MODULE)

OBJECTS		= $(GENUNIX_OBJS:%=$(OBJS_DIR)/%) \
		  $(NOT_YET_KMODS:%=$(OBJS_DIR)/%)

ROOTMODULE	= $(ROOT_KERN_DIR)/$(MODULE)

LIBGEN		= $(OBJS_DIR)/libgenunix.so
LIBSTUBS	= $(GENSTUBS_OBJS:%=$(OBJS_DIR)/%)

#
#	Include common rules.
#
include $(UTSBASE)/aarch64/Makefile.aarch64

GENASSYM_CF		= $(UTSBASE)/aarch64/ml/genassym.cf
ASSYM_H			= $(OBJS_DIR)/assym.h
AS_INC_PATH		+= -I$(OBJS_DIR)

#
#	Define targets
#
ALL_TARGET	= $(LIBGEN) $(GENUNIX)
INSTALL_TARGET	= $(ALL_TARGET) $(GENUNIX) $(ROOTMODULE)

#
#	Overrides
#
CLOBBERFILES	+= $(GENUNIX)
CLEANFILES	+= $(LIBSTUBS) $(LIBGEN) $(ASSYM_H)
BINARY		=

IPCTF_TARGET	= $(IPCTF)

CPPFLAGS	+= -I$(SRC)/common
CPPFLAGS	+= -I$(SRC)/uts/common/fs/zfs

CPPFLAGS	+= -I$(UTSBASE)/armv8

CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-clobbered
CERRWARN	+= -_gcc=-Wno-empty-body
CERRWARN	+= -_gcc=-Wno-override-init

#
# Some compilers default to stripping unused debug information from
# objects. Since genunix is used as the uniquification source for CTF data
# in the kernel, explicitly keep as much debug data as possible.
#
CFLAGS		+= $(CALLSYMS)

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

# Due to what seems to be an issue in GCC 4 generated DWARF containing
# symbolic relocations against non-allocatable .debug sections, libgenunix.so
# must be built from a stripped object, thus we create an intermediary
# libgenunix.o we can safely strip.
LIBGENUNIX_O = $(OBJS_DIR)/libgenunix.o
CLEANFILES += $(LIBGENUNIX_O)

$(LIBGENUNIX_O): $(OBJECTS)
	$(LD) -r -o $(OBJS_DIR)/libgenunix.o $(OBJECTS)
	$(STRIP) -x $(OBJS_DIR)/libgenunix.o

$(LIBGEN):	$(LIBGENUNIX_O) $(LIBSTUBS)
	$(BUILD.SO) $(LIBGENUNIX_O) $(LIBSTUBS)

$(IPCTF_TARGET) ipctf_target: FRC
	@cd $(IPDRV_DIR); pwd; $(MAKE) ipctf.$(OBJS_DIR)
	@pwd

$(GENUNIX): $(IPCTF_TARGET) $(OBJECTS)
	$(LD) -ztype=kmod $(LDFLAGS) -o $@ $(OBJECTS)
	$(CTFMERGE_GENUNIX_MERGE)
	$(POST_PROCESS)

#
#	Include common targets.
#
include $(UTSBASE)/aarch64/Makefile.targ
