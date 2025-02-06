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

#
# Copyright 2017 Hayashi Naoyuki
# Copyright 2025 Michael van der Westhuizen
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..
include $(UTSBASE)/../Makefile.master

#
#	Define the module and object file sets.
#
UNIX		= unix
OBJECTS		= $(SPECIAL_OBJS:%=$(OBJS_DIR)/%) \
		  $(CORE_OBJS:%=$(OBJS_DIR)/%) \
		  $(MACH_NOT_YET_KMODS:%=$(OBJS_DIR)/%)

KRTLD_MAPFILE	= $(UTSBASE)/$(MACH)/krtld/mapfile
KRTLD_OBJECTS	= $(KRTLD_OBJS:%=$(OBJS_DIR)/%)
KRTLD_O		= $(OBJS_DIR)/krtld.o

ROOTMODULE	= $(ROOT_PSM_KERN_DIR)/$(UNIX)
UNIX_BIN	= $(OBJS_DIR)/$(UNIX)

LIBS		= $(GENLIB) $(PLATLIB) $(CPULIB)

GENUNIX_DIR	= $(UTSBASE)/$(MACH)/genunix
GENUNIX		= genunix

PLAT_DIR	= $(UTSBASE)/armv8/platmod
PLATOPTS	= -L$(PLAT_DIR)/$(OBJS_DIR) -l$(PLATMOD)

GENOPTS		= -L$(GENUNIX_DIR)/$(OBJS_DIR) -l$(GENUNIX)

LIBOPTS		= $(GENOPTS) $(PLATOPTS)

CTFEXTRAOBJS	= $(OBJS_DIR)/vers.o

#
#	Include common rules.
#
include ../Makefile.armv8

GENASSYM_CF		= $(UTSBASE)/armv8/ml/genassym.cf
ASSYM_H			= $(OBJS_DIR)/assym.h
AS_INC_PATH		+= -I$(OBJS_DIR)

#
#	Define targets
#
ALL_TARGET	= $(UNIX_BIN)
INSTALL_TARGET	= $(UNIX_BIN) $(ROOTMODULE)

#
#	This is UNIX_DIR. Use a short path.
#
UNIX_DIR	= .

#
#	Overrides
#
CLEANFILES	+= $(UNIX_O) $(MODSTUBS_O) $(KRTLD_O) $(KRTLD_OBJECTS) \
		   $(OBJS_DIR)/vers.c $(OBJS_DIR)/vers.o \
		   $(CPU_OBJ) $(CPULIB) \
		   $(DTRACESTUBS_O) $(DTRACESTUBS_O:%.o=%.s) $(DTRACESTUBS) \
		   $(ASSYM_H) $(ZLIB_OBJS:%=$(OBJS_DIR)/%)

CLOBBERFILES	= $(CLEANFILES) $(UNIX_BIN)

#
# lint pass one enforcement
# Turn on doubleword alignment for 64 bit counter timer registers
#
CFLAGS += $(CCVERBOSE)
$(OBJS_DIR)/platimpl.o := CPPFLAGS += -I$(SRC)/contrib/libfdt

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-clobbered
CERRWARN	+= -_gcc=-Wno-empty-body
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-switch

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:  	$(INSTALL_DEPS)

$(UNIX_O):	$(OBJECTS) $(CTFEXTRAOBJS)
	$(LD) -r -o $@ $(OBJECTS) $(OBJS_DIR)/vers.o

$(UNIX_BIN):	$(UNIX_O) $(MODSTUBS_O) $(KRTLD_O) $(MAPFILE) $(GENLIB) $(DTRACESTUBS)
	$(LD) -dy -b -o $@ -znointerp -M $(MAPFILE) \
	    $(UNIX_O) $(MODSTUBS_O) $(KRTLD_O) $(LIBOPTS) $(DTRACESTUBS)
	$(CTFMERGE_UNIQUIFY_AGAINST_GENUNIX) $(LIBGEN_OBJS)
	$(POST_PROCESS)

symcheck:	$(UNIX_O) $(KRTLD_O) $(MODSTUBS_O) $(LIBS)
	$(LD) -dy -b -o $(SYM_MOD) -M $(MAPFILE) \
	$(UNIX_O) $(KRTLD_O) $(MODSTUBS_O) $(LIBOPTS) $(DTRACESTUBS)

$(KRTLD_O):	$(KRTLD_OBJECTS)
	$(LD) -r -M$(KRTLD_MAPFILE) -o $@ $(KRTLD_OBJECTS)

$(PLATLIB):
	?@(cd $(PLAT_DIR); pwd; $(MAKE) all.targ)
	?@pwd

#
#	Include common targets.
#
include ../Makefile.targ
