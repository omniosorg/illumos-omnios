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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2011, 2016 by Delphix. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY = libdtrace.a
VERS = .1

LIBSRCS = \
	dt_aggregate.c \
	dt_as.c \
	dt_buf.c \
	dt_cc.c \
	dt_cg.c \
	dt_consume.c \
	dt_decl.c \
	dt_dis.c \
	dt_dof.c \
	dt_error.c \
	dt_errtags.c \
	dt_sugar.c \
	dt_handle.c \
	dt_ident.c \
	dt_inttab.c \
	dt_link.c \
	dt_list.c \
	dt_open.c \
	dt_options.c \
	dt_program.c \
	dt_map.c \
	dt_module.c \
	dt_names.c \
	dt_parser.c \
	dt_pcb.c \
	dt_pid.c \
	dt_pq.c \
	dt_pragma.c \
	dt_print.c \
	dt_printf.c \
	dt_proc.c \
	dt_provider.c \
	dt_regset.c \
        dt_string.c \
	dt_strtab.c \
	dt_subr.c \
	dt_work.c \
	dt_xlator.c

LIBISASRCS = \
	dt_isadep.c

i386_SRCS = $(SRC)/common/dis/i386/dis_tables.c

OBJECTS = dt_lex.o dt_grammar.o $(MACHOBJS) $(LIBSRCS:%.c=%.o) \
	$(LIBISASRCS:%.c=%.o) dis_tables.o

include $(SRC)/lib/Makefile.lib
include $(SRC)/tools/Makefile.tools
include $(SRC)/lib/Makefile.lib.64

LIBS = $(DYNLIB)

SRCDIR = $(SRC)/lib/libdtrace/common

CLEANFILES += dt_lex.c dt_grammar.c dt_grammar.h y.output

i386_CPPFLAGS = -I$(SRC)/common/dis/i386

CPPFLAGS += -I$(SRCDIR) -I.  -I$(SRC)/tools/sgs/include \
	-D_ELF64 $($(NATIVE_MACH)_CPPFLAGS)
CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CFLAGS64 += $(CCVERBOSE) $(C_BIGPICFLAGS)


CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-switch

# not linted
SMATCH=off

YYCFLAGS =
LDFLAGS64 += -L$(ROOTONBLDLIBMACH64)
LDLIBS += -L$(ROOTONBLDLIBMACH64)
LDLIBS += -lgen -lproc -lrtld_db -lnsl -lsocket -lctf -lelf
# XXXARM: intrinsics
$(AARCH64_BLD)LDLIBS += -lgcc

ADJUNCT_LIBS +=		\
	libc.so		\
	libctf.so	\
	libgen.so	\
	libnsl.so	\
	libproc.so	\
	librtld_db.so	\
	libsocket.so

LFLAGS = -t -v
YFLAGS = -d -v

all: $(LIBS)

install: $(ROOTONBLDLIBMACH64)/libdtrace.so.1 $(ROOTONBLDLIBMACH64)/libdtrace.so

dt_lex.c: $(SRCDIR)/dt_lex.l dt_grammar.h
	$(LEX) $(LFLAGS) $(SRCDIR)/dt_lex.l > $@

dt_grammar.c dt_grammar.h: $(SRCDIR)/dt_grammar.y
	$(YACC) $(YFLAGS) $(SRCDIR)/dt_grammar.y
	@mv y.tab.h dt_grammar.h
	@mv y.tab.c dt_grammar.c

pics/dt_lex.o pics/dt_grammar.o := CFLAGS += $(YYCFLAGS)
pics/dt_lex.o pics/dt_grammar.o := CFLAGS64 += $(YYCFLAGS)

dt_errtags.c: $(SRCDIR)/mkerrtags.sh $(SRCDIR)/dt_errtags.h
	sh $(SRCDIR)/mkerrtags.sh < $(SRCDIR)/dt_errtags.h > $@

dt_names.c: $(SRCDIR)/mknames.sh $(SRC)/uts/common/sys/dtrace.h
	sh $(SRCDIR)/mknames.sh < $(SRC)/uts/common/sys/dtrace.h > $@

pics/%.o: $(SRC)/lib/libdtrace/$(NATIVE_MACH)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: $(SRC)/lib/libdtrace/$(NATIVE_MACH)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: $(SRC)/common/dis/i386/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(ROOTONBLDLIBMACH64)/%: %
	$(INS.file)

$(ROOTONBLDLIBMACH64)/libdtrace.so:
	$(RM) $(@); $(SYMLINK) ./libdtrace.so.1 $@

.KEEP_STATE:

include $(SRC)/lib/Makefile.targ
