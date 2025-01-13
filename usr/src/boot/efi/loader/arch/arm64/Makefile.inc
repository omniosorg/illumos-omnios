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
# Copyright 2025 Michael van der Westhuizen
#

SRCS +=	bootsvcs.c \
	cache.c \
	exec.c \
	isadir.c \
	start.S

OBJS +=	bootsvcs.o \
	cache.o \
	exec.o \
	isadir.o \
	start.o

SRCS += nullconsole.c \
	spinconsole.c

OBJS += nullconsole.o \
	spinconsole.o

start.o := CCASFLAGS += $(C_BIGPICFLAGS)
