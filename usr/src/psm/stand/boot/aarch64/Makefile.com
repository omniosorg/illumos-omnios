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
# Copyright 2025 Michael van der Westhuizen
#

include $(SRC)/Makefile.master
include $(TOPDIR)/psm/stand/boot/Makefile.boot

CSTD= $(CSTD_GNU99)

BOOTSRCDIR	= ../..
MACH_DIR	= $(BOOTSRCDIR)/$(MACH)/common
PORT_DIR	= $(BOOTSRCDIR)/port
TOP_CMN_DIR	= $(SRC)/common
CMN_DIR		= $(BOOTSRCDIR)/common
BOOT_DIR	= $(SRC)/psm/stand/boot
DTC_BASE	= $(EXTRA)/dtc

SRT0_O = srt0.o
OBJS +=				\
	aarch64_subr.o		\
	arch_timer.o		\
	assfail.o		\
	board_util.o		\
	bitext.o		\
	boot_aarch64.o		\
	boot_plat.o		\
	bootflags.o		\
	console.o		\
	ddi_subr.o		\
	get.o			\
	getoptstr.o		\
	heap_kmem.o		\
	machdep.o		\
	memchr.o		\
	memlist.o		\
	memmove.o		\
	nfsconf.o		\
	prom_exit.o		\
	prom_getchar.o		\
	prom_gettime.o		\
	prom_init.o		\
	prom_node.o		\
	prom_node_init.o	\
	prom_panic.o		\
	prom_printf.o		\
	prom_putchar.o		\
	prom_string.o		\
	prom_utils.o		\
	prom_wrtestr.o		\
	psci.o			\
	ramdisk.o		\
	readfile.o		\
	sscanf.o		\
	standalloc.o		\
	strtol.o		\
	strtoul.o		\
	uname-i.o		\
	uname-m.o

DTEXTDOM=
DTS_ERRNO=

CFLAGS +=	$(STAND_FLAGS_$(CLASS))

SRT0_OBJ = $(SRT0_O)

LIBSYS_DIR = $(ROOT)/stand/lib

NFSBOOT = inetboot
DTB = $(DTS:%.dts=%.dtb)
ROOT_PSM_NFSBOOT = $(ROOT_PSM_DIR)/$(NFSBOOT)
ROOT_PSM_DTB = $(DTB:%=$(ROOT_PSM_DIR)/%)

PSMSTANDDIR =	$(SRC)/psm/stand
STANDDIR =	$(SRC)/stand
CMNNETDIR =	$(SRC)/common/net
CMNDIR =	$(SRC)/common
CMNUTILDIR =	$(SRC)/common/util
SYSDIR	=	$(SRC)/uts
CPPDEFS	=	-D$(MACH) -D_BOOT -D_KERNEL -D_MACHDEP

# XXXARM: fs/zfs is a vague attempt to get yet another cdefs.h
CPPINCS	=	-I$(PORT_DIR) \
		-I$(PSMSTANDDIR) \
		-I$(STANDDIR)/lib/sa \
		-I$(STANDDIR) -I$(CMNDIR) -I$(MACHDIR) \
		-I$(STANDDIR)/aarch64 \
		-I$(SYSDIR)/armv8/$(BOARD) \
		-I$(SYSDIR)/armv8 \
		-I$(SYSDIR)/aarch64 \
		-I$(SYSDIR)/common \
		-I$(TOP_CMN_DIR) \
		-I$(SRC)/contrib/libfdt \
		-I$(SRC)/stand/lib/fs/zfs/ \
		-I$(SRC)/stand/lib/sa \
		-I$(ROOT)/usr/include # Must be last

CPPFLAGS	= $(CPPDEFS) $(CPPINCS) $(STAND_CPPFLAGS)
AS_CPPFLAGS	= -D_ASM $(CPPDEFS) $(CPPINCS) $(STAND_CPPFLAGS) -I.

LIBNFS_LIBS     = libnfs.a libxdr.a libsock.a libinet.a libtcp.a libfdt.a libhsfs.a libufs.a libzfs.a libsa.a
NFS_LIBS        = $(LIBNFS_LIBS:lib%.a=-l%)
NFS_DIRS        = $(LIBSYS_DIR:%=-L%)
LIBDEPS		= $(LIBNFS_LIBS:%=$(LIBSYS_DIR)/%)
NFS_MAPFILE	= mapfile
NFS_LDFLAGS	= --gc-sections -T$(NFS_MAPFILE) $(NFS_DIRS) \
	--no-warn-rwx-segments

NFS_SRT0        = $(SRT0_OBJ)
NFS_OBJS        = $(OBJS)

NFSBOOT_OUT	= $(NFSBOOT).out
NFSBOOT_BIN	= $(NFSBOOT).bin

MACHDIR = ../common
GENASSYM_CF = $(MACHDIR)/genassym.cf
ASSYM_H		= assym.h

# XXXARM: cross-smatch
SMATCH=off
