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
# Copyright 2016 RackTop Systems.
# Copyright 2025 Michael van der Westhuizen
#

include $(SRC)/boot/Makefile.master

MACHINE=	$(MACH64)
EFIPROG=	loader64.efi

all:		$(EFIPROG)

include ../Makefile.com

EFI_TARGET=	binary
LDFLAGS +=	-znocombreloc

efi_main.o := CPPFLAGS += -DLOADER_EFI=L\"loader64.efi\"
CFLAGS +=	$(CFLAGS64) -_gcc=-mgeneral-regs-only

CLEANFILES +=	machine $(EFIPROG)

$(OBJS):	machine
