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
#

TOPDIR =	../../../../..
DTS=meson-gxbb-odroidc2.dts
OBJS += dwmac.o mmc.o meson_pinmux.o meson_gpio.o meson_hwreset.o
BOARD=	meson-gxbb

include ../Makefile.com
ROOT_PSM_DIR=$(ROOT_PLAT_DIR)/Amlogic,meson-gxbb

.KEEP_STATE:

all: $(NFSBOOT_BIN) $(DTB)
$(NFS_SRT0) $(NFS_OBJS):  $(ASSYM_H)

install: all $(ROOT_PSM_NFSBOOT) $(ROOT_PSM_DTB)

CFLAGS += -I.
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-but-set-variable

include $(BOOTSRCDIR)/Makefile.rules
include ../Makefile.targ

$(ROOT_PSM_NFSBOOT): $(NFSBOOT_BIN) $(ROOT_PSM_DIR)
	$(MKIMAGE) -A arm64 -O linux -C none  -T kernel -q \
		-a 0x11000000 -e 0x11000000 \
		-n 'illumos' -d $(NFSBOOT_BIN) $@ >/dev/null

$(ROOT_PSM_DTB): $(DTB) $(ROOT_PSM_DIR)
	$(INS.file) $(DTB)

%.dtb: dts/%.dts
	$(ANSI_CPP) -nostdinc -I dts $(CPPINCS) -undef \
		-x assembler-with-cpp $< | $(DTC) -o $@ -O dtb
