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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 Joyent, Inc.
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
#

include ../Makefile.tools

SUBDIRS = stabs ctfstrip libctf ctfdiff ctfdump ctfmerge ctfconvert
# There is a bootstrap problem with adding CTF data to these components.
# To work around this, they are first installed as usual but with embedded
# DWARF data, and then converted and re-installed in a second pass.
CTF_POST = dwarf libctf ctfconvert
INSTALLCTF_SUBDIRS = $(CTF_POST:%=%/installctf)

.PARALLEL: $(SUBDIRS)
.NO_PARALLEL: $(INSTALLCTF_SUBDIRS)

all	:= TARGET= all
install	:= TARGET= install
clean	:= TARGET= clean
clobber	:= TARGET= clobber

.KEEP_STATE:

ctfmerge: ctfconvert
ctfdiff: ctfconvert
ctfdump: ctfconvert
stabs: ctfconvert
ctfconvert: libctf
ctfstrip: ctfconvert

all clean clobber: dwarf .WAIT $(SUBDIRS)
install: dwarf .WAIT $(SUBDIRS) .WAIT $(INSTALLCTF_SUBDIRS)

dwarf $(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(INSTALLCTF_SUBDIRS): FRC
	@cd $(@D); pwd; $(MAKE) $(@F)

FRC:
