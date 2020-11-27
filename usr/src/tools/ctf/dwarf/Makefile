#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include		../../Makefile.tools

SUBDIRS	= $(MACH)

all	:= TARGET= all
install	:= TARGET= install
clean	:= TARGET= clean
clobber	:= TARGET= clobber
installctf	:= TARGET= installctf

.KEEP_STATE:

install installctf all clean clobber: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
