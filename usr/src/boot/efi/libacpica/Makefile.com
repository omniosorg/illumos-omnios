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

include $(SRC)/boot/Makefile.master
include $(SRC)/boot/Makefile.inc

MACHINCLUDE = $(MACH64)

install:

#
# On the next ACPI update, add exserial.c and utcksum.c
#

SRCS += \
	acpi_efi.c \
	\
	osstub.c \
	\
	oseficlib.c osefitbl.c osefixf.c \
	\
	dsargs.c dscontrol.c dsdebug.c dsfield.c dsinit.c \
	dsmethod.c dsmthdat.c dsobject.c dsopcode.c dsutils.c \
	dswexec.c dswload.c dswload2.c dswscope.c dswstate.c \
	dspkginit.c \
	\
	evevent.c evglock.c evgpe.c evgpeblk.c evgpeinit.c \
	evgpeutil.c evhandler.c evmisc.c evregion.c evrgnini.c \
	evsci.c evxface.c evxfevnt.c evxfgpe.c evxfregn.c \
	\
	exconcat.c exconfig.c exconvrt.c excreate.c exdebug.c \
	exdump.c exfield.c exfldio.c exmisc.c exmutex.c exnames.c \
	exoparg1.c exoparg2.c exoparg3.c exoparg6.c exprep.c \
	exregion.c exresnte.c exresolv.c exresop.c \
	exstore.c exstoren.c exstorob.c exsystem.c extrace.c \
	exutils.c \
	\
	hwacpi.c hwesleep.c hwgpe.c hwpci.c hwregs.c hwsleep.c \
	hwtimer.c hwvalid.c hwxface.c hwxfsleep.c \
	\
	psargs.c psloop.c psobject.c psopcode.c psopinfo.c \
	psparse.c psscope.c pstree.c psutils.c pswalk.c psxface.c \
	\
	nsaccess.c nsalloc.c nsarguments.c nsconvert.c nsdump.c \
	nsdumpdv.c nseval.c nsinit.c nsload.c nsnames.c nsobject.c \
	nsparse.c nspredef.c nsprepkg.c nsrepair.c nsrepair2.c \
	nssearch.c nsutils.c nswalk.c nsxfeval.c nsxfname.c \
	nsxfobj.c \
	\
	tbdata.c tbfadt.c tbfind.c tbinstal.c tbprint.c tbutils.c \
	tbxface.c tbxfload.c tbxfroot.c \
	\
	utaddress.c utalloc.c utascii.c utbuffer.c utcache.c \
	utclib.c utcopy.c utdebug.c utdecode.c utdelete.c \
	uterror.c uteval.c utexcep.c utglobal.c uthex.c utids.c \
	utinit.c utlock.c utmath.c utmisc.c utmutex.c utnonansi.c \
	utobject.c utosi.c utownerid.c utpredef.c utresrc.c \
	utstate.c utstring.c uttrack.c utuuid.c utxface.c \
	utxferror.c utxfinit.c utxfmutex.c utresdecode.c \
	utstrsuppt.c utstrtoul64.c

DISASSEMBLER_SOURCES = \
	dmbuffer.c dmcstyle.c dmdeferred.c dmnames.c dmopcode.c \
	dmresrc.c dmresrcl.c dmresrcl2.c dmresrcs.c dmutils.c \
	dmwalk.c

DEBUGGER_SOURCES = \
	rsaddr.c rscalc.c rscreate.c rsdump.c rsdumpinfo.c \
	rsinfo.c rsio.c rsirq.c rslist.c rsmemory.c rsmisc.c \
	rsserial.c rsutils.c rsxface.c

XDEBUGGER_SOURCES = \
	rsaddr.c rscalc.c rscreate.c rsdumpinfo.c \
	rsinfo.c rsio.c rsirq.c rslist.c rsmemory.c rsmisc.c \
	rsserial.c rsutils.c rsxface.c

SRCS += $(XDEBUGGER_SOURCES)

OBJS=	$(SRCS:%.c=%.o)

CPPFLAGS += -U__sun
CPPFLAGS += -DEFI
CPPFLAGS += -D_EDK2_EFI
CPPFLAGS += -DUSE_STDLIB
CPPFLAGS += -DACPI_USE_LOCAL_CACHE

# CPPFLAGS += -DACPI_DISASSEMBLER
# CPPFLAGS += -DACPI_DEBUGGER

CPPFLAGS += -DEFI -I.
CPPFLAGS += -I$(SRC)/uts/common/sys/acpi
CPPFLAGS += -I$(BOOTSRC)/sys
CPPFLAGS += -I$(BOOTSRC)/common
CPPFLAGS += -I$(BOOTSRC)/libsa
CPPFLAGS += -I$(BOOTSRC)/include
CPPFLAGS += -I$(BOOTSRC)/efi/include
CPPFLAGS += -I$(BOOTSRC)/efi/include/$(MACHINCLUDE)

# needed for tbl - I'm sure we can get rid of a lot of this
CPPFLAGS += -I$(SRC)/cmd/acpi/acpidump

include ../../Makefile.inc

CFLAGS +=       $(CFLAGS64)

libacpica.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS) libacpica.a

machine:
	$(RM) machine
	$(SYMLINK) ../../../sys/$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../sys/x86/include x86

%.o:	../%.c
	$(COMPILE.c) $<

%.o:	../../../common/%.c
	$(COMPILE.c) $<

%.o:	$(PNGLITE)/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/events/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/hardware/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/dispatcher/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/executer/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/parser/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/namespace/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/resources/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/tables/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/utilities/%.c
	$(COMPILE.c) $<

%.o:	$(SRC)/common/acpica/disassembler/%.c
	$(COMPILE.c) $<
