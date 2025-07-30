
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= bcm2711_pcie
OBJECTS		= $(BCM2711_PCIE_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_RPI4_DRV_DIR)/$(MODULE)

LDFLAGS += -Nmisc/pcie -Nmisc/pcierc

INC_PATH += -I$(SRC)/uts/aarch64/io/pciex/pcierc/

#
#	Include common rules.
#
include $(UTSBASE)/armv8/rpi4/Makefile.rpi4

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/armv8/rpi4/Makefile.targ

$(OBJS_DIR)/%.o:		$(SRC)/uts/armv8/rpi4/io/bcm2711_pcie/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)
