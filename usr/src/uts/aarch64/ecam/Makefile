
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= ecam
OBJECTS		= $(ECAM_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

LDFLAGS += -Nmisc/pcie -Nmisc/pcierc

INC_PATH += -I$(SRC)/uts/aarch64/io/pciex/pcierc/

#
#	Include common rules.
#
include $(UTSBASE)/aarch64/Makefile.aarch64

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
include $(UTSBASE)/aarch64/Makefile.targ

$(OBJS_DIR)/%.o:		$(UTSBASE)/aarch64/io/pciex/ecam/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)
