SUBDIRS = ddi-interrupts pci-express

all :=		TARGET= all
clean :=	TARGET= clean

all clean: $(SUBDIRS)

$(SUBDIRS): FRC
	@$(MAKE) $(MAKEFLAGS) -w -C $@ $(TARGET)

FRC:
