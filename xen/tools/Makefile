
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

.PHONY: all dist
all dist: symbols$(HOST_EXE_SUFFIX)
	@[ ! -d $(SRCDIR)/figlet ] || $(MAKE) -C $(SRCDIR)/figlet

clean::
	@[ ! -d $(SRCDIR)/figlet ] || $(MAKE) -C $(SRCDIR)/figlet clean
$(BUILDDIR:%=x)clean::
	rm -f *.o symbols$(HOST_EXE_SUFFIX)

symbols$(HOST_EXE_SUFFIX): symbols.c
	$(_W)echo Building - $@
	$(_V)$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

endif # MAKENOW

