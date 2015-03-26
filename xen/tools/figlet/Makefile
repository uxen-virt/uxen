
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

.PHONY: all dist
all dist: figlet$(HOST_EXE_SUFFIX)

figlet$(HOST_EXE_SUFFIX): figlet.c
	$(_W)echo Building - $@
	$(_V)$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

$(BUILDDIR:%=x)clean::
	rm -f *.o figlet$(HOST_EXE_SUFFIX)

endif # MAKENOW
