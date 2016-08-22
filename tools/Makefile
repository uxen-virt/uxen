#
# trampoline Makefile -- actual Makefile is Makefile.tools
#
# check make version and build a more recent version if the executing
# version is too old, then use the newly built make to do the work
#
# required on OSX with system gnu make version 3.81
#

ifeq (,$(filter 4.0,$(firstword $(sort $(MAKE_VERSION) 4.0))))
TOPDIR = ..
include $(TOPDIR)/Config.mk
OLDMAKE := $(MAKE)
override MAKE := $(BUILD_INSTALL_DIR)/bin/make
make: $(MAKE)
$(MAKE):
	@echo make $(MAKE_VERSION) too old -- building up-to-date gnu make
	+@$(OLDMAKE) \
	  -f $(subst Makefile,Makefile.make,$(firstword $(MAKEFILE_LIST))) \
	  MAKEFLAGS= make-make
	@echo up-to-date gnu make: $(MAKE)
	@$(MAKE) -v MAKEFLAGS=
endif

.SUFFIXES:

all:

.PHONY: make
make:
	+@$(MAKE) --no-print-directory \
	  -f $(subst Makefile,Makefile.tools,$(firstword $(MAKEFILE_LIST))) \
	  $(MAKECMDGOALS)

% :: make ; @:
