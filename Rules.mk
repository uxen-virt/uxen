#
# Copyright 2012-2016, Bromium, Inc.
# Author: Christian Limpach <Christian.Limpach@gmail.com>
# SPDX-License-Identifier: ISC
#

dist: $(DISTDIR)/.exists
dist:

ifeq (,$(patsubst tools/%,,$(SUBDIR)/))
dist: all
endif

tests:: .phony

V ?= 0

ifeq (0,$(V))
_V = @
_W = @
else
_W = @: :
endif

# Handle out-of-tree builds:
# - SRCDIR set indicates that the Makefile supports out-of-tree builds
# - empty BUILDIR causes a build in the source directory
ifneq (,$(SRCDIR))
submake = $(MAKE) --no-print-directory -C $(SRCDIR)/$(1) SRCDIR=$(SRCDIR)/$(1) $(2)
ifneq (,$(BUILDDIR))
ifneq (,$(filter $(abspath $(SRCDIR)),$(CURDIR)))
MAKENOW = y

.SUFFIXES:

.PHONY: $(BUILDDIR)
$(BUILDDIR):
	+@mkdir -p $@
	+@$(MAKE) --no-print-directory -C $@ \
	  -f $(CURDIR)/$(lastword $(subst /, ,$(firstword $(MAKEFILE_LIST)))) \
	  SRCDIR=$(CURDIR) $(MAKECMDGOALS)

Makefile : ;
GNUmakefile : ;
%.mk :: ;

% :: $(BUILDDIR) ; @:

clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)
endif
endif
else
submake = $(MAKE) --no-print-directory -C $(1) $(2)
endif # end of out-of-tree build support

ifeq (,$(MAKENOW))

relpath = $(shell echo $(1) | sed 's,[^/][^/]*,..,g')/$(2)
builddir = $(if $(subst $(BUILDDIR_default),,$(BUILDDIR)),$(BUILDDIR)/$(1),$(call relpath,$(BUILDDIR_default),$(1)/$(BUILDDIR_default)))

MAKEOVERRIDES := $(filter-out SRCDIR=$(SRCDIR),$(MAKEOVERRIDES))
MAKEFLAGS := $(filter-out SRCDIR=$(SRCDIR),$(MAKEFLAGS))
unexport SRCDIR

define include_lib
$(eval $(1)_BUILT := $(call builddir,$(2))/Makefile.lib-$(1));
$(eval -include $($(1)_BUILT));
$(eval $(1)_DEPS += $($(1)_BUILT));
$(eval $($(1)_DEPS):
	+@$(MAKE) --no-print-directory -C $(SRCDIR)/$(2) $(3) all);
endef

ifeq (,$(filter-out false 0 n no,$(DEBUG)))
DEBUG_ONLY=not-
REL_ONLY=
else
DEBUG_ONLY=
REL_ONLY=not-
endif

%/.exists:
	@mkdir -p $(@D)
	@touch $@

# Allow phony attribute to be listed as dependency rather than fake target
.PHONY: .phony
.phony:
	@ :

WINDOWS = $(filter-out windows,$(TARGET_HOST))
OSX = $(filter-out osx,$(TARGET_HOST))

$(WINDOWS)EXE_SUFFIX = .exe
$(OSX)EXE_SUFFIX =

HOST_WINDOWS = $(patsubst %,n-,$(filter-out MINGW32_NT-%,$(shell uname -s)))
HOST_LINUX = $(patsubst %,n-,$(filter-out Linux,$(shell uname -s)))
HOST_OSX = $(patsubst %,n-,$(filter-out Darwin,$(shell uname -s)))

HOST_NOT_WINDOWS = $(patsubst %,n-,$(filter MINGW32_NT-%,$(shell uname -s)))
HOST_NOT_LINUX = $(patsubst %,n-,$(filter Linux,$(shell uname -s)))
HOST_NOT_OSX = $(patsubst %,n-,$(filter Darwin,$(shell uname -s)))

$(HOST_WINDOWS)HOST_EXE_SUFFIX=.exe

$(HOST_WINDOW)HOST = windows
$(HOST_LINUX)HOST = linux
$(HOST_OSX)HOST = osx

subdirs-all subdirs-dist subdirs-clean subdirs-tests subdirs-install subdirs-distclean: .phony
	@set -e; for subdir in $(subst /,_,$(SUBDIRS) $(SUBDIRS-y)); do \
		$(call submake,.,subdir-$(patsubst subdirs-%,%,$@)-$$subdir); \
	done

subdir-all-% subdir-dist-% subdir-clean-% subdir-tests-% subdir-install-%: .phony
	@$(call submake,$(subst _,/,$*),$(patsubst subdir-%-$*,%,$@))

subdir-distclean-%: .phony
	$(MAKE) -C $* clean

endif # MAKENOW

ifeq (,$(MAKENOW))
ifneq (,$(SRCDIR))
$(SRCDIR)/Makefile.tests: .phony ;
$(SRCDIR)/tests/*.mk: .phony ;
-include $(SRCDIR)/Makefile.tests
-include $(SRCDIR)/tests/*.mk
endif
endif

debug-builddir:
	@printf "%-25s %s\n" "UXEN_BUILDDIR" "$(UXEN_BUILDDIR)"
	@printf "%-25s %s\n" "UXEN_BUILDDIR_$(SUBDIR1)" "$(UXEN_BUILDDIR_$(SUBDIR1))"
	@printf "%-25s %s\n" "UXEN_BUILDDIR_xen" "$(UXEN_BUILDDIR_xen)"
	@printf "%-25s %s\n" "TOPDIR" "$(TOPDIR)"
	@printf "%-25s %s\n" "TOPDIRN" "$(TOPDIRN)"
	@printf "%-25s %s\n" "SRCDIR" "$(SRCDIR)"
	@printf "%-25s %s\n" "_SRCDIR" "$(_SRCDIR)"
	@printf "%-25s %s\n" "abspath(_SRCDIR)" "$(abspath $(_SRCDIR))"
	@printf "%-25s %s\n" "SUBDIR" "$(SUBDIR)"
	@printf "%-25s %s\n" "SUBDIR1" "$(SUBDIR1)"
	@printf "%-25s %s\n" "SUBSUBDIR" "$(SUBSUBDIR)"
	@printf "%-25s %s\n" "BUILDDIR_top" "$(BUILDDIR_top)"
	@printf "%-25s %s\n" "BUILDDIR" "$(BUILDDIR)"
	@printf "%-25s %s\n" "BUILDDIR_$(SUBDIR1)" "$(BUILDDIR_$(SUBDIR1))"
	@printf "%-25s %s\n" "BUILDDIR_xen" "$(BUILDDIR_xen)"
