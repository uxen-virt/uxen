#
# Copyright 2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../..
include $(TOPDIR)/Config.mk

ifeq (,$(HOST_WINDOWS))

ifneq (,$(BUILDDIR))
BUILDDIR_uxenv4vlib ?= $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
BUILDDIR_uxenv4vlib := $(BUILDDIR_uxenv4vlib)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxenv4vlib))&
OBJDIR_uxenv4vlib := $(BUILDDIR_uxenv4vlib)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxenv4vlib := .
SET_OBJECT_ROOT :=
OBJDIR_uxenv4vlib := .
endif

DISTDIR_uxenv4vlib ?= $(DISTDIR)
SDKDIR_lib_uxenv4vlib ?= $(SDKDIR_lib)
SDKDIR_include_uxenv4vlib ?= $(SDKDIR_include)

WIN_ARCH := $(subst 32,x86,$(subst 64,x64,$(TARGET_HOST_BITS)))
WIN_ARCH_obj := $(subst 32,x86/i386,$(subst 64,amd64/amd64,$(TARGET_HOST_BITS)))

OUTDIR_uxenv4vlib := $(OBJDIR_uxenv4vlib)/obj$(DDKENV)_win7_$(WIN_ARCH_obj)

SET_SIGN := set UXEN_WINDOWS_SIGN=$(UXEN_WINDOWS_SIGN)&

.PHONY: all
all: $(OUTDIR_uxenv4vlib)/uxenv4vlib.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxenv4vlib)/uxenv4vlib.sys
$(OUTDIR_uxenv4vlib)/uxenv4vlib.sys: $(OBJDIR_uxenv4vlib)/build_info.h
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set UXEN_BUILD_INFO=\"\"\"../../build_info.h\"\"\"& set MAKEFLAGS=& $(SET_SIGN) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(WIN_ARCH) WIN7 no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxenv4vlib))"

.PHONY: $(OBJDIR_uxenv4vlib)/build_info.h
$(OBJDIR_uxenv4vlib)/build_info.h:
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	@( echo "#define UXEN_DRIVER_FILEVERSION1 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/\(....\)-..-../\1/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION2 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/....-\(..\)-\(..\)/\1\2/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION3 " $$(( $$(git log --pretty=format:%ct -n 1) / 65536 )); \
	   echo "#define UXEN_DRIVER_FILEVERSION4 " $$(( $$(git log --pretty=format:%ct -n 1) % 65536 )); \
	   echo "#define UXEN_DRIVER_VERSION_CHANGESET \""$$(git log --pretty=format:%H -n 1 && git diff --quiet || echo -dirty)"\""; \
	   ) >$@

install_uxenv4vlib.sys: $(OUTDIR_uxenv4vlib)/uxenv4vlib.sys $(SDKDIR_lib_uxenv4vlib)/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR_uxenv4vlib)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(DISTDIR_uxenv4vlib)
	$(_W)echo Installing - $(<F:sys=pdb)
	$(_V)install $(<:sys=pdb) $(DISTDIR_uxenv4vlib)
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_lib_uxenv4vlib)
	$(_W)echo Installing - $(<F:sys=lib)
	$(_V)install $(<:sys=lib) $(SDKDIR_lib_uxenv4vlib)

install_uxenv4vlib.h: uxenv4vlib.h $(SDKDIR_include_uxenv4vlib)/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include_uxenv4vlib)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(SDKDIR_include_uxenv4vlib)

dist: install_uxenv4vlib.sys install_uxenv4vlib.h

endif # HOST_WINDOWS

all:
dist:

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)

$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_win7_amd64
	@rm -f build{chk,fre}_win7_amd64.{log,err,wrn}

