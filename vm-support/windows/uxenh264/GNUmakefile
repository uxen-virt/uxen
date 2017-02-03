#
# Copyright 2017, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

ifneq (,$(BUILDDIR))
BUILDDIR_uxenh264 := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
INTDIR_uxenh264 := $(call dospath,$(BUILDDIR_uxenh264)/$(shell pwd -W | sed 's,^[a-z]:/,,i'))
else
BUILDDIR_uxenh264 := .
INTDIR_uxenh264 := .
endif

ifeq ($(DEBUG),1)
MSBUILD_CONFIGURATION := debug
else
MSBUILD_CONFIGURATION := release
endif

OUTDIR_uxenh264 := $(call dospath,$(DISTDIR_VM_SUPPORT)/uxenh264)

.PHONY: all
all: $(OUTDIR_uxenh264)/uxenh264.dll
dist: $(OUTDIR_uxenh264)/uxenh264.dll

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxenh264)/uxenh264.dll
$(OUTDIR_uxenh264)/uxenh264.dll:
	@mkdir -p $(@D)
	$(_W)echo EWDK build $@
	$(_V)cmd /c "$(EWDK_DIR)\BuildEnv\SetupBuildEnv.cmd x86 & msbuild uxenh264.vcxproj /verbosity:minimal /p:OutDir=$(OUTDIR_uxenh264)\,IntDir=$(INTDIR_uxenh264)\ /p:configuration=$(MSBUILD_CONFIGURATION),platform=Win32"
	$(_V)cmd //c $(UXEN_WINDOWS_SIGN) $(OUTDIR_uxenh264)/uxenh26432.dll ||  { rm -f $(OUTDIR_uxenh264)/uxenh26432.dll; false; }
	$(_V)cmd /c "$(EWDK_DIR)\BuildEnv\SetupBuildEnv.cmd amd64 & msbuild uxenh264.vcxproj /verbosity:minimal /p:OutDir=$(OUTDIR_uxenh264)\,IntDir=$(INTDIR_uxenh264)\ /p:configuration=$(MSBUILD_CONFIGURATION),platform=x64"
	$(_V)cmd //c $(UXEN_WINDOWS_SIGN) $(OUTDIR_uxenh264)/uxenh26464.dll ||  { rm -f $(OUTDIR_uxenh264)/uxenh26464.dll; false; }

clean::
	@$(if $(OUTDIR_uxenh264),rm -rf $(OUTDIR_uxenh264),:)
