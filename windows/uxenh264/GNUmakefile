#
# Copyright 2017, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../..
include $(TOPDIR)/Config.mk

ifneq (,$(BUILDDIR))
BUILDDIR_uxenh264 := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
INTDIR_uxenh264 := $(call dospath,$(BUILDDIR_uxenh264)/$(shell pwd -W | sed 's,^[a-z]:/,,i'))
else
BUILDDIR_uxenh264 := .
INTDIR_uxenh264 := .
endif

ifeq ($(TARGET_HOST_BITS),32)
BUILDENV_ARCH := x86
MSBUILD_PLATFORM := Win32
else
BUILDENV_ARCH := amd64
MSBUILD_PLATFORM := x64
endif

ifeq ($(DEBUG),1)
MSBUILD_CONFIGURATION := debug
else
MSBUILD_CONFIGURATION := release
endif

OUTDIR_uxenh264 := $(call dospath,$(DISTDIR))

.PHONY: all
all: $(OUTDIR_uxenh264)/uxenh264.dll
dist: $(OUTDIR_uxenh264)/uxenh264.dll

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxenh264)/uxenh264.dll
$(OUTDIR_uxenh264)/uxenh264.dll: Makefile.lib-LIBUXENH264
	$(_W)echo EWDK build $@
	$(_V)make -C ../uxenconsole TARGET_HOST_BITS=$(TARGET_HOST_BITS) DEBUG=$(DEBUG)
	$(_V)cmd /c "$(EWDK_DIR)\BuildEnv\SetupBuildEnv.cmd $(BUILDENV_ARCH) & msbuild uxenh264.vcxproj /verbosity:minimal /p:OutDir=$(OUTDIR_uxenh264)\,IntDir=$(INTDIR_uxenh264)\ /p:configuration=$(MSBUILD_CONFIGURATION),platform=$(MSBUILD_PLATFORM)"

clean::
	@$(if $(BUILDDIR_uxenh264),rm -rf $(BUILDDIR_uxenh264),:)

Makefile.lib-LIBUXENH264:
	$(_V)rm -f $(BUILDDIR_uxenh264)/$@
	$(_V)echo "LIBUXENH264_RES = -D UXENH264_RES_ID=UXENH264 -D UXENH264_DLL_PATH=$(subst \,\\,$(OUTDIR_uxenh264)\\uxenh264.dll)" > $(BUILDDIR_uxenh264)/$@
	$(_V)echo "LIBUXENH264_DEPS = $(DISTDIR)/uxenh264.dll" >> $(BUILDDIR_uxenh264)/$@

