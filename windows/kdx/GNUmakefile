#
# Copyright 2013-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../..
include $(TOPDIR)/Config.mk

ifeq (,$(HOST_WINDOWS))

BUILDDIR_XEN := $(subst /,\\,$(shell cd $(BUILDDIR_xen) && pwd -W))

ifneq (,$(BUILDDIR))
BUILDDIR_uxenkdx := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxenkdx))&
OBJDIR_uxenkdx := $(BUILDDIR_uxenkdx)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxenkdx := .
SET_OBJECT_ROOT :=
OBJDIR_uxenkdx := .
endif

SET_SIGN := set UXEN_WINDOWS_SIGN=$(UXEN_WINDOWS_SIGN)&

WIN_ARCH := $(subst 32,x86,$(subst 64,x64,$(TARGET_HOST_BITS)))
WIN_ARCH_obj := $(subst 32,x86/i386,$(subst 64,amd64/amd64,$(TARGET_HOST_BITS)))

OUTDIR_uxenkdx := $(OBJDIR_uxenkdx)/obj$(DDKENV)_win7_$(WIN_ARCH_obj)

.PHONY: all
all: $(OUTDIR_uxenkdx)/uxenkdx.dll

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxenkdx)/uxenkdx.dll
$(OUTDIR_uxenkdx)/uxenkdx.dll: $(OBJDIR_uxenkdx)/build_info.h
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set UXEN_BUILD_INFO=\"\"\"../../build_info.h\"\"\"& set MAKEFLAGS=& set BUILDDIR_XEN=$(BUILDDIR_XEN)& $(SET_SIGN) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(WIN_ARCH) WIN7 no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxenkdx))"

.PHONY: $(OBJDIR_uxenkdx)/build_info.h
$(OBJDIR_uxenkdx)/build_info.h:
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	@( echo "#define UXEN_DRIVER_FILEVERSION1 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/\(....\)-..-../\1/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION2 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/....-\(..\)-\(..\)/\1\2/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION3 " $$(( $$(git log --pretty=format:%ct -n 1) / 65536 )); \
	   echo "#define UXEN_DRIVER_FILEVERSION4 " $$(( $$(git log --pretty=format:%ct -n 1) % 65536 )); \
	   echo "#define UXEN_DRIVER_VERSION_CHANGESET \""$$(git log --pretty=format:%H -n 1 && git diff --quiet || echo -dirty)"\""; \
	   ) >$@

install_uxenkdx.dll: $(OUTDIR_uxenkdx)/uxenkdx.dll
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(DISTDIR)

dist: install_uxenkdx.dll

endif # HOST_WINDOWS

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_win7_amd64
	@rm -f build{chk,fre}_win7_amd64.{log,err,wrn}
