#
# Copyright 2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../../..
include $(TOPDIR)/Config.mk

ifneq (,$(BUILDDIR))
BUILDDIR_uxendisp := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxendisp))&
OBJDIR_uxendisp := $(BUILDDIR_uxendisp)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxendisp := .
SET_OBJECT_ROOT :=
OBJDIR_uxendisp := .
endif

SET_SIGN := set UXEN_WINDOWS_SIGN=$(UXEN_WINDOWS_SIGN)&
SET_STAMPINF_DATE := set STAMPINF_DATE=$(shell TZ=GMT date +%m/%d/%Y)&

SET_UXENDIRS := set UXEN_DISTDIR_VM_SUPPORT=$(call dospath,$(DISTDIR_VM_SUPPORT))& set UXEN_SDKDIR_INCLUDE=$(call dospath,$(SDKDIR_include))& set UXEN_SDKDIR_LIB=$(call dospath,$(SDKDIR_lib))&

OUTDIR_uxendisp := $(OBJDIR_uxendisp)/miniport/$(OBJDIR_ddk)
OUTDIR_uxendisp32 := $(OBJDIR_uxendisp)/display/$(OBJDIR_ddk_32)

.PHONY: all
all: $(OUTDIR_uxendisp32)/uxend3d.dll $(OUTDIR_uxendisp)/uxendisp.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxendisp32)/uxend3d.dll $(OUTDIR_uxendisp)/uxendisp.sys
$(OUTDIR_uxendisp)/uxendisp.sys: $(OBJDIR_uxendisp)/build_info.h
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "del /F /Q /S $(call dospath,$(OUTDIR_uxendisp)/) >nul 2>&1"
	$(_V)cmd /c "xcopy /Y $(call dospath,$(OUTDIR_uxendisp32)/uxend3d.dll) $(call dospath,$(OUTDIR_uxendisp)/uxend3d32.dll)*"
	$(_V)cmd /c "set UXEN_BUILD_INFO=\"\"\"../../../build_info.h\"\"\"& set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_SIGN) $(SET_UXENDIRS) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -Z -jpath $(call dospath,$(OBJDIR_uxendisp))"

$(OUTDIR_uxendisp32)/uxend3d.dll:
	@mkdir -p $(@D)
	$(_W)echo WinDDK i386 build $@
	$(_V)cmd /c "set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_SIGN) $(SET_UXENDIRS) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME_32_BIT) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W)/display & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxendisp)/display)"

.PHONY: $(OBJDIR_uxendisp)/build_info.h
$(OBJDIR_uxendisp)/build_info.h:
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	@( echo "#define UXEN_DRIVER_FILEVERSION1 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/\(....\)-..-../\1/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION2 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/....-\(..\)-\(..\)/\1\2/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION3 " $$(( $$(git log --pretty=format:%ct -n 1) / 65536 )); \
	   echo "#define UXEN_DRIVER_FILEVERSION4 " $$(( $$(git log --pretty=format:%ct -n 1) % 65536 )); \
	   echo "#define UXEN_DRIVER_VERSION_CHANGESET \""$$(git log --pretty=format:%H -n 1 && git diff --quiet || echo -dirty)"\""; \
	   ) >$@

INSTALL_FILES = uxendisp.sys
INSTALL_FILES += uxendisp.cat
INSTALL_FILES += uxendisp.inf
INSTALL_FILES += uxendisp.pdb
INSTALL_FILES += uxend3d.dll
INSTALL_FILES += uxend3d.pdb
INSTALL_FILES += devcon.exe
INSTALL_FILES += install.bat

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxendisp/wddm

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(OUTDIR_uxendisp)) to $(INSTALL_DIR)

VPATH += $(OUTDIR_uxendisp)
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: $(OUTDIR_uxendisp)/%
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$(<),$(INSTALL_DIR))

install_uxend3d32.dll: _install_banner
install_uxend3d32.dll: $(OUTDIR_uxendisp32)/uxend3d.dll
	$(_W)echo Installing -- uxend3d32.dll
	$(_V)$(call install_data,$(<),$(INSTALL_DIR)/uxend3d32.dll)

dist: install_uxend3d32.dll $(patsubst %,install_%,$(INSTALL_FILES))

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH).{log,err,wrn}
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH_32_BIT)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH_32_BIT).{log,err,wrn}
