#
# Copyright 2013-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

ifneq (,$(BUILDDIR))
BUILDDIR_uxensf := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxensf))&
OBJDIR_uxensf := $(BUILDDIR_uxensf)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxensf := .
SET_OBJECT_ROOT :=
OBJDIR_uxensf := .
endif

SET_SIGN := set UXEN_WINDOWS_SIGN=$(UXEN_WINDOWS_SIGN)&
SET_STAMPINF_DATE := set STAMPINF_DATE=$(shell TZ=GMT date +%m/%d/%Y)&

SET_UXENDIRS := set UXEN_DISTDIR_VM_SUPPORT=$(call dospath,$(DISTDIR_VM_SUPPORT))& set UXEN_SDKDIR_INCLUDE=$(call dospath,$(SDKDIR_include))& set UXEN_SDKDIR_LIB=$(call dospath,$(SDKDIR_lib))&

OUTDIR_uxensf := $(OBJDIR_uxensf)/driver/$(OBJDIR_ddk)
OUTDIR_mrxnp32 := $(OBJDIR_uxensf)/dll/$(OBJDIR_ddk_32)

.PHONY: all
all: $(OUTDIR_mrxnp32)/VBoxMRXNP.dll $(OUTDIR_uxensf)/uxensf.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxensf)/uxensf.sys $(OUTDIR_mrxnp32)/VBoxMRXNP.dll
$(OUTDIR_uxensf)/uxensf.sys:
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_SIGN) $(SET_UXENDIRS) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxensf))"

$(OUTDIR_mrxnp32)/VBoxMRXNP.dll:
	@mkdir -p $(@D)
	$(_W)echo WinDDK i386 build $@
	$(_V)cmd /c "set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_SIGN) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME_32_BIT) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W)/dll & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxensf)/dll)"

INSTALL_FILES = uxensf.sys
INSTALL_FILES += uxensf.inf
INSTALL_FILES += uxensf.pdb
INSTALL_FILES += VBoxMRXNP.dll
INSTALL_FILES += install.bat
# also install VBoxMRXNP32.dll, but this does not play well with patsubst

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxensf

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(OUTDIR_uxensf)) to $(INSTALL_DIR)

VPATH += $(OUTDIR_uxensf)
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: $(OUTDIR_uxensf)/%
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$(<),$(INSTALL_DIR))

install_VBoxMRXNP32.dll: $(OUTDIR_mrxnp32)/VBoxMRXNP.dll
	$(_W)echo Installing -- VBoxMRXNP32.dll
	$(_V)$(call install_data,$(<),$(INSTALL_DIR)/VBoxMRXNP32.dll)

dist: $(patsubst %,install_%,$(INSTALL_FILES)) install_VBoxMRXNP32.dll

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH).{log,err,wrn}
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH_32_BIT)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH_32_BIT).{log,err,wrn}
