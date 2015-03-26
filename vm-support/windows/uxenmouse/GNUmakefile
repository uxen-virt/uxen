#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

ifneq (,$(BUILDDIR))
BUILDDIR_uxenmouse := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxenmouse))&
OBJDIR_uxenmouse := $(BUILDDIR_uxenmouse)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxenmouse := .
SET_OBJECT_ROOT :=
OBJDIR_uxenmouse := .
endif

SET_SIGN := set UXEN_WINDOWS_SIGN=$(UXEN_WINDOWS_SIGN)&
SET_STAMPINF_DATE := set STAMPINF_DATE=$(shell TZ=GMT date +%m/%d/%Y)&

OUTDIR_uxenmouse := $(OBJDIR_uxenmouse)/$(OBJDIR_ddk)

.PHONY: all
all: $(OUTDIR_uxenmouse)/uxenmouse.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxenmouse)/uxenmouse.sys
$(OUTDIR_uxenmouse)/uxenmouse.sys:
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_SIGN) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxenmouse))"

INSTALL_FILES = uxenmouse.sys
INSTALL_FILES += uxenmouse.cat
INSTALL_FILES += uxenmouse.inf
INSTALL_FILES += uxenmouse.pdb
INSTALL_FILES += WdfCoInstaller01009.dll
INSTALL_FILES += devcon.exe
INSTALL_FILES += install.bat

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxenmouse

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(OUTDIR_uxenmouse)) to $(INSTALL_DIR)

VPATH += $(OUTDIR_uxenmouse)
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: $(OUTDIR_uxenmouse)/%
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$(<),$(INSTALL_DIR))

dist: $(patsubst %,install_%,$(INSTALL_FILES))

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH).{log,err,wrn}
