#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
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

OUTDIR_uxendisp := $(OBJDIR_uxendisp)/miniport/$(OBJDIR_ddk)

.PHONY: all
all: $(OUTDIR_uxendisp)/uxendisp.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxendisp)/uxendisp.sys
$(OUTDIR_uxendisp)/uxendisp.sys:
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_SIGN) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxendisp))"

INSTALL_FILES = uxendisp.sys
INSTALL_FILES += uxendisp.cat
INSTALL_FILES += uxendisp.inf
INSTALL_FILES += uxendisp.pdb
INSTALL_FILES += uxendispdd.dll
INSTALL_FILES += uxendispdd.pdb
INSTALL_FILES += devcon.exe
INSTALL_FILES += install.bat

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxendisp

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(OUTDIR_uxendisp)) to $(INSTALL_DIR)

VPATH += $(OUTDIR_uxendisp)
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: $(OUTDIR_uxendisp)/%
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$(<),$(INSTALL_DIR))

dist: $(patsubst %,install_%,$(INSTALL_FILES))

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH).{log,err,wrn}
