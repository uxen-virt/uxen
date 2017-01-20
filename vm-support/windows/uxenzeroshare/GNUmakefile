#
# Copyright 2013-2017, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

COMMONDIR=../common

ifneq (,$(BUILDDIR))
BUILDDIR_uxenzeroshare := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxenzeroshare))&
SET_COMMON_DIR  := set COMMON_DIR=$(call dospath,$(COMMONDIR))&
OBJDIR_uxenzeroshare := $(BUILDDIR_uxenzeroshare)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxenzeroshare := .
SET_OBJECT_ROOT :=
OBJDIR_uxenzeroshare := .
endif

SET_STAMPINF_DATE := set STAMPINF_DATE=$(shell TZ=GMT date +%m/%d/%Y)&

OUTDIR_uxenzeroshare := $(OBJDIR_uxenzeroshare)/uxenzeroshare/$(OBJDIR_ddk)

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxenzeroshare

INSTALL_FILES  = uxenzeroshare.sys
INSTALL_FILES += uxenzeroshare.pdb
INSTALL_FILES += uxenzeroshare.inf
INSTALL_FILES += uxenzeroshare.cat
INSTALL_FILES += uxenzeroshareconsole.exe
INSTALL_FILES += uxenzeroshareconsole.pdb
INSTALL_FILES += dbghelp.dll
INSTALL_FILES += symsrv.dll
INSTALL_FILES += symsrv.yes

.PHONY: all
all: $(OUTDIR_uxenzeroshare)/uxenzeroshare.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxenzeroshare)/uxenzeroshare.sys
$(OUTDIR_uxenzeroshare)/uxenzeroshare.sys:
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_COMMON_DIR) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxenzeroshare))"
	$(_W)echo Signing - $@
	$(_V)cmd //c $(UXEN_WINDOWS_SIGN) $@ || { rm -f $@; false; }

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(OUTDIR_uxenzeroshare)) to $(INSTALL_DIR)

VPATH += $(OUTDIR_uxenzeroshare)
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: $(OUTDIR_uxenzeroshare)/%
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$(<),$(INSTALL_DIR))

dist: $(patsubst %,install_%,$(INSTALL_FILES))

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf {exe,sys}/obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)
	@rm -f {exe,sys}/build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH).{log,err,wrn}

