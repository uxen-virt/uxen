#
# Copyright 2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

ifneq (,$(BUILDDIR))
BUILDDIR_uxennet := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxennet))&
OBJDIR_uxennet := $(BUILDDIR_uxennet)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxennet := .
SET_OBJECT_ROOT :=
OBJDIR_uxennet := .
endif

SET_SIGN := set UXEN_WINDOWS_SIGN=$(UXEN_WINDOWS_SIGN)&
SET_STAMPINF_DATE := set STAMPINF_DATE=$(shell TZ=GMT date +%m/%d/%Y)&

SET_UXENDIRS := set UXEN_DISTDIR_VM_SUPPORT=$(call dospath,$(DISTDIR_VM_SUPPORT))& set UXEN_SDKDIR_INCLUDE=$(call dospath,$(SDKDIR_include))& set UXEN_SDKDIR_LIB=$(call dospath,$(SDKDIR_lib))&

OUTDIR_uxennet := $(OBJDIR_uxennet)/$(OBJDIR_ddk)

.PHONY: all
all: $(OUTDIR_uxennet)/uxennet.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxennet)/uxennet.sys
$(OUTDIR_uxennet)/uxennet.sys: 
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_SIGN) $(SET_UXENDIRS) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxennet))"

INSTALL_FILES =
INSTALL_FILES += uxennet.sys
INSTALL_FILES += uxennet.cat
INSTALL_FILES += uxennet.pdb
INSTALL_FILES += uxennet.inf
INSTALL_FILES += devcon.exe
INSTALL_FILES += install.bat
INSTALL_FILES += uxenv4vlib.sys

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxennet

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(OUTDIR_uxennet)) to $(INSTALL_DIR)

VPATH += $(OUTDIR_uxennet)
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: $(OUTDIR_uxennet)/%
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data) $(<) $(INSTALL_DIR)

dist: $(patsubst %,install_%,$(INSTALL_FILES))

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH).{log,err,wrn}

