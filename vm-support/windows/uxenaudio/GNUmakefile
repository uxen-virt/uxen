#
# Copyright 2013-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

ifneq (,$(BUILDDIR))
BUILDDIR_uxenaudio := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxenaudio))&
OBJDIR_uxenaudio := $(BUILDDIR_uxenaudio)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxenaudio := .
SET_OBJECT_ROOT :=
OBJDIR_uxenaudio := .
endif

SET_SIGN := set UXEN_WINDOWS_SIGN=$(UXEN_WINDOWS_SIGN)&
SET_STAMPINF_DATE := set STAMPINF_DATE=$(shell TZ=GMT date +%m/%d/%Y)&

OUTDIR_uxenaudio := $(OBJDIR_uxenaudio)/$(OBJDIR_ddk)

.PHONY: all
all: $(OUTDIR_uxenaudio)/uxenaudio.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxenaudio)/uxenaudio.sys
$(OUTDIR_uxenaudio)/uxenaudio.sys: 
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_SIGN) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxenaudio))"

INSTALL_FILES =
INSTALL_FILES += uxenaudio.sys
INSTALL_FILES += uxenaudio.cat
INSTALL_FILES += uxenaudio.pdb
INSTALL_FILES += uxenaudio.inf
INSTALL_FILES += devcon.exe
INSTALL_FILES += install.bat

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxenaudio

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(OUTDIR_uxenaudio)) to $(INSTALL_DIR)

VPATH += $(OUTDIR_uxenaudio)
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: $(OUTDIR_uxenaudio)/%
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$(<),$(INSTALL_DIR))

dist: $(patsubst %,install_%,$(INSTALL_FILES))

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH).{log,err,wrn}
