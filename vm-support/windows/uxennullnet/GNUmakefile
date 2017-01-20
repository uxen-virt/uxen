#
# Copyright 2015-2017, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

ifneq (,$(BUILDDIR))
BUILDDIR_uxennullnet := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxennullnet))&
OBJDIR_uxennullnet := $(BUILDDIR_uxennullnet)/$(shell pwd -W | sed 's,^[a-z]:/,,i')
else
BUILDDIR_uxennullnet := .
SET_OBJECT_ROOT :=
OBJDIR_uxennullnet := .
endif

SET_STAMPINF_DATE := set STAMPINF_DATE=$(shell TZ=GMT date +%m/%d/%Y)&

SET_UXENDIRS := set UXEN_DISTDIR_VM_SUPPORT=$(call dospath,$(DISTDIR_VM_SUPPORT))& set UXEN_SDKDIR_INCLUDE=$(call dospath,$(SDKDIR_include))& set UXEN_SDKDIR_LIB=$(call dospath,$(SDKDIR_lib))&

OUTDIR_uxennullnet := $(OBJDIR_uxennullnet)/$(OBJDIR_ddk)

.PHONY: all
all: $(OUTDIR_uxennullnet)/uxennullnet.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxennullnet)/uxennullnet.sys
$(OUTDIR_uxennullnet)/uxennullnet.sys: $(OBJDIR_uxennullnet)/build_info.h
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set UXEN_BUILD_INFO=\"\"\"../../build_info.h\"\"\"& set MAKEFLAGS=& $(SET_STAMPINF_DATE) $(SET_UXENDIRS) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME) $(UXEN_TARGET_VM_SUPPORT_OS) no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxennullnet))"
	$(_W)echo Signing - $@
	$(_V)cmd //c $(UXEN_WINDOWS_SIGN) $@ || { rm -f $@; false; }

.PHONY: $(OUTDIR_uxennullnet)/uxennullnet.cat
$(OUTDIR_uxennullnet)/uxennullnet.cat: $(OUTDIR_uxennullnet)/uxennullnet.sys
	$(_W)echo Signing - $@
	$(_V)cmd //c $(UXEN_WINDOWS_SIGN) $(call dospath, $@) || { rm -f $@; false; }

.PHONY: $(OBJDIR_uxennullnet)/build_info.h
$(OBJDIR_uxennullnet)/build_info.h:
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	@( echo "#define UXEN_DRIVER_FILEVERSION1 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/\(....\)-..-../\1/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION2 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/....-\(..\)-\(..\)/\1\2/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION3 " $$(( $$(git log --pretty=format:%ct -n 1) / 65536 )); \
	   echo "#define UXEN_DRIVER_FILEVERSION4 " $$(( $$(git log --pretty=format:%ct -n 1) % 65536 )); \
	   echo "#define UXEN_DRIVER_VERSION_CHANGESET \""$$(git log --pretty=format:%H -n 1 && git diff --quiet || echo -dirty)"\""; \
	   ) >$@

INSTALL_FILES =
INSTALL_FILES += uxennullnet.sys
INSTALL_FILES += uxennullnet.cat
INSTALL_FILES += uxennullnet.pdb
INSTALL_FILES += uxennullnet.inf
INSTALL_FILES += devcon.exe
INSTALL_FILES += install.bat

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxennullnet

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(OUTDIR_uxennullnet)) to $(INSTALL_DIR)

VPATH += $(OUTDIR_uxennullnet)
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: $(OUTDIR_uxennullnet)/%
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data) $(<) $(INSTALL_DIR)

dist: $(patsubst %,install_%,$(INSTALL_FILES))

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)
	@rm -f build{chk,fre}_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH).{log,err,wrn}

