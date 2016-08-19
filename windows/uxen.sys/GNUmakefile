#
# Copyright 2012-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../..
include $(TOPDIR)/Config.mk

ifneq (n-n-,$(HOST_WINDOWS)$(HOST_WINE))

$(HOST_NOT_WINE)sub_pwd = $(shell $(NATIVE_PWD) | sed 's,^[a-z]:/,,i')
$(HOST_WINE)sub_pwd = $(shell $(NATIVE_PWD) | sed 's,^/,,' | tr A-Z a-z)

$(HOST_NOT_WINE)BUILDDIR_XEN := $(subst /,\\,$(shell cd $(BUILDDIR_xen) && $(NATIVE_PWD)))
$(HOST_WINE)BUILDDIR_XEN := $(subst %,Z:%,$(subst /,\\,$(shell cd $(BUILDDIR_xen) && $(NATIVE_PWD) | tr A-Z a-z)))

ifneq (,$(BUILDDIR))
BUILDDIR_uxensys := $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
SET_OBJECT_ROOT := set OBJECT_ROOT=$(call dospath,$(BUILDDIR_uxensys))&
OBJDIR_uxensys := $(BUILDDIR_uxensys)/$(call sub_pwd)
else
BUILDDIR_uxensys := .
SET_OBJECT_ROOT :=
OBJDIR_uxensys := .
endif

SET_SIGN := set UXEN_WINDOWS_SIGN=$(UXEN_WINDOWS_SIGN)&

WIN_ARCH := $(subst 32,x86,$(subst 64,x64,$(TARGET_HOST_BITS)))
WIN_ARCH_obj := $(subst 32,x86/i386,$(subst 64,amd64/amd64,$(TARGET_HOST_BITS)))

OUTDIR_uxensys := $(OBJDIR_uxensys)/obj$(DDKENV)_win7_$(WIN_ARCH_obj)

.PHONY: all
all: $(OUTDIR_uxensys)/uxen.sys

# NOTE: no space after set foo=xxx since cmd otherwise includes the space in foo
.PHONY: $(OUTDIR_uxensys)/uxen.sys
$(HOST_NOT_WINE)$(OUTDIR_uxensys)/uxen.sys: $(OBJDIR_uxensys)/build_info.h
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)cmd /c "set UXEN_BUILD_INFO=\"\"\"../../build_info.h\"\"\"& set MAKEFLAGS=& set BUILDDIR_XEN=$(BUILDDIR_XEN)& $(SET_SIGN) $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(WIN_ARCH) WIN7 no_oacr & cd /D $$(pwd -W) & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxensys))"

$(HOST_WINE)$(OUTDIR_uxensys)/uxen.sys: $(OBJDIR_uxensys)/build.bat
	@mkdir -p $(@D)
	$(_W)echo WinDDK build $@
	$(_V)(cd $(OBJDIR_uxensys)/ && WINEDEBUG=-all wine cmd /c build.bat; e=$?; stty sane; exit $e)

ECHO = echo
$(HOST_OSX)ECHO = /bin/echo

$(OBJDIR_uxensys)/build.bat: $(OBJDIR_uxensys)/build_info.h
	$(_W)echo Generating $@
	$(_V)$(ECHO) "set UXEN_BUILD_INFO=\"\"\"$(call dospath,$(OBJDIR_uxensys)/build_info.h)\"\"\"& set MAKEFLAGS=& set BUILDDIR_XEN=$(BUILDDIR_XEN)& set UXEN_WINDOWS_SIGN=rem& $(WINDDK_DIR)\bin\setenv.bat $(WINDDK_DIR)\ $(DDKENV) $(WIN_ARCH) WIN7 no_oacr & z:& cd $$(pwd | sed 's,/,\\,g') & $(SET_OBJECT_ROOT) $(WINDDK_BUILD) -cZ -jpath $(call dospath,$(OBJDIR_uxensys))" >$@

.PHONY: $(OBJDIR_uxensys)/build_info.h
$(OBJDIR_uxensys)/build_info.h:
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	@( echo "#define UXEN_DRIVER_FILEVERSION1 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/\(....\)-..-../\1/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION2 " $$(git log --pretty=format:%cd --date=short -n 1 | sed 's/....-\(..\)-\(..\)/\1\2/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION3 " $$(( $$(git log --pretty=format:%ct -n 1) / 65536 )); \
	   echo "#define UXEN_DRIVER_FILEVERSION4 " $$(( $$(git log --pretty=format:%ct -n 1) % 65536 )); \
	   echo "#define UXEN_DRIVER_VERSION_CHANGESET \""$$(git log --pretty=format:%H -n 1 && git diff --quiet || echo -dirty)"\""; \
	   ) >$@

install_uxen.sys: $(OUTDIR_uxensys)/uxen.sys
	$(_W)echo
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(DISTDIR)
	$(_W)echo Installing - $(<F:sys=pdb)
	$(_V)install $(<:sys=pdb) $(DISTDIR)

install_uxenv4vlib.sys: $(OUTDIR_uxensys)/uxenv4vlib.sys
	$(_W)echo
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(DISTDIR)
	$(_W)echo Installing - $(<F:sys=pdb)
	$(_V)install $(<:sys=pdb) $(DISTDIR)

install_uxen.inf: $(TOPDIR)/windows/uxen.sys/uxen.inf
	$(_W)echo
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(DISTDIR))

dist: install_uxen.sys install_uxenv4vlib.sys install_uxen.inf

endif # HOST_WINDOWS

install_uxen_desc_sys.h: $(SDKDIR_include)/.exists
install_uxen_desc_sys.h: $(TOPDIR)/common/include/uxen_desc_sys.h
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(SDKDIR_include))

all:
dist: install_uxen_desc_sys.h

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)
$(BUILDDIR:%=x)clean::
	@rm -rf obj{chk,fre}_win7_amd64
	@rm -f build{chk,fre}_win7_amd64.{log,err,wrn}
