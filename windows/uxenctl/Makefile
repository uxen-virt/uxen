#
# Copyright 2011-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

$(call include_lib,LIBXC,../libxc)

ifeq (,$(MAKENOW))

SRCROOT = $(abspath $(TOPDIR)/common/uxenctl)

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile.uxenctl

install_uxenctllib.h: uxenctllib.h uxenctllib-libxc.h $(SDKDIR_include)/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(SDKDIR_include))
	$(_W)echo Installing -- $(<F:uxenctllib.h=uxenctllib-libxc.h)
	$(_V)$(call install_data,$(<:uxenctllib.h=uxenctllib-libxc.h),$(SDKDIR_include))

install_libuxenctl.a: libuxenctl.a $(SDKDIR_lib)/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_lib)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_lib,$<,$(SDKDIR_lib))

dist: uxenctl$(EXE_SUFFIX) install_uxenctllib.h install_libuxenctl.a
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

endif # MAKENOW
