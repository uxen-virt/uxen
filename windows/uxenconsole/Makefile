#
# Copyright 2014-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

SRCROOT = $(abspath $(TOPDIR)/common/uxenconsole)

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile.uxenconsole

install_uxenconsolelib.h: uxenconsolelib.h $(SDKDIR_include)/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(SDKDIR_include))

install_libuxenconsole.a: libuxenconsole.a $(SDKDIR_lib)/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_lib)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_lib,$<,$(SDKDIR_lib))

install_console-dump: console-dump$(EXE_SUFFIX)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

dist: uxenconsole$(EXE_SUFFIX) install_console-dump install_uxenconsolelib.h install_libuxenconsole.a
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

endif # MAKENOW
