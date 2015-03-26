#
# Copyright 2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

#$(call include_lib,LIBXC,../libxc)
#$(call include_lib,LIBUXENCTL,../uxenctl)

ifeq (,$(MAKENOW))

SRCROOT = $(abspath $(TOPDIR)/common/v4v/v4vtest)

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile.v4vtest

dist: v4vtest$(EXE_SUFFIX) v4vtestrr$(EXE_SUFFIX)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

endif # MAKENOW
