#
# Copyright 2015-2018, Bromium, Inc.
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

PROGRAMS := v4vtest$(EXE_SUFFIX) v4vtestrr$(EXE_SUFFIX)

_install_banner:
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(DISTDIR)

$(patsubst %,install_%,$(PROGRAMS)): install_%: % _install_banner
	$(_W)echo Installing -- $(<)
	$(_V)$(call install_exe,$(<),$(DISTDIR))

dist: $(patsubst %,install_%,$(PROGRAMS))

endif # MAKENOW
