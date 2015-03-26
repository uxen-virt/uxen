#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

$(call include_lib,YAJL,../yajl)

ifeq (,$(MAKENOW))

SRCROOT = $(abspath $(TOPDIR)/common/hostconfig)

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile.hostconfig

dist: hostconfig$(EXE_SUFFIX)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

endif # MAKENOW
