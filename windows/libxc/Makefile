#
# Copyright 2013-2019, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

$(call include_lib,LIBATTOIMG,../attoimg)

ifeq (,$(MAKENOW))

SRCROOT = $(TOPDIR)/common/xen-tools/libxc

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile.libxc

endif # MAKENOW
