#
# Copyright 2019, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

SRCROOT = $(TOPDIR)/common/attoimg

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile.attoimg

endif # MAKENOW
