#
# Copyright 2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

SRCROOT = $(abspath $(SRCDIR))

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile

endif # MAKENOW
