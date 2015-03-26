#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

SRCROOT = $(abspath $(TOPDIR)/common/yajl)

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile.yajl

dist: all

endif # MAKENOW
