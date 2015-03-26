#
# Copyright 2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../..)
include $(TOPDIR)/Config.mk

SEABIOS := seabios

ifeq (,$(MAKENOW))

SRCROOT = $(abspath $(SRCDIR))

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile

endif # MAKENOW

clean::
	@$(MAKE) --no-print-directory -C ../../$(SEABIOS) clean
