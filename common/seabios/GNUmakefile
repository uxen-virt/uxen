#
# Copyright 2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

%:
	@$(call submake,.,-f Makefile OUT=$(BUILDDIR)/out/ $@)
