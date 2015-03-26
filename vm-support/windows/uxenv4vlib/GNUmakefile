#
# Copyright 2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

DISTDIR_uxenv4vlib ?= $(DISTDIR_VM_SUPPORT)/uxenv4vlib
DISTDIR_uxenv4vlib := $(DISTDIR_uxenv4vlib)
export DISTDIR_uxenv4vlib
SDKDIR_lib_uxenv4vlib ?= $(DISTDIR_VM_SUPPORT)/uxenv4vlib
SDKDIR_lib_uxenv4vlib := $(SDKDIR_lib_uxenv4vlib)
export SDKDIR_lib_uxenv4vlib
SDKDIR_include_uxenv4vlib ?= $(DISTDIR_VM_SUPPORT)/uxenv4vlib
SDKDIR_include_uxenv4vlib := $(SDKDIR_include_uxenv4vlib)
export SDKDIR_include_uxenv4vlib
BUILDDIR_uxenv4vlib ?= $(shell mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && pwd)
BUILDDIR_uxenv4vlib := $(BUILDDIR_uxenv4vlib)
export BUILDDIR_uxenv4vlib

all dist clean install distclean: %: .phony
	@$(MAKE) -C $(TOPDIR)/windows/uxenv4vlib $*
