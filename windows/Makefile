#
# Copyright 2011-2018, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ..
include $(TOPDIR)/Config.mk

SUBDIRS  =
SUBDIRS += uxenv4vlib
SUBDIRS += uxenv4vproxy
SUBDIRS += uxen.sys
SUBDIRS += uxenctl
SUBDIRS += vhd-util
SUBDIRS += libxc
SUBDIRS += filecrypt
SUBDIRS += uxendm
SUBDIRS += backtrace
SUBDIRS += build
SUBDIRS += hostconfig
SUBDIRS += img-tools
SUBDIRS += include
SUBDIRS += kdd
SUBDIRS += xenctx
SUBDIRS += uxenconsole
SUBDIRS += v4vtest

TARGETS = all dist

.PHONY: $(TARGETS)

$(TARGETS): % : subdirs-%

.PHONY: clean
clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)

.PHONY: tests
tests:: subdirs-tests

.PHONY: tools
tools:
	@$(MAKE) -C $(TOPDIR) $@
