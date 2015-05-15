#
# Copyright 2012-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ..
include $(TOPDIR)/Config.mk

SUBDIRS  =
SUBDIRS += uxen.kext
SUBDIRS += uxenctl
SUBDIRS += vhd-util
SUBDIRS += libxc
SUBDIRS += uxendm
SUBDIRS += img-tools
SUBDIRS += cow-kext
SUBDIRS += hostconfig
SUBDIRS += uxenconsole
SUBDIRS += uxenv4vservice

TARGETS = all dist

.PHONY: $(TARGETS)

$(TARGETS): % : subdirs-%

.PHONY: clean
clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)

.PHONY: tools
tools:
	@$(MAKE) -C $(TOPDIR) $@
