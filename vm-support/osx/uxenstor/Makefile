#
# Copyright 2015-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

$(DEBUG_ONLY)XCODECONF = Debug
$(REL_ONLY)XCODECONF = Release

XCODEBUILD = xcodebuild -configuration $(XCODECONF)

.PHONY: all dist
all: $(BUILDDIR)/$(XCODECONF)/uxenv4vstor.kext

.PHONY: $(BUILDDIR)/$(XCODECONF)/uxenv4vstor.kext
$(BUILDDIR)/$(XCODECONF)/uxenv4vstor.kext:
	$(XCODEBUILD) build SYMROOT=$(BUILDDIR)

dist: $(BUILDDIR)/$(XCODECONF)/uxenv4vstor.kext
	$(XCODEBUILD) install DSTROOT=$(DISTDIR_VM_SUPPORT) SYMROOT=$(BUILDDIR)

.PHONY: clean
clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)
