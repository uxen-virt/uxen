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
all: $(BUILDDIR)/$(XCODECONF)/uxenhypercall.kext

.PHONY: $(BUILDDIR)/$(XCODECONF)/uxenhypercall.kext
$(BUILDDIR)/$(XCODECONF)/uxenhypercall.kext:
	$(XCODEBUILD) build SYMROOT=$(BUILDDIR)

dist: $(BUILDDIR)/$(XCODECONF)/uxenhypercall.kext
	$(XCODEBUILD) install DSTROOT=$(DISTDIR_VM_SUPPORT) SYMROOT=$(BUILDDIR)

.PHONY: clean
clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)
