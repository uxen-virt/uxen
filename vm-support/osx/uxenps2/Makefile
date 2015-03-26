#
# Copyright 2013-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../../..
include $(TOPDIR)/Config.mk

$(DEBUG_ONLY)XCODECONF = Debug
$(REL_ONLY)XCODECONF = Release

XCODEBUILD = xcodebuild -configuration $(XCODECONF)

KEXTS = $(BUILDDIR)/$(XCODECONF)/uXenPS2Controller.kext

.PHONY: all dist
all: $(KEXTS)

.PHONY: $(KEXTS)

$(BUILDDIR)/$(XCODECONF)/uXenPS2Controller.kext:
	$(XCODEBUILD) build SYMROOT=$(BUILDDIR) -alltargets

dist: $(KEXTS)
	$(XCODEBUILD) install DSTROOT=$(DISTDIR_VM_SUPPORT) SYMROOT=$(BUILDDIR) -alltargets

.PHONY: clean
clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)
