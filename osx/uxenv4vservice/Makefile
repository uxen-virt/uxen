#
# Copyright 2015-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../..
include $(TOPDIR)/Config.mk

$(DEBUG_ONLY)XCODECONF = Debug
$(REL_ONLY)XCODECONF = Release

XCODEBUILD = xcodebuild -configuration $(XCODECONF)

.PHONY: all dist
all: $(BUILDDIR)/$(XCODECONF)/uxenv4vservice.kext

.PHONY: $(BUILDDIR)/$(XCODECONF)/uxenv4vservice.kext
$(BUILDDIR)/$(XCODECONF)/uxenv4vservice.kext:
	$(XCODEBUILD) build SYMROOT=$(BUILDDIR)

dist: $(BUILDDIR)/$(XCODECONF)/uxenv4vservice.kext
	$(XCODEBUILD) install DSTROOT=$(DISTDIR) SYMROOT=$(DISTDIR) INSTALL_PATH=/ TARGET_BUILD_DIR=$(BUILDDIR)/$(XCODECONF) PROJECT_TEMP_DIR=$(BUILDDIR)/$(XCODECONF)

.PHONY: clean
clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)
