#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = $(abspath ..)
include $(TOPDIR)/Config.mk

all:
%::
	@$(MAKE) --no-print-directory -C $(TOPDIR)/$(TARGET_HOST)/uxendm $@

.PHONY: TAGS
TAGS:
	@($(MAKE) --no-print-directory -f Makefile.dm \
	  SRCROOT=$(abspath $(TOPDIR)/dm) \
	  src-files src-files-qemu src-files-slirp; \
	  find . -name \*.h | grep -v ./qemu ) | xargs etags -
