#
# Copyright 2013-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../..
include $(TOPDIR)/Config.mk

SUBDIRS  =
SUBDIRS += uxendisp
SUBDIRS += uxenps2
SUBDIRS += uxenplatform
SUBDIRS += uxenvmlib
SUBDIRS += uxenv4vguest
SUBDIRS += uxennet
SUBDIRS += uxenstor

TARGETS = all dist

.PHONY: $(TARGETS)

$(TARGETS): % : subdirs-%

.PHONY: clean
clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)
