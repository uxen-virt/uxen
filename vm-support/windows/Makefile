#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../..
include $(TOPDIR)/Config.mk

SUBDIRS  =
SUBDIRS += uxendisp
SUBDIRS += uxenmouse
SUBDIRS += uxenaudio
SUBDIRS += uxenclipboard
SUBDIRS += uxenevent
SUBDIRS += uxendmpdrv
SUBDIRS += uxenkmdod
SUBDIRS += uxenplatform
#SUBDIRS += uxenstorflt
#SUBDIRS += uxenzeroshare
SUBDIRS += uxensvc
SUBDIRS += elevate
SUBDIRS += uxenpreload
SUBDIRS += uxenv4vguest
SUBDIRS += uxenstor
SUBDIRS += uxennet
SUBDIRS += uxensf
SUBDIRS += uxenhid
SUBDIRS += installer

TARGETS = all dist

.PHONY: $(TARGETS)

$(TARGETS): % : subdirs-%

$(patsubst %,subdir-all-%,$(SUBDIRS)) $(patsubst %,subdir-dist-%,$(SUBDIRS)) : \
	$(DISTDIR_VM_SUPPORT)/uxenvmlib/uxenvmlib.sys \
	$(DISTDIR_VM_SUPPORT)/uxenv4vlib/uxenv4vlib.sys

$(DISTDIR_VM_SUPPORT)/uxenvmlib/uxenvmlib.sys:
	@$(call submake,.,subdir-dist-uxenvmlib)
$(DISTDIR_VM_SUPPORT)/uxenv4vlib/uxenv4vlib.sys:
	@$(call submake,.,subdir-dist-uxenv4vlib)

.PHONY: clean
clean::
	$(_W)echo Cleaning - $(BUILDDIR)
	$(_V)rm -rf $(BUILDDIR)
