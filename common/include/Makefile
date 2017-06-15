#
# Copyright 2015-2017, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

all:
	@ :

SDK_include_files = $(SDKDIR_include)/err.h \
					$(SDKDIR_include)/dm-features.h \
					$(SDKDIR_include)/uxendisp-common.h \
					$(SDKDIR_include)/uxenhid-common.h

dist: $(SDK_include_files)

$(SDK_include_files) : $(SDKDIR_include)/% : % $(SDKDIR_include)/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(SDKDIR_include))

endif # MAKENOW
