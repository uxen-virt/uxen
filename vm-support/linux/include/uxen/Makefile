#
# Copyright 2016-2019, Bromium, Inc.
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

SDK_include_files = $(SDKDIR_include)/err.h

dist: $(SDK_include_files)

$(SDK_include_files) : $(SDKDIR_include)/% : % $(SDKDIR_include)/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(SDKDIR_include))

endif # MAKENOW
