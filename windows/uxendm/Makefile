#
# Copyright 2012-2019, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

$(call include_lib,LIBVHD,../libvhd)
$(call include_lib,LIBATTOIMG,../attoimg)
$(call include_lib,LIBXC,../libxc)
$(call include_lib,LIBUXENCTL,../uxenctl)
$(call include_lib,YAJL,../yajl)
$(call include_lib,LIBFILECRYPT,../filecrypt)
$(call include_lib,LIBUXENCONSOLE,../uxenconsole)

ifeq (,$(MAKENOW))

SRCROOT = $(abspath $(TOPDIR)/dm)

VPATH = $(SRCROOT)

include $(SRCROOT)/Makefile.dm

endif # MAKENOW
