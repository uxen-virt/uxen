#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

$(call include_lib,LIBVHD,../libvhd)

ifeq (,$(MAKENOW))

SRCROOT = $(TOPDIR)/common/vhd-util

VPATH = $(SRCROOT)

CPPFLAGS += -I$(SRCROOT) $(LIBVHD_CPPFLAGS)

all: vhd-util$(EXE_SUFFIX)
	@ :

vhd-util_SRCS  = vhd-util-check.c
vhd-util_SRCS += vhd-util-coalesce.c
vhd-util_SRCS += vhd-util-create.c
vhd-util_SRCS += vhd-util-fill.c
vhd-util_SRCS += vhd-util-modify.c
vhd-util_SRCS += vhd-util-query.c
vhd-util_SRCS += vhd-util-read.c
vhd-util_SRCS += vhd-util-repair.c
vhd-util_SRCS += vhd-util-resize.c
vhd-util_SRCS += vhd-util-revert.c
#vhd-util_SRCS += vhd-util-scan.c
vhd-util_SRCS += vhd-util-set-field.c
vhd-util_SRCS += vhd-util-snapshot.c
vhd-util_SRCS += vhd-util.c
vhd-util_OBJS  = $(patsubst %.c,%.o,$(vhd-util_SRCS))
vhd-util_OBJS := $(subst /,_,$(vhd-util_OBJS))

OBJS = $(vhd-util_OBJS)
$(OBJS): .deps/.exists

EXTRA_CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

vhd-util$(EXE_SUFFIX): $(vhd-util_OBJS) $(LIBVHD_DEPS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $(vhd-util_OBJS) $(LDLIBS) $(LIBVHD_LIBS)

$(vhd-util_OBJS): %.o : $(SRCROOT)/%.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $< -o $@

dist: vhd-util$(EXE_SUFFIX)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

-include .deps/*.d

endif # MAKENOW
