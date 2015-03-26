#
# Copyright 2013-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

$(call include_lib,LIBXC,../libxc)
$(call include_lib,LIBUXENCTL,../uxenctl)

ifeq (,$(MAKENOW))

SRCROOT = $(TOPDIR)/common/xen-tools/xentrace

VPATH = $(SRCROOT)

CPPFLAGS += -I$(SRCROOT) $(LIBXC_CPPFLAGS) $(LIBUXENCTL_CPPFLAGS) -I$(TOPDIR)/common/include

all: xenctx$(EXE_SUFFIX)
	@ :

xenctx_SRCS  = xenctx.c save.c
xenctx_OBJS  = $(patsubst %.c,%.o,$(xenctx_SRCS))
xenctx_OBJS := $(subst /,_,$(xenctx_OBJS))

OBJS = $(xenctx_OBJS)
$(OBJS): .deps/.exists

LDLIBS += -le2fsprogs-uuid

EXTRA_CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

xenctx$(EXE_SUFFIX): $(xenctx_OBJS) $(LIBXC_DEPS) $(LIBUXENCTL_DEPS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$(xenctx_OBJS) $(LDLIBS) $(LIBXC_LIBS) $(LIBUXENCTL_LIBS))

$(xenctx_OBJS): %.o : $(SRCROOT)/%.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $< -o $@

dist: xenctx$(EXE_SUFFIX)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

-include .deps/*.d

endif # MAKENOW
