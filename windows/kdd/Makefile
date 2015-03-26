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

SRCROOT = $(TOPDIR)/common/xen-tools/debugger/kdd

VPATH = $(SRCROOT)

CPPFLAGS += -I$(SRCROOT) $(LIBXC_CPPFLAGS) $(LIBUXENCTL_CPPFLAGS) -I$(TOPDIR)/common/include

all: kdd$(EXE_SUFFIX)
	@ :

kdd_SRCS  = kdd.c kdd-xen.c memmem.c winsyms.c
kdd_OBJS  = $(patsubst %.c,%.o,$(kdd_SRCS))
kdd_OBJS := $(subst /,_,$(kdd_OBJS))

OBJS = $(kdd_OBJS)
$(OBJS): .deps/.exists

LDLIBS += -le2fsprogs-uuid -ldbghelp

EXTRA_CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

kdd$(EXE_SUFFIX): $(kdd_OBJS) $(LIBXC_DEPS) $(LIBUXENCTL_DEPS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$(kdd_OBJS) $(LDLIBS) $(LIBXC_LIBS) $(LIBUXENCTL_LIBS))

$(kdd_OBJS): %.o : $(SRCROOT)/%.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $< -o $@

dist: kdd$(EXE_SUFFIX)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

-include .deps/*.d

endif # MAKENOW
