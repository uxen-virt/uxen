#
# Copyright 2013-2015, Bromium, Inc.
# Author: Christian Limpach <Christian.Limpach@gmail.com>
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

SRCROOT = $(SRCDIR)

VPATH = $(SRCROOT)

$(HOST_WINDOWS)CC := $(TOOLSDIR)/bin/x86_64-w64-mingw32-gcc

$(HOST_WINDOWS)CPPFLAGS += -I$(TOPDIR)/windows/include

all dist: xpdata-extract$(HOST_EXE_SUFFIX)
	@ :

xpdata_extract_SRCS = xpdata-extract.c
# xpdata_extract_SRCS += unwind-dump-pe.c
xpdata_extract_OBJS  = $(patsubst %.c,%.o,$(xpdata_extract_SRCS))
xpdata_extract_OBJS := $(subst /,_,$(xpdata_extract_OBJS))

MULTILIBDIR := $(TOOLSDIR)/host-all/lib/`$(CC) -print-multi-os-directory`
CPPFLAGS += -I$(TOOLSDIR)/host-all/include
xpdata_extract_LDLIBS = -L$(TOOLSDIR)/host-all/lib -L$(MULTILIBDIR) \
	-lbfd -liberty

xpdata-extract$(HOST_EXE_SUFFIX): $(xpdata_extract_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(xpdata_extract_LDLIBS))

unwind_dump_SRCS = unwind-dump.c unwind-dump-pe.c
unwind_dump_OBJS  = $(patsubst %.c,%.o,$(unwind_dump_SRCS))
unwind_dump_OBJS := $(subst /,_,$(unwind_dump_OBJS))

unwind-dump$(HOST_EXE_SUFFIX): $(unwind_dump_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(unwind_dump_LDLIBS))

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

OBJS = $(xpdata_extract_OBJS) $(unwind_dump_OBJS)
$(OBJS): .deps/.exists

-include .deps/*.d

endif # MAKENOW
