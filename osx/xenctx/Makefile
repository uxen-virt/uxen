#
# Copyright 2013-2016, Bromium, Inc.
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

VMSAVEFILE_DIR = $(abspath $(TOPDIR)/dm)
CUCKOODIR = $(TOPDIR)/common/cuckoo
CUCKOODIR_include = $(TOPDIR)/common/cuckoo

CPPFLAGS += -I$(SRCROOT) $(LIBXC_CPPFLAGS) $(LIBUXENCTL_CPPFLAGS) -I$(TOPDIR)/common/include

all: xenctx$(EXE_SUFFIX)
	@ :

vmsavefile_SRCS =
vmsavefile_SRCS += filebuf.c
vmsavefile_SRCS += vm-savefile-simple.c

vmsavefile_OBJS = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(vmsavefile_SRCS)))
vmsavefile_OBJS := $(subst /,_,$(patsubst %,vmsavefile/%,$(vmsavefile_OBJS)))
$(vmsavefile_OBJS): CFLAGS += -fms-extensions -Wno-microsoft -DSTDERR_LOG=1
$(vmsavefile_OBJS): CFLAGS += -I$(CUCKOODIR_include)

xenctx_SRCS  = xenctx.c
xenctx_OBJS  = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(xenctx_SRCS)))
xenctx_OBJS := $(subst /,_,$(patsubst %,xenctx/%,$(xenctx_OBJS)))
xenctx_OBJS += $(vmsavefile_OBJS)

OBJS = $(xenctx_OBJS)
$(OBJS): .deps/.exists

EXTRA_CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

xenctx$(EXE_SUFFIX): $(xenctx_OBJS) $(LIBXC_DEPS) $(LIBUXENCTL_DEPS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $(xenctx_OBJS) $(LDLIBS) $(LIBXC_LIBS) \
	  $(LIBUXENCTL_LIBS)

xenctx_%.o: $(SRCROOT)/%.c
	$(_W)echo Compiling - $(subst xenctx_,xenctx/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $< -o $@
xenctx_xenctx.o: CFLAGS += -I$(VMSAVEFILE_DIR) -U__BLOCKS__ #hack, otherwise dm/block.h is included

vmsavefile_%.o: $(VMSAVEFILE_DIR)/%.c
	$(_W)echo Compiling - $(subst vmsavefile_,dm/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

dist: xenctx$(EXE_SUFFIX)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

-include .deps/*.d

endif # MAKENOW
