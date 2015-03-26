#
# Copyright 2013-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

CPPFLAGS += -I$(TOPDIR)/windows/include -I.
LDFLAGS +=
LDLIBS += -lwtsapi32 -luserenv -ladvapi32 -lpsapi -lsetupapi

.PHONY: all
all: uxensvc.exe

INSTALL_FILES = uxensvc.exe

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxensvc

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(INSTALL_DIR)

$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: %
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$(<),$(INSTALL_DIR))
dist: $(patsubst %,install_%,$(INSTALL_FILES))

UXENSVC_OBJS = uxensvc.o \
	       session.o \
	       logging.o \
	       platform.o \
	       msg.res

msg.rc msg.h: msg.mc
	$(_W)echo Generating - msg.rc
	$(_W)echo Generating - msg.h
	$(_V)$(WINDMC) -U $<
uxensvc.o: msg.h
msg.res: msg.rc
	$(_W)echo Compiling - $@
	$(_V)$(WINDRES) --input $< --output $@ --output-format=coff $(WINDRES_TARGET_FORMAT_OPTION)

platform.o: CPPFLAGS += -I$(TOPDIR)/vm-support/windows/uxenplatform
platform.o: CPPFLAGS += -I$(TOPDIR)/common/include/xen-public -D__XEN_TOOLS__
session.o: CFLAGS += -Wno-unused-function

$(UXENSVC_OBJS): .deps/.exists

uxensvc.exe: $(UXENSVC_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS))

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

-include .deps/*.d

endif # MAKENOW
