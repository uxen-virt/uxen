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

CPPFLAGS += -I$(TOPDIR)/windows/include

LDFLAGS += -mwindows
LDLIBS += 

.PHONY: all
all: elevate.exe

INSTALL_FILES = elevate.exe

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/elevate

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(INSTALL_DIR)

$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: %
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$(<),$(INSTALL_DIR))
dist: $(patsubst %,install_%,$(INSTALL_FILES))

ELEVATE_OBJS = elevate.o

$(ELEVATE_OBJS): .deps/.exists

elevate.exe: $(ELEVATE_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS))

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

-include .deps/*.d

endif # MAKENOW
