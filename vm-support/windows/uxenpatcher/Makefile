#
# Copyright 2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

CPPFLAGS += -I$(TOPDIR)/windows/include -I. -I$(TOPDIR)/vm-support/windows/common
LDFLAGS +=
LDLIBS += -lws2_32 -ldbghelp -lIphlpapi -lversion -lbcrypt

.PHONY: all
all: uxenpatcher.exe

INSTALL_FILES = uxenpatcher.exe

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxenpatcher

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(INSTALL_DIR)

$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: %
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$(<),$(INSTALL_DIR))
dist: $(patsubst %,install_%,$(INSTALL_FILES))

UXENPATCHER_OBJS = patcher.o logging.o defroute.o

$(UXENPATCHER_OBJS): .deps/.exists

uxenpatcher.exe: $(UXENPATCHER_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS))

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

-include .deps/*.d

endif # MAKENOW
