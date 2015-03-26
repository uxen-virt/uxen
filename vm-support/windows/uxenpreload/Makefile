#
# Copyright 2014-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

CFLAGS += -fno-stack-protector -mno-stack-arg-probe    
CPPFLAGS += -I$(TOPDIR)/windows/include

.PHONY: all
ifeq ($(TARGET_VM_SUPPORT_BITS),64)
all: uxenpreload.dll uxenpreload32.dll inject.exe
INSTALL_FILES = uxenpreload.dll uxenpreload32.dll inject.exe
else
all: uxenpreload.dll inject.exe
INSTALL_FILES = uxenpreload.dll inject.exe
endif

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxenpreload

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(INSTALL_DIR)

$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: %
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$(<),$(INSTALL_DIR))
dist: $(patsubst %,install_%,$(INSTALL_FILES))

preload.o preload32.o hook.o hook32.o inject.o: .deps/.exists

inject.exe: inject.o
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS))

uxenpreload.dll: preload.o hook.o
	$(_W)echo Linking - $@
	$(_V)$(CC) -m$(TARGET_VM_SUPPORT_BITS) -shared -Wl,--add-stdcall-alias -o $@ $^ -lpsapi

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

uxenpreload32.dll: preload32.o hook32.o
	$(_W)echo Linking - $@
	$(_V)$(CC) -m32 -shared -Wl,--add-stdcall-alias -o $@ $^ -lpsapi

%32.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) -m32 $< -o $@

-include .deps/*.d

endif # MAKENOW
