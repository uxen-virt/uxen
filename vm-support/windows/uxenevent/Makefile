#
# Copyright 2012-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

CPPFLAGS += -I$(TOPDIR)/windows/include

CPPFLAGS += -I$(TOPDIR)/vm-support/windows/uxendisp/xddm/include

CPPFLAGS += -I$(TOPDIR)/dm

CPPFLAGS += -I$(TOPDIR) -I$(TOPDIR)/common/include/xen-public

CPPFLAGS += -I$(TOPDIR) -I$(TOPDIR)/vm-support/windows/common

LDFLAGS += -mwindows
LDLIBS += -lws2_32 -luser32 -lgdi32 -liphlpapi -lsetupapi -lwtsapi32 -luserenv -lpdh

.PHONY: all
all: uxenevent.exe

INSTALL_FILES = uxenevent.exe

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxenevent

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(INSTALL_DIR)

$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: %
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$(<),$(INSTALL_DIR))
dist: $(patsubst %,install_%,$(INSTALL_FILES))

UXENEVENT_OBJS = uxenevent.o \
		 display.o \
		 defroute.o \
		 input.o \
		 logging.o \
		 perf_counters.o \
		 uxenevent-res.o \
		 window.o

$(UXENEVENT_OBJS): .deps/.exists

uxenevent.exe: $(UXENEVENT_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS))

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

%.o : %.rc
	$(_W)echo Compiling - $@
	$(_V)$(WINDRES) $(WINDRESFLAGS) $(WINDRES_TARGET_FORMAT_OPTION) $< -o $@

-include .deps/*.d

endif # MAKENOW
