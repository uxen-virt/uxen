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

CPPFLAGS += -I$(SRCDIR) -I$(TOPDIR)/vm-support/windows/uxensf/driver \
	-I$(TOPDIR)/dm/vbox-includes/include \
	$(LIBXC_CPPFLAGS) $(LIBUXENCTL_CPPFLAGS) \
	-I$(TOPDIR)/common/include -I$(TOPDIR) -I$(TOPDIR)/common/include/xen-public \
	-DVBOX -DIN_RING3 -DVBOX_WITH_HGCM -DVBOX_WITH_64_BITS_GUESTS \
	-DARCH_BITS=64 -DRT_OS_WINDOWS -DLOG_ENABLED -DLOG_USE_C99 \
	-DGC_ARCH_BITS=64 $(LIBXC_CPPFLAGS) $(LIBUXENCTL_CPPFLAGS)

UXENCLIPBOARD_OBJS=VBoxClipboard.o VBoxGuestR3LibClipboard.o hgcmcall.o \
    hgcm-simple.o rt.o RTErrConvertFromWin32.o channel.o defroute.o clipboardformats.o uxen_bmp_convert.o \
    clipboard-protocol.o

$(UXENCLIPBOARD_OBJS): .deps/.exists

uXenClipboard.exe: $(UXENCLIPBOARD_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ -mwindows -static-libgcc $(LDLIBS) -luser32 -lws2_32 -liphlpapi -lgdiplus -lole32)

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

INSTALL_FILES = uXenClipboard.exe

INSTALL_DIR = $(DISTDIR_VM_SUPPORT)/uxenclipboard

_install_banner: $(INSTALL_DIR)/.exists
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(INSTALL_DIR)

$(patsubst %,install_%,$(INSTALL_FILES)): install_%: _install_banner
$(patsubst %,install_%,$(INSTALL_FILES)): install_%: %
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$(<),$(INSTALL_DIR))
dist: $(patsubst %,install_%,$(INSTALL_FILES))

endif # MAKENOW
