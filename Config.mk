#
# Copyright 2011-2019, Bromium, Inc.
# Author: Christian Limpach <Christian.Limpach@gmail.com>
# SPDX-License-Identifier: ISC
#

TOPDIR ?= .
TOPDIR := $(abspath $(TOPDIR))

-include $(TOPDIR)/.config.mk

DEBUG ?= true
#DEBUG ?= false

TARGET_HOST ?= windows
TARGET_HOST_BITS ?= 64
TARGET_VM_SUPPORT ?= $(TARGET_HOST)
TARGET_VM_SUPPORT_BITS ?= $(TARGET_HOST_BITS)

_SRCDIR := $(if $(SRCDIR),$(SRCDIR),.)
SUBDIR := $(patsubst %/,%,$(subst $(TOPDIR)/,,$(abspath $(_SRCDIR))/))
SUBDIR1 := $(firstword $(subst /, ,$(SUBDIR)/.))
SUBSUBDIR := $(patsubst %/.,%,$(patsubst $(SUBDIR1)/%,%,$(SUBDIR)/.))
TOPDIRN := $(lastword $(subst /, ,$(TOPDIR)))
TARGET_HOST_BITS_32 := $(subst 32,-32,$(subst 64,,$(TARGET_HOST_BITS)))
TARGET_VM_SUPPORT_BITS_32 := $(subst 32,-32,$(subst 64,,$(TARGET_VM_SUPPORT_BITS)))
TARGET_HOST_DIR := $(TARGET_HOST)$(TARGET_HOST_BITS_32)
TARGET_VM_SUPPORT_DIR := $(TARGET_VM_SUPPORT)$(TARGET_VM_SUPPORT_BITS_32)
RELDIR := $(if $(filter-out false 0 n no,$(DEBUG)),,-release)
DEBUGDIR := $(if $(filter-out false 0 n no,$(DEBUG)),-debug,)

dir_fmt = $(patsubst %/,%,$(subst %l,$(TOPDIRN),$(subst %t,$(TOPDIR),$(subst %h,$(TARGET_HOST),$(subst %b,$(TARGET_HOST_BITS_32),$(subst %r,$(RELDIR),$(subst %d,$(DEBUGDIR),$(1))))))))
absdir_fmt = $(abspath $(call dir_fmt,$(1)))

UXEN_BUILDDIR ?= %t/build%b
UXEN_BUILDDIR_xen ?= $(UXEN_BUILDDIR)/xen.%h

BUILDDIR_top := $(call absdir_fmt,$(UXEN_BUILDDIR))
ifneq (,$(UXEN_BUILDDIR_$(SUBDIR1)))
BUILDDIR := $(call absdir_fmt,$(UXEN_BUILDDIR_$(SUBDIR1))/$(SUBSUBDIR))
else
BUILDDIR := $(call absdir_fmt,$(BUILDDIR_top)/$(SUBDIR))
endif
BUILDDIR_xen := $(call absdir_fmt,$(UXEN_BUILDDIR_xen))

TOOLSDIR := $(if $(UXEN_TOOLSDIR),$(UXEN_TOOLSDIR),$(abspath $(TOPDIR)/tools/install))

ifeq (,$(BUILDDIR))
override BUILDDIR := $(BUILDDIR_default)
endif

UXEN_TOOLS_GITREMOTE ?= origin
UXEN_TOOLS_GITREPO ?= https://git.uxen.org/tools/uxen-tools-$(HOST).git

ifneq (tools,$(SUBDIR1))
PATH := $(abspath $(TOOLSDIR)/bin):$(PATH)
endif

UXEN_DISTDIR ?= $(abspath $(TOPDIR)/dist)
UXEN_DISTDIR := $(call absdir_fmt,$(UXEN_DISTDIR))
DISTDIR = $(UXEN_DISTDIR)/$(TARGET_HOST_DIR)
DISTDIR_VM_SUPPORT = $(UXEN_DISTDIR)/vm-support-$(TARGET_VM_SUPPORT_DIR)
SDKDIR_include = $(UXEN_DISTDIR)/sdk-$(TARGET_HOST_DIR)/include
SDKDIR_lib = $(UXEN_DISTDIR)/sdk-$(TARGET_HOST_DIR)/lib
SDKDIR_src = $(UXEN_DISTDIR)/sdk-$(TARGET_HOST_DIR)/src

WINDRESFLAGS = -I$(TOPDIR)
ifeq ($(wildcard $(TOPDIR)/uxen-resources-local.h),)
else
WINDRESFLAGS += -DUXEN_RESOURCES_LOCAL
endif

UXEN_DIR = xen

include $(TOPDIR)/Rules.mk

$(WINDOWS)WINDOWS_NOT_YET = no_
$(WINDOWS_NOT_YET)WINDOWS_CONFIG_NOT = no_
$(WINDOWS_CONFIG_NOT)CPPFLAGS += -DWINDOWS_NOT_YET

$(OSX)OSX_NOT_YET = no_
$(OSX_NOT_YET)OSX_CONFIG_NOT = no_
$(OSX_CONFIG_NOT)CPPFLAGS += -DOSX_NOT_YET

UXENDM_VNCSERVER ?= no_
$(WINDOWS)UXENDM_VNCSERVER := no_
override UXENDM_VNCSERVER := $(filter-out true 1 y yes,$(UXENDM_VNCSERVER))

CFLAGS += -Werror -Wall

CFLAG_OPTIMIZE_DEBUG ?= -Og
CFLAG_OPTIMIZE_DEBUG_legacy ?= -O0
CFLAG_OPTIMIZE_DEFAULT ?= -O2
CFLAG_OPTIMIZE_HIGH ?= -O3
CFLAG_DEBUG ?= -g
$(REL_ONLY)CFLAGS_debug += $(CFLAG_OPTIMIZE_DEFAULT) $(CFLAG_DEBUG)
$(DEBUG_ONLY)CFLAGS_debug += $(CFLAG_OPTIMIZE_DEBUG) $(CFLAG_DEBUG)
$(DEBUG_ONLY)LDFLAGS_debug += $(CFLAG_DEBUG)
CFLAGS += $(CFLAGS_debug)
LDFLAGS += $(LDFLAGS_debug)

HOSTCC ?= cc
HOSTCFLAGS += $(CFLAGS)
HOSTLDFLAGS += $(LDFLAGS)
HOSTCFLAGS := $(subst $(CFLAG_OPTIMIZE_DEBUG),$(CFLAG_OPTIMIZE_DEBUG_legacy),$(HOSTCFLAGS))

# prefer python2, if it exists
PYTHON ?= $(shell `which python2 >/dev/null` && echo python2 || echo python)
export PYTHON
# don't generate pyc files
PYTHON := $(subst -B -B,-B,$(PYTHON) -B)

# REMOVEME
INSTALL_EXE = echo "Fatal: use install_exe function."; false
INSTALL_DATA = echo "Fatal: use install_data function."; false

link = $(LINK.o) -o $1 $2
sign = $2
install_lib = install $1 $2
install_data = install $1 $2
install_exe_strip = $(STRIP) -o $1 $2
install_exe = ([ -d $2 ] && set -e;                             \
               for src in $1; do                                \
                 f=$$(basename "$$src");                        \
                 dst="$2/$$f";                                  \
                 dbg="$2/debug/$$f";                            \
                 mkdir -p "$2/debug" &&                         \
                 install "$$src" "$$dbg" &&                     \
                 $(call install_exe_strip,"$$dst","$$dbg") || { \
                   rm -f "$$dst" "$$dbg";                       \
                   exit 1;                                      \
                 }                                              \
               done)

include $(TOPDIR)/$(TARGET_HOST)/Config.mk

# include tools config rules for tools build
ifeq (tools,$(SUBDIR1))
include $(TOPDIR)/tools/Config.mk
endif

# include vm-support config rules for vm-support build
ifeq (vm-support,$(SUBDIR1))
include $(TOPDIR)/vm-support/$(TARGET_VM_SUPPORT)/Config.mk
endif

.PHONY:
$(TOPDIR)/.config.mk::
	@ :
