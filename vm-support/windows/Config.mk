#
# Copyright 2013-2017, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

# use WDK7 signtool for driver projects
ifneq (,$(shell find $(_SRCDIR) -name sources))
UXEN_WINDOWS_SIGN                       := $(WDK7_UXEN_WINDOWS_SIGN)
endif

UXEN_TARGET_VM_SUPPORT_OS               := win7

UXEN_TARGET_VM_SUPPORT_ARCH_32_BIT      := x86
UXEN_TARGET_VM_SUPPORT_ARCH_64_BIT      := amd64
UXEN_TARGET_VM_SUPPORT_ARCH_NAME_32_BIT := i386
UXEN_TARGET_VM_SUPPORT_ARCH_NAME_64_BIT := x64
UXEN_TARGET_VM_SUPPORT_CPU_32_BIT       := i386
UXEN_TARGET_VM_SUPPORT_CPU_64_BIT       := amd64

ifeq ($(TARGET_VM_SUPPORT_BITS),32)
UXEN_TARGET_VM_SUPPORT_ARCH             := $(UXEN_TARGET_VM_SUPPORT_ARCH_32_BIT)
UXEN_TARGET_VM_SUPPORT_CPU              := $(UXEN_TARGET_VM_SUPPORT_CPU_32_BIT)
UXEN_TARGET_VM_SUPPORT_ARCH_NAME        := $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME_32_BIT)
else
UXEN_TARGET_VM_SUPPORT_ARCH             := $(UXEN_TARGET_VM_SUPPORT_ARCH_64_BIT)
UXEN_TARGET_VM_SUPPORT_CPU              := $(UXEN_TARGET_VM_SUPPORT_CPU_64_BIT)
UXEN_TARGET_VM_SUPPORT_ARCH_NAME        := $(UXEN_TARGET_VM_SUPPORT_ARCH_NAME_64_BIT)
endif

OBJDIR_ddk = obj$(DDKENV)_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH)/$(UXEN_TARGET_VM_SUPPORT_CPU)
OBJDIR_ddk_32 = obj$(DDKENV)_$(UXEN_TARGET_VM_SUPPORT_OS)_$(UXEN_TARGET_VM_SUPPORT_ARCH_32_BIT)/$(UXEN_TARGET_VM_SUPPORT_CPU_32_BIT)
