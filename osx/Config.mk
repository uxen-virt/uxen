#
# Copyright 2012-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

UXEN_TARGET_FORMAT ?= elf

OSX_SDK_ROOT ?= # Empty for native

# everything below only for builds under osx/
ifeq (,$(patsubst $(TARGET_HOST)/%,,$(SUBDIR)/))

UXEN_OSX_SDK_VERSION ?= 10.9
UXEN_OSX_SDK_ROOT ?= $(abspath $(TOOLSDIR)/cross-osx/MacOSX$(UXEN_OSX_SDK_VERSION).sdk)

PATH := $(abspath $(TOOLSDIR)/cross-osx/xctoolchain-6.2/usr/bin):$(PATH)

# this is CC ?= but honouring CC from the environment
CC := $(if $(subst cc,,$(CC)),$(CC),cc)
CXX := $(if $(subst c++,,$(CXX)),$(CXX),c++)
AR := $(if $(subst ar,,$(AR)),$(AR),ar)
RANLIB := $(if $(subst ranlib,,$(RANLIB)),$(RANLIB),ranlib)
STRIP := $(if $(subst strip,,$(STRIP)),$(STRIP),strip)

CPPFLAGS += --sysroot=$(UXEN_OSX_SDK_ROOT)/
LDFLAGS += --sysroot=$(UXEN_OSX_SDK_ROOT)/
CFLAGS += -mmacosx-version-min=$(UXEN_OSX_SDK_VERSION)
ASFLAGS += -mmacosx-version-min=$(UXEN_OSX_SDK_VERSION)
LDFLAGS += -mmacosx-version-min=$(UXEN_OSX_SDK_VERSION)

CPPFLAGS += -I$(abspath $(TOPDIR)/osx/include)
CPPFLAGS += -I$(abspath $(TOPDIR)/common/include)
#CPPFLAGS += -I$(abspath $(TOOLSDIR)/cross-xxx/include)

CFLAGS_debug := $(subst $(CFLAG_OPTIMIZE_DEBUG),$(CFLAG_OPTIMIZE_DEBUG_legacy),$(CFLAGS_debug))

endif
