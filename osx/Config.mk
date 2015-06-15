#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

UXEN_TARGET_FORMAT ?= elf

OSX_SDK_ROOT ?= # Empty for native

# everything below only for builds under osx/
ifeq (,$(patsubst $(TARGET_HOST)/%,,$(SUBDIR)))

# this is CC ?= but honouring CC from the environment
CC := $(if $(subst cc,,$(CC)),$(CC),cc)
AR := $(if $(subst ar,,$(AR)),$(AR),ar)
RANLIB := $(if $(subst ranlib,,$(RANLIB)),$(RANLIB),ranlib)
STRIP := $(if $(subst strip,,$(STRIP)),$(STRIP),strip)

CPPFLAGS += -I$(abspath $(TOPDIR)/osx/include)
CPPFLAGS += -I$(abspath $(TOPDIR)/common/include)
#CPPFLAGS += -I$(abspath $(TOOLSDIR)/cross-xxx/include)

#LDFLAGS += 

endif
