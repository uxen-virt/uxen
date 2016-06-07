#
# Copyright 2013-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

KEXT_BIN = cow

$(DEBUG_ONLY)CPPFLAGS += -DDEBUG=1

# Required stuff to build kext
CFLAGS += -mkernel -fno-builtin -fno-stack-protector \
	  -arch x86_64 -msoft-float -fno-common \
	  -mno-red-zone -Wno-error=\#warnings
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti -Wno-non-virtual-dtor \
	   -Wno-overloaded-virtual -Wno-exit-time-destructors 
CPPFLAGS += -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT \
	    -I$(UXEN_OSX_SDK_ROOT)/System/Library/Frameworks/Kernel.framework/Headers

LDFLAGS = -Wall -mkernel -nostdlib -r -lcc_kext -lkmod -arch x86_64 \
	  -Xlinker -kext

CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

all: $(KEXT_BIN)

dist: $(KEXT_BIN) $(SRCDIR)/Info.plist
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F).kext
	$(_V)install -d $(DISTDIR)/cow.kext/Contents/MacOS
	$(_V)install -m 0755 $(KEXT_BIN) $(DISTDIR)/cow.kext/Contents/MacOS/
	$(_V)install -m 0644 $(SRCDIR)/Info.plist $(DISTDIR)/cow.kext/Contents/

KEXT_OBJS = copy-on-write.o dlist.o

$(KEXT_OBJS): .deps/.exists

$(KEXT_BIN): $(KEXT_OBJS)
	$(_W)echo Linking - $@.kext
	$(_V)$(LINK.o) -o $@ $^

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

%.o: %.cpp
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.cpp) $< -o $@

%.o: %.S
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.S) $< -o $@

-include .deps/*.d

endif # MAKENOW
