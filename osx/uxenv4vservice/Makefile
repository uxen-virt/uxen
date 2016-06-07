#
# Copyright 2015-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

KEXT_BIN = uxenv4vservice
KEXT_DSYM = $(KEXT_BIN).dwarf

CPPFLAGS += -I$(TOPDIR)/xen/include/public/ \
	    -I$(TOPDIR)/osx/include/ \
	    -I$(TOPDIR)/common/include/xen-public/
$(DEBUG_ONLY)CPPFLAGS += -DDEBUG=1

# Required stuff to build kext
CFLAGS += -mkernel -fno-builtin -fno-stack-protector \
	  -arch x86_64 -msoft-float -fno-common -fstrict-aliasing \
	  -mno-red-zone
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti -Wno-non-virtual-dtor \
	   -Wno-overloaded-virtual -Wno-exit-time-destructors -std=gnu++11 \
	   -Wno-deprecated-register \
	   -fapple-kext
CPPFLAGS += -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT \
	    -nostdinc \
	    -I$(UXEN_OSX_SDK_ROOT)/System/Library/Frameworks/Kernel.framework/Headers

LDFLAGS = -Wall -mkernel -nostdlib -r -lcc_kext -lkmod -arch x86_64 \
	  -Xlinker -kext
LDFLAFS += -lkmodc++

CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

all: $(KEXT_BIN) $(KEXT_DSYM)

.PHONY: Info.plist
$(DEBUG_ONLY)Info.plist: $(SRCDIR)/uxenv4vservice-Info.plist
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	$(_V)( epoch=$$(cd $(SRCDIR) && env TZ=UTC git log --pretty=format:%ct --date=local -n 1); \
	   major=$$((12 * ($$(date -r $$epoch +%Y | sed 's,^0*,,') - 2013) + $$(date -r $$epoch +%m | sed 's,^0*,,') - 1)); \
	   minor=$$(date -r $$epoch +%d | sed 's,^0*,,'); \
	   micro=$$(date -r $$epoch +%H | sed 's,^0*,,'); \
	   build=$$(($(date -r $$epoch +%M | sed 's,^0*,,') + 1)); \
	   sed "s/VERSION/$${major}.$${minor}.$${micro}d$${build}/" $^ ) > $@

$(REL_ONLY)Info.plist: $(SRCDIR)/uxenv4vservice-Info.plist
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	@( epoch=$$(cd $(SRCDIR) && env TZ=UTC git log --pretty=format:%ct --date=local -n 1); \
	   major=$$((12 * ($$(date -r $$epoch +%Y | sed 's,^0*,,') - 2013) + $$(date -r $$epoch +%m | sed 's,^0*,,') - 1)); \
	   minor=$$(date -r $$epoch +%d | sed 's,^0*,,'); \
	   micro=$$(date -r $$epoch +%H | sed 's,^0*,,'); \
	   sed "s/VERSION/$${major}.$${minor}.$${micro}/" $^ ) > $@

dist: $(KEXT_BIN) $(KEXT_DSYM) Info.plist
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F).kext
	$(_V)install -d $(DISTDIR)/$(<F).kext/Contents/MacOS
	$(_V)install -m 0755 $(KEXT_BIN) $(DISTDIR)/$(<F).kext/Contents/MacOS/
	$(_V)install -m 0644 Info.plist $(DISTDIR)/$(<F).kext/Contents/
	$(_W)echo Installing -- $(<F).kext.dSYM
	$(_V)install -d $(DISTDIR)/$(<F).kext.dSYM/Contents/Resources/DWARF
	$(_V)install -m 0644 $(KEXT_DSYM) \
	  $(DISTDIR)/$(<F).kext.dSYM/Contents/Resources/DWARF/$(KEXT_BIN)

KEXT_OBJS = v4v_device.o \
	    v4v_ops.o \
	    v4v_service.o \
	    v4v_user_ring.o

$(KEXT_OBJS): .deps/.exists $(SRCDIR)/uxenv4vservice.exports

$(KEXT_BIN): $(KEXT_OBJS)
	$(_W)echo Linking - $@.kext
	$(_V)$(LINK.o) -exported_symbols_list $(SRCDIR)/uxenv4vservice.exports -o $@ $^

$(KEXT_DSYM): $(KEXT_BIN)
	$(_W)echo Generating - $@
	$(_V)dsymutil -f $^

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
