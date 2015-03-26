#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)
VPATH += :$(TOPDIR)/common/uxen.os
VPATH += :$(TOPDIR)/xen/common/libelf
VPATH += :$(TOPDIR)/common/rbtree

KEXT_BIN = uxen
KEXT_DSYM = uxen.dwarf

CPPFLAGS += -D__XEN__ -D__UXEN_SYS__
CPPFLAGS += -D__UXEN_EMBEDDED__

CPPFLAGS += -I$(BUILDDIR_xen)/include \
	    -I$(TOPDIR)/xen/include \
	    -I$(TOPDIR)/common \
	    -I$(TOPDIR)/common/uxen.os \
	    -I$(TOPDIR)/common/include \
	    -I$(TOPDIR)/common/include/xen-public \
	    -I$(SRCDIR) \
	    -iquote $(SRCDIR)/../include \
	    -I.
$(DEBUG_ONLY)CPPFLAGS += -DDEBUG=1

CPPFLAGS += --sysroot $(OSX_SDK_ROOT)/

# Required stuff to build kext
CFLAGS += -mkernel -fno-builtin -fno-stack-protector \
	  -arch x86_64 -msoft-float -fno-common \
	  -mno-red-zone
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti -Wno-non-virtual-dtor \
	   -Wno-overloaded-virtual -Wno-exit-time-destructors 
CPPFLAGS += -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT \
	    -I$(OSX_SDK_ROOT)/System/Library/Frameworks/Kernel.framework/Headers

LDFLAGS = -Wall -mkernel -nostdlib -r -lcc_kext -lkmod -arch x86_64 \
	  -Xlinker -kext

CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

all: $(KEXT_BIN) $(KEXT_DSYM)

install_uxen_desc_sys.h: $(SDKDIR_include)/.exists
install_uxen_desc_sys.h: $(TOPDIR)/common/include/uxen_desc_sys.h
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(SDKDIR_include))

.PHONY: Info.plist
$(DEBUG_ONLY)Info.plist: $(SRCDIR)/uxen-Info.plist
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	$(_V)( epoch=$$(cd $(SRCDIR) && env TZ=UTC git log --pretty=format:%ct --date=local -n 1); \
	   major=$$((12 * ($$(date -r $$epoch +%Y | sed 's,^0*,,') - 2013) + $$(date -r $$epoch +%m | sed 's,^0*,,') - 1)); \
	   minor=$$(date -r $$epoch +%d | sed 's,^0*,,'); \
	   micro=$$(date -r $$epoch +%H | sed 's,^0*,,'); \
	   build=$$(($(date -r $$epoch +%M | sed 's,^0*,,') + 1)); \
	   sed "s/VERSION/$${major}.$${minor}.$${micro}d$${build}/" $^ ) > $@

$(REL_ONLY)Info.plist: $(SRCDIR)/uxen-Info.plist
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	@( epoch=$$(cd $(SRCDIR) && env TZ=UTC git log --pretty=format:%ct --date=local -n 1); \
	   major=$$((12 * ($$(date -r $$epoch +%Y | sed 's,^0*,,') - 2013) + $$(date -r $$epoch +%m | sed 's,^0*,,') - 1)); \
	   minor=$$(date -r $$epoch +%d | sed 's,^0*,,'); \
	   micro=$$(date -r $$epoch +%H | sed 's,^0*,,'); \
	   sed "s/VERSION/$${major}.$${minor}.$${micro}/" $^ ) > $@

dist: $(KEXT_BIN) $(KEXT_DSYM) Info.plist install_uxen_desc_sys.h
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F).kext
	$(_V)install -d $(DISTDIR)/uxen.kext/Contents/MacOS
	$(_V)install -m 0755 $(KEXT_BIN) $(DISTDIR)/uxen.kext/Contents/MacOS/
	$(_V)install -m 0644 Info.plist $(DISTDIR)/uxen.kext/Contents/
	$(_W)echo Installing -- $(<F).kext.dSYM
	$(_V)install -d $(DISTDIR)/uxen.kext.dSYM/Contents/Resources/DWARF
	$(_V)install -m 0644 $(KEXT_DSYM) \
	  $(DISTDIR)/uxen.kext.dSYM/Contents/Resources/DWARF/$(KEXT_BIN)

KEXT_OBJS = uxen.o \
            uxen_driver.o \
            uxen_client.o \
	    uxen_ops.o \
	    uxen_load.o \
	    uxen_mem.o \
	    uxen_physmap.o \
	    uxen_debug.o \
	    uxen_cpu.o \
	    uxen_sys.o \
	    uxen_time.o \
	    uxen_pm.o \
	    uxen_logging.o \
	    events.o \
	    memcache-dm.o \
	    libelf-loader.o \
	    libelf-relocate.o \
	    libelf-tools.o \
	    rbtree.o \
	    xnu_symbols.o \
	    $(BUILDDIR_xen)/uxen.macho

build_info.h:
	$(_W)echo Generating - $(@F)
	@mkdir -p $(@D)
	@( echo "#define UXEN_DRIVER_VERSION_CHANGESET \""$$(cd $(SRCDIR) && git log --pretty=format:%h -n 1 && git diff --quiet || echo -dirty)"\""; \
	   ) >$@

$(KEXT_OBJS): .deps/.exists

libelf-loader.o libelf-relocate.o libelf-tools.o: CPPFLAGS += -DNO_XEN_ELF_NOTE

$(KEXT_OBJS): build_info.h

$(KEXT_BIN): $(KEXT_OBJS)
	$(_W)echo Linking - $@.kext
	$(_V)$(LINK.o) -o $@ $^

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

libelf-loader.o: CPPFLAGS += -Delf_printk=uxen_dprintk
libelf-relocate.o: CPPFLAGS += -Delf_printk=uxen_dprintk
libelf-tools.o: CPPFLAGS += -Delf_printk=uxen_dprintk

-include .deps/*.d

endif # MAKENOW
