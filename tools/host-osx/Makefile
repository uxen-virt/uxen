
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET = x86_64-elf

INSTALL_DIR = $(HOST_OSX_INSTALL_DIR)

GDB_DISTFILES = gdb-1822-stripped.tar.gz
GDB_PATCHES = gdb-elf-target.patch gdb-elf-debug-sections.patch gdb-macosx-nat-inferior-setjmp.patch
GDB_DIR = gdb-1822

IASL_DISTFILES = acpica-unix2-20120711.tar.gz
IASL_PATCHES = iasl-llvm-gcc-fixes.patch
IASL_DIR = acpica-unix2-20120711

VPATH = $(SRCDIR)/patches:$(XEN_DISTFILES)

all: gdb/.installed iasl/.installed

.PHONY: all clean

$(BUILDDIR:%=x)clean::
	rm -rf iasl

GDB_BUILD_ENV  = RC_ARCHS=x86_64 RC_OS=macos RC_RELEASE=MountainLion
GDB_BUILD_ENV += MAKEINFO=/usr/bin/true
GDB_BUILD_ENV += CROSS_TARGETS=
GDB_BUILD_ENV += CONFIG_ALL_BFD_TARGETS="host_configargs=\"--enable-targets=x86_64-apple-darwin,x86_64-elf --disable-nls\""
# MAKEINFO=true to prevent the build from creating bfd-info* files in src tree
# --disable-nls to prevent the build from creating *.gmo files in src tree
$(HOST_OSX)GDB_BUILD_ENV += CFLAGS="-Wno-empty-body -Wno-string-plus-int -Wno-self-assign -Wno-uninitialized -Wno-pointer-sign -Wparentheses-equality -Wincompatible-pointer-types -Wconstant-logical-operand -Wincompatible-pointer-types-discards-qualifiers"
$(HOST_OSX)GDB_BUILD_ENV += CPP="cc -E"

gdb/.installed: gdb/.built
	cp $(@D)/build/x86_64-apple-darwin--x86_64-apple-darwin/gdb/gdb \
	  $(TOOLSDIR)/bin/x86_64-apple-darwin-gdb
	@touch $@

gdb/.built: $(TOOLSDIR)/bin/.exists gdb/build/.exists
gdb/.built: gdb/.patched
	cd $(@D)/$(GDB_DIR) && $(BUILD_ENV) \
	  $(MAKE) $(GDB_BUILD_ENV) OBJROOT=$(abspath $(@D)/build) build
	@touch $@

gdb/.patched: gdb/.extracted
gdb/.patched: $(GDB_PATCHES)
	@for p in $(filter-out gdb/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(GDB_DIR) && patch -p1); \
        done
	@touch $@

gdb/.extracted: $(GDB_DISTFILES)
	@rm -rf $(@D)/$(GDB_DIR)
	@mkdir -p $(@D)/$(GDB_DIR)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: gdb/.exists
gdb-%: gdb/.%
	@ :

iasl/.installed: iasl/.built
	cd $(@D)/$(IASL_DIR)/source/compiler && $(BUILD_ENV) \
	  $(MAKE) install \
            INSTALLPROG='cp -f $$(PROG) $$(INSTALLDIR)' \
	    INSTALLDIR=$(TOOLSDIR)/bin
	@touch $@

iasl/.built: $(TOOLSDIR)/bin/.exists
iasl/.built: iasl/.patched
	cd $(@D)/$(IASL_DIR)/source/compiler && $(BUILD_ENV) \
	  $(MAKE) INSTALLDIR=$(TOOLSDIR)/bin
	@touch $@

iasl/.patched: iasl/.extracted
iasl/.patched: $(IASL_PATCHES)
	@for p in $(filter-out iasl/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(IASL_DIR) && patch -p1); \
        done
	@touch $@

iasl/.extracted: $(IASL_DISTFILES)
	@rm -rf $(@D)/$(IASL_DIR)
	@mkdir -p $(@D)/$(IASL_DIR)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: iasl/.exists
iasl-%: iasl/.%
	@ :

endif # MAKENOW
