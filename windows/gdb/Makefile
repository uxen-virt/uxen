#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

XEN_DISTFILES ?= $(TOPDIR)/../distfiles

GDB_DISTFILES = gdb-7.4.tar.bz2
GDB_PATCHES = gdbserver-argv0.patch
GDB_DIR = gdb-7.4

VPATH := $(SRCDIR)/patches:$(SRCDIR)/files:$(XEN_DISTFILES):$(VPATH)

all: gdb/.installed

gdb/.installed: gdb/.built
	cp $(@D)/build/gdb/{gdb.exe,gdbserver/gdbserver.exe} $(DISTDIR)
	@touch $@

gdb/.built: gdb/.configured
	cd $(@D)/build && \
	  $(MAKE) $(BUILD_ENV)
	@touch $@

gdb/.configured: gdb/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) \
	  ../$(GDB_DIR)/configure \
	    --host=x86_64-w64-mingw32 \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32 \
	    --enable-gdbserver
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
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar jxf -)
	@touch $@

.SECONDARY: gdb/.exists
gdb-%: gdb/.%
	@ :

endif # MAKENOW
