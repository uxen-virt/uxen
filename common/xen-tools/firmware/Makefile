#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

ifeq (,$(TOPDIR))
TOPDIR = ../../..
include $(TOPDIR)/Config.mk
endif

# hvmloader is a 32-bit protected mode binary.
TARGET      := hvmloader/hvmloader

SUBDIRS :=
#SUBDIRS += rombios
SUBDIRS += $(SEABIOS)
#SUBDIRS += vgabios
#SUBDIRS += etherboot

.PHONY: all
all: $(TARGET)

$(TARGET): subdirs-all
	@$(call submake,hvmloader,SEABIOS_DIR=$(call absdir_fmt,$(UXEN_BUILDDIR)/common/$(SEABIOS)) all)

export AR := x86_64-elf-ar
export AS := x86_64-elf-as
export CC := x86_64-elf-gcc
export LD := x86_64-elf-ld
export OBJCOPY := x86_64-elf-objcopy
export OBJDUMP := x86_64-elf-objdump
export RANLIB := x86_64-elf-ranlib
export STRIP := x86_64-elf-strip

subdir-all-$(SEABIOS): export HOSTCC ?= $(HOSTCC)
$(HOST_WINDOWS)subdir-all-$(SEABIOS): export HOST_EXTRACFLAGS += $(HOSTCFLAGS) -I$(abspath $(TOOLSDIR)/host-$(TARGET_HOST)/include)
$(HOST_WINDOWS)subdir-all-$(SEABIOS): export HOST_LOADLIBES += $(HOSTLDFLAGS) -lintl -L$(abspath $(TOOLSDIR)/host-$(TARGET_HOST)/lib) -lregex

subdir-all-$(SEABIOS):
	@$(call submake,../../$(SEABIOS),all)

subdir-clean-$(SEABIOS):
	@$(call submake,../../$(SEABIOS),clean)

.PHONY: dist
dist: $(TARGET)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(DISTDIR))

#.PHONY: clean distclean
#clean distclean: %: subdirs-%
#	$(MAKE) -C $(SRCDIR)/hvmloader $@

subdir-distclean-etherboot: .phony
	$(MAKE) -C etherboot distclean
