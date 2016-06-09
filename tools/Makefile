
TOPDIR = ..
include $(TOPDIR)/Config.mk

SUBDIRS :=
SUBDIRS += host-all
SUBDIRS += host-$(HOST)
$(BUILD_WINDOWS_TOOLS)SUBDIRS += cross-w64l
$(BUILD_WINDOWS_TOOLS)SUBDIRS += cross-mingw
$(BUILD_WINDOWS_TOOLS)SUBDIRS += cross-windows
$(BUILD_OSX_TOOLS)SUBDIRS += cross-osx
SUBDIRS += cross-vm

.PHONY: all
all: subdirs-all $(TOOLSDIR)/.tools_revision

.PHONY: clean
clean: subdirs-clean

.PHONY: $(TOOLSDIR)/.tools_revision
$(TOOLSDIR)/.tools_revision:
	$(_W)echo Generating $(@F) in $(@D)
	$(_V)git write-tree --prefix tools/ >$@
