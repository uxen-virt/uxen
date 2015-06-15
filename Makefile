#
# Copyright 2011-2015, Bromium, Inc.
# Author: Christian Limpach <Christian.Limpach@gmail.com>
# SPDX-License-Identifier: ISC
#

TOPDIR = .
include $(TOPDIR)/Config.mk

SUBDIRS  =
SUBDIRS += xen
SUBDIRS += common/xen-tools/firmware
SUBDIRS += common/include
SUBDIRS += $(TARGET_HOST)

TARGETS = all dist clean

.PHONY: $(TARGETS)
$(TARGETS): %: subdirs-%

.PHONY: tools
tools:
	@$(MAKE) -C tools all

subdirs-all subdirs-dist: tools-check

TOOLS_UPDATE_TARGET = tools
$(HOST_WINDOWS)TOOLS_UPDATE_TARGET := tools-update

IGNORE_TOOLS_UPDATE = false

.PHONY: tools-check
tools-check:
	$(_W)echo Checking if tools are up-to-date...
	$(_V)git write-tree --prefix tools/ | \
	  cmp -s $(TOOLSDIR)/.tools_revision - || \
	  ( echo ERROR: tools need update -- make $(TOOLS_UPDATE_TARGET) >&2; \
	    $(IGNORE_TOOLS_UPDATE) )

tools-update: TOOLS_VERSION := $(shell git write-tree --prefix tools/)
tools-update:
	$(_W)[ -d $(TOOLSDIR)/.git ] || \
	  ( echo "UXEN_TOOLSDIR=$(TOOLSDIR) is not a git repository"; \
	    echo "Checkout the tools git repository:"; \
	    echo "  git clone --single-branch $(UXEN_TOOLS_GITREPO) $(TOOLSDIR)";\
	    echo "Or update manually to version $(TOOLS_VERSION)"; \
	    false )
	$(_V)[ -d $(TOOLSDIR)/.git ] || false
	$(_W)( cd $(TOOLSDIR) && \
	       git rev-parse tools-$(TARGET_HOST)-$(TOOLS_VERSION) >/dev/null 2>&1 || \
	       echo "Fetching version $(TOOLS_VERSION) from remote $(UXEN_TOOLS_GITREMOTE)" )
	$(_V)( cd $(TOOLSDIR) && \
	       git rev-parse tools-$(TARGET_HOST)-$(TOOLS_VERSION) >/dev/null 2>&1 || \
	       git fetch $(UXEN_TOOLS_GITREMOTE) refs/tags/tools-$(TARGET_HOST)-$(TOOLS_VERSION):refs/tags/tools-$(TARGET_HOST)-$(TOOLS_VERSION) )
	$(_W)echo "Updating tools in $(TOOLSDIR) to version $(TOOLS_VERSION)"
	$(_V)( cd $(TOOLSDIR) && \
	       git checkout -f tools-$(TARGET_HOST)-$(TOOLS_VERSION) )
