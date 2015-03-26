
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

XEN_DISTFILES ?= $(TOPDIR)/../distfiles

INSTALL_DIR = $(TOOLSDIR)/cross-windows

WDK8_DISTFILES = wdk8.tar.gz
WDK8_PATCHES = wdk8-no-sal.patch
WDK8_DIR = wdk8

VPATH = $(SRCDIR)/patches:$(SRCDIR)/files:$(XEN_DISTFILES)

all: wdk8/.installed

.PHONY: all clean

$(BUILDDIR:%=x)clean::
	rm -rf wdk8

wdk8/.installed: $(INSTALL_DIR)/.exists
wdk8/.installed: wdk8/.patched
	@install -d $(INSTALL_DIR)/wdk8
	cd $(@D)/$(WDK8_DIR) && \
	  cp -R inc lib $(INSTALL_DIR)/wdk8
	@touch $@

wdk8/.patched: wdk8/.extracted
wdk8/.patched: $(WDK8_PATCHES)
	@for p in $(filter-out wdk8/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(WDK8_DIR) && patch -p1); \
        done
	@touch $@

wdk8/.extracted: $(WDK8_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: wdk8/.exists

wdk8-%: wdk8/.%
	@ :

endif # MAKENOW
