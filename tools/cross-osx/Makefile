
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

INSTALL_DIR = $(CROSS_OSX_INSTALL_DIR)

objconv_DISTFILES = objconv-2013-Jun-25.tar.bz2
objconv_PATCHES =
objconv_DIR = objconv-2013-Jun-25
objconv_CFLAGS="-Wno-logical-op-parentheses"

sdk_10_9_DISTFILES = MacOSX10.9.sdk.tar.bz2
sdk_10_9_DIR = MacOSX10.9.sdk

xctoolchain_6_2_DISTFILES = xctoolchain-6.2.tar.bz2
xctoolchain_6_2_DIR = xctoolchain-6.2

all: objconv/.installed sdk_10_9/.installed xctoolchain_6_2/.installed

PKGS += objconv
PKGS += sdk_10_9
PKGS += xctoolchain_6_2

# objconv
objconv/.installed: objconv/.built
	cp $(@D)/build/objconv $(INSTALL_BIN_DIR)/
	@touch $@
objconv/.built: objconv/.configured
	cd $(@D)/build && \
	  g++ -o objconv -O2 ../$(objconv_DIR)/*.cpp $(objconv_CFLAGS)
	@touch $@
objconv/.configured: objconv/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	@touch $@
$(eval $(call goal-patched,objconv))
$(eval $(call goal-extracted,objconv))

# sdk
sdk_10_9/.installed: $(sdk_10_9_DISTFILES)
	@mkdir -p $(@D)
	@rm -rf $(TOOLSDIR)/cross-osx/$(sdk_10_9_DIR)
	@mkdir -p $(TOOLSDIR)/cross-osx
	cat $< | (cd $(TOOLSDIR)/cross-osx && tar jxf -)
	@touch $@

# xctoolchain
xctoolchain_6_2/.installed: $(xctoolchain_6_2_DISTFILES)
	@mkdir -p $(@D)
	@rm -rf $(TOOLSDIR)/cross-osx/$(xctoolchain_6_2_DIR)
	@mkdir -p $(TOOLSDIR)/cross-osx
	cat $< | (cd $(TOOLSDIR)/cross-osx && tar jxf -)
	@touch $@

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
