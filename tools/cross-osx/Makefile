
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

INSTALL_DIR = $(CROSS_OSX_INSTALL_DIR)

OBJCONV_DISTFILES = objconv-2013-Jun-25.tar.bz2
OBJCONV_PATCHES = 
OBJCONV_DIR = objconv-2013-Jun-25
OBJCONV_CFLAGS="-Wno-logical-op-parentheses"

SDK_10_9_DISTFILES = MacOSX10.9.sdk.tar.bz2
SDK_10_9_DIR = MacOSX10.9.sdk

XCTOOLCHAIN_6_2_DISTFILES = xctoolchain-6.2.tar.bz2
XCTOOLCHAIN_6_2_DIR = xctoolchain-6.2

VPATH = $(SRCDIR)/patches:$(SRCDIR)/files:$(XEN_DISTFILES)

all: objconv/.installed sdk-10.9/.installed xctoolchain-6.2/.installed

.PHONY: all clean

clean:
	rm -rf objconv sdk-10.9 xctoolchain-6.2

objconv/.installed: $(TOOLSDIR)/bin/.exists
objconv/.installed: objconv/.built
	cp $(@D)/build/objconv $(TOOLSDIR)/bin
	@touch $@

objconv/.built: objconv/.patched
	@mkdir -p $(@D)/build
	cd $(@D)/build && \
	  g++ -o objconv -O2 ../$(OBJCONV_DIR)/*.cpp $(OBJCONV_CFLAGS)
	@touch $@

objconv/.patched: objconv/.extracted
objconv/.patched: $(OBJCONV_PATCHES)
	@for p in $(filter-out objconv/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(OBJCONV_DIR) && patch -p1); \
        done
	@touch $@

objconv/.extracted: $(OBJCONV_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar jxf -)
	@touch $@

.SECONDARY: objconv/.exists
objconv-%: objconv/.%
	@ :

sdk-10.9/.installed: sdk-10.9/.exists $(TOOLSDIR)/cross-osx/.exists
sdk-10.9/.installed: $(SDK_10_9_DISTFILES)
	@rm -rf $(TOOLSDIR)/$(SDK_10_9_DIR)
	cat $< | (cd $(TOOLSDIR)/cross-osx && tar jxf -)
	@touch $@

.SECONDARY: sdk-10.9/.exists
sdk-10.9-%: sdk-10.9/.%
	@ :

xctoolchain-6.2/.installed: xctoolchain-6.2/.exists
xctoolchain-6.2/.installed: $(TOOLSDIR)/cross-osx/.exists
xctoolchain-6.2/.installed: $(XCTOOLCHAIN_6_2_DISTFILES)
	@rm -rf $(TOOLSDIR)/$(XCTOOLCHAIN_6_2_DIR)
	cat $< | (cd $(TOOLSDIR)/cross-osx && tar jxf -)
	@touch $@

.SECONDARY: xctoolchain-6.2/.exists
xctoolchain-6.2-%: xctoolchain-6.2/.%
	@ :

endif # MAKENOW
