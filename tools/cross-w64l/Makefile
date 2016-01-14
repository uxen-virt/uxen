
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET = x86_64-w64-mingw32

XEN_DISTFILES ?= $(TOPDIR)/../distfiles

INSTALL_DIR = $(TOOLSDIR)/cross-w64l

BINUTILS_DISTFILES = binutils-2.25.1.tar.bz2
BINUTILS_PATCHES = binutils-link-pdata.patch binutils-cv8.patch binutils-install-libiberty.patch
BINUTILS_DIR = binutils-2.25.1

GCC_DISTFILES = gcc-4.9.3.tar.bz2
GCC_PATCHES = gcc-long.patch
GCC_DIR = gcc-4.9.3
GCC_VERSION = 4.9.3

MINGW64_DISTFILES = mingw-w64-v2.0.1.tar.gz
MINGW64_DIR = mingw-w64-v2.0.1

VPATH = $(SRCDIR)/patches:$(XEN_DISTFILES)

BUILD_ENV = PATH="$(TOOLSDIR)/bin:$$PATH"
ifeq (Darwin,$(shell uname))
BUILD_ENV += CPPFLAGS="-I/opt/local/include $$CPPFLAGS -g"
BUILD_ENV += LDFLAGS="-L/opt/local/lib $$LDFLAGS -g"
endif

BINUTILS_ENV = $(subst CPPFLAGS,CFLAGS,$(BUILD_ENV))

all: gcc/.core-installed

.PHONY: all clean

$(BUILDDIR:%=x)clean::
	rm -rf binutils gcc mingw64

binutils/.installed: binutils/.built
	cd $(@D)/build && $(BINUTILS_ENV) \
	  $(MAKE) install
	@touch $@

binutils/.built: binutils/.configured
	cd $(@D)/build && \
	  $(MAKE) $(BINUTILS_ENV)
	@touch $@

binutils/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
binutils/.configured: binutils/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BINUTILS_ENV) \
	  ../$(BINUTILS_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --target=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)-long-
	@touch $@
# XXX Todo add --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32

binutils/.patched: binutils/.extracted
binutils/.patched: $(BINUTILS_PATCHES)
	@for p in $(filter-out binutils/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(BINUTILS_DIR) && patch -p1); \
        done
	@touch $@

binutils/.extracted: $(BINUTILS_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar jxf -)
	@touch $@

gcc/.installed: gcc/.built
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) install
	@touch $@

# XXX This is broken with error: conflicting types for 'UINT64'
gcc/.built: mingw64/.installed
gcc/.built: gcc/.configured
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE)
	@touch $@

gcc/.core-installed: gcc/.core-built
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) install-gcc
# 	XXX installed gcc x86_64-w64-mingw32-gcc-4.9.3 is missing "-long"
	rm -f $(TOOLSDIR)/bin/$(CROSS_TARGET)-gcc-$(GCC_VERSION)$(HOST_EXE_SUFFIX)
	rm -f $(TOOLSDIR)/bin/$(CROSS_TARGET)-long-gcc-$(GCC_VERSION)
	cp $(TOOLSDIR)/bin/$(CROSS_TARGET)-long-gcc \
	  $(TOOLSDIR)/bin/$(CROSS_TARGET)-long-gcc-$(GCC_VERSION)
# enable these next lines if non-w64l gcc is the same version
#	[ ! -e $(TOOLSDIR)/bin/$(CROSS_TARGET)-gcc ] || \
#	  rm -f $(TOOLSDIR)/bin/$(CROSS_TARGET)-gcc-$(GCC_VERSION)
#	[ ! -e $(TOOLSDIR)/bin/$(CROSS_TARGET)-gcc ] || \
#	  cp $(TOOLSDIR)/bin/$(CROSS_TARGET)-gcc \
#	    $(TOOLSDIR)/bin/$(CROSS_TARGET)-gcc-$(GCC_VERSION)
	@touch $@

gcc/.core-built: gcc/.configured
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) all-gcc
	@touch $@

gcc/.configured: mingw64/.headers-installed binutils/.installed
gcc/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
gcc/.configured: gcc/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) \
	  ../$(GCC_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --target=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)-long- \
	    --enable-linker-build-id --with-system-zlib \
	    --without-included-gettext --disable-libssp --disable-libquadmath \
	    --enable-version-specific-runtime-libs --enable-threads=win32 \
	    --enable-fully-dynamic-string --enable-sjlj-exceptions \
	    --enable-languages="c" --enable-lto --with-plugin-ld \
        MAKEINFO=missing
	@touch $@
# XXX Todo: add --enable-targets=all

gcc/.patched: gcc/.extracted
gcc/.patched: $(GCC_PATCHES)
	@for p in $(filter-out gcc/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(GCC_DIR) && patch -p1); \
        done
	@touch $@

gcc/.extracted: $(GCC_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar jxf -)
	@touch $@

mingw64/.installed: mingw64/.built
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) install
	@touch $@

mingw64/.built: mingw64/.configured
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE)
	@touch $@

mingw64/.configured: gcc/.core-installed
mingw64/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
mingw64/.configured: mingw64/.extracted
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) \
	  ../$(MINGW64_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --host=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)-long-
	@touch $@
# XXX Todo add --enable-lib32

mingw64/.headers-installed: mingw64/.headers-configured
	cd $(@D)/build-headers && \
	  $(MAKE) install
	rm -rf $(INSTALL_DIR)/mingw
	ln -s x86_64-w64-mingw32 $(INSTALL_DIR)/mingw
	@touch $@

mingw64/.headers-configured: binutils/.installed
mingw64/.headers-configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
mingw64/.headers-configured: mingw64/.extracted
	@rm -rf $(@D)/build-headers
	@mkdir -p $(@D)/build-headers
	cd $(@D)/build-headers && $(BUILD_ENV) \
	  ../$(MINGW64_DIR)/mingw-w64-headers/configure \
	    --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --host=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)-long-
	@touch $@

mingw64/.extracted: mingw64/.exists
mingw64/.extracted: $(MINGW64_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: binutils/.exists gcc/.exists mingw64/.exists
binutils-%: binutils/.%
	@ :
gcc-%: gcc/.%
	@ :
mingw64-%: mingw64/.%
	@ :

endif # MAKENOW
