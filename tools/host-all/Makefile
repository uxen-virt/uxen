
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

XEN_DISTFILES ?= $(TOPDIR)/../distfiles

CROSS_TARGET = x86_64-all

INSTALL_DIR = $(TOOLSDIR)/host-all

BINUTILS_DISTFILES = binutils-2.23.1.tar.bz2
BINUTILS_PATCHES = binutils-texinfo.patch binutils-string.patch
BINUTILS_PATCHES += binutils-macho-core.patch binutils-gcc-4.9.patch
BINUTILS_DIR = binutils-2.23.1

VPATH = $(SRCDIR)/patches:$(XEN_DISTFILES)

CONFIGURE = configure
CONFIGURE += --enable-strip

# on w64 -- use our toolchain
$(HOST_WINDOWS)BUILD_PATH += PATH="$(TOOLSDIR)/bin:$$PATH"
$(HOST_WINDOWS)CONFIGURE += --build x86_64-w64-mingw32 --host x86_64-w64-mingw32

BUILD_ENV = CFLAGS="$(BUILD_ENV_CFLAGS) $$CFLAGS"
BUILD_ENV += CPPFLAGS="$(BUILD_ENV_CPPFLAGS) $$CPPFLAGS"
BUILD_ENV += LDFLAGS="$(BUILD_ENV_LDFLAGS) $$LDFLAGS"
BINUTILS_ENV = CFLAGS="$(BUILD_ENV_CFLAGS) $(BUILD_ENV_CPPFLAGS) $$CFLAGS"
BINUTILS_ENV += LDFLAGS="$(BUILD_ENV_LDFLAGS) $$LDFLAGS"

all: binutils/.libbfd-installed #binutils/.installed

.PHONY: all clean

$(BUILDDIR:%=x)clean::
	rm -rf binutils

binutils/.installed: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
binutils/.installed: binutils/.built
	cd $(@D)/build && $(BINUTILS_ENV) $(BUILD_PATH) \
	  $(MAKE) install
	@touch $@

binutils/.built: binutils/.configured
	cd $(@D)/build && $(BUILD_PATH) \
	  $(MAKE) $(BINUTILS_ENV)
	@touch $@

binutils/.configured: binutils/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BINUTILS_ENV) $(BUILD_PATH) \
	  ../$(BINUTILS_DIR)/$(CONFIGURE) \
	    --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --program-prefix=$(CROSS_TARGET)- \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32,x86_64-elf,i686-elf,x86_64-apple-darwin \
	    --enable-ld=no \
	    --enable-static --disable-shared \
	    --disable-nls --disable-intl --without-zlib
	@touch $@

binutils/.patched: binutils/.extracted
binutils/.patched: $(BINUTILS_PATCHES)
	@for p in $(filter-out binutils/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(BINUTILS_DIR) && patch -p1); \
        done
	@touch $@

binutils/.extracted: $(BINUTILS_DISTFILES) $(BINUTILS_PATCHES)
	@rm -rf $(@D)/$(BINUTILS_DIR)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar jxf -)
	@touch $@

#binutils/.libbfd-installed: binutils/.installed
binutils/.libbfd-installed: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
binutils/.libbfd-installed: binutils/.libbfd-built
	cd $(@D)/build-libbfd && $(BINUTILS_ENV) $(BUILD_PATH) \
	  $(MAKE) install-libiberty install-bfd
	@install -d $(INSTALL_DIR)/include/mach-o
	install $(@D)/$(BINUTILS_DIR)/bfd/mach-o.h \
	  $(INSTALL_DIR)/include/
	install $(@D)/$(BINUTILS_DIR)/include/mach-o/loader.h \
	  $(INSTALL_DIR)/include/mach-o/
	@touch $@

binutils/.libbfd-built: binutils/.libbfd-configured
	cd $(@D)/build-libbfd && $(BUILD_PATH) \
	  $(MAKE) $(BINUTILS_ENV) all-libiberty all-bfd
	@touch $@

binutils/.libbfd-configured: binutils/.patched
	@rm -rf $(@D)/build-libbfd
	@mkdir -p $(@D)/build-libbfd
	cd $(@D)/build-libbfd && $(BINUTILS_ENV) $(BUILD_PATH) \
	  ../$(BINUTILS_DIR)/$(CONFIGURE) \
	    --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32,x86_64-elf,i686-elf,x86_64-apple-darwin \
	    --enable-ld=no \
	    --enable-static --disable-shared \
	    --disable-nls --disable-intl --without-zlib
	@touch $@

.SECONDARY: binutils/.exists
binutils-%: binutils/.%
	@ :

endif # MAKENOW
