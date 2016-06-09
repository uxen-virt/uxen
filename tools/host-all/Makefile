
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET = x86_64-all

INSTALL_DIR = $(HOST_ALL_INSTALL_DIR)
INSTALL32_DIR = $(HOST_ALL_32_INSTALL_DIR)

BINUTILS_DISTFILES = binutils-2.25.1.tar.bz2
BINUTILS_PATCHES = binutils-macho-core.patch binutils-install-libiberty.patch
BINUTILS_PATCHES += binutils-reloc-section.patch
BINUTILS_DIR = binutils-2.25.1

MPFR_DISTFILES = mpfr-3.1.3.tar.bz2
MPFR_PATCHES =
MPFR_DIR = mpfr-3.1.3

GMP_DISTFILES = gmp-6.1.0.tar.bz2
GMP_PATCHES =
GMP_DIR = gmp-6.1.0

MPC_DISTFILES = mpc-1.0.3.tar.gz
MPC_PATCHES =
MPC_DIR = mpc-1.0.3

VPATH = $(SRCDIR)/patches:$(XEN_DISTFILES)

CONFIGURE = configure
CONFIGURE += --enable-strip
BINUTILS_CONFIGURE = $(CONFIGURE)

# on windows -- use our toolchain
$(HOST_WINDOWS)BINUTILS_BUILD_PATH += PATH="$(TOOLSDIR)/bin:$$PATH"
$(HOST_WINDOWS)BINUTILS_CONFIGURE += --build x86_64-w64-mingw32 --host x86_64-w64-mingw32

BUILD_ENV = CFLAGS="$(BUILD_ENV_CFLAGS) $$CFLAGS"
BUILD_ENV += CPPFLAGS="$(BUILD_ENV_CPPFLAGS) $$CPPFLAGS"
BUILD_ENV += LDFLAGS="$(BUILD_ENV_LDFLAGS) $$LDFLAGS"
BINUTILS_ENV = CFLAGS="$(BUILD_ENV_CFLAGS) $(BUILD_ENV_CPPFLAGS) $$CFLAGS"
BINUTILS_ENV += LDFLAGS="$(BUILD_ENV_LDFLAGS) $$LDFLAGS"

BUILD_ENV32 = CFLAGS="-m32 $(BUILD_ENV_CFLAGS) $$CFLAGS"
BUILD_ENV32 += CPPFLAGS="$(BUILD_ENV_CPPFLAGS) $$CPPFLAGS"
BUILD_ENV32 += LDFLAGS="-m32 $(BUILD_ENV_LDFLAGS) $$LDFLAGS"
BINUTILS_ENV32 = CFLAGS="-m32 $(BUILD_ENV_CFLAGS) $(BUILD_ENV_CPPFLAGS) $$CFLAGS"
BINUTILS_ENV32 += LDFLAGS="-m32 $(BUILD_ENV_LDFLAGS) $$LDFLAGS"

all: gmp/.installed mpfr/.installed mpc/.installed
all: binutils/.libbfd-installed binutils/.libbfd-installed32
#binutils/.installed

.PHONY: all clean

$(BUILDDIR:%=x)clean::
	rm -rf binutils

binutils/.installed: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
binutils/.installed: binutils/.built
	cd $(@D)/build && $(BINUTILS_ENV) $(BINUTILS_BUILD_PATH) \
	  $(MAKE) install
	@touch $@

binutils/.built: binutils/.configured
	cd $(@D)/build && $(BINUTILS_BUILD_PATH) \
	  $(MAKE) $(BINUTILS_ENV)
	@touch $@

$(HOST_WINDOWS)binutils/.configured: binutils/.cross-mingw-gcc-installed
binutils/.configured: binutils/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BINUTILS_ENV) $(BINUTILS_BUILD_PATH) \
	  ../$(BINUTILS_DIR)/$(BINUTILS_CONFIGURE) \
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
	cd $(@D)/build-libbfd && $(BINUTILS_ENV) $(BINUTILS_BUILD_PATH) \
	  $(MAKE) install-libiberty install-bfd
	@install -d $(INSTALL_DIR)/include/mach-o
	install $(@D)/$(BINUTILS_DIR)/bfd/mach-o.h \
	  $(INSTALL_DIR)/include/
	install $(@D)/$(BINUTILS_DIR)/include/mach-o/loader.h \
	  $(INSTALL_DIR)/include/mach-o/
	@touch $@

binutils/.libbfd-built: binutils/.libbfd-configured
	cd $(@D)/build-libbfd && $(BINUTILS_BUILD_PATH) \
	  $(MAKE) $(BINUTILS_ENV) all-libiberty all-bfd
	@touch $@

$(HOST_WINDOWS)binutils/.libbfd-configured: binutils/.cross-mingw-gcc-installed
binutils/.libbfd-configured: binutils/.patched
	@rm -rf $(@D)/build-libbfd
	@mkdir -p $(@D)/build-libbfd
	cd $(@D)/build-libbfd && $(BINUTILS_ENV) $(BINUTILS_BUILD_PATH) \
	  ../$(BINUTILS_DIR)/$(BINUTILS_CONFIGURE) \
	    --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32,x86_64-elf,i686-elf,x86_64-apple-darwin \
	    --enable-ld=no \
	    --enable-static --disable-shared \
	    --disable-nls --disable-intl --without-zlib
	@touch $@

binutils/.libbfd-installed32: $(TOOLSDIR)/bin/.exists $(INSTALL32_DIR)/.exists
binutils/.libbfd-installed32: binutils/.libbfd-built32
	cd $(@D)/build32-libbfd && $(BINUTILS_ENV32) $(BINUTILS_BUILD_PATH) \
	  $(MAKE) install-libiberty install-bfd
	install $(@D)/$(BINUTILS_DIR)/bfd/mach-o.h \
	  $(INSTALL32_DIR)/include/
	@install -d $(INSTALL32_DIR)/include/mach-o
	install $(@D)/$(BINUTILS_DIR)/include/mach-o/loader.h \
	  $(INSTALL32_DIR)/include/mach-o/
	@touch $@

binutils/.libbfd-built32: binutils/.libbfd-configured32
	cd $(@D)/build32-libbfd && $(BINUTILS_BUILD_PATH) \
	  $(MAKE) $(BINUTILS_ENV32) all-libiberty all-bfd
	@touch $@

$(HOST_WINDOWS)binutils/.libbfd-configured32: binutils/.cross-mingw-gcc-installed
binutils/.libbfd-configured32: binutils/.patched
	@rm -rf $(@D)/build32-libbfd
	@mkdir -p $(@D)/build32-libbfd
	cd $(@D)/build32-libbfd && $(BINUTILS_ENV32) $(BINUTILS_BUILD_PATH) \
	  ../$(BINUTILS_DIR)/$(BINUTILS_CONFIGURE) \
	    --prefix=$(INSTALL32_DIR) \
	    --with-sysroot=$(INSTALL32_DIR) \
	    --bindir=$(INSTALL32_DIR)/i686-all/bin \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32,x86_64-elf,i686-elf,x86_64-apple-darwin \
	    --enable-ld=no \
	    --enable-static --disable-shared \
	    --disable-nls --disable-intl --without-zlib
	@touch $@

binutils/.cross-mingw-gcc-installed: gmp/.installed
binutils/.cross-mingw-gcc-installed: mpfr/.installed
binutils/.cross-mingw-gcc-installed: mpc/.installed
binutils/.cross-mingw-gcc-installed:
	@$(MAKE) -C $(SRCDIR)/../cross-mingw gcc-installed
	@mkdir -p $(@D)
	@touch $@

.SECONDARY: binutils/.exists
binutils-%: binutils/.%
	@ :

gmp/.installed: gmp/.built
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) install
	@touch $@

gmp/.built: gmp/.configured
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE)
	@touch $@

$(HOST_WINDOWS)GMP_EXTRA_CONFIGURE += --build=i686-pc-mingw32
gmp/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
gmp/.configured: gmp/.extracted
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) \
	  ../$(GMP_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --enable-static --disable-shared \
	    $(GMP_EXTRA_CONFIGURE)
	@touch $@

gmp/.patched: gmp/.extracted
gmp/.patched: $(GMP_PATCHES)
	cat $< | (cd $(@D)/$(GMP_DIR) && patch -p1)
	@touch $@

gmp/.extracted: $(GMP_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar jxf -)
	@touch $@

.SECONDARY: gmp/.exists
gmp-%: gmp/.%
	@ :

mpfr/.installed: mpfr/.built
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) install
	@touch $@

mpfr/.built: mpfr/.configured
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE)
	@touch $@

mpfr/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
mpfr/.configured: mpfr/.extracted
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) \
	  ../$(MPFR_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --with-gmp=$(INSTALL_DIR) \
	    --enable-static --disable-shared
	@touch $@

mpfr/.patched: mpfr/.extracted
mpfr/.patched: $(MPFR_PATCHES)
	cat $< | (cd $(@D)/$(MPFR_DIR) && patch -p1)
	@touch $@

mpfr/.extracted: $(MPFR_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar jxf -)
	@touch $@

.SECONDARY: mpfr/.exists
mpfr-%: mpfr/.%
	@ :

mpc/.installed: mpc/.built
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) install
	@touch $@

mpc/.built: mpc/.configured
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE)
	@touch $@

mpc/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
mpc/.configured: mpc/.extracted
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) \
	  ../$(MPC_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --with-gmp=$(INSTALL_DIR) \
	    --with-mpfr=$(INSTALL_DIR) \
	    --enable-static --disable-shared
	@touch $@

mpc/.patched: mpc/.extracted
mpc/.patched: $(MPC_PATCHES)
	cat $< | (cd $(@D)/$(MPC_DIR) && patch -p1)
	@touch $@

mpc/.extracted: $(MPC_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: mpc/.exists
mpc-%: mpc/.%
	@ :

endif # MAKENOW
