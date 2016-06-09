
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET = x86_64-w64-mingw32

INSTALL_DIR = $(CROSS_MINGW_INSTALL_DIR)

BINUTILS_DISTFILES = binutils-2.25.1.tar.bz2
BINUTILS_PATCHES = binutils-pie-entry-point.patch binutils-install-libiberty.patch binutils-display-cv-pdb-name.patch
BINUTILS_DIR = binutils-2.25.1

GCC_DISTFILES = gcc-4.9.3.tar.bz2
GCC_PATCHES = gcc-cross-mingw-include-path.patch libssp-win32-random-stackguard.patch
GCC_DIR = gcc-4.9.3
GCC_VERSION = 4.9.3

GDB_DISTFILES = gdb-7.10.1.tar.gz
GDB_PATCHES = gdbserver-argv0.patch gdb-fix-remote-qOffsets.patch
GDB_DIR = gdb-7.10.1

MINGW64_DISTFILES = mingw-w64-v2.0.8.tar.gz
MINGW64_PATCHES = mingw-w64-v2.0.8-libwinhttp.patch mingw-w64-v2.0.8-d3d9ex.patch mingw-w64-v2.0.8-libfltlib.patch 
MINGW64_DIR = mingw-w64-v2.0.8

E2FSPROGS_DISTFILES = e2fsprogs-1.42.tar.gz
E2FSPROGS_PATCHES = e2fsprogs-1.42-mingw.diff
E2FSPROGS_PATCHES += e2fsprogs-1.42-libe2fsprogs-uuid.diff
E2FSPROGS_DIR = e2fsprogs-1.42

LIBICONV_DISTFILES = libiconv-1.14.tar.gz
LIBICONV_DIR = libiconv-1.14

VPATH = $(SRCDIR)/patches:$(SRCDIR)/files:$(XEN_DISTFILES)

export CFLAGS = -O3

BUILD_PATH = PATH="$(TOOLSDIR)/bin:$$PATH"

BOOTSTRAP_PATH =

CONFIGURE = configure

CONFIGURE_nongnu := $(CONFIGURE)

CONFIGURE += --enable-strip
#$(HOST_WINDOWS)CONFIGURE += --build x86_64-w64-mingw32

#BUILD_ENV += CFLAGS="$$CFLAGS"
#BUILD_ENV += CPPFLAGS="$$CPPFLAGS"
#BUILD_ENV += LDFLAGS="$$LDFLAGS"
BUILD_ENV32 += CFLAGS="-m32 $$CFLAGS"
#BUILD_ENV32 += CPPFLAGS="$$CPPFLAGS"
BUILD_ENV32 += LDFLAGS="-m32 $$LDFLAGS"
TOOLCHAIN_ENV = $(BUILD_ENV)
TOOLCHAIN_ENV += CFLAGS="$(TOOLCHAIN_ENV_CFLAGS) $(TOOLCHAIN_ENV_CPPFLAGS) $$CFLAGS"
TOOLCHAIN_ENV += LDFLAGS="$(TOOLCHAIN_ENV_LDFLAGS) $$LDFLAGS"
TOOLCHAIN_ENV32 = $(BUILD_ENV32)
TOOLCHAIN_ENV32 += CFLAGS="-m32 $(TOOLCHAIN_ENV_CFLAGS) $(TOOLCHAIN_ENV_CPPFLAGS) $$CFLAGS"
TOOLCHAIN_ENV32 += LDFLAGS="-m32 $(TOOLCHAIN_ENV_LDFLAGS) $$LDFLAGS"

all: gcc/.installed
all: e2fsprogs/.installed e2fsprogs/.installed32
all: libiconv/.installed libiconv/.installed32
all: binutils/.libbfd-installed binutils/.libbfd-installed32
all: gdb/.installed

.PHONY: all clean

$(BUILDDIR:%=x)clean::
	rm -rf binutils e2fsprogs gcc libiconv
	rm -rf mingw64

binutils/.installed: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
binutils/.installed: binutils/.built
	cd $(@D)/build && $(TOOLCHAIN_ENV) $(BOOTSTRAP_PATH) \
	  $(MAKE) install
	@touch $@

binutils/.built: binutils/.configured
	cd $(@D)/build && $(BOOTSTRAP_PATH) \
	  $(MAKE) $(TOOLCHAIN_ENV)
	@touch $@

binutils/.configured: binutils/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(TOOLCHAIN_ENV) $(BOOTSTRAP_PATH) \
	  ../$(BINUTILS_DIR)/$(CONFIGURE) \
	    --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --target=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)- \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32 \
	    --enable-static --disable-shared \
	    --disable-install-libbfd \
	    --enable-install-libiberty=no \
	    --disable-nls --disable-intl
	@touch $@

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

binutils/.libbfd-installed: binutils/.installed
binutils/.libbfd-installed: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
binutils/.libbfd-installed: binutils/.libbfd-built
	cd $(@D)/build-libbfd && $(TOOLCHAIN_ENV) $(BUILD_PATH) \
	  $(MAKE) install-libiberty install-bfd
	@touch $@

binutils/.libbfd-installed32: binutils/.installed
binutils/.libbfd-installed32: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
binutils/.libbfd-installed32: binutils/.libbfd-built32
	cd $(@D)/build32-libbfd && $(TOOLCHAIN_ENV32) $(BUILD_PATH) \
	  $(MAKE) install-libiberty install-bfd
	@touch $@

binutils/.libbfd-built: binutils/.libbfd-configured
	cd $(@D)/build-libbfd && $(BUILD_PATH) \
	  $(MAKE) $(TOOLCHAIN_ENV) all-libiberty all-bfd
	@touch $@

binutils/.libbfd-built32: binutils/.libbfd-configured32
	cd $(@D)/build32-libbfd && $(BUILD_PATH) \
	  $(MAKE) $(TOOLCHAIN_ENV32) all-libiberty all-bfd
	@touch $@

binutils/.libbfd-configured: gcc/.installed
binutils/.libbfd-configured: binutils/.patched
	@rm -rf $(@D)/build-libbfd
	@mkdir -p $(@D)/build-libbfd
	cd $(@D)/build-libbfd && $(TOOLCHAIN_ENV) $(BUILD_PATH) \
	  ../$(BINUTILS_DIR)/$(CONFIGURE) \
	    --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --exec_prefix=$(INSTALL_DIR)/$(CROSS_TARGET) \
	    --libdir=$(INSTALL_DIR)/$(CROSS_TARGET)/lib \
	    --host=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)- \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32 \
	    --enable-static --disable-shared \
	    --disable-nls --disable-intl
	@touch $@

binutils/.libbfd-configured32: gcc/.installed
binutils/.libbfd-configured32: binutils/.patched
	@rm -rf $(@D)/build32-libbfd
	@mkdir -p $(@D)/build32-libbfd
	cd $(@D)/build32-libbfd && $(TOOLCHAIN_ENV32) $(BUILD_PATH) \
	  ../$(BINUTILS_DIR)/$(CONFIGURE) \
	    --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --exec_prefix=$(INSTALL_DIR)/$(CROSS_TARGET) \
	    --libdir=$(INSTALL_DIR)/$(CROSS_TARGET)/lib32 \
	    --host=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)- \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32 \
	    --enable-static --disable-shared \
	    --disable-nls --disable-intl
	@touch $@

.SECONDARY: binutils/.exists
binutils-%: binutils/.%
	@ :

gcc/.installed: gcc/.built
	cd $(@D)/build && $(TOOLCHAIN_ENV) $(BUILD_PATH) $(BOOTSTRAP_PATH) \
	  $(MAKE) install
	@touch $@

gcc/.built: mingw64/.installed
gcc/.built: gcc/.configured
	cd $(@D)/build && $(TOOLCHAIN_ENV) $(BUILD_PATH) $(BOOTSTRAP_PATH) \
	  $(MAKE)
	@touch $@

gcc/.core-installed: gcc/.core-built
	cd $(@D)/build && $(TOOLCHAIN_ENV) $(BUILD_PATH) $(BOOTSTRAP_PATH) \
	  $(MAKE) install-gcc
	@touch $@

gcc/.core-built: gcc/.configured
	cd $(@D)/build && $(TOOLCHAIN_ENV) $(BUILD_PATH) $(BOOTSTRAP_PATH) \
	  $(MAKE) all-gcc
	@touch $@

gcc/.configured: mingw64/.headers-installed
gcc/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
gcc/.configured: binutils/.installed
gcc/.configured: gcc/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(TOOLCHAIN_ENV) $(BUILD_PATH) $(BOOTSTRAP_PATH) \
	  ../$(GCC_DIR)/$(CONFIGURE) --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --target=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)- \
	    --enable-linker-build-id \
	    --without-included-gettext --disable-libquadmath \
	    --enable-version-specific-runtime-libs --enable-threads=win32 \
	    --enable-fully-dynamic-string --enable-sjlj-exceptions \
	    --enable-languages="c" --enable-lto --with-plugin-ld \
	    --disable-nls --disable-intl \
	    --enable-static --disable-shared \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32 \
	    MAKEINFO=missing \
	    --with-gmp=$(HOST_ALL_INSTALL_DIR) \
	    --with-mpfr=$(HOST_ALL_INSTALL_DIR) \
	    --with-mpc=$(HOST_ALL_INSTALL_DIR)
	@touch $@

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

.SECONDARY: gcc/.exists
gcc-%: gcc/.%
	@ :

mingw64/.installed: mingw64/.built
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE) install
	@touch $@

mingw64/.built: mingw64/.configured
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE)
	@touch $@

mingw64/.configured: gcc/.core-installed
mingw64/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
mingw64/.configured: mingw64/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  ../$(MINGW64_DIR)/$(CONFIGURE) \
	    --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --host=$(CROSS_TARGET) \
	    --enable-lib32
	@touch $@

mingw64/.headers-installed: mingw64/.headers-configured
	cd $(@D)/build-headers && \
	  $(MAKE) install
	@touch $@

mingw64/.headers-configured: binutils/.installed
mingw64/.headers-configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
mingw64/.headers-configured: mingw64/.patched
	@rm -rf $(@D)/build-headers
	@mkdir -p $(@D)/build-headers
	cd $(@D)/build-headers && $(BUILD_ENV) $(BUILD_PATH) $(BOOTSTRAP_PATH) \
	  ../$(MINGW64_DIR)/mingw-w64-headers/$(CONFIGURE) \
	    --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --host=$(CROSS_TARGET) \
	    --enable-sdk=all
	@touch $@

mingw64/.patched: mingw64/.extracted
mingw64/.patched: $(MINGW64_PATCHES)
	@for p in $(filter-out mingw64/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(MINGW64_DIR) && patch -p1); \
        done
	@touch $@

mingw64/.extracted: mingw64/.exists
mingw64/.extracted: $(MINGW64_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: mingw64/.exists 
mingw64-%: mingw64/.%
	@ :

gdb/.installed: gdb/.built
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE) install-gdb
	@touch $@

gdb/.built: gdb/.configured
	cd $(@D)/build && $(BUILD_PATH) \
	  $(MAKE) $(BUILD_ENV)
	@touch $@

$(HOST_WINDOWS)GDB_EXTRA_CONFIGURE += --host=$(CROSS_TARGET)
gdb/.configured: $(INSTALL_DIR)/.exists
gdb/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
gdb/.configured: gdb/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  ../$(GDB_DIR)/$(CONFIGURE) --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --target=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)- \
	    --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32 \
	    --disable-nls --disable-intl \
	    --enable-static --disable-shared \
	    --disable-install-libbfd \
	    --enable-install-libiberty=no \
	    --with-python=no \
	    $(GDB_EXTRA_CONFIGURE)
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
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: gdb/.exists
gdb-%: gdb/.%
	@ :

e2fsprogs/.installed: e2fsprogs/.built
	cd $(@D)/build/lib/uuid && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE) install
	@touch $@

e2fsprogs/.installed32: e2fsprogs/.built32
	cd $(@D)/build32/lib/uuid && $(BUILD_ENV32) $(BUILD_PATH) \
	  $(MAKE) install
	@touch $@

e2fsprogs/.built: e2fsprogs/.configured
	cd $(@D)/build/lib/uuid && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE)
	@touch $@

e2fsprogs/.built32: e2fsprogs/.configured32
	cd $(@D)/build32/lib/uuid && $(BUILD_ENV32) $(BUILD_PATH) \
	  $(MAKE)
	@touch $@

e2fsprogs/.configured: gcc/.installed
e2fsprogs/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
e2fsprogs/.configured: e2fsprogs/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  ../$(E2FSPROGS_DIR)/$(CONFIGURE) --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --exec_prefix=$(INSTALL_DIR)/$(CROSS_TARGET) \
	    --libdir=$(INSTALL_DIR)/$(CROSS_TARGET)/lib \
	    --host=$(CROSS_TARGET)
	@touch $@

e2fsprogs/.configured32: gcc/.installed
e2fsprogs/.configured32: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
e2fsprogs/.configured32: e2fsprogs/.patched
	@rm -rf $(@D)/build32
	@mkdir -p $(@D)/build32
	cd $(@D)/build32 && $(BUILD_ENV32) $(BUILD_PATH) \
	  ../$(E2FSPROGS_DIR)/$(CONFIGURE) --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --exec_prefix=$(INSTALL_DIR)/$(CROSS_TARGET) \
	    --libdir=$(INSTALL_DIR)/$(CROSS_TARGET)/lib32 \
	    --host=$(CROSS_TARGET)
	@touch $@

e2fsprogs/.patched: e2fsprogs/.extracted
e2fsprogs/.patched: $(E2FSPROGS_PATCHES)
	@for p in $(filter-out e2fsprogs/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(E2FSPROGS_DIR) && patch -p1); \
        done
	@touch $@

e2fsprogs/.extracted: $(E2FSPROGS_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: e2fsprogs/.exists
e2fsprogs-%: e2fsprogs/.%
	@ :

libiconv/.installed: libiconv/.built
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE) install-lib
	@touch $@

libiconv/.installed32: libiconv/.built32
	cd $(@D)/build32 && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE) install-lib
	@touch $@

libiconv/.built: libiconv/.configured
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE)
	@touch $@

libiconv/.built32: libiconv/.configured32
	cd $(@D)/build32 && $(BUILD_ENV) $(BUILD_PATH) \
	  $(MAKE)
	@touch $@

libiconv/.configured: gcc/.installed
libiconv/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
libiconv/.configured: libiconv/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) $(BUILD_PATH) \
	  ac_cv_prog_AR=$(CROSS_TARGET)-ar \
	  ../$(LIBICONV_DIR)/$(CONFIGURE) --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --exec_prefix=$(INSTALL_DIR)/$(CROSS_TARGET) \
	    --libdir=$(INSTALL_DIR)/$(CROSS_TARGET)/lib \
	    --host=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)- \
	    --enable-static --disable-shared
	@touch $@

libiconv/.configured32: gcc/.installed
libiconv/.configured32: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
libiconv/.configured32: libiconv/.patched
	@rm -rf $(@D)/build32
	@mkdir -p $(@D)/build32
	cd $(@D)/build32 && $(BUILD_ENV32) $(BUILD_PATH) \
	  ac_cv_prog_AR=$(CROSS_TARGET)-ar \
	  ac_cv_prog_WINDRES="$(CROSS_TARGET)-windres -F pe-i386" \
	  ../$(LIBICONV_DIR)/$(CONFIGURE) --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --exec-prefix=$(INSTALL_DIR)/$(CROSS_TARGET) \
	    --libdir=$(INSTALL_DIR)/$(CROSS_TARGET)/lib32 \
	    --host=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)- \
	    --enable-static --disable-shared
	@touch $@

libiconv/.patched: libiconv/.extracted
libiconv/.patched: $(LIBICONV_PATCHES)
	@for p in $(filter-out libiconv/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(LIBICONV_DIR) && patch -p1); \
        done
	@touch $@

libiconv/.extracted: $(LIBICONV_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: libiconv/.exists
libiconv-%: libiconv/.%
	@ :

endif # MAKENOW
