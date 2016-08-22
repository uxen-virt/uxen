
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET = x86_64-w64-mingw32

INSTALL_DIR = $(CROSS_W64L_INSTALL_DIR)

binutils_DISTFILES = binutils-2.25.1.tar.bz2
binutils_PATCHES = binutils-link-pdata.patch binutils-cv8.patch
binutils_PATCHES += binutils-install-libiberty.patch
binutils_DIR = binutils-2.25.1

gcc_DISTFILES = gcc-4.9.3.tar.bz2
gcc_PATCHES = gcc-long.patch
gcc_DIR = gcc-4.9.3
gcc_VERSION = 4.9.3

dwarfcv_DISTFILES = dwarfcv-1.1.tar.gz
dwarfcv_PATCHES = dwarfcv-mingw-printf.patch
dwarfcv_PATCHES += dwarfcv-linux.patch
dwarfcv_PATCHES += dwarfcv-linux2.patch
dwarfcv_DIR = dwarfcv-1.1

all: gcc/.installed-core dwarfcv/.installed

PKGS += binutils
PKGS += gcc
PKGS += dwarfcv

# binutils
$(eval $(call goal-installed,binutils,,$$(HOST_TOOLS_ENV),install))
$(eval $(call goal-built,binutils,,$$(HOST_TOOLS_ENV),))
$(eval $(call goal-configured,binutils,,$$(HOST_TOOLS_ENV), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --target=$$(CROSS_TARGET) \
	  --program-prefix=$$(CROSS_TARGET)-long- \
	  --enable-targets=x86_64-w64-mingw32$(,)i686-w64-mingw32 \
	  --enable-64-bit-bfd --enable-multi-lib \
	  --disable-nls --disable-intl --with-zlib=no \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,binutils))
$(eval $(call goal-extracted,binutils))

# gcc
$(eval $(call goal-installed,gcc,,$$(HOST_TOOLS_ENV),install))
$(eval $(call goal-built,gcc,,$$(HOST_TOOLS_ENV),))
gcc/.configured: gcc/.headers binutils/.installed
$(eval $(call goal-configured,gcc,,$$(HOST_TOOLS_ENV), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --target=$$(CROSS_TARGET) \
	  --program-prefix=$$(CROSS_TARGET)-long- \
	  --with-native-system-header-dir=/$$(CROSS_TARGET)/include \
	  --enable-linker-build-id \
	  --without-included-gettext --disable-libssp --disable-libquadmath \
	  --enable-version-specific-runtime-libs --enable-threads=win32 \
	  --enable-fully-dynamic-string \
	  --enable-languages="c" --enable-lto --with-plugin-ld \
	  --disable-nls --disable-intl --with-zlib=no \
	  --enable-static --disable-shared \
	  --enable-targets=x86_64-w64-mingw32$(,)i686-w64-mingw32 \
	  --enable-multi-lib \
          MAKEINFO=missing \
	  --with-gmp=$$(BUILD_HOST_DIR) \
	  --with-mpfr=$$(BUILD_HOST_DIR) \
	  --with-mpc=$$(BUILD_HOST_DIR) \
	))
$(eval $(call goal-patched,gcc))
$(eval $(call goal-extracted,gcc))

# gcc-core
# 	XXX installed gcc x86_64-w64-mingw32-gcc-4.9.3 is missing "-long"
Xpost_gcc_installed_core = \
	( cd $(INSTALL_BIN_DIR) && EXE= && \
	  { [ ! -e $(CROSS_TARGET)-long-gcc.exe ] || EXE=.exe; } && \
	  rm -f $(CROSS_TARGET)-gcc-$(gcc_VERSION)$$EXE && \
	  rm -f $(CROSS_TARGET)-long-gcc-$(gcc_VERSION)$$EXE && \
	  cp $(CROSS_TARGET)-long-gcc$$EXE \
	    $(CROSS_TARGET)-long-gcc-$(gcc_VERSION)$$EXE )
# enable these next lines if non-w64l gcc is the same version
#	[ ! -e $(INSTALL_BIN_DIR)/$(CROSS_TARGET)-gcc ] || \
#	  rm -f $(INSTALL_BIN_DIR)/$(CROSS_TARGET)-gcc-$(gcc_VERSION)
#	[ ! -e $(INSTALL_BIN_DIR)/$(CROSS_TARGET)-gcc ] || \
#	  cp $(INSTALL_BIN_DIR)/$(CROSS_TARGET)-gcc \
#	    $(INSTALL_BIN_DIR)/$(CROSS_TARGET)-gcc-$(gcc_VERSION)
$(eval $(call goal-installed3,gcc,-core,-core,,$$(HOST_TOOLS_ENV),install-gcc))
$(eval $(call goal-built3,gcc,-core,,,$$(HOST_TOOLS_ENV),all-gcc))

gcc/.headers: limits.h stdint.h
	@mkdir -p $(INSTALL_DIR)/$(CROSS_TARGET)/include
	cp -f $? $(INSTALL_DIR)/$(CROSS_TARGET)/include/
	@touch $@

# dwarfcv
dwarfcv_MAKE_ARGS = TOOLSDIR=$(TOOLSDIR)
dwarfcv_MAKE_ARGS += HOST_WINDOWS=$(HOST_WINDOWS)
dwarfcv_MAKE_ARGS += HOST_LINUX=$(HOST_LINUX)
dwarfcv_MAKE_ARGS += SRCDIR=../$(dwarfcv_DIR)
dwarfcv_MAKE_ARGS += CC=$(TOOLS_HOST_PREFIX)gcc
dwarfcv_MAKE_ARGS += BFD_DIR=$(HOST_ALL_INSTALL_DIR)
$(eval $(call goal-installed,dwarfcv,,$$(HOST_TOOLS_ENV),\
	  install $(dwarfcv_MAKE_ARGS) PREFIX=$(TOOLSDIR)))
$(eval $(call goal-built,dwarfcv,,$$(HOST_TOOLS_ENV),$(dwarfcv_MAKE_ARGS)))
dwarfcv/.configured: dwarfcv/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	@cd $(@D)/build && ln -s ../$(dwarfcv_DIR)/Makefile ./
	@touch $@
$(eval $(call goal-patched,dwarfcv))
$(eval $(call goal-extracted,dwarfcv))

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
