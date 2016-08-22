#
# inputs:
# - INSTALL_DIR
# - MK_BUILD_ENV
# - MK_HOST_ENV
# - BUILD_BIN_DIR_host
#

CROSS_TARGET ?= x86_64-w64-mingw32
CROSS_TARGET32 ?= i686-w64-mingw32

binutils_DISTFILES = binutils-2.25.1.tar.bz2
binutils_PATCHES = binutils-pie-entry-point.patch
binutils_PATCHES += binutils-install-libiberty.patch
binutils_PATCHES += binutils-display-cv-pdb-name.patch
binutils_DIR = binutils-2.25.1

gcc_DISTFILES = gcc-4.9.3.tar.bz2
gcc_PATCHES = gcc-cross-mingw-include-path.patch
gcc_PATCHES += libssp-win32-random-stackguard.patch
gcc_DIR = gcc-4.9.3
gcc_VERSION = 4.9.3

mingw64_DISTFILES = mingw-w64-v2.0.8.tar.gz
mingw64_PATCHES = mingw-w64-v2.0.8-libwinhttp.patch
mingw64_PATCHES += mingw-w64-v2.0.8-d3d9ex.patch
mingw64_PATCHES += mingw-w64-v2.0.8-libfltlib.patch
mingw64_PATCHES += mingw-w64-v2.0.8-pdh.patch
mingw64_DIR = mingw-w64-v2.0.8

toolchain: gcc/.installed

libbfd: binutils/.installed-libbfd binutils/.installed-libbfd-32

binutils/%-libbfd binutils/%-libbfd-32: private binutils_ADDPATH = $(BUILD_BIN_DIR_host):
mingw64_ADDPATH = $(BUILD_BIN_DIR_host):

MK_BUILD_ENV ?= $(error MK_BUILD_ENV not defined)
MK_HOST_ENV ?= $(error MK_HOST_ENV not defined)
TOOLCHAIN_TARGETS ?= x86_64-w64-mingw32,i686-w64-mingw32
TOOLCHAIN_LANGUAGES ?= "c"
TOOLCHAIN_MULTILIB ?= --enable-multi-lib
MINGW64_ENABLE_LIB ?= --enable-lib32 --enable-lib64

PKGS += binutils
PKGS += gcc
PKGS += mingw64

# binutils
$(eval $(call goal-installed,binutils,,$$($(MK_BUILD_ENV)),install))
$(eval $(call goal-built,binutils,,$$($(MK_BUILD_ENV)),))
$(eval $(call goal-configured,binutils,,$$($(MK_BUILD_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --target=$$(CROSS_TARGET) \
	  --program-prefix=$$(CROSS_TARGET)- \
	  --enable-targets=$$(TOOLCHAIN_TARGETS) \
	  $$(TOOLCHAIN_MULTILIB) \
	  --disable-install-libbfd \
	  --enable-install-libiberty=no \
	  --disable-nls --disable-intl --with-zlib=no \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,binutils))
$(eval $(call goal-extracted,binutils))

# binutils libbfd
binutils/.installed-libbfd: binutils/.installed
$(eval $(call goal-installed,binutils,-libbfd, \
	  $$($(MK_BUILD_ENV)),install-libiberty install-bfd))
$(eval $(call goal-built,binutils,-libbfd, \
	  $$($(MK_BUILD_ENV)),all-libiberty all-bfd))
binutils/.configured-libbfd: gcc/.built | gcc/.installed
binutils/.configured-libbfd: private TOOLS_CONFIGURE_HOST = $(CROSS_TARGET)
binutils/.configured-libbfd: private TOOLS_CONFIGURE_TARGET = $(CROSS_TARGET)
$(eval $(call goal-configured,binutils,-libbfd, \
	  $$($(MK_BUILD_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --exec_prefix=$$(INSTALL_DIR)/$$(CROSS_TARGET) \
	  --libdir=$$(INSTALL_DIR)/$$(CROSS_TARGET)/lib \
	  --program-prefix=$$(CROSS_TARGET)- \
	  --enable-targets=x86_64-w64-mingw32$(,)i686-w64-mingw32 \
	  --enable-static --disable-shared \
	  --disable-nls --disable-intl --with-zlib=no \
	))

# binutils libbfd-32
binutils/.installed-libbfd-32: binutils/.installed
Xpost_binutils_installed_libbfd_32 = \
	[ ! -e $(INSTALL_DIR)/$(CROSS_TARGET)/lib/lib32/libiberty.a ] || \
	  mv -f $(INSTALL_DIR)/$(CROSS_TARGET)/lib/lib32/libiberty.a \
	    $(INSTALL_DIR)/$(CROSS_TARGET)/lib32/ && \
	  { rmdir $(INSTALL_DIR)/$(CROSS_TARGET)/lib/lib32 2>/dev/null || \
	    true; }
$(eval $(call goal-installed,binutils,-libbfd-32, \
	  $$($(MK_BUILD_ENV)),install-libiberty install-bfd))
$(eval $(call goal-built,binutils,-libbfd-32, \
	  $$($(MK_BUILD_ENV)),all-libiberty all-bfd))
binutils/.configured-libbfd-32: gcc/.built | gcc/.installed
binutils/.configured-libbfd-32: private TOOLS_CONFIGURE_HOST = $(CROSS_TARGET32)
binutils/.configured-libbfd-32: private TOOLS_CONFIGURE_TARGET = $(CROSS_TARGET32)
$(eval $(call goal-configured,binutils,-libbfd-32, \
	  $$($(MK_BUILD_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --exec_prefix=$$(INSTALL_DIR)/$$(CROSS_TARGET) \
	  --libdir=$$(INSTALL_DIR)/$$(CROSS_TARGET)/lib32 \
	  --program-prefix=$$(CROSS_TARGET32)- \
	  --enable-targets=x86_64-w64-mingw32$(,)i686-w64-mingw32 \
	  --enable-static --disable-shared \
	  --disable-nls --disable-intl --with-zlib=no \
	))

# gcc
$(eval $(call goal-installed,gcc,,$$($(MK_BUILD_ENV)),install))
gcc/.built: mingw64/.built | mingw64/.installed
$(eval $(call goal-built,gcc,,$$($(MK_BUILD_ENV)),))
# build should just be the previous line -- but to support
# non-multilib mingw compilers, break out building
# all-target-lib{gcc,ssp}, and build these using our compiler which is
# multilib
ifeq ($(TOOLS_CONFIGURE_HOST),i686-w64-mingw32)
gcc/.built: gcc/.installed-target-libs
gcc/.installed-target-libs: private gcc_ADDPATH = $(BUILD_BIN_DIR_host):
$(eval $(call goal-installed3,gcc,-target-libs,-target-libs,, \
  $$($(MK_BUILD_ENV)),install-target-libgcc install-target-libssp))
gcc/.built-target-libs: private gcc_ADDPATH = $(BUILD_BIN_DIR_host):
$(eval $(call goal-built3,gcc,-target-libs,,,$$($(MK_BUILD_ENV)), \
  all-target-libgcc all-target-libssp))
endif
gcc/.configured: mingw64/.built-headers | mingw64/.installed-headers
gcc/.configured: binutils/.built | binutils/.installed
$(eval $(call goal-configured,gcc,,$$($(MK_BUILD_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --target=$$(CROSS_TARGET) \
	  --program-prefix=$$(CROSS_TARGET)- \
	  --with-native-system-header-dir=/$$(CROSS_TARGET)/include \
	  --enable-linker-build-id \
	  --without-included-gettext --disable-libquadmath \
	  --enable-version-specific-runtime-libs --enable-threads=win32 \
	  --enable-fully-dynamic-string \
	  --enable-languages=$$(TOOLCHAIN_LANGUAGES) \
	  --enable-lto --with-plugin-ld \
	  --disable-nls --disable-intl --with-zlib=no \
	  --enable-static --disable-shared \
	  --enable-targets=$$(TOOLCHAIN_TARGETS) \
	  $$(TOOLCHAIN_MULTILIB) \
          MAKEINFO=missing \
	  --with-gmp=$$(GCC_DEPS_DIR) \
	  --with-mpfr=$$(GCC_DEPS_DIR) \
	  --with-mpc=$$(GCC_DEPS_DIR) \
	))
$(eval $(call goal-patched,gcc))
$(eval $(call goal-extracted,gcc))

# gcc-core
$(eval $(call goal-installed3,gcc,-core,-core,, \
	  $$($(MK_BUILD_ENV)),install-gcc))
$(eval $(call goal-built3,gcc,-core,,, \
	  $$($(MK_BUILD_ENV)),all-gcc))

# mingw64
mingw64/%: private TOOLS_CPPFLAGS_MINGW_ANSI_STDIO :=
$(eval $(call goal-installed,mingw64,, \
	  $$($(MK_HOST_ENV)),install))
$(eval $(call goal-built,mingw64,,$$($(MK_HOST_ENV)),))
mingw64/.configured: gcc/.built-core | gcc/.installed-core
mingw64/.configured: private TOOLS_CONFIGURE_HOST = $(CROSS_TARGET)
$(eval $(call goal-configured,mingw64,,$$($(MK_HOST_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  $(MINGW64_ENABLE_LIB) \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,mingw64))
$(eval $(call goal-extracted,mingw64))

# mingw64-headers
$(eval $(call goal-installed,mingw64,-headers, \
	  $$($(MK_HOST_ENV)),install))
mingw64/.built-headers: mingw64/.configured-headers
	@touch $@
mingw64/.configured-headers: binutils/.built | binutils/.installed
mingw64/.configured-headers: private TOOLS_CONFIGURE_HOST = $(CROSS_TARGET)
Xsubdir_mingw64_configured_headers = /mingw-w64-headers
$(eval $(call goal-configured,mingw64,-headers, \
	  $$($(MK_HOST_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --enable-sdk=all \
	  --enable-static --disable-shared \
	))
