#
# inputs:
# - INSTALL_DIR
# - MK_ENV
# - GCC_DEPS_DIR
#

CROSS_TARGET = x86_64-elf

binutils_DISTFILES = binutils-2.25.1.tar.bz2
binutils_PATCHES = binutils-install-libiberty.patch
binutils_DIR = binutils-2.25.1

gcc_DISTFILES = gcc-4.9.3.tar.bz2
gcc_PATCHES =
gcc_DIR = gcc-4.9.3
gcc_VERSION = 4.9.3

toolchain: gcc/.installed-core

MK_ENV ?= $(error MK_ENV not defined)

PKGS += binutils
PKGS += gcc

binutils/.installed: binutils/.installed-ld

# binutils
$(eval $(call goal-installed,binutils,,$$($(MK_ENV)),install))
$(eval $(call goal-built,binutils,,$$($(MK_ENV)),))
$(eval $(call goal-configured,binutils,,$$($(MK_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --target=$$(CROSS_TARGET) \
	  --program-prefix=$$(CROSS_TARGET)- \
	  --disable-werror-always \
	  --disable-nls --disable-intl --with-zlib=no \
	  --enable-ld=no \
	  --enable-targets=x86_64-elf$(,)i686-elf$(,)x86_64-apple-darwin$(,)x86_64-pe \
	))
$(eval $(call goal-patched,binutils))
$(eval $(call goal-extracted,binutils))

# binutils-ld
$(eval $(call goal-installed,binutils,-ld,$$($(MK_ENV)),install))
$(eval $(call goal-built,binutils,-ld,$$($(MK_ENV)),))
$(eval $(call goal-configured,binutils,-ld,$$($(MK_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --target=$$(CROSS_TARGET) \
	  --program-prefix=$$(CROSS_TARGET)- \
	  --disable-nls --disable-intl --with-zlib=no \
	  --enable-ld=yes \
	  --enable-targets=x86_64-elf$(,)i686-elf$(,)x86_64-pe \
	))

# gcc
Xpost_gcc_installed_core = \
	cd $(INSTALL_BIN_DIR) && ln -f $(CROSS_TARGET)-gcc$(HOST_EXE_SUFFIX) \
	  $(CROSS_TARGET)-cc$(HOST_EXE_SUFFIX)
$(eval $(call goal-installed3,gcc,-core,-core,, \
	  $$($(MK_ENV)) inhibit_libc=true, \
	  install-gcc install-target-libgcc))

Xpre_gcc_built_core = mkdir -p $(INSTALL_DIR)/usr/include
$(eval $(call goal-built3,gcc,-core,,,$$($(MK_ENV)) inhibit_libc=true, \
	  all-gcc all-target-libgcc))

# configure --without-headers should make the libgcc build not require
# libc headers, but that doesn't work --with-sysroot, so set
# inhibit_libc=true here explicityly

gcc/.configured: gcc/.headers binutils/.installed
$(eval $(call goal-configured,gcc,,$$($(MK_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --target=$$(CROSS_TARGET) \
	  --enable-linker-build-id \
	  --disable-nls --disable-intl --with-zlib=no \
	  --without-included-gettext --disable-libssp --disable-libquadmath \
	  --enable-languages="c" --enable-lto --with-plugin-ld \
	  --without-headers \
	  --enable-targets=x86_64-elf$(,)i686-elf \
	  MAKEINFO=missing \
	  --with-gmp=$$(GCC_DEPS_DIR) \
	  --with-mpfr=$$(GCC_DEPS_DIR) \
	  --with-mpc=$$(GCC_DEPS_DIR) \
	))

gcc/.headers: limits.h stdint.h
	@mkdir -p $(INSTALL_DIR)/$(CROSS_TARGET)/include
	cp -f $? $(INSTALL_DIR)/$(CROSS_TARGET)/include/
	@touch $@

$(eval $(call goal-patched,gcc))
$(eval $(call goal-extracted,gcc))
