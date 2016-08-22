#
# tools/libraries needed on the host system to build executables running on
# the host system:
# - libbfd/libbfd-32
#

SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

INSTALL_DIR = $(HOST_ALL_INSTALL_DIR)

binutils_DISTFILES = binutils-2.25.1.tar.bz2
binutils_PATCHES = binutils-macho-core.patch binutils-install-libiberty.patch
binutils_PATCHES += binutils-reloc-section.patch
binutils_DIR = binutils-2.25.1

all: binutils/.installed-libbfd

$(CANADIAN)binutils_ADDPATH = $(BUILD_BIN_DIR_host):

PKGS += binutils

# binutils
$(eval $(call goal-patched,binutils))
$(eval $(call goal-extracted,binutils))

# binutils libbfd
Xpost_binutils_installed_libbfd = \
	install -d $(INSTALL_DIR)/include/mach-o ; \
	install $(@D)/$(binutils_DIR)/bfd/mach-o.h \
	  $(INSTALL_DIR)/include/ ; \
	install $(@D)/$(binutils_DIR)/include/mach-o/loader.h \
	  $(INSTALL_DIR)/include/mach-o/ ; \
	[ ! -e $(INSTALL_DIR)/lib32/libiberty.a ] || \
	  mv -f $(INSTALL_DIR)/lib32/libiberty.a \
	    $(INSTALL_DIR)/lib/ && \
	  { rmdir $(INSTALL_DIR)/lib32 2>/dev/null || true; }
$(eval $(call goal-installed,binutils,-libbfd,$$(HOST_TOOLS_ENV), \
	  install-libiberty  install-bfd))
$(eval $(call goal-built,binutils,-libbfd,$$(HOST_TOOLS_ENV), \
	  all-libiberty all-bfd))
binutils/.configured-libbfd: private TOOLS_CONFIGURE_TARGET = $(TOOLS_CONFIGURE_HOST)
$(eval $(call goal-configured,binutils,-libbfd, \
	  $$(HOST_TOOLS_ENV), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-sysroot=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --libdir=$$(INSTALL_DIR)/lib \
	  --enable-targets=x86_64-w64-mingw32$(,)i686-w64-mingw32$(,)x86_64-elf$(,)i686-elf$(,)x86_64-apple-darwin \
	  --enable-static --disable-shared \
	  --disable-nls --disable-intl --with-zlib=no \
	))

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
