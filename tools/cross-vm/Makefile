
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET = x86_64-elf

INSTALL_DIR = $(CROSS_VM_INSTALL_DIR)

BINUTILS_DISTFILES = binutils-2.25.1.tar.bz2
BINUTILS_PATCHES = binutils-install-libiberty.patch
BINUTILS_DIR = binutils-2.25.1

GCC_DISTFILES = gcc-4.9.3.tar.bz2
GCC_PATCHES =
GCC_DIR = gcc-4.9.3
GCC_VERSION = 4.9.3

VPATH = $(SRCDIR)/patches:$(SRCDIR)/files:$(XEN_DISTFILES)

BUILD_ENV = PATH="$(TOOLSDIR)/bin:$$PATH"

$(HOST_OSX)BUILD_ENV += CFLAGS="-Wno-unused-function -Wno-empty-body -Wno-string-plus-int -Wno-self-assign -Wno-deprecated-declarations $$CFLAGS"

BINUTILS_ENV = $(subst CPPFLAGS,CFLAGS,$(BUILD_ENV))

all: gcc/.core-installed

.PHONY: all clean

clean:
	rm -rf binutils gcc

binutils/.installed: binutils/.built binutils/.built-ld
	cd $(@D)/build-ld && $(BINUTILS_ENV) \
	  $(MAKE) install
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
	    --program-prefix=$(CROSS_TARGET)- \
	    --disable-werror-always \
	    --disable-nls \
	    --enable-ld=no \
	    --enable-targets=x86_64-elf,i686-elf,x86_64-apple-darwin
	@touch $@

binutils/.built-ld: binutils/.configured-ld
	cd $(@D)/build-ld && \
	  $(MAKE) $(BINUTILS_ENV)
	@touch $@

binutils/.configured-ld: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
binutils/.configured-ld: binutils/.patched
	@rm -rf $(@D)/build-ld
	@mkdir -p $(@D)/build-ld
	cd $(@D)/build-ld && $(BINUTILS_ENV) \
	  ../$(BINUTILS_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --target=$(CROSS_TARGET) \
	    --program-prefix=$(CROSS_TARGET)- \
	    --disable-nls \
	    --enable-ld=yes \
	    --enable-targets=x86_64-elf,i686-elf
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

.SECONDARY: binutils/.exists gcc/.exists
binutils-%: binutils/.%
	@ :

#gcc/.installed: gcc/.built
#	cd $(@D)/build && $(BUILD_ENV) \
#	  $(MAKE) install
#	@touch $@

#gcc/.built: gcc/.configured
#	cd $(@D)/build && $(BUILD_ENV) \
#	  $(MAKE)
#	@touch $@

gcc/.core-installed: gcc/.core-built
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) install-gcc
	@touch $@

gcc/.core-built: gcc/.configured
	@mkdir -p $(INSTALL_DIR)/usr/include
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) all-gcc
	@touch $@

gcc/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
gcc/.configured: gcc/.patched gcc/.headers binutils/.installed
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) \
	  ../$(GCC_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --with-sysroot=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin \
	    --target=$(CROSS_TARGET) \
	    --enable-linker-build-id --with-system-zlib \
	    --without-included-gettext --disable-libssp --disable-libquadmath \
	    --disable-nls \
	    --enable-languages="c" --enable-lto --with-plugin-ld \
	    --enable-targets=x86_64-elf,i686-elf \
	    MAKEINFO=missing \
	    --with-gmp=$(HOST_ALL_INSTALL_DIR) \
	    --with-mpfr=$(HOST_ALL_INSTALL_DIR) \
	    --with-mpc=$(HOST_ALL_INSTALL_DIR)
	@touch $@

gcc/.headers: limits.h stdint.h
	@mkdir -p $(INSTALL_DIR)/$(CROSS_TARGET)/include
	cp -f $? $(INSTALL_DIR)/$(CROSS_TARGET)/include/
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

endif # MAKENOW
