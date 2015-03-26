
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET = x86_64-elf

XEN_DISTFILES ?= $(TOPDIR)/../distfiles

INSTALL_DIR = $(TOOLSDIR)/cross-vm

BINUTILS_DISTFILES = binutils-2.23.1.tar.bz2
BINUTILS_PATCHES = 
BINUTILS_DIR = binutils-2.23.1

GCC_DISTFILES = gcc-4.7.2.tar.bz2
GCC_PATCHES = 
GCC_DIR = gcc-4.7.2
GCC_VERSION = 4.7.2

MPFR_DISTFILES = mpfr-3.1.2.tar.bz2
MPFR_PATCHES =
MPFR_DIR = mpfr-3.1.2

GMP_DISTFILES = gmp-5.1.1.tar.bz2
GMP_PATCHES =
GMP_DIR = gmp-5.1.1

MPC_DISTFILES = mpc-1.0.1.tar.gz
MPC_PATCHES =
MPC_DIR = mpc-1.0.1

VPATH = $(SRCDIR)/patches:$(SRCDIR)/files:$(XEN_DISTFILES)

BUILD_ENV = PATH="$(TOOLSDIR)/bin:$$PATH"

$(HOST_OSX)BUILD_ENV += CPPFLAGS="-I/opt/local/include $$CPPFLAGS -g"
$(HOST_OSX)BUILD_ENV += CFLAGS="-Wno-unused-function -Wno-empty-body -Wno-string-plus-int -Wno-self-assign -Wno-deprecated-declarations"
$(HOST_OSX)BUILD_ENV += LDFLAGS="-L/opt/local/lib $$LDFLAGS -g"
$(HOST_OSX)GCC_EXTRA_DEPS += gmp/.installed mpfr/.installed mpc/.installed
$(HOST_OSX)GCC_EXTRA_CONFIG += --with-gmp=$(INSTALL_DIR) --with-mpfr=$(INSTALL_DIR) --with-mpc=$(INSTALL_DIR)

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
gcc/.configured: gcc/.patched gcc/.headers binutils/.installed $(GCC_EXTRA_DEPS)
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
	    $(GCC_EXTRA_CONFIG)
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

gmp/.installed: gmp/.built
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE) install
	@touch $@

gmp/.built: gmp/.configured
	cd $(@D)/build && $(BUILD_ENV) \
	  $(MAKE)
	@touch $@

gmp/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
gmp/.configured: gmp/.extracted
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && $(BUILD_ENV) \
	  ../$(GMP_DIR)/configure --prefix=$(INSTALL_DIR)
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
	    --with-gmp=$(INSTALL_DIR)
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
	    --with-gmp=$(INSTALL_DIR) --with-mpfr=$(INSTALL_DIR)
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

.SECONDARY: binutils/.exists gcc/.exists gmp/.exists
binutils-%: binutils/.%
	@ :
gcc-%: gcc/.%
	@ :
gmp-%: gmp/.%
	@ :

endif # MAKENOW
