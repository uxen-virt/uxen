
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET ?= x86_64-w64-mingw32
CROSS_TARGET32 ?= i686-w64-mingw32

INSTALL_DIR = $(CROSS_MINGW_INSTALL_DIR)

gdb_DISTFILES = gdb-7.10.1.tar.gz
gdb_PATCHES = gdbserver-argv0.patch gdb-fix-remote-qOffsets.patch
gdb_DIR = gdb-7.10.1

e2fsprogs_DISTFILES = e2fsprogs-1.42.tar.gz
e2fsprogs_PATCHES = e2fsprogs-1.42-mingw.diff
e2fsprogs_PATCHES += e2fsprogs-1.42-libe2fsprogs-uuid.diff
e2fsprogs_DIR = e2fsprogs-1.42

libiconv_DISTFILES = libiconv-1.14.tar.gz
libiconv_PATCHES =
libiconv_DIR = libiconv-1.14

all: toolchain/mingw
all: toolchain/mingw-32
all: toolchain/libbfd
all: e2fsprogs/.installed e2fsprogs/.installed-32
all: libiconv/.installed libiconv/.installed-32
all: gdb/.installed

e2fsprogs_ADDPATH = $(BUILD_BIN_DIR_host):
libiconv_ADDPATH = $(BUILD_BIN_DIR_host):

PKGS += gdb
PKGS += e2fsprogs
PKGS += libiconv

.PHONY: toolchain/mingw
toolchain/mingw:
	@mkdir -p $(@D)
	(cd $(@D) && \
	  $(MAKE) -f $(SRCDIR)/Makefile.toolchain \
	    SRCDIR=$(SRCDIR) \
	    INSTALL_DIR=$(INSTALL_DIR) \
	    INSTALL_BIN_DIR=$(INSTALL_BIN_DIR) \
	    MK_BUILD_ENV=HOST_TOOLS_ENV \
	    MK_HOST_ENV=HOST_TOOLS_ENV \
	    GCC_DEPS_DIR=$(BUILD_HOST_DIR) \
	    toolchain)

.PHONY: toolchain/mingw-32
toolchain/mingw-32: wrapper-m32
	@mkdir -p $@
	(cd $@ && \
	  $(MAKE) -f $(SRCDIR)/Makefile.toolchain \
	    SRCDIR=$(SRCDIR) \
	    INSTALL_DIR=$(INSTALL_DIR) \
	    INSTALL_BIN_DIR=$(INSTALL_BIN_DIR) \
	    MK_BUILD_ENV=HOST_TOOLS_ENV \
	    MK_HOST_ENV=HOST_TOOLS_ENV \
	    GCC_DEPS_DIR=$(BUILD_HOST_DIR) \
	    CROSS_TARGET=i686-w64-mingw32 \
	    binutils-installed)
	for g in gcc gcc-4.9.3 gcc-ar gcc-nm gcc-ranlib gcov; \
	do \
	  install $(filter %/wrapper-m32,$^) \
	    $(BUILD_BIN_DIR_host)/i686-w64-mingw32-$$g; \
	done

.PHONY: toolchain/libbfd
toolchain/libbfd: | toolchain/mingw toolchain/mingw-32
	@mkdir -p $(@D)
	(cd $(@D) && \
	  $(MAKE) -f $(SRCDIR)/Makefile.toolchain \
	    SRCDIR=$(SRCDIR) \
	    INSTALL_DIR=$(INSTALL_DIR) \
	    INSTALL_BIN_DIR=$(INSTALL_BIN_DIR) \
	    MK_BUILD_ENV=HOST_TOOLS_ENV \
	    MK_HOST_ENV=HOST_TOOLS_ENV \
	    GCC_DEPS_DIR=$(BUILD_HOST_DIR) \
	    libbfd)

# gdb
$(eval $(call goal-installed,gdb,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH), \
	  install-gdb))
$(eval $(call goal-built,gdb,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH),))
$(eval $(call goal-configured,gdb,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH), \
	  --prefix=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --target=$$(CROSS_TARGET) \
	  --program-prefix=$$(CROSS_TARGET)- \
	  --enable-targets=x86_64-w64-mingw32$(,)i686-w64-mingw32 \
	  --disable-install-libbfd \
	  --enable-install-libiberty=no \
	  --with-python=no \
	  --disable-nls --disable-intl --with-zlib=no \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,gdb))
$(eval $(call goal-extracted,gdb))

# e2fsprogs
Xsubdir_e2fsprogs_build = /lib/uuid
$(eval $(call goal-installed,e2fsprogs,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH), \
	  install))
$(eval $(call goal-built,e2fsprogs,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH),))
e2fsprogs/.configured: | toolchain/mingw
e2fsprogs/.configured: private TOOLS_CONFIGURE_HOST = $(CROSS_TARGET)
$(eval $(call goal-configured,e2fsprogs,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH), \
	  --prefix=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --exec_prefix=$$(INSTALL_DIR)/$$(CROSS_TARGET) \
	  --libdir=$$(INSTALL_DIR)/$$(CROSS_TARGET)/lib \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,e2fsprogs))
$(eval $(call goal-extracted,e2fsprogs))

# e2fsprogs-32
Xsubdir_e2fsprogs_build_32 = /lib/uuid
$(eval $(call goal-installed,e2fsprogs,-32,$$(HOST_TOOLS_ENV) $$(BUILD_PATH), \
	  install))
$(eval $(call goal-built,e2fsprogs,-32,$$(HOST_TOOLS_ENV) $$(BUILD_PATH),))
e2fsprogs/.configured-32: | toolchain/mingw-32
e2fsprogs/.configured-32: private TOOLS_CONFIGURE_HOST = $(CROSS_TARGET32)
$(eval $(call goal-configured,e2fsprogs,-32,$$(HOST_TOOLS_ENV) $$(BUILD_PATH), \
	  --prefix=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --exec_prefix=$$(INSTALL_DIR)/$$(CROSS_TARGET) \
	  --libdir=$$(INSTALL_DIR)/$$(CROSS_TARGET)/lib32 \
	  --enable-static --disable-shared \
	))

# libiconv
$(eval $(call goal-installed,libiconv,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH), \
	  install-lib))
$(eval $(call goal-built,libiconv,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH),))
libiconv/.configured: | toolchain/mingw
libiconv/.configured: private TOOLS_CONFIGURE_HOST = $(CROSS_TARGET)
$(eval $(call goal-configured,libiconv,,$$(HOST_TOOLS_ENV) $$(BUILD_PATH) \
	  ac_cv_prog_AR=$(CROSS_TARGET)-ar, \
	  --prefix=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --exec_prefix=$$(INSTALL_DIR)/$$(CROSS_TARGET) \
	  --libdir=$$(INSTALL_DIR)/$$(CROSS_TARGET)/lib \
	  --program-prefix=$$(CROSS_TARGET)- \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,libiconv))
$(eval $(call goal-extracted,libiconv))

# libiconv-32
$(eval $(call goal-installed,libiconv,-32,$$(HOST_TOOLS_ENV) $$(BUILD_PATH), \
	  install-lib))
$(eval $(call goal-built,libiconv,-32,$$(HOST_TOOLS_ENV) $$(BUILD_PATH),))
libiconv/.configured-32: | toolchain/mingw-32
libiconv/.configured-32: private TOOLS_CONFIGURE_HOST = $(CROSS_TARGET32)
$(eval $(call goal-configured,libiconv,-32,$$(HOST_TOOLS_ENV) $$(BUILD_PATH) \
	  ac_cv_prog_AR=$(CROSS_TARGET)-ar \
	  ac_cv_prog_WINDRES="$(CROSS_TARGET)-windres -F pe-i386", \
	  --prefix=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --exec_prefix=$$(INSTALL_DIR)/$$(CROSS_TARGET) \
	  --libdir=$$(INSTALL_DIR)/$$(CROSS_TARGET)/lib32 \
	  --program-prefix=$$(CROSS_TARGET)- \
	  --enable-static --disable-shared \
	))

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
