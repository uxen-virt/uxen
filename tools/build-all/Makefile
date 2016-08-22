#
# everything needed on the build system to build the tools for the host system:
# - canadian gcc build dependencies (gmp, mpfr, mpc)
# - canadian x86_64-elf cross-compiler
# - canadian i686-w64-mingw32/x86_64-w64-mingw32 cross-compilers
#   with multilib targets x86_64-w64-mingw32/i686-w64-mingw32
# - host gcc build dependencies (gmp, mpfr, mpc)
#

SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

# native cross toolchain with host == build
# setting _UXEN_TOOLS_HOST=build when calling gcc-deps/toolchain
# causes a native build
INSTALL_DIR = $(BUILD_INSTALL_DIR)

$(CANADIAN)$(WINDOWS)all: toolchain-elf
$(CANADIAN)$(WINDOWS)all: toolchain-mingw
$(CANADIAN)$(WINDOWS)all: toolchain-mingw-32
all: host-gcc-deps

PKGS += gcc-deps
PKGS += host-gcc-deps
PKGS += toolchain-elf
PKGS += toolchain-mingw
PKGS += toolchain-mingw-32

.PHONY: gcc-deps
gcc-deps:
	@mkdir -p $@
	(cd $@ && \
	  $(MAKE) -f $(SRCDIR)/Makefile.gcc-deps \
	    SRCDIR=$(SRCDIR) \
	    INSTALL_DIR=$(INSTALL_DIR) \
	    _UXEN_TOOLS_HOST=build \
	    MK_ENV=BUILD_TOOLS_ENV \
	    gcc-deps)

.PHONY: host-gcc-deps
host-gcc-deps:
	@mkdir -p $@
	(cd $@ && \
	  $(MAKE) -f $(SRCDIR)/Makefile.gcc-deps \
	    SRCDIR=$(SRCDIR) \
	    INSTALL_DIR=$(BUILD_HOST_DIR) \
	    _UXEN_TOOLS_HOST=$(UXEN_TOOLS_HOST) \
	    MK_ENV=HOST_BUILD_TOOLS_ENV \
	    gcc-deps)

.PHONY: toolchain-elf
toolchain-elf: gcc-deps
	@mkdir -p $@
	(cd $@ && \
	  $(MAKE) -f $(SRCDIR)/../cross-vm/Makefile.toolchain \
	    SRCDIR=$(SRCDIR)/../cross-vm \
	    INSTALL_DIR=$(INSTALL_DIR) \
	    INSTALL_BIN_DIR=$(BUILD_BIN_DIR_elf) \
	    _UXEN_TOOLS_HOST=build \
	    MK_ENV=BUILD_TOOLS_ENV \
	    GCC_DEPS_DIR=$(BUILD_INSTALL_DIR) \
	    toolchain)

.PHONY: toolchain-mingw
toolchain-mingw: gcc-deps
	@mkdir -p $@
	(cd $@ && \
	  $(MAKE) -f $(SRCDIR)/../cross-mingw/Makefile.toolchain \
	    SRCDIR=$(SRCDIR)/../cross-mingw \
	    INSTALL_DIR=$(INSTALL_DIR) \
	    INSTALL_BIN_DIR=$(BUILD_BIN_DIR_host) \
	    _UXEN_TOOLS_HOST=build \
	    MK_BUILD_ENV=BUILD_TOOLS_ENV \
	    MK_HOST_ENV=BUILD_TOOLS_ENV \
	    GCC_DEPS_DIR=$(BUILD_INSTALL_DIR) \
	    toolchain)

.PHONY: toolchain-mingw-32
toolchain-mingw-32: gcc-deps
toolchain-mingw-32: wrapper-m32
	@mkdir -p $@
	(cd $@ && \
	  $(MAKE) -f $(SRCDIR)/../cross-mingw/Makefile.toolchain \
	    SRCDIR=$(SRCDIR)/../cross-mingw \
	    INSTALL_DIR=$(INSTALL_DIR) \
	    INSTALL_BIN_DIR=$(BUILD_BIN_DIR_host) \
	    _UXEN_TOOLS_HOST=build \
	    MK_BUILD_ENV=BUILD_TOOLS_ENV \
	    MK_HOST_ENV=BUILD_TOOLS_ENV \
	    GCC_DEPS_DIR=$(BUILD_INSTALL_DIR) \
	    CROSS_TARGET=i686-w64-mingw32 \
	    binutils-installed)
	for g in gcc gcc-4.9.3 gcc-ar gcc-nm gcc-ranlib gcov; \
	do \
	  install $(filter %/wrapper-m32,$^) \
	    $(BUILD_BIN_DIR_host)/i686-w64-mingw32-$$g; \
	done

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
