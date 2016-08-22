
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

INSTALL_DIR = $(CROSS_VM_INSTALL_DIR)

iasl_DISTFILES = acpica-unix2-20120711.tar.gz
$(HOST_WINDOWS)iasl_PATCHES = acpica-mingw.patch
$(HOST_OSX)iasl_PATCHES = iasl-llvm-gcc-fixes.patch
iasl_DIR = acpica-unix2-20120711

$(HOST_OSX)HOST_TOOLS_ENV += CFLAGS="-Wno-unused-function -Wno-empty-body -Wno-string-plus-int -Wno-self-assign -Wno-deprecated-declarations $$CFLAGS"
$(HOST_LINUX)HOST_TOOLS_ENV += CFLAGS="-Wno-error=redundant-decls -Wno-error=maybe-uninitialized $$CFLAGS"

all: toolchain-elf iasl/.installed

PKGS += iasl

.PHONY: toolchain-elf
toolchain-elf:
	@mkdir -p $@
	(cd $@ && PATH=$(BUILD_BIN_DIR_elf):$(PATH) \
	  $(MAKE) -f $(SRCDIR)/Makefile.toolchain \
	    SRCDIR=$(SRCDIR) \
	    INSTALL_DIR=$(INSTALL_DIR) \
	    INSTALL_BIN_DIR=$(INSTALL_BIN_DIR) \
	    MK_ENV=HOST_TOOLS_ENV \
	    GCC_DEPS_DIR=$(BUILD_HOST_DIR) \
	    toolchain)

$(HOST_WINDOWS)iasl/.installed: iasl/.built
	cd $(@D)/$(iasl_DIR)/source/compiler && $(HOST_TOOLS_ENV) \
	  $(MAKE) install HOST=_WINDOWS \
	    CC="$(TOOLS_HOST_PREFIX)gcc" \
	    INSTALLDIR=$(INSTALL_BIN_DIR)
	cd $(INSTALL_BIN_DIR) && [ ! -e iasl.exe ] || mv iasl.exe iasl
	@touch $@
$(HOST_OSX)iasl/.installed $(HOST_LINUX)iasl/.installed: iasl/.built
	cd $(@D)/$(iasl_DIR)/source/compiler && $(HOST_TOOLS_ENV) \
	  $(MAKE) install \
            INSTALLPROG='cp -f $$(PROG) $$(INSTALLDIR)' \
	    INSTALLDIR=$(INSTALL_BIN_DIR)
	@touch $@

$(HOST_WINDOWS)iasl/.built: iasl/.patched
	cd $(@D)/$(iasl_DIR)/source/compiler && $(HOST_TOOLS_ENV) \
	  $(MAKE) $(MAKE_ENV) HOST=WIN32 \
	    CC="$(TOOLS_HOST_PREFIX)gcc -U__STRICT_ANSI__ -Wno-error=unknown-pragmas -Wno-error=redundant-decls -Wno-error=maybe-uninitialized $(MAKE_ENV_CC_EXTRA)" \
	    INSTALLDIR=$(INSTALL_BIN_DIR)
	       # for 64bit: -m64 -UWIN32
	@touch $@
$(HOST_OSX)iasl/.built $(HOST_LINUX)iasl/.built: iasl/.configured
	cd $(@D)/$(iasl_DIR)/source/compiler && $(HOST_TOOLS_ENV) \
	  $(MAKE) INSTALLDIR=$(INSTALL_BIN_DIR)
	@touch $@

iasl/.configured: iasl/.patched
	@touch $@

$(eval $(call goal-patched,iasl))
$(eval $(call goal-extracted,iasl))

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
