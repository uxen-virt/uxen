
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

INSTALL_DIR = $(HOST_OSX_INSTALL_DIR)

gdb_DISTFILES = gdb-1822-stripped.tar.gz
gdb_PATCHES = gdb-elf-target.patch gdb-elf-debug-sections.patch gdb-macosx-nat-inferior-setjmp.patch
gdb_DIR = gdb-1822

all: gdb/.installed

PKGS += gdb

# gdb
gdb_BUILD_ENV  = RC_ARCHS=x86_64 RC_OS=macos RC_RELEASE=MountainLion
gdb_BUILD_ENV += MAKEINFO=/usr/bin/true
gdb_BUILD_ENV += CROSS_TARGETS=
gdb_BUILD_ENV += CONFIG_ALL_BFD_TARGETS="host_configargs=\"--enable-targets=x86_64-apple-darwin,x86_64-elf --disable-nls\""
# MAKEINFO=true to prevent the build from creating bfd-info* files in src tree
# --disable-nls to prevent the build from creating *.gmo files in src tree
$(HOST_OSX)gdb_BUILD_ENV += CFLAGS="-Wno-empty-body -Wno-string-plus-int -Wno-self-assign -Wno-uninitialized -Wno-pointer-sign -Wparentheses-equality -Wincompatible-pointer-types -Wconstant-logical-operand -Wincompatible-pointer-types-discards-qualifiers"
$(HOST_OSX)gdb_BUILD_ENV += CPP="cc -E"

gdb/.installed: gdb/.built
	cp $(@D)/build/x86_64-apple-darwin--x86_64-apple-darwin/gdb/gdb \
	  $(INSTALL_BIN_DIR)/x86_64-apple-darwin-gdb
	@touch $@
gdb/.built: gdb/.configured
	cd $(@D)/$(gdb_DIR) && $(HOST_TOOLS_ENV) \
	  $(MAKE) $(gdb_BUILD_ENV) OBJROOT=$(abspath $(@D)/build) build
	@touch $@
gdb/.configured: gdb/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	@touch $@
$(eval $(call goal-patched,gdb))
$(eval $(call goal-extracted,gdb))

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
