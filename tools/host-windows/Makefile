#
# windows host system specific tools/libraries needed to build
# executables running on the host system:
# - mingw-libgnurx (for gdb)
#

SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

INSTALL_DIR = $(HOST_WINDOWS_INSTALL_DIR)

regex_DISTFILES = mingw-libgnurx-2.5.1-src.tar.gz
regex_PATCHES =
regex_DIR = mingw-libgnurx-2.5.1

all: regex/.installed

regex_ADDPATH = $(BUILD_BIN_DIR_host):

PKGS += regex

# disable x86_64-w64-mingw32/include/crtdefs.h "typedef int errcode;"
regex/.built regex/.installed: private TOOLS_CPPFLAGS += -D__ERRCODE_DEFINED_MS

# regex
$(eval $(call goal-installed,regex,,$$(HOST_TOOLS_ENV),install))
$(eval $(call goal-built,regex,,$$(HOST_TOOLS_ENV),))
$(eval $(call goal-configured,regex,,$$(HOST_TOOLS_ENV), \
	  --prefix=$$(INSTALL_DIR) \
	  --bindir=$$(INSTALL_BIN_DIR) \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,regex))
$(eval $(call goal-extracted,regex))

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
