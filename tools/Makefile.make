#
# build gnu make, for when the system make is too old
#

# build native
_UXEN_TOOLS_HOST = build

SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

INSTALL_DIR = $(BUILD_INSTALL_DIR)

make_DISTFILES = make-4.2.1.tar.bz2
make_PATCHES =
make_DIR = make-4.2.1

make-make: make/.installed

PKGS += make

MAKE_ENV =

# execute install unconditionally, because if this makefile is
# invoked, then make is not present in $(INSTALL_DIR)
.PHONY: make/.installed

$(eval $(call goal-installed,make,,$$(MAKE_ENV),install))
$(eval $(call goal-built,make,,$$(MAKE_ENV),))
make/.configured: CONFIGURE_target =
$(eval $(call goal-configured,make,,$$(MAKE_ENV), \
	  --prefix=$$(INSTALL_DIR) \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,make))
$(eval $(call goal-extracted,make))

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
