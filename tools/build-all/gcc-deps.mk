#
# inputs:
# - INSTALL_DIR
# - MK_ENV (set to the literals BUILD_TOOLS_ENV or HOST_BUILD_TOOLS_ENV)
#

gmp_DISTFILES = gmp-6.1.0.tar.bz2
gmp_PATCHES =
gmp_DIR = gmp-6.1.0

mpfr_DISTFILES = mpfr-3.1.3.tar.bz2
mpfr_PATCHES =
mpfr_DIR = mpfr-3.1.3

mpc_DISTFILES = mpc-1.0.3.tar.gz
mpc_PATCHES =
mpc_DIR = mpc-1.0.3

gcc-deps: mpc/.installed

MK_ENV ?= $(error MK_ENV not defined)

PKGS += gmp
PKGS += mpfr
PKGS += mpc

# gmp
$(eval $(call goal-installed,gmp,,$$($(MK_ENV)),install))
$(eval $(call goal-built,gmp,,$$($(MK_ENV)),))
gmp/.configured: CONFIGURE_target =
$(eval $(call goal-configured,gmp,,$$($(MK_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,gmp))
$(eval $(call goal-extracted,gmp))

# mpfr
mpfr/.configured: gmp/.built | gmp/.installed
$(eval $(call goal-installed,mpfr,,$$($(MK_ENV)),install))
$(eval $(call goal-built,mpfr,,$$($(MK_ENV)),))
$(eval $(call goal-configured,mpfr,,$$($(MK_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-gmp=$$(INSTALL_DIR) \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,mpfr))
$(eval $(call goal-extracted,mpfr))

# mpc
mpc/.configured: mpfr/.built | mpfr/.installed
$(eval $(call goal-installed,mpc,,$$($(MK_ENV)),install))
$(eval $(call goal-built,mpc,,$$($(MK_ENV)),))
$(eval $(call goal-configured,mpc,,$$($(MK_ENV)), \
	  --prefix=$$(INSTALL_DIR) \
	  --with-gmp=$$(INSTALL_DIR) \
	  --with-mpfr=$$(INSTALL_DIR) \
	  --enable-static --disable-shared \
	))
$(eval $(call goal-patched,mpc))
$(eval $(call goal-extracted,mpc))
