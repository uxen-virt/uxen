
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

INSTALL_DIR = $(CROSS_WINDOWS_INSTALL_DIR)

wdk8_DISTFILES = wdk8.tar.gz
wdk8_PATCHES = wdk8-no-sal.patch
wdk8_DIR = wdk8

# http://wixtoolset.org/releases/v3.7.1126.0/wix37-binaries.zip
# extracted and recompressed as tar.bz2
wix_DISTFILES = wix37-binaries.tar.bz2

cv2pdb_DISTFILES = cv2pdb-5c63d48.tar.bz2
cv2pdb_PATCHES = cv2pdb-mingw.patch \
		 cv2pdb-nocxxstring.patch \
		 cv2pdb-timestamps.patch \
		 cv2pdb-windows-path-separator.patch \
		 cv2pdb-no-bigobj.patch \
		 cv2pdb-buildid-and-no-strip.patch \
		 cv2pdb-pdb-no-path.patch \
		 cv2pdb-no-dll-nonfatal.patch
cv2pdb_DIR = cv2pdb-5c63d48

all: wdk8/.installed wix/.installed
$(HOST_WINDOWS)all: cv2pdb/.installed

PKGS += wdk8
PKGS += wix
PKGS += cv2pdb

# wdk8
wdk8/.installed: wdk8/.configured
	@install -d $(INSTALL_DIR)/wdk8
	cd $(@D)/$(wdk8_DIR) && \
	  cp -R inc lib $(INSTALL_DIR)/wdk8
	@touch $@
wdk8/.configured: wdk8/.patched
	@touch $@
$(eval $(call goal-patched,wdk8))
$(eval $(call goal-extracted,wdk8))

# wix
wix/.installed: $(wix_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	@rm -rf $(INSTALL_DIR)/wix
	@mkdir -p $(INSTALL_DIR)/wix
	cat $< | (cd $(INSTALL_DIR)/wix && tar --strip-components=1 -jxf -)
	chmod -R go+rX $(INSTALL_DIR)/wix
	@touch $@

# cv2pdb
cv2pdb/.installed: cv2pdb/.built
	install -m 755 $(@D)/$(cv2pdb_DIR)/src/cv2pdb.exe $(INSTALL_BIN_DIR)
	@touch $@
cv2pdb/.built: cv2pdb/.configured
	cd $(@D)/$(cv2pdb_DIR)/src && $(HOST_TOOLS_ENV) \
	  $(MAKE) -f Makefile.mingw \
	    CXX="$(TOOLS_HOST_PREFIX)g++ -std=c++11" \
	    LDFLAGS="-static-libgcc -static-libstdc++ $$LDFLAGS"
	@touch $@
cv2pdb/.configured: cv2pdb/.patched
	@touch $@
$(eval $(call goal-patched,cv2pdb))
$(eval $(call goal-extracted,cv2pdb))

# pkgs
$(eval $(call packages,$(PKGS)))

endif # MAKENOW
