
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

CROSS_TARGET = x86_64-elf

XEN_DISTFILES ?= $(TOPDIR)/../distfiles

INSTALL_DIR = $(TOOLSDIR)/host-windows

IASL_DISTFILES = acpica-unix2-20120711.tar.gz
IASL_PATCHES = acpica-mingw.patch
IASL_DIR = acpica-unix2-20120711

REGEX_DISTFILES = mingw-libgnurx-2.5.1-src.tar.gz
REGEX_PATCHES = 
REGEX_DIR = mingw-libgnurx-2.5.1

# http://wixtoolset.org/releases/v3.7.1126.0/wix37-binaries.zip
# extracted and recompressed as tar.bz2
WIX_DISTFILES = wix37-binaries.tar.bz2

CV2PDB_DISTFILES = cv2pdb-0.31.tar.gz
CV2PDB_PATCHES = cv2pdb-mingw.patch cv2pdb-nocxxstring.patch cv2pdb-timestamps.patch
CV2PDB_DIR = cv2pdb-0.31

VPATH = $(SRCDIR)/patches:$(XEN_DISTFILES)

BUILD_ENV = PATH=$(TOOLSDIR)/bin:$$PATH
ifeq (Darwin,$(shell uname))
BUILD_ENV += CPPFLAGS="-I/opt/local/include $$CPPFLAGS"
BUILD_ENV += LDFLAGS="-L/opt/local/lib $$LDFLAGS"
endif

BINUTILS_ENV = $(subst CPPFLAGS,CFLAGS,$(BUILD_ENV))

all: iasl/.installed regex/.installed wix/.installed cv2pdb/.installed

.PHONY: all clean

$(BUILDDIR:%=x)clean::
	rm -rf iasl regex

iasl/.installed: iasl/.built
	cd $(@D)/$(IASL_DIR)/source/compiler && $(BUILD_ENV) \
	  $(MAKE) install HOST=_WINDOWS CC="cc -m32" \
	    INSTALLDIR=$(TOOLSDIR)/bin
	@touch $@

iasl/.built: $(TOOLSDIR)/bin/.exists
iasl/.built: iasl/.patched
	cd $(@D)/$(IASL_DIR)/source/compiler && $(BUILD_ENV) \
	  $(MAKE) HOST=WIN32 \
	    INSTALLDIR=$(TOOLSDIR)/bin \
	    CC="cc -U__STRICT_ANSI__ -m32 -Wno-error=unknown-pragmas -Wno-error=redundant-decls"
	       # for 64bit: -m64 -UWIN32
	@touch $@

iasl/.patched: iasl/.extracted
iasl/.patched: $(IASL_PATCHES)
	@for p in $(filter-out iasl/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(IASL_DIR) && patch -p1); \
        done
	@touch $@

iasl/.extracted: $(IASL_DISTFILES)
	@rm -rf $(@D)/$(IASL_DIR)
	@mkdir -p $(@D)/$(IASL_DIR)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

regex/.installed: regex/.built
	cd $(@D)/build && \
	  $(MAKE) install
	@touch $@

regex/.built: regex/.configured
	cd $(@D)/build && \
	  $(MAKE)
	@touch $@

regex/.configured: $(TOOLSDIR)/bin/.exists $(INSTALL_DIR)/.exists
regex/.configured: regex/.patched
	@rm -rf $(@D)/build
	@mkdir -p $(@D)/build
	cd $(@D)/build && \
	  ../$(REGEX_DIR)/configure --prefix=$(INSTALL_DIR) \
	    --bindir=$(TOOLSDIR)/bin
	@touch $@

regex/.patched: regex/.extracted
regex/.patched: $(REGEX_PATCHES)
	@for p in $(filter-out regex/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(REGEX_DIR) && patch -p1); \
        done
	@touch $@

regex/.extracted: $(REGEX_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

wix/.installed: $(WIX_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	@rm -rf $(INSTALL_DIR)/wix
	@mkdir -p $(INSTALL_DIR)/wix
	cat $< | (cd $(INSTALL_DIR)/wix && tar --strip-components=1 -jxf -)
	@touch $@

cv2pdb/.installed: cv2pdb/.built
	@install -m 755 $(@D)/$(CV2PDB_DIR)/src/cv2pdb.exe $(TOOLSDIR)/bin
	@touch $@

cv2pdb/.built: $(TOOLSDIR)/bin/.exists
cv2pdb/.built: cv2pdb/.patched
	cd $(@D)/$(CV2PDB_DIR)/src && $(BUILD_ENV) \
	  $(MAKE) -f Makefile.mingw CXX="c++ -m32"
	@touch $@

cv2pdb/.patched: cv2pdb/.extracted
cv2pdb/.patched: $(CV2PDB_PATCHES)
	@for p in $(filter-out cv2pdb/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(CV2PDB_DIR) && patch -p1); \
        done
	@touch $@

cv2pdb/.extracted: $(CV2PDB_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar zxf -)
	@touch $@

.SECONDARY: iasl/.exists regex/.exists wix/.exists cv2pdb/.exists
iasl-%: iasl/.%
	@ :
regex-%: regex/.%
	@ :
wix-%: wix/.%
	@ :
cv2pdb-%: cv2pdb/.%
	@ :

endif # MAKENOW
