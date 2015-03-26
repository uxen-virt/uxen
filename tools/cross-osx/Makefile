
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

XEN_DISTFILES ?= $(TOPDIR)/../distfiles

INSTALL_DIR = $(TOOLSDIR)/cross-osx

OBJCONV_DISTFILES = objconv-2013-Jun-25.tar.bz2
OBJCONV_PATCHES = 
OBJCONV_DIR = objconv-2013-Jun-25
OBJCONV_CFLAGS="-Wno-logical-op-parentheses"

VPATH = $(SRCDIR)/patches:$(SRCDIR)/files:$(XEN_DISTFILES)

all: objconv/.installed

.PHONY: all clean

clean:
	rm -rf objconv

objconv/.installed: $(TOOLSDIR)/bin/.exists
objconv/.installed: objconv/.built
	cp $(@D)/build/objconv $(TOOLSDIR)/bin
	@touch $@

objconv/.built: objconv/.patched
	@mkdir -p $(@D)/build
	cd $(@D)/build && \
	  g++ -o objconv -O2 ../$(OBJCONV_DIR)/*.cpp $(OBJCONV_CFLAGS)
	@touch $@

objconv/.patched: objconv/.extracted
objconv/.patched: $(OBJCONV_PATCHES)
	@for p in $(filter-out objconv/.extracted,$^); \
        do \
          echo Applying $$p; \
          cat $$p | (cd $(@D)/$(OBJCONV_DIR) && patch -p1); \
        done
	@touch $@

objconv/.extracted: $(OBJCONV_DISTFILES)
	@rm -rf $(@D)
	@mkdir -p $(@D)
	cat $< | (cd $(@D) && tar jxf -)
	@touch $@

.SECONDARY: objconv/.exists
objconv-%: objconv/.%
	@ :

endif # MAKENOW
