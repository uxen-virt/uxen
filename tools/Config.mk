
ifeq (,$(MAKENOW))

UXEN_TOOLS_TARGETS ?= $(TARGET_HOST)
UXEN_TOOLS_HOST ?= $(HOST)

BUILD_WINDOWS_TOOLS := $(if $(filter windows,$(UXEN_TOOLS_TARGETS)),,n-)
BUILD_OSX_TOOLS := $(if $(filter osx,$(UXEN_TOOLS_TARGETS)),,n-)

CROSS_MINGW_INSTALL_DIR = $(TOOLSDIR)/cross-mingw
CROSS_OSX_INSTALL_DIR = $(TOOLSDIR)/cross-osx
CROSS_VM_INSTALL_DIR = $(TOOLSDIR)/cross-vm
CROSS_W64L_INSTALL_DIR = $(TOOLSDIR)/cross-w64l
CROSS_WINDOWS_INSTALL_DIR = $(TOOLSDIR)/cross-windows

HOST_ALL_INSTALL_DIR = $(TOOLSDIR)/host-all
HOST_LINUX_INSTALL_DIR = $(TOOLSDIR)/host-linux
HOST_OSX_INSTALL_DIR = $(TOOLSDIR)/host-osx
HOST_WINDOWS_INSTALL_DIR = $(TOOLSDIR)/host-windows

INSTALL_BIN_DIR = $(TOOLSDIR)/bin

BUILD_INSTALL_DIR = $(TOOLSDIR)-build
BUILD_BIN_DIR_elf = $(BUILD_INSTALL_DIR)/bin-elf
BUILD_BIN_DIR_host = $(INSTALL_BIN_DIR)
BUILD_HOST_DIR = $(BUILD_INSTALL_DIR)/host

XEN_DISTFILES ?= $(TOPDIR)/../distfiles

TOOLS_DEBUG = -g
TOOLS_OPT = -O3

_TOOLS_ENV = CPPFLAGS="$(TOOLS_CPPFLAGS) $(_TOOLS_CPPFLAGS) $$CPPFLAGS"
_TOOLS_ENV += CFLAGS="ARCHFLAG $(TOOLS_CFLAGS) $(_TOOLS_CFLAGS) $(TOOLS_DEBUG) $(TOOLS_OPT) $$CFLAGS"
_TOOLS_ENV += LDFLAGS="ARCHFLAG $(TOOLS_LDFLAGS) $(_TOOLS_LDFLAGS) $(TOOLS_DEBUG) $$LDFLAGS"

HOST_TOOLS_ENV = $(_TOOLS_ENV:ARCHFLAG=)
BUILD_TOOLS_ENV = $(_TOOLS_ENV:ARCHFLAG=)

# reset HOST_ based on UXEN_TOOLS_HOST
HOST_WINDOWS = $(patsubst %,n-windows-,$(filter-out windows,$(UXEN_TOOLS_HOST)))
HOST_LINUX = $(patsubst %,n-linux-,$(filter-out linux,$(UXEN_TOOLS_HOST)))
HOST_OSX = $(patsubst %,n-osx-,$(filter-out osx,$(UXEN_TOOLS_HOST)))
HOST_NOT_WINDOWS = $(patsubst %,n-windows-,$(filter windows,$(UXEN_TOOLS_HOST)))
HOST_NOT_LINUX = $(patsubst %,n-linux-,$(filter linux,$(UXEN_TOOLS_HOST)))
HOST_NOT_OSX = $(patsubst %,n-osx-,$(filter osx,$(UXEN_TOOLS_HOST)))

HOST_EXE_SUFFIX =

_UXEN_TOOLS_HOST ?= $(UXEN_TOOLS_HOST)
ifeq ($(UXEN_TOOLS_HOST),$(HOST))
CANADIAN = no-
endif

ifeq ($(_UXEN_TOOLS_HOST),windows)
TOOLS_HOST ?= x86_64-w64-mingw32
TOOLS_CONFIGURE_HOST ?= i686-w64-mingw32
TOOLS_HOST_PREFIX ?= $(TOOLS_CONFIGURE_HOST)-
HOST_EXE_SUFFIX = .exe
BUILD_BIN_DIR_host = $(BUILD_INSTALL_DIR)/bin-mingw
endif

TOOLS_CONFIGURE_BUILD ?= $(if $(TOOLS_BUILD),$(TOOLS_BUILD),$$([ -x ../$(1)/config.guess ] && ../$(1)/config.guess || $(TOPDIR)/tools/config.guess))
_TOOLS_CONFIGURE_HOST ?= $(if $(TOOLS_HOST),$(TOOLS_HOST),$$([ -x ../$(1)/config.guess ] && ../$(1)/config.guess || $(TOPDIR)/tools/config.guess))
TOOLS_CONFIGURE_HOST ?= $(_TOOLS_CONFIGURE_HOST)
ifeq ($(_UXEN_TOOLS_HOST),build)
override TOOLS_CONFIGURE_HOST = $(TOOLS_CONFIGURE_BUILD)
endif
TOOLS_HOST_PREFIX ?= $(if $(TOOLS_HOST),$(TOOLS_HOST)-,)
$(WINDOWS)TOOLS_CONFIGURE_TARGET = x86_64-w64-mingw32
$(OSX)TOOLS_CONFIGURE_TARGET = x86_64-apple-darwin

configure = ../$(1)/$(CONFIGURE) \
	      --build=$(TOOLS_CONFIGURE_BUILD) \
	      --host=$(TOOLS_CONFIGURE_HOST)
CONFIGURE_target = --target=$(TOOLS_CONFIGURE_TARGET)
CONFIGURE_strip = --enable-strip
CONFIGURE ?= configure $(CONFIGURE_target) $(CONFIGURE_strip)

%/.configured %/.configured-32 %/.configured-libbfd %/.configured-libbfd-32 %/.configured-headers: | $(INSTALL_DIR)/. $(INSTALL_BIN_DIR)/.
%/.:
	@mkdir -p $@

VPATH = $(SRCDIR)/patches:$(SRCDIR)/files:$(XEN_DISTFILES)

.PHONY: all clean

clean:
	rm -rf $(PKGS)

define goal-installed3
$(1)/.installed$(2): $(1)/.built$(3)
	@echo ======== $(1)-installed$(2) =====================================
	echo $$$$PATH
	$$(Xpre_$(1)_installed$$(subst -,_,$(2)))
	cd $$(@D)/build$(4)$$(Xsubdir_$(1)_build$$(subst -,_,$(2))) && \
	  PATH="$$($(1)_ADDPATH)$$$$PATH" && $(5) $$(MAKE) $(6)
	$$(Xpost_$(1)_installed$$(subst -,_,$(2)))
	@touch $$@
endef

define goal-installed
$(1)/.installed$(2): $(1)/.built$(2)
	@echo ======== $(1)-installed$(2) =====================================
	echo $$$$PATH
	$$(Xpre_$(1)_installed$$(subst -,_,$(2)))
	cd $$(@D)/build$(2)$$(Xsubdir_$(1)_build$$(subst -,_,$(2))) && \
	  PATH="$$($(1)_ADDPATH)$$$$PATH" && $(3) $$(MAKE) $(4)
	$$(Xpost_$(1)_installed$$(subst -,_,$(2)))
	@touch $$@
endef

define goal-built3
$(1)/.built$(2): $(1)/.configured$(3)
	@echo ======== $(1)-built$(2) =====================================
	echo $$$$PATH
	$$(Xpre_$(1)_built$$(subst -,_,$(2)))
	cd $$(@D)/build$(4)$$(Xsubdir_$(1)_build$$(subst -,_,$(2))) && \
	  PATH="$$($(1)_ADDPATH)$$$$PATH" && $(5) $$(MAKE) $(6)
	$$(Xpost_$(1)_built$$(subst -,_,$(2)))
	@touch $$@
endef

define goal-built
$(1)/.built$(2): $(1)/.configured$(2)
	@echo ======== $(1)-built$(2) =====================================
	echo $$$$PATH
	$$(Xpre_$(1)_built$$(subst -,_,$(2)))
	cd $$(@D)/build$(2)$$(Xsubdir_$(1)_build$$(subst -,_,$(2))) && \
	  PATH="$$($(1)_ADDPATH)$$$$PATH" && $(3) $$(MAKE) $(4)
	$$(Xpost_$(1)_built$$(subst -,_,$(2)))
	@touch $$@
endef

define goal-configured
$(1)/.configured$(2): | $(INSTALL_DIR)/. $(INSTALL_BIN_DIR)/.
$(1)/.configured$(2): $(1)/.patched
	@echo ======== $(1)-configured$(2) =====================================
	echo $$$$PATH
	@rm -rf $$(@D)/build$(2)
	@mkdir -p $$(@D)/build$(2)
	$$(Xpre_$(1)_configured$$(subst -,_,$(2)))
	cd $$(@D)/build$(2) && PATH="$$($(1)_ADDPATH)$$$$PATH" && $(3) \
	  $$(call configure,$$($(1)_DIR)$$(Xsubdir_$(1)_configured$$(subst -,_,$(2)))) \
	  $(4)
	$$(Xpost_$(1)_configured$$(subst -,_,$(2)))
	@touch $$@
endef

define goal-patched
$(1)/.patched: $(1)/.extracted
$(1)/.patched: $$($(1)_PATCHES)
	@echo ======== $(1)-patched =====================================
	for p in $$(filter-out $(1)/.extracted,$$^); \
        do \
          echo Applying $$$$p; \
          cat $$$$p | (cd $$(@D)/$$($(1)_DIR) && patch --binary -p1); \
        done
	@touch $$@
endef

define goal-extracted
$(1)/.extracted: $$($(1)_DISTFILES)
	@echo ======== $(1)-extracted =====================================
	@rm -rf $$(@D)
	@mkdir -p $$(@D)
	cat $$< | (cd $$(@D) && case $$< in \
	  *.bz2) tar jxf -;; \
	  *.gz) tar zxf -;; \
	esac)
	@touch $$@
endef

define goal-package
.SECONDARY: | $(1)/.
$(1)-%: $(1)/.%
	@ :
$(1)/.:
	@mkdir -p $(1)
.PHONY: clean-$(1)
clean-$(1):
	@rm -rf $(1)
endef

define packages
$(foreach pkg,$(1),$(eval $(call goal-package,$(pkg))))
endef

# define $(,) = , for eval/call
, = ,

endif # MAKENOW
