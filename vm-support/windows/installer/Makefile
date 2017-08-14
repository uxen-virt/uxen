#
# Copyright 2012-2017, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

ELEVATE_DIR = $(DISTDIR_VM_SUPPORT)/elevate
UXENCLIPBOARD_DIR = $(DISTDIR_VM_SUPPORT)/uxenclipboard
UXENDISP_DIR = $(DISTDIR_VM_SUPPORT)/uxendisp/xddm
UXENAUDIO_DIR = $(DISTDIR_VM_SUPPORT)/uxenaudio
UXENDMPDRV_DIR = $(DISTDIR_VM_SUPPORT)/uxendmpdrv
UXENEVENT_DIR = $(DISTDIR_VM_SUPPORT)/uxenevent
UXENKMDOD_DIR = $(DISTDIR_VM_SUPPORT)/uxenkmdod
UXENMOUSE_DIR = $(DISTDIR_VM_SUPPORT)/uxenmouse
UXENPLATFORM_DIR = $(DISTDIR_VM_SUPPORT)/uxenplatform
UXENSF_DIR = $(DISTDIR_VM_SUPPORT)/uxensf
UXENSTOR_DIR = $(DISTDIR_VM_SUPPORT)/uxenstor
UXENSVC_DIR = $(DISTDIR_VM_SUPPORT)/uxensvc
UXENVMLIB_DIR = $(DISTDIR_VM_SUPPORT)/uxenvmlib
UXENV4VLIB_DIR = $(DISTDIR_VM_SUPPORT)/uxenv4vlib
UXENV4VGUEST_DIR = $(DISTDIR_VM_SUPPORT)/uxenv4vguest
UXENNET_DIR = $(DISTDIR_VM_SUPPORT)/uxennet
UXENNULLNET_DIR = $(DISTDIR_VM_SUPPORT)/uxennullnet
UXENHID_DIR = $(DISTDIR_VM_SUPPORT)/uxenhid
UXENH264_DIR = $(DISTDIR_VM_SUPPORT)/uxenh264

TARGETS = all dist clean

.PHONY: $(TARGETS)

WIX_DIR = $(TOOLSDIR)/cross-windows/wix
CANDLE = $(WIX_DIR)/candle.exe
LIGHT = $(WIX_DIR)/light.exe
WIXFLAGS = -ext WixUIExtension.dll \
	   -ext WixDifxAppExtension.dll \
	   -ext WixUtilExtension.dll

ifeq ($(TARGET_VM_SUPPORT_BITS),32)
WIX_LIBS = $(WIX_DIR)/difxapp_x86.wixlib
CANDLE_FLAGS = -arch x86
WIN64=no
else
WIX_LIBS = $(WIX_DIR)/difxapp_x64.wixlib
CANDLE_FLAGS = -arch x64
WIN64=yes
endif

WIX_INCLUDES = -delevatedir=$(ELEVATE_DIR) \
	       -dsrcdir=$(SRCDIR) \
	       -duxenclipboarddir=$(UXENCLIPBOARD_DIR) \
	       -duxendispdir=$(UXENDISP_DIR) \
	       -duxenaudiodir=$(UXENAUDIO_DIR) \
	       -duxendmpdrvdir=$(UXENDMPDRV_DIR) \
	       -duxeneventdir=$(UXENEVENT_DIR) \
	       -duxenkmdoddir=$(UXENKMDOD_DIR) \
	       -duxenmousedir=$(UXENMOUSE_DIR) \
	       -duxenplatformdir=$(UXENPLATFORM_DIR) \
	       -duxensfdir=$(UXENSF_DIR) \
	       -duxenstordir=$(UXENSTOR_DIR) \
	       -duxenv4vguestdir=$(UXENV4VGUEST_DIR) \
	       -duxennetdir=$(UXENNET_DIR) \
	       -duxennullnetdir=$(UXENNULLNET_DIR) \
	       -duxensvcdir=$(UXENSVC_DIR) \
	       -dWin64=$(WIN64) \
	       -duxenhiddir=$(UXENHID_DIR) \
	       -duxenh264dir=$(UXENH264_DIR)

WIX_DEPS = $(ELEVATE_DIR)/elevate.exe \
	   $(UXENCLIPBOARD_DIR)/uxenclipboard.exe \
	   $(UXENDISP_DIR)/uxendisp.sys \
	   $(UXENAUDIO_DIR)/uxenaudio.sys \
	   $(UXENDMPDRV_DIR)/uxendmpdrv.sys \
	   $(UXENEVENT_DIR)/uxenevent.exe \
	   $(UXENKMDOD_DIR)/uxenkmdod.sys \
	   $(UXENMOUSE_DIR)/uxenmouse.sys \
	   $(UXENPLATFORM_DIR)/uxenplatform.sys \
	   $(UXENV4VGUEST_DIR)/uxenv4vguest.sys \
	   $(UXENNET_DIR)/uxennet.sys \
	   $(UXENNULLNET_DIR)/uxennullnet.sys \
	   $(UXENSF_DIR)/uxensf.sys \
	   $(UXENSTOR_DIR)/uxenstor.sys \
	   $(UXENSVC_DIR)/uxensvc.exe \
	   $(UXENHID_DIR)/uxenhid.sys \
	   $(UXENH264_DIR)/uxenh26432.dll \
	   $(UXENH264_DIR)/uxenh26464.dll

$(WIX_DEPS): $(UXENVMLIB_DIR)/uxenvmlib.sys $(UXENV4VLIB_DIR)/uxenv4vlib.sys

INSTALLER = uxen-vm-support.msi
INSTALLER_WIXOBJS = installer.wixobj

# Only produce msi when calling the dist rule
all:

clean::
	@$(if $(BUILDDIR),rm -rf $(BUILDDIR),:)

dist: $(INSTALLER)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(DISTDIR))

$(UXENAUDIO_DIR)/uxenaudio.sys:
	$(MAKE) -C $(SRCDIR)/../uxenaudio dist
$(UXENDISP_DIR)/uxendisp.sys:
	$(MAKE) -C $(SRCDIR)/../uxendisp/xddm dist
$(UXENMOUSE_DIR)/uxenmouse.sys:
	$(MAKE) -C $(SRCDIR)/../uxenmouse dist
$(UXENSF_DIR)/uxensf.sys:
	$(MAKE) -C $(SRCDIR)/../uxensf dist
$(UXENCLIPBOARD_DIR)/uxenclipboard.exe:
	$(MAKE) -C $(SRCDIR)/../uxenclipboard dist
$(UXENEVENT_DIR)/uxenevent.exe:
	$(MAKE) -C $(SRCDIR)/../uxenevent dist
$(UXENDMPDRV_DIR)/uxendmpdrv.sys:
	$(MAKE) -C $(SRCDIR)/../uxendmpdrv dist
$(UXENKMDOD_DIR)/uxenkmdod.sys:
	$(MAKE) -C $(SRCDIR)/../uxenkmdod dist
$(UXENPLATFORM_DIR)/uxenplatform.sys:
	$(MAKE) -C $(SRCDIR)/../uxenplatform dist
$(UXENSTOR_DIR)/uxenstor.sys:
	$(MAKE) -C $(SRCDIR)/../uxenstor dist
$(UXENV4VGUEST_DIR)/uxenv4vguest.sys:
	$(MAKE) -C $(SRCDIR)/../uxenv4vguest dist
$(UXENNET_DIR)/uxennet.sys:
	$(MAKE) -C $(SRCDIR)/../uxennet dist
$(UXENNULLNET_DIR)/uxennullnet.sys:
	$(MAKE) -C $(SRCDIR)/../uxennullnet dist
$(UXENVMLIB_DIR)/uxenvmlib.sys:
	$(MAKE) -C $(SRCDIR)/../uxenvmlib dist
$(UXENV4VLIB_DIR)/uxenv4vlib.sys:
	$(MAKE) -C $(SRCDIR)/../uxenv4vlib dist
$(UXENSVC_DIR)/uxensvc.exe:
	$(MAKE) -C $(SRCDIR)/../uxensvc dist
$(ELEVATE_DIR)/elevate.exe:
	$(MAKE) -C $(SRCDIR)/../elevate dist
$(UXENHID_DIR)/uxenhid.sys:
	$(MAKE) -C $(SRCDIR)/../uxenhid dist
$(UXENH264_DIR)/uxenh264.dll:
	$(MAKE) -C $(SRCDIR)/../uxenh264 dist

$(INSTALLER): $(INSTALLER_WIXOBJS) $(WIX_DEPS)
	$(_W)echo Linking - $@
	$(_V)$(call sign,$@,$(LIGHT) $(WIXFLAGS) $(WIX_LIBS) $< -o $@)

%.wixobj: %.wxs
	$(CANDLE) $(CANDLE_FLAGS) $(WIXFLAGS) $(WIX_INCLUDES) $< -o $@

endif # MAKENOW
