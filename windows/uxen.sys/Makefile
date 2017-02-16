#
# Copyright 2016-2017, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

SRCROOT = $(SRCDIR)

VPATH = $(SRCROOT)

ifneq (n-,$(HOST_WINDOWS))

uxen_sys_SRCS = \
	uxen.c \
	uxen_debug.c \
	uxen_call.c \
	uxen_cpu.c \
	uxen_ioctl.c \
	uxen_load.c \
	uxen_logging.c \
	uxen_mem.c \
	uxen_ops.c \
	memcache-dm.c \
	pagemap.c \
	rbtree.c \
	v4v.c \
	uxen.rc

ifeq ($(TARGET_HOST_BITS),32)
uxen_sys_SRCS += \
	uxen_hiber.c \
	i386/uxen_sys.asm
else
uxen_sys_SRCS += \
	uxen_stackwalk.c \
	amd64/uxen_sys.asm \
	amd64/uxen_debug_sup.asm
endif

EWDK_INCLUDES = \
	//I$(call dosdir,$(EWDK_KIT_DIR_include)/um) \
	//I$(call dosdir,$(EWDK_KIT_DIR_include)/shared) \
	//I$(call dosdir,$(EWDK_KIT_DIR_include)/km) \
	//I$(call dosdir,$(EWDK_KIT_DIR_include)/km/crt)
EWDK_INCLUDE_warning = \
	//FI$(call dosdir,$(EWDK_KIT_DIR_include)/shared/warning.h)
EWDK_LIBS = \
	$(call dosdir,$(EWDK_KIT_DIR_lib)/BufferOverflowK.lib) \
	$(call dosdir,$(EWDK_KIT_DIR_lib)/ntoskrnl.lib) \
	$(call dosdir,$(EWDK_KIT_DIR_lib)/hal.lib) \
	$(call dosdir,$(EWDK_KIT_DIR_lib)/wdmsec.lib)

uxen_sys_INCLUDE = \
	. \
	$(BUILDDIR_xen)/include \
	$(TOPDIR)/xen/include \
	$(TOPDIR)/common \
	$(TOPDIR)/common/include \
	$(TOPDIR)/windows/include \
	$(TOPDIR)/windows/uxenv4vlib
uxen_sys_INCLUDE_dos := $(foreach include,$(uxen_sys_INCLUDE),//I$(call dospath,$(include)))

ifeq ($(TARGET_HOST_BITS),32)
uxen_sys_CPPFLAGS = \
	//D_X86_=1 //Di386=1 //DSTD_CALL //DFPO=0 //D__i386__
uxen_sys_CFLAGS = \
	//Gm- //Gz //hotpatch //Oy-
uxen_sys_RCFLAGS = \
	-DSXS_PROCESSOR_ARCHITECTURE="x86" \
	$(WINDRESFLAGS)
uxen_sys_LDFLAGS = \
	//functionpadmin:5 \
	//entry:GsDriverEntry@8
uxen_sys_ASFLAGS = \
	//safeseh //coff //Zm
uxen_sys_LDOBJS = \
	..\\uxenv4vlib\\uxenv4vlib.lib \
	$(BUILDDIR_xen)/uxen-cv.obj
else
uxen_sys_CPPFLAGS = \
	//D_WIN64 //D_AMD64_ //DAMD64 //D__x86_64__
uxen_sys_CFLAGS = \
	//GL //homeparams
uxen_sys_RCFLAGS = \
	-DSXS_PROCESSOR_ARCHITECTURE="AMD64" \
	$(WINDRESFLAGS)
uxen_sys_LDFLAGS = \
	//LTCG:NOSTATUS \
	//functionpadmin:6 \
	//entry:GsDriverEntry
uxen_sys_LDOBJS = \
	..\\uxenv4vlib\\uxenv4vlib.lib \
	$(BUILDDIR_xen)/uxen-cv.obj $(BUILDDIR_xen)/uxen-xpdata.obj
uxen_sys_ASFLAGS =
endif

$(DEBUG_ONLY)uxen_sys_CPPFLAGS += \
	//DDBG=1 \
	//DDEPRECATE_DDK_FUNCTIONS=1 //DMSC_NOOPT
$(DEBUG_ONLY)uxen_sys_CFLAGS += \
	//Od //Oi
$(REL_ONLY)uxen_sys_CPPFLAGS += \
	//DNDEBUG
$(REL_ONLY)uxen_sys_CFLAGS += \
	//WX //Oxs

uxen_sys_CPPFLAGS += \
	//DPOOL_NX_OPTIN=1 \
	//DCONDITION_HANDLING=1 \
	//DNT_UP=1 //DNT_INST=0 //DWIN32=100 //D_NT1X_=100 //DWINNT=1 \
	//D_WIN32_WINNT=0x0601 //DWINVER=0x0601 //D_WIN32_IE=0x0800 \
	//DWIN32_LEAN_AND_MEAN=1 \
	//DDEVL=1 \
	//D__BUILDMACHINE__=WinDDK //D_DLL=1 \
	//DNTDDI_VERSION=0x06010000 \
	//D_KERNEL_MODE \
	//D__XEN__ //D__UXEN__ //D__UXEN_SYS__ \
	//D__MS_ABI__ //D__UXEN_EMBEDDED__ //D__OBJ_PE__ \
	//DUXEN_HOST_WINDOWS \
	//D__KERNEL__ //D_DEFENSIVE_LIMITS \
	//DBUILD_INFO="\"build_info.h\""

uxen_sys_RES = $(patsubst %.rc,%.res,$(filter %.rc,$(uxen_sys_SRCS)))

$(uxen_sys_RES): %.res: %.rc build_info.h
	$(_W)echo Compiling - $@
	$(_V)$(EWDK_KIT_DIR_bin)/rc.exe //nologo \
	  -l 409 \
	  $(uxen_sys_RCFLAGS) \
	  -DSXS_TARGET="uxen.sys" \
	  -DSYSTEM_COMPATIBLE_ASSEMBLY_NAME="Microsoft.Windows.SystemCompatible" \
	  -DLSYSTEM_COMPATIBLE_ASSEMBLY_NAME=L"Microsoft.Windows.SystemCompatible" \
	  -DSXS_ASSEMBLY_VERSION="" \
	  //r //fo $@ \
	  $(uxen_sys_CPPFLAGS) \
	  $(uxen_sys_INCLUDE_dos) \
	  $(EWDK_INCLUDES) \
	  $(call dospath,$<)

uxen_sys_OBJ_asm = $(patsubst %.asm,%.obj,$(filter %.asm,$(uxen_sys_SRCS)))

$(uxen_sys_OBJ_asm): %.obj: %.asm
	$(_W)echo Assembling - $@
	$(_V)$(EWDK_VC_asm) //nologo \
	  //c //Cx \
	  $(uxen_sys_INCLUDE_dos) \
	  $(EWDK_INCLUDES) \
	  //Zi //Zi \
	  $(uxen_sys_CPPFLAGS) \
	  $(uxen_sys_ASFLAGS) \
	  //Fo$(call dospath,$@) \
	  $(call dospath,$<)

uxen_sys_OBJ_c = $(patsubst %.c,%.obj,$(filter %.c,$(uxen_sys_SRCS)))
$(uxen_sys_OBJ_c): %.obj: %.c
	$(_W)echo Compiling - $@
	$(_V)$(EWDK_VC_DIR_bin)/cl.exe //nologo \
	  //Fo$(call dospath,$@) //FC \
	  $(uxen_sys_INCLUDE_dos) \
	  $(EWDK_INCLUDES) \
	  $(uxen_sys_CPPFLAGS) \
	  $(uxen_sys_CFLAGS) \
	  //c //Zc:wchar_t- //Zl //Zp8 //Gy \
	  -cbstring //WX //EHs-c- //GR- //GF //GS //Zi //Zi \
	  //Fd$(call dospath,.)\\ \
	  //DKMDF_MAJOR_VERSION_STRING=01 //DKMDF_MINOR_VERSION_STRING=009 \
	  //typedil- //wd4603 //wd4627 \
	  $(EWDK_INCLUDE_warning) \
	  $(call dospath,$<)

uxen.sys: override PATH := $(PATH):$(subst $(EWDK_DIR),$(EWDK_DIR_path),$(EWDK_PATH_CRT)):$(subst $(EWDK_DIR),$(EWDK_DIR_path),$(EWDK_PATH_BIN))
uxen.sys: $(uxen_sys_RES) $(uxen_sys_OBJ_asm) $(uxen_sys_OBJ_c)
	$(_W)echo Linking - $@
	$(_V)$(EWDK_VC_DIR_bin)/link.exe //nologo \
	  //SECTION:.rsrc,!d \
	  //MERGE:_PAGE=PAGE \
	  //MERGE:_TEXT=.text \
	  //SECTION:INIT,d \
	  //OPT:REF //OPT:ICF \
	  //IGNORE:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221,4108,4088,4218,4218,4235 \
	  //INCREMENTAL:NO \
	  //release \
	  //NODEFAULTLIB \
	  //WX //debug //debugtype:cv,fixup,pdata \
	  //version:6.1 //osversion:6.1 \
	  //pdbcompress //STACK:0x40000,0x1000 \
	  //driver //base:0x10000 //subsystem:native,6.01 \
	  $(uxen_sys_LDFLAGS) \
	  //out:$(call dospath,$@) $^ \
	  $(EWDK_LIBS) \
	  $(uxen_sys_LDOBJS)
	$(_W)echo Signing - $@
	$(_V)cmd //c $(UXEN_WINDOWS_SIGN) $@ || { rm -f $@; false; }

install_uxen.sys: uxen.sys
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(DISTDIR)
	$(_W)echo Installing - $(<F:sys=pdb)
	$(_V)install $(<:sys=pdb) $(DISTDIR)

dist: install_uxen.sys

.PHONY: build_info.h
build_info.h:
	$(_W)echo Generating - $(@F)
	@( echo "#define UXEN_DRIVER_FILEVERSION1 " $$(cd $(SRCDIR) && git log --pretty=format:%cd --date=short -n 1 | sed 's/\(....\)-..-../\1/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION2 " $$(cd $(SRCDIR) && git log --pretty=format:%cd --date=short -n 1 | sed 's/....-\(..\)-\(..\)/\1\2/'); \
	   echo "#define UXEN_DRIVER_FILEVERSION3 " $$(( $$(cd $(SRCDIR) && git log --pretty=format:%ct -n 1) / 65536 )); \
	   echo "#define UXEN_DRIVER_FILEVERSION4 " $$(( $$(cd $(SRCDIR) && git log --pretty=format:%ct -n 1) % 65536 )); \
	   echo "#define UXEN_DRIVER_VERSION_CHANGESET \""$$(cd $(SRCDIR) && git log --pretty=format:%H -n 1 && git diff --quiet || echo -dirty)"\""; \
	   ) >$@

endif # HOST_WINDOWS

install_uxen_desc_sys.h: $(SDKDIR_include)/.exists
install_uxen_desc_sys.h: $(TOPDIR)/common/include/uxen_desc_sys.h
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(SDKDIR_include))

install_uxen.inf: uxen.inf
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(DISTDIR))

all:
dist: install_uxen_desc_sys.h install_uxen.inf

-include .deps/*.d

endif # MAKENOW

#clean::
#	@$(if $(BUILDDIR),[ -d $(BUILDDIR) ] && rm -rf $(BUILDDIR),:)
