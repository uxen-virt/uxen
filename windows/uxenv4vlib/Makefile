#
# Copyright 2016-2019, Bromium, Inc.
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

DISTDIR_uxenv4vlib ?= $(DISTDIR)
SDKDIR_lib_uxenv4vlib ?= $(SDKDIR_lib)
SDKDIR_include_uxenv4vlib ?= $(SDKDIR_include)

uxenv4vlib_SRCS = \
	main.c \
	alloc.c \
	hypercall.c \
	export.c \
	shared.c \
	plumbing.c \
	hook.c \
	pde.c \
	resume.c \
	ring.c \
	notify.c \
	gh_create.c \
	gh_csq.c \
	gh_hypercall.c \
	gh_ioctl.c \
	gh_ring.c \
	gh_rw.c \
	gh_xenv4v.c \
	uxenv4vlib.rc

ifeq ($(TARGET_HOST_BITS),32)
uxenv4vlib_SRCS += \
	i386/ax_hypercall_sup.asm
else
uxenv4vlib_SRCS += \
	amd64/ax_hypercall_sup.asm
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

uxenv4vlib_INCLUDE = \
	$(BUILDDIR_xen)/include \
	$(TOPDIR)/xen/include \
	$(TOPDIR)/common
uxenv4vlib_INCLUDE_dos := $(foreach include,$(uxenv4vlib_INCLUDE),//I$(call dospath,$(include)))

ifeq ($(TARGET_HOST_BITS),32)
uxenv4vlib_CPPFLAGS = \
	//D_X86_=1 //Di386=1 //DSTD_CALL //DFPO=0 //D__i386__
uxenv4vlib_CFLAGS = \
	//Gm- //Gz //hotpatch //Oy-
uxenv4vlib_RCFLAGS = \
	-DSXS_PROCESSOR_ARCHITECTURE="x86" \
	$(WINDRESFLAGS)
uxenv4vlib_LDFLAGS = \
	//safeseh \
	//functionpadmin:5 \
	//entry:GsDriverEntry@8
uxenv4vlib_ASFLAGS = \
	//safeseh //coff //Zm
else
uxenv4vlib_CPPFLAGS = \
	//D_WIN64 //D_AMD64_ //DAMD64 //D__x86_64__
uxenv4vlib_CFLAGS = \
	//GL //homeparams
uxenv4vlib_RCFLAGS = \
	-DSXS_PROCESSOR_ARCHITECTURE="AMD64" \
	$(WINDRESFLAGS)
uxenv4vlib_LDFLAGS = \
	//LTCG:NOSTATUS \
	//functionpadmin:6 \
	//entry:GsDriverEntry
uxenv4vlib_ASFLAGS =
endif

$(DEBUG_ONLY)uxenv4vlib_CPPFLAGS += \
	//DDBG=1 \
	//DDEPRECATE_DDK_FUNCTIONS=1 //DMSC_NOOPT
$(DEBUG_ONLY)uxenv4vlib_CFLAGS += \
	//Od //Oi
$(REL_ONLY)uxenv4vlib_CPPFLAGS += \
	//DNDEBUG
$(REL_ONLY)uxenv4vlib_CFLAGS += \
	//WX //Oxs

uxenv4vlib_CPPFLAGS += \
	//DPOOL_NX_OPTIN=1 \
	//DCONDITION_HANDLING=1 \
	//DNT_UP=1 //DNT_INST=0 //DWIN32=100 //D_NT1X_=100 //DWINNT=1 \
	//D_WIN32_WINNT=0x0601 //DWINVER=0x0601 //D_WIN32_IE=0x0800 \
	//DWIN32_LEAN_AND_MEAN=1 \
	//DDEVL=1 \
	//D__BUILDMACHINE__=WinDDK //D_DLL=1 \
	//DNTDDI_VERSION=0x06010000 \
	//D_KERNEL_MODE \
	//D__UXEN_TOOLS__ //D__MS_ABI__ \
	//D__KERNEL__ //D_DEFENSIVE_LIMITS \
	//DBUILD_INFO="\"build_info.h\""

uxenv4vlib_RES = $(patsubst %.rc,%.res,$(filter %.rc,$(uxenv4vlib_SRCS)))

$(uxenv4vlib_RES): %.res: %.rc build_info.h
	$(_W)echo Compiling - $@
	$(_V)$(EWDK_KIT_DIR_bin)/rc.exe //nologo \
	  -l 409 \
	  $(uxenv4vlib_RCFLAGS) \
	  -DSXS_TARGET="uxenv4vlib.sys" \
	  -DSYSTEM_COMPATIBLE_ASSEMBLY_NAME="Microsoft.Windows.SystemCompatible" \
	  -DLSYSTEM_COMPATIBLE_ASSEMBLY_NAME=L"Microsoft.Windows.SystemCompatible" \
	  -DSXS_ASSEMBLY_VERSION="" \
	  //r //fo $@ \
	  $(uxenv4vlib_CPPFLAGS) \
	  $(uxenv4vlib_INCLUDE_dos) \
	  $(EWDK_INCLUDES) \
	  $(call dospath,$<)

uxenv4vlib_OBJ_c = $(patsubst %.c,%.obj,$(filter %.c,$(uxenv4vlib_SRCS)))
$(uxenv4vlib_OBJ_c): %.obj: %.c
	$(_W)echo Compiling - $@
	$(_V)$(EWDK_VC_DIR_bin)/cl.exe //nologo \
	  //Fo$(call dospath,$@) //FC \
	  $(uxenv4vlib_INCLUDE_dos) \
	  $(EWDK_INCLUDES) \
	  $(uxenv4vlib_CPPFLAGS) \
	  $(uxenv4vlib_CFLAGS) \
	  //c //Zc:wchar_t- //Zl //Zp8 //Gy \
	  -cbstring //W3 //EHs-c- //GR- //GF //GS //Zi //Zi \
	  //Fd$(call dospath,.)\\ \
	  //DKMDF_MAJOR_VERSION_STRING=01 //DKMDF_MINOR_VERSION_STRING=009 \
	  //typedil- //wd4603 //wd4627 \
	  $(EWDK_INCLUDE_warning) \
	  $(call dospath,$<)

uxenv4vlib_OBJ_asm = $(patsubst %.asm,%.obj,$(filter %.asm,$(uxenv4vlib_SRCS)))

$(uxenv4vlib_OBJ_asm): %.obj: %.asm
	$(_W)echo Assembling - $@
	$(_V)$(EWDK_VC_asm) //nologo \
	  //c //Cx \
	  $(uxenv4vlib_INCLUDE_dos) \
	  $(EWDK_INCLUDES) \
	  //Zi //Zi \
	  $(uxenv4vlib_CPPFLAGS) \
	  $(uxenv4vlib_ASFLAGS) \
	  //Fo$(call dospath,$@) \
	  $(call dospath,$<)

uxenv4vlib.sys: override PATH := $(PATH):$(subst $(EWDK_DIR),$(EWDK_DIR_path),$(EWDK_PATH_CRT)):$(subst $(EWDK_DIR),$(EWDK_DIR_path),$(EWDK_PATH_BIN))
uxenv4vlib.sys: $(uxenv4vlib_RES) $(uxenv4vlib_OBJ_asm) $(uxenv4vlib_OBJ_c)
	$(_W)echo Linking - $@
	$(_V)$(EWDK_VC_DIR_bin)/link.exe //nologo \
	  //DEF:$(call dospath,$(SRCDIR)/uxenv4vlib.def) \
	  //SECTION:.shared,RWS \
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
	  //base:0x10000 \
	  $(uxenv4vlib_LDFLAGS) \
	  //out:$(call dospath,$@) $^ \
	  $(EWDK_LIBS)
	$(_W)echo Signing - $@
	$(_V)cmd //c $(UXEN_WINDOWS_SIGN) $@ || { rm -f $@; false; }

install_uxenv4vlib.sys: uxenv4vlib.sys
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR_uxenv4vlib)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(DISTDIR_uxenv4vlib)
	$(_W)echo Installing - $(<F:sys=pdb)
	$(_V)install $(<:sys=pdb) $(DISTDIR_uxenv4vlib)
	@mkdir -p $(SDKDIR_lib_uxenv4vlib)
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_lib_uxenv4vlib)
	$(_W)echo Installing - $(<F:sys=lib)
	$(_V)install $(<:sys=lib) $(SDKDIR_lib_uxenv4vlib)
#	$(_W)echo Installing - $(<F:sys=exp)
#	$(_V)install $(<:sys=exp) $(SDKDIR_lib_uxenv4vlib)

install_uxenv4vlib.h: uxenv4vlib.h
	@mkdir -p $(SDKDIR_include_uxenv4vlib)
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include_uxenv4vlib)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(SDKDIR_include_uxenv4vlib)

install_gh_v4vapi.h: gh_v4vapi.h
	@mkdir -p $(SDKDIR_include_uxenv4vlib)
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include_uxenv4vlib)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(SDKDIR_include_uxenv4vlib)

install_gh_v4vkapi.h: gh_v4vkapi.h
	@mkdir -p $(SDKDIR_include_uxenv4vlib)
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_include_uxenv4vlib)
	$(_W)echo Installing - $(<F)
	$(_V)install $(<) $(SDKDIR_include_uxenv4vlib)

dist: install_uxenv4vlib.sys install_uxenv4vlib.h install_gh_v4vapi.h install_gh_v4vkapi.h

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

#all:
#dist:

-include .deps/*.d

endif # MAKENOW
