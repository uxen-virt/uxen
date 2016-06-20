#
# Copyright 2012-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

$(call include_lib,LIBIMG,.,-f Makefile.libimg)
$(call include_lib,LIBVHD,../libvhd)
$(call include_lib,NTFS_3G,../ntfs-3g)
$(call include_lib,YAJL,../yajl)

LZ4DIR_include ?= $(TOPDIR)/common/lz4
LZ4_CPPFLAGS += -I$(LZ4DIR_include)

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

CPPFLAGS += -I$(SRCDIR) -I$(TOPDIR)/dm -I$(TOPDIR)/common/img-tools
CPPFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

CFLAGS := $(subst -O2,-O3,$(CFLAGS))

PROGRAMS = img-bcdedit$(EXE_SUFFIX)
PROGRAMS += img-convert$(EXE_SUFFIX)
PROGRAMS += img-ntfscat$(EXE_SUFFIX)
PROGRAMS += img-ntfscp$(EXE_SUFFIX)
PROGRAMS += img-ntfsfix$(EXE_SUFFIX)
PROGRAMS += img-ntfsls$(EXE_SUFFIX)
PROGRAMS += img-ntfsplant$(EXE_SUFFIX)
PROGRAMS += img-ntfsrm$(EXE_SUFFIX)
PROGRAMS += img-rm$(EXE_SUFFIX)
PROGRAMS += img-test$(EXE_SUFFIX)
PROGRAMS += swap-seal$(EXE_SUFFIX)
PROGRAMS += swap-fsck$(EXE_SUFFIX)
PROGRAMS += img-logiccp$(EXE_SUFFIX)

all: $(PROGRAMS)

_install_banner:
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(DISTDIR)

$(patsubst %,install_%,$(PROGRAMS)): install_%: % _install_banner
	$(_W)echo Installing -- $(<)
	$(_V)$(call install_exe,$(<),$(DISTDIR))

dist: $(patsubst %,install_%,$(PROGRAMS))

swap-seal.o: $(TOPDIR)/common/img-tools/swap-seal.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) $< -o $@

swap-fsck.o: $(TOPDIR)/common/img-tools/swap-fsck.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) $< -o $@

mt19937-64.o: $(TOPDIR)/common/img-tools/mt19937-64.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) $< -o $@

img-rm.o: $(TOPDIR)/common/img-tools/img-rm.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) $< -o $@

img-test.o: $(TOPDIR)/common/img-tools/img-test.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) $< -o $@


RES = imgtool-res.o
IMG_BCDEDIT_OBJS = img-bcdedit.o $(RES)
IMG_CONVERT_OBJS = img-convert.o $(RES)
IMG_NTFSCAT_OBJS = img-ntfscat.o $(RES)
IMG_NTFSCP_OBJS = img-ntfscp.o fileset.o $(RES)
IMG_NTFSFIX_OBJS = img-ntfsfix.o $(RES)
IMG_NTFSLS_OBJS = img-ntfsls.o fileset.o $(RES)
IMG_NTFSPLANT_OBJS = img-ntfsplant.o $(RES)
IMG_NTFSRM_OBJS = img-ntfsrm.o $(RES)
IMG_RM_OBJS = img-rm.o sys.o $(RES)
IMG_TEST_OBJS = img-test.o mt19937-64.o sys.o $(RES)
SWAP_SEAL_OBJS = swap-seal.o sys.o $(RES)
SWAP_FSCK_OBJS = swap-fsck.o sys.o $(RES)
IMG_LOGICCP_OBJS = img-logiccp.o sys.o $(RES)

DISKLIB_OBJS = util.o
DISKLIB_OBJS += ntreg.o
DISKLIB_OBJS += bcd.o
#DISKLIB_OBJS += machimg.o
DISKLIB_OBJS += hexdump.o
DISKLIB_OBJS += ntfsfix.o
DISKLIB_OBJS += fs-ntfs.o
DISKLIB_OBJS += ntfs-extras.o
DISKLIB_OBJS += disklib.o
DISKLIB_OBJS += ntdev.o
DISKLIB_OBJS += part.o
DISKLIB_OBJS += cache.o
DISKLIB_OBJS += glob.o
DISKLIB_OBJS += fnmatch.o
DISKLIB_OBJS += sha1.o
DISKLIB_OBJS += vd.o
DISKLIB_OBJS += sys.o

$(IMG_BCDEDIT_OBJS) $(IMG_CONVERT_OBJS) $(IMG_NTFSCP_OBJS) \
$(IMG_NTFSFIX_OBJS) $(IMG_NTFSLS_OBJS) $(IMG_NTFSPLAN_OBJS) \
$(IMG_NTFSRM_OBJS) $(IMG_RM_OBJS) $(SWAP_SEAL_OBJS) $(DISKLIB_OBJS): \
	$(LIBIMG_DEPS) $(LIBVHD_DEPS) $(NTFS_3G_DEPS) $(YAJL_DEPS) \
	.deps/.exists

IMG_LIBS = disklib.a

PROGRAMS_LDLIBS = $(LIBIMG_LIBS) $(YAJL_LIBS) $(LIBVHD_LIBS) $(NTFS_3G_LIBS) \
	-luuid -lole32 -lkernel32 -lpsapi -lshlwapi

img-bcdedit$(EXE_SUFFIX): $(IMG_BCDEDIT_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

img-convert$(EXE_SUFFIX): $(IMG_CONVERT_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

img-ntfscat$(EXE_SUFFIX): $(IMG_NTFSCAT_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

img-ntfscp$(EXE_SUFFIX): $(IMG_NTFSCP_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

img-ntfsfix$(EXE_SUFFIX): $(IMG_NTFSFIX_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

img-ntfsls$(EXE_SUFFIX): $(IMG_NTFSLS_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

img-ntfsplant$(EXE_SUFFIX): $(IMG_NTFSPLANT_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

img-ntfsrm$(EXE_SUFFIX): $(IMG_NTFSRM_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

img-rm$(EXE_SUFFIX): $(IMG_RM_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(PROGRAMS_LDLIBS) $(LDLIBS))

img-test$(EXE_SUFFIX): $(IMG_TEST_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(LDLIBS) $(PROGRAMS_LDLIBS))

swap-seal$(EXE_SUFFIX): $(SWAP_SEAL_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(PROGRAMS_LDLIBS) $(LDLIBS))

swap-fsck$(EXE_SUFFIX): $(SWAP_FSCK_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(PROGRAMS_LDLIBS) $(LDLIBS))

img-logiccp$(EXE_SUFFIX): $(IMG_LOGICCP_OBJS) $(IMG_LIBS);
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$^ $(PROGRAMS_LDLIBS) $(LDLIBS) -lversion)


disklib.a: $(DISKLIB_OBJS)
	$(_W)echo Archiving - $@
	$(_V)$(AR) rc $@ $^
	$(_V)$(RANLIB) $@

fs-ntfs.o: CPPFLAGS += $(NTFS_3G_CPPFLAGS)
ntdev.o: CPPFLAGS += $(NTFS_3G_CPPFLAGS)
ntfsfix.o: CPPFLAGS += $(NTFS_3G_CPPFLAGS)
ntfs-extras.o: CPPFLAGS += $(NTFS_3G_CPPFLAGS)
part.o: CPPFLAGS += $(NTFS_3G_CPPFLAGS)
fs2.o: CPPFLAGS += $(NTFS_3G_CPPFLAGS)
cache.o: CPPFLAGS += $(LZ4_CPPFLAGS)

img-rm.o: CPPFLAGS += $(LIBIMG_CPPFLAGS)
cache.o: CPPFLAGS += $(LIBIMG_CPPFLAGS)

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

%.o : %.rc
	$(_W)echo Compiling resource - $@
	$(_V)$(WINDRES) $(WINDRES_TARGET_FORMAT_OPTION) $< -o $@

-include .deps/*.d

endif # MAKENOW
