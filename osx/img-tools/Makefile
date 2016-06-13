#
# Copyright 2013-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

$(call include_lib,LIBIMG,.,-f Makefile.libimg)
$(call include_lib,LIBVHD,../libvhd)
$(call include_lib,YAJL,../yajl)

ifeq (,$(MAKENOW))

VPATH = $(SRCDIR)

CFLAGS += -I$(SRCDIR) -I$(TOPDIR)/dm -I$(TOPDIR)/common/img-tools -O3

CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

PROGRAMS += swap-seal$(EXE_SUFFIX)
PROGRAMS += swap-fsck$(EXE_SUFFIX)
PROGRAMS += img-bootcode$(EXE_SUFFIX)
PROGRAMS += img-create$(EXE_SUFFIX)
PROGRAMS += img-hfs$(EXE_SUFFIX)
PROGRAMS += img-copy$(EXE_SUFFIX)
PROGRAMS += img-shallow$(EXE_SUFFIX)
PROGRAMS += img-rm$(EXE_SUFFIX)
PROGRAMS += img-test$(EXE_SUFFIX)
PROGRAMS += bfs$(EXE_SUFFIX)
PROGRAMS += cowctl$(EXE_SUFFIX)
PROGRAMS += cowlink$(EXE_SUFFIX)

all: $(PROGRAMS)

_install_banner:
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(DISTDIR)

$(patsubst %,install_%,$(PROGRAMS)): install_%: % _install_banner
	$(_W)echo Installing -- $(<)
	$(_V)$(call install_exe,$(<),$(DISTDIR))

dist: $(patsubst %,install_%,$(PROGRAMS)) $(DISTDIR)/.exists

swap-seal.o: $(TOPDIR)/common/img-tools/swap-seal.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) -c $< -o $@

swap-fsck.o: $(TOPDIR)/common/img-tools/swap-fsck.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) -c $< -o $@

mt19937-64.o: $(TOPDIR)/common/img-tools/mt19937-64.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) $< -o $@

img-rm.o: $(TOPDIR)/common/img-tools/img-rm.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) $< -o $@

img-test.o: $(TOPDIR)/common/img-tools/img-test.c
	$(_W)echo Importing - $@
	$(_V)$(COMPILE.c) $< -o $@

SWAP_SEAL_OBJS = swap-seal.o
SWAP_FSCK_OBJS = swap-fsck.o
IMG_BOOTCODE_OBJS = img-bootcode.o
IMG_CREATE_OBJS = img-create.o
IMG_TEST_OBJS = img-test.o mt19937-64.o
IMG_HFS_OBJS = hfs.o shallow.o btree.o catalog.o extents.o fastunicodecompare.o flatfile.o \
    hfslib.o rawfile.o utility.o volume.o abstractfile.o cache.o
IMG_DUMP_RAW_OBJS = img-copy.o block-swap.o
IMG_SHALLOW_OBJS = img-shallow.o shallow.o btree.o catalog.o extents.o fastunicodecompare.o flatfile.o \
    hfslib.o rawfile.o utility.o volume.o abstractfile.o cache.o
IMG_RM_OBJS = img-rm.o
BFS_OBJS = bfs.o
COWCTL_OBJS = cowctl.o cow-user.o 
COWLINK_OBJS = hardlink-worker.o cow-user.o 

DISKLIB_OBJS += sys.o

$(SWAP_SEAL_OBJS): \
	$(LIBIMG_DEPS) $(LIBVHD_DEPS) $(YAJL_DEPS) \
	.deps/.exists

$(SWAP_FSCK_OBJS): \
	$(LIBIMG_DEPS) $(LIBVHD_DEPS) $(YAJL_DEPS) \
	.deps/.exists

IMG_LIBS = disklib.a

PROGRAMS_LDLIBS = $(LIBIMG_LIBS) $(YAJL_LIBS) $(LIBVHD_LIBS)

swap-seal$(EXE_SUFFIX): $(SWAP_SEAL_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS) $(PROGRAMS_LDLIBS)

swap-fsck$(EXE_SUFFIX): $(SWAP_FSCK_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS) $(PROGRAMS_LDLIBS)

img-bootcode$(EXE_SUFFIX): $(IMG_BOOTCODE_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS) $(PROGRAMS_LDLIBS)

img-create$(EXE_SUFFIX): $(IMG_CREATE_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS) $(PROGRAMS_LDLIBS)

img-test$(EXE_SUFFIX): $(IMG_TEST_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS) $(PROGRAMS_LDLIBS)

img-hfs$(EXE_SUFFIX): $(IMG_HFS_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS) $(PROGRAMS_LDLIBS)

img-copy$(EXE_SUFFIX): $(IMG_DUMP_RAW_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS) $(PROGRAMS_LDLIBS)

img-shallow$(EXE_SUFFIX): $(IMG_SHALLOW_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS) $(PROGRAMS_LDLIBS)

img-rm$(EXE_SUFFIX): $(IMG_RM_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(PROGRAMS_LDLIBS)

bfs$(EXE_SUFFIX): $(BFS_OBJS) $(IMG_LIBS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS)

cowctl$(EXE_SUFFIX): $(COWCTL_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS)

cowlink$(EXE_SUFFIX): $(COWLINK_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(LDLIBS)

disklib.a: $(DISKLIB_OBJS)
	$(_W)echo Archiving - $@
	$(_V)$(AR) rc $@ $^
	$(_V)$(RANLIB) $@

swap-seal.o: CPPFLAGS += $(LIBIMG_CPPFLAGS)
img-create.o: CPPFLAGS += $(LIBIMG_CPPFLAGS)

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $< -o $@

-include .deps/*.d

endif # MAKENOW
