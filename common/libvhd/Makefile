#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

RANLIB ?= ranlib

CPPFLAGS += -I$(SRCROOT)

all: libvhd.a libvhdaio.a Makefile.lib-LIBVHD

libvhd_SRCS  = libvhd.c relative-path.c libvhd-journal.c atomicio.c
libvhd_OBJS  = $(patsubst %.c,%.o,$(libvhd_SRCS))
libvhd_OBJS := $(subst /,_,$(libvhd_OBJS))
libvhd_CPPFLAGS = 

libvhdaio_SRCS  = block-vhd.c tapdisk-log.c
libvhdaio_OBJS  = $(patsubst %.c,%.o,$(libvhdaio_SRCS))
libvhdaio_OBJS := $(subst /,_,$(libvhdaio_OBJS))
libvhdaio_CPPFLAGS = 

EXTRA_CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

libvhd.a: $(libvhd_OBJS)
	$(_W)echo Archiving - $@
	$(_V)$(AR) rc $@ $(libvhd_OBJS)
	$(_V)$(RANLIB) $@

libvhdaio.a: $(libvhdaio_OBJS)
	$(_W)echo Archiving - $@
	$(_V)$(AR) rc $@ $(libvhdaio_OBJS)
	$(_V)$(RANLIB) $@

$(libvhd_OBJS): .deps/.exists
$(libvhd_OBJS): %.o : $(SRCROOT)/%.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $(libvhd_CPPFLAGS) $< -o $@

$(libvhdaio_OBJS): .deps/.exists
$(libvhdaio_OBJS): %.o : $(SRCROOT)/%.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $(libvhdaio_CPPFLAGS) $< -o $@

Makefile.lib-LIBVHD:
	@rm -f $@
	@(echo "LIBVHD_CPPFLAGS = -I$(SRCROOT)" ;\
	  echo "LIBVHD_LIBS = -L$(abspath .) -lvhd -lvhdaio" ;\
	  echo "LIBVHD_LIBS += -liconv" ;\
	  echo "$(WINDOWS)LIBVHD_LIBS += -le2fsprogs-uuid" ;\
	  echo "LIBVHD_DEPS = $(abspath .)/libvhd.a $(abspath .)/libvhdaio.a" ;\
	  echo "LIBVHD_SRCDIR = $(SRCROOT)" ;\
	  echo "$(abspath .)/libvhd.a: $(patsubst %,$(SRCROOT)/%,$(libvhd_SRCS))" ;\
	  echo "$(abspath .)/libvhdaio.a: $(patsubst %,$(SRCROOT)/%,$(libvhdaio_SRCS))" ) >$@

-include .deps/*.d
