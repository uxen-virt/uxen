#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

TOPDIR = ../..
include $(TOPDIR)/Config.mk

CPPFLAGS += -g
CPPFLAGS += -I$(TOPDIR)/dist/include
LDFLAGS += -mwindows -mconsole

PROG = uxendmctl.exe

all: $(PROG)

dist: all
	cp -f $(PROG) $(DISTDIR)

clean:
	rm -f $(PROG) $(UXENDMCTL_OBJS)

UXENDMCTL_OBJS = uxendmctl.o

$(PROG): $(UXENDMCTL_OBJS)
	$(call link,$@,$^ $(LDLIBS))
