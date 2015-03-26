#
# Copyright 2013-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

BUILDDIR_default = obj
SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/../..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

SRCROOT = $(SRCDIR)

VPATH = $(SRCROOT)

PROGRAMS = uxen-backtrace.dll crash-monitor.exe

all: $(PROGRAMS)

_install_banner:
	$(_W)echo Installing from $(abspath $(BUILDDIR)) to $(DISTDIR)

$(patsubst %,install_%,$(PROGRAMS)): install_%: % _install_banner
	$(_W)echo Installing -- $(<)
	$(_V)$(call install_exe,$(<),$(DISTDIR))

dist: $(patsubst %,install_%,$(PROGRAMS))

uxen_backtrace_SRCS  = backtrace.c
uxen_backtrace_OBJS  = $(patsubst %.c,%.o,$(uxen_backtrace_SRCS))
uxen_backtrace_OBJS := $(subst /,_,$(uxen_backtrace_OBJS))

crash_monitor_SRCS  = monitor.c
crash_monitor_OBJS  = $(patsubst %.c,%.o,$(crash_monitor_SRCS))
crash_monitor_OBJS := $(subst /,_,$(crash_monitor_OBJS))

OBJS = $(uxen_backtrace_OBJS) $(crash_monitor_OBJS)
$(OBJS) test.o: .deps/.exists

EXTRA_CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

uxen_backtrace_LDFLAGS += -shared
ifeq ($(TARGET_HOST_BITS),32)
$(REL_ONLY)uxen_backtrace_LDFLAGS += -Wl,-e_DllMainCRTStartup \
	-Wl,--enable-stdcall-fixup
endif
uxen_backtrace_LIBS += $(LDLIBS) -lbfd -liberty -limagehlp
crash_monitor_LIBS += $(LDLIBS) -ldbghelp -lpsapi

uxen-backtrace.dll: $(uxen_backtrace_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$(uxen_backtrace_LDFLAGS) \
		$(uxen_backtrace_OBJS) $(uxen_backtrace_LIBS))

crash-monitor.exe: $(crash_monitor_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^ $(crash_monitor_LIBS)

$(uxen_backtrace_OBJS) $(crash_monitor_OBJS) test.o: %.o : $(SRCROOT)/%.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $< -o $@

test.exe: test.o
	$(_W)echo Linking - $@
	$(_V)$(LINK.o) -o $@ $^

-include .deps/*.d

endif # MAKENOW
