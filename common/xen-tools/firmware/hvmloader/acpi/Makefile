#
# Copyright (c) 2004, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA 02111-1307 USA.
#

#
# uXen changes:
#
# Copyright 2012-2015, Bromium, Inc.
# SPDX-License-Identifier: ISC
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

ifeq (,$(TOPDIR))
TOPDIR = ../../../../..
include $(TOPDIR)/Config.mk
endif

SRCDIR ?= .
include $(SRCDIR)/../Rules.mk

C_SRC = build.c dsdt_anycpu.c dsdt_15cpu.c static_tables.c dsdt_anycpu_qemu_xen.c
OBJS  = $(patsubst %.c,%.o,$(C_SRC))

CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += -m32

CPPFLAGS += -I.

vpath iasl $(PATH)
all: acpi.a

ssdt_s3.h ssdt_s4.h ssdt_pm.h ssdt_tpm.h: %.h: %.asl iasl
	iasl -vs -p $* -tc $<
	sed -e 's/AmlCode/$*/g' $*.hex >$@
	rm -f $*.hex $*.aml

mk_dsdt: mk_dsdt.c
	$(HOSTCC) $(HOSTCFLAGS) $(CFLAGS_xeninclude) -o $@ $<

dsdt_anycpu_qemu_xen.asl: dsdt.asl mk_dsdt
	awk 'NR > 1 {print s} {s=$$0}' $< > $@
	./mk_dsdt --dm-version qemu-xen >> $@

# NB. awk invocation is a portable alternative to 'head -n -1'
dsdt_%cpu.asl: dsdt.asl mk_dsdt
	awk 'NR > 1 {print s} {s=$$0}' $< > $@
	./mk_dsdt --maxcpu $*  >> $@

$(filter dsdt_%.c,$(C_SRC)): %.c: iasl %.asl
	iasl -vs -p $* -tc $*.asl
	sed -e 's/AmlCode/$*/g' $*.hex >$@
	echo "int $*_len=sizeof($*);" >>$@
	rm -f $*.aml $*.hex

iasl:
	@echo
	@echo "ACPI ASL compiler (iasl) is needed"
	@echo "Download and install Intel ACPI CA from"
	@echo "http://acpica.org/downloads/"
	@echo 
	@exit 1

build.o: ssdt_s3.h ssdt_s4.h ssdt_pm.h # ssdt_tpm.h

acpi.a: $(OBJS)
	$(AR) rc $@ $(OBJS) && $(RANLIB) $@ || rm -f $@

clean:
	rm -rf *.a *.o $(IASL_VER) $(IASL_VER).tar.gz $(DEPS)
	rm -rf ssdt_*.h dsdt*.c *~ *.aml *.hex mk_dsdt$(EXE_SUFFIX) dsdt_*.asl

install: all

-include $(DEPS)
