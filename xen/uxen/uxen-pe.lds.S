/* Copyright (C) 2011 Free Software Foundation, Inc.
   Copying and distribution of this script, with or without modification,
   are permitted in any medium without royalty provided the copyright
   notice and this notice are preserved.  */
/*
 * uXen changes:
 *
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <xen/config.h>
#include <xen/cache.h>
#include <asm/page.h>
#undef ENTRY
#undef ALIGN
#undef i386

/* Script for ld -r: link without relocation */
#if defined(__x86_64__)
OUTPUT_FORMAT(pe-x86-64)
#elif defined(__i386__)
OUTPUT_FORMAT(pe-i386)
#endif
SECTIONS
{
  .text  : SUBALIGN(PAGE_SIZE)
  {
    LABEL(_xen_start) = .;
    LABEL(_text_start) = .;
    LABEL(_stext) = .;        /* Text and read-only data */
    *(.text)
    *(.glue_7t)
    *(.glue_7)
    *(.fixup)
    LABEL(_etext) = .;        /* End of text section */
    LABEL(_sinittext) = . ;   /* Define _e{init,extra}text to avoid symbols.c */
    LABEL(_einittext) = .;    /* logic removing first symbols in file. */
    LABEL(_sextratext) = .;
    LABEL(_eextratext) = .;
    /* ??? Why is .gcc_exc here?  */
    . = ALIGN(STACK_SIZE);
    LABEL(_text_end) = .;
  }
  /* The Cygwin32 library uses a section to avoid copying certain data
     on fork.  This used to be named ".data".  The linker used
     to include this between __data_start__ and __data_end__, but that
     breaks building the cygwin32 dll.  Instead, we name the section
     ".data_cygwin_nocopy" and explictly include it after __data_end__. */
  .data  : SUBALIGN(PAGE_SIZE)
  {
    LABEL(_data_start) = .;
    /* Exception table */
    LABEL(__start___ex_table) = .;
    *(.ex_table)
    LABEL(__stop___ex_table) = .;

    /* Pre-exception table */
    LABEL(__start___pre_ex_table) = .;
    *(.ex_table.pre)
    LABEL(__stop___pre_ex_table) = .;

    *(.data)
    *(.data2)
    *(.jcr)
    *(.data.read_mostly)
    . = ALIGN(STACK_SIZE);
    LABEL(_data_end) = .;
  }
  .rdata  : SUBALIGN(PAGE_SIZE)
  {
    LABEL(_rdata_start) = .;
    *(.rodata)
    *(.rdata)
    *(.rdata_runtime_pseudo_reloc)
    . = ALIGN(STACK_SIZE);
    LABEL(_rdata_end) = .;
  }

#if 0
  . = ALIGN(PAGE_SIZE);             /* Init code and data */
  __init_begin = .;
#endif
  .init.setup : {
       LABEL(__setup_start) = .;
       *(.init.setup)
       LABEL(__setup_end) = .;
  }
  .initcall.init : {
       LABEL(__initcall_start) = .;
       *(.initcallpresmp.init)
       LABEL(__presmp_initcall_end) = .;
       *(.initcall1.init)
       LABEL(__initcall_end) = .;
  }
  . = ALIGN(STACK_SIZE);
#if 0
  __init_end = .;
#endif

  .bss  : SUBALIGN(PAGE_SIZE)
  {
    LABEL(_bss_start) = .;
    __bss_start = .;
    *(.bss.stack_aligned)
    . = ALIGN(PAGE_SIZE);
    *(.bss.page_aligned)
    *(.bss)
    *(COMMON)
    . = ALIGN(SMP_CACHE_BYTES);
    LABEL(__per_cpu_start) = .;
    *(.bss.percpu)
    . = ALIGN(SMP_CACHE_BYTES);
    *(.bss.percpu.read_mostly)
    . = ALIGN(SMP_CACHE_BYTES);
    LABEL(__per_cpu_data_end) = .;
    . = ALIGN(STACK_SIZE);
    LABEL(_bss_end) = .;
  }
  .edata  :
  {
    *(.edata)
    _xen_end = .;
  }
  .eh_frame  :
  {
    *(.eh_frame)
  }
  .xdata  :
  {
    *(.xdata*)
  }
  .pdata  :
  {
    /* LABEL(_pdata_start) = .; */
    *(.pdata*)
  }
  /DISCARD/ :
  {
    *(.debug$T)
    *(.debug$F)
    *(.drectve)
  }
  .idata  :
  {
    /* This cannot currently be handled with grouped sections.
	See pep.em:sort_sections.  */
  }
  .CRT  :
  {
    /* ___crt_xl_end__ is defined in the TLS Directory support code */
  }
  .tls  :
  {
  }
  .endjunk  :
  {
    /* end is deprecated, don't use it */
  }
  .rsrc  :
  {
    *(.rsrc)
  }
  .reloc  :
  {
    *(.reloc)
  }
  .stab   :
  {
    *(.stab)
  }
  .stabstr   :
  {
    *(.stabstr)
  }
  /* DWARF debug sections.
     Symbols in the DWARF debugging sections are relative to the beginning
     of the section.  Unlike other targets that fake this by putting the
     section VMA at 0, the PE format will not allow it.  */
  /* DWARF 1.1 and DWARF 2.  */
  .debug_aranges   :
  {
    *(.debug_aranges)
  }
  .debug_pubnames   :
  {
    *(.debug_pubnames)
  }
  .debug_pubtypes   :
  {
    *(.debug_pubtypes)
  }
  /* DWARF 2.  */
  .debug_info   :
  {
    *(.debug_info) *(.gnu.linkonce.wi.*)
  }
  .debug_abbrev   :
  {
    *(.debug_abbrev)
  }
  .debug_line   :
  {
    *(.debug_line)
  }
  .debug_frame   :
  {
    *(.debug_frame)
  }
  .debug_str   :
  {
    *(.debug_str)
  }
  .debug_loc   :
  {
    *(.debug_loc)
  }
  .debug_macinfo   :
  {
    *(.debug_macinfo)
  }
  /* SGI/MIPS DWARF 2 extensions.  */
  .debug_weaknames   :
  {
    *(.debug_weaknames)
  }
  .debug_funcnames   :
  {
    *(.debug_funcnames)
  }
  .debug_typenames   :
  {
    *(.debug_typenames)
  }
  .debug_varnames   :
  {
    *(.debug_varnames)
  }
  /* DWARF 3.  */
  .debug_ranges   :
  {
    *(.debug_ranges)
  }
  /* DWARF 4.  */
  .debug_types   :
  {
    *(.debug_types) *(.gnu.linkonce.wt.*)
  }
}
