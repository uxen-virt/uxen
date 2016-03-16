/* adapted from: http://www.opensource.apple.com/source/gdb/gdb-908/src/include/coff/internal.h?txt */

/* Internal format of COFF object file data structures, for GNU BFD.
   This file is part of BFD, the Binary File Descriptor library.
   
   Copyright 1999, 2000, 2001, 2002, 2003, 2004
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

struct internal_extra_pe_aouthdr 
{
    short fill1;
    char fill2;
    char fill3;
    long fill4;
    long fill5;
    long fill6;
    bfd_vma fill7;
    bfd_vma fill8;
    bfd_vma fill9;

  /* PE stuff  */
  bfd_vma ImageBase;		/* address of specific location in memory that
				   file is located, NT default 0x10000 */

  bfd_vma SectionAlignment;	/* section alignment default 0x1000 */
  bfd_vma FileAlignment;	/* file alignment default 0x200 */
};

/* adapted from: http://www.opensource.apple.com/source/gdb/gdb-908/src/bfd/libcoff-in.h?txt */

/* BFD COFF object file private structure.
   Copyright 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999,
   2000, 2001, 2002, 2003, 2004, 2005
   Free Software Foundation, Inc.
   Written by Cygnus Support.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

/* `Tdata' information kept for COFF files.  */

typedef struct coff_tdata
{
  struct coff_symbol_struct *symbols;	/* Symtab for input bfd.  */
  unsigned int *conversion_table;
  int conv_table_size;
  file_ptr sym_filepos;

  struct coff_ptr_struct *raw_syments;
  unsigned long raw_syment_count;

  /* These are only valid once writing has begun.  */
  unsigned long int relocbase;

  /* These members communicate important constants about the symbol table
     to GDB's symbol-reading code.  These `constants' unfortunately vary
     from coff implementation to implementation...  */
  unsigned local_n_btmask;
  unsigned local_n_btshft;
  unsigned local_n_tmask;
  unsigned local_n_tshift;
  unsigned local_symesz;
  unsigned local_auxesz;
  unsigned local_linesz;

  /* The unswapped external symbols.  May be NULL.  Read by
     _bfd_coff_get_external_symbols.  */
  void * external_syms;
  /* If this is TRUE, the external_syms may not be freed.  */
  bfd_boolean keep_syms;

  /* The string table.  May be NULL.  Read by
     _bfd_coff_read_string_table.  */
  char *strings;
  /* The length of the strings table.  For error checking.  */
  bfd_size_type strings_len;
  /* If this is TRUE, the strings may not be freed.  */
  bfd_boolean keep_strings;
  /* If this is TRUE, the strings have been written out already.  */
  bfd_boolean strings_written;

  /* Is this a PE format coff file?  */
  int pe;
  /* Used by the COFF backend linker.  */
  struct coff_link_hash_entry **sym_hashes;

  /* Used by the pe linker for PowerPC.  */
  int *local_toc_sym_map;

  struct bfd_link_info *link_info;

  /* Used by coff_find_nearest_line.  */
  void * line_info;

  /* A place to stash dwarf2 info for this bfd.  */
  void * dwarf2_find_line_info;

  /* The timestamp from the COFF file header.  */
  long timestamp;

  /* Copy of some of the f_flags bits in the COFF filehdr structure,
     used by ARM code.  */
  flagword flags;

  /* coff-stgo32 EXE stub header after BFD tdata has been allocated.  Its data
     is kept in internal_filehdr.go32stub beforehand.  */
  char *go32stub;
} coff_data_type;

/* Tdata for pe image files.  */
typedef struct pe_tdata
{
  coff_data_type coff;
  struct internal_extra_pe_aouthdr pe_opthdr;
  int dll;
  int has_reloc_section;
    int fill1;
  bfd_boolean (*in_reloc_p) (bfd *, reloc_howto_type *);
  flagword real_flags;
  /* int target_subsystem; */
  /* bfd_boolean force_minimum_alignment; */
} pe_data_type;
