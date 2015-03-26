/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifdef _WIN32
#define ERR_WINDOWS
#endif
#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKAGE "xpdata-extract"
#include <bfd.h>

// #include "unwind-pe.h"

#ifdef _WIN32
DECLARE_PROGNAME;
#endif  /* _WIN32 */

#define err_bfd(fmt, ...)                                               \
    errx(1, fmt ": %s", ## __VA_ARGS__, bfd_errmsg(bfd_get_error()))

static void
output_section_symbols(asymbol **symtab, const char *name,
                       bfd *abfd, asection *sec, bfd_size_type size,
                       const char *sym_prefix)
{
    char *symname;
    asymbol *sym;

    symname = calloc(1, strlen(sym_prefix) + 1 + strlen(name) +
                     strlen("_start") + 1);
    if (!symname)
        err(1, "calloc symname %s_%s_start", sym_prefix, name);

    sprintf(symname, "%s_%s_start",  sym_prefix, name);

    sym = bfd_make_empty_symbol(abfd);
    if (!sym)
        err_bfd("bfd_make_empty_symbol failed");
    sym->name = symname;
    sym->section = sec;
    sym->flags = BSF_GLOBAL;
    sym->value = 0x0;
    symtab[0] = sym;

    symname = calloc(1, strlen(sym_prefix) + 1 + strlen(name) +
                     strlen("_start") + 1);
    if (!symname)
        err(1, "calloc symname %s_%s_start", sym_prefix, name);

    sprintf(symname, "%s_%s_end",  sym_prefix, name);

    sym = bfd_make_empty_symbol(abfd);
    if (!sym)
        err_bfd("bfd_make_empty_symbol failed");
    sym->name = symname;
    sym->section = sec;
    sym->flags = BSF_GLOBAL;
    sym->value = 0x0 + size;
    symtab[1] = sym;
}

static void
create_section(const char *name, bfd *ibfd, bfd *obfd)
{
    asection *isec, *osec;
    bfd_size_type size;
    char *outname;
    int ret;

    isec = bfd_get_section_by_name(ibfd, name);
    if (!isec)
        err_bfd("bfd_get_section_by_name(%s) failed", name);

    size = bfd_section_size(b, isec);
    // warnx("section %s, size %lx", name, (long)size);

    outname = calloc(1, strlen(".data") + strlen(name) + 1);
    if (!outname)
        err(1, "calloc outname failed");
    sprintf(outname, ".data%s", name);

    osec = bfd_make_section(obfd, outname);
    if (!osec)
        err_bfd("bfd_make_section(%s) failed", outname);

    ret = bfd_set_section_flags(obfd, osec,
                                SEC_HAS_CONTENTS | SEC_READONLY | SEC_DATA);
    if (!ret)
        err_bfd("bfd_set_section_flags(%s) failed", outname);

    ret = bfd_set_section_size(obfd, osec, size);
    if (!ret)
        err_bfd("bfd_set_section_size(%s) failed", outname);
}

static void
copy_section(const char *name, bfd *ibfd, bfd *obfd, asymbol **symtab,
             const char *sym_prefix)
{
    asection *isec, *osec;
    bfd_size_type size;
    uint8_t *data, *p;
    char *outname;
    int ret;

    isec = bfd_get_section_by_name(ibfd, name);
    if (!isec)
        err_bfd("bfd_get_section_by_name(%s) failed", name);

    size = bfd_section_size(b, isec);
    data = calloc(1, size);
    if (!data)
        err(1, "calloc %lx bytes for section %s failed", (long)size, name);

    p = bfd_simple_get_relocated_section_contents(ibfd, isec, data, NULL);
    if (p != data)
        err_bfd("bfd_simple_get_relocated_section_contents(%s) failed", name);

    outname = calloc(1, strlen(".data") + strlen(name) + 1);
    if (!outname)
        err(1, "calloc outname failed");
    sprintf(outname, ".data%s", name);

    osec = bfd_get_section_by_name(obfd, outname);
    if (!osec)
        err_bfd("bfd_get_section_by_name(%s) failed", outname);

    ret = bfd_set_section_contents(obfd, osec, data, 0, size);
    if (!ret)
        err_bfd("bfd_set_section_contents(%s) failed", outname);

    output_section_symbols(symtab, &name[1], obfd, osec, size, sym_prefix);

    free(outname);
}

int
main(int argc, char **argv)
{
    bfd *ibfd, *obfd;
    asymbol *symtab[4 + 1];
    int ret;

#ifdef _WIN32
    setprogname(argv[0]);
#endif  /* _WIN32 */

    if (argc != 3)
        errx(1, "usage: %s infile outfile", argv[0]);

    ibfd = bfd_openr(argv[1], NULL);
    if (!ibfd)
        err_bfd("bfd_openr failed");

    ret = bfd_check_format(ibfd, bfd_object);
    if (!ret)
        err_bfd("bfd_check_format failed");

    ret = bfd_check_format_matches(ibfd, bfd_object, NULL);
    if (!ret)
        err_bfd("bfd_check_format_matches failed");

    obfd = bfd_openw(argv[2], bfd_get_target(ibfd));
    if (!obfd)
        errx(1, "bfd_openw failed");

    ret = bfd_set_arch_mach(obfd, bfd_get_arch(ibfd), bfd_get_mach(ibfd));
    if (!ret)
        err_bfd("bfd_set_arch_mach failed");

    ret = bfd_set_format(obfd, bfd_get_format(ibfd));
    if (!ret)
        err_bfd("bfd_set_format failed");

    ret = bfd_set_file_flags(obfd, HAS_DEBUG | HAS_SYMS);
    if (!ret)
        err_bfd("bfd_set_file_flags failed");

    create_section(".xdata", ibfd, obfd);
    create_section(".pdata", ibfd, obfd);

    copy_section(".xdata", ibfd, obfd, &symtab[0], "uxen");
    copy_section(".pdata", ibfd, obfd, &symtab[2], "uxen");

    // dump_unwind(xdata, size_xdata, pdata, size_pdata);

    symtab[4] = (asymbol *)NULL;

    ret = bfd_set_symtab(obfd, symtab, 4);
    if (!ret)
        err_bfd("bfd_set_symtab failed");

    ret = bfd_close(obfd);
    if (!ret)
        err_bfd("bfd_close failed");

    return 0;
}
