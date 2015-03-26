/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifdef _WIN32
#define ERR_WINDOWS
#endif
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "unwind-dump-pe.h"

#ifdef _WIN32
DECLARE_PROGNAME;
#endif  /* _WIN32 */

/* #define DUMP_DATA */

#ifdef DUMP_DATA
static void
dump_data(uint8_t *data, long int size, int width)
{
    long int i, j, k;
    uint64_t v;

    k = 16;
    for (i = 0; i < size; i += width) {
        v = 0;
        for (j = 0; j < width && i + j < size; j++)
            v |= data[i + j] << (8 * j);
        printf("%0*X ", width * 2, v);
        k -= width;
        if (k <= 0) {
            printf("\n");
            k = 16;
        }
    }

    if (i % 8)
        printf("\n");
}
#endif  /* DUMP_DATA */

int
main(int argc, char **argv)
{
    long int offset;
    FILE *f;
    uint8_t *xdata, *pdata;
    long int size_xdata, size_pdata;

#ifdef _WIN32
    setprogname(argv[0]);
#endif  /* _WIN32 */

    if (argc != 6)
        errx(1, "usage: %s file xdata-start xdata-len pdata-start pdata-len",
             argv[0]);

    f = fopen(argv[1], "rb");
    if (!f)
        err(1, "fopen");

    offset = strtoul(argv[2], NULL, 16);
    size_xdata = strtoul(argv[3], NULL, 16);
    warnx("xdata: offset %lx, size %lx", offset, size_xdata);

    xdata = calloc(1, size_xdata);
    if (!xdata)
        err(1, "calloc xdata");

    if (fseek(f, offset, SEEK_SET))
        err(1, "fseek xdata");

    if (fread(xdata, size_xdata, 1, f) != 1)
        err(1, "fread");

    offset = strtoul(argv[4], NULL, 16);
    size_pdata = strtoul(argv[5], NULL, 16);
    warnx("pdata: offset %lx, size %lx", offset, size_pdata);

    pdata = calloc(1, size_pdata);
    if (!pdata)
        err(1, "calloc pdata");

    if (fseek(f, offset, SEEK_SET))
        err(1, "fseek pdata");

    if (fread(pdata, size_pdata, 1, f) != 1)
        err(1, "fread");

#ifdef DUMP_DATA
    dump_data(xdata, size_xdata, 1);
    dump_data(pdata, size_pdata, 4);
#endif

    dump_unwind(xdata, size_xdata, pdata, size_pdata);

    return 0;
}
