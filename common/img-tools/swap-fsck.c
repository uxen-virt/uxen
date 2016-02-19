/*
 * Copyright 2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Sanity-check contents of .swap disk.
 */

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libimg.h"

#ifdef _WIN32
#include "sys.h"
DECLARE_PROGNAME;
#endif

int main(int argc, char **argv)
{
    BlockDriverState *bs;
    int r;

#ifdef _WIN32
    setprogname(argv[0]);
#endif

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <disk.swap>\n", argv[0]);
        return -1;
    }
    char *disk;
    if (strncmp(argv[1], "swap:", 5) != 0) {
        disk = malloc(5 + strlen(argv[1]) + 1);
        sprintf(disk, "swap:%s", argv[1]);
    } else {
        disk = argv[1];
    }

    ioh_init();
    bh_init();
    aio_init();
    bdrv_init();
    bs = bdrv_new("");

    if (!bs) {
        fprintf(stderr, "no bs\n");
        return -1;
    }

    r = bdrv_open(bs, disk, BDRV_O_RDWR);
    if (r < 0) {
        fprintf(stderr, "%s: unable to open %s\n", argv[0], disk);
        return r;
    }

    r = bdrv_ioctl(bs, 2, NULL);
    if (r < 0) {
        fprintf(stderr, "%s: unable to fsck %s\n", argv[0], disk);
    }

    bdrv_delete(bs);

    if (r == 0) {
        fprintf(stderr, "fsck completed.\n");
    }
    return r;
}
