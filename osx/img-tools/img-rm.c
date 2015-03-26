/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Deletes a disk image, using the storage backend's own API.
 * For .swap this means freeing the snapshot ID and its blocks
 * in the shared database.
 */

#include <err.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "libimg.h"

int main(int argc, char **argv)
{
    BlockDriverState *bs;
    const char *img;

    if ( argc != 2 ) {
        fprintf(stderr, "usage: %s <protocol>:<image>\n", argv[0]);
        exit(-1);
    }
    img = argv[1];

    bh_init();
    bdrv_init();

    if (!(bs = bdrv_new(""))) {
        fprintf(stderr, "unable to allocate block backend\n");
        return -1;
    }

    if (bdrv_open(bs, img, BDRV_O_RDWR) < 0) {
        fprintf(stderr, "unable to open %s\n", img);
        return -1;
    }

    if (bdrv_remove(bs) < 0) {
        fprintf(stderr, "unable to remove %s\n", img);
        return -1;
    }

    bdrv_flush(bs);
    bdrv_delete(bs);
    return 0;
}
