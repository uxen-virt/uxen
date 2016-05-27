/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Seal a swap disk by merging all data in a single, all-sorted level.
 */

#include <block-swap/dubtree_sys.h>
#include <block-swap/dubtree.h>

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sys.h"
#include "libimg.h"

DECLARE_PROGNAME;

int main(int argc, char **argv)
{
    DUBTREE *t = (DUBTREE*) malloc(sizeof(DUBTREE));
    int r;

    early_init();

    setprogname(argv[0]);
    convert_args(argc, argv);

    if (argc != 3) {
        printf("Usage: %s <swapdata> <level>\n", argv[0]);
        return EXIT_FAILURE;
    }

    reduce_io_priority();
    r = dubtreeInit(t, argv[1], NULL);
    if (r < 0) {
        printf("swap-seal: unable to open %s\n", argv[1]);
        goto out;
    }
    
    /* Sort the data into the dest level, and write out
     * the compressed top.save meta-data. Sealing will
     * conclude by closing the tree. */
    r = dubtreeSeal(t, atoi(argv[2]));
    if (r < 0) {
        printf("swap-seal: unable to seal %s\n", argv[1]);
        goto out;
    }
    printf("sealing completed.\n");
out:
    return r;
}
