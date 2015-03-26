/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

/* Copyright (c) 2012-2013 Bromium Inc.
 * All rights reserved
 * Author: Jacob Gorm Hansen
 *
 * Seal a swap disk by merging all data in a single, all-sorted level.
*/

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <block-swap/dubtree_sys.h>
#include <block-swap/dubtree_io.h>
#include <block-swap/dubtree.h>

int main(int argc, char **argv)
{
    DUBTREE *t = (DUBTREE*) malloc(sizeof(DUBTREE));
    int r;

    if (argc != 3) {
        printf("Usage: swap-seal <swapdata> <level>\n");
        return EXIT_FAILURE;
    }

    r = dubtreeInit(t, argv[1], NULL);
    if (r < 0) {
        fprintf(logfile, "unable to open tree at %s!\n", argv[1]);
        return r;
    }
    
    /* Seal and close the tree, making it immutable. */
    r = dubtreeSeal(t, atoi(argv[2]));
    if (r < 0) {
        fprintf(logfile, "unable to seal tree at %s!\n", argv[1]);
        return r;
    }

    fprintf(logfile, "tree at %s sealed ok.\n", argv[1]);
    return 0;
}
