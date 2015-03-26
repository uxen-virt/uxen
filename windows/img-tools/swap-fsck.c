/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <block-swap/dubtree_sys.h>
#include <block-swap/dubtree.h>

#ifdef RT_OS_WINDOWS
#include <windows.h> /* must go first. */
#include <stdio.h>
#pragma comment (lib, "Shell32.lib")
#else
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <lz4.h>
#include "sys.h"

uint64_t
dubtreeGetVersionByIndex(const DUBTREE* t, int idx);

#ifdef _WIN32
DECLARE_PROGNAME;
#endif

int main(int argc, char **argv)
{

    DUBTREE *t = (DUBTREE*) malloc(sizeof(DUBTREE));
    void *context;
    int r;
    uint64_t start = 0;
    int found = 0;
    uint64_t v = 0;

#ifdef _WIN32
    setprogname(argv[0]);
    convert_args(argc, argv);
#endif

    if (argc < 2 || argc > 3) {
        printf("usage: %s swapdata sysimage/swapdata\n", argv[0]);
        printf("   or: %s swapdata\n", argv[0]);
        exit(1);
    }

    char *fallbacks[] = {NULL, NULL};
    if (argc > 2) {
        fallbacks[0] = argv[2];
    }
    r = dubtreeInit(t, argv[1], fallbacks);
    if (r) {
        printf("dubtreeInit failed %d\n", r);
        exit(1);
    }

    v = dubtreeGetVersionByIndex(t, 0);
    if (!v) {
        printf("no snapshot found, giving up!\n");
        exit(1);
    }
    printf("first snapshot found was %"PRIx64"\n", v);

    context = dubtreePrepareFind(t, v);
    if (!context) {
        printf("dubtreePrepareFind failed\n");
        exit(1);
    }

    r = dubtreeSanityCheck(t);
    if (r < 0) {
        printf("dubtree sanity check fails!\n");
        exit(1);
    }

    /* Verify all blocks up to 80GiB. */
    for (start = 0; start < ((80ULL<<30ULL)/4096ULL); ++start) {

        uint8_t out[DUBTREE_BLOCK_SIZE];
        uint64_t map[1];
        size_t sizes[1];

        memset(map, 0, sizeof(map));
        memset(sizes, 0, sizeof(sizes));

        r = dubtreeFind(t, start, 1, out, map, sizes,
                context);
        if (r < 0) {
            printf("dubtreeFind call failed!\n");
            exit(1);
        }

        /* Print progress. */
        if (!(start % 1000000)) printf("%u found=%d...\n", (uint32_t)start, found);

        /* If we found the block, check that it decompresses to the right size. */
        if (map[0]) {
            char page[4096];
            int unsz;
            ++found;
            if (map[0] != v) {
                printf("found wrong version %"PRIx64"\n", map[0]);
                exit(1);
            }
                
            if (sizes[0] < 4096) {
                unsz = LZ4_uncompress((const char*)out, page, DUBTREE_BLOCK_SIZE);

            } else {
                unsz = 4096;
            }
            if (unsz != sizes[0]) {
                printf("%"PRIx64" is %d should be %u\n", start, unsz, (uint32_t)sizes[0]);
                exit(1);
            }
        }
    }

    dubtreeEndFind(t, context);
    printf("All blocks decompressed OK.\n");

    return 0;
}
