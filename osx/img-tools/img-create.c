/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>


#include <libimg.h>

int main(int argc, char **argv)
{
    BlockDriverState *bs;
    int r;

    if (argc != 3) {
        fprintf(stderr, "usage: %s src.raw swap:dst.swap\n", argv[0]);
        exit(-1);
    }

    ioh_init();
    bh_init();
    aio_init();
    bdrv_init();
    bs = bdrv_new("");

    if (!bs) {
        printf("no bs\n");
        return -1;
    }

    const char *src = argv[1];
    const char *dst = argv[2];

    FILE *f = fopen(src, "rb");
    assert(f);
    struct stat st;
    fstat(fileno(f), &st);

    r = bdrv_create(dst, st.st_size, 0);
    assert(r >= 0);

    r = bdrv_open(bs, dst, BDRV_O_RDWR);
    assert(r >= 0);

    uint64_t offset = 0;
    uint8_t buf[4096*16];

    for (offset = 0;; offset += sizeof(buf)) {

        r = fread(buf, 1, sizeof(buf), f);

        if (r < 0)
            break;

        int i;
        for (i = 0; i < sizeof(buf); ++i) {
            if (buf[i]) break;
        }
        if (i == sizeof(buf)) {
            printf("_");
            continue;
        } else  {
            printf(".");
            fflush(stdout);
        }
#if 0
        printf("write %llu\n", offset);

        if (!(offset & ((1<<20)-1))) {
            printf("@ %llu\n", offset);
        }
#endif

        int r2 = bdrv_write(bs, offset >> BDRV_SECTOR_BITS, buf,
                         (r + 511) >> BDRV_SECTOR_BITS);

        if (r != sizeof(buf) || r2 < 0) {
            printf("r=%d, r2=%d @ %llu\n", r, r2, offset);
            break;
        }
    }
    fclose(f);
    bdrv_flush(bs);
    bdrv_delete(bs);

}
