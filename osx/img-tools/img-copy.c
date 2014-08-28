/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libimg.h"

static void usage(const char **argv)
{
    printf("%s proto:IN-FILE proto:OUT-FILE\n", argv[0]);
    printf("\n");
    printf("example: %s swap:/tmp/disk.swap vhd:/tmp/disk.vhd\n", argv[0]);
}

static int copy_blocks(BlockDriverState *bs_dst, BlockDriverState *bs_src, size_t len)
{
    int ret = -1;
    const int64_t buf_size = 4096*16;
    uint8_t *buf = malloc(buf_size);
    uint8_t *zero_buf = malloc(buf_size);
    assert(buf);
    assert(zero_buf);

    bzero(buf, buf_size);
    bzero(zero_buf, buf_size);

    for (off_t off = 0; off < len; off += buf_size) {
        const int64_t num_sectors = (buf_size + BDRV_SECTOR_SIZE - 1) >> BDRV_SECTOR_BITS;
        int read_s = bdrv_read(bs_src, off >> BDRV_SECTOR_BITS, buf, num_sectors);
        if (read_s != 0) {
            ret = read_s;
            goto out;
        }
        if (0 == memcmp(buf, zero_buf, buf_size)) {
            continue;
        }
        int write_s = bdrv_write(bs_dst, off >> BDRV_SECTOR_BITS, buf, num_sectors);
        if (write_s != 0) {
            ret = write_s;
            goto out;
        }
    }

out:
    free(buf);
    free(zero_buf);
    return ret;
}

int main(int argc, const char **argv)
{
    int argc_in_file = 1;
    int argc_out_file = 2;
    int r;
    int64_t len;
    BlockDriverState *bs_src;
    BlockDriverState *bs_dst;

    if (argc < 3) {
        usage(argv);
        exit(1);
    }

    char *src = strdup(argv[argc_in_file]);
    char *dst = strdup(argv[argc_out_file]);

    ioh_init();
    bh_init();
    aio_init();
    bdrv_init();

    bs_src = bdrv_new(src);
    bs_dst = bdrv_new(dst);

    if (!bs_src || !bs_dst) {
        printf("bs_src = %p, bs_dst = %p\n", bs_src, bs_dst);
        exit(1);
    }

    r = bdrv_open(bs_src, src, BDRV_O_RDWR);
    if (r < 0) {
        fprintf(stderr, "brdv_open('%s') failed: %s.\n", src, strerror(errno));
        exit(1);
    }
    free(src);

    len = bdrv_getlength(bs_src);
    r = bdrv_create(dst, len, 0);
    if (r < 0) {
        fprintf(stderr, "brdv_create('%s') failed: %s.\n", dst, strerror(errno));
        exit(1);
    }
    r = bdrv_open(bs_dst, dst, BDRV_O_RDWR);
    if (r < 0) {
        fprintf(stderr, "brdv_open('%s') failed: %s.\n", dst, strerror(errno));
        exit(1);
    }
    free(dst);

    printf("converting disk of size %"PRId64"MiB\n", len / 1024 / 1024);

    int cp_s = copy_blocks(bs_dst, bs_src, len);
    assert(0 == cp_s);

    bdrv_delete(bs_src);
    bdrv_delete(bs_dst);

    printf("OK.\n");

    return 0;
}
