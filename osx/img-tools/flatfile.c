/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <stdlib.h>
#include <hfs/hfsplus.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <libimg.h>
#include "cache.h"
#include "shallow.h"

#define MAX_PATH_LEN 2048 // XXX duplicate

/* The HFS plus code does not assume any sector alignment, so we have to
 * emulate. However, to avoid doing RMW etc. both here and in the swap backend,
 * we emulate 4kB instead of 512B. */

#define BLOCK_SIZE CACHE_SECTORSIZE
#define PARTITION_START 64
#define CACHE_LOG_LINES 12

typedef struct FileData {
    BlockDriverState *bs;
    Cache cache;
    int is_shallowed;
    ShallowMap sm;
} FileData;

#include <sys/time.h>
static inline double rtc(void)
{
    struct timeval time;
    gettimeofday(&time,0);
    return ( (double)(time.tv_sec)+(double)(time.tv_usec)/1e6f );
}
double total = 0.0;

static void update_cache(FileData *fd, uint64_t aligned_offset, const void *buffer, int dirty)
{
    uint64_t old;
    void *old_sector = NULL;
    cacheStore(&fd->cache, aligned_offset / BLOCK_SIZE, buffer, dirty, &old, &old_sector);
    double t0 = rtc();

    if (old_sector) {

        /* Write back evicted block. */
        int r = bdrv_write(fd->bs, (old * BLOCK_SIZE) >> BDRV_SECTOR_BITS, old_sector,
                BLOCK_SIZE >> BDRV_SECTOR_BITS);

        assert(r >= 0);
        free(old_sector);
    }
    total += rtc() - t0;
}

static int hits = 0;
static int misses = 0;

static inline int aligned_read(FileData *fd, off_t aligned_offset, off_t
        aligned_end, uint8_t *buffer)
{
//    if (!((hits+misses)%10000)) printf("hits=%d misses=%d t=%f\n", hits, misses, total);
    while (aligned_offset != aligned_end) {

        void *cached = cachePeek(&fd->cache, aligned_offset / BLOCK_SIZE, 0);

        if (!cached) {
            ++misses;
            double t0 = rtc();
            int r = bdrv_read(fd->bs, aligned_offset >> BDRV_SECTOR_BITS, buffer,
                    BLOCK_SIZE >> BDRV_SECTOR_BITS);
            assert(r>=0);
            total += rtc() - t0;

            update_cache(fd, aligned_offset, buffer, 0);

        } else {
            
            ++hits;
            memcpy(buffer, cached, BLOCK_SIZE);
        }

        aligned_offset += BLOCK_SIZE;
        buffer += BLOCK_SIZE;
    }
    return 0;
}

static inline int aligned_write(FileData *fd, off_t aligned_offset, off_t
        aligned_end, const uint8_t *buffer)
{
    while (aligned_offset != aligned_end) {
        update_cache(fd, aligned_offset, buffer, 1);
        aligned_offset += BLOCK_SIZE;
        buffer += BLOCK_SIZE;
    }

    return 0;
}
        
static int flatFileRead(io_func* io, off_t offset, size_t count, void *buffer)
{
    offset += PARTITION_START << BDRV_SECTOR_BITS;

    FileData *fd = (FileData*) io->data;
    const uint64_t mask = BLOCK_SIZE - 1;
    uint64_t aligned_offset = offset & ~mask;
    uint64_t aligned_end = (offset + count + mask) & ~mask;
    size_t aligned_count = aligned_end - aligned_offset;

    if (aligned_count == BLOCK_SIZE) {

        uint8_t *cached = cachePeek(&fd->cache, aligned_offset / BLOCK_SIZE, 0);
        if (cached) {
            ++hits;
            memcpy(buffer, cached + (offset & mask), count);
            return TRUE;
        }
    }

    uint8_t *b = malloc(aligned_count);
    assert(b);

    //if (aligned_count > 4096) printf("big read %llx %zx %zx\n", offset, count, aligned_count);

    int r = aligned_read(fd, aligned_offset, aligned_end, b);
    assert(r >= 0);

    memcpy(buffer, b + (offset & mask), count);
    free(b);

    return TRUE;
}

static int flatFileWrite(io_func* io, off_t offset, size_t count, void *buffer)
{
    offset += PARTITION_START << BDRV_SECTOR_BITS;

    FileData *fd = (FileData*) io->data;
    ssize_t r;
    const uint64_t mask = BLOCK_SIZE - 1;
    uint8_t *aligned_buf = NULL;
    uint64_t aligned_offset = offset & ~mask;
    uint64_t aligned_end = (offset + count + mask) & ~mask;
    size_t aligned_count = aligned_end - aligned_offset;
    int prefix_len;

    prefix_len = shallow_check_magic(buffer);
    if (prefix_len > 0) {
        if (!fd->is_shallowed) {
            printf("shallow writes pattern found on device which is not .swap and therefore not shallowed\n");
            return FALSE;
        }

        uint64_t inode;
        uint64_t file_offset;
        char fn[MAX_PATH_LEN];
        const char *s = (const char*) buffer + prefix_len;
        sscanf(s, "%llu-%llu-%[^\n]", &file_offset, &inode, fn);
        shallow_record_file(&fd->sm, fn, inode, aligned_offset, aligned_count, file_offset);
        return TRUE;
    }

    if ((offset & mask) || (count & mask)) {

        if (aligned_count == BLOCK_SIZE) {

            uint8_t *cached = cachePeek(&fd->cache, aligned_offset / BLOCK_SIZE, 1);
            if (cached) {
                memcpy(cached + (offset & mask), buffer, count);
                return TRUE;
            }
        }

        if (!(aligned_buf = malloc(aligned_count))) {
            printf("unable to alloc aligned buffer\n");
            return FALSE;
        }
        /* Read... */

        r = aligned_read(fd, aligned_offset, aligned_end, aligned_buf);
        if (r < 0) {
            printf("RMW read failed!\n");
            goto out;
        }

        /* Modify... */
        memcpy(aligned_buf + (offset & mask), buffer, count);

    }

    /* Write and update cache. */
    aligned_write(fd, aligned_offset, aligned_end, aligned_buf ? aligned_buf : buffer);

out:
    free(aligned_buf);

    return TRUE;
}

static void closeFlatFile(io_func* io)
{
    FileData *fd = (FileData*) io->data;


    int i;

    for (i = 0; i < (1<<CACHE_LOG_LINES); ++i) {

        uint64_t block;
        void *sector;
        if (cacheGetDirtyLine(&fd->cache, i, &block, &sector)) {

            int r = bdrv_write(fd->bs, (block * BLOCK_SIZE) >> BDRV_SECTOR_BITS, sector,
                    BLOCK_SIZE >> BDRV_SECTOR_BITS);

            assert(r >= 0);
        }

    }

    if (shallow_flush_map(&fd->sm) != 0) {
        fprintf(stderr, "shallow_flush_map() failed, exiting.\n");
        exit(-1);
    }

    BlockDriverState *bs = fd->bs;
    bdrv_flush(bs);
    bdrv_delete(bs);
    free(fd);
}

char *dir_name(const char *fn)
{
    const char *c;
    char *ret;
    size_t len = 0;
    for (c = fn; *c; ++c) {
        if (*c == '/')
            len = c - fn;
    }
    if ((ret = malloc(len + 1))) {
        memcpy(ret, fn, len);
        ret[len] = '\0';
    }
    return ret;
}

io_func* openFlatFile(const char* fileName)
{
    io_func* io;
    FileData *fd;
    char fn[1024];
    char *dn = NULL;

    size_t l = strlen(fileName);
    if (l > 5 && strncmp(fileName, "swap:", 5) != 0 && strncmp(fileName + l - 5, ".swap", 5) == 0) {
        strcpy(fn, "swap:");
        realpath(fileName, fn + 5);
        dn = dir_name(fn + 5);
    } else
        strcpy(fn, fileName);

    bh_init();
    bdrv_init();
    fd = (FileData*) malloc(sizeof(FileData));
    assert(fd);
    memset(fd, 0, sizeof(FileData));
    fd->bs = bdrv_new("");
    cacheInit(&fd->cache, CACHE_LOG_LINES);

    if (dn) {
        /* Shallow only works with .swap */
        char map[1024];
        char watches[1024];
        fd->is_shallowed = 1;
        sprintf(map, "%s/swapdata/map.idx", dn);
        sprintf(watches, "%s/swapdata/watches", dn);
        free(dn);
        if (shallow_init(&fd->sm, map, watches) < -1) {
            fprintf(stderr, "warning: unable to open shallow map for overwrite.\n");
        }
    } else
        fd->is_shallowed = 0;

    io = (io_func*) malloc(sizeof(io_func));
    io->data = fd;

    if(io->data == NULL) {
        perror("fopen");
        return NULL;
    }

    int r = bdrv_open(fd->bs, fn, BDRV_O_RDWR);
    if (r < 0) {
        fprintf(stderr, "bdrv_open fails\n");
        return NULL;
    }

    io->read = &flatFileRead;
    io->write = &flatFileWrite;
    io->close = &closeFlatFile;

    return io;
}

io_func* openFlatFileRO(const char* fileName)
{
    return openFlatFile(fileName);
}
