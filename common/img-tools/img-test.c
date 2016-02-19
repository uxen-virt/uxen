/*
 * Copyright 2013-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <err.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include "libimg.h"

void init_genrand64(unsigned long long seed);
unsigned long long genrand64_int64(void);

#if defined(_WIN32)
#include <windows.h>
DECLARE_PROGNAME;
#endif	/* _WIN32 */


#ifdef _WIN32
static inline double rtc(void)
{
    LARGE_INTEGER time;
    LARGE_INTEGER freq;

    QueryPerformanceCounter(&time);
    QueryPerformanceFrequency(&freq);

    uint64_t t = ((uint64_t)time.HighPart << 32UL) | time.LowPart;
    uint64_t f = ((uint64_t)freq.HighPart << 32UL) | freq.LowPart;

    return ((double)t) / ((double)f);
}
#else
#include <sys/time.h>
static inline double rtc(void)
{
    struct timeval time;
    gettimeofday(&time,0);
    return ( (double)(time.tv_sec)+(double)(time.tv_usec)/1e6f );
}
#endif


#if defined(_WIN32)
#include <windows.h>
DECLARE_PROGNAME;
#endif	/* _WIN32 */

/* Generate a sector's worth of data, in a way that it
 * will get average compression out of LZ4. */
void gen(uint64_t seed, int version, uint8_t *out)
{
    int i;
    uint32_t *o = (uint32_t*) out;
    seed ^= (1117 * version);

    int mod = (1 + (seed % 800));
    for (i = 0; i < BDRV_SECTOR_SIZE / sizeof(uint32_t); ++i) {
        *o++ = i % mod;
    }
    *((uint64_t *) out) = seed;
}

void cmp(uint64_t sector, int ver, uint8_t *buf, uint8_t *buf2)
{
    if (memcmp(buf, buf2, BDRV_SECTOR_SIZE)) {
        printf("sector 0x%"PRIx64" (ver=%d) (in block %"PRIx64" is BAD!!!!!!!\n", sector, ver, sector / 8);
        uint64_t perhaps = *((uint64_t *) buf);

        printf("looks like perhaps sector %"PRIx64" from block %"PRIx64"\n",
                perhaps, perhaps / 8);

        int i;
        for (i = 0; i < BDRV_SECTOR_SIZE; i += 32) {

            if (memcmp(buf + i, buf2 + i, 32)) {
                int j;
                printf("i=%x\n", i);
                for (j = 0; j < 32; ++j) {
                    printf("%02x ", buf[i + j]);
                }
                printf("\n");
                for (j = 0; j < 32; ++j) {
                    printf("%02x ", buf2[i + j]);
                }
                printf("\n");
            }


        }
        exit(1);
    }
}

#define MAX_SECTORS (16ULL << (30ULL-9ULL))
//#define MAX_SECTORS (1ULL << (20ULL-9ULL))
uint16_t sector_map[MAX_SECTORS + 1024*1024];

/* Generate random <offset, len> pair. */
static inline void rnd(uint64_t *s, uint32_t *l, int align)
{
    uint64_t mask = 7;
    *s = (genrand64_int64() & (MAX_SECTORS - 1));
    *l = 1 + (genrand64_int64() & 0x1f);
    if (align) {
        *s = ((*s + mask) & ~mask);
        *l = ((*l + mask) & ~mask);
    }
}

#if 0
/* Generate random <offset, len> pair. */
static inline void seq(uint64_t *s, uint32_t *l, int align)
{
    static int start = 0;
    *s = start;
    *l = 16;
    start += *l;
}
#endif

int main(int argc, char **argv)
{
#ifdef _WIN32
    setprogname(argv[0]);
#endif

    BlockDriverState *bs;
    int r;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <swap:dst.swap> <N> <ROUNDS> <align|unalign>\n",
                argv[0]);
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

    const char *dst = argv[1];
    int N = atoi(argv[2]);
    int R = atoi(argv[3]);
    int align = (!strcmp("align", argv[4]));

    r = bdrv_create(dst, 17ULL << 30ULL, 0);
    assert(r >= 0);

    r = bdrv_open(bs, dst, BDRV_O_RDWR);
    assert(r >= 0);

    uint8_t buf[0x20000];
    uint8_t *b;
    uint64_t sector;
    uint32_t len;
    int i, j;
    uint32_t total_sectors;

    int round = 0;

    for (round = 0, total_sectors = 0; round < R; ++round) {
        printf("enter loop %d\n", round);
        double t0 = rtc();
        double t1, dt;

        init_genrand64(round);
        for (i = 0; i < N; ++i) {
            rnd(&sector, &len, align);
            for (j = 0, b = buf; j < len; ++j, b += BDRV_SECTOR_SIZE) {
                int ver = ++(sector_map[sector + j]);
                gen(sector + j, ver, b);
            }

            int r = bdrv_write(bs, sector, buf, len);
            total_sectors += len;

#if 0
            if (!(i % 1000) && i > 0) {
                printf("%.2f %s writes/s\n", ((double)i) / (rtc() - t0),
                        align ? "4kiB-aligned" : "unaligned");
            }
#endif

            if (r < 0) {
                printf("r %d\n", r);
                exit(1);
            }
        }
        bdrv_flush(bs);
        t1 = rtc();
        dt = t1 - t0;
        printf("%.1f writes/s, %.2fMiB/s %s\n", ((double)i) / dt,
                (double) (total_sectors >> 11) / dt,
                align ? "4kiB-aligned" : "unaligned");

        t0 = t1;
        init_genrand64(round);
        for (i = 0; i < N; ++i) {
            uint8_t buf2[0x20000];
            rnd(&sector, &len, align);

            int r = bdrv_read(bs, sector, buf, len);
            for (j = 0, b = buf; j < len; ++j, b += BDRV_SECTOR_SIZE) {
                int ver = sector_map[sector + j];
                gen(sector + j, ver, buf2);
                cmp(sector + j, ver, b, buf2);
            }

#if 0
            if (!(i % 1000) && i > 0) {
                printf("%.2f %s reads/s\n", ((double)i) / (rtc() - t0),
                        align ? "4kiB-aligned" : "unaligned");
            }
#endif

            if (r < 0) {
                printf("r %d\n", r);
                break;
            }
        }
        t1 = rtc();
        dt = t1 - t0;
        printf("%.1f reads/s, %.2fMiB/s %s\n", ((double)i) / dt,
                (double) (total_sectors >> 11) / dt,
                align ? "4kiB-aligned" : "unaligned");

        t0 = t1;

    }
    bdrv_flush(bs);
    bdrv_delete(bs);
    printf("test complete\n");
    return 0;
}
