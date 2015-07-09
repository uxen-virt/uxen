/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

/* 
 *  fingerprint.c
 *
 *  COPYRIGHT
 *
 */

#include <stdint.h>

#define PAGE_SIZE 4096

/* Compute a rolling hash over a 64 byte window for every 32b offset
 * in the page, and return the min and max values combined into a
 * single hash value. If the input page lacks enough entropy to compute
 * a meaningful hash, the return value will be ~0ULL. */
uint64_t
page_fingerprint(const uint8_t *_page, uint16_t *rotate)
{
    uint32_t *page = (uint32_t *)_page;
    const unsigned int sz = PAGE_SIZE / sizeof(uint32_t);

    uint64_t h, h1;
    static uint64_t base = 0;

    int i;
    uint32_t *old;

    const uint64_t B = 251;
    const int P = 64 / sizeof(uint32_t);
    const uint64_t key = 0x0100020080040000ULL;

    uint64_t max = 0;
    uint64_t min = ~0ULL;
    int minpos = 0;

    /* Compute base to subtract when exceeding window. For reasonably small
     * values of P there is no measurable effect of precomputing this (perhaps
     * the compiler has figured out its a constant). */
    if (!base)
        for (base = 1, i = 1; i < P; i++)
            base = (base * B);

    old = &page[-P];

    for (i = 0, h = 0; i < sz; i++, old++) {
        h = B * (h - ((i >= P) ? (*old * base) : 0)) + page[i];

        /* With a hash that matches our sampling bit pattern, re-hash it using
         * a stronger hash function. The bit pattern check is only to speed
         * things up. */

        if ((h & key) == key) {
            /* Avalanche bits using Murmurhash3 64-bit finalizer. */
            h1 = h;
            h1 ^= h1 >> 33;
            h1 *= 0xff51afd7ed558ccd;
            h1 ^= h1 >> 33;
            h1 *= 0xc4ceb9fe1a85ec53;
            h1 ^= h1 >> 33;

            /* Update min, max, and minpos. Use cmove for speed. */
            minpos = min < h1 ? minpos : i;
            min = min < h1 ? min : h1;
            max = max < h1 ? h1 : max;
        }
    }

    *rotate = minpos;
    /* Combine into single hash, but shift max by one to avoid returning 0 when
     * * min == max. */
    return min ^ (max << 1ULL);
}
