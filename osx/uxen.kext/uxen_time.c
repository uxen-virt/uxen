/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"

struct tscInfo
{
    uint64_t    busFCvtt2n;
    uint64_t    busFCvtn2t;
    uint64_t    tscFreq;
    uint64_t    tscFCvtt2n;
    uint64_t    tscFCvtn2t;
    uint64_t    tscGranularity;
    uint64_t    bus2tsc;
    uint64_t    busFreq;
    uint32_t    flex_ratio;
    uint32_t    flex_ratio_min;
    uint32_t    flex_ratio_max;
};
typedef struct tscInfo tscInfo_t;

extern void tsc_get_info(tscInfo_t *info);

uint64_t
uxen_get_counter_freq(void)
{
    tscInfo_t info;

    tsc_get_info(&info);

    return info.tscFreq;
}

