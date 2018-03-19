/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_UTIL_H_
#define WHPX_UTIL_H_

#include "winhvglue.h"
#include "winhvplatform.h"
#include "cpu.h"
#include "core.h"

#define PERF_TEST 0

extern uint64_t tsum_runvp;
extern uint64_t count_runvp;

/* internal whpx utility functions */
void whpx_initialize_api(void);
whpx_reg_list_t *whpx_all_registers(void);
WHV_PARTITION_HANDLE whpx_get_partition(void);
const char *get_whv_register_name_str(WHV_REGISTER_NAME x);
void get_whv_register_descr(WHV_REGISTER_NAME r, WHV_REGISTER_VALUE v, char *buf, int bufsz);
int get_cpu_mhz(void);
void whpx_dump_cpu_state(int cpu_index);
void dump_whv_register_list(WHV_REGISTER_NAME *r, WHV_REGISTER_VALUE *v, int count);

WHV_X64_SEGMENT_REGISTER whpx_seg_q2h(const SegmentCache *qs);
SegmentCache whpx_seg_h2q(const WHV_X64_SEGMENT_REGISTER *hs);
HRESULT whpx_get_vp_registers(UINT32 VpIndex, const WHV_REGISTER_NAME *RegisterNames,
    UINT32 RegisterCount,  WHV_REGISTER_VALUE *RegisterValues);
HRESULT whpx_set_vp_registers(UINT32 VpIndex, const WHV_REGISTER_NAME *RegisterNames,
    UINT32 RegisterCount,  const WHV_REGISTER_VALUE *RegisterValues);
void whpx_perf_stats(void);


/* _rdtsc */
static inline uint64_t _rdtsc()
{
    uint32_t low, high;
    uint64_t val;
    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
}

/* pagerange functions */
typedef struct pagerange {
    uint64_t start; /* start page */
    uint64_t end; /* end page plus one (if start==end, empty page range */
} pagerange_t;

static inline uint64_t
pr_bytes(pagerange_t *r)
{
    return (r->end - r->start) << PAGE_SHIFT;
}

static inline pagerange_t
mk_pr(uint64_t addr, uint64_t len)
{
    pagerange_t r;

    assert((addr & ~TARGET_PAGE_MASK) == 0);
    assert((len & ~TARGET_PAGE_MASK) == 0);

    r.start = addr >> PAGE_SHIFT;
    r.end   = (addr + len) >> PAGE_SHIFT;

    return r;
}

// return 1 if intersects
static inline int
intersect_pr(pagerange_t *a, pagerange_t *b, pagerange_t *out)
{
    uint64_t p_start, p_end;

    if (a->start >= b->end ||
        b->start >= a->end)
        return 0; /* no intersection */

    if (a->start >= b->start && a->start < b->end)
        p_start = a->start;
    else if (a->start < b->start)
        p_start = b->start;
    else
        return 0;

    if (a->end > b->start && a->end <= b->end)
        p_end = a->end;
    else if (a->end > b->end)
        p_end = b->end;
    else
        return 0;

    out->start = p_start;
    out->end = p_end;

    return 1;
}

// a minus b, returns number of chunks
static inline int
diff_pr(pagerange_t *a, pagerange_t *b, pagerange_t *out)
{
    pagerange_t inter;
    int count = 0;

    if (!intersect_pr(a, b, &inter)) {
        *out = *a;
        return 1;
    }

    if (a->start < b->start) {
        out->start = a->start;
        out->end   = b->start;
        out++;
        count++;
    }

    if (a->end > b->end) {
        out->start = b->end;
        out->end   = a->end;
        out++;
        count++;
    }

    return count;
}

#endif
