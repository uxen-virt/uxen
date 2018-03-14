/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_UTIL_H_
#define WHPX_UTIL_H_

#define PERF_TEST 0

extern uint64_t tsum_runvp;
extern uint64_t count_runvp;

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

/* internal whpx utility functions */
void whpx_initialize_api(void);
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


#endif
