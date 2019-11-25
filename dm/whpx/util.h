/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_UTIL_H_
#define WHPX_UTIL_H_

#include "WinHvGlue.h"
#include "WinHvPlatform.h"
#include "cpu.h"
#include "core.h"

extern uint64_t tmsum_runvp;
extern uint64_t count_runvp;
extern uint64_t tmsum_xlate;
extern uint64_t count_xlate;
extern uint64_t count_request_irq;
extern uint64_t tmsum_request_irq;
extern uint64_t tmsum_vmexit[256];
extern uint64_t count_vmexit[256];
extern uint64_t tmsum_lapic_access;
extern uint64_t count_lapic_access;
extern uint64_t tmsum_v4v;
extern uint64_t count_v4v;
extern uint64_t count_longspin;
extern uint64_t count_hpet;
extern uint64_t count_reftime;
extern uint64_t count_synthtimer;
extern uint64_t count_synthic;

extern bool whpx_has_suspend_time;

/* internal whpx utility functions */
void whpx_initialize_api(void);
whpx_reg_list_t *whpx_all_registers(void);
WHV_PARTITION_HANDLE whpx_get_partition(void);
const char *get_whv_register_name_str(WHV_REGISTER_NAME x);
void get_whv_register_descr(WHV_REGISTER_NAME r, WHV_REGISTER_VALUE v, char *buf, int bufsz);
int get_registry_cpu_mhz(void);
void whpx_dump_cpu_state(int cpu_index);
void dump_whv_register_list(WHV_REGISTER_NAME *r, WHV_REGISTER_VALUE *v, int count);
void dump_phys_mem(uint64_t paddr, int len);

WHV_X64_SEGMENT_REGISTER whpx_seg_q2h(const SegmentCache *qs);
SegmentCache whpx_seg_h2q(const WHV_X64_SEGMENT_REGISTER *hs);
HRESULT whpx_get_vp_registers(UINT32 VpIndex, const WHV_REGISTER_NAME *RegisterNames,
    UINT32 RegisterCount,  WHV_REGISTER_VALUE *RegisterValues);
HRESULT whpx_set_vp_registers(UINT32 VpIndex, const WHV_REGISTER_NAME *RegisterNames,
    UINT32 RegisterCount,  const WHV_REGISTER_VALUE *RegisterValues);
void whpx_dump_perf_stats(void);
void whpx_reset_perf_stats(void);

uint8_t whpx_er_byte_encode(int exit_reason);
int whpx_er_byte_decode(uint8_t exit_reason_byte);

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

/* From Windows 17763 SDK */
#define PAGE_REVERT_TO_FILE_MAP     0x80000000
#define MEM_REPLACE_PLACEHOLDER     0x00004000
#define MEM_RESERVE_PLACEHOLDER     0x00040000
#define MEM_COALESCE_PLACEHOLDERS   0x00000001
#define MEM_PRESERVE_PLACEHOLDER    0x00000002

typedef PVOID WINAPI
(*MapViewOfFile3_t)(
  HANDLE FileMapping,
  HANDLE Process,
  PVOID BaseAddress,
  ULONG64 Offset,
  SIZE_T ViewSize,
  ULONG AllocationType,
  ULONG PageProtection,
  PVOID ExtendedParameters,
  ULONG ParameterCount
);

typedef PVOID WINAPI
(*VirtualAlloc2_t)(
  HANDLE Process,
  PVOID BaseAddress,
  SIZE_T Size,
  ULONG AllocationType,
  ULONG PageProtection,
  PVOID ExtendedParameters,
  ULONG ParameterCount
);

typedef struct win32_memory_range_entry {
  PVOID VirtualAddress;
  SIZE_T NumberOfBytes;
} win32_memory_range_entry;

typedef BOOL WINAPI
(*PrefetchVirtualMemory_t)(
  HANDLE hProcess,
  ULONG_PTR NumberOfEntries,
  win32_memory_range_entry *VirtualAddresses,
  ULONG Flags);

extern MapViewOfFile3_t MapViewOfFile3P;
extern VirtualAlloc2_t VirtualAlloc2P;
extern PrefetchVirtualMemory_t PrefetchVirtualMemoryP;

/* from ntdll.dll */

/* for NtQuerySystemInformation */
#include <winternl.h>
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

typedef WINAPI NTSTATUS
(*NtQuerySystemInformation_t)(
  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
  OUT PVOID                   SystemInformation,
  IN ULONG                    SystemInformationLength,
  OUT PULONG                  ReturnLength
);

extern NtQuerySystemInformation_t NtQuerySystemInformationP;

#endif
