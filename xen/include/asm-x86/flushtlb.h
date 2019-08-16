/******************************************************************************
 * flushtlb.h
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2004, K A Fraser
 */

#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

#include <xen/config.h>
#include <xen/percpu.h>
#include <xen/smp.h>
#include <xen/types.h>

/* Read the value of cr3  */
static inline unsigned long read_cr3(void)
{
    unsigned long cr3;
    __asm__ __volatile__ (
        "mov %%cr3, %0" : "=r" (cr3) : );
    return cr3;
}

/* Read pagetable base. */
static inline unsigned long read_paging_base(void)
{
    unsigned long cr3 = read_cr3();

#ifdef __x86_64__
    cr3 &= PAGE_MASK;
#endif

    return cr3;
}

/* Write pagetable base and implicitly tick the tlbflush clock. */
void write_cr3(unsigned long cr3);

/* flush_* flag fields: */
 /*
  * Area to flush: 2^flush_order pages. Default is flush entire address space.
  * NB. Multi-page areas do not need to have been mapped with a superpage.
  */
#define FLUSH_ORDER_MASK 0xff
#define FLUSH_ORDER(x)   ((x)+1)
 /* Flush TLBs (or parts thereof) */
#define FLUSH_TLB        0x100
 /* Flush TLBs (or parts thereof) including global mappings */
#define FLUSH_TLB_GLOBAL 0x200
 /* Flush data caches */
#define FLUSH_CACHE      0x400

/* Flush local TLBs/caches. */
void flush_area_local(const void *va, unsigned int flags);
#define flush_local(flags) flush_area_local(NULL, flags)

/* Flush specified CPUs' TLBs/caches */
void flush_area_mask(const cpumask_t *, const void *va, unsigned int flags);
#define flush_mask(mask, flags) flush_area_mask(mask, NULL, flags)

/* Flush all CPUs' TLBs/caches */
#define flush_area_all(va, flags) flush_area_mask(&cpu_online_map, va, flags)
#define flush_all(flags) flush_mask(&cpu_online_map, flags)

/* Flush local TLBs */
#define flush_tlb_local()                       \
    flush_local(FLUSH_TLB)
#define flush_tlb_one_local(v)                  \
    flush_area_local((const void *)(v), FLUSH_TLB|FLUSH_ORDER(0))

/* Flush specified CPUs' TLBs */
#define flush_tlb_mask(mask)                    \
    flush_mask(mask, FLUSH_TLB)
#define flush_tlb_one_mask(mask,v)              \
    flush_area_mask(mask, (const void *)(v), FLUSH_TLB|FLUSH_ORDER(0))

/* Flush all CPUs' TLBs */
#define flush_tlb_all()                         \
    flush_tlb_mask(&cpu_online_map)
#define flush_tlb_one_all(v)                    \
    flush_tlb_one_mask(&cpu_online_map, v)

#endif /* __FLUSHTLB_H__ */
