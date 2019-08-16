/******************************************************************************
 * flushtlb.c
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2006, K A Fraser
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <asm/flushtlb.h>
#include <asm/page.h>

void flush_area_local(const void *va, unsigned int flags)
{
    const struct cpuinfo_x86 *c = &current_cpu_data;
    unsigned int order = (flags - 1) & FLUSH_ORDER_MASK;
    unsigned long irqfl;

    /* This non-reentrant function is sometimes called in interrupt context. */
    cpu_irq_save(irqfl);

    if ( flags & (FLUSH_TLB|FLUSH_TLB_GLOBAL) )
    {
        if ( order == 0 )
        {
            /*
             * We don't INVLPG multi-page regions because the 2M/4M/1G
             * region may not have been mapped with a superpage. Also there
             * are various errata surrounding INVLPG usage on superpages, and
             * a full flush is in any case not *that* expensive.
             */
            asm volatile ( "invlpg %0"
                           : : "m" (*(const char *)(va)) : "memory" );
        }
        else
        {

            hvm_flush_guest_tlbs();

#ifndef USER_MAPPINGS_ARE_GLOBAL
            if ( !(flags & FLUSH_TLB_GLOBAL) || !(read_cr4() & X86_CR4_PGE) )
            {
                asm volatile ( "mov %0, %%cr3"
                               : : "r" (read_cr3()) : "memory" );
            }
            else
#endif
            {
                unsigned long cr4 = read_cr4();
                write_cr4(cr4 & ~X86_CR4_PGE);
                barrier();
                write_cr4(cr4);
            }

        }
    }

    if ( flags & FLUSH_CACHE )
    {
        unsigned long i, sz = 0;

        if ( order < (BITS_PER_LONG - PAGE_SHIFT) )
            sz = 1UL << (order + PAGE_SHIFT);

        if ( c->x86_clflush_size && c->x86_cache_size && sz &&
             ((sz >> 10) < c->x86_cache_size) )
        {
            va = (const void *)((unsigned long)va & ~(sz - 1));
            for ( i = 0; i < sz; i += c->x86_clflush_size )
                 asm volatile ( "clflush %0"
                                : : "m" (((const char *)va)[i]) );
        }
        else
        {
            wbinvd();
        }
    }

    cpu_irq_restore(irqfl);
}
