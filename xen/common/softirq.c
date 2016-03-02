/******************************************************************************
 * common/softirq.c
 * 
 * Softirqs in Xen are only executed in an outermost activation (e.g., never 
 * within an interrupt activation). This simplifies some things and generally 
 * seems a good thing.
 * 
 * Copyright (c) 2003, K A Fraser
 * Copyright (c) 1992, Linus Torvalds
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/preempt.h>
#include <xen/sched.h>
#include <xen/rcupdate.h>
#include <xen/softirq.h>
#include <xen/perfc.h>

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS];
#endif

static union {
    softirq_handler cpu;
    softirq_handler_vcpu vcpu;
} softirq_handlers[NR_SOFTIRQS];

static void __do_softirq(unsigned long ignore_mask)
{
    unsigned int i, cpu = smp_processor_id();
    unsigned long pending;

    for ( ; ; ) {
        if ( rcu_pending(cpu) )
            rcu_check_callbacks(cpu);

        if ( ((pending = (softirq_pending(cpu) & ~ignore_mask)) == 0)
             || cpu_is_offline(cpu) )
            break;

        i = find_first_set_bit(pending);
        clear_bit(i, &softirq_pending(cpu));
        switch (i) {
        case TIMER_CPU0_SOFTIRQ:
            perfc_incr(do_TIMER_SOFTIRQ);
            break;
        case RCU_CPU_SOFTIRQ:
            break;
        case TASKLET_SCHEDULE_CPU_SOFTIRQ:
            break;
        case P2M_L1_CACHE_CPU_SOFTIRQ:
            break;
        default:
            printk("vm%u.%u softirq %d on cpu %d => %S\n",
                   current->domain->domain_id, current->vcpu_id, i, cpu,
                   (printk_symbol)softirq_handlers[i].cpu);
            DEBUG();
        }
        ASSERT(softirq_handlers[i].cpu);
        (*softirq_handlers[i].cpu)();
    }
}

void process_pending_softirqs(void)
{
    ASSERT(!in_irq());
    ASSERT(local_irq_is_enabled());
    __do_softirq(
        /* timer softirq only on cpu0 idle thread */
        (!smp_processor_id() && is_idle_vcpu(current) ?
         0 : (1ul << TIMER_CPU0_SOFTIRQ)) |
        /* tasklet softirq only on idle thread */
        (is_idle_vcpu(current) ? 0 : (1ul << TASKLET_SCHEDULE_CPU_SOFTIRQ)));

    /* kick idle thread if any softirqs are still pending (incl. masked) */
    if (softirq_pending(smp_processor_id()))
        smp_send_event_check_cpu(smp_processor_id());
}

/* asmlinkage */ void do_softirq(void)
{
    ASSERT(!preempt_count());
    ASSERT(!in_irq());
    ASSERT(local_irq_is_enabled());
    ASSERT(!in_atomic());
    __do_softirq(0);
}

static void __do_softirq_vcpu(struct vcpu *v, unsigned long ignore_mask)
{
    unsigned int i;
    unsigned long pending;

    ASSERT(v == current);

    for ( ; ; ) {
        if ( (pending = (v->softirq_pending & ~ignore_mask)) == 0)
            break;

        i = find_first_set_bit(pending);
        clear_bit(i, &v->softirq_pending);
        switch (i) {
        case TIMER_VCPU_SOFTIRQ:
        case SCHEDULE_VCPU_SOFTIRQ:
        case KICK_VCPU_SOFTIRQ:
        case SYNC_TSC_VCPU_SOFTIRQ:
            break;
        default:
            printk("softirq %i on vcpu %p => %S\n", i, v,
                   (printk_symbol)softirq_handlers[i].vcpu);
            DEBUG();
        }
        ASSERT(softirq_handlers[i].vcpu);
        (*softirq_handlers[i].vcpu)(v);
    }
}

static inline void
check_vcpu_timer_interrupt(struct vcpu *v)
{
    struct vm_vcpu_info_shared *vci = v->vm_vcpu_info_shared;
    if (vci && vci->vci_has_timer_interrupt) {
        perfc_incr(vcpu_timer);
        set_bit(TIMER_VCPU_SOFTIRQ, &v->softirq_pending);
        vci->vci_has_timer_interrupt = 0;
    }
}

/* asmlinkage */ void do_softirq_vcpu(struct vcpu *v)
{
    ASSERT(!in_atomic());

    check_vcpu_timer_interrupt(v);

    /* this executes without vmcs loaded, softirqs depending on vmcs
     * need to be ignored */
    __do_softirq_vcpu(v, VCPU_SOFTIRQ_WITH_VMCS_MASK);
}

asmlinkage_abi int
check_work_vcpu(struct vcpu *v)
{

    check_vcpu_timer_interrupt(v);

    if (softirq_pending_vcpu(v, 0)) {
        cpu_irq_enable();
        __do_softirq_vcpu(v, 0);

        return 1;
    }

    if (UI_HOST_CALL(ui_host_needs_preempt)) {
        cpu_irq_enable();
        return 1;
    }

    return 0;
}

void
do_run_idle_thread(uint32_t had_timeout)
{

    if (had_timeout) {
        ASSERT(!smp_processor_id());
        set_bit(TIMER_CPU0_SOFTIRQ, &softirq_pending(smp_processor_id()));
        platform_time_sync();
    }

    __do_softirq(0);
}

void open_softirq(int nr, softirq_handler handler)
{
    ASSERT(nr < NR_SOFTIRQS);
    ASSERT(!softirq_handlers[nr].cpu || softirq_handlers[nr].cpu == handler);
    softirq_handlers[nr].cpu = handler;
}

void open_softirq_vcpu(int nr, softirq_handler_vcpu handler)
{
    ASSERT(nr < NR_SOFTIRQS);
    ASSERT(!softirq_handlers[nr].vcpu || softirq_handlers[nr].vcpu == handler);
    softirq_handlers[nr].vcpu = handler;
}

void cpumask_raise_softirq(const cpumask_t *mask, unsigned int nr)
{
    int cpu;
    cpumask_t send_mask;

    cpumask_clear(&send_mask);
    for_each_cpu(cpu, mask)
        if ( !test_and_set_bit(nr, &softirq_pending(cpu)) )
            cpumask_set_cpu(cpu, &send_mask);

    smp_send_event_check_mask(&send_mask);
}

void cpu_raise_softirq(unsigned int cpu, unsigned int nr)
{
    if ( !test_and_set_bit(nr, &softirq_pending(cpu))
         && (cpu != smp_processor_id())
         && (!is_idle_vcpu(current))
        )
        smp_send_event_check_cpu(cpu);
}

void raise_softirq(unsigned int nr)
{
    ASSERT(softirq_handlers[nr].cpu != NULL);
    switch (nr) {
    case TIMER_CPU0_SOFTIRQ:
        if (smp_processor_id())
            WARN_ONCE();
    case RCU_CPU_SOFTIRQ:
    case TASKLET_SCHEDULE_CPU_SOFTIRQ:
    case P2M_L1_CACHE_CPU_SOFTIRQ:
        set_bit(nr, &softirq_pending(smp_processor_id()));
        break;
    default:
        WARN_ONCE();
        set_bit(nr, &softirq_pending(0 /* smp_processor_id() */));
        smp_send_event_check_cpu(0 /* smp_processor_id() */);
    }
}

void __init softirq_init(void)
{
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
