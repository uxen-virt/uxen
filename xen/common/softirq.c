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
 * Copyright 2011-2015, Bromium, Inc.
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

static softirq_handler softirq_handlers[NR_SOFTIRQS];
static softirq_handler_vcpu softirq_handlers_vcpu[NR_SOFTIRQS];

static void __do_softirq(unsigned long ignore_mask)
{
    unsigned int i, cpu;
    unsigned long pending;

    for ( ; ; )
    {
        /*
         * Initialise @cpu on every iteration: SCHEDULE_SOFTIRQ may move
         * us to another processor.
         */
        cpu = smp_processor_id();

        if ( rcu_pending(cpu) )
            rcu_check_callbacks(cpu);

        if ( ((pending = (softirq_pending(cpu) & ~ignore_mask)) == 0)
             || cpu_is_offline(cpu) )
            break;

        i = find_first_set_bit(pending);
        clear_bit(i, &softirq_pending(cpu));
#ifdef __UXEN__
        /* softirq, other than RCU_SOFTIRQ only ever on cpu0 idle thread */
        if ((cpu || !is_idle_vcpu(current)) && i != RCU_SOFTIRQ)
            WARN_ONCE();
        switch (i) {
        case SCHEDULE_SOFTIRQ:
            break;
        case RCU_SOFTIRQ:
            break;
        case TIMER_SOFTIRQ:
            perfc_incr(do_TIMER_SOFTIRQ);
            break;
        case TIME_CALIBRATE_SOFTIRQ:
            perfc_incr(do_TIME_CALIBRATE_SOFTIRQ);
            break;
        default:
            printk("vm%u.%u softirq %d on cpu %d => %S\n",
                   current->domain->domain_id, current->vcpu_id, i, cpu,
                   (printk_symbol)softirq_handlers[i]);
        }
        ASSERT(softirq_handlers[i]);
#endif  /* __UXEN__ */
        (*softirq_handlers[i])();
    }
}

void process_pending_softirqs(void)
{
    ASSERT(!in_irq() && local_irq_is_enabled());
    /* Do not enter scheduler as it can preempt the calling context. */
    __do_softirq(1ul<<SCHEDULE_SOFTIRQ |
                 (is_idle_vcpu(current) ? 0 : (1ul << TIMER_SOFTIRQ)));
}

void process_pending_rcu_softirq(void)
{
    ASSERT(!in_irq() && local_irq_is_enabled());
    /* Only process rcu softirq. */
    __do_softirq(~(1ul<<RCU_SOFTIRQ));
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

    for ( ; ; )
    {
        if ( (pending = (v->softirq_pending & ~ignore_mask)) == 0)
            break;

        i = find_first_set_bit(pending);
        clear_bit(i, &v->softirq_pending);
        switch (i) {
        case TIMER_SOFTIRQ:
        case SCHEDULE_SOFTIRQ:
#if 0
        case TIME_CALIBRATE_SOFTIRQ:
#endif
        case VCPU_KICK_SOFTIRQ:
        case VCPU_TSC_SOFTIRQ:
            break;
        default:
            printk("softirq %i on vcpu %p => %p\n", i, v,
                   softirq_handlers_vcpu[i]);
        }
        ASSERT(softirq_handlers_vcpu[i]);
        (*softirq_handlers_vcpu[i])(v);
    }
}

static inline void
check_vcpu_timer_interrupt(struct vcpu *v)
{
    struct vm_vcpu_info_shared *vci = v->vm_vcpu_info_shared;
    if (vci && vci->vci_has_timer_interrupt) {
        perfc_incr(vcpu_timer);
        set_bit(TIMER_SOFTIRQ, &v->softirq_pending);
        vci->vci_has_timer_interrupt = 0;
    }
}

/* asmlinkage */ void do_softirq_vcpu(struct vcpu *v)
{
    ASSERT(!in_atomic());

    check_vcpu_timer_interrupt(v);

    /* executes without vmcs loaded, softirqs depending on vmcs
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

    if (uxen_info->ui_host_needs_preempt(v->vm_vcpu_info_shared)) {
        cpu_irq_enable();
        return 1;
    }

    return 0;
}

DECLARE_PER_CPU(uint8_t, timer_had_timeout);

void
do_run_idle_thread(uint32_t had_timeout)
{

    if (had_timeout) {
        this_cpu(timer_had_timeout) = 1;
        set_bit(TIMER_SOFTIRQ, &softirq_pending(0 /* smp_processor_id() */));
        platform_time_sync();
    }

    __do_softirq(0);
}

void open_softirq(int nr, softirq_handler handler)
{
    ASSERT(nr < NR_SOFTIRQS);
    softirq_handlers[nr] = handler;
}

void open_softirq_vcpu(int nr, softirq_handler_vcpu handler)
{
    ASSERT(nr < NR_SOFTIRQS);
    softirq_handlers_vcpu[nr] = handler;
}

void cpumask_raise_softirq(const cpumask_t *mask, unsigned int nr)
{
    int cpu;
    cpumask_t send_mask;

    if (nr != RCU_SOFTIRQ)
        WARN_ONCE();

    cpumask_clear(&send_mask);
    for_each_cpu(cpu, mask)
        if ( !test_and_set_bit(nr, &softirq_pending(cpu)) )
            cpumask_set_cpu(cpu, &send_mask);

    smp_send_event_check_mask(&send_mask);
}

void cpu_raise_softirq(unsigned int cpu, unsigned int nr)
{
    if ( !test_and_set_bit(nr, &softirq_pending(cpu))
#ifndef __UXEN__
         && (cpu != smp_processor_id())
#else  /* __UXEN__ */
         && (!is_idle_vcpu(current))
#endif  /* __UXEN__ */
        )
        smp_send_event_check_cpu(cpu);
}

void raise_softirq(unsigned int nr)
{
    extern softirq_handler softirq_handlers[];
    ASSERT(softirq_handlers[nr] != NULL);
    switch (nr) {
    case RCU_SOFTIRQ:
        set_bit(nr, &softirq_pending(smp_processor_id()));
        break;
    default:
        set_bit(nr, &softirq_pending(0 /* smp_processor_id() */));
        uxen_info->ui_signal_idle_thread();
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
