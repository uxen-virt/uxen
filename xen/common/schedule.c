/****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 University of Cambridge
 * (C) 2004      - Mark Williamson - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: common/schedule.c
 *      Author: Rolf Neugebauer & Keir Fraser
 *              Updated for generic API by Mark Williamson
 * 
 * Description: Generic CPU scheduling code
 *              implements support functionality for the Xen scheduler API.
 *
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
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

#ifndef COMPAT
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <xen/trace.h>
#include <xen/mm.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/multicall.h>
#include <xen/cpu.h>
#include <xen/preempt.h>
#include <public/sched.h>
#include <xsm/xsm.h>

#define opt_sched "host"

static void vcpu_throttle_timer_fn(void *data);

/* This is global for now so that private implementations can reach it */
DEFINE_PER_CPU(struct schedule_data, schedule_data);
DEFINE_PER_CPU(struct scheduler *, scheduler);

static const struct scheduler *schedulers[] = {
    &sched_host_def,
};

static struct scheduler __read_mostly ops;

#define SCHED_OP(opsptr, fn, ...)                                          \
         (( (opsptr)->fn != NULL ) ? (opsptr)->fn(opsptr, ##__VA_ARGS__ )  \
          : (typeof((opsptr)->fn(opsptr, ##__VA_ARGS__)))0 )

#define DOM2OP(_d)    (((_d)->cpupool == NULL) ? &ops : ((_d)->cpupool->sched))
#define VCPU2OP(_v)   (DOM2OP((_v)->domain))

static inline void trace_runstate_change(struct vcpu *v, int new_state)
{
    struct { uint32_t vcpu:16, domain:16; } d;
    uint32_t event;

    if ( likely(!tb_init_done) )
        return;

    d.vcpu = v->vcpu_id;
    d.domain = v->domain->domain_id;

    event = TRC_SCHED_RUNSTATE_CHANGE;
    event |= ( v->runstate.state & 0x3 ) << 8;
    event |= ( new_state & 0x3 ) << 4;

    __trace_var(event, 1/*tsc*/, sizeof(d), &d);
}

static inline void vcpu_urgent_count_update(struct vcpu *v)
{
    if ( is_idle_vcpu(v) )
        return;

    if ( unlikely(v->is_urgent) )
    {
        if ( !test_bit(_VPF_blocked, &v->pause_flags) ||
             !test_bit(v->vcpu_id, v->domain->poll_mask) )
        {
            v->is_urgent = 0;
            atomic_dec(&per_cpu(schedule_data,v->processor).urgent_count);
        }
    }
    else
    {
        if ( unlikely(test_bit(_VPF_blocked, &v->pause_flags) &&
                      test_bit(v->vcpu_id, v->domain->poll_mask)) )
        {
            v->is_urgent = 1;
            atomic_inc(&per_cpu(schedule_data,v->processor).urgent_count);
        }
    }
}

static inline void vcpu_runstate_change(
    struct vcpu *v, int new_state, s_time_t new_entry_time)
{
    s_time_t delta;

    ASSERT(v->runstate.state != new_state);
    ASSERT(spin_is_locked(per_cpu(schedule_data,v->processor).schedule_lock));

    vcpu_urgent_count_update(v);

    trace_runstate_change(v, new_state);

    delta = new_entry_time - v->runstate.state_entry_time;
    if ( delta > 0 )
    {
        v->runstate.time[v->runstate.state] += delta;
        v->runstate.state_entry_time = new_entry_time;
    }

    v->runstate.state = new_state;
}

void vcpu_runstate_get(struct vcpu *v, struct vcpu_runstate_info *runstate)
{
    s_time_t delta;

    if ( unlikely(v != current) )
        vcpu_schedule_lock_irq(v);

    memcpy(runstate, &v->runstate, sizeof(*runstate));
    delta = NOW() - runstate->state_entry_time;
    if ( delta > 0 )
        runstate->time[runstate->state] += delta;

    if ( unlikely(v != current) )
        vcpu_schedule_unlock_irq(v);
}

int sched_init_vcpu(struct vcpu *v, unsigned int processor) 
{
    struct domain *d = v->domain;

    /*
     * Initialize processor and affinity settings. The idler, and potentially
     * domain-0 VCPUs, are pinned onto their respective physical CPUs.
     */
    v->processor = processor;
    if ( is_idle_domain(d)
         )
        cpumask_copy(v->cpu_affinity, cpumask_of(processor));
    else
        cpumask_setall(v->cpu_affinity);

    init_vcpu_timer(&v->vcpu_throttle_timer, vcpu_throttle_timer_fn, v, v);

    /* Idle VCPUs are scheduled immediately. */
    if ( is_idle_domain(d) )
    {
        per_cpu(schedule_data, v->processor).curr = v;
        v->is_running = 1;
    }

    TRACE_2D(TRC_SCHED_DOM_ADD, v->domain->domain_id, v->vcpu_id);

    SCHED_OP(VCPU2OP(v), insert_vcpu, v);

    return 0;
}

void sched_destroy_vcpu(struct vcpu *v)
{
    kill_timer(&v->vcpu_throttle_timer);
    if ( test_and_clear_bool(v->is_urgent) )
        atomic_dec(&per_cpu(schedule_data, v->processor).urgent_count);
    SCHED_OP(VCPU2OP(v), remove_vcpu, v);
}

int sched_init_domain(struct domain *d)
{
    return 0;
}

void sched_destroy_domain(struct domain *d)
{
    printk("%s: vm%u\n", __FUNCTION__, d->domain_id);
    SCHED_OP(DOM2OP(d), destroy_domain, d);
}

void vcpu_sleep_nosync(struct vcpu *v)
{
    unsigned long flags;

    vcpu_schedule_lock_irqsave(v, flags);

    if ( likely(!vcpu_runnable(v)) )
    {
        if ( v->runstate.state == RUNSTATE_runnable )
            vcpu_runstate_change(v, RUNSTATE_offline, NOW());

        SCHED_OP(VCPU2OP(v), sleep, v);
    }

    vcpu_schedule_unlock_irqrestore(v, flags);

    TRACE_2D(TRC_SCHED_SLEEP, v->domain->domain_id, v->vcpu_id);
}

void vcpu_sleep_sync(struct vcpu *v)
{
    vcpu_sleep_nosync(v);

    while ( !vcpu_runnable(v) && v->is_running )
        cpu_relax();

    sync_vcpu_execstate(v);
}

void vcpu_wake(struct vcpu *v)
{
    unsigned long flags;

    vcpu_schedule_lock_irqsave(v, flags);

    if ( likely(vcpu_runnable(v)) )
    {
        if ( v->runstate.state >= RUNSTATE_blocked )
            vcpu_runstate_change(v, RUNSTATE_runnable, NOW());
        SCHED_OP(VCPU2OP(v), wake, v);
    }
    else if ( !test_bit(_VPF_blocked, &v->pause_flags) )
    {
        if ( v->runstate.state == RUNSTATE_blocked )
            vcpu_runstate_change(v, RUNSTATE_offline, NOW());
    }

    vcpu_schedule_unlock_irqrestore(v, flags);

    TRACE_2D(TRC_SCHED_WAKE, v->domain->domain_id, v->vcpu_id);
}

void vcpu_unblock(struct vcpu *v)
{
    if ( !test_and_clear_bit(_VPF_blocked, &v->pause_flags) )
        return;

    /* Polling period ends when a VCPU is unblocked. */
    if ( unlikely(v->poll_evtchn != 0) )
    {
        v->poll_evtchn = 0;
        /*
         * We *must* re-clear _VPF_blocked to avoid racing other wakeups of
         * this VCPU (and it then going back to sleep on poll_mask).
         * Test-and-clear is idiomatic and ensures clear_bit not reordered.
         */
        if ( test_and_clear_bit(v->vcpu_id, v->domain->poll_mask) )
            clear_bit(_VPF_blocked, &v->pause_flags);
    }

    vcpu_wake(v);
}

void vcpu_switch_host_cpu(struct vcpu *v)
{
    int new_cpu = smp_processor_id(), old_cpu = v->processor;

    if (new_cpu != old_cpu) {
        unsigned long flags;

        pcpu_schedule_lock_irqsave(old_cpu, flags);

        v->processor = new_cpu;

        per_cpu(curr_vcpu, new_cpu) = v;

        pcpu_schedule_unlock_irqrestore(old_cpu, flags);
    }
}

/* Block the currently-executing domain until a pertinent event occurs. */
static long do_block(void)
{
    struct vcpu *v = current;

    local_event_delivery_enable();
    set_bit(_VPF_blocked, &v->pause_flags);

    /* Check for events /after/ blocking: avoids wakeup waiting race. */
    if ( local_events_need_delivery() )
    {
        clear_bit(_VPF_blocked, &v->pause_flags);
    }
    else
    {
        TRACE_2D(TRC_SCHED_BLOCK, v->domain->domain_id, v->vcpu_id);
        vcpu_raise_softirq(v, SCHEDULE_VCPU_SOFTIRQ);
    }

    return 0;
}

/* Voluntarily yield the processor for this allocation. */
static long do_yield(void)
{
    struct vcpu * v=current;

    vcpu_schedule_lock_irq(v);
    SCHED_OP(VCPU2OP(v), yield, v);
    vcpu_schedule_unlock_irq(v);

    TRACE_2D(TRC_SCHED_YIELD, current->domain->domain_id, current->vcpu_id);
    vcpu_raise_softirq(v, SCHEDULE_VCPU_SOFTIRQ);
    return 0;
}

typedef long ret_t;

#endif /* !COMPAT */

ret_t do_sched_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    ret_t ret = 0;

    switch ( cmd )
    {
    case SCHEDOP_yield:
    {
        ret = do_yield();
        break;
    }

    case SCHEDOP_block:
    {
        ret = do_block();
        break;
    }

    case SCHEDOP_shutdown:
    {
        struct sched_shutdown sched_shutdown;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_shutdown, arg, 1) )
            break;

        ret = 0;
        TRACE_3D(TRC_SCHED_SHUTDOWN,
                 current->domain->domain_id, current->vcpu_id,
                 sched_shutdown.reason);
        domain_shutdown(current->domain, (u8)sched_shutdown.reason);

        break;
    }

    case SCHEDOP_shutdown_code:
    {
        struct sched_shutdown sched_shutdown;
        struct domain *d = current->domain;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_shutdown, arg, 1) )
            break;

        TRACE_3D(TRC_SCHED_SHUTDOWN_CODE,
                 d->domain_id, current->vcpu_id, sched_shutdown.reason);

        spin_lock(&d->shutdown_lock);
        if ( d->shutdown_code == -1 )
            d->shutdown_code = (u8)sched_shutdown.reason;
        spin_unlock(&d->shutdown_lock);

        ret = 0;
        break;
    }

    case SCHEDOP_remote_shutdown:
    {
        struct domain *d;
        struct sched_remote_shutdown sched_remote_shutdown;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_remote_shutdown, arg, 1) )
            break;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(sched_remote_shutdown.domain_id);
        if ( d == NULL )
            break;

        if ( !IS_PRIV_FOR(current->domain, d) )
        {
            rcu_unlock_domain(d);
            return -EPERM;
        }

        printk("vm%u SCHEDOP_remote_shutdown reason %d\n",
               d->domain_id, (u8)sched_remote_shutdown.reason);
        domain_shutdown(d, (u8)sched_remote_shutdown.reason);

        rcu_unlock_domain(d);
        ret = 0;

        break;
    }

    default:
        ret = -ENOSYS;
    }

    return ret;
}

#ifndef COMPAT

static
void schedule_from_vcpu(struct vcpu *prev)
{
    s_time_t              now = NOW();
    struct schedule_data *sd;

    perfc_incr(sched_run);

    if (vcpu_runnable(prev))
        return;

    sd = &per_cpu(schedule_data, prev->processor);

    spin_lock_irq(sd->schedule_lock);

    if (prev->runstate.state == RUNSTATE_running) {
        vcpu_runstate_change(prev,
                             (test_bit(_VPF_blocked, &prev->pause_flags) ?
                              RUNSTATE_blocked :
                              (vcpu_runnable(prev) ? RUNSTATE_runnable :
                               RUNSTATE_offline)),
                             now);
        prev->last_run_time = now;
    }

    spin_unlock_irq(sd->schedule_lock);
}

int
schedule_vcpu(struct vcpu *next)
{
    s_time_t              now = NOW();
    struct schedule_data *sd;

    sd = &this_cpu(schedule_data);

    vcpu_switch_host_cpu(next);

    spin_lock_irq(sd->schedule_lock);

    if (!vcpu_runnable(next)) {
        /* NOTE: return with scheduler lock held in failure case */
        /* spin_unlock_irq(sd->schedule_lock); */
        return 0;
    }

    if (next->runstate.state != RUNSTATE_running)
        vcpu_runstate_change(next, RUNSTATE_running, now);

    next->is_running = 1;

    spin_unlock_irq(sd->schedule_lock);

    perfc_incr(sched_ctx);

    /* Ensure that the domain has an up-to-date time base. */
    update_vcpu_system_time(next);
    // vcpu_periodic_timer_work(next);

    return 1;
}

/* vcpu throttle callback. */
static void vcpu_throttle_timer_fn(void *data)
{
}

static int cpu_schedule_up(unsigned int cpu)
{
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);

    per_cpu(scheduler, cpu) = &ops;
    spin_lock_init(&sd->_lock);
    sd->schedule_lock = &sd->_lock;
    sd->curr = idle_vcpu[cpu];
    atomic_set(&sd->urgent_count, 0);

    /* Boot CPU is dealt with later in schedule_init(). */
    if ( cpu == 0 )
        return 0;

    if ( idle_vcpu[cpu] == NULL )
        alloc_vcpu(idle_vcpu[0]->domain, cpu, cpu);
    if ( idle_vcpu[cpu] == NULL )
        return -ENOMEM;

    ASSERT(!ops.alloc_pdata);

    return 0;
}

static int cpu_schedule_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = cpu_schedule_up(cpu);
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        break;
    default:
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_schedule_nfb = {
    .notifier_call = cpu_schedule_callback
};

/* Initialise the data structures. */
void __init scheduler_init(void)
{
    struct domain *idle_domain;
    int i;

    open_softirq_vcpu(SCHEDULE_VCPU_SOFTIRQ, schedule_from_vcpu);

    for ( i = 0; i < ARRAY_SIZE(schedulers); i++ )
    {
        if ( schedulers[i]->global_init && schedulers[i]->global_init() < 0 )
            schedulers[i] = NULL;
        else if ( !ops.name && !strcmp(schedulers[i]->opt_name, opt_sched) )
            ops = *schedulers[i];
    }

    if ( !ops.name )
    {
        printk("Could not find scheduler: %s\n", opt_sched);
        for ( i = 0; i < ARRAY_SIZE(schedulers); i++ )
            if ( schedulers[i] )
            {
                ops = *schedulers[i];
                break;
            }
        BUG_ON(!ops.name);
        printk("Using '%s' (%s)\n", ops.name, ops.opt_name);
    }

    if ( cpu_schedule_up(0) )
        BUG();
    register_cpu_notifier(&cpu_schedule_nfb);

    printk("Using scheduler: %s (%s)\n", ops.name, ops.opt_name);

    idle_domain = domain_create_internal(DOMID_IDLE, 0, 0, NULL);
    BUG_ON(idle_domain == NULL);
    idle_domain->vcpu = idle_vcpu;
    idle_domain->max_vcpus = nr_cpu_ids;
    if ( alloc_vcpu(idle_domain, 0, 0) == NULL )
        BUG();
    if ( ops.alloc_pdata &&
         !(this_cpu(schedule_data).sched_priv = ops.alloc_pdata(&ops, 0)) )
        BUG();
}

#endif /* !COMPAT */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
