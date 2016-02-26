/******************************************************************************
 * tasklet.c
 * 
 * Tasklets are dynamically-allocatable tasks run in either VCPU context
 * (specifically, the idle VCPU's context) or in softirq context, on at most
 * one CPU at a time. Softirq versus VCPU context execution is specified
 * during per-tasklet initialisation.
 * 
 * Copyright (c) 2010, Citrix Systems, Inc.
 * Copyright (c) 1992, Linus Torvalds
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
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
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/cpu.h>

/* Some subsystems call into us before we are initialised. We ignore them. */
static bool_t tasklets_initialised;

DEFINE_PER_CPU(unsigned long, tasklet_work_to_do);

static DEFINE_PER_CPU(struct list_head, tasklet_list);
#ifndef __UXEN__
static DEFINE_PER_CPU(struct list_head, softirq_tasklet_list);
#endif  /* __UXEN__ */

/* Protects all lists and tasklet structures. */
static DEFINE_SPINLOCK(tasklet_lock);

static void tasklet_enqueue(struct tasklet *t)
{
    unsigned int cpu = t->scheduled_on;

    ASSERT(!t->is_vcpu_idle);
#ifndef __UXEN__
    if ( t->is_softirq )
    {
        struct list_head *list = &per_cpu(softirq_tasklet_list, cpu);
        bool_t was_empty = list_empty(list);
        list_add_tail(&t->list, list);
        if ( was_empty )
            cpu_raise_softirq(cpu, TASKLET_SOFTIRQ);
    }
    else
#endif  /* __UXEN__ */
    {
        unsigned long *work_to_do = &per_cpu(tasklet_work_to_do, cpu);
        list_add_tail(&t->list, &per_cpu(tasklet_list, cpu));
        if ( !test_and_set_bit(_TASKLET_enqueued, work_to_do) )
            cpu_raise_softirq(cpu, TASKLET_SCHEDULE_CPU_SOFTIRQ);
    }
}

void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu)
{
    unsigned long flags;

#ifdef __UXEN__
    if (cpu)
        DEBUG();           /* tasklet only ever on cpu0 */
#endif  /* __UXEN__ */

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( tasklets_initialised && !t->is_dead )
    {
        t->scheduled_on = cpu;
        if ( !t->is_running )
        {
            list_del(&t->list);
            tasklet_enqueue(t);
        }
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void tasklet_schedule(struct tasklet *t)
{
    tasklet_schedule_on_cpu(t,
#ifndef __UXEN__
                            smp_processor_id()
#else  /* __UXEN__ */
                            0
#endif  /* __UXEN__ */
        );
}

void
tasklet_schedule_vcpu_idle(struct tasklet *t, struct domain *d)
{
    struct list_head *list = &d->vcpu_idle_tasklet_list;
    unsigned long flags;

    ASSERT(t->is_vcpu_idle);

    spin_lock_irqsave(&d->vcpu_idle_tasklet_lock, flags);
    if (!t->is_running && list_empty(&t->list))
        list_add_tail(&t->list, list);
    spin_unlock_irqrestore(&d->vcpu_idle_tasklet_lock, flags);
}

static void do_tasklet_work(unsigned int cpu, struct list_head *list)
{
    struct tasklet *t;

    if ( unlikely(list_empty(list) || cpu_is_offline(cpu)) )
        return;

    t = list_entry(list->next, struct tasklet, list);
    list_del_init(&t->list);

    BUG_ON(t->is_dead || t->is_running || (t->scheduled_on != cpu));
    t->scheduled_on = -1;
    t->is_running = 1;

    spin_unlock_irq(&tasklet_lock);
#ifndef __UXEN__
    sync_local_execstate();
#endif  /* __UXEN__ */
    t->func(t->data);
    spin_lock_irq(&tasklet_lock);

    t->is_running = 0;

    if ( t->scheduled_on >= 0 )
    {
        BUG_ON(t->is_dead || !list_empty(&t->list));
        tasklet_enqueue(t);
    }
}

/* VCPU context work */
void do_tasklet(void)
{
    unsigned int cpu = smp_processor_id();
    unsigned long *work_to_do = &per_cpu(tasklet_work_to_do, cpu);
    struct list_head *list = &per_cpu(tasklet_list, cpu);

    /*
     * Work must be enqueued *and* scheduled. Otherwise there is no work to
     * do, and/or scheduler needs to run to update idle vcpu priority.
     */
    if ( likely(*work_to_do != (TASKLET_enqueued|TASKLET_scheduled)) )
        return;

    spin_lock_irq(&tasklet_lock);

    do_tasklet_work(cpu, list);

    if ( list_empty(list) )
        clear_bit(_TASKLET_enqueued, work_to_do);        

    raise_softirq(TASKLET_SCHEDULE_CPU_SOFTIRQ);

    spin_unlock_irq(&tasklet_lock);
}

#ifndef __UXEN__
/* Softirq context work */
static void tasklet_softirq_action(void)
{
    unsigned int cpu = smp_processor_id();
    struct list_head *list = &per_cpu(softirq_tasklet_list, cpu);

    spin_lock_irq(&tasklet_lock);

    do_tasklet_work(cpu, list);

    if ( !list_empty(list) && !cpu_is_offline(cpu) )
        raise_softirq(TASKLET_SOFTIRQ);

    spin_unlock_irq(&tasklet_lock);
}
#endif  /* __UXEN__ */

/* vcpu idle work */
int
vcpu_idle_tasklet_work(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct list_head *list = &d->vcpu_idle_tasklet_list;
    struct tasklet *t;
    unsigned long flags;
    int ret = 0;
    int n = 0;

    if (list_empty(list)) {
        printk(XENLOG_DEBUG "%s vm%d.%d on cpu%d idle\n", __FUNCTION__,
               d->domain_id, v->vcpu_id, smp_processor_id());
        return ret;
    }
    printk(XENLOG_DEBUG "%s vm%d.%d on cpu%d\n", __FUNCTION__, d->domain_id,
           v->vcpu_id, smp_processor_id());

    spin_lock_irqsave(&d->vcpu_idle_tasklet_lock, flags);

    while (likely(!ret) && likely(!list_empty(list))) {
        t = list_entry(list->next, struct tasklet, list);
        list_del_init(&t->list);

        ASSERT(!t->is_running);
        t->is_running = 1;

        spin_unlock_irqrestore(&d->vcpu_idle_tasklet_lock, flags);

        do {
            if (UI_HOST_CALL(ui_host_needs_preempt)) {
                ret = -EPREEMPT;
                break;
            }
            if (work_pending_vcpu(v) ||
                current->runstate.state < RUNSTATE_blocked)
                break;
            ret = t->vcpu_idle_func(v, t->data);
            n++;
        } while (ret == -EAGAIN);

        spin_lock_irqsave(&d->vcpu_idle_tasklet_lock, flags);

        ASSERT(t->is_running);
        t->is_running = 0;

        if (ret == -EAGAIN)
            list_add(&t->list, list);
        else {
            printk(XENLOG_DEBUG "%s: work done from vm%d.%d list %s\n",
                   __FUNCTION__, d->domain_id, v->vcpu_id,
                   list_empty(list) ? "empty" : "more");
            ASSERT(ret == 0 || ret == -EPREEMPT);
        }
    }

    spin_unlock_irqrestore(&d->vcpu_idle_tasklet_lock, flags);

    printk(XENLOG_INFO "%s vm%d.%d on cpu%d done %d ops\n", __FUNCTION__,
           d->domain_id, v->vcpu_id, smp_processor_id(), n);
    return ret;
}

void tasklet_kill(struct tasklet *t)
{
    unsigned long flags;

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( !list_empty(&t->list) )
    {
        BUG_ON(t->is_dead || t->is_running || (t->scheduled_on < 0));
        list_del_init(&t->list);
    }

    t->scheduled_on = -1;
    t->is_dead = 1;

    while ( t->is_running )
    {
        spin_unlock_irqrestore(&tasklet_lock, flags);
        cpu_relax();
        spin_lock_irqsave(&tasklet_lock, flags);
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

static void migrate_tasklets_from_cpu(unsigned int cpu, struct list_head *list)
{
    unsigned long flags;
    struct tasklet *t;

    spin_lock_irqsave(&tasklet_lock, flags);

    while ( !list_empty(list) )
    {
        t = list_entry(list->next, struct tasklet, list);
        BUG_ON(t->scheduled_on != cpu);
        t->scheduled_on = smp_processor_id();
        list_del(&t->list);
        tasklet_enqueue(t);
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    memset(t, 0, sizeof(*t));
    INIT_LIST_HEAD(&t->list);
    t->scheduled_on = -1;
    t->func = func;
    t->data = data;
}

#ifndef __UXEN__
void softirq_tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    tasklet_init(t, func, data);
    t->is_softirq = 1;
}
#endif  /* __UXEN__ */

void
vcpu_idle_tasklet_init(struct tasklet *t,
                       int (*vcpu_idle_func)(struct vcpu *, unsigned long),
                       unsigned long data)
{
    tasklet_init(t, (void (*)(unsigned long))vcpu_idle_func, data);
    t->is_vcpu_idle = 1;
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        INIT_LIST_HEAD(&per_cpu(tasklet_list, cpu));
#ifndef __UXEN__
        INIT_LIST_HEAD(&per_cpu(softirq_tasklet_list, cpu));
#endif  /* __UXEN__ */
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        migrate_tasklets_from_cpu(cpu, &per_cpu(tasklet_list, cpu));
#ifndef __UXEN__
        migrate_tasklets_from_cpu(cpu, &per_cpu(softirq_tasklet_list, cpu));
#endif  /* __UXEN__ */
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback,
    .priority = 99
};

static void
tasklet_schedule_action(void)
{
    unsigned long *tasklet_work = &this_cpu(tasklet_work_to_do);
    bool_t tasklet_work_scheduled = 0;

    /* Update tasklet scheduling status. */
    switch ( *tasklet_work ) {
    case TASKLET_enqueued:
        set_bit(_TASKLET_scheduled, tasklet_work);
    case TASKLET_enqueued|TASKLET_scheduled:
        tasklet_work_scheduled = 1;
        break;
    case TASKLET_scheduled:
        clear_bit(_TASKLET_scheduled, tasklet_work);
    case 0:
        /*tasklet_work_scheduled = 0;*/
        break;
    default:
        BUG();
    }

    if (tasklet_work_scheduled)
        do_tasklet();
}

void __init tasklet_subsys_init(void)
{
    void *hcpu = (void *)(long)smp_processor_id();
    cpu_callback(&cpu_nfb, CPU_UP_PREPARE, hcpu);
    register_cpu_notifier(&cpu_nfb);
#ifndef __UXEN__
    open_softirq(TASKLET_SOFTIRQ, tasklet_softirq_action);
#else  /* __UXEN__ */
    open_softirq(TASKLET_SCHEDULE_CPU_SOFTIRQ, tasklet_schedule_action);
#endif  /* __UXEN__ */
    tasklets_initialised = 1;
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
