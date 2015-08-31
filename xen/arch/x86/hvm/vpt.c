/*
 * vpt.c: Virtual Platform Timer
 *
 * Copyright (c) 2006, Xiaowei Yang, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2015, Bromium, Inc.
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

#include <xen/time.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/event.h>
#include <asm/apic.h>

//#define DEBUG_VPT

/* give up on tick reinjection after this amount of
 * missed tick period is accumulated */
#define MAX_MISSED_TICKS_PERIOD_MS 500
/* max ticks to inject at one time */
#define MAX_INJECT_TICKS 50

#define timer_mode_is(d, subparam, m) \
    (((d)->arch.hvm_domain.params[HVM_PARAM_TIMER_MODE] & \
     HVMPTF_##subparam##_MASK) == \
     HVMPTF_##subparam##_##m )

void hvm_init_guest_time(struct domain *d)
{
    struct pl_time *pl = &d->arch.hvm_domain.pl_time;

    spin_lock_init(&pl->pl_time_lock);
    pl->stime_offset = -(u64)get_s_time();
    pl->last_guest_time = 0;
}

u64 hvm_get_guest_time(struct vcpu *v)
{
    struct pl_time *pl = &v->domain->arch.hvm_domain.pl_time;
    u64 now;

    /* Called from device models shared with PV guests. Be careful. */
    ASSERT(is_hvm_vcpu(v));

    spin_lock(&pl->pl_time_lock);
    now = get_s_time() + pl->stime_offset;
    if ( (int64_t)(now - pl->last_guest_time) > 0 )
        pl->last_guest_time = now;
    else
        now = ++pl->last_guest_time;
    spin_unlock(&pl->pl_time_lock);

    return now + v->arch.hvm_vcpu.stime_offset;
}

void hvm_set_guest_time(struct vcpu *v, u64 guest_time)
{
    v->arch.hvm_vcpu.stime_offset += guest_time - hvm_get_guest_time(v);
}

static int pt_irq_vector(struct periodic_time *pt, enum hvm_intsrc src)
{
    struct vcpu *v = pt->vcpu;
    unsigned int gsi, isa_irq;

    if ( pt->source == PTSRC_lapic )
        return pt->irq;

    isa_irq = pt->irq;
    gsi = hvm_isa_irq_to_gsi(isa_irq);

    if ( src == hvm_intsrc_pic )
        return (v->domain->arch.hvm_domain.vpic[isa_irq >> 3].irq_base
                + (isa_irq & 7));

    ASSERT(src == hvm_intsrc_lapic);
    return domain_vioapic(v->domain)->redirtbl[gsi].fields.vector;
}

static int pt_irq_masked(struct periodic_time *pt)
{
    struct vcpu *v = pt->vcpu;
    unsigned int gsi, isa_irq;
    uint8_t pic_imr;

    if ( pt->source == PTSRC_lapic )
    {
        struct vlapic *vlapic = vcpu_vlapic(v);
        return (!vlapic_enabled(vlapic) ||
                (vlapic_get_reg(vlapic, APIC_LVTT) & APIC_LVT_MASKED));
    }

    isa_irq = pt->irq;
    gsi = hvm_isa_irq_to_gsi(isa_irq);
    pic_imr = v->domain->arch.hvm_domain.vpic[isa_irq >> 3].imr;

    return (((pic_imr & (1 << (isa_irq & 7))) || !vlapic_accept_pic_intr(v)) &&
            domain_vioapic(v->domain)->redirtbl[gsi].fields.mask);
}

static void pt_lock(struct periodic_time *pt)
{
    struct vcpu *v;

    for ( ; ; )
    {
        v = pt->vcpu;
        spin_lock(&v->arch.hvm_vcpu.tm_lock);
        if ( likely(pt->vcpu == v) )
            break;
        spin_unlock(&v->arch.hvm_vcpu.tm_lock);
    }
}

static void pt_unlock(struct periodic_time *pt)
{
    spin_unlock(&pt->vcpu->arch.hvm_vcpu.tm_lock);
}

static u64 calculate_pending_ticks(struct periodic_time *pt, s_time_t now)
{
    u64 time_passed;
    s_time_t time_done = pt->time_done;

    if ( pt->one_shot || now < pt->scheduled_t0 )
        return 0;

    time_passed = now - pt->scheduled_t0 + pt->period;
    if ( time_passed <= time_done )
        return 0;

    return (time_passed - time_done) / pt->period;
}

static u64 calculate_intr_inject(struct periodic_time *pt, int pending_ticks)
{
    u64 max;
    u64 inject = pending_ticks;

    if ( timer_mode_is(pt->vcpu->domain, DESCHED_MTICKS, single) )
        max = 1;
    else if ( pt->schedule_period > pt->period )
        /* scale maximum injected ticks if we're coalescing */
        max = MAX_INJECT_TICKS * pt->schedule_period / pt->period;
    else
        max = MAX_INJECT_TICKS;

    if ( inject > max )
        inject = max;

    return inject;
}

static void pt_process_missed_ticks(struct periodic_time *pt)
{
    s64 pending;
    s_time_t now = NOW();
    struct vcpu *v = pt->vcpu;

    if ( pt->one_shot )
        return;

    if ( pt->scheduled >= now )
        return;

    pending = calculate_pending_ticks(pt, now);

    if ( pending*pt->period >
         MAX_MISSED_TICKS_PERIOD_MS*1000000ULL ) {
        /* missed too much, give up and set exception in the guest */
        printk("vpt: (vm%u.%u): dropping %"PRIu64" pending ticks\n",
               v->domain->domain_id, v->vcpu_id, pending);

        pt->pending_intr_nr++;
        pt->time_done += pending * pt->period; /* reset pending ticks */
        hostsched_notify_exception(v->domain);
    } else {
        u64 inject = calculate_intr_inject(pt, pending);
        pt->pending_intr_nr += inject;
        /* reset ticks in non-replay mode, accumulate otherwise */
        pt->time_done += pt->period * (
            timer_mode_is(pt->vcpu->domain, DESCHED_MTICKS, replay)
            ? inject : pending);
    }

    /* set pt->scheduled to first schedule_period aligned time later than now */
    if ( pt->scheduled <= now ) {
        u64 p = pt->schedule_period;
        pt->scheduled += (1 + (now-pt->scheduled)/p) * p;
    }

#ifdef DEBUG_VPT
    if (pending >= 10)
        printk("vpt: (vm%u.%u): pending %ld (%ldms) total time done %ldms "
               "total ticks done %ld pending intrs %d\n",
               v->domain->domain_id, v->vcpu_id,
               pending, pending*pt->period/1000000, pt->time_done/1000000,
               pt->time_done / pt->period, pt->pending_intr_nr);
#endif
}

static void pt_freeze_time(struct vcpu *v)
{
    if ( !timer_mode_is(v->domain, DESCHED_TIMER, stop) )
        return;

    v->arch.hvm_vcpu.guest_time = hvm_get_guest_time(v);
}

static void pt_thaw_time(struct vcpu *v)
{
    if ( !timer_mode_is(v->domain, DESCHED_GTIME, stop) )
        return;

    if ( v->arch.hvm_vcpu.guest_time == 0 )
        return;

    hvm_set_guest_time(v, v->arch.hvm_vcpu.guest_time);
    v->arch.hvm_vcpu.guest_time = 0;
}

void pt_save_timer(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    if ( test_bit(_VPF_blocked, &v->pause_flags) )
        return;

    if ( !timer_mode_is(v->domain, DESCHED_TIMER, stop) &&
         !timer_mode_is(v->domain, DESCHED_GTIME, stop) )
        /* short-circuit spinlock */
        return;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
        if ( timer_mode_is(v->domain, DESCHED_TIMER, stop) )
            stop_timer(&pt->timer);

    pt_freeze_time(v);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void pt_restore_timer(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
    {
        if ( pt->pending_intr_nr == 0 )
        {
            pt_process_missed_ticks(pt);
            set_timer(&pt->timer, pt->scheduled);
        }
    }

    pt_thaw_time(v);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

static void pt_timer_fn(void *data)
{
    struct periodic_time *pt = data;

    pt_lock(pt);

    if ( pt->one_shot )
        ++pt->pending_intr_nr;
    else {
        pt_process_missed_ticks(pt);
        if ( pt->pending_intr_nr == 0 )
            set_timer(&pt->timer, pt->scheduled);
    }
    vcpu_kick(pt->vcpu);

    pt_unlock(pt);
}

void pt_update_irq(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt, *temp, *earliest_pt = NULL;
    uint64_t max_lag = -1ULL;
    int irq, is_lapic;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry_safe ( pt, temp, head, list )
    {
        if ( pt->pending_intr_nr )
        {
            if ( pt_irq_masked(pt) )
            {
                /* suspend timer emulation */
                list_del(&pt->list);
                pt->on_list = 0;
            }
            else
            {
                if ( (pt->last_plt_gtime + pt->schedule_period) < max_lag )
                {
                    max_lag = pt->last_plt_gtime + pt->schedule_period;
                    earliest_pt = pt;
                }
            }
        }
    }

    if ( earliest_pt == NULL )
    {
        spin_unlock(&v->arch.hvm_vcpu.tm_lock);
        return;
    }

    earliest_pt->irq_issued = 1;
    irq = earliest_pt->irq;
    is_lapic = (earliest_pt->source == PTSRC_lapic);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);

    if ( is_lapic )
    {
        vlapic_set_irq(vcpu_vlapic(v), irq, 0);
    }
    else
    {
        hvm_isa_irq_deassert(v->domain, irq);
        hvm_isa_irq_assert(v->domain, irq);
    }

}

static void pt_collapse_ticks(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    if ( list_empty(&v->arch.hvm_vcpu.tm_list) )
        return;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
        pt->collapse_ticks = 1;

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void pt_unpause(struct vcpu *v)
{
    /* possibly collapse all ticks missed during pause into one */
    if ( timer_mode_is(v->domain, UNPAUSE_MTICKS, single) )
        pt_collapse_ticks(v);
}

static struct periodic_time *is_pt_irq(
    struct vcpu *v, struct hvm_intack intack)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    list_for_each_entry ( pt, head, list )
    {
        if ( pt->pending_intr_nr && pt->irq_issued &&
             (intack.vector == pt_irq_vector(pt, intack.source)) )
            return pt;
    }

    return NULL;
}

void pt_intr_post(struct vcpu *v, struct hvm_intack intack)
{
    struct periodic_time *pt;
    time_cb *cb;
    void *cb_priv;

    if ( intack.source == hvm_intsrc_vector )
        return;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    pt = is_pt_irq(v, intack);
    if ( pt == NULL )
    {
        spin_unlock(&v->arch.hvm_vcpu.tm_lock);
        return;
    }

    pt->irq_issued = 0;

    if ( pt->one_shot )
    {
        if ( pt->on_list )
            list_del(&pt->list);
        pt->on_list = 0;
        pt->pending_intr_nr = 0;
    }
    else if ( timer_mode_is(v->domain, DESCHED_MTICKS, single) ||
              pt->collapse_ticks )
    {
#ifdef DEBUG_VPT
        if (pt->collapse_ticks)
            printk("vpt: (vm%u.%u): collapsing ticks\n", v->domain->domain_id,
                   v->vcpu_id);
#endif
        pt->last_plt_gtime = hvm_get_guest_time(v);
        pt_process_missed_ticks(pt);
        pt->pending_intr_nr = 0; /* 'collapse' all missed ticks */
        pt->collapse_ticks = 0;

        set_timer(&pt->timer, pt->scheduled);
    }
    else
    {
        pt->last_plt_gtime += pt->period;
        if ( --pt->pending_intr_nr == 0 )
        {
            pt_process_missed_ticks(pt);
            if ( pt->pending_intr_nr == 0 )
                set_timer(&pt->timer, pt->scheduled);
        }
    }

    if ( timer_mode_is(v->domain, DESCHED_GTIME, stop) &&
         (hvm_get_guest_time(v) < pt->last_plt_gtime) )
        hvm_set_guest_time(v, pt->last_plt_gtime);

    cb = pt->cb;
    cb_priv = pt->priv;

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);

    if ( cb != NULL )
        cb(v, cb_priv);
}

void pt_migrate(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
        migrate_timer(&pt->timer, v->processor);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

static void pt_update_schedule_period_one(struct vcpu *v, struct periodic_time *pt)
{
    if ( !pt->one_shot ) {
        u64 coalesce_period =
            v->domain->arch.hvm_domain.params[HVM_PARAM_VPT_COALESCE_NS];

        /* use coalescing period as timer scheduling period, if set so */
        pt->schedule_period =
            ( coalesce_period && (pt->period < coalesce_period) )
            ? coalesce_period : pt->period;

        if ( v->domain->arch.hvm_domain.params[HVM_PARAM_VPT_ALIGN] )
            pt->scheduled = align_timer(pt->scheduled, pt->schedule_period);
    }
}

void pt_update_schedule_period(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
        pt_update_schedule_period_one(v, pt);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void update_periodic_time(struct periodic_time *pt, int irq, uint64_t period,
    int leftover_ticks)
{
    struct vcpu *v = pt->vcpu;

    ASSERT(!pt->one_shot);
    ASSERT(v != NULL);

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    pt_process_missed_ticks(pt);

    /* subtract from time done so that any pending ticks
     * will get reinjected at new period rate */
    pt->time_done -= pt->pending_intr_nr * pt->period;

    /* but keep 'leftover_ticks' amount processed at old
     * period rate */
    pt->time_done += pt->period * leftover_ticks;
    pt->pending_intr_nr = leftover_ticks;
    if (pt->irq != irq) {
        pt->irq = irq;
        pt->irq_issued = 0;
    }

    pt->period = period;
    pt_update_schedule_period_one(pt->vcpu, pt);

    set_timer(&pt->timer, pt->scheduled);

#ifdef DEBUG_VPT
    if (pt->period)
        printk("vpt: (vm%u.%u): update periodic time: period %"PRIu64"us"
               " schedule period %"PRIu64"us\n",
               v->domain->domain_id, v->vcpu_id,
               pt->period / 1000, pt->schedule_period / 1000);
#endif

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void create_periodic_time(
    struct vcpu *v, struct periodic_time *pt, uint64_t delta,
    uint64_t period, uint8_t irq, time_cb *cb, void *data)
{
    ASSERT(pt->source != 0);
    destroy_periodic_time(pt);

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    pt->time_done = 0;
    pt->pending_intr_nr = 0;
    pt->irq_issued = 0;

    /* Periodic timer must be at least 0.1ms. */
    if ( (period < 100000) && period )
    {
        if ( !test_and_set_bool(pt->warned_timeout_too_short) )
            gdprintk(XENLOG_WARNING, "HVM_PlatformTime: program too "
                     "small period %"PRIu64"\n", period);
        period = 100000;
    }

    pt->period = period;
    pt->schedule_period = period;
    pt->vcpu = v;
    pt->last_plt_gtime = hvm_get_guest_time(pt->vcpu);
    pt->irq = irq;
    pt->one_shot = !period;
    pt->scheduled = NOW() + delta;
    pt->collapse_ticks = 0;

    if ( !pt->one_shot )
    {
        pt_update_schedule_period_one(v, pt);

        if ( pt->source == PTSRC_lapic &&
             !v->domain->arch.hvm_domain.params[HVM_PARAM_VPT_ALIGN] )
        {
            /*
             * Offset LAPIC ticks from other timer ticks. Otherwise guests
             * which use LAPIC ticks for process accounting can see long
             * sequences of process ticks incorrectly accounted to interrupt
             * processing (seen with RHEL3 guest).
             */
            pt->scheduled += delta >> 1;
        }
    }

    pt->scheduled_t0 = pt->scheduled;

#ifdef DEBUG_VPT
    if (pt->period)
        printk("vpt: (vm%u.%u): create periodic time: period %"PRIu64"us"
               " schedule period %"PRIu64"us delta %"PRIu64"us\n",
               v->domain->domain_id, v->vcpu_id,
               pt->period / 1000, pt->schedule_period / 1000,
            delta / 1000);
#endif

    pt->cb = cb;
    pt->priv = data;

    pt->on_list = 1;
    list_add(&pt->list, &v->arch.hvm_vcpu.tm_list);

    init_vcpu_timer(&pt->timer, pt_timer_fn, pt, v);
    set_timer(&pt->timer, pt->scheduled);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void destroy_periodic_time(struct periodic_time *pt)
{
    /* Was this structure previously initialised by create_periodic_time()? */
    if ( pt->vcpu == NULL )
        return;

    pt_lock(pt);
    if ( pt->on_list )
        list_del(&pt->list);
    pt->on_list = 0;
    pt->pending_intr_nr = 0;
    pt_unlock(pt);

    /*
     * pt_timer_fn() can run until this kill_timer() returns. We must do this
     * outside pt_lock() otherwise we can deadlock with pt_timer_fn().
     */
    kill_timer(&pt->timer);
}

static void pt_adjust_vcpu(struct periodic_time *pt, struct vcpu *v)
{
    int on_list;

    ASSERT(pt->source == PTSRC_isa);

    if ( pt->vcpu == NULL )
        return;

    pt_lock(pt);
    on_list = pt->on_list;
    if ( pt->on_list )
        list_del(&pt->list);
    pt->on_list = 0;
    pt_unlock(pt);

    spin_lock(&v->arch.hvm_vcpu.tm_lock);
    pt->vcpu = v;
    if ( on_list )
    {
        pt->on_list = 1;
        list_add(&pt->list, &v->arch.hvm_vcpu.tm_list);

        migrate_timer(&pt->timer, v->processor);
    }
    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void pt_adjust_global_vcpu_target(struct vcpu *v)
{
    struct PITState *vpit;
    struct pl_time *pl_time;
    int i;

    if ( v == NULL )
        return;

    vpit = &v->domain->arch.vpit;

    spin_lock(&vpit->lock);
    pt_adjust_vcpu(&vpit->pt0, v);
    spin_unlock(&vpit->lock);

    pl_time = &v->domain->arch.hvm_domain.pl_time;

    spin_lock(&pl_time->vrtc.lock);
    pt_adjust_vcpu(&pl_time->vrtc.pt, v);
    spin_unlock(&pl_time->vrtc.lock);

    spin_lock(&pl_time->vhpet.lock);
    for ( i = 0; i < HPET_TIMER_NUM; i++ )
        pt_adjust_vcpu(&pl_time->vhpet.pt[i], v);
    spin_unlock(&pl_time->vhpet.lock);
}


static void pt_resume(struct periodic_time *pt)
{
    if ( pt->vcpu == NULL )
        return;

    pt_lock(pt);
    if ( pt->pending_intr_nr && !pt->on_list )
    {
        pt->on_list = 1;
        list_add(&pt->list, &pt->vcpu->arch.hvm_vcpu.tm_list);
        vcpu_kick(pt->vcpu);
    }
    pt_unlock(pt);
}

void pt_may_unmask_irq(struct domain *d, struct periodic_time *vlapic_pt)
{
    int i;

    if ( d )
    {
        pt_resume(&d->arch.vpit.pt0);
        pt_resume(&d->arch.hvm_domain.pl_time.vrtc.pt);
        for ( i = 0; i < HPET_TIMER_NUM; i++ )
            pt_resume(&d->arch.hvm_domain.pl_time.vhpet.pt[i]);
    }

    if ( vlapic_pt )
        pt_resume(vlapic_pt);
}
