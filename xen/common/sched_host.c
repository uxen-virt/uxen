/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <asm/atomic.h>
#include <xen/errno.h>

static void
hostsched_vcpu_sleep(const struct scheduler *ops, struct vcpu *v)
{

    vcpu_raise_softirq(v, SCHEDULE_SOFTIRQ);
}

static void
hostsched_vcpu_wake(const struct scheduler *ops, struct vcpu *v)
{
    struct vm_vcpu_info_shared *vci = v->vm_vcpu_info_shared;

    if (vci == NULL)
        return;

    if (vci->vci_host_halted) {
        perfc_incr(hostsched_wake_vm);
        uxen_info->ui_wake_vm(vci);
    }
}

static void
hostsched_vcpu_yield(const struct scheduler *ops, struct vcpu *v) 
{
    set_bit(_VPF_yield, &v->pause_flags);
}

#if 0
static void
hostsched_init(void)
{
}
#endif

int
hostsched_setup_vm(struct domain *d, struct vm_info_shared *vmi)
{
    if (d->vm_info_shared)
        return -EBUSY;

    d->vm_info_shared = vmi;
    return 0;
}

struct vm_vcpu_info_shared *
hostsched_setup_vcpu(struct vcpu *v, struct vm_vcpu_info_shared *vci)
{
    if (v->vm_vcpu_info_shared)
        return v->vm_vcpu_info_shared;

    v->vm_vcpu_info_shared = vci;
    return NULL;
}

static void
hostsched_dom_destroy(const struct scheduler *ops, struct domain *d)
{
    struct vcpu *v;
    int i;

    for (i = d->max_vcpus - 1; i >= 0; i--) {
        if ((v = d->vcpu[i]) == NULL)
            continue;
        v->vm_vcpu_info_shared = NULL;
    }

    d->vm_info_shared = NULL;
}

void
hostsched_vcpu_softirq(struct vcpu *v)
{

    hostsched_vcpu_wake(NULL /* XXX */, v);
    if (smp_processor_id() != v->processor && !atomic_read(&v->event_check)) {
        atomic_set(&v->event_check, 1);
        hostsched_kick_vcpu(v);
    }
}

void
hostsched_set_timer_vcpu(struct vcpu *v, uint64_t expire)
{
    struct vm_vcpu_info_shared *vci = v->vm_vcpu_info_shared;

    ASSERT(v == current);
    if (vci)
        uxen_info->ui_set_timer_vcpu(vci, expire);
    else
        printk("hostsched_set_timer_vcpu %d.%d no vm_info\n",
               v->domain->domain_id, v->vcpu_id);
}

void
hostsched_kick_vcpu(struct vcpu *v)
{
    struct vm_vcpu_info_shared *vci = v->vm_vcpu_info_shared;

    if (vci)
        uxen_info->ui_kick_vcpu(vci);
    else
        printk("hostsched_kick_vcpu %d.%d no vm_info\n",
               v->domain->domain_id, v->vcpu_id);
}

void
hostsched_notify_exception(struct domain *d)
{
    struct vm_info_shared *vmis = d->vm_info_shared;

    if (!vmis || is_template_domain(d))
        return;

    uxen_info->ui_notify_exception(vmis);
}

void
hostsched_signal_event(struct vcpu *v, void *opaque)
{
    struct vm_vcpu_info_shared *vci = v->vm_vcpu_info_shared;

    if (vci)
        uxen_info->ui_signal_event(vci, opaque);
    else
        printk("hostsched_signal_event %d.%d no vm_info\n",
               v->domain->domain_id, v->vcpu_id);
}

void
hostsched_set_handle(struct domain *d, xen_domain_handle_t handle)
{
    struct vm_info_shared *vmi = d->vm_info_shared;

    if (!vmi)
        return;

    memcpy(vmi->vmi_uuid, handle, sizeof(xen_domain_handle_t));
}

void
hostsched_dump_vcpu(struct vcpu *v, int wake)
{
    struct vm_vcpu_info_shared *vci = v->vm_vcpu_info_shared;

    if (vci == NULL)
        return;

    printk("    vcpu %d (halted %x, runstate %x, runmode %x, "
           "pause counts %x/%x\n"
           "             softirq %lx, timer int %s, timeout %"PRId64"ms)\n",
           v->vcpu_id, vci->vci_host_halted,
           v->runstate.state, vci->vci_run_mode,
		   atomic_read(&v->pause_count), atomic_read(&v->domain->pause_count),
           v->softirq_pending, vci->vci_has_timer_interrupt ? "yes" : "no",
           (v->timer_deadline - NOW()) / 1000000);
    if (wake)
        uxen_info->ui_wake_vm(vci);
}

const struct scheduler sched_host_def = {
    .name           = "Host Scheduler",
    .opt_name       = "host",
    .sched_id       = XEN_SCHEDULER_HOST,

#if 0
    .init_domain    = hostsched_dom_init,
#endif
    .destroy_domain = hostsched_dom_destroy,

#if 0
    .alloc_vdata    = hostsched_alloc_vdata,
    .free_vdata     = hostsched_free_vdata,
#endif

    .sleep          = hostsched_vcpu_sleep,
    .wake           = hostsched_vcpu_wake,
    .yield          = hostsched_vcpu_yield,

#if 0
    .init           = hostsched_init,
#endif
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
