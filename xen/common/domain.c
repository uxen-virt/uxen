/******************************************************************************
 * domain.c
 * 
 * Generic domain-handling functions.
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/ctype.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/domain.h>
#include <xen/mm.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/console.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/domain_page.h>
#include <xen/rangeset.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/delay.h>
#include <xen/shutdown.h>
#include <xen/percpu.h>
#include <xen/multicall.h>
#include <xen/rcupdate.h>
#include <xen/wait.h>
#include <xen/grant_table.h>
#include <xen/xenoprof.h>
#include <xen/irq.h>
#include <acpi/cpufreq/cpufreq.h>
#include <asm/debugger.h>
#include <public/sched.h>
#include <public/sysctl.h>
#include <public/vcpu.h>
#include <asm/hvm/attovm.h>
#include <asm/hvm/ax.h>
#include <xsm/xsm.h>
#include <xen/trace.h>
#include <xen/tmem.h>

/* Protect updates/reads (resp.) of domain_list and domain_hash. */
DEFINE_SPINLOCK(domlist_update_lock);
DEFINE_RCU_READ_LOCK(domlist_read_lock);

struct domain *domain_list;

struct domain *dom0;

struct vcpu *idle_vcpu[NR_CPUS] __read_mostly;

vcpu_info_t dummy_vcpu_info;

const uint128_t handle_dead_template_domain = {
    .val_lo = 0x0000010000000000ULL, .val_hi = 0x0000000000000000ULL
};

int current_domain_id(void)
{
    return current->domain->domain_id;
}

static void __domain_finalise_shutdown(struct domain *d)
{
    struct vcpu *v;

    BUG_ON(!spin_is_locked(&d->shutdown_lock));

    if ( d->is_shut_down )
        return;

    for_each_vcpu ( d, v )
        if ( !v->paused_for_shutdown )
            return;

    domain_pause_time(d);

    /* only needed on suspend path, can cause deadlock on SHUTDOWN_crash path */
    if (d->shutdown_code == SHUTDOWN_suspend)
        v4v_shutdown_for_suspend(d);

    d->is_shut_down = 1;
    hostsched_notify_exception(d);
}

static void vcpu_check_shutdown(struct vcpu *v)
{
    struct domain *d = v->domain;

    spin_lock(&d->shutdown_lock);

    if ( d->is_shutting_down )
    {
        if ( !v->paused_for_shutdown )
            vcpu_pause_nosync(v);
        v->paused_for_shutdown = 1;
        v->defer_shutdown = 0;
        __domain_finalise_shutdown(d);
    }

    spin_unlock(&d->shutdown_lock);
}

struct vcpu *alloc_vcpu(
    struct domain *d, unsigned int vcpu_id, unsigned int cpu_id)
{
    struct vcpu *v;

    BUG_ON((!is_idle_domain(d) || vcpu_id) && d->vcpu[vcpu_id]);

    if ( (v = alloc_vcpu_struct()) == NULL )
        return NULL;

    v->domain = d;
    v->vcpu_id = vcpu_id;

    spin_lock_init(&v->virq_lock);
    init_timers(&v->timers);

    if ( !zalloc_cpumask_var(&v->cpu_affinity) ||
         !zalloc_cpumask_var(&v->cpu_affinity_tmp) ||
         !zalloc_cpumask_var(&v->vcpu_dirty_cpumask) )
        goto fail_free;

    if ( is_idle_domain(d) )
    {
        v->runstate.state = RUNSTATE_running;
    }
    else
    {
        v->runstate.state = RUNSTATE_offline;        
        v->runstate.state_entry_time = NOW();
        set_bit(_VPF_down, &v->pause_flags);
        v->vcpu_info = ((vcpu_id < XEN_LEGACY_MAX_VCPUS)
                        ? (vcpu_info_t *)&shared_info(
                            d, vcpu_info[array_index_nospec(
                                    vcpu_id, XEN_LEGACY_MAX_VCPUS)])
                        : &dummy_vcpu_info);
    }

    if ( sched_init_vcpu(v, cpu_id) != 0 )
        goto fail_wq;

    if ( vcpu_initialise(v) != 0 )
    {
        sched_destroy_vcpu(v);
 fail_wq:
 fail_free:
        free_cpumask_var(v->cpu_affinity);
        free_cpumask_var(v->cpu_affinity_tmp);
        free_cpumask_var(v->vcpu_dirty_cpumask);
        free_vcpu_struct(v);
        return NULL;
    }

    d->vcpu[vcpu_id] = v;
    if ( vcpu_id != 0 )
    {
        int prev_id = v->vcpu_id - 1;
        while ( (prev_id >= 0) && (d->vcpu[prev_id] == NULL) )
            prev_id--;
        BUG_ON(prev_id < 0);
        v->next_in_list = d->vcpu[prev_id]->next_in_list;
        d->vcpu[prev_id]->next_in_list = v;
    }

    if ( vcpu_id == 0 && is_hvm_domain(d) && !is_template_domain(d) )
        rtc_init_timers(d);

    /* Must be called after making new vcpu visible to for_each_vcpu(). */
    vcpu_check_shutdown(v);

    return v;
}

struct domain **domain_array = NULL;
static int __init
domain_array_init(void)
{

    domain_array = _uxen_info.ui_domain_array;
    if (!domain_array)
        panic("Error allocating domain array\n");
    memset(domain_array, 0, _uxen_info.ui_domain_array_pages << PAGE_SHIFT);
    return 0;
}
__initcall(domain_array_init);

struct domain *domain_create_internal(
    domid_t domid, unsigned int domcr_flags, uint32_t ssidref,
    struct vm_info_shared *vmi)
{
    struct domain *d, **pd;
    enum { INIT_xsm = 1u<<0, INIT_watchdog = 1u<<1, INIT_rangeset = 1u<<2,
           INIT_evtchn = 1u<<3, INIT_gnttab = 1u<<4, INIT_arch = 1u<<5,
           INIT_v4v = 1u<<6 };
    int init_status = 0;
    int poolid = CPUPOOLID_NONE;

    if ( (d = alloc_domain_struct()) == NULL )
        return NULL;

    d->start_time = NOW();
#ifndef NDEBUG
    spin_lock_init(&d->p2m_stat_lock);
#endif  /* NDEBUG */

    d->domain_id = domid;
    if (domid < DOMID_FIRST_RESERVED)
        domain_array[domid] = d;

    d->vm_info_shared = vmi;

    lock_profile_register_struct(LOCKPROF_TYPE_PERDOM, d, domid, "Domain");

    atomic_set(&d->refcnt, 1);
    spin_lock_init_prof(d, domain_lock);
    spin_lock_init_prof(d, page_alloc_lock);
    spin_lock_init(&d->hypercall_deadlock_mutex);
 
    rwlock_init(&d->v4v_lock);

    INIT_LIST_HEAD(&d->vcpu_idle_tasklet_list);
    spin_lock_init(&d->vcpu_idle_tasklet_lock);

    spin_lock_init(&d->shutdown_lock);
    d->shutdown_code = -1;

    spin_lock_init(&d->time_pause_lock);

    if ( !zalloc_cpumask_var(&d->domain_dirty_cpumask) )
        goto fail;

    if ( domcr_flags & DOMCRF_hvm )
        d->is_hvm = 1;
    if ( domcr_flags & DOMCRF_attovm_ax ) {
        if (!ax_present) {
            printk(XENLOG_ERR "%s: attovm create vm%u: no ax present\n",
                __FUNCTION__, domid);
            goto fail;
        }
        if (!ax_has_attovm) {
            printk(XENLOG_ERR "%s: attovm create vm%u: no ax attovm support\n",
                __FUNCTION__, domid);
            goto fail;
        }
        printk(XENLOG_WARNING "%s: attovm create vm%u\n",
            __FUNCTION__, domid);
        d->is_attovm = d->is_attovm_ax = 1;
    }

    if ( domid == 0 )
    {
    }

    rangeset_domain_initialise(d);
    init_status |= INIT_rangeset;

    if ( domcr_flags & DOMCRF_dummy )
        return d;

    if ( domcr_flags & DOMCRF_template )
        d->is_template = 1;

#ifdef __i386__
    if ( domcr_flags & DOMCRF_hidden_mem )
        d->use_hidden_mem = 1;
#endif

    if ( !is_idle_domain(d) )
    {

        d->is_paused_by_controller = 1;
        atomic_inc(&d->pause_count);

        if ( evtchn_init(d) != 0 )
            goto fail;
        init_status |= INIT_evtchn;


        poolid = 0;
    }

    if ( arch_domain_create(d, domcr_flags) != 0 )
        goto fail;
    init_status |= INIT_arch;

    if ( cpupool_add_domain(d, poolid) != 0 )
        goto fail;

    if ( sched_init_domain(d) != 0 )
        goto fail;

    if ( !is_idle_domain(d) )
    {
        if ( v4v_init(d) != 0 )
            goto fail;
        init_status |= INIT_v4v;

        spin_lock(&domlist_update_lock);
        pd = &domain_list; /* NB. domain_list maintained in order of domid. */
        for ( pd = &domain_list; *pd != NULL; pd = &(*pd)->next_in_list )
            if ( (*pd)->domain_id > d->domain_id )
                break;
        d->next_in_list = *pd;
        rcu_assign_pointer(*pd, d);
        spin_unlock(&domlist_update_lock);
    }

    return d;

 fail:
    d->is_dying = DOMDYING_dead;
    atomic_set(&d->refcnt, DOMAIN_DESTROYED);
    if ( init_status & INIT_arch )
        arch_domain_destroy(d);
    if (d->is_attovm_ax)
       attovm_destroy(d);
    if ( init_status & INIT_v4v )
        v4v_destroy(d);
    if ( init_status & INIT_evtchn )
    {
        evtchn_destroy(d);
        evtchn_destroy_final(d);
    }
    if ( init_status & INIT_rangeset )
        rangeset_domain_destroy(d);
    if (domid < DOMID_FIRST_RESERVED)
        domain_array[domid] = NULL;
    free_cpumask_var(d->domain_dirty_cpumask);
    free_domain_struct(d);
    return NULL;
}

static inline int is_free_domid(domid_t dom)
{
    struct domain *d;

    if ( dom >= DOMID_FIRST_RESERVED )
        return 0;

    if ( (d = rcu_lock_domain_by_id(dom)) == NULL )
        return 1;

    rcu_unlock_domain(d);
    return 0;
}

int
domain_create(domid_t dom, unsigned int flags, uint32_t ssidref,
              xen_domain_handle_t uuid, xen_domain_handle_t v4v_token,
              struct vm_info_shared *vmi, struct domain **_d)
{
    struct domain *d, *d_uuid;
    static domid_t rover = 0;

#define REQUIRED_FLAGS (DOMCRF_hvm | DOMCRF_hap)
    if ((flags & REQUIRED_FLAGS) != REQUIRED_FLAGS) {
        printk("domain_create with incorrect flags 0x%x\n", flags);
        return -EINVAL;
    }

    if ((dom > 0) && (dom < DOMID_FIRST_RESERVED)) {
        if ( !is_free_domid(dom) ) {
            printk("vm%u: %" PRIuuid " id already in use\n",
                   dom, PRIuuid_arg(uuid));
            return -EINVAL;
        }
    } else {
        for (dom = rover + 1; dom != rover; dom++) {
            if (dom == DOMID_FIRST_RESERVED)
                dom = 0;
            if (is_free_domid(dom))
                break;
        }

        if (dom == rover)
            return -ENOMEM;

        rover = dom;
    }

    d = domain_create_internal(dom, flags, ssidref, vmi);
    if (!d)
        return -ENOMEM;

    spin_lock(&domlist_update_lock);

    /* check if requested handle is already used */
    d_uuid = rcu_lock_domain_by_uuid(uuid, UUID_HANDLE);
    if (d_uuid) {
        printk("vm%u: %" PRIuuid " handle already in use\n",
               dom, PRIuuid_arg(uuid));
        spin_unlock(&domlist_update_lock);
        rcu_unlock_domain(d_uuid);
        return -EEXIST;
    }
    d_uuid = rcu_lock_domain_by_uuid(uuid, UUID_V4V_TOKEN);
    if (d_uuid) {
        printk("vm%u: %" PRIuuid " v4v token already in use\n",
               dom, PRIuuid_arg(uuid));
        spin_unlock(&domlist_update_lock);
        rcu_unlock_domain(d_uuid);
        return -EEXIST;
    }

    rcu_lock_domain(d);

    atomic_write_domain_handle(&d->v4v_token_atomic, (uint128_t *)v4v_token);
    atomic_write_domain_handle(&d->handle_atomic, (uint128_t *)uuid);

    if (d->is_attovm_ax) {
        if ( attovm_assign_token(d, (uint128_t *)v4v_token) ) {
            printk(XENLOG_ERR "vm%u: %" PRIuuid " failed to assign token\n",
                dom, PRIuuid_arg(v4v_token));
            spin_unlock(&domlist_update_lock);
            rcu_unlock_domain(d);
            return -EINVAL;
        }
    }

    spin_unlock(&domlist_update_lock);

    *_d = d;

    return 0;
}

static unsigned int default_vcpu0_location(cpumask_t *online)
{
    return smp_processor_id();
}

long
domain_set_max_vcpus(struct domain *d, unsigned int max)
{
    cpumask_t *online;
    unsigned int i, cpu;
    long ret;

    /* We cannot reduce maximum VCPUs. */
    ret = -EINVAL;
    if ((max < d->max_vcpus) &&
        (d->vcpu[array_index_nospec(max, d->max_vcpus)] != NULL))
        goto out;

    /*
     * For now don't allow increasing the vcpu count from a non-zero
     * value: This code and all readers of d->vcpu would otherwise need
     * to be converted to use RCU, but at present there's no tools side
     * code path that would issue such a request.
     */
    ret = -EBUSY;
    if ( (d->max_vcpus > 0) && (max > d->max_vcpus) )
        goto out;

    ret = -ENOMEM;
    online = (d->cpupool == NULL) ? &cpu_online_map : d->cpupool->cpu_valid;
    if ( max > d->max_vcpus )
    {
        struct vcpu **vcpus;

        BUG_ON(d->vcpu != NULL);
        BUG_ON(d->max_vcpus != 0);

        vcpus = d->extra_1->vcpu;

        /* Install vcpu array /then/ update max_vcpus. */
        d->vcpu = vcpus;
        wmb();
        d->max_vcpus = max;
    }

    for ( i = 0; i < max; i++ )
    {
        if ( d->vcpu[i] != NULL )
            continue;

        cpu = (i == 0) ?
            default_vcpu0_location(online) :
            cpumask_cycle(d->vcpu[i-1]->processor, online);

        if ( alloc_vcpu(d, i, cpu) == NULL )
            goto out;
    }

    ret = 0;
  out:
    return ret;
}


struct domain *get_domain_by_id(domid_t dom)
{
    struct domain *d;

    if (dom >= DOMID_FIRST_RESERVED)
        return NULL;

    rcu_read_lock(&domlist_read_lock);

    dom = array_index_nospec(dom, DOMID_FIRST_RESERVED);
    d = domain_array[dom];
    if (d && unlikely(!get_domain(d)))
        d = NULL;

    rcu_read_unlock(&domlist_read_lock);

    return d;
}


struct domain *rcu_lock_domain_by_id(domid_t dom)
{
    struct domain *d = NULL;

    if (dom >= DOMID_FIRST_RESERVED)
        return NULL;

    rcu_read_lock(&domlist_read_lock);

    dom = array_index_nospec(dom, DOMID_FIRST_RESERVED);
    d = domain_array[dom];
    if (d)
        rcu_lock_domain(d);

    rcu_read_unlock(&domlist_read_lock);

    return d;
}

int rcu_lock_target_domain_by_id(domid_t dom, struct domain **d)
{
    if ( dom == DOMID_SELF )
        *d = rcu_lock_current_domain();
    else if ( (*d = rcu_lock_domain_by_id(dom)) == NULL )
        return -ESRCH;

    if ( !IS_PRIV_FOR(current->domain, *d) )
    {
        rcu_unlock_domain(*d);
        return -EPERM;
    }

    return 0;
}

int rcu_lock_remote_target_domain_by_id(domid_t dom, struct domain **d)
{
    if ( (*d = rcu_lock_domain_by_id(dom)) == NULL )
        return -ESRCH;

    if ( (*d == current->domain) || !IS_PRIV_FOR(current->domain, *d) )
    {
        rcu_unlock_domain(*d);
        return -EPERM;
    }

    return 0;
}

struct domain *rcu_lock_domain_by_uuid(xen_domain_handle_t uuid,
                                       enum uuid_type uuid_type)
{
    struct domain *d = NULL;
    uint128_t d_uuid;

    rcu_read_lock(&domlist_read_lock);

    for ( d = rcu_dereference(domain_list);
          d != NULL;
          d = rcu_dereference(d->next_in_list) )
    {
        switch (uuid_type) {
        case UUID_HANDLE:
            atomic_read_domain_handle(&d->handle_atomic, &d_uuid);
            break;
        case UUID_V4V_TOKEN:
            atomic_read_domain_handle(&d->v4v_token_atomic, &d_uuid);
            break;
        default:
            continue;
        }
        if ( uint128_t_equal((uint128_t *)uuid, &d_uuid) )
        {
            rcu_lock_domain(d);
            break;
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    return d;
}

#if 0
int rcu_lock_target_domain_by_uuid(xen_domain_handle_t uuid, struct domain **d)
{

    if ( (*d = rcu_lock_domain_by_uuid(uuid, UUID_HANDLE)) == NULL )
        return -ESRCH;

    if ( !IS_PRIV_FOR(current->domain, *d) )
    {
        rcu_unlock_domain(*d);
        return -EPERM;
    }

    return 0;
}
#endif

int domain_kill(struct domain *d)
{
    struct domain *clone_of;
    int rc = 0;

    printk(XENLOG_WARNING "%s: dom:%p, curr_dom:%p, is_dying:%d\n",
           __FUNCTION__, d, current->domain, d->is_dying);

    if ( d == current->domain )
        return -EINVAL;

    /* Protected by domctl_lock. */
    switch ( d->is_dying )
    {
    case DOMDYING_alive:
        domain_pause(d);
        d->is_dying = DOMDYING_dying;
        spin_barrier(&d->domain_lock);
        if (d->is_attovm_ax)
          attovm_destroy(d);
        v4v_destroy(d);
        evtchn_destroy(d);
        /* fallthrough */
    case DOMDYING_dying:
        rc = domain_relinquish_resources(d);
        if ( rc != 0 )
        {
            BUG_ON(rc != -EAGAIN);
            if (is_template_domain(d)) {
                printk(XENLOG_WARNING "%s: vm%u template still in use\n",
                       __FUNCTION__, d->domain_id);
                d->vm_info_shared->vmi_free_deferred = 1;
                /* clear uuid of template domains, so that the uuid can be
                 * re-used */
                atomic_write_domain_handle(&d->handle_atomic,
                                           &handle_dead_template_domain);
                rc = 0;
            }
            break;
        }
        /* release ref held on template domain, now that our memory
         * has been torn down */
        clone_of = d->clone_of;
        if (clone_of) {
            printk(XENLOG_WARNING "%s: vm%u: template put_domain: "
                   "refcnt=%d tot_pages=%d xenheap_pages=%d vframes=%d\n",
                   __FUNCTION__, d->clone_of->domain_id,
                   atomic_read(&d->clone_of->refcnt), d->clone_of->tot_pages,
                   d->clone_of->xenheap_pages, d->clone_of->vframes);
            put_domain(clone_of);
            if (clone_of->is_dying &&
                domain_relinquish_resources(clone_of) == 0) {
                d->vm_info_shared->vmi_free_related = clone_of->vm_info_shared;
                printk(XENLOG_WARNING "%s: vm%u: template "
                       "sched_destroy_domain()\n", __FUNCTION__,
                       clone_of->domain_id);
                sched_destroy_domain(clone_of);
                clone_of->is_dying = DOMDYING_dead;
                printk(XENLOG_WARNING "%s: vm%u: template put_domain final: "
                       "refcnt=%d tot_pages=%d xenheap_pages=%d vframes=%d\n",
                       __FUNCTION__, clone_of->domain_id,
                       atomic_read(&clone_of->refcnt), clone_of->tot_pages,
                       clone_of->xenheap_pages, clone_of->vframes);
                put_domain(clone_of);
            }
        }
        d->is_dying = DOMDYING_dead;
        hostsched_notify_exception(d);
        printk(XENLOG_WARNING "%s: vm%u sched_destroy_domain()\n",
               __FUNCTION__, d->domain_id);
        sched_destroy_domain(d);
        printk(XENLOG_WARNING "%s: vm%u: put_domain: refcnt=%d tot_pages=%d "
               "xenheap_pages=%d vframes=%d\n", __FUNCTION__, d->domain_id,
               atomic_read(&d->refcnt), d->tot_pages, d->xenheap_pages,
               d->vframes);
        put_domain(d);
        /* fallthrough */
    case DOMDYING_dead:
        break;
    }

    return rc;
}


void __domain_crash(struct domain *d)
{

    if (d->is_crashing)
        return;
    d->is_crashing = 1;

    if ( d->is_shutting_down )
    {
        /* Print nothing: the domain is already shutting down. */
    }
    else if ( d == current->domain )
    {
        printk("vm%u.%u crashed on cpu#%d:\n",
               d->domain_id, current->vcpu_id, smp_processor_id());
        show_execution_state(guest_cpu_user_regs());
#ifdef run_in_exception_handler
        run_in_exception_handler(show_stack);
#endif
    }
    else
    {
        printk("vm%u reported crashed by vm%u on cpu#%d:\n",
               d->domain_id, current->domain->domain_id, smp_processor_id());
    }

    domain_shutdown(d, SHUTDOWN_crash);
}


void __domain_crash_synchronous(void)
{
    BUG();
    for ( ; ; ) ;
}


void domain_shutdown(struct domain *d, u8 reason)
{
    struct vcpu *v;

    spin_lock(&d->shutdown_lock);

    if ( d->shutdown_code == -1 )
        d->shutdown_code = reason;
    reason = d->shutdown_code;

    if ( d->domain_id == 0 )
        BUG();

    if ( d->is_shutting_down )
    {
        spin_unlock(&d->shutdown_lock);
        return;
    }

    d->is_shutting_down = 1;

    smp_mb(); /* set shutdown status /then/ check for per-cpu deferrals */

    for_each_vcpu ( d, v )
    {
        if ( reason == SHUTDOWN_crash )
            v->defer_shutdown = 0;
        else if ( v->defer_shutdown )
            continue;
        vcpu_pause_nosync(v);
        v->paused_for_shutdown = 1;
    }

    __domain_finalise_shutdown(d);

    spin_unlock(&d->shutdown_lock);
}

void domain_resume(struct domain *d)
{
    struct vcpu *v;

    /*
     * Some code paths assume that shutdown status does not get reset under
     * their feet (e.g., some assertions make this assumption).
     */
    domain_pause(d);

    spin_lock(&d->shutdown_lock);

    d->is_shutting_down = d->is_shut_down = 0;
    d->shutdown_code = -1;

    domain_unpause_time(d);

    for_each_vcpu ( d, v )
    {
        if ( v->paused_for_shutdown )
            vcpu_unpause(v);
        v->paused_for_shutdown = 0;
    }

    spin_unlock(&d->shutdown_lock);

    domain_unpause(d);

    v4v_resume(d);
}

int vcpu_start_shutdown_deferral(struct vcpu *v)
{
    if ( v->defer_shutdown )
        return 1;

    v->defer_shutdown = 1;
    smp_mb(); /* set deferral status /then/ check for shutdown */
    if ( unlikely(v->domain->is_shutting_down) )
        vcpu_check_shutdown(v);

    return v->defer_shutdown;
}

void vcpu_end_shutdown_deferral(struct vcpu *v)
{
    v->defer_shutdown = 0;
    smp_mb(); /* clear deferral status /then/ check for shutdown */
    if ( unlikely(v->domain->is_shutting_down) )
        vcpu_check_shutdown(v);
}

void domain_pause_for_debugger(void)
{
#ifdef __UXEN_debugger__
    struct domain *d = current->domain;
    struct vcpu *v;

    atomic_inc(&d->pause_count);
    if ( test_and_set_bool(d->is_paused_by_controller) )
        domain_unpause(d); /* race-free atomic_dec(&d->pause_count) */

    for_each_vcpu ( d, v )
        vcpu_sleep_nosync(v);

#ifdef __UXEN_debugger__
    send_guest_global_virq(dom0, VIRQ_DEBUGGER);
#else  /* __UXEN_debugger__ */
    hostsched_notify_exception(d);
#endif  /* __UXEN_debugger__ */
#else  /* __UXEN_debugger__ */
    BUG();
#endif  /* __UXEN_debugger__ */
}

/* Complete domain destroy after RCU readers are not holding old references. */
static void complete_domain_destroy(struct rcu_head *head)
{
    struct domain *d = container_of(head, struct domain, rcu);
    struct vcpu *v;
    int i;

    for ( i = d->max_vcpus - 1; i >= 0; i-- )
    {
        if ( (v = d->vcpu[i]) == NULL )
            continue;
        vcpu_destroy(v);
        sched_destroy_vcpu(v);
    }

    arch_domain_destroy(d);

    rangeset_domain_destroy(d);

    cpupool_rm_domain(d);

    printk("%s:%d: sched_destroy_domain() for vm%u\n",
           __FUNCTION__, __LINE__, d->domain_id);
    sched_destroy_domain(d);

    for ( i = d->max_vcpus - 1; i >= 0; i-- )
        if ( (v = d->vcpu[i]) != NULL )
        {
            free_cpumask_var(v->cpu_affinity);
            free_cpumask_var(v->cpu_affinity_tmp);
            free_cpumask_var(v->vcpu_dirty_cpumask);
            free_vcpu_struct(v);
        }

    if ( d->target != NULL )
        put_domain(d->target);

    evtchn_destroy_final(d);

    free_cpumask_var(d->domain_dirty_cpumask);
    free_domain_struct(d);

}

/* Release resources belonging to task @p. */
void domain_destroy(struct domain *d)
{
    struct domain **pd;
    atomic_t      old, new;

    BUG_ON(!d->is_dying);

    printk("domain_destroy for vm%u\n", d->domain_id);

    /* May be already destroyed, or get_domain() can race us. */
    _atomic_set(old, 0);
    _atomic_set(new, DOMAIN_DESTROYED);
    old = atomic_compareandswap(old, new, &d->refcnt);
    if ( _atomic_read(old) != 0 )
        return;

    /* Delete from task list and task hashtable. */
    TRACE_1D(TRC_SCHED_DOM_REM, d->domain_id);
    spin_lock(&domlist_update_lock);
    pd = &domain_list;
    while ( *pd != d ) 
        pd = &(*pd)->next_in_list;
    rcu_assign_pointer(*pd, d->next_in_list);
    spin_unlock(&domlist_update_lock);

    if (d->is_attovm_ax)
        attovm_destroy(d);

    printk("schedule rcu complete_domain_destroy for vm%u\n", d->domain_id);
    /* Schedule RCU asynchronous completion of domain destroy. */
    call_rcu(&d->rcu, complete_domain_destroy);
}

void vcpu_pause(struct vcpu *v)
{
    ASSERT(v != current);
    atomic_inc(&v->pause_count);
    vcpu_sleep_sync(v);
}

void vcpu_pause_nosync(struct vcpu *v)
{
    atomic_inc(&v->pause_count);
    vcpu_sleep_nosync(v);
}

void vcpu_unpause(struct vcpu *v)
{
    if ( atomic_dec_and_test(&v->pause_count) )
        vcpu_wake(v);
}

void domain_pause(struct domain *d)
{
    struct vcpu *v;

    ASSERT(d != current->domain);

    atomic_inc(&d->pause_count);

    for_each_vcpu( d, v )
        vcpu_sleep_sync(v);
}

void domain_unpause(struct domain *d)
{
    struct vcpu *v;

    if ( atomic_dec_and_test(&d->pause_count) )
        for_each_vcpu( d, v )
            vcpu_wake(v);
}

void
domain_pause_time(struct domain *d)
{

    spin_lock(&d->time_pause_lock);
    if (is_hvm_domain(d) && !d->arch.vtsc && !d->time_pause_count) {
        struct vcpu *v;
        uint64_t pause_tsc;

        d->time_pause_begin = NOW();

        rdtscll(pause_tsc);
        for_each_vcpu( d, v )
            v->arch.pause_tsc = pause_tsc;
    }
    d->time_pause_count++;
    spin_unlock(&d->time_pause_lock);
}

void
domain_unpause_time(struct domain *d)
{

    spin_lock(&d->time_pause_lock);

    if (!d->time_pause_count)   /* initial, or spurious */
        goto out;
    d->time_pause_count--;

    if (!d->time_pause_count) {
        struct vcpu *v;
        u64 tsc;

        rdtscll(tsc);
        for_each_vcpu( d, v ) {
            /* read guest tsc with at-pause-time pause_tsc, then
             * update pause_tsc to current tsc and reset. This
             * avoids guest tsc skipping the duration of pause.
             */
            uint64_t gtsc = hvm_get_guest_tsc(v);
            v->arch.pause_tsc = tsc;
            hvm_set_guest_tsc(v, gtsc);
            v->arch.pause_tsc = 0;
            hvm_set_guest_time(v, gtsc_to_gtime(v->domain, gtsc));
            pt_unpause(v);
        }

        d->pause_time += NOW() - d->time_pause_begin;
    }

  out:
    spin_unlock(&d->time_pause_lock);
}

void domain_pause_by_systemcontroller(struct domain *d)
{
    domain_pause(d);
    if ( test_and_set_bool(d->is_paused_by_controller) )
        domain_unpause(d);
    else
        domain_pause_time(d);

    hostsched_notify_exception(d);
}

void domain_unpause_by_systemcontroller(struct domain *d)
{
    if ( test_and_clear_bool(d->is_paused_by_controller) ) {
        domain_unpause_time(d);
        domain_unpause(d);
    }
    hostsched_notify_exception(d);
}

void
domain_pause_for_suspend(struct domain *d)
{

    domain_pause(d);
    if (test_and_set_bool(d->is_paused_for_suspend))
        domain_unpause(d);
    else
        domain_pause_time(d);

    hostsched_notify_exception(d);
}

void
domain_unpause_for_suspend(struct domain *d)
{

    if (test_and_clear_bool(d->is_paused_for_suspend)) {
        domain_unpause_time(d);
        domain_unpause(d);
    }
    hostsched_notify_exception(d);
}

int boot_vcpu(struct domain *d, int vcpuid, vcpu_guest_context_u ctxt)
{
    struct vcpu *v = d->vcpu[vcpuid];

    BUG_ON(v->is_initialised);

    return arch_set_info_guest(v, ctxt);
}

void vcpu_reset(struct vcpu *v)
{
    struct domain *d = v->domain;

    vcpu_pause(v);
    domain_lock(d);

    arch_vcpu_reset(v);

    set_bit(_VPF_down, &v->pause_flags);

    clear_bit(v->vcpu_id, d->poll_mask);
    v->poll_evtchn = 0;

    v->fpu_initialised = 0;
    v->fpu_dirtied     = 0;
    v->is_initialised  = 0;
#ifdef VCPU_TRAP_LAST
    v->async_exception_mask = 0;
    memset(v->async_exception_state, 0, sizeof(v->async_exception_state));
#endif
    cpumask_clear(v->cpu_affinity_tmp);
    clear_bit(_VPF_blocked, &v->pause_flags);

    domain_unlock(v->domain);
    vcpu_unpause(v);
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
