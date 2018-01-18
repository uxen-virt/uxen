/*
 *  uxen_main.c
 *  uxen
 *
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/hypercall.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <xen/symbols.h>
#include <xen/console.h>
#include <xen/delay.h>
#include <xen/keyhandler.h>
#include <asm/bug.h>
#include <asm/current.h>
#include <asm/guest_access.h>
#include <asm/hvm/hvm.h>
#include <asm/mm.h>
#include <asm/p2m.h>
#include <asm/hap.h>
#include <asm/xstate.h>
#include <public/sched.h>

#include <uxen/uxen.h>
#include <uxen/uxen_desc.h>
#include <uxen/uxen_link.h>
#include <uxen/mapcache.h>
#include <uxen/memcache-dm.h>

int uxen_verbose = 0;

static void free_dom0(void);
static void do_hvm_cpu_down(void *);

DEFINE_PER_CPU(uintptr_t, stack_top);
DEFINE_PER_CPU(struct uxen_hypercall_desc *, hypercall_args);

uint64_t aligned_throttle_period = -1ULL;

static cpumask_t cpu_down_map;

struct _uxen_info _uxen_info = {
        .ui_sizeof_struct_page_info = sizeof(struct page_info),

        .ui_domain_array_pages =
        (DOMID_FIRST_RESERVED * sizeof(struct domain *) + PAGE_SIZE - 1) >>
        PAGE_SHIFT,

#ifdef UXEN_HOST_WINDOWS
        .ui_mapcache_size = MAPCACHE_SIZE,
#endif  /* UXEN_HOST_WINDOWS */

        .ui_vframes_fill = VFRAMES_PCPU_FILL,
};

/* SSS: use per_cpu for this? */
struct cpu_info uxen_cpu_info[UXEN_MAXIMUM_PROCESSORS];

#if 0
DEFINE_PER_CPU(uint32_t, host_cpu_preemption);
#else
uint32_t _host_cpu_preemption[NR_CPUS];
#endif

asmlinkage_abi void
_cpu_irq_disable(void)
{

    asm volatile ( "cli" : : : "memory" );
}

asmlinkage_abi void
_cpu_irq_enable(void)
{

    if (boot_cpu_data.x86_vendor ==  X86_VENDOR_INTEL)
        asm volatile ( "sti" : : : "memory" );
    else
        asm volatile ( "stgi" : : : "memory" );
}

void
_cpu_irq_save_flags(unsigned long *x)
{

    asm volatile ( "pushf" __OS " ; pop" __OS " %0" : "=g" (*x));
}

int
_cpu_irq_is_enabled(void)
{
    unsigned long flags;

    _cpu_irq_save_flags(&flags);
    return !!(flags & (1<<9)); /* EFLAGS_IF */
}

void
_cpu_irq_save(unsigned long *x)
{

    _cpu_irq_save_flags(x);
    _cpu_irq_disable();
}

void
_cpu_irq_restore(unsigned long x)
{

    asm volatile ( "push" __OS " %0 ; popf" __OS
                   : : "g" (x) : "memory", "cc" );
}

static void
_end_execution(struct vcpu *vcpu)
{
    int cpu = smp_processor_id();

    if (rcu_pending(cpu))
        rcu_check_callbacks(cpu);
    process_pending_softirqs();

    hvm_cpu_off();
    uxen_set_current(vcpu);
}
#define end_execution() _end_execution(NULL)

/* If the domain exists and has been setup, returns the vm_info_shared pointer
   If the domain exists but has not been setup, returns NULL
   Otherwise returns -1 */
intptr_t
do_lookup_vm(xen_domain_handle_t vm_uuid)
{
    struct domain *d;

    d = rcu_lock_domain_by_uuid(vm_uuid, UUID_HANDLE);
    if (d)
        rcu_unlock_domain(d);

    return d ? (intptr_t)d->vm_info_shared : -ENOENT;
}

intptr_t UXEN_INTERFACE_FN(
__uxen_lookup_vm)(xen_domain_handle_t vm_uuid)
{
    intptr_t ret;

    if (!dom0 || !dom0->vcpu)
        return -1;

    set_stack_top();
    uxen_set_current(dom0->vcpu[smp_processor_id()]);
    hvm_cpu_on();

    ret = do_lookup_vm(vm_uuid);

    end_execution();

    return ret;
}

intptr_t
do_setup_vm(struct uxen_createvm_desc *ucd, struct vm_info_shared *vmi,
            struct vm_vcpu_info_shared **vcis)
{
    struct domain *d = NULL;
    struct vcpu *v;
    unsigned int domcr_flags;
    int ret;

    while (!domctl_lock_acquire())
        cpu_relax();

    ret = -EINVAL;
    domcr_flags = domctl_createdomain_parse_flags(ucd->ucd_create_flags);
    if (domcr_flags == ~0) {
        domctl_lock_release();
        goto out;
    }

    ret = domain_create(ucd->ucd_domid, domcr_flags, ucd->ucd_create_ssidref,
                        ucd->ucd_vmuuid, ucd->ucd_v4v_token, &d);
    if (ret) {
        domctl_lock_release();
        goto out;
    }

    domctl_lock_release();

    vmi->vmi_domid = d->domain_id;
    atomic_read_domain_handle(&d->handle_atomic, (uint128_t *)vmi->vmi_uuid);

    printk("%s: vm%u: uuid %" PRIuuid "\n",
           __FUNCTION__, vmi->vmi_domid, PRIuuid_arg(vmi->vmi_uuid));

    printk("vm%u: %p/%p\n", d->domain_id, d, vmi);
    ret = hostsched_setup_vm(d, vmi);
    if (ret)
        goto out;

    ret = domain_set_max_vcpus(d, ucd->ucd_max_vcpus);
    if (ret)
        goto out;

    if (d->max_vcpus < 1) {
	printk("domain has no vcpus\n");
        ret = -EINVAL;
        goto out;
    }

    v = d->vcpu[0];
    if (v == NULL) {
	printk("domain has no vcpu[0]\n");
        ret = -EINVAL;
        goto out;
    }

    for_each_vcpu(d, v) {
        struct vm_vcpu_info_shared *vci = vcis[v->vcpu_id];
        printk("vm%u.%u: %p/%p on cpu %d\n", d->domain_id,
               v->vcpu_id, v, vci, v->processor);
        vci->vci_vcpuid = v->vcpu_id;

        hostsched_setup_vcpu(v, vci);

        rcu_unlock_domain(d);

        local_irq_disable();
        uxen_set_current(v);
        vcpu_switch_host_cpu(v);
        uxen_set_current(dom0->vcpu[smp_processor_id()]);
        local_irq_enable();

        rcu_lock_domain(d);

        vci->vci_run_mode = VCI_RUN_MODE_SETUP;
    }

  out:
    if (d)
        rcu_unlock_domain(d);
    return ret;
}

intptr_t UXEN_INTERFACE_FN(
__uxen_setup_vm)(struct uxen_createvm_desc *ucd, struct vm_info_shared *vmi,
                 struct vm_vcpu_info_shared **vcis)
{
    intptr_t ret;

    if (!dom0 || !dom0->vcpu)
        return -ENOENT;

    set_stack_top();
    uxen_set_current(dom0->vcpu[smp_processor_id()]);
    hvm_cpu_on();
    current->always_access_ok = 1;
    current->is_privileged = 1;

    ret = do_setup_vm(ucd, vmi, vcis);

    current->is_privileged = 0;
    current->always_access_ok = 0;
    end_execution();

    return ret;
}

intptr_t
do_run_vcpu(uint32_t domid, uint32_t vcpuid)
{
    struct domain *d;
    struct vcpu *v;
    struct vm_vcpu_info_shared *vci = NULL;
    int ret = -EFAULT;

    d = get_domain_by_id(domid);
    if (d == NULL)
        goto out;

    if (vcpuid >= d->max_vcpus)
        goto out;

    vcpuid = array_index_nospec(vcpuid, d->max_vcpus);
    v = d->vcpu[vcpuid];
    if (v == NULL)
        goto out;

    vci = v->vm_vcpu_info_shared;
    if (vci == NULL)
        goto out;

    switch (vci->vci_run_mode) {
    case VCI_RUN_MODE_IDLE:
        BUG();
    case VCI_RUN_MODE_SETUP:
        printk("vm%u.%u pause flags %lx count %x domain count %x\n",
               v->domain->domain_id, v->vcpu_id,
               v->pause_flags, atomic_read(&v->pause_count),
               atomic_read(&v->domain->pause_count));

        v->context_loaded = 0;

        if (d->shutdown_code != -1)
            goto out;

        uxen_set_current(v);
        hvm_cpu_on();
        if (!v->vcpu_id)
            v4v_resume(d);
        break;

    case VCI_RUN_MODE_PROCESS_IOREQ:
        uxen_set_current(v);
        hvm_cpu_on();
        if (test_and_clear_bit(_VPF_blocked_in_xen, &v->pause_flags))
            vcpu_wake(v);
        break;

    case VCI_RUN_MODE_HALT:
    case VCI_RUN_MODE_IDLE_WORK:
        uxen_set_current(v);
        hvm_cpu_on();
        break;

    case VCI_RUN_MODE_YIELD:
        clear_bit(_VPF_yield, &v->pause_flags);
        /* fall through */
    case VCI_RUN_MODE_PREEMPT:
    case VCI_RUN_MODE_PAGEMAP_CHECK:
    case VCI_RUN_MODE_FREEPAGE_CHECK:
    case VCI_RUN_MODE_MAP_PAGE_REQUEST:
        uxen_set_current(v);
        hvm_cpu_on();
        break;
    }

    v->need_hvm_resume = 1;

    if (uxen_verbose) printk("running vm\n");
    while (_uxen_info.ui_running && vci->vci_runnable) {

      again:
        if (atomic_read(&v->event_check)) {
            UI_HOST_CALL(ui_kick_vcpu_cancel, vci);
            atomic_set(&v->event_check, 0);
        }
        if (v->force_preempt || UI_HOST_CALL(ui_host_needs_preempt)) {
            v->force_preempt = 0;
            vci->vci_run_mode = VCI_RUN_MODE_PREEMPT;
            ret = 0;
            goto out_reset_current;
        }
        if (test_bit(_VPF_yield, &v->pause_flags)) {
            vci->vci_run_mode = VCI_RUN_MODE_YIELD;
            ret = 0;
            goto out_reset_current;
        }
        if (v->paused_for_shutdown && d->shutdown_code != SHUTDOWN_suspend &&
            d->shutdown_code != -1) {
            vci->vci_run_mode = VCI_RUN_MODE_SHUTDOWN;
            ret = 0;
            goto out_reset_current;
        }
        if (check_free_pages_needed(0)) {
            vci->vci_run_mode = VCI_RUN_MODE_FREEPAGE_CHECK;
            ret = 0;
            goto out_reset_current;
        }
        if (check_pagemap_needed()) {
            vci->vci_run_mode = VCI_RUN_MODE_PAGEMAP_CHECK;
            ret = 0;
            goto out_reset_current;
        }
        if (vci->vci_map_page_range_requested) {
            vci->vci_run_mode = VCI_RUN_MODE_MAP_PAGE_REQUEST;
            ret = 0;
            goto out_reset_current;
        }
        if (check_vframes_needed()) {
            vci->vci_run_mode = VCI_RUN_MODE_VFRAMES_CHECK;
            ret = 0;
            goto out_reset_current;
        }

        if (test_bit(_VPF_blocked_in_xen, &v->pause_flags)) {
            if (UI_HOST_CALL(ui_check_ioreq, vci)) {
                clear_bit(_VPF_blocked_in_xen, &v->pause_flags);
                vcpu_wake(v);
                v->need_hvm_resume = 1;
            } else {
                perfc_incr(blocked_in_xen);
                vci->vci_run_mode = VCI_RUN_MODE_PROCESS_IOREQ;
                ret = 0;
                goto out_reset_current;
            }
        }

#define THROTTLE_PERIOD(d)                                              \
            (int64_t)((d)->arch.hvm_domain.params[HVM_PARAM_THROTTLE_PERIOD])
#define THROTTLE_RATE(d)                                                \
            (int64_t)((d)->arch.hvm_domain.params[HVM_PARAM_THROTTLE_RATE])
        if (THROTTLE_PERIOD(d)) {
            s_time_t period, rate, now;
            period = MILLISECS(THROTTLE_PERIOD(d));
            rate = MILLISECS(THROTTLE_RATE(d));
            now = NOW();
            v->vcpu_throttle_credit += (now - v->vcpu_throttle_last_time) *
                THROTTLE_RATE(d);
            if (v->vcpu_throttle_credit > period * THROTTLE_RATE(d))
                v->vcpu_throttle_credit = period * THROTTLE_RATE(d);
            v->vcpu_throttle_last_time = now;
            if (v->vcpu_throttle_credit < 0 &&
                v->runstate.state == RUNSTATE_running) {
                if (aligned_throttle_period > period - rate)
                    aligned_throttle_period = period - rate;
                now = aligned_throttle_period + now -
                    ((now + aligned_throttle_period) % aligned_throttle_period);
                set_timer(&v->vcpu_throttle_timer, now);
                atomic_write32(&vci->vci_host_halted, 1);
                if (work_pending_vcpu(v))
                    do_softirq_vcpu(v);
                if (vcpu_active_timer(&v->vcpu_throttle_timer)) {
                    vci->vci_run_mode = VCI_RUN_MODE_HALT;
                    ret = 0;
                    goto out_reset_current;
                }
                atomic_write32(&vci->vci_host_halted, 0);
            }
        }

        if (!vcpu_runnable(v) || v->runstate.state != RUNSTATE_running ||
            !v->context_loaded) {
            HVM_FUNCS(ctxt_switch_from, v);
            v->is_running = 0;

            while ((v->runstate.state >= RUNSTATE_blocked &&
                    (({ vcpu_schedule_lock_irq(v); 1; }))) ||
                   !schedule_vcpu(v)) {
                if (v->runstate.state >= RUNSTATE_blocked)
                    v->need_hvm_resume = 1;

                if (!vci->vci_runnable) {
                    vcpu_schedule_unlock_irq(v);
                    goto out_reset_current;
                }
                if (work_pending_vcpu(v)) {
                    vcpu_schedule_unlock_irq(v);
                    do_softirq_vcpu(v);
                    goto again;
                } else {
                    perfc_incr(hostsched_halt_vm);
                    atomic_write32(&vci->vci_host_halted, 1);
                    vcpu_schedule_unlock_irq(v);
                    if (!work_pending_vcpu(v) &&
                        current->runstate.state >= RUNSTATE_blocked) {
                        switch (vcpu_idle_tasklet_work(v)) {
                        case -EPREEMPT:
                            vci->vci_run_mode = VCI_RUN_MODE_IDLE_WORK;
                            ret = 0;
                            goto out_reset_current;
                        case -EAGAIN:
                            vci->vci_run_mode = VCI_RUN_MODE_IDLE_WORK;
                            break;
                        default:
                            vci->vci_run_mode = VCI_RUN_MODE_HALT;
                            break;
                        }
                        if (!work_pending_vcpu(v) &&
                            current->runstate.state >= RUNSTATE_blocked) {
                            ret = 0;
                            goto out_reset_current;
                        }
                    }
                    atomic_write32(&vci->vci_host_halted, 0);
                }
            }

            HVM_FUNCS(ctxt_switch_to, v);
        }

        if (!vci->vci_runnable)
            goto out_reset_current;

        if (v->need_hvm_resume)
            hvm_do_resume(v);
        v->need_hvm_resume = 0;
        hvm_do_resume_trap(v);

        if (!vci->vci_runnable)
            goto out_reset_current;

        hvm_execute(v);

        if (THROTTLE_PERIOD(d)) {
            s_time_t period, now;
            period = MILLISECS(THROTTLE_PERIOD(d));
            now = NOW();
            if (now - v->vcpu_throttle_last_time >= period)
                v->vcpu_throttle_credit += period *
                    (THROTTLE_RATE(d) - THROTTLE_PERIOD(d));
            else
                v->vcpu_throttle_credit += (now - v->vcpu_throttle_last_time) *
                    (THROTTLE_RATE(d) - THROTTLE_PERIOD(d));
            v->vcpu_throttle_last_time = now;
        }
    }

  out_reset_current:
    hvm_do_suspend(v);
    HVM_FUNCS(ctxt_switch_from, v);
    v->is_running = 0;
    _end_execution(NULL);

  out:
    assert_xcr0_state(XCR0_STATE_HOST);
    if (d)
        put_domain(d);
    return ret;
}

intptr_t UXEN_INTERFACE_FN(
__uxen_run_vcpu)(uint32_t domid, uint32_t vcpuid)
{
    intptr_t ret;

    set_stack_top();
    ret = do_run_vcpu(domid, vcpuid);

    return ret;
}

intptr_t
do_destroy_vm(xen_domain_handle_t vm_uuid)
{
    struct domain *d;
    struct vcpu *v;
    int ret = -ENOENT;

    d = rcu_lock_domain_by_uuid(vm_uuid, UUID_HANDLE);
    printk("%s: dom:%p\n", __FUNCTION__, d);
    if (d == NULL)
        goto out;

    for_each_vcpu(d, v) {
        cpumask_clear_cpu(v->processor, v->domain->domain_dirty_cpumask);
        cpumask_clear_cpu(v->processor, v->vcpu_dirty_cpumask);
    }

    while (!domctl_lock_acquire())
        cpu_relax();

    ret = domain_kill(d);

    domctl_lock_release();

    rcu_unlock_domain(d);

  out:
    return ret;
}

intptr_t UXEN_INTERFACE_FN(
__uxen_destroy_vm)(xen_domain_handle_t vm_uuid)
{
    int ret;

    if (!dom0 || !dom0->vcpu)
        return -ENOENT;

    set_stack_top();
    uxen_set_current(dom0->vcpu[smp_processor_id()]);
    hvm_cpu_on();

    ret = do_destroy_vm(vm_uuid);

    end_execution();

    return ret;
}

void UXEN_INTERFACE_FN(
__uxen_shutdown_xen)(void)
{

    if (!dom0 || !dom0->vcpu)
        return;

    set_stack_top();
    uxen_set_current(dom0->vcpu[smp_processor_id()]);
    hvm_cpu_on();

    console_start_sync();

    cpumask_copy(&cpu_down_map,&cpu_online_map);

    on_selected_cpus(&cpu_online_map, do_hvm_cpu_down, NULL, 0);

    printk("waiting to bring all cpus home\n");
    while (!cpumask_empty(&cpu_down_map))
        rep_nop();

    printk("clearing cpu_online_map\n");
    cpumask_clear(&cpu_online_map);

    free_dom0();

    end_execution();

    /* freeing host pages makes dom0 current invalid */
    free_all_host_pages();
}

static void
do_hvm_cpu_down(void *arg)
{

    hvm_cpu_down();
    cpumask_test_and_clear_cpu(smp_processor_id(), &cpu_down_map);
}

void UXEN_INTERFACE_FN(
__uxen_suspend_xen_prepare)(void)
{
    struct domain *d;

    if (!dom0 || !dom0->vcpu)
        return;

    set_stack_top();
    uxen_set_current(dom0->vcpu[smp_processor_id()]);
    hvm_cpu_on();
    current->is_privileged = 1;

    rcu_read_lock(&domlist_read_lock);
    for_each_domain(d)
        if (d != dom0)
            domain_pause_for_suspend(d);
    rcu_read_unlock(&domlist_read_lock);

    current->is_privileged = 0;
    end_execution();
}

void UXEN_INTERFACE_FN(
__uxen_suspend_xen)(void)
{

    if (!dom0 || !dom0->vcpu)
        return;

    uxen_set_current(dom0->vcpu[smp_processor_id()]);
    current->is_privileged = 1;

    cpumask_copy(&cpu_down_map,&cpu_online_map);

    on_selected_cpus(&cpu_online_map, do_hvm_cpu_down, NULL, 0);

    printk("waiting to bring all cpus home\n");
    while (!cpumask_empty(&cpu_down_map))
        rep_nop();

    suspend_platform_time();

    current->is_privileged = 0;
    uxen_set_current(NULL); /* not end_execution, do not process rcu */
}

static cpumask_t hvm_cpu_up_mask;

void
do_hvm_cpu_up(void *arg)
{

    hvm_cpu_up(hvmon_default);
    mb();
    cpumask_clear_cpu(smp_processor_id(), &hvm_cpu_up_mask);
}

void UXEN_INTERFACE_FN(
__uxen_resume_xen)(void)
{
    struct domain *d;

    if (!dom0 || !dom0->vcpu)
        return;

    set_stack_top();
    uxen_set_current(dom0->vcpu[smp_processor_id()]);
    current->is_privileged = 1;

    resume_platform_time();

    cpumask_copy(&hvm_cpu_up_mask, &cpu_online_map);

    /* use send_IPI_mask directly with dedicated vector, to avoid
     * interactions with on_selected_cpus locks and skip processing
     * rcu/softirq work */
    send_IPI_mask(&hvm_cpu_up_mask, UXEN_RESUME_VECTOR);
    local_irq_disable();
    do_hvm_cpu_up(NULL);
    local_irq_enable();

    while (!cpumask_empty(&hvm_cpu_up_mask))
        cpu_relax();

    rcu_read_lock(&domlist_read_lock);
    for_each_domain(d)
        if (d != dom0)
            domain_unpause_for_suspend(d);
    rcu_read_unlock(&domlist_read_lock);

    current->is_privileged = 0;
    hvm_cpu_off();
    uxen_set_current(NULL); /* not end_execution, do not process rcu */
}

typedef unsigned long uxen_hypercall_t(unsigned long, unsigned long,
				       unsigned long, unsigned long,
				       unsigned long, unsigned long);

#define HYPERCALL(x)                                                   \
    case __HYPERVISOR_ ## x: {                                         \
        uxen_hypercall_t *uh = (uxen_hypercall_t *)do_ ## x;           \
        return uh(                                                     \
            uhd->uhd_arg[0], uhd->uhd_arg[1], uhd->uhd_arg[2],         \
            uhd->uhd_arg[3], uhd->uhd_arg[4], uhd->uhd_arg[5]);        \
    }

intptr_t
do_hypercall(struct uxen_hypercall_desc *uhd)
{

    this_cpu(hypercall_args) = uhd;

    switch (uhd->uhd_op) {
        HYPERCALL(memory_op);
        HYPERCALL(xen_version);
        HYPERCALL(hvm_op);
        HYPERCALL(domctl);
        HYPERCALL(sched_op);
        HYPERCALL(event_channel_op);
        HYPERCALL(v4v_op);
        HYPERCALL(sysctl);
    }

    return -ENOSYS;
}

intptr_t UXEN_INTERFACE_FN(
__uxen_hypercall)(struct uxen_hypercall_desc *uhd,
                  struct vm_info_shared *target_vmis,
                  void *user_access_opaque,
                  uint32_t privileged)
{
    intptr_t ret;

    if (!dom0 || !dom0->vcpu)
        return -ENOENT;

    set_stack_top();
    uxen_set_current(dom0->vcpu[smp_processor_id()]);
    hvm_cpu_on();
    if (privileged & UXEN_UNRESTRICTED_ACCESS_HYPERCALL)
        current->always_access_ok = 1;
    if (privileged & UXEN_ADMIN_HYPERCALL)
        current->is_privileged = 1;
    if (privileged & UXEN_SYSTEM_HYPERCALL)
        current->is_sys_privileged = 1;
    if (target_vmis) {
        if (privileged & UXEN_VMI_OWNER)
            current->target_vmis_owner = 1;
        current->target_vmis = target_vmis;
    }
    current->user_access_opaque = user_access_opaque;

    ret = do_hypercall(uhd);

    current->user_access_opaque = NULL;
    current->target_vmis = NULL;
    current->target_vmis_owner = 0;
    current->is_sys_privileged = 0;
    current->is_privileged = 0;
    current->always_access_ok = 0;
    end_execution();

    return ret;
}

/* adapted from arch/x86/domain_build.c:alloc_dom0_vcpu0 */
struct vcpu * __init
alloc_dom0_vcpu0(void)
{
    int i;

    dom0->max_vcpus = num_present_cpus();
    dom0->vcpu = dom0->extra_1->vcpu;

    for (i = 0; i < dom0->max_vcpus; i++)
	if (!alloc_vcpu(dom0, i, i))
	    return NULL;
    return dom0->vcpu[0];
}

static void
free_dom0(void)
{
    if (!dom0)
        return;

    if (dom0->shared_info) {
        free_domheap_page(virt_to_page(dom0->shared_info));
        free_xenheap_page(dom0->shared_info);
    }
}

void UXEN_INTERFACE_FN(
__uxen_add_heap_memory)(uint64_t start, uint64_t end)
{

#ifdef __i386__
    if (!idle_vcpu[smp_processor_id()])
        return;

    set_stack_top();
    uxen_set_current(idle_vcpu[smp_processor_id()]);
    hvm_cpu_on();

    init_hidden_pages(ALIGN_PAGE_UP(start), ALIGN_PAGE_DOWN(end));

    end_execution();
#endif
}

intptr_t UXEN_INTERFACE_FN(
__uxen_handle_keypress)(unsigned char key)
{

    if (!idle_vcpu[smp_processor_id()])
        return -ENOENT;

    set_stack_top();
    uxen_set_current(idle_vcpu[smp_processor_id()]);
    hvm_cpu_on();

    handle_keypress(key, NULL);

    end_execution();

    return 0;
}

void UXEN_INTERFACE_FN(
__uxen_run_idle_thread)(uint32_t had_timeout)
{

    if (!idle_vcpu[smp_processor_id()])
        return;

    set_stack_top();
    uxen_set_current(idle_vcpu[smp_processor_id()]);
    hvm_cpu_on();

    if (_uxen_info.ui_unixtime_generation != unixtime_generation)
        update_xen_time();

    do_run_idle_thread(had_timeout);

    end_execution();
}

static atomic_t cpu_count = ATOMIC_INIT(0);

struct rcu_barrier_data {
    struct rcu_head head;
    atomic_t *cpu_count;
};

static void rcu_barrier_callback(struct rcu_head *head)
{
    struct rcu_barrier_data *data = container_of(
        head, struct rcu_barrier_data, head);
    atomic_dec(data->cpu_count);
}

static DEFINE_PER_CPU(struct rcu_barrier_data, flush_rcu_data);

intptr_t UXEN_INTERFACE_FN(
__uxen_flush_rcu)(uint32_t complete)
{
    int cpu = host_processor_id();

    set_stack_top();
    uxen_set_current(idle_vcpu[smp_processor_id()]);
    hvm_cpu_on();

    if (!complete) {
        if (!cpu)
            atomic_set(&cpu_count, cpumask_weight(&cpu_online_map));
        this_cpu(flush_rcu_data).cpu_count = &cpu_count;
        call_rcu(&this_cpu(flush_rcu_data).head, rcu_barrier_callback);
    }

    if (atomic_read(this_cpu(flush_rcu_data).cpu_count)) {
        if (rcu_pending(cpu))
            rcu_check_callbacks(cpu);
        process_pending_softirqs();
    }

    hvm_cpu_off();
    uxen_set_current(NULL);
    return !!atomic_read(this_cpu(flush_rcu_data).cpu_count);
}

/* from common/kernel.c */
static void __init
assign_integer_param(struct kernel_param *param, uint64_t val)
{
    switch (param->len) {
    case sizeof(uint8_t):
        *(uint8_t *)param->var = val;
        break;
    case sizeof(uint16_t):
        *(uint16_t *)param->var = val;
        break;
    case sizeof(uint32_t):
        *(uint32_t *)param->var = val;
        break;
    case sizeof(uint64_t):
        *(uint64_t *)param->var = val;
        break;
    default:
        BUG();
    }
}

void __init
options_parse(const struct uxen_init_desc *init_options,
              uint64_t init_options_size)
{
    struct kernel_param *param;
    uint64_t mask;

    /* printk("setup start %p end %p sizeof %lx\n", &__setup_start, */
    /*        &__setup_end, sizeof(struct kernel_param)); */
    for (param = &__setup_start; param < &__setup_end; param++) {
        if (!param->opt_mask)
            continue;
        /* printk("checking option %s: ", param->name); */
        mask = *(uint64_t *)((uintptr_t)init_options + param->mask_offset);
        if (!(mask & param->opt_mask)) {
            /* printk("not present\n"); */
            continue;
        }
        if (param->value_offset + param->value_size > init_options_size) {
            /* printk("out of bounds\n"); */
            continue;
        }
        switch (param->type) {
        case OPT_STR:
            strllcpy(param->var, param->len,
                     (char *)((uintptr_t)init_options + param->value_offset),
                     param->value_size);
            /* printk("set to %s\n", (char *)param->var); */
            break;
        case OPT_BOOL:
        case OPT_INVBOOL:
            assign_integer_param(param, *(uint64_t *)((uintptr_t)init_options +
                                                      param->value_offset));
            /* printk("set to %d\n", *(uint8_t *)param->var); */
            break;
        case OPT_UINT:
            assign_integer_param(param, *(uint64_t *)((uintptr_t)init_options +
                                                      param->value_offset));
            /* printk("set to %" PRIx64 "\n", *(uint64_t *)param->var); */
            break;

        default:
            /* printk("not handled\n"); */
            break;
        }
    }
}

/* adapted from arch/x86/traps.c:do_invalid_op */
intptr_t UXEN_INTERFACE_FN(
__uxen_process_ud2)(struct cpu_user_regs *regs)
{
    struct bug_frame *bug;
    struct bug_frame_str *bug_str;
    const char *p, *filename, *predicate, *eip = (char *)regs->eip;
    uint64_t fixup;
    int id, lineno;

    // printk("eip is %S\n", (printk_symbol)eip);

    bug = (struct bug_frame *)eip;
    if (memcmp(bug->ud2, "\xf\xb", sizeof(bug->ud2)) ||
        (bug->ret != 0xc2))
        goto die;
    eip += sizeof(*bug);

    /* Decode first pointer argument. */
    bug_str = (struct bug_frame_str *)eip;
    if (bug_str->mov != 0xbc)
        goto die;
    p = bug_str(*bug_str, eip);
    eip += sizeof(*bug_str);

    id = bug->id & 7;

    if ( id == BUGFRAME_run_fn )
    {
        void (*fn)(struct cpu_user_regs *) = (void *)p;
        (*fn)(regs);
        regs->eip = (unsigned long)eip;
        return 0;
    }

    /* WARN, BUG or ASSERT: decode the filename pointer and line number. */
    filename = p;
    lineno = bug->id >> 3;

    if ( id == BUGFRAME_warn )
    {
        show_execution_state(regs);
        UI_HOST_CALL(ui_printf, NULL, "Xen WARN at %.50s:%d\n", filename,
                     lineno);
        regs->eip = (unsigned long)eip;
        return 0;
    }

    if ( id == BUGFRAME_bug )
    {
        show_execution_state(regs);
        UI_HOST_CALL(ui_printf, NULL, "Xen BUG at %.50s:%d\n", filename,
                     lineno);
        return 1;
    }

    if ( id == BUGFRAME_abort )
    {
#ifndef NDEBUG
        show_stack(regs);
        UI_HOST_CALL(ui_printf, NULL, "Xen ABORT at %.50s:%d\n", filename,
                     lineno);
#endif
        return 2;
    }

    /* ASSERT: decode the predicate string pointer. */
    ASSERT(id == BUGFRAME_assert);
    bug_str = (struct bug_frame_str *)eip;
    if (bug_str->mov != 0xbc)
        goto die;
    predicate = bug_str(*bug_str, eip);
    eip += sizeof(*bug_str);

    show_execution_state(regs);
    UI_HOST_CALL(ui_printf, NULL, "Assertion '%s' failed at %.50s:%d\n",
                 predicate, filename, lineno);
    return 1;

 die:
    if ( (fixup = search_exception_table(regs->eip)) != 0 )
    {
        regs->eip = fixup;
        return 0;
    }
    show_execution_state(regs);
    UI_HOST_CALL(ui_printf, NULL, "FATAL TRAP: vector = %d (invalid opcode)\n",
                 TRAP_invalid_op);
    return 1;
}

intptr_t UXEN_INTERFACE_FN(
__uxen_lookup_symbol)(uint64_t address, char *buffer, uint32_t buflen)
{
    const char *name;
    unsigned long offset, size, flags;

    static DEFINE_SPINLOCK(lock);
    static char namebuf[KSYM_NAME_LEN+1];
#if 0
#define BUFFER_SIZE sizeof("%s+%ld/%ld [%s]") + KSYM_NAME_LEN + \
      2*(BITS_PER_LONG*3/10) + 1
    static char buffer[BUFFER_SIZE];
#else
#define BUFFER_SIZE buflen
#endif

    spin_lock_irqsave(&lock, flags);

    name = symbols_lookup(address, &size, &offset, namebuf);

    if (!name)
        snprintf(buffer, BUFFER_SIZE, "???");
    else
        snprintf(buffer, BUFFER_SIZE, "%s+%ld/%ld", name, offset, size);

    spin_unlock_irqrestore(&lock, flags);

    return name ? 0 : 1;
}
