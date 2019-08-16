/******************************************************************************
 * Arch-specific sysctl.c
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <public/sysctl.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/processor.h>
#include <asm/numa.h>
#include <xen/nodemask.h>
#include <xen/cpu.h>
#include <xsm/xsm.h>

long arch_do_sysctl(
    struct xen_sysctl *sysctl, XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl)
{
    uint64_t free_pages = 0;
    int cpu;
    long ret = 0;

    switch ( sysctl->cmd )
    {
    case XEN_SYSCTL_log_ratelimit:
        change_log_limits(sysctl->u.log_ratelimit.ms,
                          sysctl->u.log_ratelimit.burst);
        break;
    case XEN_SYSCTL_physinfo:
    {
        xen_sysctl_physinfo_t *pi = &sysctl->u.physinfo;

        ret = xsm_physinfo();
        if ( ret )
            break;


        memset(pi, 0, sizeof(*pi));
        pi->threads_per_core = 0;
        pi->cores_per_socket = 0;
        pi->nr_cpus = num_online_cpus();
        pi->nr_nodes = num_online_nodes();
        pi->max_node_id = MAX_NUMNODES-1;
        pi->max_cpu_id = nr_cpu_ids - 1;
        pi->used_pages = atomic_read(&host_pages_allocated);
        for_each_present_cpu(cpu)
            free_pages += _uxen_info.ui_free_pages[cpu].count;
        pi->free_pages = free_pages;
        pi->total_pages = pi->used_pages + pi->free_pages;
#ifdef __i386__
        pi->used_hidden_pages = atomic_read(&hidden_pages_allocated);
        pi->free_hidden_pages = atomic_read(&hidden_pages_available) -
            pi->used_hidden_pages;
        pi->total_hidden_pages = atomic_read(&hidden_pages_available);
#else  /* __i386__ */
        pi->used_hidden_pages = 0;
        pi->free_hidden_pages = 0;
        pi->total_hidden_pages = 0;
#endif /* __i386__ */
        pi->scrub_pages = 0;
        pi->cpu_khz = cpu_khz;
        memcpy(pi->hw_cap, boot_cpu_data.x86_capability, NCAPINTS*4);
        if ( hvm_enabled )
            pi->capabilities |= XEN_SYSCTL_PHYSCAP_hvm;

        if ( copy_to_guest(u_sysctl, sysctl, 1) )
            ret = -EFAULT;
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
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
