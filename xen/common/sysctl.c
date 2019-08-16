/******************************************************************************
 * sysctl.c
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <asm/current.h>
#include <xen/hypercall.h>
#include <public/sysctl.h>
#include <asm/numa.h>
#include <xen/nodemask.h>
#include <xsm/xsm.h>
#include <xen/pmstat.h>

long do_sysctl(XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl)
{
    long ret = 0;
    struct xen_sysctl curop, *op = &curop;
    static DEFINE_SPINLOCK(sysctl_lock);

    if ( copy_from_guest(op, u_sysctl, 1) )
        return -EFAULT;

    switch ( op->cmd )
    {
    /* Sysctls that do **not** require privilege to execute. */
    case XEN_SYSCTL_physinfo:
        break;

    /* The rest do, by default. */
    default:
        if ( !IS_PRIV(current->domain) )
            return -EPERM;

        break;
    }

    if ( op->interface_version != XEN_SYSCTL_INTERFACE_VERSION )
        return -EACCES;

    /*
     * Trylock here avoids deadlock with an existing sysctl critical section
     * which might (for some current or future reason) want to synchronise
     * with this vcpu.
     */
    while ( !spin_trylock(&sysctl_lock) )
#ifdef __UXEN_todo__
        if ( hypercall_preempt_check() )
            return hypercall_create_continuation(
                __HYPERVISOR_sysctl, "h", u_sysctl);
#else  /* __UXEN_todo__ */
        cpu_relax();
#endif  /* __UXEN_todo__ */

    switch ( op->cmd )
    {

    default:
        ret = arch_do_sysctl(op, u_sysctl);
        break;
    }

    spin_unlock(&sysctl_lock);

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
