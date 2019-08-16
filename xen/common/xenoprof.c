/*
 * Copyright (C) 2005 Hewlett-Packard Co.
 * written by Aravind Menon & Jose Renato Santos
 *            (email: xenoprof@groups.hp.com)
 *
 * arch generic xenoprof and IA64 support.
 * dynamic map/unmap xenoprof buffer support.
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 */

#ifndef COMPAT
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/xenoprof.h>
#include <public/xenoprof.h>
#include <xen/paging.h>
#include <xsm/xsm.h>
#include <xen/hypercall.h>

static DEFINE_SPINLOCK(pmu_owner_lock);
int pmu_owner = 0;
int pmu_hvm_refcount = 0;

int acquire_pmu_ownership(int pmu_ownship)
{
    spin_lock(&pmu_owner_lock);
    if ( pmu_owner == PMU_OWNER_NONE )
    {
        pmu_owner = pmu_ownship;
        goto out;
    }

    if ( pmu_owner == pmu_ownship )
        goto out;

    spin_unlock(&pmu_owner_lock);
    return 0;
 out:
    if ( pmu_owner == PMU_OWNER_HVM )
        pmu_hvm_refcount++;
    spin_unlock(&pmu_owner_lock);
    return 1;
}

void release_pmu_ownship(int pmu_ownship)
{
    spin_lock(&pmu_owner_lock);
    if ( pmu_ownship == PMU_OWNER_HVM )
        pmu_hvm_refcount--;
    if ( !pmu_hvm_refcount )
        pmu_owner = PMU_OWNER_NONE;
    spin_unlock(&pmu_owner_lock);
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
