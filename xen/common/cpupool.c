/******************************************************************************
 * cpupool.c
 * 
 * Generic cpupool-handling functions.
 *
 * Cpupools are a feature to have configurable scheduling domains. Each
 * cpupool runs an own scheduler on a dedicated set of physical cpus.
 * A domain is bound to one cpupool at any time, but it can be moved to
 * another cpupool.
 *
 * (C) 2009, Juergen Gross, Fujitsu Technology Solutions
 */

#include <xen/lib.h>
#include <xen/init.h>
#include <xen/cpumask.h>
#include <xen/percpu.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/cpu.h>

/*
 * add a new domain to a cpupool
 * possible failures:
 * - pool does not exist
 * - no cpu assigned to pool
 */
int cpupool_add_domain(struct domain *d, int poolid)
{
    if ( poolid != CPUPOOLID_NONE && poolid )
        WARN();
    return 0;
}

/*
 * remove a domain from a cpupool
 */
void cpupool_rm_domain(struct domain *d)
{
    ASSERT( d->cpupool == NULL );
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
