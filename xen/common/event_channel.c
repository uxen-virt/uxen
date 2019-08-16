/******************************************************************************
 * event_channel.c
 * 
 * Event notifications from VIRQs, PIRQs, and other domains.
 * 
 * Copyright (c) 2003-2006, K A Fraser.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/irq.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <asm/current.h>

#include <public/xen.h>
#include <public/event_channel.h>
#include <xsm/xsm.h>

#define bucket_from_port(d,p) \
    ((d)->evtchn[(p)/EVTCHNS_PER_BUCKET])
#define port_is_valid(d,p)    \
    (((p) >= 0) && ((p) < MAX_EVTCHNS(d)) && \
     (bucket_from_port(d,p) != NULL))
#define evtchn_from_port(d,p) \
    (&(bucket_from_port(d,p))[(p)&(EVTCHNS_PER_BUCKET-1)])

#define ERROR_EXIT_DOM(_errno, _dom)                                \
    do {                                                            \
        gdprintk(XENLOG_WARNING,                                    \
                 "EVTCHNOP failure: vm%u, error %d\n",              \
                 (_dom)->domain_id, (_errno));                      \
        rc = (_errno);                                              \
        goto out;                                                   \
    } while ( 0 )


static int get_free_port(struct domain *d)
{
    struct evtchn *chn;
    int            port;

    if ( d->is_dying )
        return -EINVAL;

    for ( port = 0; port_is_valid(d, port); port++ )
        if ( evtchn_from_port(d, port)->state == ECS_FREE )
            return port;

    if ( port == MAX_EVTCHNS(d) )
        return -ENOSPC;

    BUILD_BUG_ON(sizeof(struct evtchn) * EVTCHNS_PER_BUCKET > PAGE_SIZE);
    chn = (struct evtchn *)alloc_xenheap_page();
    if ( unlikely(chn == NULL) )
        return -ENOMEM;
    clear_page(chn);
    bucket_from_port(d, port) = chn;

    return port;
}


static long evtchn_bind_host(evtchn_bind_host_t *bind)
{
    struct evtchn *chn;
    struct domain *ld = current->domain, *rd;
    int            port= bind->remote_port;
    long           rc;

    if ( !bind->host_opaque )
        return -EINVAL;

    if ( ld != dom0 )
        return -EPERM;

    if ( (rd = rcu_lock_domain_by_id(bind->remote_dom)) == NULL )
        return -ESRCH;

    spin_lock(&rd->event_lock);

    if ( !port_is_valid(rd, port) )
        ERROR_EXIT_DOM(-EINVAL, rd);
    chn = evtchn_from_port(rd, port);
    if ( (chn->state != ECS_UNBOUND) ||
         (chn->u.unbound.remote_domid != ld->domain_id) )
        ERROR_EXIT_DOM(-EINVAL, rd);

    chn->u.host.host_opaque = bind->host_opaque;
    chn->state = ECS_HOST;

    rc = 0;
 out:
    spin_unlock(&rd->event_lock);

    rcu_unlock_domain(rd);

    return rc;
}


static long __evtchn_close(struct domain *d1, int port1)
{
    struct evtchn *chn1;
    long           rc = 0;

    spin_lock(&d1->event_lock);

    if ( !port_is_valid(d1, port1) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn1 = evtchn_from_port(d1, port1);

    /* Guest cannot close a Xen-attached event channel. */
    if ( unlikely(chn1->consumer_is_xen) )
    {
        rc = -EINVAL;
        goto out;
    }

    switch ( chn1->state )
    {
    case ECS_FREE:
    case ECS_RESERVED:
        rc = -EINVAL;
        goto out;

    case ECS_UNBOUND:
        break;

    case ECS_HOST:
        break;

    default:
        BUG();
    }

    /* Clear pending event to avoid unexpected behavior on re-bind. */
    clear_bit(port1, &shared_info(d1, evtchn_pending));

    /* Reset binding to vcpu0 when the channel is freed. */
    chn1->state          = ECS_FREE;
    chn1->notify_vcpu_id = 0;

    xsm_evtchn_close_post(chn1);

 out:

    spin_unlock(&d1->event_lock);

    return rc;
}


void send_guest_global_virq(struct domain *d, int virq)
{
    if (d != NULL)
        printk("send_guest_global_virq vm%u virq %d\n", d->domain_id, virq);
}

int send_guest_pirq(struct domain *d, const struct pirq *pirq)
{
    BUG(); return 0;
}


long do_event_channel_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    long rc;

    switch ( cmd )
    {

    case EVTCHNOP_bind_host: {
        struct evtchn_bind_host bind_host;
        if ( copy_from_guest(&bind_host, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_host(&bind_host);
        if ( (rc == 0) && (copy_to_guest(arg, &bind_host, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}


int alloc_unbound_xen_event_channel(
    struct vcpu *local_vcpu, domid_t remote_domid)
{
    struct evtchn *chn;
    struct domain *d = local_vcpu->domain;
    int            port;

    spin_lock(&d->event_lock);

    if ( (port = get_free_port(d)) < 0 )
        goto out;
    chn = evtchn_from_port(d, port);

    chn->state = ECS_UNBOUND;
    chn->consumer_is_xen = 1;
    chn->notify_vcpu_id = local_vcpu->vcpu_id;
    chn->u.unbound.remote_domid = remote_domid;

 out:
    spin_unlock(&d->event_lock);

    return port;
}


void free_xen_event_channel(
    struct vcpu *local_vcpu, int port)
{
    struct evtchn *chn;
    struct domain *d = local_vcpu->domain;
    int port_is_sane;

    spin_lock(&d->event_lock);

    if ( unlikely(d->is_dying) )
    {
        spin_unlock(&d->event_lock);
        return;
    }

    port_is_sane = port_is_valid(d, port);
    if (port_is_sane) {
        chn = evtchn_from_port(d, port);
        port_is_sane = chn->consumer_is_xen;
        if (port_is_sane)
            chn->consumer_is_xen = 0;
    }
    spin_unlock(&d->event_lock);

    if (port_is_sane)
        (void)__evtchn_close(d, port);
    else
         gdprintk(XENLOG_ERR, "attempt to free (bad) port %d, domain %d\n",
            port, d->domain_id);
}


void notify_via_xen_event_channel(struct domain *ld, int lport)
{
    struct evtchn *lchn = NULL;
    int port_is_sane = 1;

    spin_lock(&ld->event_lock);

    if ( unlikely(ld->is_dying) )
        goto out_unlock;

    port_is_sane = port_is_valid(ld, lport);
    if (port_is_sane) {
        lchn = evtchn_from_port(ld, lport);
        port_is_sane = lchn->consumer_is_xen;
    }
    if (!port_is_sane)
        goto out_unlock;

    if ( likely(lchn->state == ECS_HOST) )
    {
        hostsched_signal_event(ld->vcpu[lchn->notify_vcpu_id],
                               lchn->u.host.host_opaque);
        perfc_incr(signaled_event);
    } else
        /* DEBUG() */;

    out_unlock:
    spin_unlock(&ld->event_lock);

    if (!port_is_sane)
         gdprintk(XENLOG_ERR,
            "notify_via_xen_event_channel (bad) port %d, domain %d\n",
            lport, ld->domain_id);
}

void *
xen_event_channel_host_opaque(struct domain *ld, int lport)
{
    struct evtchn *lchn;
    void *opaque = NULL;

    spin_lock(&ld->event_lock);

    if (unlikely(ld->is_dying)) {
        spin_unlock(&ld->event_lock);
        return NULL;
    }

    ASSERT(port_is_valid(ld, lport));
    lchn = evtchn_from_port(ld, lport);
    ASSERT(lchn->consumer_is_xen);

    if (likely(lchn->state == ECS_HOST))
        opaque = lchn->u.host.host_opaque;

    spin_unlock(&ld->event_lock);
    return opaque;
}


int evtchn_init(struct domain *d)
{
    spin_lock_init(&d->event_lock);
    if ( get_free_port(d) != 0 )
        return -EINVAL;
    evtchn_from_port(d, 0)->state = ECS_RESERVED;

#if MAX_VIRT_CPUS > BITS_PER_LONG
    d->poll_mask = xmalloc_array(unsigned long, BITS_TO_LONGS(MAX_VIRT_CPUS));
    if ( !d->poll_mask )
        return -ENOMEM;
    bitmap_zero(d->poll_mask, MAX_VIRT_CPUS);
#endif

    return 0;
}


void evtchn_destroy(struct domain *d)
{
    int i;

    /* After this barrier no new event-channel allocations can occur. */
    BUG_ON(!d->is_dying);
    spin_barrier(&d->event_lock);

    /* Close all existing event channels. */
    for ( i = 0; port_is_valid(d, i); i++ )
    {
        evtchn_from_port(d, i)->consumer_is_xen = 0;
        (void)__evtchn_close(d, i);
    }

    /* Free all event-channel buckets. */
    spin_lock(&d->event_lock);
    for ( i = 0; i < NR_EVTCHN_BUCKETS; i++ )
    {
        free_xenheap_page(d->evtchn[i]);
        d->evtchn[i] = NULL;
    }
    spin_unlock(&d->event_lock);
}


void evtchn_destroy_final(struct domain *d)
{
#if MAX_VIRT_CPUS > BITS_PER_LONG
    xfree(d->poll_mask);
    d->poll_mask = NULL;
#endif
}


static void domain_dump_evtchn_info(struct domain *d)
{
    unsigned int port;

    bitmap_scnlistprintf(keyhandler_scratch, sizeof(keyhandler_scratch),
                         d->poll_mask, d->max_vcpus);
    printk("Event channel information for vm%u:\n"
           "Polling vCPUs: {%s}\n"
           "    port [p/m]\n", d->domain_id, keyhandler_scratch);

    spin_lock(&d->event_lock);

    for ( port = 1; port < MAX_EVTCHNS(d); ++port )
    {
        const struct evtchn *chn;

        if ( !port_is_valid(d, port) )
            continue;
        chn = evtchn_from_port(d, port);
        if ( chn->state == ECS_FREE )
            continue;

        printk("    %4u [%d/%d]: s=%d n=vm%u.%u",
               port,
               !!test_bit(port, &shared_info(d, evtchn_pending)),
               !!test_bit(port, &shared_info(d, evtchn_mask)),
               chn->state, d->domain_id, chn->notify_vcpu_id);
        switch ( chn->state )
        {
        case ECS_UNBOUND:
            printk(" d=vm%u", chn->u.unbound.remote_domid);
            break;
        case ECS_HOST:
            printk(" h=%p", chn->u.host.host_opaque);
            break;
        }
        printk(" x=%d\n", chn->consumer_is_xen);
    }

    spin_unlock(&d->event_lock);
}

static void dump_evtchn_info(unsigned char key)
{
    struct domain *d;

    printk("'%c' pressed -> dumping event-channel info\n", key);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
        domain_dump_evtchn_info(d);

    rcu_read_unlock(&domlist_read_lock);
}

static struct keyhandler dump_evtchn_info_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_evtchn_info,
    .desc = "dump evtchn info"
};

static int __init dump_evtchn_info_key_init(void)
{
    register_keyhandler('e', &dump_evtchn_info_keyhandler);
    return 0;
}
__initcall(dump_evtchn_info_key_init);

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
