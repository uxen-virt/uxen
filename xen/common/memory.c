/******************************************************************************
 * memory.c
 *
 * Code to handle memory-related requests.
 *
 * Copyright (c) 2003-2004, B Dragovic
 * Copyright (c) 2003-2005, K A Fraser
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
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/paging.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/errno.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#ifdef CONFIG_X86
# include <asm/p2m.h>
#endif
#include <xen/numa.h>
#include <public/memory.h>
#include <xsm/xsm.h>
#include <xen/trace.h>

struct memop_args {
    /* INPUT */
    struct domain *domain;     /* Domain to be affected. */
    XEN_GUEST_HANDLE(xen_pfn_t) extent_list; /* List of extent base addrs. */
    unsigned int nr_extents;   /* Number of extents to allocate or free. */
    unsigned int extent_order; /* Size of each extent. */
    unsigned int memflags;     /* Allocation flags. */
    XEN_GUEST_HANDLE(uint8) buffer;
    unsigned int buffer_pos;

    /* INPUT/OUTPUT */
    unsigned int nr_done;    /* Number of extents processed so far. */
    int          preempted;  /* Was the hypercall preempted? */
};

static void populate_physmap(struct memop_args *a)
{
    struct page_info *page;
    unsigned long i;
    xen_pfn_t gpfn, mfn;
    struct domain *d = a->domain, *curr_d = current->domain;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( a->extent_order != 0 /* && !(a->memflags & MEMF_populate_on_demand) */ )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, a->extent_list, i, 1)) )
            goto out;

        if ( a->memflags & MEMF_populate_on_demand )
        {
            /* Disallow populating PoD pages on oneself. */
            if ( d == curr_d )
                goto out;

            if (guest_physmap_mark_populate_on_demand
                (d, gpfn, a->extent_order, _mfn(SHARED_ZERO_MFN)) < 0)
                goto out;
        }
        else if (a->memflags & MEMF_populate_from_buffer_compressed)
        {
            if (a->extent_order) {
                gdprintk(XENLOG_INFO, "order=%d not supported for extent:"
                         " id=vm%u memflags=%x (%ld of %d)\n",
                         a->extent_order, d->domain_id, a->memflags,
                         i, a->nr_extents);
                goto out;
            }
            if (guest_physmap_mark_populate_on_demand_contents(
                    d, gpfn, a->buffer, &a->buffer_pos) < 0)
                goto out;
        }
        else
        {
            if (a->extent_order) {
                gdprintk(XENLOG_INFO, "order=%d not supported for extent:"
                         " id=vm%u memflags=%x (%ld of %d)\n",
                         a->extent_order, d->domain_id, a->memflags,
                         i, a->nr_extents);
                goto out;
            }
            page = alloc_domheap_pages(d, a->extent_order, a->memflags);
            if ( unlikely(page == NULL) ) 
            {
                    gdprintk(XENLOG_INFO, "Could not allocate order=%d extent:"
                             " id=vm%u memflags=%x (%ld of %d)\n",
                             a->extent_order, d->domain_id, a->memflags,
                             i, a->nr_extents);
                goto out;
            }

            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, gpfn, mfn);
            put_page(page);

            if ( !paging_mode_translate(d) )
            {
                /* Inform the domain of the new page's machine address. */ 
                if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                    goto out;
            }

            if (a->memflags & MEMF_populate_from_buffer) {
                void *va;
                va = map_domain_page(mfn);
                if (unlikely(__copy_from_guest_offset(va, a->buffer,
                                                      i << PAGE_SHIFT,
                                                      PAGE_SIZE))) {
                    unmap_domain_page(va);
                    goto out;
                }
                unmap_domain_page(va);
            }
        }
    }

out:
    a->nr_done = i;
}

static int
capture_memory(struct domain *d, xen_memory_capture_t *capture)
{
    xen_memory_capture_gpfn_info_t gi;
    struct domain *source_d;
    struct page_info *page;
    uint8_t *data;
    uint32_t size;
    uint32_t offset = 0;
    unsigned long mfn;
    p2m_type_t t;
    uint32_t gpfn, flags;
    int ret = 0;

    if (!guest_handle_subrange_okay(capture->gpfn_info_list, capture->nr_done,
                                    capture->nr_gpfns - 1))
        return -EFAULT;

    page = alloc_domheap_page(NULL, 0);
    if (!page)
        return -ENOMEM;
    data = __map_domain_page(page);

    while (!ret && capture->nr_done < capture->nr_gpfns) {
        /* XXX preempt check, ret = -EAGAIN */

        if (unlikely(__copy_from_guest_offset(&gi, capture->gpfn_info_list,
                                              capture->nr_done, 1))) {
            ret = -EFAULT;
            goto out;
        }

        gpfn = gi.gpfn;
        flags = gi.flags;
        gi.offset = -1;

        if (flags & XENMEM_MCGI_FLAGS_TEMPLATE) {
            if (!d->clone_of) {
                gi.type = XENMEM_MCGI_TYPE_NO_TEMPLATE;
                gi.offset = -1;
                ret = -EEXIST;
                goto next;
            }
            source_d = d->clone_of;
        } else
            source_d = d;

        mfn = mfn_x(get_gfn_contents(source_d, gpfn, &t, data, &size,
                                     !!(flags & XENMEM_MCGI_FLAGS_REMOVE_PFN)));
        if (mfn_zero_page(mfn)) {
            gi.type = XENMEM_MCGI_TYPE_ZERO;
            gi.offset = -1;
        } else if (is_xen_mfn(mfn)) {
            gi.type = XENMEM_MCGI_TYPE_XEN;
            gi.offset = -1;
        } else if (is_host_mfn(mfn)) {
            gi.type = XENMEM_MCGI_TYPE_HOST;
            gi.offset = -1;
        } else if (mfn_valid_page(mfn) || mfn_compressed_page(mfn)) {
            if (offset + size > capture->buffer_size) {
                gi.type = XENMEM_MCGI_TYPE_BUFFER_FULL;
                gi.offset = -1;
                ret = -ENOMEM;
                goto next;
            }
            if (unlikely(__copy_to_guest_offset(capture->buffer, offset,
                                                data, size))) {
                ret = -EFAULT;
                goto out;
            }
            gi.type = XENMEM_MCGI_TYPE_NORMAL;
            if (mfn_compressed_page(mfn))
                gi.type |= XENMEM_MCGI_TYPE_COMPRESSED;
            gi.offset = offset;
            offset += size;
        } else if (p2m_is_pod(t)) {
            gi.type = XENMEM_MCGI_TYPE_POD;
            gi.offset = -1;
        } else if (mfn_error_page(mfn)) {
            gi.type = XENMEM_MCGI_TYPE_ERROR;
            gi.offset = -1;
        } else {
            gi.type = XENMEM_MCGI_TYPE_NOT_PRESENT;
            gi.offset = -1;
        }
        put_gfn(source_d, gpfn);

      next:
        if (unlikely(__copy_to_guest_offset(capture->gpfn_info_list,
                                            capture->nr_done, &gi, 1))) {
            ret = -EFAULT;
            goto out;
        }

        if (!ret)
            capture->nr_done++;
    }
  out:
    if (data)
        unmap_domain_page(data);
    if (page)
        free_domheap_page(page);
    return ret;
}

int guest_remove_page(struct domain *d, unsigned long gmfn)
{
    struct page_info *page;
#ifdef CONFIG_X86
    p2m_type_t p2mt;
#endif
    unsigned long mfn;

#ifdef CONFIG_X86
    mfn = mfn_x(get_gfn(d, gmfn, &p2mt)); 
#else
    mfn = gmfn_to_mfn(d, gmfn);
#endif
    if ( unlikely(!mfn_valid(mfn)) )
    {
        put_gfn(d, gmfn);
        gdprintk(XENLOG_INFO, "vm%u page number %lx invalid\n",
                 d->domain_id, gmfn);
        return 0;
    }
            
    page = mfn_to_page(mfn);
    if ( unlikely(!get_page(page, d)) )
    {
        put_gfn(d, gmfn);
        gdprintk(XENLOG_INFO, "Bad page free for vm%u\n", d->domain_id);
        return 0;
    }

    guest_physmap_remove_page(d, gmfn, mfn);

    put_page(page);
    put_gfn(d, gmfn);

    return 1;
}

long do_memory_op(unsigned long cmd, XEN_GUEST_HANDLE(void) arg)
{
    struct domain *d;
    int rc, op;
    unsigned int address_bits;
    unsigned long start_extent;
    struct xen_memory_reservation reservation;
    struct memop_args args = { };
    struct xen_memory_capture capture;
    struct xen_memory_clone_physmap cloneinfo;
    domid_t domid;

    op = cmd & MEMOP_CMD_MASK;

    switch ( op )
    {
    case XENMEM_populate_physmap:
        start_extent = cmd >> MEMOP_EXTENT_SHIFT;

        if ( copy_from_guest(&reservation, arg, 1) )
            return start_extent;

        /* Is size too large for us to encode a continuation? */
        if ( reservation.nr_extents > (ULONG_MAX >> MEMOP_EXTENT_SHIFT) )
            return start_extent;

        if ( unlikely(start_extent >= reservation.nr_extents) )
            return start_extent;

        args.extent_list  = reservation.extent_start;
        args.nr_extents   = reservation.nr_extents;
        args.extent_order = reservation.extent_order;
        args.nr_done      = start_extent;
        args.preempted    = 0;
        args.memflags     = 0;

        address_bits = XENMEMF_get_address_bits(reservation.mem_flags);
        if ( (address_bits != 0) &&
             (address_bits < (get_order_from_pages(max_page) + PAGE_SHIFT)) )
        {
            if ( address_bits <= PAGE_SHIFT )
                return start_extent;
            args.memflags = MEMF_bits(address_bits);
        }

        args.memflags |= MEMF_node(XENMEMF_get_node(reservation.mem_flags));

        if ( op == XENMEM_populate_physmap
             && (reservation.mem_flags & XENMEMF_populate_on_demand) )
            args.memflags |= MEMF_populate_on_demand;

        if (op == XENMEM_populate_physmap &&
            (reservation.mem_flags & XENMEMF_populate_from_buffer)) {
            args.memflags |= MEMF_populate_from_buffer;
            args.buffer = reservation.buffer;
        }

        if (op == XENMEM_populate_physmap &&
            (reservation.mem_flags & XENMEMF_populate_from_buffer_compressed)) {
            args.memflags |= MEMF_populate_from_buffer_compressed;
            args.buffer = reservation.buffer;
            args.buffer_pos = 0;
        }

        if ( likely(reservation.domid == DOMID_SELF) )
        {
            d = rcu_lock_current_domain();
        }
        else
        {
            if ( (d = rcu_lock_domain_by_id(reservation.domid)) == NULL )
                return start_extent;
            if ( !IS_PRIV_FOR(current->domain, d) )
            {
                rcu_unlock_domain(d);
                return start_extent;
            }
        }
        args.domain = d;

        rc = xsm_memory_adjust_reservation(current->domain, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        switch ( op )
        {
        default: /* XENMEM_populate_physmap */
            populate_physmap(&args);
            break;
        }

        rcu_unlock_domain(d);

        rc = args.nr_done;

        if ( args.preempted )
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh",
                op | (rc << MEMOP_EXTENT_SHIFT), arg);

        break;

    case XENMEM_capture:
        if (copy_from_guest(&capture, arg, 1))
            return -EFAULT;

        if (unlikely(capture.nr_done >= capture.nr_gpfns))
            return -EINVAL;

        if (likely(capture.domid == DOMID_SELF))
            d = rcu_lock_current_domain();
        else {
            d = rcu_lock_domain_by_id(capture.domid);
            if (d == NULL)
                return -EEXIST;
            if (!IS_PRIV_FOR(current->domain, d)) {
                rcu_unlock_domain(d);
                return -EEXIST;
            }
        }

        rc = capture_memory(d, &capture);

        rcu_unlock_domain(d);

        if (copy_field_to_guest(
                XEN_GUEST_HANDLE_CAST(xen_memory_capture_t, arg),
                &capture, nr_done))
            return -EFAULT;

        if (rc == -EAGAIN)
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh",
                op, arg);

        break;

    case XENMEM_clone_physmap:
    {
        struct domain *pd;

        if (copy_from_guest(&cloneinfo, arg, 1))
            return -EFAULT;

        pd = rcu_lock_domain_by_uuid(cloneinfo.parentuuid, UUID_HANDLE);
        if (pd == NULL)
            return -ESRCH;
        if (pd->is_dying) {
            rcu_unlock_domain(pd);
            return -EINVAL;
        }
        rc = rcu_lock_target_domain_by_id(cloneinfo.domid, &d);
        if (rc) {
            rcu_unlock_domain(pd);
            return rc;
        }

        if (p2m_get_hostp2m(d)->is_alive)
            rc = -EINVAL;
        else if (d->clone_of &&
                 !(d->clone_of == pd &&
                   p2m_get_hostp2m(d)->clone_gpfn <=
                   p2m_get_hostp2m(pd)->max_mapped_pfn))
            rc = -EINVAL;
        else if (d->clone_of == pd || get_domain(pd)) {
            d->clone_of = pd;
            rc = p2m_clone(p2m_get_hostp2m(pd), d);
            if (rc == -EAGAIN)
                rc = hypercall_create_continuation(
                    __HYPERVISOR_memory_op, "lh",
                    op, arg);
        } else
            rc = -EEXIST;

        rcu_unlock_domain(d);
        rcu_unlock_domain(pd);
    }
        break;

    case XENMEM_maximum_ram_page:
        rc = max_page;
        break;

    case XENMEM_current_reservation:
    case XENMEM_maximum_reservation:
    case XENMEM_maximum_gpfn:
        if ( copy_from_guest(&domid, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(domid, &d);
        if ( rc )
            return rc;

        rc = xsm_memory_stat_reservation(current->domain, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        switch ( op )
        {
        case XENMEM_current_reservation:
            rc = d->tot_pages;
            break;
        case XENMEM_maximum_reservation:
            rc = d->max_pages;
            break;
        default:
            ASSERT(op == XENMEM_maximum_gpfn);
            rc = domain_get_maximum_gpfn(d);
            break;
        }

        rcu_unlock_domain(d);

        break;

    default:
        rc = arch_memory_op(op, arg);
        break;
    }

    return rc;
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
