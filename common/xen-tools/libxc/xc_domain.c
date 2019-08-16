/******************************************************************************
 * xc_domain.c
 *
 * API for manipulating and obtaining information on domains.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (c) 2003, K A Fraser.
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2019, Bromium, Inc.
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

#include "xc_private.h"
#include <xen/memory.h>
#include <xen/hvm/hvm_op.h>

int xc_domain_create(xc_interface *xch,
                     uint32_t ssidref,
                     xen_domain_handle_t handle,
                     uint32_t flags,
                     uint32_t *pdomid)
{
    int err;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_createdomain;
    domctl.domain = (domid_t)*pdomid;
    domctl.u.createdomain.ssidref = ssidref;
    domctl.u.createdomain.flags   = flags;
    memcpy(domctl.u.createdomain.handle, handle, sizeof(xen_domain_handle_t));
    if ( (err = do_domctl(xch, &domctl)) != 0 )
        return err;

    *pdomid = (uint16_t)domctl.domain;
    return 0;
}


int xc_domain_pause(xc_interface *xch,
                    uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_pausedomain;
    domctl.domain = (domid_t)domid;
    return do_domctl(xch, &domctl);
}


int xc_domain_unpause(xc_interface *xch,
                      uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_unpausedomain;
    domctl.domain = (domid_t)domid;
    return do_domctl(xch, &domctl);
}


int xc_domain_destroy(xc_interface *xch,
                      uint32_t domid)
{
    int ret;
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_destroydomain;
    domctl.domain = (domid_t)domid;
    do {
        ret = do_domctl(xch, &domctl);
    } while ( ret && (errno == EAGAIN) );
    return ret;
}

int xc_domain_shutdown(xc_interface *xch,
                       uint32_t domid,
                       int reason)
{
    int ret = -1;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(sched_remote_shutdown_t, arg);

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_domain_shutdown hypercall");
        goto out1;
    }

    hypercall.op     = __HYPERVISOR_sched_op;
    hypercall.arg[0] = (unsigned long)SCHEDOP_remote_shutdown;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);
    arg->domain_id = domid;
    arg->reason = reason;

    ret = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

 out1:
    return ret;
}

int
xc_domain_resume(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_resumedomain;
    domctl.domain = domid;

    return do_domctl(xch, &domctl);
}


int xc_domain_getinfo(xc_interface *xch,
                      uint32_t first_domid,
                      unsigned int max_doms,
                      xc_dominfo_t *info)
{
    unsigned int nr_doms;
    uint32_t next_domid = first_domid;
    DECLARE_DOMCTL;
    int rc = 0;

    memset(info, 0, max_doms*sizeof(xc_dominfo_t));

    for ( nr_doms = 0; nr_doms < max_doms; nr_doms++ )
    {
        domctl.cmd = XEN_DOMCTL_getdomaininfo;
        domctl.domain = (domid_t)next_domid;
        if ( (rc = do_domctl(xch, &domctl)) < 0 )
            break;
        info->domid      = (uint16_t)domctl.domain;

        info->dying    = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_dying);
        info->shutdown = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_shutdown);
        info->paused   = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_paused);
        info->blocked  = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_blocked);
        info->running  = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_running);
        info->hvm      = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_hvm_guest);
        info->debugged = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_debugged);
        info->shutting_down =
            !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_shutting_down);

        info->shutdown_reason =
            (domctl.u.getdomaininfo.flags>>XEN_DOMINF_shutdownshift) &
            XEN_DOMINF_shutdownmask;

        if ( info->shutdown && (info->shutdown_reason == SHUTDOWN_crash) )
        {
            info->shutdown = 0;
            info->crashed  = 1;
        }

        info->ssidref  = domctl.u.getdomaininfo.ssidref;
        info->nr_pages = domctl.u.getdomaininfo.tot_pages;
        info->nr_host_mapped_pages = domctl.u.getdomaininfo.host_pages;
        info->nr_hidden_pages = domctl.u.getdomaininfo.hidden_pages;
        info->nr_pod_pages = domctl.u.getdomaininfo.pod_pages;
        info->nr_zero_shared_pages = domctl.u.getdomaininfo.zero_shared_pages;
        info->nr_tmpl_shared_pages = domctl.u.getdomaininfo.tmpl_shared_pages;
        info->max_memkb = domctl.u.getdomaininfo.max_pages << (PAGE_SHIFT-10);
        info->shared_info_frame = domctl.u.getdomaininfo.shared_info_frame;
        info->cpu_time = domctl.u.getdomaininfo.cpu_time;
        info->nr_online_vcpus = domctl.u.getdomaininfo.nr_online_vcpus;
        info->max_vcpu_id = domctl.u.getdomaininfo.max_vcpu_id;
        info->cpupool = domctl.u.getdomaininfo.cpupool;

        memcpy(info->handle, domctl.u.getdomaininfo.handle,
               sizeof(xen_domain_handle_t));

        info->pause_time = domctl.u.getdomaininfo.pause_time;

        next_domid = (uint16_t)domctl.domain + 1;
        info++;
    }

    if ( nr_doms == 0 )
        return rc;

    return nr_doms;
}

/* get info from hvm guest for save */
int xc_domain_hvm_getcontext(xc_interface *xch,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size)
{
    int ret;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt_buf, size, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, ctxt_buf) )
        return -1;

    domctl.cmd = XEN_DOMCTL_gethvmcontext;
    domctl.domain = (domid_t)domid;
    domctl.u.hvmcontext.size = size;
    set_xen_guest_handle(domctl.u.hvmcontext.buffer, ctxt_buf);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, ctxt_buf);

    return (ret < 0 ? -1 : domctl.u.hvmcontext.size);
}

/* Get just one element of the HVM guest context.
 * size must be >= HVM_SAVE_LENGTH(type) */
int xc_domain_hvm_getcontext_partial(xc_interface *xch,
                                     uint32_t domid,
                                     uint16_t typecode,
                                     uint16_t instance,
                                     void *ctxt_buf,
                                     uint32_t size)
{
    int ret;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt_buf, size, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( !ctxt_buf || xc_hypercall_bounce_pre(xch, ctxt_buf) )
        return -1;

    domctl.cmd = XEN_DOMCTL_gethvmcontext_partial;
    domctl.domain = (domid_t) domid;
    domctl.u.hvmcontext_partial.type = typecode;
    domctl.u.hvmcontext_partial.instance = instance;
    set_xen_guest_handle(domctl.u.hvmcontext_partial.buffer, ctxt_buf);

    ret = do_domctl(xch, &domctl);

    if ( ctxt_buf )
        xc_hypercall_bounce_post(xch, ctxt_buf);

    return ret ? -1 : 0;
}

/* set info to hvm guest for restore */
int xc_domain_hvm_setcontext(xc_interface *xch,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size)
{
    int ret;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt_buf, size, XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, ctxt_buf) )
        return -1;

    domctl.cmd = XEN_DOMCTL_sethvmcontext;
    domctl.domain = domid;
    domctl.u.hvmcontext.size = size;
    set_xen_guest_handle(domctl.u.hvmcontext.buffer, ctxt_buf);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, ctxt_buf);

    return ret;
}

int xc_vcpu_getcontext(xc_interface *xch,
                       uint32_t domid,
                       uint32_t vcpu,
                       vcpu_guest_context_any_t *ctxt)
{
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt, sizeof(vcpu_guest_context_any_t), XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, ctxt) )
        return -1;

    domctl.cmd = XEN_DOMCTL_getvcpucontext;
    domctl.domain = (domid_t)domid;
    domctl.u.vcpucontext.vcpu   = (uint16_t)vcpu;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

    rc = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, ctxt);

    return rc;
}


int xc_domain_setmaxmem(xc_interface *xch,
                        uint32_t domid,
                        unsigned int max_memkb)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_max_mem;
    domctl.domain = (domid_t)domid;
    domctl.u.max_mem.max_memkb = max_memkb;
    return do_domctl(xch, &domctl);
}

int xc_domain_set_time_offset(xc_interface *xch,
                              uint32_t domid,
                              int32_t time_offset_seconds)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_settimeoffset;
    domctl.domain = (domid_t)domid;
    domctl.u.settimeoffset.time_offset_seconds = time_offset_seconds;
    return do_domctl(xch, &domctl);
}

int xc_domain_set_tsc_info(xc_interface *xch,
                           uint32_t domid,
                           uint32_t tsc_mode,
                           uint64_t elapsed_nsec,
                           uint32_t gtsc_khz,
                           uint32_t incarnation)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_settscinfo;
    domctl.domain = (domid_t)domid;
    domctl.u.tsc_info.info.tsc_mode = tsc_mode;
    domctl.u.tsc_info.info.elapsed_nsec = elapsed_nsec;
    domctl.u.tsc_info.info.gtsc_khz = gtsc_khz;
    domctl.u.tsc_info.info.incarnation = incarnation;
    return do_domctl(xch, &domctl);
}

int xc_domain_get_tsc_info(xc_interface *xch,
                           uint32_t domid,
                           uint32_t *tsc_mode,
                           uint64_t *elapsed_nsec,
                           uint32_t *gtsc_khz,
                           uint32_t *incarnation)
{
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(xen_guest_tsc_info_t, info);

    info = xc_hypercall_buffer_alloc(xch, info, sizeof(*info));
    if ( info == NULL )
        return -ENOMEM;

    domctl.cmd = XEN_DOMCTL_gettscinfo;
    domctl.domain = (domid_t)domid;
    set_xen_guest_handle(domctl.u.tsc_info.out_info, info);
    rc = do_domctl(xch, &domctl);
    if ( rc == 0 )
    {
        *tsc_mode = info->tsc_mode;
        *elapsed_nsec = info->elapsed_nsec;
        *gtsc_khz = info->gtsc_khz;
        *incarnation = info->incarnation;
    }
    xc_hypercall_buffer_free(xch, info);
    return rc;
}


int xc_domain_maximum_gpfn(xc_interface *xch, domid_t domid)
{
    return do_memory_op(xch, XENMEM_maximum_gpfn, &domid, sizeof(domid));
}

int xc_domain_add_to_physmap(xc_interface *xch,
                             uint32_t domid,
                             unsigned int space,
                             unsigned long idx,
                             xen_pfn_t gpfn)
{
    struct xen_add_to_physmap xatp = {
        .domid = domid,
        .space = space,
        .idx = idx,
        .gpfn = gpfn,
    };
    return do_memory_op(xch, XENMEM_add_to_physmap, &xatp, sizeof(xatp));
}

static int _xc_domain_populate_physmap(xc_interface *xch,
                                       uint32_t domid,
                                       unsigned long nr_extents,
                                       unsigned int extent_order,
                                       unsigned int mem_flags,
                                       xen_pfn_t *extent_start,
                                       xc_hypercall_buffer_t *buffer)
{
    int err;
    struct xen_memory_reservation reservation = {
        .nr_extents   = nr_extents,
        .extent_order = extent_order,
        .mem_flags    = mem_flags,
        .domid        = domid
    };
    DECLARE_HYPERCALL_BOUNCE(extent_start, nr_extents * sizeof(*extent_start), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(buffer);

    if ( xc_hypercall_bounce_pre(xch, extent_start) )
    {
        PERROR("Could not bounce memory for XENMEM_populate_physmap hypercall");
        return -1;
    }
    set_xen_guest_handle(reservation.extent_start, extent_start);
    if (buffer)
        set_xen_guest_handle(reservation.buffer, buffer);

    err = do_memory_op(xch, XENMEM_populate_physmap, &reservation, sizeof(reservation));

    xc_hypercall_bounce_post(xch, extent_start);
    return err;
}

int xc_domain_populate_physmap(xc_interface *xch,
                               uint32_t domid,
                               unsigned long nr_extents,
                               unsigned int extent_order,
                               unsigned int mem_flags,
                               xen_pfn_t *extent_start)
{

    return _xc_domain_populate_physmap(xch, domid, nr_extents, extent_order,
                                       mem_flags, extent_start, NULL);
}

int xc_domain_populate_physmap_exact(xc_interface *xch,
                                     uint32_t domid,
                                     unsigned long nr_extents,
                                     unsigned int extent_order,
                                     unsigned int mem_flags,
                                     xen_pfn_t *extent_start)
{
    int err;

    err = _xc_domain_populate_physmap(xch, domid, nr_extents,
                                      extent_order, mem_flags, extent_start,
                                      NULL);
    if ( err == nr_extents )
        return 0;

    if ( err >= 0 )
    {
        DPRINTF("Failed allocation for dom %d: %ld extents of order %d\n",
                domid, nr_extents, extent_order);
        errno = EBUSY;
        err = -1;
    }

    return err;
}

int xc_domain_populate_physmap_from_buffer(xc_interface *xch,
                                           uint32_t domid,
                                           unsigned long nr_extents,
                                           unsigned int extent_order,
                                           unsigned int mem_flags,
                                           xen_pfn_t *extent_start,
                                           xc_hypercall_buffer_t *buffer)
{
    int err;

    err = _xc_domain_populate_physmap(xch, domid, nr_extents,
                                      extent_order, mem_flags, extent_start,
                                      buffer);
    if ( err == nr_extents )
        return 0;

    if ( err >= 0 )
    {
        DPRINTF("Failed allocation for dom %d: %ld extents of order %d\n",
                domid, nr_extents, extent_order);
        errno = EBUSY;
        err = -1;
    }

    return err;
}

int
xc_domain_memory_capture(xc_interface *xch,
                         uint32_t domid,
                         unsigned long nr_gpfns,
                         xen_memory_capture_gpfn_info_t *gpfn_info_list,
                         unsigned long *nr_done,
                         xc_hypercall_buffer_t *buffer,
                         uint32_t buffer_size)
{
    int err;
    struct xen_memory_capture xmc = {
        .domid = domid,
        .nr_gpfns = nr_gpfns,
        .buffer_size = buffer_size
    };
    DECLARE_HYPERCALL_BOUNCE(gpfn_info_list, nr_gpfns * sizeof(*gpfn_info_list),
                             XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(buffer);

    if (xc_hypercall_bounce_pre(xch, gpfn_info_list)) {
        PERROR("Could not bounce gpfn_info_list for XENMEM_capture");
        return -1;
    }
    set_xen_guest_handle(xmc.gpfn_info_list, gpfn_info_list);

    set_xen_guest_handle(xmc.buffer, buffer);

    err = do_memory_op(xch, XENMEM_capture, &xmc, sizeof(xmc));

    xc_hypercall_bounce_post(xch, gpfn_info_list);
    *nr_done = xmc.nr_done;

    return err;
}

int xc_domain_clone_physmap(xc_interface *xch,
                            uint32_t domid,
                            xen_domain_handle_t parentuuid)
{
    int err;
    struct xen_memory_clone_physmap cloneinfo = {
        .domid        = domid,
    };

    memcpy(cloneinfo.parentuuid, parentuuid, sizeof(xen_domain_handle_t));

    err = do_memory_op(xch, XENMEM_clone_physmap, &cloneinfo, sizeof(cloneinfo));

    return err;
}

static int xc_domain_pod_target(xc_interface *xch,
                                int op,
                                uint32_t domid,
                                uint64_t target_pages,
                                uint64_t *tot_pages,
                                uint64_t *pod_cache_pages,
                                uint64_t *pod_entries)
{
    int err;

    struct xen_pod_target pod_target = {
        .domid = domid,
        .target_pages = target_pages
    };

    err = do_memory_op(xch, op, &pod_target, sizeof(pod_target));

    if ( err < 0 )
    {
        DPRINTF("Failed %s_pod_target dom %d\n",
                (op==XENMEM_set_pod_target)?"set":"get",
                domid);
        errno = -err;
        err = -1;
    }
    else
        err = 0;

    if ( tot_pages )
        *tot_pages = pod_target.tot_pages;
    if ( pod_cache_pages )
        *pod_cache_pages = pod_target.pod_cache_pages;
    if ( pod_entries )
        *pod_entries = pod_target.pod_entries;

    return err;
}


int xc_domain_set_pod_target(xc_interface *xch,
                             uint32_t domid,
                             uint64_t target_pages,
                             uint64_t *tot_pages,
                             uint64_t *pod_cache_pages,
                             uint64_t *pod_entries)
{
    return xc_domain_pod_target(xch,
                                XENMEM_set_pod_target,
                                domid,
                                target_pages,
                                tot_pages,
                                pod_cache_pages,
                                pod_entries);
}

int xc_domain_max_vcpus(xc_interface *xch, uint32_t domid, unsigned int max)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_max_vcpus;
    domctl.domain = (domid_t)domid;
    domctl.u.max_vcpus.max    = max;
    return do_domctl(xch, &domctl);
}

int xc_domain_sethandle(xc_interface *xch, uint32_t domid,
                        xen_domain_handle_t handle)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_setdomainhandle;
    domctl.domain = (domid_t)domid;
    memcpy(domctl.u.setdomainhandle.handle, handle,
           sizeof(xen_domain_handle_t));
    return do_domctl(xch, &domctl);
}

int xc_vcpu_getinfo(xc_interface *xch,
                    uint32_t domid,
                    uint32_t vcpu,
                    xc_vcpuinfo_t *info)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_getvcpuinfo;
    domctl.domain = (domid_t)domid;
    domctl.u.getvcpuinfo.vcpu   = (uint16_t)vcpu;

    rc = do_domctl(xch, &domctl);

    memcpy(info, &domctl.u.getvcpuinfo, sizeof(*info));

    return rc;
}

#ifdef __UXEN_sendtrigger__
int xc_domain_send_trigger(xc_interface *xch,
                           uint32_t domid,
                           uint32_t trigger,
                           uint32_t vcpu)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_sendtrigger;
    domctl.domain = domid;
    domctl.u.sendtrigger.trigger = trigger;
    domctl.u.sendtrigger.vcpu = vcpu;

    return do_domctl(xch, &domctl);
}
#endif  /* __UXEN_sendtrigger__ */

int xc_set_hvm_param(xc_interface *handle, domid_t dom, int param, uint64_t value)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_param_t, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_param;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);
    arg->domid = dom;
    arg->index = param;
    arg->value = value;
    rc = do_xen_hypercall(handle, &hypercall);
    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_get_hvm_param(xc_interface *handle, domid_t dom, int param, uint64_t *value)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_param_t, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_get_param;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);
    arg->domid = dom;
    arg->index = param;
    rc = do_xen_hypercall(handle, &hypercall);
    *value = arg->value;
    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

#ifdef __UXEN_debugger__
int xc_domain_setdebugging(xc_interface *xch,
                           uint32_t domid,
                           unsigned int enable)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = domid;
    domctl.u.setdebugging.enable = enable;
    return do_domctl(xch, &domctl);
}
#endif  /* __UXEN_debugger__ */

#ifdef __UXEN_debugger__
int xc_domain_debug_control(xc_interface *xc, uint32_t domid, uint32_t sop, uint32_t vcpu)
{
    DECLARE_DOMCTL;

    memset(&domctl, 0, sizeof(domctl));
    domctl.domain = (domid_t)domid;
    domctl.cmd = XEN_DOMCTL_debug_op;
    domctl.u.debug_op.op     = sop;
    domctl.u.debug_op.vcpu   = vcpu;

    return do_domctl(xc, &domctl);
}
#endif  /* __UXEN_debugger__ */

int
xc_hvm_register_ioreq_server(xc_interface *xch, domid_t dom, servid_t *id)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_register_ioreq_server_t, arg);
    int rc = -1;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof (*arg));
    if (!arg) {
        PERROR("Could not allocate memory for "
               "xc_hvm_register_ioreq_server hypercall");
        goto out;
    }

    hypercall.op        = __HYPERVISOR_hvm_op;
    hypercall.arg[0]    = HVMOP_register_ioreq_server;
    hypercall.arg[1]    = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid = dom;

    rc = do_xen_hypercall(xch, &hypercall);

    *id = arg->id;

    xc_hypercall_buffer_free(xch, arg);
  out:
    return rc;
}

xen_pfn_t
xc_hvm_iopage(xc_interface *xch, domid_t dom, int serverid,
              enum xc_hvm_iopage_type type)
{
    xen_pfn_t pfn;

    xc_get_hvm_param(xch, dom, HVM_PARAM_IO_PFN_FIRST, &pfn);
    pfn += (serverid - 1) * NR_IO_PAGES_PER_SERVER +
        (type == XC_HVM_IOPAGE ? 0 : 1) + 1;

    return pfn;
}

int
xc_hvm_map_io_range_to_ioreq_server(xc_interface *xch, domid_t dom, servid_t id,
                                    char is_mmio, uint64_t start, uint64_t end)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_map_io_range_to_ioreq_server_t, arg);
    int rc = -1;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof (*arg));
    if (!arg) {
        PERROR("Could not allocate memory for "
               "xc_hvm_map_io_range_to_ioreq_server hypercall");
        goto out;
    }

    hypercall.op        = __HYPERVISOR_hvm_op;
    hypercall.arg[0]    = HVMOP_map_io_range_to_ioreq_server;
    hypercall.arg[1]    = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid = dom;
    arg->id = id;
    arg->is_mmio = is_mmio;
    arg->s = start;
    arg->e = end;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);
  out:
    return rc;
}

int
xc_hvm_unmap_io_range_from_ioreq_server(xc_interface *xch, domid_t dom,
                                        servid_t id, char is_mmio,
                                        uint64_t addr)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_unmap_io_range_from_ioreq_server_t, arg);
    int rc = -1;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof (*arg));
    if (!arg) {
        PERROR("Could not allocate memory for "
               "xc_hvm_unmap_io_range_from_ioreq_server hypercall");
        goto out;
    }

    hypercall.op        = __HYPERVISOR_hvm_op;
    hypercall.arg[0]    = HVMOP_unmap_io_range_from_ioreq_server;
    hypercall.arg[1]    = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid = dom;
    arg->id = id;
    arg->is_mmio = is_mmio;
    arg->addr = addr;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);
  out:
    return rc;
}

int
xc_hvm_register_pcidev(xc_interface *xch, domid_t dom, servid_t id,
                       uint16_t bdf)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_register_pcidev_t, arg);
    int rc = -1;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof (*arg));
    if (!arg) {
        PERROR("Could not allocate memory for "
               "xc_hvm_register_pcidev hypercall");
        goto out;
    }

    hypercall.op        = __HYPERVISOR_hvm_op;
    hypercall.arg[0]    = HVMOP_register_pcidev;
    hypercall.arg[1]    = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid = dom;
    arg->id = id;
    arg->bdf = bdf;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);
  out:
    return rc;
}



int
xc_domain_set_introspection_features(xc_interface *xch,
                                     uint32_t domid, uint64_t mask)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_set_introspection_features;
    domctl.domain = (domid_t)domid;
    domctl.u.introspection_features.mask = mask;

    return do_domctl(xch, &domctl);
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
