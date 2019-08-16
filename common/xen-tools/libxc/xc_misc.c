/******************************************************************************
 * xc_misc.c
 *
 * Miscellaneous control interface functions.
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
#include <xen/hvm/hvm_op.h>

int xc_physinfo(xc_interface *xch,
                xc_physinfo_t *put_info)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_physinfo;

    memcpy(&sysctl.u.physinfo, put_info, sizeof(*put_info));

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        return ret;

    memcpy(put_info, &sysctl.u.physinfo, sizeof(*put_info));

    return 0;
}


int xc_hvm_set_pci_intx_level(
    xc_interface *xch, domid_t dom,
    uint8_t domain, uint8_t bus, uint8_t device, uint8_t intx,
    unsigned int level)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_set_pci_intx_level, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_set_pci_intx_level hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_pci_intx_level;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid  = dom;
    arg->domain = domain;
    arg->bus    = bus;
    arg->device = device;
    arg->intx   = intx;
    arg->level  = level;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_set_isa_irq_level(
    xc_interface *xch, domid_t dom,
    uint8_t isa_irq,
    unsigned int level)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_set_isa_irq_level, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_set_isa_irq_level hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_isa_irq_level;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid   = dom;
    arg->isa_irq = isa_irq;
    arg->level   = level;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_set_pci_link_route(
    xc_interface *xch, domid_t dom, uint8_t link, uint8_t isa_irq)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_set_pci_link_route, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_set_pci_link_route hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_pci_link_route;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid   = dom;
    arg->link    = link;
    arg->isa_irq = isa_irq;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

#ifdef __UXEN_vmsi__
int xc_hvm_inject_msi(
    xc_interface *xch, domid_t dom, uint64_t addr, uint32_t data)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_inject_msi, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_inject_msi hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_inject_msi;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid = dom;
    arg->addr  = addr;
    arg->data  = data;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}
#endif  /* __UXEN_vmsi__ */

int xc_hvm_track_dirty_vram(
    xc_interface *xch, domid_t dom,
    uint64_t first_pfn, uint64_t nr,
    uint8_t *dirty_bitmap, uint16_t want_events)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BOUNCE(dirty_bitmap, (nr+7) / 8, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_track_dirty_vram, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL || xc_hypercall_bounce_pre(xch, dirty_bitmap) )
    {
        PERROR("Could not bounce memory for xc_hvm_track_dirty_vram hypercall");
        rc = -1;
        goto out;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_track_dirty_vram;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid     = dom;
    arg->want_events = want_events;
    arg->first_pfn = first_pfn;
    arg->nr        = nr;
    set_xen_guest_handle(arg->dirty_bitmap, dirty_bitmap);

    rc = do_xen_hypercall(xch, &hypercall);

out:
    xc_hypercall_buffer_free(xch, arg);
    xc_hypercall_bounce_post(xch, dirty_bitmap);
    return rc;
}

int xc_hvm_modified_memory(
    xc_interface *xch, domid_t dom, uint64_t first_pfn, uint64_t nr)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_modified_memory, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_modified_memory hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_modified_memory;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid     = dom;
    arg->first_pfn = first_pfn;
    arg->nr        = nr;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_set_mem_type(
    xc_interface *xch, domid_t dom, hvmmem_type_t mem_type, uint64_t first_pfn, uint64_t nr)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_set_mem_type, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_set_mem_type hypercall");
        return -1;
    }

    arg->domid        = dom;
    arg->hvmmem_type  = mem_type;
    arg->first_pfn    = first_pfn;
    arg->nr           = nr;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_mem_type;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_inject_trap(
    xc_interface *xch, domid_t dom, int vcpu, uint32_t trap, uint32_t error_code, 
    uint64_t cr2)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_inject_trap, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_inject_trap hypercall");
        return -1;
    }

    arg->domid       = dom;
    arg->vcpuid      = vcpu;
    arg->trap        = trap;
    arg->error_code  = error_code;
    arg->cr2         = cr2;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_inject_trap;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

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
