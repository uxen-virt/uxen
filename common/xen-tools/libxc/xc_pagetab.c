/******************************************************************************
 * xc_pagetab.c
 *
 * Function to translate virtual to physical addresses.
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
 * Copyright 2012-2015, Bromium, Inc.
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
#include <xen/hvm/save.h>

#define CR0_PG  0x80000000
#define CR4_PAE 0x20
#define PTE_PSE 0x80
#define EFER_LMA 0x400

static int
pgt_walk(xc_interface *xch, uint32_t dom,
         int pt_levels, uint64_t paddr, uint64_t virt,
         uint64_t mask, int size,
         uint64_t *gfn)
{
    uint64_t pte = 0;
    int level;
    void *map;

    /* Walk the pagetables */
    for (level = pt_levels; level > 0; level--) {
        paddr += ((virt & mask) >> (xc_ffs64(mask) - 1)) * size;
        map = xc_map_foreign_range(xch, dom, PAGE_SIZE, PROT_READ, 
                                   paddr >>PAGE_SHIFT);
        if (!map) {
            *gfn = 0;
            return -1;
        }
        memcpy(&pte, map + (paddr & (PAGE_SIZE - 1)), size);
        xc_munmap(xch, dom, map, PAGE_SIZE);
        if (!(pte & 1)) {
            *gfn = 0;
            return -1;
        }
        paddr = pte & 0x000ffffffffff000ull;
        if (level == 2 && (pte & PTE_PSE)) {
            mask = ((mask ^ ~-mask) >> 1); /* All bits below first set bit */
            *gfn = ((paddr & ~mask) | (virt & mask)) >> PAGE_SHIFT;
            return 0;
        }
        mask >>= (pt_levels == 2 ? 10 : 9);
    }
    *gfn =  paddr >> PAGE_SHIFT;
    return 0;
}

int xc_translate_foreign_address_range(
    xc_interface *xch, uint32_t dom,
    int vcpu, unsigned long long virt_begin, unsigned int npages,
    uint64_t *gfn)
{
    xc_dominfo_t dominfo;
    uint64_t paddr_base, mask;
    int size, pt_levels = 2;
    unsigned int i;
    unsigned long long virt;
    int rc;

    memset(gfn, 0, sizeof(*gfn) * npages);
    if (xc_domain_getinfo(xch, dom, 1, &dominfo) != 1
        || dominfo.domid != dom)
        return -1;

    /* What kind of paging are we dealing with? */
    if (dominfo.hvm) {
        struct hvm_hw_cpu ctx;
        if (xc_domain_hvm_getcontext_partial(xch, dom,
                                             HVM_SAVE_CODE(CPU), vcpu,
                                             &ctx, sizeof ctx) != 0)
            return -1;
        if (!(ctx.cr0 & CR0_PG)) {
            for (i = 0; i < npages; ++i)
                gfn[i] = (virt_begin >> PAGE_SHIFT) + i;
            return 0;
        }
        pt_levels = (ctx.msr_efer&EFER_LMA) ? 4 : (ctx.cr4&CR4_PAE) ? 3 : 2;
        paddr_base = ctx.cr3 & ((pt_levels == 3) ? ~0x1full : ~0xfffull);
    } else {
        DECLARE_DOMCTL;
        vcpu_guest_context_any_t ctx;
        if (xc_vcpu_getcontext(xch, dom, vcpu, &ctx) != 0)
            return -1;
        domctl.domain = dom;
        domctl.cmd = XEN_DOMCTL_get_address_size;
        if ( do_domctl(xch, &domctl) != 0 )
            return -1;
        if (domctl.u.address_size.size == 64) {
            pt_levels = 4;
            paddr_base = (uint64_t)xen_cr3_to_pfn_x86_64(ctx.x64.ctrlreg[3])
                << PAGE_SHIFT;
        } else {
            pt_levels = 3;
            paddr_base = (uint64_t)xen_cr3_to_pfn_x86_32(ctx.x32.ctrlreg[3])
                << PAGE_SHIFT;
        }
    }

    rc = 0;
    for (i = 0; i < npages; ++i) {
        virt = virt_begin + i * PAGE_SIZE;

        if (pt_levels == 4) {
            virt &= 0x0000ffffffffffffull;
            mask =  0x0000ff8000000000ull;
        } else if (pt_levels == 3) {
            virt &= 0x00000000ffffffffull;
            mask =  0x0000007fc0000000ull;
        } else {
            virt &= 0x00000000ffffffffull;
            mask =  0x00000000ffc00000ull;
        }
        size = (pt_levels == 2 ? 4 : 8);

        /* Walk the pagetables */
        if (pgt_walk(xch, dom, pt_levels, paddr_base, virt, mask, size, &gfn[i]))
            rc = -1;
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
