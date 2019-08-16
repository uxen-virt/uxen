/******************************************************************************
 * Arch-specific domctl.c
 * 
 * Copyright (c) 2002-2006, K A Fraser
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
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
#include <xen/guest_access.h>
#include <xen/pci.h>
#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/paging.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <asm/processor.h>
#include <asm/acpi.h> /* for hvm_acpi_power_button */
#include <xen/hypercall.h> /* for arch_do_domctl */
#include <xsm/xsm.h>
#include <xen/iommu.h>
#include <asm/xstate.h>
#include <asm/debugger.h>
#include <xen/pfn.h>

long arch_do_domctl(
    struct xen_domctl *domctl,
    XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    long ret = 0;

    switch ( domctl->cmd )
    {

    case XEN_DOMCTL_getpageframeinfo:
    {
        struct page_info *page;
        unsigned long mfn = domctl->u.getpageframeinfo.gmfn;
        domid_t dom = domctl->domain;
        struct domain *d;

        ret = -EINVAL;

        if ( unlikely(!mfn_valid(mfn)) ||
             unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
            break;

        page = mfn_to_page(mfn);

        ret = xsm_getpageframeinfo(page);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        if ( likely(get_page(page, d)) )
        {
            ret = 0;

            domctl->u.getpageframeinfo.type = XEN_DOMCTL_PFINFO_NOTAB;

            put_page(page);
        }

        rcu_unlock_domain(d);

        copy_to_guest(u_domctl, domctl, 1);
    }
    break;

    case XEN_DOMCTL_getpageframeinfo3:
        {
            unsigned int n, j;
            unsigned int num = domctl->u.getpageframeinfo3.num;
            domid_t dom = domctl->domain;
            struct domain *d;
            struct page_info *page;
            xen_pfn_t *arr;

            ret = -ESRCH;
            if ( unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
                break;

            if ( unlikely(num > 1024) ||
                 unlikely(num != domctl->u.getpageframeinfo3.num) )
            {
                ret = -E2BIG;
                rcu_unlock_domain(d);
                break;
            }

            page = alloc_domheap_page(NULL, 0);
            if ( !page )
            {
                ret = -ENOMEM;
                rcu_unlock_domain(d);
                break;
            }
            arr = __map_domain_page(page);

            for ( n = ret = 0; n < num; )
            {
                unsigned int k = min_t(unsigned int, num - n,
                                       PAGE_SIZE / sizeof(*arr));

                if ( copy_from_guest_offset(arr,
                                            domctl->u.getpageframeinfo3.array,
                                            n, k) )
                {
                    ret = -EFAULT;
                    break;
                }

                for ( j = 0; j < k; j++ )
                {
                    p2m_type_t pt;
                    unsigned long type = 0, mfn = mfn_x(get_gfn_query(d, arr[j], &pt));

                    page = mfn_to_page(mfn);

                    if (p2m_is_pod(pt)) {
                        if (mfn_zero_page(mfn))
                            type = XEN_DOMCTL_PFINFO_XALLOC;
                        else
                            type = XEN_DOMCTL_PFINFO_XPOD;
                    } else if ( unlikely(!mfn_valid(mfn)) ||
                                unlikely(is_xen_mfn(mfn)) ||
                                unlikely(is_host_mfn(mfn)) )
                        type = XEN_DOMCTL_PFINFO_XTAB;
                    else if ( xsm_getpageframeinfo(page) != 0 )
                        ;
                    else if ( likely(get_page(page, d)) )
                    {

                        put_page(page);
                    }
                    else
                        type = XEN_DOMCTL_PFINFO_XTAB;

                    put_gfn(d, arr[j]);
                    arr[j] = type;
                }

                if ( copy_to_guest_offset(domctl->u.getpageframeinfo3.array,
                                          n, arr, j) )
                {
                    ret = -EFAULT;
                    break;
                }

                n += j;

                if (j != k)
                    break;
            }

            page = virt_to_page(arr);
            unmap_domain_page(arr);
            free_domheap_page(page);

            rcu_unlock_domain(d);
            break;
        }
        /* fall thru */
    case XEN_DOMCTL_getpageframeinfo2:
    {
        int n,j;
        int num = domctl->u.getpageframeinfo2.num;
        domid_t dom = domctl->domain;
        struct domain *d;
        uint32_t *arr32;
        ret = -ESRCH;

        if ( unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
            break;

        if ( unlikely(num > 1024) )
        {
            ret = -E2BIG;
            rcu_unlock_domain(d);
            break;
        }

        arr32 = alloc_xenheap_page();
        if ( !arr32 )
        {
            ret = -ENOMEM;
            rcu_unlock_domain(d);
            break;
        }
 
        ret = 0;
        for ( n = 0; n < num; )
        {
            int k = PAGE_SIZE / 4;
            if ( (num - n) < k )
                k = num - n;

            if ( copy_from_guest_offset(arr32,
                                        domctl->u.getpageframeinfo2.array,
                                        n, k) )
            {
                ret = -EFAULT;
                break;
            }
     
            for ( j = 0; j < k; j++ )
            {      
                struct page_info *page;
                unsigned long gfn = arr32[j];
                unsigned long mfn = get_gfn_untyped(d, gfn);

                page = mfn_to_page(mfn);

                if ( domctl->cmd == XEN_DOMCTL_getpageframeinfo3)
                    arr32[j] = 0;

                if ( unlikely(!mfn_valid(mfn)) ||
                     unlikely(is_xen_mfn(mfn)) )
                    arr32[j] |= XEN_DOMCTL_PFINFO_XTAB;
                else if ( xsm_getpageframeinfo(page) != 0 )
                {
                    put_gfn(d, gfn); 
                    continue;
                } else if ( likely(get_page(page, d)) )
                {
                    unsigned long type = 0;

                    arr32[j] |= type;
                    put_page(page);
                }
                else
                    arr32[j] |= XEN_DOMCTL_PFINFO_XTAB;

                put_gfn(d, gfn); 
            }

            if ( copy_to_guest_offset(domctl->u.getpageframeinfo2.array,
                                      n, arr32, j) )
            {
                ret = -EFAULT;
                break;
            }

            n += j;

            if (j != k)
                break;
        }

        free_xenheap_page(arr32);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_sethvmcontext:
    { 
        struct hvm_domain_context c = { .size = domctl->u.hvmcontext.size };
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_hvmcontext(d, domctl->cmd);
        if ( ret )
            goto sethvmcontext_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) ) 
            goto sethvmcontext_out;

        ret = -ENOMEM;
        c.data = alloc_host_pages(PFN_UP(c.size), MEMF_multiok);
        if ( c.data == NULL ) {
            if (current->vm_vcpu_info_shared->vci_map_page_range_requested)
                ret = -EMAPPAGERANGE;
            goto sethvmcontext_out;
        }

        ret = -EFAULT;
        if ( copy_from_guest(c.data, domctl->u.hvmcontext.buffer, c.size) != 0)
            goto sethvmcontext_out;

        domain_pause(d);
        domain_pause_time(d);
        ret = hvm_load(d, &c);
        domain_unpause_time(d);
        domain_unpause(d);

    sethvmcontext_out:
        if ( c.data != NULL )
            free_host_pages(c.data, PFN_UP(c.size));

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gethvmcontext:
    { 
        struct hvm_domain_context c = { 0 };
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_hvmcontext(d, domctl->cmd);
        if ( ret )
            goto gethvmcontext_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) ) 
            goto gethvmcontext_out;

        c.size = hvm_save_size(d);

        if ( guest_handle_is_null(domctl->u.hvmcontext.buffer) )
        {
            /* Client is querying for the correct buffer size */
            domctl->u.hvmcontext.size = c.size;
            ret = 0;
            goto gethvmcontext_out;            
        }

        /* Check that the client has a big enough buffer */
        ret = -ENOSPC;
        if ( domctl->u.hvmcontext.size < c.size ) 
            goto gethvmcontext_out;

        /* Allocate our own marshalling buffer */
        ret = -ENOMEM;
        c.data = alloc_host_pages(PFN_UP(c.size), MEMF_multiok);
        if ( c.data == NULL ) {
            if (current->vm_vcpu_info_shared->vci_map_page_range_requested)
                ret = -EMAPPAGERANGE;
            goto gethvmcontext_out;
        }

        domain_pause(d);
        domain_pause_time(d);
        ret = hvm_save(d, &c);
        domain_unpause_time(d);
        domain_unpause(d);

        domctl->u.hvmcontext.size = c.cur;
        if ( copy_to_guest(domctl->u.hvmcontext.buffer, c.data, c.size) != 0 )
            ret = -EFAULT;

    gethvmcontext_out:
        if ( copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;

        if ( c.data != NULL )
            free_host_pages(c.data, PFN_UP(c.size));

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gethvmcontext_partial:
    { 
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_hvmcontext(d, domctl->cmd);
        if ( ret )
            goto gethvmcontext_partial_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) ) 
            goto gethvmcontext_partial_out;

        domain_pause(d);
        domain_pause_time(d);
        ret = hvm_save_one(d, domctl->u.hvmcontext_partial.type,
                           domctl->u.hvmcontext_partial.instance,
                           domctl->u.hvmcontext_partial.buffer);
        domain_unpause_time(d);
        domain_unpause(d);

    gethvmcontext_partial_out:
        rcu_unlock_domain(d);
    }
    break;


    case XEN_DOMCTL_get_address_size:
    {
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_address_size(d, domctl->cmd);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        domctl->u.address_size.size =
            is_pv_32on64_domain(d) ? 32 : BITS_PER_LONG;

        ret = 0;
        rcu_unlock_domain(d);

        if ( copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
    }
    break;

#ifdef __UXEN_sendtrigger__
    case XEN_DOMCTL_sendtrigger:
    {
        struct domain *d;
        struct vcpu *v;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_sendtrigger(d);
        if ( ret )
            goto sendtrigger_out;

        ret = -EINVAL;
        if ( domctl->u.sendtrigger.vcpu >= MAX_VIRT_CPUS )
            goto sendtrigger_out;

        ret = -ESRCH;
        if (domctl->u.sendtrigger.vcpu >= d->max_vcpus)
            goto sendtrigger_out;
        domctl->u.sendtrigger.vcpu =
            array_index_nospec(domctl->u.sendtrigger.vcpu, d->max_vcpus);
        if ((v = d->vcpu[domctl->u.sendtrigger.vcpu]) == NULL)
            goto sendtrigger_out;

        switch ( domctl->u.sendtrigger.trigger )
        {
        case XEN_DOMCTL_SENDTRIGGER_NMI:
        {
            ret = 0;
            if ( !test_and_set_bool(v->nmi_pending) )
                vcpu_kick(v);
        }
        break;

        case XEN_DOMCTL_SENDTRIGGER_POWER:
        {
            ret = -EINVAL;
            if ( is_hvm_domain(d) ) 
            {
                ret = 0;
                hvm_acpi_power_button(d);
            }
        }
        break;

        case XEN_DOMCTL_SENDTRIGGER_SLEEP:
        {
            ret = -EINVAL;
            if ( is_hvm_domain(d) ) 
            {
                ret = 0;
                hvm_acpi_sleep_button(d);
            }
        }
        break;

        default:
            ret = -ENOSYS;
        }

    sendtrigger_out:
        rcu_unlock_domain(d);
    }
    break;
#endif  /* __UXEN_sendtrigger__ */

    case XEN_DOMCTL_set_cpuid:
    {
        struct domain *d;
        xen_domctl_cpuid_t *ctl = &domctl->u.cpuid;
        cpuid_input_t *cpuid = NULL; 
        int i;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        for ( i = 0; i < MAX_CPUID_INPUT; i++ )
        {
            cpuid = &d->arch.cpuids[i];

            if ( cpuid->input[0] == XEN_CPUID_INPUT_UNUSED )
                break;

            if ( (cpuid->input[0] == ctl->input[0]) &&
                 ((cpuid->input[1] == XEN_CPUID_INPUT_UNUSED) ||
                  (cpuid->input[1] == ctl->input[1])) )
                break;
        }
        
        if ( i == MAX_CPUID_INPUT )
        {
            ret = -ENOENT;
        }
        else
        {
            memcpy(cpuid, ctl, sizeof(cpuid_input_t));
            ret = 0;
        }

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gettscinfo:
    {
        struct domain *d;
        xen_guest_tsc_info_t info;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        domain_pause(d);
        tsc_get_info(d, &info.tsc_mode,
                        &info.elapsed_nsec,
                        &info.gtsc_khz,
                        &info.incarnation);
        if ( copy_to_guest(domctl->u.tsc_info.out_info, &info, 1) )
            ret = -EFAULT;
        else
            ret = 0;
        domain_unpause(d);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_settscinfo:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        domain_pause(d);
        tsc_set_info(d, domctl->u.tsc_info.info.tsc_mode,
                     domctl->u.tsc_info.info.elapsed_nsec,
                     domctl->u.tsc_info.info.gtsc_khz,
                     domctl->u.tsc_info.info.incarnation);
        domain_unpause(d);

        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

#ifdef __UXEN_debugger__
    case XEN_DOMCTL_debug_op:
    {
        struct domain *d;
        struct vcpu *v;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        ret = -EINVAL;
        if (domctl->u.debug_op.vcpu >= d->max_vcpus)
            goto debug_op_out;
        domctl->u.debug_op.vcpu =
            array_index_nospec(domctl->u.debug_op.vcpu, d->max_vcpus);
        if ((v = d->vcpu[domctl->u.debug_op.vcpu]) == NULL)
            goto debug_op_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d))
            goto debug_op_out;

        ret = hvm_debug_op(v, domctl->u.debug_op.op);

    debug_op_out:
        rcu_unlock_domain(d);
    }
    break;
#endif  /* __UXEN_debugger__ */

    case XEN_DOMCTL_setvcpuextstate:
    case XEN_DOMCTL_getvcpuextstate:
    {
        struct xen_domctl_vcpuextstate *evc;
        struct domain *d;
        struct vcpu *v;
        uint32_t offset = 0;
        uint64_t _xfeature_mask = 0;
        uint64_t _xcr0, _xcr0_accum;
        void *receive_buf = NULL, *_xsave_area;

#define PV_XSAVE_SIZE (2 * sizeof(uint64_t) + xsave_cntxt_size)

        evc = &domctl->u.vcpuextstate;

        ret = -ESRCH;

        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        ret = xsm_vcpuextstate(d, domctl->cmd);
        if ( ret )
            goto vcpuextstate_out;

        ret = -ESRCH;
        if (evc->vcpu >= d->max_vcpus)
            goto vcpuextstate_out;
        evc->vcpu = array_index_nospec(evc->vcpu, d->max_vcpus);
        if ((v = d->vcpu[evc->vcpu]) == NULL)
            goto vcpuextstate_out;

        if ( domctl->cmd == XEN_DOMCTL_getvcpuextstate )
        {
            if ( !evc->size && !evc->xfeature_mask )
            {
                evc->xfeature_mask = xfeature_mask;
                evc->size = PV_XSAVE_SIZE;
                ret = 0;
                goto vcpuextstate_out;
            }
            if ( evc->size != PV_XSAVE_SIZE ||
                 evc->xfeature_mask != xfeature_mask )
            {
                ret = -EINVAL;
                goto vcpuextstate_out;
            }
            if ( copy_to_guest_offset(domctl->u.vcpuextstate.buffer,
                                      offset, (void *)&v->arch.xcr0,
                                      sizeof(v->arch.xcr0)) )
            {
                ret = -EFAULT;
                goto vcpuextstate_out;
            }
            offset += sizeof(v->arch.xcr0);
            if ( copy_to_guest_offset(domctl->u.vcpuextstate.buffer,
                                      offset, (void *)&v->arch.xcr0_accum,
                                      sizeof(v->arch.xcr0_accum)) )
            {
                ret = -EFAULT;
                goto vcpuextstate_out;
            }
            offset += sizeof(v->arch.xcr0_accum);
            if ( copy_to_guest_offset(domctl->u.vcpuextstate.buffer,
                                      offset, (void *)v->arch.xsave_area,
                                      xsave_cntxt_size) )
            {
                ret = -EFAULT;
                goto vcpuextstate_out;
            }
        }
        else
        {
            ret = -EINVAL;

            _xfeature_mask = evc->xfeature_mask;
            /* xsave context must be restored on compatible target CPUs */
            if ( (_xfeature_mask & xfeature_mask) != _xfeature_mask )
                goto vcpuextstate_out;
            if ( evc->size > PV_XSAVE_SIZE || evc->size < 2 * sizeof(uint64_t) )
                goto vcpuextstate_out;

            receive_buf = xmalloc_bytes(evc->size);
            if ( !receive_buf )
            {
                ret = -ENOMEM;
                goto vcpuextstate_out;
            }
            if ( copy_from_guest_offset(receive_buf, domctl->u.vcpuextstate.buffer,
                                        offset, evc->size) )
            {
                ret = -EFAULT;
                xfree(receive_buf);
                goto vcpuextstate_out;
            }

            _xcr0 = *(uint64_t *)receive_buf;
            _xcr0_accum = *(uint64_t *)(receive_buf + sizeof(uint64_t));
            _xsave_area = receive_buf + 2 * sizeof(uint64_t);

            if ( !(_xcr0 & XSTATE_FP) || _xcr0 & ~xfeature_mask )
            {
                xfree(receive_buf);
                goto vcpuextstate_out;
            }
            if ( (_xcr0 & _xcr0_accum) != _xcr0 )
            {
                xfree(receive_buf);
                goto vcpuextstate_out;
            }

            v->arch.xcr0 = _xcr0;
            v->arch.xcr0_accum = _xcr0_accum;
            memcpy(v->arch.xsave_area, _xsave_area, evc->size - 2 * sizeof(uint64_t) );

            xfree(receive_buf);
        }

        ret = 0;

    vcpuextstate_out:
        rcu_unlock_domain(d);
        if ( (domctl->cmd == XEN_DOMCTL_getvcpuextstate) &&
             copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
    }
    break;

    default:
        gdprintk(XENLOG_ERR, "unknown domctl %d on vm%u\n", domctl->cmd,
                 domctl->domain);
        ret = -ENOSYS;
        break;
    }

    return ret;
}

#ifdef CONFIG_COMPAT
#define xen_vcpu_guest_context vcpu_guest_context
#define fpu_ctxt fpu_ctxt.x
CHECK_FIELD_(struct, vcpu_guest_context, fpu_ctxt);
#undef fpu_ctxt
#undef xen_vcpu_guest_context
#endif

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    unsigned int i;
    bool_t compat = is_pv_32on64_domain(v->domain);
#ifdef CONFIG_COMPAT
#define c(fld) (!compat ? (c.nat->fld) : (c.cmp->fld))
#else
#define c(fld) (c.nat->fld)
#endif

    if ( is_hvm_vcpu(v) )
        memset(c.nat, 0, sizeof(*c.nat));
    memcpy(&c.nat->fpu_ctxt, v->arch.fpu_ctxt, sizeof(c.nat->fpu_ctxt));
    c(flags = v->arch.vgc_flags & ~(VGCF_i387_valid|VGCF_in_kernel));
    if ( v->fpu_initialised )
        c(flags |= VGCF_i387_valid);
    if ( !test_bit(_VPF_down, &v->pause_flags) )
        c(flags |= VGCF_online);
    if ( !compat )
    {
        memcpy(&c.nat->user_regs, &v->arch.user_regs, sizeof(c.nat->user_regs));
    }
#ifdef CONFIG_COMPAT
    else
    {
        XLAT_cpu_user_regs(&c.cmp->user_regs, &v->arch.user_regs);
        for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); ++i )
            XLAT_trap_info(c.cmp->trap_ctxt + i,
                           v->arch.pv_vcpu.trap_ctxt + i);
    }
#endif

    for ( i = 0; i < ARRAY_SIZE(v->arch.debugreg); ++i )
        c(debugreg[i] = v->arch.debugreg[i]);

    if ( is_hvm_vcpu(v) )
    {
        struct segment_register sreg;

        c.nat->ctrlreg[0] = v->arch.hvm_vcpu.guest_cr[0];
        c.nat->ctrlreg[2] = v->arch.hvm_vcpu.guest_cr[2];
        c.nat->ctrlreg[3] = v->arch.hvm_vcpu.guest_cr[3];
        c.nat->ctrlreg[4] = v->arch.hvm_vcpu.guest_cr[4];
        hvm_get_segment_register(v, x86_seg_cs, &sreg);
        c.nat->user_regs.cs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ss, &sreg);
        c.nat->user_regs.ss = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ds, &sreg);
        c.nat->user_regs.ds = sreg.sel;
        hvm_get_segment_register(v, x86_seg_es, &sreg);
        c.nat->user_regs.es = sreg.sel;
        hvm_get_segment_register(v, x86_seg_fs, &sreg);
        c.nat->user_regs.fs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_gs, &sreg);
        c.nat->user_regs.gs = sreg.sel;
    }

    c(vm_assist = v->domain->vm_assist);
#undef c
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
