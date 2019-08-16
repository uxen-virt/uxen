/******************************************************************************
 * arch/x86/domain.c
 *
 * x86-specific domain handling (e.g., register setup and context switching).
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

/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <xen/grant_table.h>
#include <xen/iocap.h>
#include <xen/kernel.h>
#include <xen/multicall.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/percpu.h>
#include <xen/acpi.h>
#include <xen/pci.h>
#include <xen/paging.h>
#include <xen/cpu.h>
#include <xen/wait.h>
#include <xen/guest_access.h>
#include <public/sysctl.h>
#include <asm/regs.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/mpspec.h>
#include <asm/ldt.h>
#include <asm/hypercall.h>
#include <asm/fixmap.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/traps.h>
#include <asm/nmi.h>
#include <asm/mce.h>
#include <xen/numa.h>
#include <xen/iommu.h>
#ifdef CONFIG_COMPAT
#include <compat/vcpu.h>
#endif

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);
DEFINE_PER_CPU(unsigned long, cr4);

struct domain *alloc_domain_struct(void)
{
    struct domain *d;
    /*
     * We pack the PDX of the domain structure into a 32-bit field within
     * the page_info structure. Hence the MEMF_bits() restriction.
     */
    unsigned int bits = 32 + PAGE_SHIFT;

    BUILD_BUG_ON(sizeof(*d) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(*d->extra_1) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(*d->extra_2) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(*d->arch.p2m) > sizeof(d->extra_1->p2m));

    /* Maximum we can support with current vLAPIC ID mapping. */
    BUILD_BUG_ON(MAX_HVM_VCPUS > 128);

    d = alloc_xenheap_pages(0, MEMF_bits(bits));
    if (!d)
        return NULL;
    clear_page(d);

    d->extra_1 = alloc_xenheap_pages(0, MEMF_bits(bits));
    if (!d->extra_1) {
        free_xenheap_page(d);
        return NULL;
    }
    clear_page(d->extra_1);

    d->extra_2 = alloc_xenheap_pages(0, MEMF_bits(bits));
    if (!d->extra_2) {
        free_xenheap_page(d->extra_1);
        free_xenheap_page(d);
        return NULL;
    }
    clear_page(d->extra_2);

    return d;
}

void free_domain_struct(struct domain *d)
{
    lock_profile_deregister_struct(LOCKPROF_TYPE_PERDOM, d);
    if (d->domain_id < DOMID_FIRST_RESERVED)
        domain_array[d->domain_id] = NULL;
    free_xenheap_page(d->extra_2);
    free_xenheap_page(d->extra_1);
    free_xenheap_page(d);
}

struct vcpu *alloc_vcpu_struct(void)
{
    struct vcpu *v;
    /*
     * This structure contains embedded PAE PDPTEs, used when an HVM guest
     * runs on shadow pagetables outside of 64-bit mode. In this case the CPU
     * may require that the shadow CR3 points below 4GB, and hence the whole
     * structure must satisfy this restriction. Thus we specify MEMF_bits(32).
     */
    BUILD_BUG_ON(sizeof(*v) > PAGE_SIZE);
    v = alloc_xenheap_pages(0, MEMF_bits(32));
    if ( v != NULL )
        clear_page(v);
    return v;
}

void free_vcpu_struct(struct vcpu *v)
{
    free_xenheap_page(v);
}

int vcpu_initialise(struct vcpu *v)
{
    struct domain *d = v->domain;
    int rc;

    v->arch.flags = TF_kernel_mode;

    paging_vcpu_init(v);

    if ( (rc = vcpu_init_fpu(v)) != 0 )
        return rc;

    if ( is_hvm_domain(d) )
    {
        rc = hvm_vcpu_initialise(v);
        goto done;
    }

 done:
    if ( rc )
    {
        vcpu_destroy_fpu(v);

    }

    return rc;
}

void vcpu_destroy(struct vcpu *v)
{

    vcpu_destroy_fpu(v);

    if ( is_hvm_vcpu(v) )
        hvm_vcpu_destroy(v);
}

int arch_domain_create(struct domain *d, unsigned int domcr_flags)
{
    int i, paging_initialised = 0;
    int rc = -ENOMEM;

    d->arch.hvm_domain.hap_enabled =
        is_hvm_domain(d) &&
        hvm_funcs.hap_supported &&
        (domcr_flags & DOMCRF_hap);
    if (!hap_enabled(d) &&
        d->domain_id && d->domain_id < DOMID_FIRST_RESERVED) {
        printk(XENLOG_ERR "%s: vm%u: VM without hap "
               "(is %shvm domain, hap %ssupported, DOMCRF_hap %sset)\n",
               __FUNCTION__, d->domain_id,
               is_hvm_domain(d) ? "" : "not ",
               hvm_funcs.hap_supported ? "" : "not ",
               (domcr_flags & DOMCRF_hap) ? "" : "not ");
        rc = -EINVAL;
        goto fail;
    }

    d->arch.hvm_domain.mem_sharing_enabled = 0;

    d->arch.s3_integrity = !!(domcr_flags & DOMCRF_s3_integrity);

    INIT_LIST_HEAD(&d->arch.pdev_list);

    d->arch.relmem = RELMEM_not_started;

    if ( (rc = paging_domain_init(d, domcr_flags)) != 0 )
        goto fail;
    paging_initialised = 1;

    if ( !is_idle_domain(d) )
    {
        d->arch.cpuids = d->extra_1->cpuids;
        for ( i = 0; i < MAX_CPUID_INPUT; i++ )
        {
            d->arch.cpuids[i].input[0] = XEN_CPUID_INPUT_UNUSED;
            d->arch.cpuids[i].input[1] = XEN_CPUID_INPUT_UNUSED;
        }

        /*
         * The shared_info machine address must fit in a 32-bit field within a
         * 32-bit guest's start_info structure. Hence we specify MEMF_bits(32).
         */
        rc = -ENOMEM;
        if ( (d->shared_info = alloc_xenheap_pages(0, MEMF_bits(32))) == NULL )
            goto fail;

        clear_page(d->shared_info);
        share_xen_page_with_guest(
            virt_to_page(d->shared_info), d, XENSHARE_writable);

        d->shared_info_gpfn = INVALID_GFN;

#ifdef __UXEN_vmce__
        /* For Guest vMCE MSRs virtualization */
        vmce_init_msr(d);
#endif  /* __UXEN_vmce__ */
    }

    if ( is_hvm_domain(d) )
    {
        if ( (rc = hvm_domain_initialise(d)) != 0 )
        {
            goto fail;
        }
    }

    /* initialize default tsc behavior in case tools don't */
    tsc_set_info(d, TSC_MODE_DEFAULT, 0UL, 0, 0);
    spin_lock_init(&d->arch.vtsc_lock);

    return 0;

 fail:
    d->is_dying = DOMDYING_dead;
#ifdef __UXEN_vmce__
    vmce_destroy_msr(d);
#endif  /* __UXEN_vmce__ */
    if (d->shared_info) {
        free_domheap_page(virt_to_page(d->shared_info));
        free_xenheap_page(d->shared_info);
    }
    if ( paging_initialised )
        paging_final_teardown(d);
    return rc;
}

void arch_domain_destroy(struct domain *d)
{

    if ( is_hvm_domain(d) )
        hvm_domain_destroy(d);

#ifdef __UXEN_vmce__
    vmce_destroy_msr(d);
#endif  /* __UXEN_vmce__ */

    paging_final_teardown(d);

    free_xenheap_page(d->shared_info);
}

/*
 * This is called by do_domctl(XEN_DOMCTL_setvcpucontext, ...), boot_vcpu(),
 * and hvm_load_cpu_ctxt().
 *
 * Note that for a HVM guest NULL may be passed for the context pointer,
 * meaning "use current values".
 */
int arch_set_info_guest(
    struct vcpu *v, vcpu_guest_context_u c)
{
    struct domain *d = v->domain;
    unsigned long flags;
    unsigned int i;
    int compat;

    /* The context is a compat-mode one if the target domain is compat-mode;
     * we expect the tools to DTRT even in compat-mode callers. */
    compat = is_pv_32on64_domain(d);

#ifdef CONFIG_COMPAT
#define c(fld) (compat ? (c.cmp->fld) : (c.nat->fld))
#else
#define c(fld) (c.nat->fld)
#endif
    flags = c.nat ? c(flags) : v->arch.vgc_flags;

    if ( !is_hvm_vcpu(v) )
    {
        if ( !compat )
        {
            fixup_guest_stack_selector(d, c.nat->user_regs.ss);
            fixup_guest_stack_selector(d, c.nat->kernel_ss);
            fixup_guest_code_selector(d, c.nat->user_regs.cs);
#ifdef __i386__
            fixup_guest_code_selector(d, c.nat->event_callback_cs);
            fixup_guest_code_selector(d, c.nat->failsafe_callback_cs);
#endif

            for ( i = 0; i < 256; i++ )
                fixup_guest_code_selector(d, c.nat->trap_ctxt[i].cs);

            /* LDT safety checks. */
            if ( ((c.nat->ldt_base & (PAGE_SIZE-1)) != 0) ||
                 (c.nat->ldt_ents > 8192) ||
                 !array_access_ok(c.nat->ldt_base,
                                  c.nat->ldt_ents,
                                  LDT_ENTRY_SIZE) )
                return -EINVAL;
        }
#ifdef CONFIG_COMPAT
        else
        {
            fixup_guest_stack_selector(d, c.cmp->user_regs.ss);
            fixup_guest_stack_selector(d, c.cmp->kernel_ss);
            fixup_guest_code_selector(d, c.cmp->user_regs.cs);
            fixup_guest_code_selector(d, c.cmp->event_callback_cs);
            fixup_guest_code_selector(d, c.cmp->failsafe_callback_cs);

            for ( i = 0; i < 256; i++ )
                fixup_guest_code_selector(d, c.cmp->trap_ctxt[i].cs);

            /* LDT safety checks. */
            if ( ((c.cmp->ldt_base & (PAGE_SIZE-1)) != 0) ||
                 (c.cmp->ldt_ents > 8192) ||
                 !compat_array_access_ok(c.cmp->ldt_base,
                                         c.cmp->ldt_ents,
                                         LDT_ENTRY_SIZE) )
                return -EINVAL;
        }
#endif
    }

    v->fpu_initialised = !!(flags & VGCF_I387_VALID);

    v->arch.flags &= ~TF_kernel_mode;
    if ( (flags & VGCF_in_kernel) || is_hvm_vcpu(v)/*???*/ )
        v->arch.flags |= TF_kernel_mode;

    v->arch.vgc_flags = flags;

    if ( c.nat )
    {
        memcpy(v->arch.fpu_ctxt, &c.nat->fpu_ctxt, sizeof(c.nat->fpu_ctxt));
        if ( !compat )
        {
            memcpy(&v->arch.user_regs, &c.nat->user_regs, sizeof(c.nat->user_regs));
        }
#ifdef CONFIG_COMPAT
        else
        {
            XLAT_cpu_user_regs(&v->arch.user_regs, &c.cmp->user_regs);
            for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); ++i )
                XLAT_trap_info(v->arch.pv_vcpu.trap_ctxt + i,
                               c.cmp->trap_ctxt + i);
        }
#endif
        for ( i = 0; i < ARRAY_SIZE(v->arch.debugreg); ++i )
            v->arch.debugreg[i] = c(debugreg[i]);
    }

    v->arch.user_regs.eflags |= 2;

    if ( is_hvm_vcpu(v) )
    {
        hvm_set_info_guest(v);
        goto out;
    }

    BUG();

 out:
    if ( flags & VGCF_online )
        clear_bit(_VPF_down, &v->pause_flags);
    else
        set_bit(_VPF_down, &v->pause_flags);
    return 0;
#undef c
}

void arch_vcpu_reset(struct vcpu *v)
{
    {
        vcpu_end_shutdown_deferral(v);
    }
}

void sync_vcpu_execstate(struct vcpu *v)
{

    /* Other cpus call __sync_local_execstate from flush ipi handler. */
    flush_tlb_mask(v->vcpu_dirty_cpumask);
}

#define next_arg(fmt, args) ({                                              \
    unsigned long __arg;                                                    \
    switch ( *(fmt)++ )                                                     \
    {                                                                       \
    case 'i': __arg = (unsigned long)va_arg(args, unsigned int);  break;    \
    case 'l': __arg = (unsigned long)va_arg(args, unsigned long); break;    \
    case 'h': __arg = (unsigned long)va_arg(args, void *);        break;    \
    default:  __arg = 0; BUG();                                             \
    }                                                                       \
    __arg;                                                                  \
})

void hypercall_cancel_continuation(void)
{
    current->arch.hvm_vcpu.hcall_preempted = 0;
    current->arch.hvm_vcpu.hcall_preempted_retry = 0;
}

static void
_hypercall_continuation(unsigned int op, const char *format, va_list args)
{
    struct uxen_hypercall_desc *uhd = this_cpu(hypercall_args);
    const char *p = format;
    unsigned long arg;
    unsigned int i;

    uhd->uhd_op = op;

    for (i = 0; *p != '\0'; i++) {
        arg = next_arg(p, args);
        uhd->uhd_arg[i] = arg;
    }
}

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
    struct cpu_user_regs *regs;
    const char *p = format;
    unsigned long arg;
    unsigned int i;
    va_list args;

    va_start(args, format);

    if (IS_HOST(current->domain)) {
        _hypercall_continuation(op, format, args);

        va_end(args);

        return -ECONTINUATION;
    }

    {
        regs       = guest_cpu_user_regs();
        regs->eax  = op;

            current->arch.hvm_vcpu.hcall_preempted = 1;

#ifdef __x86_64__
        if (
             (hvm_guest_x86_mode(current) == 8) )
        {
            for ( i = 0; *p != '\0'; i++ )
            {
                arg = next_arg(p, args);
                switch ( i )
                {
                case 0: regs->rdi = arg; break;
                case 1: regs->rsi = arg; break;
                case 2: regs->rdx = arg; break;
                case 3: regs->r10 = arg; break;
                case 4: regs->r8  = arg; break;
                case 5: regs->r9  = arg; break;
                }
            }
        }
        else
#endif
        {
            if ( supervisor_mode_kernel )
                regs->eip &= ~31; /* re-execute entire hypercall entry stub */

            for ( i = 0; *p != '\0'; i++ )
            {
                arg = next_arg(p, args);
                switch ( i )
                {
                case 0: regs->ebx = arg; break;
                case 1: regs->ecx = arg; break;
                case 2: regs->edx = arg; break;
                case 3: regs->esi = arg; break;
                case 4: regs->edi = arg; break;
                case 5: regs->ebp = arg; break;
                }
            }
        }
    }

    va_end(args);

    return op;
}

unsigned long
hypercall_create_retry_continuation(void)
{

    current->arch.hvm_vcpu.hcall_preempted_retry = 1;
    return -ERETRY;
}

static void vcpu_destroy_pagetables(struct vcpu *v)
{

    v->arch.cr3 = 0;
}

int domain_relinquish_resources(struct domain *d)
{
    struct vcpu *v;

    BUG_ON(!cpumask_empty(d->domain_dirty_cpumask));

    /* each clone takes a domain ref -- 3 is the base number of refs
     * that are held on a template that has no clones, then add 1 if
     * the template has vframes */
    if (d->is_template && atomic_read(&d->refcnt) > 3 + (d->vframes ? 1 : 0))
        return -EAGAIN;

    switch ( d->arch.relmem )
    {
    case RELMEM_not_started:
        /* Tear down paging-assistance stuff. */
        paging_teardown(d);

        if ( !is_hvm_domain(d) )
        {
            for_each_vcpu ( d, v )
            {
                /* Drop the in-use references to page-table bases. */
                vcpu_destroy_pagetables(v);

            }

        }

        d->arch.relmem = RELMEM_xen;
        /* fallthrough */

        /* Relinquish shared xen pages. */
    case RELMEM_xen:
        if (d->shared_info)
            put_page(virt_to_page(d->shared_info));
        if (is_hvm_domain(d))
            hvm_relinquish_memory(d);

        d->arch.relmem = RELMEM_foreign_pages;
        /* fallthrough */

    case RELMEM_foreign_pages:
        if (d->host_pages)
            return -EAGAIN;

        d->arch.relmem = RELMEM_done;
        /* fallthrough */

    case RELMEM_done:
        break;

    default:
        BUG();
    }

    if ( is_hvm_domain(d) )
        hvm_domain_relinquish_resources(d);

    return 0;
}

void arch_dump_domain_info(struct domain *d)
{
    paging_dump_domain_info(d);
}

void arch_dump_vcpu_info(struct vcpu *v)
{
    paging_dump_vcpu_info(v);
}

void domain_cpuid(
    struct domain *d,
    unsigned int  input,
    unsigned int  sub_input,
    unsigned int  *eax,
    unsigned int  *ebx,
    unsigned int  *ecx,
    unsigned int  *edx)
{
    cpuid_input_t *cpuid;
    int i;

    for ( i = 0; i < MAX_CPUID_INPUT; i++ )
    {
        cpuid = &d->arch.cpuids[i];

        if ( (cpuid->input[0] == input) &&
             ((cpuid->input[1] == XEN_CPUID_INPUT_UNUSED) ||
              (cpuid->input[1] == sub_input)) )
        {
            *eax = cpuid->eax;
            *ebx = cpuid->ebx;
            *ecx = cpuid->ecx;
            *edx = cpuid->edx;

            return;
        }
    }

    *eax = *ebx = *ecx = *edx = 0;
}

void vcpu_kick(struct vcpu *v)
{
    /*
     * NB1. 'pause_flags' and 'processor' must be checked /after/ update of
     * pending flag. These values may fluctuate (after all, we hold no
     * locks) but the key insight is that each change will cause
     * evtchn_upcall_pending to be polled.
     * 
     * NB2. We save the running flag across the unblock to avoid a needless
     * IPI for domains that we IPI'd to unblock.
     */
    bool_t running = v->is_running;
    vcpu_unblock(v);
    if ( running && (in_irq() || (v != current)) )
        vcpu_raise_softirq(v, KICK_VCPU_SOFTIRQ);
}

static void vcpu_kick_softirq(struct vcpu *v)
{
    /*
     * Nothing to do here: we merely prevent notifiers from racing with checks
     * executed on return to guest context with interrupts enabled. See, for
     * example, xxx_intr_assist() executed on return to HVM guest context.
     */
}

static int __init init_vcpu_kick_softirq(void)
{
    open_softirq_vcpu(KICK_VCPU_SOFTIRQ, vcpu_kick_softirq);
    return 0;
}
__initcall(init_vcpu_kick_softirq);

static void vcpu_sync_tsc_softirq(struct vcpu *v)
{
    HVM_FUNCS(set_tsc_offset, v, v->arch.hvm_vcpu.cache_tsc_offset);
}

static int __init init_vcpu_tsc_softirq(void)
{
    open_softirq_vcpu(SYNC_TSC_VCPU_SOFTIRQ, vcpu_sync_tsc_softirq);
    return 0;
}
__initcall(init_vcpu_tsc_softirq);

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
