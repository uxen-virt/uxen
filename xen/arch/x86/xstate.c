/*
 *  arch/x86/xstate.c
 *
 *  x86 extended state operations
 *
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
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/hvm/support.h>
#include <asm/hvm/ax.h>
#include <asm/xstate.h>
#include <asm/asm_defns.h>

bool_t __read_mostly cpu_has_xsaveopt;

/*
 * Maximum size (in byte) of the XSAVE/XRSTOR save area required by all
 * the supported and enabled features on the processor, including the
 * XSAVE.HEADER. We only enable XCNTXT_MASK that we have known.
 */
u32 xsave_cntxt_size;

/*
 * size (in bytes) of the XSAVE/XRSTOR save area used in save files,
 * using only features in XCNTXT_MASK_vmsave.
 */
u32 xsave_cntxt_size_vmsave;

/* A 64-bit bitmask of the XSAVE/XRSTOR features supported by processor. */
u64 xfeature_mask;

/* Cached xcr0 for fast read */
DEFINE_PER_CPU(uint64_t, xcr0);

#ifdef XCR0_STATE_DEBUG
DEFINE_PER_CPU(int, xcr0_state);
#endif /* XCR0_STATE_DEBUG */

/* Because XCR0 is cached for each CPU, xsetbv() is not exposed. Users should 
 * use set_xcr0() instead.
 */
static inline void xsetbv(u32 index, u64 xfeatures)
{
    u32 hi = xfeatures >> 32;
    u32 lo = (u32)xfeatures;

    asm volatile (".byte 0x0f,0x01,0xd1" :: "c" (index),
            "a" (lo), "d" (hi));
}

/* Cached xcr0 to avoid writes */
DEFINE_PER_CPU(uint64_t, xcr0_last);

/* Danger - this call is used on the hostcall path so you can NOT */
/* call any host calls like printk here */
static inline void xsetbv_maybe(u32 index, u64 xfeatures)
{

    if (ax_present_amd)
        return;

    if (this_cpu(xcr0_last) != xfeatures ||
        index != XCR_XFEATURE_ENABLED_MASK) {
        u32 hi, lo;

        if (index == XCR_XFEATURE_ENABLED_MASK ) {
            if (!((xfeatures ^ this_cpu(xcr0_last)) & xfeatures))
                return;
            xfeatures |= this_cpu(xcr0_last);
        }

        hi = xfeatures >> 32;
        lo = (u32)xfeatures;

        asm volatile (".byte 0x0f,0x01,0xd1" :: "c" (index),
                      "a" (lo), "d" (hi));

        if (index == XCR_XFEATURE_ENABLED_MASK)
            this_cpu(xcr0_last) = xfeatures;
    }
}

uint64_t xgetbv(uint32_t index)
{
    uint32_t hi, lo;

    asm volatile ("xgetbv" : "=a" (lo), "=d" (hi) : "c" (index));

    return ((uint64_t)hi << 32) | lo;
}

inline void sync_xcr0(void)
{

    this_cpu(xcr0_last) = xgetbv(XCR_XFEATURE_ENABLED_MASK);
}

inline void _set_xcr0(u64 xfeatures)
{
    this_cpu(xcr0) = xfeatures;
    xsetbv_maybe(XCR_XFEATURE_ENABLED_MASK, xfeatures);
}

#ifdef __UXEN_unused__
inline uint64_t get_xcr0(void)
{
    return this_cpu(xcr0);
}
#endif  /* __UXEN_unused__ */


void xsave(struct vcpu *v, uint64_t mask)
{
    struct xsave_struct *ptr = v->arch.xsave_area;
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;

    if ( cpu_has_xsaveopt )
        asm volatile (
            ".byte " REX_PREFIX "0x0f,0xae,0x37"
            :
            : "a" (lmask), "d" (hmask), "D"(ptr)
            : "memory" );
    else
        asm volatile (
            ".byte " REX_PREFIX "0x0f,0xae,0x27"
            :
            : "a" (lmask), "d" (hmask), "D"(ptr)
            : "memory" );

    /* FIXME: performance improvement from calling vzero here, but
     * need to test cpu feature*/
}

void xrstor(struct vcpu *v, uint64_t mask)
{
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;

    struct xsave_struct *ptr = v->arch.xsave_area;

    xsetbv_maybe(XCR_XFEATURE_ENABLED_MASK,
                 v->domain->domain_id ? v->arch.xcr0_accum : xfeature_mask);

    asm volatile (
        ".byte " REX_PREFIX "0x0f,0xae,0x2f"
        :
        : "m" (*ptr), "a" (lmask), "d" (hmask), "D"(ptr) );
}

bool_t xsave_enabled(const struct vcpu *v)
{
    if ( cpu_has_xsave )
    {
        ASSERT(xsave_cntxt_size >= XSTATE_AREA_MIN_SIZE);
        ASSERT(v->arch.xsave_area);
    }

    return cpu_has_xsave;	
}

int xstate_alloc_save_area(struct vcpu *v)
{
    struct xsave_struct *save_area;

    if ( !cpu_has_xsave || is_idle_vcpu(v) )
        return 0;

    BUG_ON(xsave_cntxt_size < XSTATE_AREA_MIN_SIZE);

    if (v->domain->domain_id)   /* no vmi_xsave for dom0 */
        save_area = (struct xsave_struct *)(uintptr_t)
            (v->domain->vm_info_shared->vmi_xsave +
             v->vcpu_id * _uxen_info.ui_xsave_cntxt_size);
    else {
        /* XSAVE/XRSTOR requires the save area be 64-byte-boundary aligned. */
        save_area = _xzalloc(xsave_cntxt_size, 64);
        if ( save_area == NULL )
            return -ENOMEM;
    }

    save_area->fpu_sse.fcw = FCW_DEFAULT;
    save_area->fpu_sse.mxcsr = MXCSR_DEFAULT;
    save_area->xsave_hdr.xstate_bv = XSTATE_FP_SSE;

    v->arch.xsave_area = save_area;

    if (((size_t)v->arch.xsave_area & 0x3fULL) != 0) {
        printk(XENLOG_ERR "%s: vm%u.%u: unaligned xsave_area:0x%p\n",
               __func__, v->domain->domain_id, v->vcpu_id, v->arch.xsave_area);
        return -EINVAL;
    }

    v->arch.xcr0 = XSTATE_FP_SSE;
#ifndef UXEN_HOST_OSX
    /* on windows, save SSE plus whatever the VM uses */
    v->arch.xcr0_accum = XSTATE_FP_SSE;
#else  /* UXEN_HOST_OSX */
    /* on osx, always save everything the host supports */
    v->arch.xcr0_accum = xfeature_mask;
#endif  /* UXEN_HOST_OSX */

    return 0;
}

void xstate_free_save_area(struct vcpu *v)
{
    if (!v->domain->domain_id)
        xfree(v->arch.xsave_area);
    v->arch.xsave_area = NULL;
}

/* Collect the information of processor's extended state */
void xstate_init(void)
{
    u32 eax, ebx, ecx, edx;
    int cpu = smp_processor_id();
    u32 min_size;
    u64 xcr0;
    unsigned long flags;

    if ( boot_cpu_data.cpuid_level < XSTATE_CPUID )
        return;

    /* Set CR4_OSXSAVE and run "cpuid" to get xsave_cntxt_size. */
    set_in_cr4(X86_CR4_OSXSAVE);
    cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);

    BUG_ON((eax & XSTATE_FP_SSE) != XSTATE_FP_SSE);
    BUG_ON((eax & XSTATE_YMM) && !(eax & XSTATE_SSE));

    /* FP/SSE, XSAVE.HEADER, YMM */
    min_size =  XSTATE_AREA_MIN_SIZE;
    if ( eax & XSTATE_YMM )
        min_size += XSTATE_YMM_SIZE;
    BUG_ON(ecx < min_size);

    sync_xcr0();
    xcr0 = this_cpu(xcr0_last);

    if ( cpu == 0 )
    {
        /*
         * xsave_cntxt_size is the max size required by possible features.
         * We know FP/SSE and YMM about eax, and nothing about edx at present.
         */
        xsave_cntxt_size = ecx;
        xfeature_mask = xcr0;
        printk(XENLOG_WARNING "%s: using cntxt_size: 0x%x "
               "and states: 0x%"PRIx64"\n", __func__, xsave_cntxt_size,
               xfeature_mask);
        if (xfeature_mask & ~XCNTXT_MASK) {
            WARN_ONCE();
            xfeature_mask &= XCNTXT_MASK;
            printk(XENLOG_ERR "%s: using cntxt_size: 0x%x "
                   "and states: 0x%"PRIx64" (was 0x%"PRIx64")\n", __func__,
                   xsave_cntxt_size, xfeature_mask, xcr0);
        }

        /* Check XSAVEOPT feature. */
        cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
        cpu_has_xsaveopt = !!(eax & XSTATE_FEATURE_XSAVEOPT);

        /* XSAVE/XRSTOR requires the save area be 64-byte-boundary aligned. */
        _uxen_info.ui_xsave_cntxt_size = (xsave_cntxt_size + 63) & ~63;

        /* Compute xsave_cntxt_size_vmsave with only
         * xfeature_mask & XCNTXT_MASK_vmsave features enabled */
        cpu_irq_save(flags);
        xsetbv(XCR_XFEATURE_ENABLED_MASK, xfeature_mask & XCNTXT_MASK_vmsave);
        cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
        xsave_cntxt_size_vmsave = ebx;
        xsetbv(XCR_XFEATURE_ENABLED_MASK, xcr0);
        cpu_irq_restore(flags);
        printk(XENLOG_INFO "%s: using vmsave cntxt_size: 0x%x "
               "and states: 0x%"PRIx64"\n", __func__, xsave_cntxt_size_vmsave,
               xfeature_mask & XCNTXT_MASK_vmsave);
    }
    else
    {
        BUG_ON(xsave_cntxt_size != ecx);
        BUG_ON(xfeature_mask != (xfeature_mask & XCNTXT_MASK));
    }
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
