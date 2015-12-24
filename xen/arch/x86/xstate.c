/*
 *  arch/x86/xstate.c
 *
 *  x86 extended state operations
 *
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2016, Bromium, Inc.
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
#include <asm/xstate.h>
#include <asm/asm_defns.h>

static u64 __devinitdata opt_xfeatures = 0;
integer_param("xfeatures", opt_xfeatures);

bool_t __read_mostly cpu_has_xsaveopt;

/*
 * Maximum size (in byte) of the XSAVE/XRSTOR save area required by all
 * the supported and enabled features on the processor, including the
 * XSAVE.HEADER. We only enable XCNTXT_MASK that we have known.
 */
u32 xsave_cntxt_size;

/* A 64-bit bitmask of the XSAVE/XRSTOR features supported by processor. */
u64 xfeature_mask;

/* Cached xcr0 for fast read */
DEFINE_PER_CPU(uint64_t, xcr0);

#ifndef __UXEN__
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
#endif  /* __UXEN__ */

/* Cached xcr0 to avoid writes */
DEFINE_PER_CPU(uint64_t, xcr0_last);

static inline void xsetbv_maybe(u32 index, u64 xfeatures)
{

    if (this_cpu(xcr0_last) != xfeatures ||
        index != XCR_XFEATURE_ENABLED_MASK) {
        u32 hi = xfeatures >> 32;
        u32 lo = (u32)xfeatures;

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

inline void set_xcr0(u64 xfeatures)
{
    this_cpu(xcr0) = xfeatures;
    xsetbv_maybe(XCR_XFEATURE_ENABLED_MASK, xfeatures);
}

#ifndef __UXEN__
inline uint64_t get_xcr0(void)
{
    return this_cpu(xcr0);
}
#endif  /* __UXEN__ */


static void _xsave(struct xsave_struct *ptr, uint64_t mask)
{
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


void xsave(struct vcpu *v, uint64_t mask)
{
    struct xsave_struct *ptr = v->arch.xsave_area;

    _xsave(ptr, mask);
}

void xsave_host(struct vcpu *v, uint64_t mask)
{
    struct xsave_struct *ptr = v->arch.host_xsave_area;

    _xsave(ptr, mask);
}

static void _xrstor(struct xsave_struct *ptr, uint64_t mask)
{
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;

    asm volatile (
        ".byte " REX_PREFIX "0x0f,0xae,0x2f"
        :
        : "m" (*ptr), "a" (lmask), "d" (hmask), "D"(ptr) );

}

void xrstor(struct vcpu *v, uint64_t mask)
{
    struct xsave_struct *ptr = v->arch.xsave_area;

#ifdef __UXEN__
    xsetbv_maybe(XCR_XFEATURE_ENABLED_MASK, v->arch.xcr0_accum);
#endif  /* __UXEN__ */

    _xrstor(ptr, mask);
}

void xrstor_host(struct vcpu *v, uint64_t mask)
{
    struct xsave_struct *ptr = v->arch.host_xsave_area;

#ifdef __UXEN__
    xsetbv_maybe(XCR_XFEATURE_ENABLED_MASK, xfeature_mask);
#endif  /* __UXEN__ */

    _xrstor(ptr, mask);
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
    struct xsave_struct *save_area, *host_save_area;

    if ( !cpu_has_xsave || is_idle_vcpu(v) )
        return 0;

    BUG_ON(xsave_cntxt_size < XSTATE_AREA_MIN_SIZE);



    if (v->domain->domain_id) {  /* no vmi_xsave for dom0 */
        save_area = (struct xsave_struct *)(uintptr_t)
            (v->domain->vm_info_shared->vmi_xsave +
             2 * v->vcpu_id * xsave_cntxt_size);
        host_save_area = (struct xsave_struct *)(uintptr_t)
            (v->domain->vm_info_shared->vmi_xsave +
             (1 + 2 * v->vcpu_id) * xsave_cntxt_size);
    } else {
        /* XSAVE/XRSTOR requires the save area be 64-byte-boundary aligned. */
        save_area = _xzalloc(xsave_cntxt_size, 64);
        if ( save_area == NULL )
            return -ENOMEM;
        host_save_area = _xzalloc(xsave_cntxt_size, 64);
        if ( host_save_area == NULL ) {
	    xfree(save_area);
            return -ENOMEM;
        }
    }

    save_area->fpu_sse.fcw = FCW_DEFAULT;
    save_area->fpu_sse.mxcsr = MXCSR_DEFAULT;
    save_area->xsave_hdr.xstate_bv = XSTATE_FP_SSE;

    host_save_area->fpu_sse.fcw = FCW_DEFAULT;
    host_save_area->fpu_sse.mxcsr = MXCSR_DEFAULT;
    host_save_area->xsave_hdr.xstate_bv = xfeature_mask;

    v->arch.xsave_area = save_area;
    v->arch.host_xsave_area = host_save_area;
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
    if (!v->domain->domain_id) {
        xfree(v->arch.xsave_area);
        xfree(v->arch.host_xsave_area);
    }
    v->arch.xsave_area = NULL;
    v->arch.host_xsave_area = NULL;
}

/* Collect the information of processor's extended state */
void xstate_init(void)
{
    u32 eax, ebx, ecx, edx;
    int cpu = smp_processor_id();
    u32 min_size;
    u64 curr_xcr0, xcr0;

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

    curr_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
    if ( opt_xfeatures ) {
        sync_xcr0();
        set_xcr0(((((u64)edx << 32) | eax) & (curr_xcr0 | opt_xfeatures)) &
                 XCNTXT_MASK);
        cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
        xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
        set_xcr0(curr_xcr0);             
    } else
        xcr0 = curr_xcr0;

    if ( cpu == 0 )
    {
        /*
         * xsave_cntxt_size is the max size required by enabled features.
         * We know FP/SSE and YMM about eax, and nothing about edx at present.
         */
        xsave_cntxt_size = ebx;
        xfeature_mask = xcr0 & XCNTXT_MASK;
        printk("%s: using cntxt_size: 0x%x and states: 0x%"PRIx64
            " (masked 0x%"PRIx64")\n", __func__, xsave_cntxt_size,
               xcr0, xfeature_mask);

        /* Check XSAVEOPT feature. */
        cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
        cpu_has_xsaveopt = !!(eax & XSTATE_FEATURE_XSAVEOPT);

        /* XSAVE/XRSTOR requires the save area be 64-byte-boundary aligned. */
        _uxen_info.ui_xsave_cntxt_size = 2 * ((xsave_cntxt_size + 63) & ~63);
    }
    else
    {
        BUG_ON(xsave_cntxt_size != ebx);
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
