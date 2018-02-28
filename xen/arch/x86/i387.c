/*
 *  linux/arch/i386/kernel/i387.c
 *
 *  Copyright (C) 1994 Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  General FPU state handling cleanups
 *  Gareth Hughes <gareth@valinux.com>, May 2000
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2018, Bromium, Inc.
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
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/asm_defns.h>

/* eXtended features mask used by the host. */
static uint64_t xcr0_host = 0;

void fpu_early_init(void)
{

    if ( cpu_has_xsave && !xcr0_host )
        xcr0_host = xgetbv(XCR_XFEATURE_ENABLED_MASK);
}

void fpu_init(void)
{
    unsigned long val;
    
    asm volatile ( "fninit" );
    if ( cpu_has_xmm )
    {
        /* load default value into MXCSR control/status register */
        val = MXCSR_DEFAULT;
        asm volatile ( "ldmxcsr %0" : : "m" (val) );
    }
}

/*******************************/
/*     FPU Restore Functions   */
/*******************************/
/* Restore x87 extended state */
static inline void fpu_xrstor(struct vcpu *v, uint64_t mask)
{
#ifndef __UXEN__
    /*
     * XCR0 normally represents what guest OS set. In case of Xen itself, 
     * we set all supported feature mask before doing save/restore.
     */
    if ( unlikely(v->arch.xcr0_accum != xcr0_host) && 
         likely(read_cr0() & X86_CR0_TS) )
        asm volatile ( "movdqu %xmm0,%xmm0" );
#endif  /* __UXEN__ */
    sync_xcr0();
    set_xcr0(v->arch.xcr0_accum, XCR0_STATE_VMALL);
    xrstor(v, mask);
}

DEFINE_PER_CPU(bool_t, ffxse_efer);

/* Restor x87 FPU, MMX, SSE and SSE2 state */
static inline void fpu_fxrstor(struct vcpu *v)
{
    const char *fpu_ctxt = v->arch.fpu_ctxt;

    if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
        this_cpu(ffxse_efer) = !!(read_efer() & EFER_FFXSE);
        if (this_cpu(ffxse_efer))
            write_efer(read_efer() & ~((u64)EFER_FFXSE));
    }

    /*
     * FXRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools, by silently clearing the block.
     */
    asm volatile (
#ifdef __i386__
        "1: fxrstor %0            \n"
#else /* __x86_64__ */
        /* See above for why the operands/constraints are this way. */
        "1: " REX64_PREFIX "fxrstor (%2)\n"
#endif
        ".section .fixup,\"ax\"   \n"
        "2: push %%"__OP"ax       \n"
        "   push %%"__OP"cx       \n"
        "   push %%"__OP"di       \n"
        "   lea  %0,%%"__OP"di    \n"
        "   mov  %1,%%ecx         \n"
        "   xor  %%eax,%%eax      \n"
        "   rep ; stosl           \n"
        "   pop  %%"__OP"di       \n"
        "   pop  %%"__OP"cx       \n"
        "   pop  %%"__OP"ax       \n"
        "   jmp  1b               \n"
        _ASM_PREVIOUS "           \n"
        _ASM_EXTABLE(1b, 2b)
        : 
        : "m" (*fpu_ctxt),
          "i" (sizeof(v->arch.xsave_area->fpu_sse)/4)
#ifdef __x86_64__
          ,"cdaSDb" (fpu_ctxt)
#endif
        );
}

#ifndef __UXEN__
/* Restore x87 extended state */
static inline void fpu_frstor(struct vcpu *v)
{
    const char *fpu_ctxt = v->arch.fpu_ctxt;

    asm volatile ( "frstor %0" : : "m" (*fpu_ctxt) );
}
#endif  /* __UXEN__ */

/*******************************/
/*      FPU Save Functions     */
/*******************************/
/* Save x87 extended state */
static inline void fpu_xsave(struct vcpu *v)
{
#ifndef __UXEN__
    /* XCR0 normally represents what guest OS set. In case of Xen itself,
     * we set all accumulated feature mask before doing save/restore.
     */
    if ( unlikely(v->arch.xcr0_accum != xcr0_host) && 
         likely(read_cr0() & X86_CR0_TS) )
        asm volatile ( "movdqu %xmm0,%xmm0" );
#endif  /* __UXEN__ */
    set_xcr0(v->arch.xcr0_accum, XCR0_STATE_VMALL);
    xsave(v, v->arch.nonlazy_xstate_used ? XSTATE_ALL : XSTATE_LAZY);
}

/* Save x87 FPU, MMX, SSE and SSE2 state */
static inline void fpu_fxsave(struct vcpu *v)
{
    char *fpu_ctxt = v->arch.fpu_ctxt;

#ifdef __i386__
    asm volatile (
        "fxsave %0"
        : "=m" (*fpu_ctxt) );
#else /* __x86_64__ */
    /*
     * The only way to force fxsaveq on a wide range of gas versions. On 
     * older versions the rex64 prefix works only if we force an
     * addressing mode that doesn't require extended registers.
     */
    asm volatile (
        REX64_PREFIX "fxsave (%1)"
        : "=m" (*fpu_ctxt) : "cdaSDb" (fpu_ctxt) );
#endif
    
    /* Clear exception flags if FSW.ES is set. */
    if ( unlikely(fpu_ctxt[2] & 0x80) )
        asm volatile ("fnclex");
    
#ifndef __UXEN__
    /*
     * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
     * is pending. Clear the x87 state here by setting it to fixed
     * values. The hypervisor data segment can be sometimes 0 and
     * sometimes new user value. Both should be ok. Use the FPU saved
     * data block as a safe address because it should be in L1.
     */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
    {
        asm volatile (
            "emms\n\t"  /* clear stack tags */
            "fildl %0"  /* load to clear state */
            : : "m" (*fpu_ctxt) );
    }
#endif  /* __UXEN__ */

    if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD && this_cpu(ffxse_efer))
        write_efer(read_efer() | (u64)EFER_FFXSE);
}

#ifndef __UXEN__
/* Save x87 FPU state */
static inline void fpu_fsave(struct vcpu *v)
{
    char *fpu_ctxt = v->arch.fpu_ctxt;

    /* FWAIT is required to make FNSAVE synchronous. */
    asm volatile ( "fnsave %0 ; fwait" : "=m" (*fpu_ctxt) );
}

/*******************************/
/*       VCPU FPU Functions    */
/*******************************/
/* Restore FPU state whenever VCPU is schduled in. */
void vcpu_restore_fpu_eager(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));
    
    /* save the nonlazy extended state which is not tracked by CR0.TS bit */
    if ( v->arch.nonlazy_xstate_used )
    {
        /* Avoid recursion */
        clts();        
        fpu_xrstor(v, XSTATE_NONLAZY);
        stts();
    }
}
#endif  /* __UXEN__ */

#if defined(__i386__) || defined(UXEN_HOST_OSX)
DEFINE_PER_CPU(uint8_t, host_cr0_ts);

static inline void
clear_cr0_ts(void)
{
#if defined(__i386__)
    if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD)
        return;
#endif  /* __i386__ */

    clts();
}

static inline void
save_and_clear_cr0_ts(void)
{
#if defined(__i386__)
    if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD)
        return;
#endif  /* __i386__ */

    this_cpu(host_cr0_ts) = !!(read_cr0() & X86_CR0_TS);
    if (this_cpu(host_cr0_ts))
        clts();
}

static inline void
restore_cr0_ts(void)
{
#if defined(__i386__)
    if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD)
        return;
#endif  /* __i386__ */

    if (this_cpu(host_cr0_ts)) {
        stts();
        this_cpu(host_cr0_ts) = 0;
    }
}

#else  /* __i386__ || UXEN_HOST_OSX */
#define clear_cr0_ts() do { /* nothing */ } while (0)
#define save_and_clear_cr0_ts() do { /* nothing */ } while (0)
#define restore_cr0_ts() do { /* nothing */ } while (0)
#endif /* __i386__ || UXEN_HOST_OSX */

/* 
 * Restore FPU state when #NM is triggered.
 */
void vcpu_restore_fpu_lazy(struct vcpu *v)
{
    unsigned long flags;

    ASSERT(!vmexec_fpu_ctxt_switch);

    ASSERT(!is_idle_vcpu(v));

    cpu_irq_save(flags);
    clear_cr0_ts();

    if (v->fpu_dirtied) {
        cpu_irq_restore(flags);
        return;
    }

    if ( v->fpu_initialised ) {
        if ( xsave_enabled(v) )
            fpu_xrstor(v, XSTATE_LAZY);
        else if ( cpu_has_fxsr )
            fpu_fxrstor(v);
#ifndef __UXEN__
        else
            fpu_frstor(v);
#else   /* __UXEN__ */
        else
            BUG();
#endif  /* __UXEN__ */
    } else {
        fpu_init();
        if ( xsave_enabled(v) ) {
#ifndef __UXEN__
            if ( unlikely(v->arch.xcr0_accum != xcr0_host) && 
                 likely(read_cr0() & X86_CR0_TS) )
                asm volatile ( "movdqu %xmm0,%xmm0" );
#endif  /* __UXEN__ */
            sync_xcr0();
            set_xcr0(v->arch.xcr0_accum, XCR0_STATE_VMALL);
            xrstor(v, 0);           /* init xsave area for xsaveopt */
            xsave(v, XSTATE_LAZY);
        }
        v->fpu_initialised = 1;
    }

    if ( xsave_enabled(v) )
        set_xcr0(v->arch.xcr0, XCR0_STATE_VM);

    v->fpu_dirtied = 1;

    cpu_irq_restore(flags);
}

/* 
 * On each context switch, save the necessary FPU info of VCPU being switch 
 * out. It dispatches saving operation based on CPU's capability.
 */
void vcpu_save_fpu(struct vcpu *v)
{
    unsigned long flags;

    ASSERT(!vmexec_fpu_ctxt_switch);

    if ( !v->fpu_dirtied )
        return;

    ASSERT(!is_idle_vcpu(v));

    cpu_irq_save(flags);
    clear_cr0_ts();

    if ( xsave_enabled(v) )
        fpu_xsave(v);
    else if ( cpu_has_fxsr )
        fpu_fxsave(v);
#ifndef __UXEN__
    else
        fpu_fsave(v);
#else   /* __UXEN__ */
    else
        BUG();
#endif  /* __UXEN__ */

    v->fpu_dirtied = 0;

    cpu_irq_restore(flags);
}

void vcpu_save_fpu_hostcall(struct vcpu *v)
{
    ASSERT(!vmexec_fpu_ctxt_switch);

    vcpu_save_fpu(v);
    if (cpu_has_xsave)
        set_xcr0(xcr0_host, XCR0_STATE_HOST);
    assert_xcr0_state(XCR0_STATE_HOST);
}

void vcpu_save_fpu_host(struct vcpu *v)
{
    unsigned long flags;

    ASSERT(!vmexec_fpu_ctxt_switch);

    if (!xsave_enabled(v))
        return;

    cpu_irq_save(flags);
    save_and_clear_cr0_ts();

    set_xcr0(xfeature_mask, XCR0_STATE_HOSTALL);
    xsave(dom0->vcpu[smp_processor_id()], xfeature_mask);

    cpu_irq_restore(flags);
}

void vcpu_restore_fpu_host(struct vcpu *v)
{
    unsigned long flags;

    ASSERT(!vmexec_fpu_ctxt_switch);

    if (!xsave_enabled(v))
        return;

    cpu_irq_save(flags);
    clear_cr0_ts();

    set_xcr0(xfeature_mask, XCR0_STATE_HOSTALL);
    xrstor(dom0->vcpu[smp_processor_id()], xfeature_mask);
    set_xcr0(xcr0_host, XCR0_STATE_HOST);

    restore_cr0_ts();
    cpu_irq_restore(flags);
}

/* Initialize FPU's context save area */
int vcpu_init_fpu(struct vcpu *v)
{
    int rc = 0;
    
    /* Idle domain doesn't have FPU state allocated */
    if ( is_idle_vcpu(v) )
        goto done;

    if ( (rc = xstate_alloc_save_area(v)) != 0 )
        return rc;

    if ( v->arch.xsave_area )
        v->arch.fpu_ctxt = &v->arch.xsave_area->fpu_sse;
    else
    {
        v->arch.fpu_ctxt = _xzalloc(sizeof(v->arch.xsave_area->fpu_sse), 16);
        if ( !v->arch.fpu_ctxt )
        {
            rc = -ENOMEM;
            goto done;
        }
    }

done:
    return rc;
}

/* Free FPU's context save area */
void vcpu_destroy_fpu(struct vcpu *v)
{
    if ( v->arch.xsave_area )
        xstate_free_save_area(v);
    else
        xfree(v->arch.fpu_ctxt);
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
