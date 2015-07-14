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
 * Copyright 2011-2015, Bromium, Inc.
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
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/asm_defns.h>

/* eXtended features mask used by the host. */
static uint64_t xcr0_host = 0;

/* static */ void fpu_init(void)
{
    unsigned long val;
    
    asm volatile ( "fninit" );
    if ( cpu_has_xmm )
    {
        /* load default value into MXCSR control/status register */
        val = MXCSR_DEFAULT;
        asm volatile ( "ldmxcsr %0" : : "m" (val) );
    }

    if ( cpu_has_xsave && !xcr0_host )
        xcr0_host = xgetbv(XCR_XFEATURE_ENABLED_MASK);
}

/*******************************/
/*     FPU Restore Functions   */
/*******************************/
/* Restore x87 extended state */
static inline void fpu_xrstor(struct vcpu *v, uint64_t mask)
{
    /*
     * XCR0 normally represents what guest OS set. In case of Xen itself, 
     * we set all supported feature mask before doing save/restore.
     */
    if ( unlikely(v->arch.xcr0_accum != xcr0_host) && 
         likely(read_cr0() & X86_CR0_TS) )
        asm volatile ( "movdqu %xmm0,%xmm0" );
    sync_xcr0();
    set_xcr0(v->arch.xcr0_accum); /* XXX optional */
    xrstor(v, mask);
    set_xcr0(xcr0_host);
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
    /* XCR0 normally represents what guest OS set. In case of Xen itself,
     * we set all accumulated feature mask before doing save/restore.
     */
    if ( unlikely(v->arch.xcr0_accum != xcr0_host) && 
         likely(read_cr0() & X86_CR0_TS) )
        asm volatile ( "movdqu %xmm0,%xmm0" );
    set_xcr0(v->arch.xcr0_accum);
    xsave(v, v->arch.nonlazy_xstate_used ? XSTATE_ALL : XSTATE_LAZY);
    set_xcr0(xcr0_host);    
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

/* 
 * Restore FPU state when #NM is triggered.
 */
void vcpu_restore_fpu_lazy(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

#ifdef __i386__
    /* Avoid recursion. */
    if (boot_cpu_data.x86_vendor ==  X86_VENDOR_AMD)
        clts();
#endif  /* __UXEN__ */

    if ( v->fpu_dirtied )
        return;

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
            if ( unlikely(v->arch.xcr0_accum != xcr0_host) && 
                 likely(read_cr0() & X86_CR0_TS) )
                asm volatile ( "movdqu %xmm0,%xmm0" );
            sync_xcr0();
            set_xcr0(v->arch.xcr0_accum);
            xrstor(v, 0);           /* init xsave area for xsaveopt */
            xsave(v, XSTATE_LAZY);
            set_xcr0(xcr0_host);
        }
        v->fpu_initialised = 1;
    }

    v->fpu_dirtied = 1;
}

/* 
 * On each context switch, save the necessary FPU info of VCPU being switch 
 * out. It dispatches saving operation based on CPU's capability.
 */
void vcpu_save_fpu(struct vcpu *v)
{
    if ( !v->fpu_dirtied )
        return;

    ASSERT(!is_idle_vcpu(v));

#ifndef __UXEN__
    /* This can happen, if a paravirtualised guest OS has set its CR0.TS. */
    clts();
#endif  /* __UXEN__ */

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
#ifndef __UXEN__
    stts();
#endif  /* __UXEN__ */
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
