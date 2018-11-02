/*
 *  uxen_ops.c
 *  uxen
 *
 * Copyright 2011-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"
#include <xen/errno.h>
#include <uxen_ioctl.h>

#include <stddef.h>

#include <public/domctl.h>
#include <public/event_channel.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#include "pagemap.h"

#include "attoxen-api/ax_constants.h"
#include "attoxen-api/hv_tests.h"

static ULONG build_number = 0;

uint8_t *frametable = NULL;
unsigned int frametable_size;
uint8_t *frametable_populated = NULL;
static char *percpu_area = NULL;
static size_t percpu_area_size;
struct vm_info *dom0_vmi = NULL;
static BOOLEAN ui_hvm_io_bitmap_contiguous = TRUE;
static uint32_t mapcache_size = 0;
static uintptr_t *mapcache_va = 0;

#ifdef DEBUG_PAGE_ALLOC
struct pinfo *pinfotable = NULL;
static unsigned int pinfotable_size;
#endif  /* DEBUG_PAGE_ALLOC */

uxen_pfn_t uxen_zero_mfn = ~0;

static KDPC uxen_cpu_ipi_dpc[MAXIMUM_PROCESSORS];
static KSPIN_LOCK uxen_cpu_ipi_spinlock[MAXIMUM_PROCESSORS];
static uint32_t uxen_cpu_ipi_raised_vectors[MAXIMUM_PROCESSORS];
PETHREAD uxen_idle_thread[MAXIMUM_PROCESSORS];
KEVENT uxen_idle_thread_event[MAXIMUM_PROCESSORS];
static int resume_requested = 0;
static uint32_t idle_thread_suspended = 0;

static KEVENT dummy_event;

static LARGE_INTEGER uxen_start_time;
static LARGE_INTEGER uxen_host_counter_start, uxen_host_counter_freq;

extern BOOLEAN *KdDebuggerEnabled;

static void __cdecl uxen_op_wake_vm(struct vm_vcpu_info_shared *vcis);
static int uxen_vmi_destroy_vm(struct vm_info *vmi);
static void quiesce_execution(void);
static void resume_execution(void);
static void uxen_flush_rcu(void);

static intptr_t
vm_info_compare_key(void *ctx, const void *b, const void *key)
{
    const struct vm_info * const pnp = b;
    const struct vm_info_shared * const fhp = key;
    int i;

    if (pnp->vmi_shared.vmi_domid < fhp->vmi_domid)
        return -1;
    if (pnp->vmi_shared.vmi_domid > fhp->vmi_domid)
        return 1;

    for (i = 0; i < sizeof(fhp->vmi_uuid); i++) {
        if (pnp->vmi_shared.vmi_uuid[i] < fhp->vmi_uuid[i])
            return -1;
        if (pnp->vmi_shared.vmi_uuid[i] > fhp->vmi_uuid[i])
            return 1;
    }
    return 0;
}

static intptr_t
vm_info_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct vm_info * const np = node;

    return vm_info_compare_key(ctx, parent, &np->vmi_shared);
}

const rb_tree_ops_t vm_info_rbtree_ops = {
    /* .rbto_compare_nodes = */ vm_info_compare_nodes,
    /* .rbto_compare_key = */ vm_info_compare_key,
    /* .rbto_node_offset = */ offsetof(struct vm_info, vmi_rbnode),
    /* .rbto_context = */ NULL
};

#ifdef CONTEXT_i386
#define Rip Eip
#endif

int
uxen_except_handler(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
    intptr_t ret;
    char symbol_buffer[200];

    // dprintk("uxen_except_handler: rip %Ix\n", ep->ContextRecord->Rip);

    if (uxen_do_process_ud2) {
        struct cpu_user_regs regs;
#ifndef CONTEXT_i386
        regs.r15 = ep->ContextRecord->R15;
        regs.r14 = ep->ContextRecord->R14;
        regs.r13 = ep->ContextRecord->R13;
        regs.r12 = ep->ContextRecord->R12;
        regs.rbp = ep->ContextRecord->Rbp;
        regs.rbx = ep->ContextRecord->Rbx;
        regs.r11 = ep->ContextRecord->R11;
        regs.r10 = ep->ContextRecord->R10;
        regs.r9 = ep->ContextRecord->R9;
        regs.r8 = ep->ContextRecord->R8;
        regs.rax = ep->ContextRecord->Rax;
        regs.rcx = ep->ContextRecord->Rcx;
        regs.rdx = ep->ContextRecord->Rdx;
        regs.rsi = ep->ContextRecord->Rsi;
        regs.rdi = ep->ContextRecord->Rdi;
        regs.rip = ep->ContextRecord->Rip;
        regs.cs = (uint16_t)ep->ContextRecord->SegCs;
        regs.rflags = ep->ContextRecord->EFlags;
        regs.rsp = ep->ContextRecord->Rsp;
        regs.ss = (uint16_t)ep->ContextRecord->SegSs;
        regs.es = (uint16_t)ep->ContextRecord->SegEs;
        regs.ds = (uint16_t)ep->ContextRecord->SegDs;
        regs.fs = (uint16_t)ep->ContextRecord->SegFs;
        regs.gs = (uint16_t)ep->ContextRecord->SegGs;
#else
        regs.ebx = ep->ContextRecord->Ebx;
        regs.ecx = ep->ContextRecord->Ecx;
        regs.edx = ep->ContextRecord->Edx;
        regs.esi = ep->ContextRecord->Esi;
        regs.edi = ep->ContextRecord->Edi;
        regs.ebp = ep->ContextRecord->Ebp;
        regs.eax = ep->ContextRecord->Eax;
        regs.eip = ep->ContextRecord->Eip;
        regs.cs = (uint16_t)ep->ContextRecord->SegCs;
        regs.eflags = ep->ContextRecord->EFlags;
        regs.esp = ep->ContextRecord->Esp;
        regs.ss = (uint16_t)ep->ContextRecord->SegSs;
        regs.es = (uint16_t)ep->ContextRecord->SegEs;
        regs.ds = (uint16_t)ep->ContextRecord->SegDs;
        regs.fs = (uint16_t)ep->ContextRecord->SegFs;
        regs.gs = (uint16_t)ep->ContextRecord->SegGs;
#endif
        ret = uxen_do_process_ud2(&regs);
#ifndef CONTEXT_i386
        ep->ContextRecord->Rip = regs.rip;
#else
        ep->ContextRecord->Eip = regs.eip;
#endif
        switch (ret) {
        case 0:
            return EXCEPTION_CONTINUE_EXECUTION;
        case 2:
            return EXCEPTION_EXECUTE_HANDLER;
        }

#ifdef _WIN64
        uxen_stacktrace(ep->ContextRecord);
#endif
    }

    if (uxen_info)
        uxen_info->ui_running = 0;

    if (uxen_do_lookup_symbol)
        uxen_do_lookup_symbol(ep->ContextRecord->Rip, symbol_buffer,
                              sizeof(symbol_buffer));
    else
        strncpy(symbol_buffer, "???", 4);
    printk("rip %Ix sym %s\n", ep->ContextRecord->Rip, symbol_buffer);
#if !defined(__UXEN_EMBEDDED__)
    dprintk("lduxen 0x%p; gdb uxen\n", uxen_hv);
#endif
    printk(".cxr 0x%p\n", ep->ContextRecord);
    if (*KdDebuggerEnabled)
	DbgBreakPoint();
    return EXCEPTION_EXECUTE_HANDLER;
}

int
hostdrv_except_handler(char *fmt, ...)
{
    PULONG_PTR stack_frames;
    USHORT collapsed, frames_captured, i, max_frames;
    ULONG_PTR start, end;
    ULONG hash;
    va_list ap;

    va_start(ap, fmt);
    uxen_vprintk(NULL, fmt, ap);
    va_end(ap);

    max_frames = 64;
    stack_frames = kernel_malloc(sizeof(*stack_frames) * max_frames);
    if (!stack_frames) {
        fail_msg("failed to allocate stack trace buffer");
        goto out;
    }

    collapsed = 0;
    start = (ULONG_PTR)uxen_drvobj->DriverStart;
    end = start + uxen_drvobj->DriverSize;

    frames_captured = RtlCaptureStackBackTrace(0, max_frames,
                                               (PVOID *)stack_frames, &hash);
    if (frames_captured > 0) {
        for (i = 0; i < frames_captured; i++) {
            if (IN_RANGE(stack_frames[i], start, end)) {
                if (collapsed) {
                    printk("  --- collapsing %d non-uxen frames ---\n",
                           collapsed);
                    collapsed = 0;
                }
                printk("  %02x: %p  uxen+0x%p\n",
                       i, stack_frames[i], stack_frames[i] - start);
            } else
                collapsed++;
        }
        if (collapsed)
            printk("  --- collapsing %d non-uxen frames ---\n", collapsed);
        printk("  stack trace bucket: %08x, total frames: %d:\n",
               hash, frames_captured);
    }

  out:
    if (stack_frames)
        kernel_free(stack_frames, sizeof(*stack_frames) * max_frames);

    return EXCEPTION_EXECUTE_HANDLER;
}

static void
uxen_cpu_ipi_cb(IN PKDPC Dpc, IN PVOID DeferredContext,
		IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    unsigned int host_cpu = (unsigned int)(ULONG_PTR)SystemArgument1;
    unsigned int vectors, v;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (uxen_info->ui_running == 0)
	return;

    KeAcquireSpinLockAtDpcLevel(&uxen_cpu_ipi_spinlock[host_cpu]);
    vectors = uxen_cpu_ipi_raised_vectors[host_cpu];
    uxen_cpu_ipi_raised_vectors[host_cpu] = 0;
    KeReleaseSpinLockFromDpcLevel(&uxen_cpu_ipi_spinlock[host_cpu]);
    while (vectors) {
	v = ffs(vectors) - 1;
	vectors &= ~(1 << v);
        try_call(, , uxen_do_dispatch_ipi, 0xff - v);
    }
}

static void __cdecl
uxen_op_cpu_ipi(uint64_t host_cpu, uint64_t vector)
{
    PKDPC dpc;
    KIRQL old_irql;
    int queue_dpc = 0;

    if (uxen_info->ui_running == 0)
	return;

    if (host_cpu < max_host_cpu && vector >= 0xf0 && vector <= 0xff) {
	KeAcquireSpinLock(&uxen_cpu_ipi_spinlock[host_cpu], &old_irql);
	if ((uxen_cpu_ipi_raised_vectors[host_cpu] & (1 << (0xff - vector)))
	    == 0) {
	    uxen_cpu_ipi_raised_vectors[host_cpu] |= 1 << (0xff - vector);
	    queue_dpc = 1;
	}
	KeReleaseSpinLock(&uxen_cpu_ipi_spinlock[host_cpu], old_irql);
	/* XXX insn barrier */
	if (queue_dpc) {
	    dpc = &uxen_cpu_ipi_dpc[host_cpu];
	    KeInsertQueueDpc(dpc, (PVOID)(ULONG_PTR)host_cpu, NULL);
	}
    }
}

static void
uxen_vcpu_ipi_cb(IN PKDPC Dpc, IN PVOID DeferredContext,
		 IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    struct vm_vcpu_info *vci = DeferredContext;
    preemption_t pre;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    spinlock_acquire(vci->vci_ipi_lck, pre);
    vci->vci_ipi_queued = 0;
    spinlock_release(vci->vci_ipi_lck, pre);
}

static void __cdecl
uxen_op_vcpu_ipi(struct vm_vcpu_info_shared *vcis)
{
    struct vm_vcpu_info *vci = (struct vm_vcpu_info *)vcis;
    preemption_t pre;

    if (!is_vci_runnable(vci))
	return;

    spinlock_acquire(vci->vci_ipi_lck, pre);
    vci->vci_ipi_queued++;
    if (vci->vci_ipi_cpu != vci->vci_host_cpu) {
        if (vci->vci_ipi_queued > 1) {
            KeRemoveQueueDpc(&vci->vci_ipi_dpc);
            vci->vci_ipi_queued--;
        }
	KeSetTargetProcessorDpc(&vci->vci_ipi_dpc, (CCHAR)vci->vci_host_cpu);
	vci->vci_ipi_cpu = vci->vci_host_cpu;
    }
    if (vci->vci_ipi_queued == 1)
    KeInsertQueueDpc(&vci->vci_ipi_dpc, NULL, NULL);
    else {
        DASSERT(vci->vci_ipi_queued == 2);
        vci->vci_ipi_queued = 1;
    }

    if (!is_vci_runnable(vci)) {
        KeRemoveQueueDpc(&vci->vci_ipi_dpc);
        vci->vci_ipi_queued = 0;
    }
    spinlock_release(vci->vci_ipi_lck, pre);
}

static void __cdecl
uxen_op_vcpu_ipi_cancel(struct vm_vcpu_info_shared *vcis)
{
    struct vm_vcpu_info *vci = (struct vm_vcpu_info *)vcis;
    preemption_t pre;

    if (!is_vci_runnable(vci))
	return;

    spinlock_acquire(vci->vci_ipi_lck, pre);
    KeRemoveQueueDpc(&vci->vci_ipi_dpc);
    vci->vci_ipi_queued = 0;
    spinlock_release(vci->vci_ipi_lck, pre);
}

void
update_ui_host_counter(void)
{
    LARGE_INTEGER now;
    LARGE_INTEGER system_time;

    KeQuerySystemTime(&system_time);

    now = KeQueryPerformanceCounter(NULL);
    uxen_info->ui_host_counter_unixtime = (system_time.QuadPart - 116444736000000000LL) * 100;
    uxen_info->ui_host_counter_tsc = __rdtsc();
    uxen_info->ui_host_counter = now.QuadPart -
        uxen_host_counter_start.QuadPart;
}

static void
uxen_exception_event_all(void)
{
    affinity_t aff;
    struct vm_info *vmi, *tvmi;

    aff = uxen_lock();
    RB_TREE_FOREACH_SAFE(vmi, &uxen_devext->de_vm_info_rbtree, tvmi) {
        if (vmi->vmi_ioemu_exception_event)
            KeSetEvent(vmi->vmi_ioemu_exception_event, 0, FALSE);
    }
    uxen_unlock(aff);
}

static void
uxen_idle_thread_fn(void *context)
{
    unsigned int cpu = (uintptr_t)context;
    unsigned int host_cpu;
    uint32_t increase;

    uxen_cpu_pin(cpu);

    dprintk("cpu%u: idle thread ready\n", cpu);

    while (uxen_info->ui_running) {
        LONG x;
        preemption_t i;
        LARGE_INTEGER timeout, now;
        int had_timeout = 0;

        if (!cpu) {
            KeQuerySystemTime(&now);
            timeout.QuadPart = now.QuadPart + uxen_info->ui_host_idle_timeout;
        }

        do {
            KeWaitForSingleObject(
                &uxen_idle_thread_event[cpu], Executive, KernelMode, TRUE,
                (!cpu && uxen_info->ui_host_idle_timeout &&
                 !idle_thread_suspended) ? &timeout : NULL);
            KeClearEvent(&uxen_idle_thread_event[cpu]);
            MemoryBarrier();
            if (!cpu && resume_requested) {
                idle_thread_suspended = 0;
                printk_with_timestamp("power state change: resuming\n");
                update_ui_host_counter();
                /* uxen_call without de_executing and suspend_block call */
                while (uxen_pages_increase_reserve(&i, IDLE_RESERVE, &increase))
                    /* nothing */ ;
                try_call(, , uxen_do_resume_xen);
                resume_execution();
                resume_requested = 0;
                KeSetEvent(&uxen_devext->de_suspend_event, 0, FALSE);
                uxen_pages_decrease_reserve(i, increase);
                KeQuerySystemTime(&now);
                for (host_cpu = 1; host_cpu < max_host_cpu; host_cpu++)
                    uxen_signal_idle_thread(host_cpu);
                uxen_sys_signal_v4v();
            }
        } while (idle_thread_suspended && uxen_info->ui_running);

        if (!uxen_info->ui_running)
            break;

        if (!cpu && uxen_info->ui_host_idle_timeout) {
            timeout.QuadPart = now.QuadPart + uxen_info->ui_host_idle_timeout;
            KeQuerySystemTime(&now);
            if (now.QuadPart >= timeout.QuadPart) {
                update_ui_host_counter();
                had_timeout = 1;
                uxen_info->ui_host_idle_timeout = 0;
            } else
                uxen_info->ui_host_idle_timeout = timeout.QuadPart -
                    now.QuadPart;
        }

        /* like uxen_call, except do not call suspend_block, but loop
         * to wait for idle_thread_event */
        if (uxen_pages_increase_reserve(&i, IDLE_RESERVE, &increase))
            x = 0;
        else {
            while ((x = uxen_devext->de_executing) == 0 ||
                   InterlockedCompareExchange(
                       &uxen_devext->de_executing, x + 1, x) != x) {
                if (x == 0)
                    break;
            }
            if (x == 0)
                uxen_pages_decrease_reserve(i, increase);
        }
        if (x == 0) {
            /* Reset a timeout if we were going to signal that a
             * timeout had occurred. */
            if (!cpu && had_timeout)
                uxen_info->ui_host_idle_timeout = 1;
            continue;
        }
        try_call(, , uxen_do_run_idle_thread, had_timeout);
        if (!InterlockedDecrement(&uxen_devext->de_executing))
            KeSetEvent(&uxen_devext->de_suspend_event, 0, FALSE);
        uxen_pages_decrease_reserve(i, increase);
        if (!cpu) {
            if (idle_free_list && idle_free_free_list())
                uxen_signal_idle_thread(cpu);
            if (uxen_info->ui_exception_event_all) {
                uxen_info->ui_exception_event_all = 0;
                uxen_exception_event_all();
            }
        }
    }

    dprintk("cpu%u: idle thread exiting\n", cpu);
}

static void __cdecl
uxen_op_signal_idle_thread(uint64_t mask)
{
    unsigned int host_cpu;

    if (uxen_info->ui_running == 0)
	return;

    for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++) {
	if (mask & affinity_mask(host_cpu))
            uxen_signal_idle_thread(host_cpu);
    }
}

void
set_host_preemption(uint64_t disable)
{

    if (disable) {
	KIRQL i;
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
	KeRaiseIrql(DISPATCH_LEVEL, &i);
    } else {
	KeLowerIrql(PASSIVE_LEVEL);
    }
}

static uint64_t __cdecl
uxen_op_host_needs_preempt(void)
{
#ifdef _WIN64
    uint8_t volatile *kprcb =
	(uint8_t volatile *)__readgsqword(offsetof(KPCR, CurrentPrcb));

    switch (build_number) {
    case 7601:
        /* Windows7.7601 */
        // +0x21d9 QuantumEnd       : UChar
        // +0x2180 DpcData          : [2] _KDPC_DATA
        //        +0x018 DpcQueueDepth    : Int4B
        if (*(kprcb + 0x21d9))
            return 1;
        if (*(uint32_t volatile *)(kprcb + 0x2180 + 0x018))
            return 1;
        break;
    case 9200:
        /* Windows8.9200 */
        // +0x2dd9 QuantumEnd       : UChar
        // +0x2d80 DpcData          : [2] _KDPC_DATA
        //        +0x018 DpcQueueDepth    : Int4B
        if (*(kprcb + 0x2dd9))
            return 1;
        if (*(uint32_t volatile *)(kprcb + 0x2d80 + 0x018))
            return 1;
        break;
    case 9600:
    case 10240:
    case 10586:
    case 14393:
        /* Windows8.1.u1.9600 */
        /* Windows10.10240 TH1 */
        /* Windows10.10586 TH2 */
        /* Windows10.14393 RS1/AU */
        // +0x2de9 QuantumEnd       : UChar
        // +0x2d80 DpcData          : [2] _KDPC_DATA
        //        +0x018 DpcQueueDepth    : Int4B
        if (*(kprcb + 0x2de9))
            return 1;
        if (*(uint32_t volatile *)(kprcb + 0x2d80 + 0x018))
            return 1;
    case 15063:
    case 16299:
    case 17083:
    case 17133:
    case 17134:
    case 17655:
    case 17763:
        /* Windows10.15063 RS2/CU */
        /* Windows10.16299 RS3/FCU */
        /* Windows10.17083 RS4 preview */
        /* Windows10.17133 RS4 RC1 */
        /* Windows10.17134 RS4 RC2 */
        /* Windows10.17655 RS5 preview */
        /* Windows10.17763 RS5 RC */
        // +0x2e69 QuantumEnd       : UChar
        // +0x2e00 DpcData          : [2] _KDPC_DATA
        //        +0x018 DpcQueueDepth    : Int4B
        if (*(kprcb + 0x2e69))
            return 1;
        if (*(uint32_t volatile *)(kprcb + 0x2e00 + 0x018))
            return 1;
        break;
    }

    return 0;
#else
    uint8_t volatile *kprcb =
	(uint8_t volatile *)__readfsdword(offsetof(KPCR, Prcb));

    /* Windows7.7601 */
    // +0x1931 QuantumEnd       : UChar
    // +0x18e0 DpcData          : [2] _KDPC_DATA
    //        +0x00c DpcQueueDepth    : Int4B
    if (*(kprcb + 0x1931))
	return 1;
    if (*(uint32_t volatile *)(kprcb + 0x18e0 + 0x00c))
	return 1;

    return 0;
#endif
}

static void
uxen_vcpu_timer_cb(IN PKDPC Dpc, IN PVOID DeferredContext,
		   IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    struct vm_vcpu_info *vci = (struct vm_vcpu_info *)DeferredContext;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!is_vci_runnable(vci))
	return;

    vci->vci_shared.vci_has_timer_interrupt = 1;
    uxen_op_wake_vm(&vci->vci_shared);
    /* Check if vcpu started running on another cpu after the timer
     * was set.  If so, interrupt it there. */
    if (vci->vci_host_cpu != KeGetCurrentProcessorNumber())
        uxen_op_vcpu_ipi(&vci->vci_shared);
}

static void __cdecl
uxen_op_set_vcpu_timer(struct vm_vcpu_info_shared *vcis, uint64_t expire)
{
    LARGE_INTEGER timeDue;
    struct vm_vcpu_info *vci = (struct vm_vcpu_info *)vcis;

    if (!is_vci_runnable(vci))
	return;

    timeDue.QuadPart = TIME_RELATIVE(expire);
    if (timeDue.QuadPart >= 0)
	timeDue.QuadPart = -1;
    if (vci->vci_timer_cpu != vci->vci_host_cpu) {
        vci->vci_timer_cpu = vci->vci_host_cpu;
        KeSetTargetProcessorDpc(&vci->vci_timer_dpc, (CCHAR)vci->vci_timer_cpu);
    }
    KeSetTimerEx(&vci->vci_timer, timeDue, 0, &vci->vci_timer_dpc);

    if (!is_vci_runnable(vci))
	KeCancelTimer(&vci->vci_timer);
}

static uint64_t __cdecl
uxen_op_get_host_counter(void)
{
    LARGE_INTEGER time;

    time = KeQueryPerformanceCounter(NULL);

    return time.QuadPart - uxen_host_counter_start.QuadPart;
}

void
uxen_update_unixtime_generation(void)
{

    if (uxen_info) {
        uxen_info->ui_unixtime_generation++;
        if (uxen_idle_thread[0])
            uxen_signal_idle_thread(0);
    }
}

static uint64_t __cdecl
uxen_op_get_unixtime(void)
{
    LARGE_INTEGER system_time;

    KeQuerySystemTime(&system_time);

    /* January 1, 1601 -> January 1, 1970 -- in ns */
    return (system_time.QuadPart - 116444736000000000LL) * 100;
}

static void __cdecl
uxen_op_wake_vm(struct vm_vcpu_info_shared *vcis)
{
    struct vm_vcpu_info *vci = (struct vm_vcpu_info *)vcis;

    if (InterlockedExchange(&vci->vci_shared.vci_host_halted, 0) == 1)
        KeSetEvent(&vci->vci_runnable, 0, FALSE);
}

int
suspend_block(preemption_t i, uint32_t pages, uint32_t *reserve_increase)
{
    int ret;

    ASSERT(!preemption_enabled());
    while (1) {
        MemoryBarrier();
        if (uxen_devext->de_executing)
            break;
        uxen_pages_decrease_reserve(i, *reserve_increase);
        if (i >= DISPATCH_LEVEL)
            return -EAGAIN;
        KeWaitForSingleObject(&uxen_devext->de_resume_event, Executive,
                              KernelMode, FALSE, NULL);
        ret = uxen_pages_increase_reserve(&i, pages, reserve_increase);
        if (ret)
            return -ENOMEM;
    }
    return 0;
}

static void __cdecl
uxen_op_notify_exception(struct vm_info_shared *vmis)
{
    struct vm_info *vmi, *tvmi, *evmi;
    int vmi_exists = 0;

    vmi = (struct vm_info *)vmis;

    RB_TREE_FOREACH_SAFE(evmi, &uxen_devext->de_vm_info_rbtree, tvmi) {
        if (vmi == evmi) {
            printk("%s: vmi %p in rbt\n", __FUNCTION__, vmi);
            vmi_exists = 1;
            break;
        }
    }

    if (vmi_exists == 0)
        printk("%s: vmi %p not in rbt (avoiding crash)\n", __FUNCTION__, vmi);
    else {
        if (vmi->vmi_ioemu_exception_event)
            KeSetEvent(vmi->vmi_ioemu_exception_event, 0, FALSE);
    }
}

static void __cdecl
uxen_op_notify_vram(struct vm_info_shared *vmis)
{
    struct vm_info *vmi = (struct vm_info *)vmis;

    if (vmi->vmi_ioemu_vram_event)
	KeSetEvent(vmi->vmi_ioemu_vram_event, 0, FALSE);
}

static uint64_t __cdecl
uxen_op_signal_event(struct vm_vcpu_info_shared *vcis,
                     struct host_event_channel *hec,
                     void * volatile *_wait_event)
{
    struct vm_vcpu_info *vci = (struct vm_vcpu_info *)vcis;
    KEVENT * volatile *wait_event = (KEVENT * volatile *)_wait_event;

    if (!hec || !hec->request || !is_vci_runnable(vci))
	return 1;

    if (hec->completed && *wait_event != hec->completed) {
        if (*wait_event && *wait_event != &dummy_event) {
            fail_msg("%s: nested waiting signal event", __FUNCTION__);
            return 1;
        }
        *wait_event = hec->completed;
    }
    KeSetEvent(hec->request, 0, FALSE);
    return 0;
}

static uint64_t __cdecl
uxen_op_check_ioreq(struct vm_vcpu_info_shared *vcis)
{
    struct vm_vcpu_info *vci = (struct vm_vcpu_info *)vcis;
    KEVENT *event = (KEVENT * volatile)vcis->vci_wait_event;
    int ret;

    if (event == &dummy_event || !is_vci_runnable(vci))
	return 1;
    ret = KeReadStateEvent(event);
    if (ret) {
        KeClearEvent(event);
        vcis->vci_wait_event = &dummy_event;
    }
    return ret;
}

void
uxen_op_init_free_allocs(void)
{

    if (uxen_info) {
        uxen_pages_clear();
	pagemap_free();
        if (uxen_info->ui_hvm_io_bitmap) {
            if (ui_hvm_io_bitmap_contiguous)
                kernel_free_contiguous(uxen_info->ui_hvm_io_bitmap,
                                       UI_HVM_IO_BITMAP_SIZE);
            else
                kernel_free(uxen_info->ui_hvm_io_bitmap, UI_HVM_IO_BITMAP_SIZE);
            uxen_info->ui_hvm_io_bitmap = NULL;
        }
        if (uxen_info->ui_domain_array) {
            kernel_free(uxen_info->ui_domain_array,
                        uxen_info->ui_domain_array_pages << PAGE_SHIFT);
            uxen_info->ui_domain_array = NULL;
        }
    }

    if (frametable_populated) {
        dprintk("uxen mem: free frametable_populated\n");
        depopulate_frametable(frametable_size >> PAGE_SHIFT);
        kernel_free(frametable_populated,
                    ((frametable_size >> PAGE_SHIFT) + 7) / 8);
        frametable_populated = NULL;
    }
    if (frametable) {
	dprintk("uxen mem: free frametable\n");
        kernel_free_va(frametable, frametable_size >> PAGE_SHIFT);
	frametable = NULL;
    }
    if (percpu_area) {
	dprintk("uxen mem: free percpu_area\n");
	kernel_free(percpu_area, percpu_area_size);
	percpu_area = NULL;
    }
    if (dom0_vmi) {
        dprintk("uxen mem: free dom0_vmi\n");
        kernel_free(dom0_vmi,
                    (size_t)ALIGN_PAGE_UP(
                        sizeof(struct vm_info) +
                        nr_host_cpus * sizeof(struct vm_vcpu_info)));
        dom0_vmi = NULL;
    }
    if (uxen_zero_mfn != ~0) {
	dprintk("uxen mem: free zero page\n");
	kernel_free_mfn(uxen_zero_mfn);
	uxen_zero_mfn = ~0;
    }
    if (mapcache_va) {
        int i;
        for (i = 0; i < nr_host_cpus; i++) {
            if (mapcache_va[i])
                kernel_free_va((void *)mapcache_va[i], mapcache_size);
        }
        kernel_free(mapcache_va, nr_host_cpus * sizeof(void *));
        mapcache_va = 0;
    }
#ifdef DEBUG_PAGE_ALLOC
    if (pinfotable) {
        kernel_free(pinfotable, pinfotable_size);
        pinfotable = NULL;
    }
#endif  /* DEBUG_PAGE_ALLOC */
}


#ifndef __i386__
/* If bit set in mask, bit must be set in reply */
static int
test_ax_compatibility_masks(uint32_t *masks, unsigned n_masks)
{
    uint64_t  rax, rbx, rcx, rdx;
    unsigned i;

    for (i = 0; i < n_masks; ++i) {
        rax = AX_CPUID_AX_FEATURES;
        rcx = i;
        rdx = 0;

        hv_tests_cpuid(&rax, &rbx, &rcx, &rdx);

        if ((masks[i] & rdx) != masks[i])  {
            fail_msg("ax_compatibility: AX feature missing ECX: 0x%x "
                     "needed %08x got %08x", i, masks[i], (uint32_t)rdx);
            return 1;
        }
    }

    return 0;
}

/* If bit set in reply, bit must be set in mask */
static int
test_ln_compatibility_masks(uint32_t *masks, unsigned n_masks)
{
    uint64_t  rax, rbx, rcx, rdx;
    unsigned i;

    for (i = 0; i < n_masks; ++i) {
        rax = AX_CPUID_LN_FEATURES;
        rcx = i;
        rdx = 0;

        hv_tests_cpuid(&rax, &rbx, &rcx, &rdx);

        if ((rdx & masks[i]) != rdx)  {
            fail_msg("ax_compatibility: uXen feature missing ECX: 0x%x "
                     "needed %08x got %08x", i, masks[i], (uint32_t)rdx);
            return 1;
        }
    }

    if (rcx > n_masks) {
        fail_msg("ax_compatibility: uXen feature missing ECX: 0x%x, "
                 "n_masks 0x%x", (uint32_t)rcx, n_masks);
        return 1;
    }

    return 0;
}

static int
test_ax_compatibility_l1(void)
{
    /* There is currently no defined PV L1 interface for AX, so bail */
    fail_msg("This uxen binary does not support running at L1 under AX");
    return -1;
}

static int
test_ax_compatibility_l2(void)
{
    uint32_t ax_masks[]={ AX_FEATURES_AX_L2_VMX | AX_FEATURES_AX_L2_VMCLEAR |
                          AX_FEATURES_AX_L2_FLUSHTLB };

    uint32_t ln_masks[]={ AX_FEATURES_LN_NO_RESTORE_DT_LIMITS |
                          AX_FEATURES_LN_ACCEPT_LAZY_EPT_FAULTS };

    int err = 0;

    if (hv_tests_cpu_is_intel()) {
        ln_masks[0] |=  AX_FEATURES_LN_VMCS_X_V1;
    } else if (hv_tests_cpu_is_amd()) {
        ln_masks[0] |=  AX_FEATURES_LN_VMCB_X_V1;
    }

    err |= test_ax_compatibility_masks(ax_masks,
                                       sizeof(ax_masks) / sizeof(ax_masks[0]));
    err |= test_ln_compatibility_masks(ln_masks,
                                       sizeof(ln_masks) / sizeof(ln_masks[0]));

    if (!err)
        printk("AX and uXen are compatible\n");

    return err;
}

int
test_ax_pv_vmcs(void)
{
    uint32_t ax_masks[] = { AX_FEATURES_AX_PV_VMCS };

    int err = 0;

    err |= test_ax_compatibility_masks(ax_masks,
                                       sizeof(ax_masks) / sizeof(ax_masks[0]));

    if (!err)
        printk("AX has PV VMCS\n");

    return err;
}

static int
test_ax_compatibility(void)
{
    if (!hv_tests_ax_running())
        return 0;

    printk("AX is running\n");

    if (!hv_tests_hyperv_running())  {
        printk("Hyper-v is not running\n");
        return test_ax_compatibility_l1();
    } else {
        printk("Hyper-v is running\n");
        return test_ax_compatibility_l2();
    }
}
#endif

static NTSTATUS
init_cpu_dpc(KDPC *dpc, unsigned int host_cpu,
	     void (*cb)(KDPC *, void *, void *, void *), void *arg)
{
    KeInitializeDpc(dpc, cb, arg);
    KeSetTargetProcessorDpc(dpc, (CCHAR)host_cpu);
    KeSetImportanceDpc(dpc, HighImportance);

    return STATUS_SUCCESS;
}

int
uxen_op_init(struct fd_assoc *fda, struct uxen_init_desc *_uid,
             uint32_t uid_len, DEVICE_OBJECT *devobj)
{
    struct uxen_init_desc uid;
    uint32_t max_pfn;
    unsigned int host_cpu;
    unsigned int cpu;
    HANDLE handle;
    LARGE_INTEGER system_time, pc_now, pc_freq, tsc_now;
    KIRQL irql;
    size_t sizeof_percpu;
    ULONG major_version, minor_version;
    BOOLEAN is_checked;
    NTSTATUS status;
    uint64_t use_hidden = 0;
    int ret = 0;
    uint64_t pae_enabled;
    struct vm_vcpu_info_shared *vcis[UXEN_MAXIMUM_PROCESSORS];
    affinity_t aff;

    aff = uxen_lock();
    while (InterlockedCompareExchange(&uxen_devext->de_initialised,
                                      1, 0) != 0) {
        uxen_unlock(aff);
        status = KeWaitForSingleObject(&uxen_devext->de_init_done, UserRequest,
                                       UserMode, TRUE, NULL);
        if (status != STATUS_SUCCESS)
            return -EINTR;
        if (uxen_devext->de_initialised)
            return 0;
        aff = uxen_lock();
    }
    uxen_devext->de_executing = 2;
    KeResetEvent(&uxen_devext->de_init_done);
    uxen_unlock(aff);

    if (!fda->admin_access) {
        fail_msg("access denied");
        ret = -EPERM;
        goto out;
    }

    /* early bail out if PAE is disabled to avoid crash in pagemap_init */

    /* this fails with an internal compiler error (C1001) on 32-bit, FRE build
       only, for reasons that I can't figure out.  Looks like a compiler bug.
    if (!(__readcr4() & (1 << 5))) */

    pae_enabled = __readcr4() & (1 << 5);
    if (! pae_enabled) {
        fail_msg("PAE is disabled");
        ret = -EPERM;
        goto out;
    }

#ifndef __i386__
    if (test_ax_compatibility()) {
        ret = -EPERM;
        goto out;
    }
#endif

    memset(&uid, 0, sizeof(uid));
    if (uid_len > sizeof(uid))
        uid_len = sizeof(uid);
    if (_uid)
        memcpy(&uid, _uid, uid_len);
    uid_len = sizeof(uid);

    if (uid.UXEN_INIT_opt_crash_on_MASK & UXEN_INIT_opt_crash_on)
        crash_on = uid.opt_crash_on;
    if (crash_on)
        printk("set crash_on: %x\n", crash_on);

    if (uid.UXEN_INIT_opt_v4v_thread_priority_MASK & UXEN_INIT_opt_v4v_thread_priority) {
        printk("setting v4v threads priority to %d\n", (int) uid.opt_v4v_thread_priority);
        uxen_sys_set_v4v_thread_priority(uid.opt_v4v_thread_priority);
    }

    is_checked = PsGetVersion(&major_version, &minor_version, &build_number,
                              NULL);

    printk("===============================================================\n");
    printk_with_timestamp("starting uXen driver version: %d.%d %s\n",
                          UXEN_DRIVER_VERSION_MAJOR, UXEN_DRIVER_VERSION_MINOR,
                          UXEN_DRIVER_VERSION_TAG);
    printk("uXen changeset: %s\n", UXEN_DRIVER_VERSION_CHANGESET);
    printk("OS version: %d.%d build %d%s\n", major_version, minor_version,
           build_number, is_checked ? " checked" : "");
    printk("===============================================================\n");

#if defined(__UXEN_EMBEDDED__)
    ret = uxen_load_symbols();
    if (ret) {
        fail_msg("uxen_load_symbols failed: %d", ret);
	goto out;
    }
#endif

    if (uxen_info->ui_sizeof_struct_page_info == 0) {
        fail_msg("invalid sizeof(struct page_info)");
        ret = -EINVAL;
	goto out;
    }

#if !defined(__UXEN_EMBEDDED__)
    dprintk("vvvvvvvvvvvvvvvvv\n"
	    "lduxen %p; gdb uxen\n"
	    "^^^^^^^^^^^^^^^^^\n", uxen_hv);
#endif

#ifdef __i386__
    use_hidden = 1;
    if (uid.UXEN_INIT_use_hidden_mem_MASK & UXEN_INIT_use_hidden_mem) {
        use_hidden = uid.use_hidden_mem;
        if (use_hidden > 3)
            max_hidden_mem = use_hidden << 30;
    }
    printk("%susing hidden memory (%016I64x)\n", 
           use_hidden ? "" : "not ", max_hidden_mem);
    if (use_hidden) {
        status = IoRegisterShutdownNotification(devobj);
        if (!NT_SUCCESS(status)) {
            fail_msg("IoRegisterShutdownNotification() failed: %08x", status);
            use_hidden = 0;
        } else
            use_hidden = (0 == uxen_hibernation_init()) ? 1 : 0;
        if (!use_hidden)
            fail_msg("failed to patch power services - disabling hidden memory");
    } 
#endif /* __i386__ */

    max_pfn = get_max_pfn(use_hidden);

    if (uxen_cpu_set_active_mask(&uxen_info->ui_cpu_active_mask)) {
        ret = -EINVAL;
        goto out;
    }

    ret = mem_late_init();
    if (ret)
        goto out;

    uxen_info->host_os_is_xmm_clean = 0;

    uxen_info->ui_printf = uxen_printk;

    /* not called through to host (both map and unmap on windows) */
    /* uxen_info->ui_map_page = uxen_mem_map_page; */
    /* uxen_info->ui_unmap_page_va = uxen_mem_unmap_page_va; */
    uxen_info->ui_map_page_global = uxen_mem_map_page;
    uxen_info->ui_unmap_page_global_va = uxen_mem_unmap_page_va;
    uxen_info->ui_map_page_range = uxen_mem_map_page_range;
    uxen_info->ui_unmap_page_range = uxen_mem_unmap_page_range;
    uxen_info->ui_mapped_global_va_pfn = uxen_mem_mapped_va_pfn;

    uxen_info->ui_max_page = max_pfn;
    /* space for max_pfn virtual frametable entries */
    vframes_start = max_pfn;
    vframes_end = vframes_start + max_pfn;
    uxen_info->ui_max_vframe = vframes_end;

    uxen_info->ui_host_needs_preempt = uxen_op_host_needs_preempt;

    uxen_info->ui_on_selected_cpus = uxen_cpu_on_selected;
    uxen_info->ui_kick_cpu = uxen_op_cpu_ipi;
    uxen_info->ui_kick_vcpu = uxen_op_vcpu_ipi;
    uxen_info->ui_kick_vcpu_cancel = uxen_op_vcpu_ipi_cancel;
    uxen_info->ui_wake_vm = uxen_op_wake_vm;

    uxen_info->ui_signal_idle_thread = uxen_op_signal_idle_thread;
    uxen_info->ui_set_timer_vcpu = uxen_op_set_vcpu_timer;

    uxen_info->ui_notify_exception = uxen_op_notify_exception;
    uxen_info->ui_notify_vram = uxen_op_notify_vram;
    uxen_info->ui_signal_event = uxen_op_signal_event;
    uxen_info->ui_check_ioreq = uxen_op_check_ioreq;

    uxen_info->ui_pagemap_needs_check = 0;

    uxen_info->ui_map_mfn = map_mfn;

    uxen_info->ui_user_access_ok = uxen_mem_user_access_ok;

    uxen_info->ui_signal_v4v = uxen_sys_signal_v4v;

    printk("uxen mem:     maxpage %x\n", uxen_info->ui_max_page);

#ifdef DEBUG_PAGE_ALLOC
    pinfotable_size = max_pfn * sizeof(struct pinfo);
    pinfotable_size = ((pinfotable_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    pinfotable = kernel_malloc(pinfotable_size);
    if (pinfotable == NULL) {
        fail_msg("kernel_malloc(pinfotable) failed");
        ret = -ENOMEM;
        goto out;
    }
#endif  /* DEBUG_PAGE_ALLOC */

    ret = kernel_alloc_mfn(&uxen_zero_mfn);
    if (ret) {
        uxen_zero_mfn = ~0;
        fail_msg("kernel_malloc_mfns(zero_mfn) failed");
        ret = -ENOMEM;
        goto out;
    }
    dprintk("uxen mem:   zero page %x\n", uxen_zero_mfn);

    dprintk("uxen mem:   page_info %x\n",
            uxen_info->ui_sizeof_struct_page_info);
    /* frametable is sized based on vframes */
    frametable_size = vframes_end * uxen_info->ui_sizeof_struct_page_info;
    frametable_size = ((frametable_size + PAGE_SIZE-1) & ~(PAGE_SIZE-1));
    frametable = kernel_alloc_va(frametable_size >> PAGE_SHIFT);
    if (frametable == NULL || ((uintptr_t)frametable & (PAGE_SIZE - 1))) {
        fail_msg("kernel_malloc_va(frametable) failed");
        ret = -ENOMEM;
	goto out;
    }
    uxen_info->ui_frametable = frametable;
    dprintk("uxen mem:  frametable %p - %p (0x%x/%dMB)\n", frametable,
            frametable + frametable_size, frametable_size,
	    frametable_size >> 20);
    frametable_populated = kernel_malloc(
        ((frametable_size >> PAGE_SHIFT) + 7) / 8);
    if (!frametable_populated) {
        fail_msg("kernel_malloc(frametable_populated) failed");
        ret = -ENOMEM;
        goto out;
    }
    dprintk("uxen mem: f-populated %p - %p (%dKB)\n", frametable_populated,
            frametable_populated + ((frametable_size >> PAGE_SHIFT) + 7) / 8,
            (((frametable_size >> PAGE_SHIFT) + 7) / 8) >> 10);
    KeInitializeGuardedMutex(&populate_frametable_mutex);

    populate_frametable_physical_memory();

    KeInitializeGuardedMutex(&populate_vframes_mutex);

    sizeof_percpu = (uxen_addr_per_cpu_data_end - uxen_addr_per_cpu_start +
                     PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    /* skip cpu 0 since uxen stores it in .data */
    percpu_area_size = (nr_host_cpus - 1) * sizeof_percpu;
    if (percpu_area_size) {
        percpu_area = kernel_malloc(percpu_area_size);
        if (percpu_area == NULL || ((uintptr_t)percpu_area & (PAGE_SIZE - 1))) {
            fail_msg("kernel_malloc(percpu_area) failed");
            ret = -ENOMEM;
            goto out;
        }
        cpu = 0;
        for (host_cpu = 1; host_cpu < max_host_cpu; host_cpu++) {
            if ((uxen_info->ui_cpu_active_mask & affinity_mask(host_cpu)) == 0)
                continue;
            uxen_info->ui_percpu_area[host_cpu] =
                &percpu_area[cpu * sizeof_percpu];
            cpu++;
        }
        dprintk("uxen mem: percpu_area %p - %p\n", percpu_area,
                &percpu_area[percpu_area_size]);
    }

    uxen_info->ui_hvm_io_bitmap =
        kernel_alloc_contiguous(UI_HVM_IO_BITMAP_SIZE);
    if (!uxen_info->ui_hvm_io_bitmap) {
        printk("kernel_alloc_contiguous(hvm_io_bitmap) failed");
        uxen_info->ui_hvm_io_bitmap = kernel_malloc(UI_HVM_IO_BITMAP_SIZE);
        if (!uxen_info->ui_hvm_io_bitmap) {
            fail_msg("kernel_malloc(hvm_io_bitmap) failed");
            ret = -ENOMEM;
            goto out;
        }
        ui_hvm_io_bitmap_contiguous = FALSE;
    }

    uxen_info->ui_domain_array =
        kernel_malloc(uxen_info->ui_domain_array_pages << PAGE_SHIFT);
    if (!uxen_info->ui_domain_array) {
        fail_msg("kernel_malloc(ui_domain_array) failed");
        ret = -ENOMEM;
        goto out;
    }

    dom0_vmi = kernel_malloc(
        (size_t)ALIGN_PAGE_UP(sizeof(struct vm_info) +
                              nr_host_cpus * sizeof(struct vm_vcpu_info)));
    if (!dom0_vmi) {
        fail_msg("kernel_malloc(dom0_vmi) failed");
        ret = -ENOMEM;
        goto out;
    }
    cpu = 0;
    for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++) {
        if ((uxen_info->ui_cpu_active_mask & affinity_mask(host_cpu)) == 0)
            continue;
        vcis[host_cpu] = &dom0_vmi->vmi_vcpus[cpu].vci_shared;
        cpu++;
    }

#if defined(__x86_64__) && defined(__UXEN_EMBEDDED__)
    dprintk("uxen xdata start: %p-%p\n", &uxen_xdata_start, &uxen_xdata_end);
    dprintk("uxen pdata start: %p-%p\n", &uxen_pdata_start, &uxen_pdata_end);
    uxen_info->ui_xdata_start = &uxen_xdata_start;
    uxen_info->ui_xdata_end = &uxen_xdata_end;
    uxen_info->ui_pdata_start = &uxen_pdata_start;
    uxen_info->ui_pdata_end = &uxen_pdata_end;
#endif

    uxen_info->ui_map_page_range_max_nr = map_page_range_max_nr;

    mapcache_size = uxen_info->ui_mapcache_size;
    mapcache_va = kernel_malloc(nr_host_cpus * sizeof(void *));
    if (!mapcache_va) {
        fail_msg("kernel_malloc(mapcache_va) failed");
        ret = -ENOMEM;
        goto out;
    }
    cpu = 0;
    for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++) {
        if ((uxen_info->ui_cpu_active_mask & affinity_mask(host_cpu)) == 0)
            continue;
        mapcache_va[cpu] = (uintptr_t)kernel_alloc_va(mapcache_size);
        if (!mapcache_va[cpu] || (mapcache_va[cpu] & (PAGE_SIZE - 1))) {
            fail_msg("kernel_alloc_va(mapcache_va) failed");
            ret = -ENOMEM;
            goto out;
        }
        uxen_info->ui_mapcache_va[host_cpu] = mapcache_va[cpu];
        cpu++;
    }

    KeInitializeSpinLock(&idle_free_lock);

    KeInitializeEvent(&dummy_event, NotificationEvent, TRUE);

    ret = pagemap_init(max_pfn);
    if (ret != 0) {
        fail_msg("pagemap_init() failed");
        goto out;
    }

    KeQuerySystemTime(&uxen_start_time);
    uxen_host_counter_start =
        KeQueryPerformanceCounter(&uxen_host_counter_freq);
    update_ui_host_counter();
    uxen_info->ui_host_counter_frequency =
        (uint32_t)uxen_host_counter_freq.QuadPart;
    uxen_info->ui_get_unixtime = uxen_op_get_unixtime;
    uxen_info->ui_get_host_counter = uxen_op_get_host_counter;
    uxen_info->ui_host_timer_frequency = UXEN_HOST_TIMER_FREQUENCY;

    KeResetEvent(&uxen_devext->de_shutdown_done);
    uxen_info->ui_running = 1;

#ifndef __i386__
    uid.pvi_vmread = uxen_devext->de_pvi_vmread;
    uid.pvi_vmwrite = uxen_devext->de_pvi_vmwrite;
    uid.UXEN_INIT_pvi_vmread_MASK |= UXEN_INIT_pvi_vmread;
    uid.UXEN_INIT_pvi_vmwrite_MASK |= UXEN_INIT_pvi_vmwrite;
#endif /* __i386__ */

    for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++) {
	if ((uxen_info->ui_cpu_active_mask & affinity_mask(host_cpu)) == 0)
	    continue;
        uxen_idle_thread[host_cpu] = NULL;
        KeInitializeEvent(&uxen_idle_thread_event[host_cpu],
                          NotificationEvent, FALSE);
        status = PsCreateSystemThread(&handle, 0, NULL, NULL, NULL,
                                      uxen_idle_thread_fn,
                                      (PVOID)(ULONG_PTR)host_cpu);
        if (!NT_SUCCESS(status)) {
            fail_msg("create cpu%u idle thread failed: 0x%08X",
                     host_cpu, status);
            ret = -ENOMEM;
            goto out;
        }

        status = ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, NULL,
                                           KernelMode,
                                           &uxen_idle_thread[host_cpu], NULL);
        ZwClose(handle);
        if (!NT_SUCCESS(status)) {
            fail_msg("get reference to cpu%u idle thread failed: 0x%08X",
                     host_cpu, status);
            ret = -ENOMEM;
            goto out;
        }
        dprintk("setup cpu%u idle thread done\n", host_cpu);
    }

    for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++) {
	PKDPC dpc;

	if ((uxen_info->ui_cpu_active_mask & affinity_mask(host_cpu)) == 0)
	    continue;
	status = init_cpu_dpc(&uxen_cpu_ipi_dpc[host_cpu], host_cpu,
			      uxen_cpu_ipi_cb, NULL);
	if (!NT_SUCCESS(status)) {
            fail_msg("init_cpu_dpc(,0x%x,) failed: 0x%08X", host_cpu,
                     status);
	    break;
	}
	KeInitializeSpinLock(&uxen_cpu_ipi_spinlock[host_cpu]);
	uxen_cpu_ipi_raised_vectors[host_cpu] = 0;

	dprintk("setup cpu 0x%x: cpu dpc done\n", host_cpu);
    }
    if (!NT_SUCCESS(status)) {
        ret = -EINVAL;
	goto out;
    }

    KeSetEvent(&uxen_devext->de_resume_event, 0, FALSE);

    aff = uxen_cpu_pin_first();
    uxen_call(ret = (int), -EINVAL, STARTXEN_RESERVE, uxen_do_start_xen, &uid,
              uid_len, &dom0_vmi->vmi_shared, vcis);
    uxen_cpu_unpin(aff);
    if (ret) {
        fail_msg("start xen failed: %d", ret);
        goto out;
    }

#ifdef __i386__
    if (use_hidden)
       add_hidden_memory();
#endif

    /* run idle thread to make it pick up the current timeout */
    uxen_signal_idle_thread(0);

    if (!InterlockedDecrement(&uxen_devext->de_executing))
        KeSetEvent(&uxen_devext->de_suspend_event, 0, FALSE);

  out:
    if (ret) {
        if (uxen_info)
            uxen_info->ui_running = 0;
	uxen_op_init_free_allocs();
        uxen_devext->de_executing = 0;
        uxen_devext->de_initialised = 0;
    }
    KeSetEvent(&uxen_devext->de_init_done, 0, FALSE);
    return ret;
}

int
uxen_op_shutdown(void)
{
    KIRQL irql;
    affinity_t aff;
    struct vm_info *vmi, *tvmi;
    unsigned int host_cpu;

    if (uxen_info == NULL)
        goto out;

    printk("%s: destroying VMs (core is %srunning)\n", __FUNCTION__,
           uxen_info->ui_running ? "" : "not ");

    aff = uxen_lock();
    RB_TREE_FOREACH_SAFE(vmi, &uxen_devext->de_vm_info_rbtree, tvmi) {
        dprintk("uxen shutdown: destroy vm%u\n", vmi->vmi_shared.vmi_domid);
        uxen_vmi_destroy_vm(vmi);
    }

    /* cleanup any templates which weren't freed before all clones
     * were destroyed */
    RB_TREE_FOREACH_SAFE(vmi, &uxen_devext->de_vm_info_rbtree, tvmi) {
        dprintk("uxen shutdown: cleanup vm%u\n", vmi->vmi_shared.vmi_domid);
        uxen_vmi_cleanup_vm(vmi);
    }

    if (RB_TREE_MIN(&uxen_devext->de_vm_info_rbtree)) {
        uxen_unlock(aff);
        goto out;
    }
    uxen_unlock(aff);

    if (InterlockedCompareExchange(&uxen_devext->de_initialised, 0, 1) == 0) {
        KeWaitForSingleObject(&uxen_devext->de_shutdown_done, Executive,
                              KernelMode, FALSE, NULL);
        goto out;
    }

    printk("%s: shutdown core\n", __FUNCTION__);

    uxen_flush_rcu();

    aff = uxen_lock();
    uxen_call(, , NO_RESERVE, uxen_do_shutdown_xen);
    uxen_unlock(aff);

    uxen_info->ui_running = 0;

    for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++)
        uxen_signal_idle_thread(host_cpu);
    for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++) {
        if (!uxen_idle_thread[host_cpu])
            continue;
        KeWaitForSingleObject(uxen_idle_thread[host_cpu], Executive,
                              KernelMode, FALSE, NULL);
        ObDereferenceObject(uxen_idle_thread[host_cpu]);
        uxen_idle_thread[host_cpu] = NULL;
    }

    KeFlushQueuedDpcs();

    KeSetEvent(&uxen_devext->de_shutdown_done, 0, FALSE);

    printk("%s: shutdown done\n", __FUNCTION__);

#ifdef DEBUG_STRAY_PAGES
    if (frametable_populated) {
        dprintk("checking frametable for stray pages\n");
        find_stray_pages_in_frametable(frametable_size >> PAGE_SHIFT);
    }
#endif  /* DEBUG_STRAY_PAGES */

  out:
    return 0;
}

void
uxen_complete_shutdown(void)
{
    affinity_t aff;

    while (uxen_devext->de_initialised) {
        uxen_op_shutdown();

        aff = uxen_lock();
        if (RB_TREE_MIN(&uxen_devext->de_vm_info_rbtree)) {
            KeResetEvent(&uxen_devext->de_vm_cleanup_event);
            if (RB_TREE_MIN(&uxen_devext->de_vm_info_rbtree)) {
                uxen_unlock(aff);
                KeWaitForSingleObject(&uxen_devext->de_vm_cleanup_event,
                                      Executive, KernelMode, FALSE, NULL);
                aff = uxen_lock();
            }
        }
        uxen_unlock(aff);
    }
}

int
uxen_op_wait_vm_exit(void)
{
    affinity_t aff;
    NTSTATUS status;

    aff = uxen_lock();
    while (RB_TREE_MIN(&uxen_devext->de_vm_info_rbtree)) {
        KeResetEvent(&uxen_devext->de_vm_cleanup_event);
        if (RB_TREE_MIN(&uxen_devext->de_vm_info_rbtree)) {
            uxen_unlock(aff);
            status = KeWaitForSingleObject(&uxen_devext->de_vm_cleanup_event,
                                           UserRequest, UserMode, TRUE, NULL);
            if (status != STATUS_SUCCESS) {
                if (status != STATUS_USER_APC)
                    fail_msg("KeWaitForSingleObject failed: 0x%08X", status);
                return EINTR;
            }
            aff = uxen_lock();
        }
    }
    uxen_unlock(aff);

    return 0;
}

int
uxen_op_version(struct uxen_version_desc *uvd)
{

    uvd->uvd_driver_version_major = UXEN_DRIVER_VERSION_MAJOR;
    uvd->uvd_driver_version_minor = UXEN_DRIVER_VERSION_MINOR;
    memset(uvd->uvd_driver_version_tag, 0, sizeof(uvd->uvd_driver_version_tag));
    strncpy_s(uvd->uvd_driver_version_tag, sizeof(uvd->uvd_driver_version_tag),
	      UXEN_DRIVER_VERSION_TAG, _TRUNCATE);

    return 0;
}

int
uxen_op_keyhandler(char *keys, unsigned int num)
{
    affinity_t aff;
    unsigned int i;
    int ret = 0;

    aff = uxen_exec_dom0_start();

    for (i = 0; i < num && keys[i]; i++) {
        unsigned char key = keys[i];
        switch (key) {
        case 'r':
            uxen_flush_rcu();
            ret = 0;
            break;
        default:
            uxen_call(ret = (int), -EINVAL, HYPERCALL_RESERVE,
                      uxen_do_handle_keypress, key);
            ret = -ret;
            break;
        }
        if (ret)
            break;
    }

    /* run idle thread in case a keyhandler changed a timer */
    uxen_signal_idle_thread(0);

    uxen_exec_dom0_end(aff);

    return ret;
}

int
uxen_op_create_vm(struct uxen_createvm_desc *ucd, struct fd_assoc *fda)
{
    struct vm_info *vmi = NULL;
    struct vm_vcpu_info *vci;
    struct vm_vcpu_info_shared *vcis[UXEN_MAXIMUM_VCPUS];
    KIRQL irql;
    affinity_t aff;
    unsigned int i;
    int ret = 0;

    if (fda->vmi) {
        fail_msg("domain %d: %" PRIuuid " vmi already exists",
                 fda->vmi->vmi_shared.vmi_domid, PRIuuid_arg(ucd->ucd_vmuuid));
        return -EEXIST;
    }

    aff = uxen_exec_dom0_start();
    uxen_call(vmi = (struct vm_info *), -ENOENT, NO_RESERVE,
              uxen_do_lookup_vm, ucd->ucd_vmuuid);
    uxen_exec_dom0_end(aff);

    /* Found the vm or lookup failed */
    if (vmi && (intptr_t)vmi != -ENOENT) {
        if (is_neg_errno((intptr_t)vmi)) {
            fail_msg("%" PRIuuid " lookup failed: %d",
                     PRIuuid_arg(ucd->ucd_vmuuid), -(int)(intptr_t)vmi);
            return (intptr_t)vmi;
        }
        fail_msg("domain %d: %" PRIuuid " already exists",
                 vmi->vmi_shared.vmi_domid, PRIuuid_arg(ucd->ucd_vmuuid));
        return -EEXIST;
    }

    if (ucd->ucd_max_vcpus > UXEN_MAXIMUM_VCPUS) {
        fail_msg("max_vcpu value too large: %d", ucd->ucd_max_vcpus);
        return -EINVAL;
    }

    vmi = kernel_malloc((size_t)ALIGN_PAGE_UP(
                            sizeof(struct vm_info) +
                            ucd->ucd_max_vcpus * sizeof(struct vm_vcpu_info)));
    if (!vmi) {
        ret = -ENOMEM;
        goto out;
    }

    vmi->vmi_nrvcpus = ucd->ucd_max_vcpus;

    for (i = 0; i < vmi->vmi_nrvcpus; i++)
        vcis[i] = &vmi->vmi_vcpus[i].vci_shared;

    if (uxen_info->ui_vmi_msrpm_size) {
        vmi->vmi_shared.vmi_msrpm = (uint64_t)kernel_alloc_contiguous(
            ucd->ucd_max_vcpus * uxen_info->ui_vmi_msrpm_size);
        if (!vmi->vmi_shared.vmi_msrpm) {
            fail_msg("kernel_alloc_contiguous(vmi_msrpm, %d) failed",
                     ucd->ucd_max_vcpus * uxen_info->ui_vmi_msrpm_size);
            ret = -ENOMEM;
            goto out;
        }
        vmi->vmi_shared.vmi_msrpm_size =
            ucd->ucd_max_vcpus * uxen_info->ui_vmi_msrpm_size;
    }

    if (uxen_info->ui_xsave_cntxt_size) {
        vmi->vmi_shared.vmi_xsave = (uint64_t)kernel_malloc(
            (size_t)ALIGN_PAGE_UP(ucd->ucd_max_vcpus *
                                  uxen_info->ui_xsave_cntxt_size));
        if (!vmi->vmi_shared.vmi_xsave) {
            fail_msg("kernel_malloc(vmi_xsave, %d) failed",
                     ucd->ucd_max_vcpus * uxen_info->ui_xsave_cntxt_size);
            ret = -ENOMEM;
            goto out;
        }
        vmi->vmi_shared.vmi_xsave_size =
            ucd->ucd_max_vcpus * uxen_info->ui_xsave_cntxt_size;
    }

    vci = &vmi->vmi_vcpus[0];

    vci->vci_host_cpu = KeGetCurrentProcessorNumber(); /* VVV */

    aff = uxen_cpu_pin_vcpu(vci, vci->vci_host_cpu);
    uxen_call(ret = (int), -EFAULT, SETUPVM_RESERVE, uxen_do_setup_vm,
              ucd, &vmi->vmi_shared, vcis);
    uxen_cpu_unpin(aff);
    if (ret) {
        fail_msg("domain %d: %" PRIuuid " setup vm failed: %d",
            vmi->vmi_shared.vmi_domid, PRIuuid_arg(ucd->ucd_vmuuid), ret);
	goto out;
    }

    aff = uxen_lock();
    ret = (vmi == rb_tree_insert_node(&uxen_devext->de_vm_info_rbtree, vmi));
    uxen_unlock(aff);
    if (!ret) {
        fail_msg("domain ID already present in de_vm_info_rbtree");
        ret = -EINVAL;
        goto out;
    }

    InterlockedIncrement(&vmi->vmi_alive);

    /* This reference will be dropped on vm destroy */
    InterlockedIncrement(&vmi->vmi_active_references);

    for (i = 0; i < vmi->vmi_nrvcpus; i++) {
        vci = &vmi->vmi_vcpus[i];
        KeInitializeTimer(&vci->vci_timer);
        KeInitializeDpc(&vci->vci_timer_dpc, uxen_vcpu_timer_cb, vci);
        KeSetImportanceDpc(&vci->vci_timer_dpc, HighImportance);
        vci->vci_timer_cpu = -1;
        KeInitializeDpc(&vci->vci_ipi_dpc, uxen_vcpu_ipi_cb, vci);
        KeSetImportanceDpc(&vci->vci_ipi_dpc, HighImportance);
        vci->vci_ipi_cpu = -1;
        vci->vci_ipi_queued = 0;
        vci->vci_executing = 0;
        vci->vci_thread = 0;
        spinlock_initialize(vci->vci_ipi_lck);
        vci->vci_shared.vci_wait_event = &dummy_event;

        KeInitializeEvent(&vci->vci_runnable, NotificationEvent, FALSE);
        vci->vci_shared.vci_runnable = 1;
    }

    KeInitializeEvent(&vmi->vmi_notexecuting, NotificationEvent, FALSE);
    KeInitializeEvent(&vmi->vmi_spinloop_wake_event, NotificationEvent, FALSE);

    ret = kernel_malloc_mfns(1, &vmi->vmi_undefined_mfn, 0);
    if (ret != 1) {
        fail_msg("kernel_malloc_mfns(vmi_undefined page) failed: %d", ret);
        vmi->vmi_undefined_mfn = ~0;
        ret = -ENOMEM;
        goto out;
    }

    vmi->vmi_shared.vmi_runnable = 1;

    fda->vmi_owner = TRUE;
    if (!(ucd->ucd_create_flags & XEN_DOMCTL_CDF_template))
        fda->vmi_destroy_on_close = TRUE;

    ret = 0;
  out:
    if (vmi && ret) {
        if (vmi->vmi_alive) {
            aff = uxen_lock();
            uxen_vmi_destroy_vm(vmi);
            uxen_unlock(aff);
        } else {
            aff = uxen_exec_dom0_start();
            uxen_call(, , NO_RESERVE, uxen_do_destroy_vm, ucd->ucd_vmuuid);
            uxen_exec_dom0_end(aff);
            if (vmi->vmi_shared.vmi_msrpm) {
                kernel_free_contiguous((void *)vmi->vmi_shared.vmi_msrpm,
                                       vmi->vmi_shared.vmi_msrpm_size);
                vmi->vmi_shared.vmi_msrpm = 0;
                vmi->vmi_shared.vmi_msrpm_size = 0;
            }
            if (vmi->vmi_shared.vmi_xsave) {
                kernel_free((void *)vmi->vmi_shared.vmi_xsave,
                            vmi->vmi_shared.vmi_xsave_size);
                vmi->vmi_shared.vmi_xsave = 0;
                vmi->vmi_shared.vmi_xsave_size = 0;
            }
            kernel_free(vmi, (size_t)ALIGN_PAGE_UP(
                            sizeof(struct vm_info) +
                            vmi->vmi_nrvcpus * sizeof(struct vm_vcpu_info)));
        }
        vmi = NULL;
    }

    if (vmi) {
        ucd->ucd_domid = vmi->vmi_shared.vmi_domid;

        /* This reference will be dropped on handle close */
        InterlockedIncrement(&vmi->vmi_active_references);
        fda->vmi = vmi;
    }

    return ret;
}

int
uxen_op_target_vm(struct uxen_targetvm_desc *utd, struct fd_assoc *fda)
{
    struct vm_info *vmi = NULL;
    affinity_t aff;
    int ret = 0;

    if (fda->vmi)
        return -EEXIST;

    aff = uxen_exec_dom0_start();
    uxen_call(vmi = (struct vm_info *), -ENOENT, NO_RESERVE,
              uxen_do_lookup_vm, utd->utd_vmuuid);
    uxen_exec_dom0_end(aff);

    /* Not found */
    if (!vmi)
        return -ENOENT;
    /* or lookup failed */
    if (is_neg_errno((intptr_t)vmi))
        return (intptr_t)vmi;

    utd->utd_domid = vmi->vmi_shared.vmi_domid;

    /* This reference will be dropped on handle close */
    InterlockedIncrement(&vmi->vmi_active_references);
    fda->vmi = vmi;

    return ret;
}

void
uxen_vmi_free(struct vm_info *vmi)
{
    uint32_t refs;

    printk("%s: vm%u refs %d\n", __FUNCTION__,
           vmi->vmi_shared.vmi_domid, vmi->vmi_active_references);
    do {
        refs = vmi->vmi_active_references;
    } while (InterlockedCompareExchange(&vmi->vmi_active_references,
                                        refs - 1, refs) != refs);
    if (refs != 1)
        return;

    rb_tree_remove_node(&uxen_devext->de_vm_info_rbtree, vmi);

    KeFlushQueuedDpcs();

    while (vmi->vmi_host_event_channels != NULL) {
	struct host_event_channel *hec = vmi->vmi_host_event_channels;
	vmi->vmi_host_event_channels = hec->next;
	ObDereferenceObject(hec->request);
        if (hec->completed)
            ObDereferenceObject(hec->completed);
	kernel_free(hec, sizeof(*hec));
    }
	
    if (vmi->vmi_ioemu_vram_event) {
	ObDereferenceObject(vmi->vmi_ioemu_vram_event);
	vmi->vmi_ioemu_vram_event = NULL;
    }

    if (vmi->vmi_ioemu_exception_event) {
	ObDereferenceObject(vmi->vmi_ioemu_exception_event);
	vmi->vmi_ioemu_exception_event = NULL;
    }

    if (vmi->vmi_undefined_mfn != ~0) {
        kernel_free_mfn(vmi->vmi_undefined_mfn);
        vmi->vmi_undefined_mfn = ~0;
    }

    if (vmi->vmi_shared.vmi_msrpm) {
        kernel_free_contiguous((void *)vmi->vmi_shared.vmi_msrpm,
                               vmi->vmi_shared.vmi_msrpm_size);
        vmi->vmi_shared.vmi_msrpm = 0;
        vmi->vmi_shared.vmi_msrpm_size = 0;
    }

    if (vmi->vmi_shared.vmi_xsave) {
        kernel_free((void *)vmi->vmi_shared.vmi_xsave,
                    vmi->vmi_shared.vmi_xsave_size);
        vmi->vmi_shared.vmi_xsave = 0;
        vmi->vmi_shared.vmi_xsave_size = 0;
    }

    logging_free(&vmi->vmi_logging_desc);

    printk("%s: vm%u vmi freed\n", __FUNCTION__, vmi->vmi_shared.vmi_domid);
    kernel_free(vmi, (size_t)ALIGN_PAGE_UP(
                    sizeof(struct vm_info) +
                    vmi->vmi_nrvcpus * sizeof(struct vm_vcpu_info)));

    KeSetEvent(&uxen_devext->de_vm_cleanup_event, 0, FALSE);
}

void
uxen_vmi_cleanup_vm(struct vm_info *vmi)
{
    int domid = vmi->vmi_shared.vmi_domid;
    unsigned int i;

    printk("%s: vm%u refs %d, running %d vcpus\n", __FUNCTION__, domid,
            vmi->vmi_active_references, vmi->vmi_running_vcpus);
    for (i = 0; i < vmi->vmi_nrvcpus; i++)
        dprintk("  vcpu vm%u.%u running %s\n", domid, i,
                vmi->vmi_vcpus[i].vci_shared.vci_runnable ? "yes" : "no");

    if (vmi->vmi_marked_for_destroy && uxen_vmi_destroy_vm(vmi)) {
        printk("%s: vm%u deferred by destroy\n", __FUNCTION__, domid);
        return;
    }

    printk("%s: vm%u cleanup complete\n", __FUNCTION__, domid);
}

static void
uxen_vmi_stop_running(struct vm_info *vmi)
{
    unsigned int i;

    printk("%s: vm%u\n", __FUNCTION__, vmi->vmi_shared.vmi_domid);
    dprintk("%s: vm%u has %d of %d vcpus running\n", __FUNCTION__,
            vmi->vmi_shared.vmi_domid, vmi->vmi_running_vcpus,
            vmi->vmi_nrvcpus);

    vmi->vmi_shared.vmi_runnable = 0;

    for (i = 0; i < vmi->vmi_nrvcpus; i++) {
        struct vm_vcpu_info *vci = &vmi->vmi_vcpus[i];
        KEVENT *event = (KEVENT * volatile)vci->vci_shared.vci_wait_event;

        dprintk("  vcpu vm%u.%u runnable %s\n", vmi->vmi_shared.vmi_domid, i,
                vci->vci_shared.vci_runnable ? "yes" : "no");

        if (InterlockedCompareExchange(&vci->vci_shared.vci_runnable,
                                       0, 1) == 0)
            continue;

        if (event != &dummy_event) {
            vci->vci_shared.vci_wait_event = &dummy_event;
            KeSetEvent(event, 0, FALSE);
        }

        vci->vci_shared.vci_host_halted = 0;
	KeSetEvent(&vci->vci_runnable, 0, FALSE);

	KeCancelTimer(&vci->vci_timer);

        KeInsertQueueDpc(&uxen_cpu_ipi_dpc[vci->vci_host_cpu],
                         (PVOID)(ULONG_PTR)vci->vci_host_cpu, NULL);
    }

    KeFlushQueuedDpcs();

    KeClearEvent(&vmi->vmi_notexecuting);
    MemoryBarrier();
    if (vmi->vmi_running_vcpus)
        KeWaitForSingleObject(&vmi->vmi_notexecuting, Executive, KernelMode,
                              FALSE, NULL);

    printk("%s: vm%u all %d vcpus stopped (%d running)\n", __FUNCTION__,
           vmi->vmi_shared.vmi_domid, vmi->vmi_nrvcpus,
           vmi->vmi_running_vcpus);
}

int
uxen_destroy_vm(struct vm_info *vmi)
{
    affinity_t aff;
    int ret;

    printk("%s: vm%u\n", __FUNCTION__, vmi->vmi_shared.vmi_domid);

    aff = uxen_exec_dom0_start();
    uxen_call(ret = (int), -EINVAL, NO_RESERVE,
              uxen_do_destroy_vm, vmi->vmi_shared.vmi_uuid);
    uxen_exec_dom0_end(aff);
    if (ret == -ENOENT)
        ret = 0;
    if (ret)
        printk("%s: vm%u not destroyed: %d\n", __FUNCTION__,
               vmi->vmi_shared.vmi_domid, ret);

    return ret;
}

static int
uxen_vmi_destroy_vm(struct vm_info *vmi)
{
    affinity_t aff;
    unsigned int i;
    int ret;

    printk("%s: vm%u alive %s, refs %d, running %d vcpus\n", __FUNCTION__,
            vmi->vmi_shared.vmi_domid, vmi->vmi_alive ? "yes" : "no",
            vmi->vmi_active_references, vmi->vmi_running_vcpus);

    if (InterlockedCompareExchange(&vmi->vmi_alive, 0, 1) == 0)
        return 0;

    vmi->vmi_marked_for_destroy = 1;

    uxen_vmi_stop_running(vmi);

    ret = uxen_destroy_vm(vmi);
    if (ret) {
        printk("%s: vm%u not destroyed: %d\n", __FUNCTION__,
               vmi->vmi_shared.vmi_domid, ret);
        InterlockedIncrement(&vmi->vmi_alive);
        goto out;
    }

    printk("%s: vm%u destroyed\n", __FUNCTION__, vmi->vmi_shared.vmi_domid);
    vmi->vmi_marked_for_destroy = 0;

    uxen_vmi_free(vmi);

  out:
    return ret;
}

int
uxen_op_destroy_vm(struct uxen_destroyvm_desc *udd, struct fd_assoc *fda)
{
    struct vm_info *vmi = NULL;
    affinity_t aff, aff_locked;
    int ret = 0;

    /* allow destroy if admin or if this handle created the vm/vmi */
    if (!fda->admin_access &&
        (!fda->vmi || !fda->vmi_owner ||
         memcmp(udd->udd_vmuuid, fda->vmi->vmi_shared.vmi_uuid,
                sizeof(udd->udd_vmuuid)))) {
        fail_msg("access denied");
        ret = -EPERM;
        goto out;
    }

    aff = uxen_lock();
    aff_locked = uxen_exec_dom0_start();
    uxen_call(vmi = (struct vm_info *), -ENOENT, NO_RESERVE,
              uxen_do_lookup_vm, udd->udd_vmuuid);
    uxen_exec_dom0_end(aff_locked);

    /* Found the vm or -errno means uuid not found or other error */
    if (is_neg_errno((intptr_t)vmi)) {
        ret = (intptr_t)vmi;
        uxen_unlock(aff);
        goto out;
    }

    if (vmi) {
        printk("%s: vm%u\n", __FUNCTION__, vmi->vmi_shared.vmi_domid);
        InterlockedIncrement(&vmi->vmi_active_references);
        ret = uxen_vmi_destroy_vm(vmi);
        if (!ret)
            uxen_vmi_cleanup_vm(vmi);
        uxen_vmi_free(vmi);
        uxen_unlock(aff);
    } else {
        printk("%s: no vmi\n", __FUNCTION__);
        uxen_unlock(aff);
        aff = uxen_exec_dom0_start();
        uxen_call(ret = (int), -EINVAL, NO_RESERVE,
                  uxen_do_destroy_vm, udd->udd_vmuuid);
        uxen_exec_dom0_end(aff);
    }

  out:
    return ret;
}

static void
wake_spinning_vcpus(struct vm_info *vmi)
{
    KeSetEvent(&vmi->vmi_spinloop_wake_event, 0, FALSE);
    KeClearEvent(&vmi->vmi_spinloop_wake_event);
}

static int
uxen_vcpu_thread_fn(struct vm_info *vmi, struct vm_vcpu_info *vci)
{
    affinity_t aff;
    int ret;

#define EVENT_WAIT(object, interruptible, timeout)                      \
    do {                                                                \
        NTSTATUS status;                                                \
        LARGE_INTEGER t;                                                \
        t.QuadPart = -timeout;                                          \
        status = KeWaitForSingleObject(                                 \
            object, Executive, interruptible ? UserMode : KernelMode,   \
            FALSE, timeout ? &t : NULL);                                \
        if (status != STATUS_SUCCESS && status != STATUS_TIMEOUT) {     \
            fail_msg("%d: vm%u.%u: wait interrupted: 0x%08X", __LINE__, \
                     vmi->vmi_shared.vmi_domid, vci->vci_shared.vci_vcpuid, \
                     status);                                           \
            ret = -EINTR;                                               \
            goto out;                                                   \
        }                                                               \
    } while (0)

    while (is_vci_runnable(vci)) {
        LONG x;
        uint32_t increase;
        preemption_t i;

        aff = uxen_cpu_pin_vcpu(vci, KeGetCurrentProcessorNumber());
        /* like uxen_call, except unpin cpu before re-enabling
         * preemption */
        if (uxen_pages_increase_reserve_extra(&i, VCPU_RUN_RESERVE,
                                              VCPU_RUN_EXTRA_RESERVE,
                                              &increase))
            x = 0;
        else
            while ((x = uxen_devext->de_executing) == 0 ||
                   InterlockedCompareExchange(
                       &uxen_devext->de_executing, x + 1, x) != x) {
                if (suspend_block(i, VCPU_RUN_RESERVE +
                                  VCPU_RUN_EXTRA_RESERVE / 2, &increase)) {
                    x = 0;
                    break;
                }
            }
        if (x == 0) {
            uxen_cpu_unpin_vcpu(vci, aff);
            enable_preemption(i);
            continue;
        }
        vci->vci_executing = 1;
        try_call(ret = (int), -EFAULT, uxen_do_run_vcpu,
                 vmi->vmi_shared.vmi_domid, vci->vci_shared.vci_vcpuid);
        vci->vci_executing = 0;

        if (ret)
            fail_msg("uxen_do_run_vcpu: vm%u.%u: ret %d",
                     vmi->vmi_shared.vmi_domid, vci->vci_shared.vci_vcpuid,
                     ret);

        /* we might've been holding the spinlock and finished with it,
         * wake any vcpus waiting in spin loop */
        wake_spinning_vcpus(vmi);

        if (!InterlockedDecrement(&uxen_devext->de_executing))
            KeSetEvent(&uxen_devext->de_suspend_event, 0, FALSE);
	uxen_cpu_unpin_vcpu(vci, aff);
        uxen_pages_decrease_reserve(i, increase);

        if (ret || !is_vci_runnable(vci))
	    break;

        if (vci->vci_shared.vci_map_page_range_requested) {
#ifdef DEBUG_POC_MAP_PAGE_RANGE_RETRY
            dprintk("%s: vm%d.%d EMAPPAGERANGE cpu%d\n", __FUNCTION__,
                    vmi->vmi_shared.vmi_domid, vci->vci_shared.vci_vcpuid,
                    cpu_number());
            vci->vci_map_page_range_provided =
                vci->vci_shared.vci_map_page_range_requested;
            vci->vci_shared.vci_map_page_range_requested = 0;
#else  /* DEBUG_POC_MAP_PAGE_RANGE_RETRY */
            fail_msg("%s: vm%d.%d: unexpected EMAPPAGERANGE", __FUNCTION__,
                     vmi->vmi_shared.vmi_domid, vci->vci_shared.vci_vcpuid);
            ret = -EINVAL;
            goto out;
#endif  /* DEBUG_POC_MAP_PAGE_RANGE_RETRY */
        }

        switch (vci->vci_shared.vci_run_mode) {
        case VCI_RUN_MODE_PROCESS_IOREQ: {
            KEVENT *event = (KEVENT * volatile)vci->vci_shared.vci_wait_event;
            if (event != &dummy_event) {
                EVENT_WAIT(event, 1, 0);
                /* since timeout == 0, EVENT_WAIT only continues here
                 * on SUCCESS */
                KeClearEvent(event);
                vci->vci_shared.vci_wait_event = &dummy_event;
            }
            break;
        }
        case VCI_RUN_MODE_PREEMPT:
            /* nothing */
            break;
        case VCI_RUN_MODE_YIELD: {
            /* Yield run mode means that spin loop was detected in the guest.
             * If another vcpu is executing, go back to spinning otherwise
             * wait for some vcpu to execute for a bit */
            int num_executing = 0, num_halt = 0, i;
            MemoryBarrier();
            for (i = 0; i < vmi->vmi_nrvcpus; ++i) {
                struct vm_vcpu_info *v = &vmi->vmi_vcpus[i];
                if (v->vci_executing &&
                    v->vci_shared.vci_run_mode != VCI_RUN_MODE_YIELD)
                    num_executing++;
                if (v->vci_shared.vci_run_mode == VCI_RUN_MODE_HALT)
                    num_halt++;
            }
            if (num_executing == 0 &&
                num_halt < vmi->vmi_nrvcpus - 1)
                EVENT_WAIT(&vmi->vmi_spinloop_wake_event, 1, 20000);
            break;
        }

        case VCI_RUN_MODE_SETUP:
        case VCI_RUN_MODE_HALT:
            KeClearEvent(&vci->vci_runnable);
	    MemoryBarrier();	/* ensure vci_host_halted was not pre-fetched */
            if (vci->vci_shared.vci_host_halted)
                EVENT_WAIT(&vci->vci_runnable, 1, 0);
            break;
        case VCI_RUN_MODE_IDLE_WORK:
            /* nothing */
            break;
        case VCI_RUN_MODE_SHUTDOWN:
            ret = 0;
            goto out;
        case VCI_RUN_MODE_PAGEMAP_CHECK:
            pagemap_check_space();
            break;
        case VCI_RUN_MODE_FREEPAGE_CHECK:
            /* nothing */
            break;
        case VCI_RUN_MODE_MAP_PAGE_REQUEST:
            /* nothing - handled above */
            break;
        case VCI_RUN_MODE_VFRAMES_CHECK:
            /* nothing */
            break;
        }
    }

#undef EVENT_WAIT

  out:
    return ret;
}

int
uxen_op_execute(struct uxen_execute_desc *ued, struct vm_info *vmi)
{
    struct vm_vcpu_info *vci;
    int ret = ENOENT;

    if (ued->ued_vcpu >= vmi->vmi_nrvcpus) {
        fail_msg("invalid vm%u.%u", vmi->vmi_shared.vmi_domid, ued->ued_vcpu);
        return EINVAL;
    }

    InterlockedIncrement(&vmi->vmi_running_vcpus);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    vci = &vmi->vmi_vcpus[ued->ued_vcpu];
    vci->vci_thread = KeGetCurrentThread();

    ret = uxen_vcpu_thread_fn(vmi, vci);
    ret = -ret;

  out:
    printk("%s: exiting vm%u.%u (%d)\n", __FUNCTION__,
           vmi->vmi_shared.vmi_domid, ued->ued_vcpu, ret);

    if (InterlockedDecrement(&vmi->vmi_running_vcpus) == 0)
        KeSetEvent(&vmi->vmi_notexecuting, 0, FALSE);
    return ret;
}

int
uxen_op_set_event(struct uxen_event_desc *ued, struct vm_info *vmi)
{
    NTSTATUS status;
    KEVENT **kev;
    int ret = ENOENT;

    InterlockedIncrement(&vmi->vmi_running_vcpus);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    switch (ued->ued_id) {
    case UXEN_EVENT_EXCEPTION:
	kev = &vmi->vmi_ioemu_exception_event;
	break;
    case UXEN_EVENT_VRAM:
	kev = &vmi->vmi_ioemu_vram_event;
	break;
    default:
        fail_msg("unknown event %d", ued->ued_id);
        ret = EINVAL;
        goto out;
    }

    if (*kev) {
        fail_msg("cannot change event %d", ued->ued_id);
        ret = EINVAL;
        goto out;
    }

    status = ObReferenceObjectByHandle(ued->ued_event, SYNCHRONIZE,
				       *ExEventObjectType, UserMode,
				       kev, NULL);
    if (!NT_SUCCESS(status)) {
        fail_msg("cannot get reference for event %d: 0x%08X", ued->ued_id,
                 status);
	*kev = NULL;
        ret = EINVAL;
        goto out;
    }

    ret = 0;
  out:
    if (InterlockedDecrement(&vmi->vmi_running_vcpus) == 0)
        KeSetEvent(&vmi->vmi_notexecuting, 0, FALSE);
    return ret;
}

int
uxen_op_set_event_channel(struct uxen_event_channel_desc *uecd,
                          struct vm_info *vmi, struct fd_assoc *fda)
{
    NTSTATUS status;
    struct host_event_channel *hec = NULL;
    struct evtchn_bind_host bind;
    int ev;
    int ret = ENOENT;

    InterlockedIncrement(&vmi->vmi_running_vcpus);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    if (uecd->uecd_vcpu >= UXEN_MAXIMUM_VCPUS) {
        fail_msg("invalid vcpu");
        ret = EINVAL;
        goto out;
    }

    hec = kernel_malloc(sizeof(*hec));
    if (hec == NULL) {
        fail_msg("kernel_malloc failed");
        ret = ENOMEM;
        goto out;
    }

    status = ObReferenceObjectByHandle(uecd->uecd_request_event,
                                       SYNCHRONIZE, *ExEventObjectType,
                                       UserMode, &hec->request, NULL);
    if (!NT_SUCCESS(status)) {
        fail_msg("cannot get reference for event channel %d request event"
                 ": 0x%08X", uecd->uecd_port, status);
	hec->request = NULL;
	ret = EINVAL;
	goto out;
    }

    if (uecd->uecd_completed_event) {
        status = ObReferenceObjectByHandle(uecd->uecd_completed_event,
                                           SYNCHRONIZE, *ExEventObjectType,
                                           UserMode, &hec->completed, NULL);
        if (!NT_SUCCESS(status)) {
            fail_msg("cannot get reference for event channel %d completed event"
                     ": 0x%08X", uecd->uecd_port, status);
            hec->completed = NULL;
            ret = EINVAL;
            goto out;
        }
    }

    bind.remote_dom = vmi->vmi_shared.vmi_domid;
    bind.remote_port = uecd->uecd_port;
    bind.host_opaque = hec;
    ret = (int)uxen_dom0_hypercall(
        &vmi->vmi_shared, &fda->user_mappings,
        UXEN_UNRESTRICTED_ACCESS_HYPERCALL |
        (fda->admin_access ? UXEN_ADMIN_HYPERCALL : 0) |
        UXEN_SYSTEM_HYPERCALL |
        (fda->vmi_owner ? UXEN_VMI_OWNER : 0), __HYPERVISOR_event_channel_op,
        (uintptr_t)EVTCHNOP_bind_host, (uintptr_t)&bind);
    if (ret) {
        fail_msg("event_channel_op(bind_host) failed: %d", ret);
	goto out;
    }

    if (hec->completed)
        KeClearEvent(hec->completed);

    hec->next = vmi->vmi_host_event_channels;
    vmi->vmi_host_event_channels = hec;

    ret = 0;
  out:
    if (ret && hec) {
	if (hec->request)
	    ObDereferenceObject(hec->request);
	if (hec->completed)
	    ObDereferenceObject(hec->completed);
	kernel_free(hec, sizeof(*hec));
    }
    if (InterlockedDecrement(&vmi->vmi_running_vcpus) == 0)
        KeSetEvent(&vmi->vmi_notexecuting, 0, FALSE);
    return ret;
}

int
uxen_op_query_vm(struct uxen_queryvm_desc *uqd)
{
    struct vm_info *vmi;
    struct vm_info_shared vmis;
    affinity_t aff;

    memset(&vmis, 0, sizeof(vmis));
    vmis.vmi_domid = uqd->uqd_domid;

    aff = uxen_lock();

    vmi = rb_tree_find_node_geq(&uxen_devext->de_vm_info_rbtree,
                                &vmis);
    if (vmi) {
        uqd->uqd_domid = vmi->vmi_shared.vmi_domid;
        memcpy(uqd->uqd_vmuuid, vmi->vmi_shared.vmi_uuid,
               sizeof(uqd->uqd_vmuuid));
    } else
        uqd->uqd_domid = -1;

    uxen_unlock(aff);

    return 0;
}

static void
quiesce_execution(void)
{
    KeClearEvent(&uxen_devext->de_resume_event);
    InterlockedDecrement(&uxen_devext->de_executing);

    while (uxen_devext->de_executing || resume_requested) {
        KeWaitForSingleObject(&uxen_devext->de_suspend_event, Executive,
                              KernelMode, FALSE, NULL);
        KeClearEvent(&uxen_devext->de_resume_event);
        KeClearEvent(&uxen_devext->de_suspend_event);
    }
}

static void
resume_execution(void)
{

    if (InterlockedIncrement(&uxen_devext->de_executing) > 0)
        KeSetEvent(&uxen_devext->de_resume_event, 0, FALSE);
}

void
uxen_power_state(uint32_t suspend)
{
#ifdef __i386__
    PIRP irp;
#endif /* __i386__ */

    if (!uxen_devext->de_initialised)
        return;

    if (!suspend) {
        resume_requested = 1;
        uxen_signal_idle_thread(0);

#ifdef __i386__
        InterlockedExchange(&s4_in_progress, FALSE);
        irp = InterlockedExchangePointer(&wait_for_resume_from_s4_irp, NULL);
        if (irp && IoSetCancelRoutine(irp, NULL)) {
            dprintk("uxen hiber: \n",);
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
        }
#endif /* __i386__ */
    } else {
        affinity_t aff;
        preemption_t i;
        NTSTATUS status;

        status = KeWaitForSingleObject(&uxen_devext->de_init_done, UserRequest,
                                       UserMode, TRUE, NULL);
        if (status != STATUS_SUCCESS)
            return;
        if (!uxen_devext->de_initialised)
            return;

        printk_with_timestamp("power state change: suspending\n");

        idle_thread_suspended = suspend;

        fill_vframes();
        aff = uxen_lock();
        disable_preemption(&i);
        try_call(, , uxen_do_suspend_xen_prepare);
        enable_preemption(i);
        uxen_unlock(aff);

        quiesce_execution();

        /* now we're the only uxen thread executing, safe to take down vmx */
        fill_vframes();
        disable_preemption(&i);
        try_call(, , uxen_do_suspend_xen);
        enable_preemption(i);
    }
}

static void
uxen_flush_rcu(void)
{
    unsigned int host_cpu;
    int rcu_pending, cpu_rcu_pending;
    preemption_t i;
    affinity_t aff;

    aff = uxen_cpu_pin_current();

    for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++) {
        if ((uxen_info->ui_cpu_active_mask & affinity_mask(host_cpu)) == 0)
            continue;
        uxen_cpu_pin(host_cpu);
        fill_vframes();
        disable_preemption(&i);
        try_call(, , uxen_do_flush_rcu, 0);
        enable_preemption(i);
    }

    do {
        rcu_pending = 0;
        for (host_cpu = 0; host_cpu < max_host_cpu; host_cpu++) {
            if ((uxen_info->ui_cpu_active_mask & affinity_mask(host_cpu)) == 0)
                continue;
            uxen_cpu_pin(host_cpu);
            fill_vframes();
            disable_preemption(&i);
            try_call(cpu_rcu_pending = (int), 0, uxen_do_flush_rcu, 1);
            enable_preemption(i);
            rcu_pending |= cpu_rcu_pending;
        }
    } while (rcu_pending);

    uxen_cpu_unpin(aff);
}

int
uxen_op_map_host_pages(struct uxen_map_host_pages_desc *umhpd,
                       struct fd_assoc *fda)
{

    return map_host_pages(umhpd->umhpd_va, (size_t)umhpd->umhpd_len,
                          umhpd->umhpd_gpfns, fda);
}

int
uxen_op_unmap_host_pages(struct uxen_map_host_pages_desc *umhpd,
                         struct fd_assoc *fda)
{

    return unmap_host_pages(umhpd->umhpd_va, (size_t)umhpd->umhpd_len, fda);
}
