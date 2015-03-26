/*
 *  uxen_cpu.c
 *  uxen
 *
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

unsigned long
uxen_first_cpu(void)
{
    KAFFINITY affinity;
    unsigned long host_cpu;

    affinity = KeQueryActiveProcessors();
    for (host_cpu = 0; host_cpu < MAXIMUM_PROCESSORS; host_cpu++) {
	if (affinity & affinity_mask(host_cpu))
	    break;
    }
    BUG_ON(host_cpu == MAXIMUM_PROCESSORS);
    return host_cpu;
}

void
uxen_cpu_pin(unsigned long host_cpu)
{
    KAFFINITY affinity;

    affinity = affinity_mask(host_cpu);
    KeSetSystemAffinityThread(affinity);
}

void
uxen_cpu_pin_current(void)
{
    unsigned long cpu;

    cpu = KeGetCurrentProcessorNumber();
    uxen_cpu_pin(cpu);
}

void
uxen_cpu_pin_first(void)
{
    unsigned long cpu;

    cpu = uxen_first_cpu();
    uxen_cpu_pin(cpu);
}

void
uxen_cpu_unpin(void)
{

    KeRevertToUserAffinityThread();
}

void
uxen_cpu_pin_vcpu(struct vm_vcpu_info *vci, int cpu)
{
    preemption_t pre;

    spinlock_acquire(vci->vci_ipi_lck, pre);
    if (vci->vci_ipi_queued && vci->vci_ipi_cpu != cpu) {
        KeRemoveQueueDpc(&vci->vci_ipi_dpc);
	KeSetTargetProcessorDpc(&vci->vci_ipi_dpc, (CCHAR)cpu);
	vci->vci_ipi_cpu = cpu;
        KeInsertQueueDpc(&vci->vci_ipi_dpc, NULL, NULL);
    }
    spinlock_release(vci->vci_ipi_lck, pre);

    uxen_cpu_pin(cpu);
    vci->vci_host_cpu = cpu;
}

/* This controls which cpus the vm execution thread is pinned to when
 * it's not running.  The thread pins itself to whichever cpu it is
 * running on when it gets to run again, thus this controls the
 * possible cpus for the thread. */
#define VM_AFFINITY_USER 1
// #define VM_AFFINITY_ALL 1
// #define VM_AFFINITY_ALL_BUT_FIRST 1
// #define VM_AFFINITY_ONE 1

#if defined(VM_AFFINITY_ONE)
static unsigned long uxen_cpu_vm = 0;
#endif

void
uxen_cpu_unpin_vcpu(struct vm_vcpu_info *vci)
{
    KAFFINITY affinity;
    unsigned long cpu;

#if defined(VM_AFFINITY_USER)
    KeRevertToUserAffinityThread();
    return;
#elif defined(VM_AFFINITY_ALL)
    affinity = KeQueryActiveProcessors();
    KeSetSystemAffinityThread(affinity);
    return;
#elif defined(VM_AFFINITY_ALL_BUT_FIRST)
    cpu = uxen_first_cpu();
    affinity = KeQueryActiveProcessors();
    affinity &= ~affinity_mask(cpu);
    KeSetSystemAffinityThread(affinity);
    return;
#elif defined(VM_AFFINITY_ONE)
    uxen_cpu_pin(uxen_cpu_vm);
    return;
#endif
}

void
uxen_cpu_set_active_mask(void *mask, int mask_size)
{
    KAFFINITY affinity;

    affinity = KeQueryActiveProcessors();
    BUG_ON(sizeof(affinity) > mask_size);
    memcpy(mask, &affinity, sizeof(affinity));

#if defined(VM_AFFINITY_ONE)
    for (uxen_cpu_vm = uxen_first_cpu() + 1; uxen_cpu_vm < MAXIMUM_PROCESSORS;
	 uxen_cpu_vm++) {
	if (affinity & affinity_mask(uxen_cpu_vm))
	    break;
    }
    BUG_ON(uxen_cpu_vm == MAXIMUM_PROCESSORS);
#endif
}

void __cdecl
uxen_cpu_on_selected(const void *mask, uintptr_t (*fn)(uintptr_t))
{
    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)fn, 0);
}

static ULONG_PTR
interrupt_noop(ULONG_PTR arg)
{

    /* nothing */
    return 0;
}

void __cdecl
uxen_cpu_interrupt(uintptr_t mask)
{

    KeIpiGenericCall(interrupt_noop, 0);
}

#define CPUID_STRING_LEN 13

static int
cpuid_string(uint32_t leaf, char *signature)
{
    int cpu_info[4];

    memset(signature, 0, CPUID_STRING_LEN);

    __cpuid(cpu_info, leaf);

    switch (leaf) {
    case 0x40000000:
        *((int *)signature) = cpu_info[1];
        *((int *)(signature + 4)) = cpu_info[2];
        *((int *)(signature + 8)) = cpu_info[3];
        break;
    default:
        *((int *)signature) = cpu_info[1];
        *((int *)(signature + 4)) = cpu_info[3];
        *((int *)(signature + 8)) = cpu_info[2];
        break;
    }

#ifdef DBG
    {
        int i;
        for (i = 0; i < 12; i++)
            if (signature[i] < 32 || signature[i] > 126)
                break;
        dprintk("cpuid leaf %08x signature: %s\n", leaf,
                (i == 12) ? signature : "<garbage>");
    }
#endif

    return 0;
}

int
pv_vmware(void)
{
    char signature[CPUID_STRING_LEN];

    cpuid_string(0x40000000, signature);
    return !strcmp(signature, "VMwareVMware");
}

int
uxen_cpu_vendor(void)
{
    char signature[CPUID_STRING_LEN];

    cpuid_string(0x0, signature);

    if (!strcmp(signature, "GenuineIntel"))
        return UXEN_CPU_VENDOR_INTEL;
    if (!strcmp(signature, "AuthenticAMD"))
        return UXEN_CPU_VENDOR_AMD;
    return UXEN_CPU_VENDOR_UNKNOWN;
}
