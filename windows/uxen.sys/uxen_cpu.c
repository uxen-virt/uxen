/*
 *  uxen_cpu.c
 *  uxen
 *
 * Copyright 2011-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

static unsigned int first_cpu = MAXIMUM_PROCESSORS - 1;
unsigned int nr_host_cpus = 0;
unsigned int max_host_cpu = 0;

affinity_t
uxen_cpu_pin(unsigned long host_cpu)
{
    KAFFINITY affinity;

    affinity = affinity_mask(host_cpu);
    return KeSetSystemAffinityThreadEx(affinity);
}

affinity_t
uxen_cpu_pin_current(void)
{
    unsigned long cpu;

    cpu = KeGetCurrentProcessorNumber();
    return uxen_cpu_pin(cpu);
}

affinity_t
uxen_cpu_pin_first(void)
{

    return uxen_cpu_pin(first_cpu);
}

void
uxen_cpu_unpin(affinity_t aff)
{

    KeRevertToUserAffinityThreadEx(aff);
}

affinity_t
uxen_cpu_pin_vcpu(struct vm_vcpu_info *vci, int cpu)
{
    affinity_t aff;
    preemption_t pre;

    spinlock_acquire(vci->vci_ipi_lck, pre);
    if (vci->vci_ipi_queued && vci->vci_ipi_cpu != cpu) {
        KeRemoveQueueDpc(&vci->vci_ipi_dpc);
	KeSetTargetProcessorDpc(&vci->vci_ipi_dpc, (CCHAR)cpu);
	vci->vci_ipi_cpu = cpu;
        KeInsertQueueDpc(&vci->vci_ipi_dpc, NULL, NULL);
    }
    spinlock_release(vci->vci_ipi_lck, pre);

    aff = uxen_cpu_pin(cpu);
    vci->vci_host_cpu = cpu;

    return aff;
}

void
uxen_cpu_unpin_vcpu(struct vm_vcpu_info *vci, affinity_t aff)
{

    KeRevertToUserAffinityThreadEx(aff);
}

int
uxen_cpu_set_active_mask(uint64_t *mask)
{
    KAFFINITY affinity;
    unsigned int host_cpu;

    affinity = KeQueryActiveProcessors();
    BUG_ON(sizeof(affinity) > sizeof(uint64_t));
    *mask = 0;
    memcpy(mask, &affinity, sizeof(affinity));

    for (host_cpu = 0; host_cpu < MAXIMUM_PROCESSORS; host_cpu++) {
        if (host_cpu >= UXEN_MAXIMUM_PROCESSORS) {
            fail_msg("invalid cpu %d in active mask", host_cpu);
            return 1;
        }
	if ((affinity & affinity_mask(host_cpu)) == 0)
	    continue;
#if defined(VM_AFFINITY_ONE)
        if (!uxen_cpu_vm && host_cpu > first_cpu)
            uxen_cpu_vm = host_cpu;
#endif
        if (host_cpu < first_cpu)
            first_cpu = host_cpu;
        max_host_cpu = host_cpu;
        nr_host_cpus++;
    }
    max_host_cpu++;
#if defined(VM_AFFINITY_ONE)
    BUG_ON(!uxen_cpu_vm);
#endif

    return 0;
}

void __cdecl
uxen_cpu_on_selected(const void *mask, uintptr_t (*fn)(uintptr_t))
{

#ifdef __x86_64__
    printk("KeIpiGenericCall(%p) was called\n", fn);
#endif
    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)fn, 0);
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
