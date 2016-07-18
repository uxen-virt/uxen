/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"

#include <kern/sched_prim.h>
#include <kern/locks.h>
#include <libkern/libkern.h> /* ffs() */


static unsigned int first_cpu = MAX_CPUS - 1;
unsigned int nr_host_cpus = 0;
unsigned int max_host_cpu = 0;
static uint32_t ipi_raised_vector[MAX_CPUS];
static lck_spin_t *ipi_lock[MAX_CPUS];
static void (*ipi_dispatch)(unsigned int);
static uint64_t active_mask;

static int get_cpu_number(cpu_data_t *cpu)
{
    static size_t cpu_offset = 0;

    if (cpu_offset == 0) {
        cpu_offset = CPU_DATA_CPUNUMBER();
    }

    return *(int *)((uint8_t *)cpu + cpu_offset);
}

int
uxen_cpu_set_active_mask(uint64_t *mask)
{
    cpu_data_t **cpu_data_ptr = xnu_cpu_data_ptr();
    int i;

    *mask = 0;
    dprintk("CPUs:\n");
    for (i = 0; i < MAX_CPUS; i++) {
        int host_cpu;

        if (!cpu_data_ptr[i])
            continue;

        host_cpu = get_cpu_number(cpu_data_ptr[i]);
        dprintk("    CPU %d active\n", i);

        if (host_cpu >= UXEN_MAXIMUM_PROCESSORS) {
            fail_msg("invalid cpu %d in active mask", host_cpu);
            return 1;
        }

        *mask |= (1 << host_cpu);

        if (host_cpu < first_cpu)
            first_cpu = host_cpu;

        max_host_cpu = host_cpu;
        nr_host_cpus++;
    }
    max_host_cpu++;

    active_mask = *mask;

    return 0;
}

affinity_t
uxen_cpu_pin(int cpu)
{
    affinity_t aff;
    processor_t processor = xnu_cpu_to_processor(cpu);

    if (!processor)
        return PROCESSOR_NULL;

    aff = xnu_thread_bind(processor);
    if (cpu != cpu_number())
        thread_block(THREAD_CONTINUE_NULL);

    return aff;
}

affinity_t
uxen_cpu_pin_current(void)
{
    affinity_t aff;
    int cpu = cpu_number();
    processor_t processor = xnu_cpu_to_processor(cpu);

    if (!processor)
        return PROCESSOR_NULL;

    aff = xnu_thread_bind(processor);
    if (cpu != cpu_number())
        thread_block(THREAD_CONTINUE_NULL);

    return aff;
}

affinity_t
uxen_cpu_pin_first(void)
{

    return uxen_cpu_pin(first_cpu);
}

void
uxen_cpu_unpin(affinity_t aff)
{

    xnu_thread_bind(aff);
    if (aff != PROCESSOR_NULL)
        thread_block(THREAD_CONTINUE_NULL);
}

affinity_t
uxen_cpu_pin_vcpu(struct vm_vcpu_info *vci, int cpu)
{
    affinity_t aff;

    aff = uxen_cpu_pin(cpu);
    vci->vci_host_cpu = cpu;

    return aff;
}

void
uxen_cpu_unpin_vcpu(struct vm_vcpu_info *vci, affinity_t aff)
{

    uxen_cpu_unpin(aff);
}

static void
interrupt_noop(void *arg)
{

    /* nothing */
}

void
uxen_cpu_interrupt(uintptr_t mask)
{

    mask &= active_mask;
    xnu_mp_cpus_call(mask, NOSYNC, interrupt_noop, NULL);
}

void
uxen_cpu_call(int cpu, void (*fn)(void *), void *arg)
{
    uintptr_t mask = 1ULL << cpu;

    if (!(mask & active_mask))
        return;

    xnu_mp_cpus_call(mask, NOSYNC, fn, arg);
}

void
uxen_cpu_on_selected(const void *_mask, uintptr_t (*fn)(uintptr_t))
{
    uintptr_t mask = *(uintptr_t *)_mask;

    mask &= active_mask;
    xnu_mp_cpus_call(mask, NOSYNC, (void (*)(void *))fn, NULL);
}

void
uxen_cpu_on_selected_async(uintptr_t mask, uintptr_t (*fn)(uintptr_t))
{

    mask &= active_mask;
    xnu_mp_cpus_call(mask, ASYNC, (void (*)(void *))fn, NULL);
}

int
uxen_ipi_init(void (*dispatch)(unsigned int))
{
    int cpu;

    memset(ipi_lock, 0, max_host_cpu * sizeof(lck_spin_t *));

    for (cpu = 0; cpu < max_host_cpu; cpu++) {
        if ((active_mask & affinity_mask(cpu)) == 0)
            continue;
        ipi_lock[cpu] = lck_spin_alloc_init(uxen_lck_grp, LCK_ATTR_NULL);
        if (!ipi_lock[cpu])
            return ENOMEM;
        ipi_raised_vector[cpu] = 0;
    }

    ipi_dispatch = dispatch;

    return 0;
}

void
uxen_ipi_cleanup(void)
{
    int cpu;

    for (cpu = 0; cpu < max_host_cpu; cpu++) {
        if (ipi_lock[cpu]) {
            lck_spin_free(ipi_lock[cpu], uxen_lck_grp);
            ipi_lock[cpu] = NULL;
        }
    }
}

static void ipi_cb(void *arg)
{
    int cpu = cpu_number();
    uint32_t vectors = ipi_raised_vector[cpu];

    while (vectors) {
        int v = ffs(vectors) - 1;

        vectors &= ~(1 << v);

        lck_spin_lock(ipi_lock[cpu]);
        ipi_raised_vector[cpu] &= ~(1 << v);
        lck_spin_unlock(ipi_lock[cpu]);

        ipi_dispatch(v);
    }
}

void
uxen_cpu_ipi(int cpu, unsigned int vector)
{
    assert(cpu < max_host_cpu && vector < (sizeof (ipi_raised_vector[0]) * 8));

    lck_spin_lock(ipi_lock[cpu]);
    ipi_raised_vector[cpu] |= (1 << vector);
    lck_spin_unlock(ipi_lock[cpu]);

    xnu_mp_cpus_call((1 << cpu), NOSYNC, ipi_cb, NULL);
}

