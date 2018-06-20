/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/os.h>
#include <dm/cpu.h>
#include <dm/whpx/whpx.h>
#include <dm/whpx/apic.h>

/* Viridian MSR numbers. */
#define VIRIDIAN_MSR_GUEST_OS_ID                0x40000000
#define VIRIDIAN_MSR_HYPERCALL                  0x40000001
#define VIRIDIAN_MSR_VP_INDEX                   0x40000002
#define VIRIDIAN_MSR_TIME_REF_COUNT             0x40000020
#define VIRIDIAN_MSR_REFERENCE_TSC_PAGE         0x40000021
#define VIRIDIAN_MSR_EOI                        0x40000070
#define VIRIDIAN_MSR_ICR                        0x40000071
#define VIRIDIAN_MSR_TPR                        0x40000072
#define VIRIDIAN_MSR_APIC_ASSIST                0x40000073
#define VIRIDIAN_MSR_CRASH_P0                   0x40000100
#define VIRIDIAN_MSR_CRASH_P1                   0x40000101
#define VIRIDIAN_MSR_CRASH_P2                   0x40000102
#define VIRIDIAN_MSR_CRASH_P3                   0x40000103
#define VIRIDIAN_MSR_CRASH_P4                   0x40000104
#define VIRIDIAN_MSR_CRASH_CTL                  0x40000105

/* Viridian Hypercall Status Codes. */
#define HV_STATUS_SUCCESS                       0x0000
#define HV_STATUS_INVALID_HYPERCALL_CODE        0x0002

#define HV_X64_MSR_TSC_REFERENCE_ENABLE         0x00000001
#define HV_X64_MSR_TSC_REFERENCE_ADDRESS_SHIFT  12

/* Viridian Hypercall Codes and Parameters. */
#define HvNotifyLongSpinWait    8

/* Viridian CPUID 4000003, Viridian MSR availability. */
#define CPUID3A_MSR_REF_COUNT   (1 << 1)
#define CPUID3A_MSR_APIC_ACCESS (1 << 4)
#define CPUID3A_MSR_HYPERCALL   (1 << 5)
#define CPUID3A_MSR_VP_INDEX    (1 << 6)
#define CPUID3A_MSR_TSC_ACCESS  (1 << 9)
#define CPUID3D_MSR_CRASH       (1 << 10) 

/* Viridian CPUID 4000004, Implementation Recommendations. */
#define CPUID4A_MSR_BASED_APIC  (1 << 3)
#define CPUID4A_RELAX_TIMER_INT (1 << 5)

// FIXME: save/restore

union viridian_apic_assist
{
    uint64_t raw;
    struct
    {
        uint64_t enabled:1;
        uint64_t reserved_preserved:11;
        uint64_t pfn:48;
    } fields;
};

union viridian_guest_os_id
{
    uint64_t raw;
    struct
    {
        uint64_t build_number:16;
        uint64_t service_pack:8;
        uint64_t minor:8;
        uint64_t major:8;
        uint64_t os:8;
        uint64_t vendor:16;
    } fields;
};

union viridian_hypercall_gpa
{   uint64_t raw;
    struct
    {
        uint64_t enabled:1;
        uint64_t reserved_preserved:11;
        uint64_t pfn:48;
    } fields;
};

typedef struct viridian {
    union viridian_guest_os_id guest_os_id;
    union viridian_hypercall_gpa hypercall_gpa;
} viridian_t;

static viridian_t viridian;
static union viridian_apic_assist apic_assist[WHPX_MAX_VCPUS];

int cpuid_viridian_leaves(uint64_t leaf, uint64_t *eax,
                          uint64_t *ebx, uint64_t *ecx,
                          uint64_t *edx)
{
    if (!vm_viridian)
        return 0;

    leaf -= 0x40000000;
    if ( leaf > 6 )
        return 0;

    *eax = *ebx = *ecx = *edx = 0;
    switch ( leaf )
    {
    case 1:
        *eax = 0x31237648; /* Version number */
        break;
    case 2:
        /* Hypervisor information, but only if the guest has set its
           own version number. */
        if ( viridian.guest_os_id.raw == 0 )
            break;
        *eax = 1; /* Build number */
        *ebx = 1; /* version */
        *ecx = 0; /* SP */
        *edx = 0; /* Service branch and number */
        break;
    case 3:
        /* Which hypervisor MSRs are available to the guest */
        *eax = (CPUID3A_MSR_APIC_ACCESS |
                CPUID3A_MSR_HYPERCALL |
                CPUID3A_MSR_VP_INDEX);
        *edx = 0;
        break;
    case 4:
        /* Recommended hypercall usage. */
        if ( (viridian.guest_os_id.raw == 0) ||
             (viridian.guest_os_id.fields.os < 4) )
            break;
        *eax = (CPUID4A_MSR_BASED_APIC |
                CPUID4A_RELAX_TIMER_INT);
        *ebx = 2047; /* long spin count */
        break;
    }

    return 1;
}

int
viridian_hypercall(uint64_t *rax)
{
    uint64_t input = *rax;
    uint64_t callcode = input & 0xFFFF;
    uint64_t ret = HV_STATUS_SUCCESS;

    switch (callcode) {
    case HvNotifyLongSpinWait:
        break;
    default:
        //debug_printf("unhandled viridian hypercall: call code=0x%x input=%"PRIx64"\n", (int)callcode, input);
        ret = HV_STATUS_INVALID_HYPERCALL_CODE;
        break;
    }

    *rax = ret;

    return 1;
}

static void
dump_guest_os_id(void)
{
    debug_printf("GUEST_OS_ID:\n");
    debug_printf("\tvendor: %x\n",
            viridian.guest_os_id.fields.vendor);
    debug_printf("\tos: %x\n",
            viridian.guest_os_id.fields.os);
    debug_printf("\tmajor: %x\n",
            viridian.guest_os_id.fields.major);
    debug_printf("\tminor: %x\n",
            viridian.guest_os_id.fields.minor);
    debug_printf("\tsp: %x\n",
            viridian.guest_os_id.fields.service_pack);
    debug_printf("\tbuild: %x\n",
            viridian.guest_os_id.fields.build_number);
}

static void
dump_apic_assist(CPUState *cpu)
{
    union viridian_apic_assist *aa = &apic_assist[cpu->cpu_index];

    debug_printf("APIC_ASSIST[%d]:\n", cpu->cpu_index);
    debug_printf("\tenabled: %x\n", aa->fields.enabled);
    debug_printf("\tpfn: %"PRIx64"\n", (uint64_t)aa->fields.pfn);
}

static void
dump_hypercall()
{
    debug_printf("HYPERCALL:\n");
    debug_printf("\tenabled: %x\n",
            viridian.hypercall_gpa.fields.enabled);
    debug_printf("\tpfn: %"PRIx64"\n",
            (uint64_t)viridian.hypercall_gpa.fields.pfn);
}

static int
enable_hypercall_page(void)
{
    uint64_t gmfn = viridian.hypercall_gpa.fields.pfn;
    uint8_t *p;
    uint64_t len = PAGE_SIZE;

    p = whpx_ram_map(gmfn << PAGE_SHIFT, &len);
    if (p) {
        assert(len == PAGE_SIZE);

        /* We setup hypercall stub such that it invokes cpuid with bits 30&31 set
         * in eax as a marker */
        *(uint8_t  *)(p + 0) = 0x0d; /* orl $0x80000000, %eax */
        *(uint32_t *)(p + 1) = 0xC0000000;
        *(uint8_t  *)(p + 5) = 0x0f; /* cpuid */
        *(uint8_t  *)(p + 6) = 0xA2;
        *(uint8_t  *)(p + 7) = 0xc3; /* ret */
        memset(p + 9, 0xcc, PAGE_SIZE - 9); /* int3, int3, ... */

        whpx_ram_unmap(p);

        return 0;
    }

    return -1;
}

static int
initialize_apic_assist(CPUState *cpu)
{
    uint64_t gmfn = apic_assist[cpu->cpu_index].fields.pfn;
    uint64_t len = PAGE_SIZE;
    void *p;

    p = whpx_ram_map(gmfn << PAGE_SHIFT, &len);
    if (p) {
        assert(len == PAGE_SIZE);
        *(uint32_t*)p = 0;
        whpx_ram_unmap(p);
        return 0;
    }

    debug_printf("failed to initialize apic assist\n");
    return -1;
}

int wrmsr_viridian_regs(uint32_t idx, uint64_t val)
{
    CPUState *cpu = whpx_get_current_cpu();

    if (!vm_viridian)
        return 0;

    switch ( idx )
    {
    case VIRIDIAN_MSR_GUEST_OS_ID:
        viridian.guest_os_id.raw = val;
        dump_guest_os_id();
        break;

    case VIRIDIAN_MSR_VP_INDEX:
        break;

    case VIRIDIAN_MSR_HYPERCALL:
        viridian.hypercall_gpa.raw = val;
        dump_hypercall();
        if ( viridian.hypercall_gpa.fields.enabled )
            if (enable_hypercall_page())
                return -1;
        break;
    case VIRIDIAN_MSR_EOI:
        whpx_lock_iothread();
        apic_eoi(cpu->apic_state);
        whpx_unlock_iothread();
        break;

    case VIRIDIAN_MSR_ICR: {
        uint32_t eax = (uint32_t)val, edx = (uint32_t)(val >> 32);
        eax &= ~(1 << 12);
        edx &= 0xff000000;
        whpx_lock_iothread();
        apic_set_icr2(cpu->apic_state, edx);
        apic_set_icr(cpu->apic_state, eax);
        whpx_unlock_iothread();
        break;
    }

    case VIRIDIAN_MSR_TPR:
        whpx_lock_iothread();
        apic_set_taskpri(cpu->apic_state, (uint8_t)val);
        whpx_unlock_iothread();
        break;

    case VIRIDIAN_MSR_APIC_ASSIST:
        apic_assist[cpu->cpu_index].raw = val;
        dump_apic_assist(cpu);
        if (apic_assist[cpu->cpu_index].fields.enabled)
            if (initialize_apic_assist(cpu))
                return -1;
        break;
    default:
        return 0;
    }

    return 1;
}

int rdmsr_viridian_regs(uint32_t idx, uint64_t *val)
{
    CPUState *cpu = whpx_get_current_cpu();

    if (!vm_viridian)
        return 0;

    switch ( idx )
    {
    case VIRIDIAN_MSR_GUEST_OS_ID:
        *val = viridian.guest_os_id.raw;
        break;

    case VIRIDIAN_MSR_VP_INDEX:
        *val = cpu->cpu_index;
        break;

    case VIRIDIAN_MSR_ICR:
        whpx_lock_iothread();
        *val = (((uint64_t)apic_get_icr2(cpu->apic_state) << 32) |
            apic_get_icr(cpu->apic_state));
        whpx_unlock_iothread();
        break;

    case VIRIDIAN_MSR_TPR:
        whpx_lock_iothread();
        *val = apic_get_taskpri(cpu->apic_state);
        whpx_unlock_iothread();
        break;

    case VIRIDIAN_MSR_APIC_ASSIST:
        *val = apic_assist[cpu->cpu_index].raw;
        break;

    default:
        return 0;
    }

    return 1;
}
