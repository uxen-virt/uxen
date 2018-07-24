/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

/******************************************************************************
 * viridian.c
 *
 * An implementation of some Viridian enlightenments. See Microsoft's
 * Hypervisor Top Level Functional Specification (v5.0a) at:
 *
 * https://github.com/Microsoft/Virtualization-Documentation/raw/master/tlfs/Hypervisor%20Top%20Level%20Functional%20Specification%20v5.0.pdf 
 *
 * for more information.
 */

#include <dm/qemu_glue.h>
#include <dm/os.h>
#include <dm/cpu.h>
#include <dm/whpx/whpx.h>
#include <dm/whpx/apic.h>
#include <dm/whpx/util.h>


/* Base+Freq viridian feature sets:
 *
 * - Hypercall MSRs (HV_X64_MSR_GUEST_OS_ID and HV_X64_MSR_HYPERCALL)
 * - APIC access MSRs (HV_X64_MSR_EOI, HV_X64_MSR_ICR and HV_X64_MSR_TPR)
 * - Virtual Processor index MSR (HV_X64_MSR_VP_INDEX)
 * - Timer frequency MSRs (HV_X64_MSR_TSC_FREQUENCY and
 *   HV_X64_MSR_APIC_FREQUENCY)
 */
#define _HVMPV_base_freq 0
#define HVMPV_base_freq  (1 << _HVMPV_base_freq)

/* Feature set modifications */

/* Disable timer frequency MSRs (HV_X64_MSR_TSC_FREQUENCY and
 * HV_X64_MSR_APIC_FREQUENCY).
 * This modification restores the viridian feature set to the
 * original 'base' set exposed in releases prior to Xen 4.4.
 */
#define _HVMPV_no_freq 1
#define HVMPV_no_freq  (1 << _HVMPV_no_freq)

/* Enable Partition Time Reference Counter (HV_X64_MSR_TIME_REF_COUNT) */
#define _HVMPV_time_ref_count 2
#define HVMPV_time_ref_count  (1 << _HVMPV_time_ref_count)

/* Enable Reference TSC Page (HV_X64_MSR_REFERENCE_TSC) */
#define _HVMPV_reference_tsc 3
#define HVMPV_reference_tsc  (1 << _HVMPV_reference_tsc)

/* Use Hypercall for remote TLB flush */
#define _HVMPV_hcall_remote_tlb_flush 4
#define HVMPV_hcall_remote_tlb_flush (1 << _HVMPV_hcall_remote_tlb_flush)

/* Use APIC assist */
#define _HVMPV_apic_assist 5
#define HVMPV_apic_assist (1 << _HVMPV_apic_assist)

/* Enable crash MSRs */
#define _HVMPV_crash_ctl 6
#define HVMPV_crash_ctl (1 << _HVMPV_crash_ctl)

/* Enable Synthetic Timer */
#define _HVMPV_synth_timer 7
#define HVMPV_synth_timer (1 << _HVMPV_synth_timer)

const uint64_t HVMPV_feature_mask =
    (
//      HVMPV_hcall_remote_tlb_flush |     // todo
//      HVMPV_crash_ctl |                  // todo
//      HVMPV_reference_tsc |              // doesn't work very well atm
        HVMPV_base_freq |
        HVMPV_no_freq |
        HVMPV_time_ref_count |
        HVMPV_synth_timer |
        HVMPV_apic_assist );


/* Viridian MSR numbers. */
#define HV_X64_MSR_GUEST_OS_ID                   0x40000000
#define HV_X64_MSR_HYPERCALL                     0x40000001
#define HV_X64_MSR_VP_INDEX                      0x40000002
#define HV_X64_MSR_RESET                         0x40000003
#define HV_X64_MSR_VP_RUNTIME                    0x40000010
#define HV_X64_MSR_TIME_REF_COUNT                0x40000020
#define HV_X64_MSR_REFERENCE_TSC                 0x40000021
#define HV_X64_MSR_TSC_FREQUENCY                 0x40000022
#define HV_X64_MSR_APIC_FREQUENCY                0x40000023
#define HV_X64_MSR_EOI                           0x40000070
#define HV_X64_MSR_ICR                           0x40000071
#define HV_X64_MSR_TPR                           0x40000072
#define HV_X64_MSR_VP_ASSIST_PAGE                0x40000073
#define HV_X64_MSR_SCONTROL                      0x40000080
#define HV_X64_MSR_SVERSION                      0x40000081
#define HV_X64_MSR_SIEFP                         0x40000082
#define HV_X64_MSR_SIMP                          0x40000083
#define HV_X64_MSR_EOM                           0x40000084
#define HV_X64_MSR_SINT0                         0x40000090
#define HV_X64_MSR_SINT1                         0x40000091
#define HV_X64_MSR_SINT2                         0x40000092
#define HV_X64_MSR_SINT3                         0x40000093
#define HV_X64_MSR_SINT4                         0x40000094
#define HV_X64_MSR_SINT5                         0x40000095
#define HV_X64_MSR_SINT6                         0x40000096
#define HV_X64_MSR_SINT7                         0x40000097
#define HV_X64_MSR_SINT8                         0x40000098
#define HV_X64_MSR_SINT9                         0x40000099
#define HV_X64_MSR_SINT10                        0x4000009A
#define HV_X64_MSR_SINT11                        0x4000009B
#define HV_X64_MSR_SINT12                        0x4000009C
#define HV_X64_MSR_SINT13                        0x4000009D
#define HV_X64_MSR_SINT14                        0x4000009E
#define HV_X64_MSR_SINT15                        0x4000009F
#define HV_X64_MSR_STIMER0_CONFIG                0x400000B0
#define HV_X64_MSR_STIMER0_COUNT                 0x400000B1
#define HV_X64_MSR_STIMER1_CONFIG                0x400000B2
#define HV_X64_MSR_STIMER1_COUNT                 0x400000B3
#define HV_X64_MSR_STIMER2_CONFIG                0x400000B4
#define HV_X64_MSR_STIMER2_COUNT                 0x400000B5
#define HV_X64_MSR_STIMER3_CONFIG                0x400000B6
#define HV_X64_MSR_STIMER3_COUNT                 0x400000B7
#define HV_X64_MSR_POWER_STATE_TRIGGER_C1        0x400000C1
#define HV_X64_MSR_POWER_STATE_TRIGGER_C2        0x400000C2
#define HV_X64_MSR_POWER_STATE_TRIGGER_C3        0x400000C3
#define HV_X64_MSR_POWER_STATE_CONFIG_C1         0x400000D1
#define HV_X64_MSR_POWER_STATE_CONFIG_C2         0x400000D2
#define HV_X64_MSR_POWER_STATE_CONFIG_C3         0x400000D3
#define HV_X64_MSR_STATS_PARTITION_RETAIL_PAGE   0x400000E0
#define HV_X64_MSR_STATS_PARTITION_INTERNAL_PAGE 0x400000E1
#define HV_X64_MSR_STATS_VP_RETAIL_PAGE          0x400000E2
#define HV_X64_MSR_STATS_VP_INTERNAL_PAGE        0x400000E3
#define HV_X64_MSR_GUEST_IDLE                    0x400000F0
#define HV_X64_MSR_SYNTH_DEBUG_CONTROL           0x400000F1
#define HV_X64_MSR_SYNTH_DEBUG_STATUS            0x400000F2
#define HV_X64_MSR_SYNTH_DEBUG_SEND_BUFFER       0x400000F3
#define HV_X64_MSR_SYNTH_DEBUG_RECEIVE_BUFFER    0x400000F4
#define HV_X64_MSR_SYNTH_DEBUG_PENDING_BUFFER    0x400000F5
#define HV_X64_MSR_CRASH_P0                      0x40000100
#define HV_X64_MSR_CRASH_P1                      0x40000101
#define HV_X64_MSR_CRASH_P2                      0x40000102
#define HV_X64_MSR_CRASH_P3                      0x40000103
#define HV_X64_MSR_CRASH_P4                      0x40000104
#define HV_X64_MSR_CRASH_CTL                     0x40000105

#define VIRIDIAN_MSR_MIN HV_X64_MSR_GUEST_OS_ID
#define VIRIDIAN_MSR_MAX HV_X64_MSR_CRASH_CTL

/* Viridian Hypercall Status Codes. */
#define HV_STATUS_SUCCESS                       0x0000
#define HV_STATUS_INVALID_HYPERCALL_CODE        0x0002
#define HV_STATUS_INVALID_PARAMETER             0x0005

/* Viridian Hypercall Codes. */
#define HvFlushVirtualAddressSpace 0x0002
#define HvFlushVirtualAddressList  0x0003
#define HvNotifyLongSpinWait       0x0008
#define HvGetPartitionId           0x0046
#define HvExtCallQueryCapabilities 0x8001

/* Viridian Hypercall Flags. */
#define HV_FLUSH_ALL_PROCESSORS 1

/*
 * Viridian Partition Privilege Flags.
 *
 * This is taken from section 4.2.2 of the specification, and fixed for
 * style and correctness.
 */
typedef struct {
    /* Access to virtual MSRs */
    uint64_t AccessVpRunTimeReg:1;
    uint64_t AccessPartitionReferenceCounter:1;
    uint64_t AccessSynicRegs:1;
    uint64_t AccessSyntheticTimerRegs:1;
    uint64_t AccessIntrCtrlRegs:1;
    uint64_t AccessHypercallMsrs:1;
    uint64_t AccessVpIndex:1;
    uint64_t AccessResetReg:1;
    uint64_t AccessStatsReg:1;
    uint64_t AccessPartitionReferenceTsc:1;
    uint64_t AccessGuestIdleReg:1;
    uint64_t AccessFrequencyRegs:1;
    uint64_t AccessDebugRegs:1;
    uint64_t Reserved1:19;

    /* Access to hypercalls */
    uint64_t CreatePartitions:1;
    uint64_t AccessPartitionId:1;
    uint64_t AccessMemoryPool:1;
    uint64_t AdjustMessageBuffers:1;
    uint64_t PostMessages:1;
    uint64_t SignalEvents:1;
    uint64_t CreatePort:1;
    uint64_t ConnectPort:1;
    uint64_t AccessStats:1;
    uint64_t Reserved2:2;
    uint64_t Debugging:1;
    uint64_t CpuManagement:1;
    uint64_t Reserved3:1;
    uint64_t Reserved4:1;
    uint64_t Reserved5:1;
    uint64_t AccessVSM:1;
    uint64_t AccessVpRegisters:1;
    uint64_t Reserved6:1;
    uint64_t Reserved7:1;
    uint64_t EnableExtendedHypercalls:1;
    uint64_t StartVirtualProcessor:1;
    uint64_t Reserved8:10;
} HV_PARTITION_PRIVILEGE_MASK;

typedef union _HV_CRASH_CTL_REG_CONTENTS
{
    uint64_t AsUINT64;
    struct
    {
        uint64_t Reserved:63;
        uint64_t CrashNotify:1;
    } u;
} HV_CRASH_CTL_REG_CONTENTS;

typedef struct {
    union
    {
        UINT64 AsUINT64;
        struct
        {
            UINT64 Enable      : 1;
            UINT64 Periodic    : 1;
            UINT64 Lazy        : 1;
            UINT64 AutoEnable  : 1;
            UINT64 ApicVector  : 8;
            UINT64 DirectMode  : 1;
            UINT64 ReservedZ1  : 3;
            UINT64 SINTx       : 4;
            UINT64 ReservedZ2  :44;
        };
    };
} HV_X64_MSR_STIMER_CONFIG_CONTENTS;

/* Viridian CPUID leaf 3, Hypervisor Feature Indication */
#define CPUID3D_CRASH_MSRS (1 << 10)

/* Viridian CPUID leaf 4: Implementation Recommendations. */
#define CPUID4A_HCALL_REMOTE_TLB_FLUSH (1 << 2)
#define CPUID4A_MSR_BASED_APIC         (1 << 3)
#define CPUID4A_RELAX_TIMER_INT        (1 << 5)

/* Viridian CPUID leaf 6: Implementation HW features detected and in use. */
#define CPUID6A_APIC_OVERLAY    (1 << 0)
#define CPUID6A_MSR_BITMAPS     (1 << 1)
#define CPUID6A_NESTED_PAGING   (1 << 3)

#define SINT_COUNT 16
#define TIMER_COUNT 4

/*
 * Version and build number reported by CPUID leaf 2
 *
 * These numbers are chosen to match the version numbers reported by
 * Windows Server 2008.
 */

static uint16_t viridian_major = 6;
static uint16_t viridian_minor = 0;
static uint32_t viridian_build = 0x1772;

/* versions corresponding to Windows 10 RS4: */
//static uint16_t viridian_major = 10;
//static uint16_t viridian_minor = 0;
//static uint32_t viridian_build = 0x42ee;

/*
 * Maximum number of retries before the guest will notify of failure
 * to acquire a spinlock.
 */
static uint32_t viridian_spinlock_retry_count = 2047;

#define APIC_BUS_CYCLE_NS               10

struct reference_tsc_page {
    uint32_t tsc_sequence;
    uint32_t reserved;
    uint64_t tsc_scale;
    int64_t  tsc_offset;
};

union viridian_vp_assist
{
    uint64_t raw;
    struct
    {
        uint64_t enabled:1;
        uint64_t reserved_preserved:11;
        uint64_t pfn:48;
    } fields;
};

union viridian_sint {
    uint64_t raw;
    struct
    {
        uint64_t vector:8;
        uint64_t rsvdp2:8;
        uint64_t masked:1;
        uint64_t autoeoi:1;
        uint64_t polling:1;
        uint64_t rsvdp:45;
    } fields;
};

union viridian_siefp
{
    uint64_t raw;
    struct
    {
        uint64_t enabled:1;
        uint64_t rsvdp:11;
        uint64_t pfn:48;
    } fields;
};

union viridian_simp
{
    uint64_t raw;
    struct
    {
        uint64_t enabled:1;
        uint64_t rsvdp:11;
        uint64_t pfn:48;
    } fields;
};

struct viridian_synic {
    uint64_t scontrol;
    uint64_t sversion;
    union viridian_siefp siefp;
    union viridian_simp simp;
    uint64_t eom;
    union viridian_sint sint[SINT_COUNT];
    uint64_t sint_irr;
};

struct viridian_timer {
    int cpu_index;
    int timer_index;
    Timer *timer;
    HV_X64_MSR_STIMER_CONFIG_CONTENTS config;
    uint64_t count;
};

struct viridian_vcpu
{
    int index;
    struct {
        union viridian_vp_assist msr;
        void *va;
        bool pending;
    } vp_assist;
    struct viridian_synic synic;
    struct viridian_timer timer[TIMER_COUNT];
    uint64_t crash_param[5];
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

union viridian_reference_tsc_msr
{
    uint64_t raw;
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
    union viridian_reference_tsc_msr reference_tsc_msr;
    uint64_t tsc_khz;
} viridian_t;

static viridian_t viridian;
static struct viridian_vcpu viridian_vcpu[WHPX_MAX_VCPUS];

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
    case 0:
        /* See section 2.4.1 of the specification */
        *eax = 0x40000006; /* Maximum leaf */
        memcpy(ebx, "Micr", 4);
        memcpy(ecx, "osof", 4);
        memcpy(edx, "t Hv", 4);
        break;

    case 1:
        /* See section 2.4.2 of the specification */
        memcpy(eax, "Hv#1", 4);
        break;

    case 2:
        /* Hypervisor information, but only if the guest has set its
           own version number. */
        if ( viridian.guest_os_id.raw == 0 )
            break;
        *eax = viridian_build;
        *ebx = ((uint32_t)viridian_major << 16) | viridian_minor;
        *ecx = 0; /* SP */
        *edx = 0; /* Service branch and number */
        break;

    case 3:
    {
        /*
         * Section 2.4.4 details this leaf and states that EAX and EBX
         * are defined to be the low and high parts of the partition
         * privilege mask respectively.
         */
        HV_PARTITION_PRIVILEGE_MASK mask = {
            .AccessIntrCtrlRegs = 1,
            .AccessHypercallMsrs = 1,
            .AccessVpIndex = 1,
        };
        union {
            HV_PARTITION_PRIVILEGE_MASK mask;
            struct { uint32_t lo, hi; };
        } u;

        if ( !(HVMPV_feature_mask & HVMPV_no_freq) )
            mask.AccessFrequencyRegs = 1;
        if ( HVMPV_feature_mask & HVMPV_time_ref_count )
            mask.AccessPartitionReferenceCounter = 1;
        if ( HVMPV_feature_mask & HVMPV_reference_tsc )
            mask.AccessPartitionReferenceTsc = 1;
        if ( HVMPV_feature_mask & HVMPV_synth_timer ) {
            mask.AccessSynicRegs = 1;
            mask.AccessSyntheticTimerRegs = 1;
        }

        u.mask = mask;

        *eax = u.lo;
        *ebx = u.hi;

        if ( HVMPV_feature_mask & HVMPV_crash_ctl )
            *edx = CPUID3D_CRASH_MSRS;

        break;
    }

    case 4:
        /* Recommended hypercall usage. */
        if ( (viridian.guest_os_id.raw == 0) ||
             (viridian.guest_os_id.fields.os < 4) )
            break;
        *eax = CPUID4A_RELAX_TIMER_INT;
        if ( HVMPV_feature_mask & HVMPV_hcall_remote_tlb_flush )
            *eax |= CPUID4A_HCALL_REMOTE_TLB_FLUSH;
        /* until APIC virt */
        *eax |= CPUID4A_MSR_BASED_APIC;

        /*
         * This value is the recommended number of attempts to try to
         * acquire a spinlock before notifying the hypervisor via the
         * HvNotifyLongSpinWait hypercall.
         */
        *ebx = viridian_spinlock_retry_count;
        break;

    case 6:
        /* Detected and in use hardware features. */
        //if ( cpu_has_vmx_virtualize_apic_accesses )
        //    res->a |= CPUID6A_APIC_OVERLAY;
        //if ( cpu_has_vmx_msr_bitmap || (read_efer() & EFER_SVME) )
        //    res->a |= CPUID6A_MSR_BITMAPS;
        //if ( hap_enabled(d) )
        //    res->a |= CPUID6A_NESTED_PAGING;
        *eax |= CPUID6A_NESTED_PAGING;

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
        count_longspin++;
        break;
    default:
        debug_printf("unhandled viridian hypercall: call code=0x%x input=%"PRIx64"\n", (int)callcode, input);
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
dump_vp_assist(CPUState *cpu)
{
    union viridian_vp_assist *aa = &viridian_vcpu[cpu->cpu_index].vp_assist.msr;

    debug_printf("VP_ASSIST[%d]:\n", cpu->cpu_index);
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

static void
dump_reference_tsc(void)
{
    const union viridian_reference_tsc_msr *rt;

    rt = &viridian.reference_tsc_msr;
    debug_printf("VIRIDIAN REFERENCE_TSC: enabled: %x pfn: %lx\n",
           rt->fields.enabled, (unsigned long)rt->fields.pfn);
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
        *(uint8_t * )(p + 0) = 0x89; /* mov %ecx, %eax */
        *(uint8_t * )(p + 1) = 0xc8;
        *(uint8_t  *)(p + 2) = 0x0d; /* orl $0xC0000000, %eax */
        *(uint32_t *)(p + 3) = 0xC0000000;
        *(uint8_t  *)(p + 7) = 0x0f; /* cpuid */
        *(uint8_t  *)(p + 8) = 0xA2;
        *(uint8_t  *)(p + 9) = 0xc3; /* ret */
        memset(p + 10, 0xcc, PAGE_SIZE - 9); /* int3, int3, ... */

        whpx_ram_unmap(p);

        return 0;
    }

    return -1;
}

static uint64_t
calibrate_tsc(void)
{
    LARGE_INTEGER wait, cur, start;
    uint64_t tsc_start;

    QueryPerformanceFrequency(&wait);
    QueryPerformanceCounter(&start);
    wait.QuadPart >>= 5;
    tsc_start = _rdtsc();
    do {
        QueryPerformanceCounter(&cur);
    } while (cur.QuadPart - start.QuadPart < wait.QuadPart);

    return ((_rdtsc() - tsc_start) << 5) / 1000;
}

static uint64_t
get_tsc_khz(void)
{
    static uint64_t tsc_khz = 0;

    if (!tsc_khz) {
        tsc_khz = calibrate_tsc();
        debug_printf("TSC calibrated @ %.3f MHz\n", tsc_khz / 1000.0);
    }

    return tsc_khz;
}

static int
enable_reference_tsc_page(CPUState *cpu, uint64_t gmfn)
{
    uint64_t len = PAGE_SIZE;
    struct reference_tsc_page *tsc_ref;

    tsc_ref = whpx_ram_map(gmfn << PAGE_SHIFT, &len);
    if (tsc_ref) {
        assert(len == PAGE_SIZE);

        if (!viridian.tsc_khz)
            viridian.tsc_khz = get_tsc_khz();
        memset(tsc_ref, 0, PAGE_SIZE);
        tsc_ref->tsc_sequence = 1;
        tsc_ref->tsc_scale =
            (((10000LL << 32) / viridian.tsc_khz) << 32);
        tsc_ref->tsc_offset = 0;

        debug_printf("TSC scale = %"PRId64"\n", tsc_ref->tsc_scale);

        whpx_ram_unmap(tsc_ref);

        return 0;
    }

    return -1;
}

static int
initialize_vp_assist(CPUState *cpu)
{
    uint64_t gmfn = viridian_vcpu[cpu->cpu_index].vp_assist.msr.fields.pfn;
    uint64_t len = PAGE_SIZE;
    void *p;

    if (!viridian_vcpu[cpu->cpu_index].vp_assist.msr.fields.enabled)
        return 0;

    p = whpx_ram_map(gmfn << PAGE_SHIFT, &len);
    if (p) {
        assert(len == PAGE_SIZE);
        memset(p, 0, PAGE_SIZE);
        viridian_vcpu[cpu->cpu_index].vp_assist.va = p;

        return 0;
    }

    debug_printf("failed to initialize apic assist\n");

    return -1;
}

static void
teardown_vp_assist(CPUState *cpu)
{
    void *va = viridian_vcpu[cpu->cpu_index].vp_assist.va;

    if ( !va )
        return;

    viridian_vcpu[cpu->cpu_index].vp_assist.va = NULL;
    whpx_ram_unmap(va);
}

static void
viridian_synic_deliver_irq(CPUState *cpu, int sint)
{
    struct viridian_synic *ic = &viridian_vcpu[cpu->cpu_index].synic;
    int vec = ic->sint[sint].fields.vector;

    whpx_lock_iothread();
    apic_deliver_irq(WHPX_LAPIC_ID(cpu->cpu_index), 0,
        APIC_DM_FIXED, vec, APIC_TRIGGER_EDGE);
    whpx_unlock_iothread();
}

static void
viridian_synic_update_irq(CPUState *cpu, int sint)
{
    struct viridian_synic *ic = &viridian_vcpu[cpu->cpu_index].synic;

    if ((ic->sint_irr & (1ULL << sint)) &&
        !ic->sint[sint].fields.masked) {
        viridian_synic_deliver_irq(cpu, sint);
        ic->sint_irr &= ~(1ULL << sint);
    }
}

void
viridian_synic_assert_irq(CPUState *cpu, int sint)
{
    if (!vm_viridian)
        return;

    if (sint >= 0 && sint < SINT_COUNT) {
        struct viridian_synic *ic = &viridian_vcpu[cpu->cpu_index].synic;

        ic->sint_irr |= (1ULL << sint);
        viridian_synic_update_irq(cpu, sint);
    }
}

void
viridian_synic_ack_irq(CPUState *cpu, int vec)
{
    struct viridian_synic *ic = &viridian_vcpu[cpu->cpu_index].synic;
    int eoi = 0;
    int sint;

    if (!vm_viridian)
        return;

    for (sint = 0; sint < SINT_COUNT; sint++) {
        if (ic->sint[sint].fields.vector == vec &&
            ic->sint[sint].fields.autoeoi) {
            eoi = 1;
            break;
        }
    }

    if (eoi) {
        whpx_lock_iothread();
        apic_eoi(cpu->apic_state);
        whpx_unlock_iothread();
    }
}

static void
timer_expiry(void *opaque)
{
    struct viridian_timer *timer = opaque;
    int sint = timer->config.SINTx;
    CPUState *cpu = whpx_get_cpu(timer->cpu_index);

    assert(cpu);
    assert(sint);
    viridian_synic_assert_irq(cpu, sint);

    if (timer->config.Periodic) {
        if (timer->config.Enable)
            mod_timer_ns(timer->timer, get_clock_ns(vm_clock) + timer->count * 100);
    } else
        timer->config.Enable = 0;
}

static void
timer_update(
    struct viridian_timer *timer,
    HV_X64_MSR_STIMER_CONFIG_CONTENTS config,
    uint64_t count)
{
    whpx_lock_iothread();

    timer->config = config;
    timer->count  = count;
    if (config.Enable) {
        if (config.Periodic)
            mod_timer_ns(timer->timer, get_clock_ns(vm_clock) + count * 100);
        else
            mod_timer_ns(timer->timer, count * 100);
    } else {
        del_timer(timer->timer);
    }

    whpx_unlock_iothread();
}

static void
wrmsr_timer_count(CPUState *cpu, int timer_idx, uint64_t val)
{
    struct viridian_timer *timer = &viridian_vcpu[cpu->cpu_index].timer[timer_idx];
    HV_X64_MSR_STIMER_CONFIG_CONTENTS config;

    config.AsUINT64 = timer->config.AsUINT64;

    debug_printf("viridian: cpu%d write timer%d count = %"PRIx64"\n", cpu->cpu_index, timer_idx, val);

    if (!val) {
        config.Enable = 0;
    } else {
        if (config.AutoEnable)
            config.Enable = 1;
    }
    timer_update(timer, config, val);
}

static void
wrmsr_timer_config(CPUState *cpu, int timer_idx, uint64_t val)
{
    struct viridian_timer *timer = &viridian_vcpu[cpu->cpu_index].timer[timer_idx];
    HV_X64_MSR_STIMER_CONFIG_CONTENTS v = { .AsUINT64 = val };

    debug_printf("viridian: cpu%d write timer%d config = %"PRIx64
        " en %d periodic %d lazy %d autoen %d vec %x direct %d SINTx %d\n",
        cpu->cpu_index, timer_idx, val,
        v.Enable, v.Periodic, v.Lazy, v.AutoEnable, v.ApicVector, v.DirectMode, v.SINTx);

    if (v.Enable && !v.SINTx)
        v.Enable = 0;

    timer_update(timer, v, timer->count);
}

static uint64_t
rdmsr_timer_count(CPUState *cpu, int timer_idx)
{
    return viridian_vcpu[cpu->cpu_index].timer[timer_idx].count;
}

static uint64_t
rdmsr_timer_config(CPUState *cpu, int timer_idx)
{
    return viridian_vcpu[cpu->cpu_index].timer[timer_idx].config.AsUINT64;
}

static void
wrmsr_synic_regs(CPUState *cpu, struct viridian_synic *ic, uint32_t idx, uint64_t val)
{
    debug_printf("viridian: synic  write %08x = %08"PRIx64"\n", idx, val);
    switch (idx) {
    case HV_X64_MSR_SCONTROL:
        ic->scontrol = val;
        break;
    case HV_X64_MSR_SVERSION:
        break;
    case HV_X64_MSR_SIEFP:
        ic->siefp.raw = val;
        break;
    case HV_X64_MSR_SIMP:
        ic->simp.raw = val;
        break;
    case HV_X64_MSR_EOM:
        break;
    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15: {
        int sint = idx - HV_X64_MSR_SINT0;
        union viridian_sint sint_v = {
            .raw = val
        };

        debug_printf("viridian: sint%02d write vec=0x%02x masked=%d autoeoi=%d polling=%d\n",
            idx - HV_X64_MSR_SINT0, sint_v.fields.vector, sint_v.fields.masked,
            sint_v.fields.autoeoi, sint_v.fields.polling);

        ic->sint[sint] = sint_v;
        viridian_synic_update_irq(cpu, sint);
        break;
    }
    default:
        assert(false);
    }
}

static uint64_t
rdmsr_synic_regs(CPUState *cpu, struct viridian_synic *ic, uint32_t idx)
{
    switch (idx) {
    case HV_X64_MSR_SCONTROL:
        return ic->scontrol;
    case HV_X64_MSR_SVERSION:
        return ic->sversion;
    case HV_X64_MSR_SIEFP:
        return ic->siefp.raw;
    case HV_X64_MSR_SIMP:
        return ic->simp.raw;
    case HV_X64_MSR_EOM:
        return 0;
    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15: {
        int sint = idx - HV_X64_MSR_SINT0;
        return ic->sint[sint].raw;
    }
    default:
        assert(false);
    }

    return 0;
}

int
wrmsr_viridian_regs(uint32_t idx, uint64_t val)
{
    CPUState *cpu = whpx_get_current_cpu();

    if (!vm_viridian)
        return 0;

    switch ( idx )
    {
    case HV_X64_MSR_GUEST_OS_ID:
        viridian.guest_os_id.raw = val;
        dump_guest_os_id();
        break;

    case HV_X64_MSR_HYPERCALL:
        viridian.hypercall_gpa.raw = val;
        dump_hypercall();
        if ( viridian.hypercall_gpa.fields.enabled )
            enable_hypercall_page();
        break;

    case HV_X64_MSR_VP_INDEX:
        break;

    case HV_X64_MSR_EOI:
        whpx_lock_iothread();
        apic_eoi(cpu->apic_state);
        whpx_unlock_iothread();
        break;

    case HV_X64_MSR_ICR: {
        uint32_t eax = (uint32_t)val, edx = (uint32_t)(val >> 32);
        eax &= ~(1 << 12);
        edx &= 0xff000000;
        whpx_lock_iothread();
        apic_set_icr2(cpu->apic_state, edx);
        apic_set_icr(cpu->apic_state, eax);
        whpx_unlock_iothread();
        break;
    }

    case HV_X64_MSR_TPR:
        whpx_lock_iothread();
        apic_set_taskpri(cpu->apic_state, (uint8_t)val);
        whpx_unlock_iothread();
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        teardown_vp_assist(cpu); /* release any previous mapping */
        viridian_vcpu[cpu->cpu_index].vp_assist.msr.raw = val;
        dump_vp_assist(cpu);
        if ( viridian_vcpu[cpu->cpu_index].vp_assist.msr.fields.enabled )
            initialize_vp_assist(cpu);
        break;

    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(HVMPV_feature_mask & HVMPV_reference_tsc) )
            return 0;

        viridian.reference_tsc_msr.raw = val;
        dump_reference_tsc();
        if ( viridian.reference_tsc_msr.fields.enabled )
            enable_reference_tsc_page(cpu, viridian.reference_tsc_msr.fields.pfn);
        break;

    case HV_X64_MSR_STIMER0_CONFIG:
    case HV_X64_MSR_STIMER1_CONFIG:
    case HV_X64_MSR_STIMER2_CONFIG:
    case HV_X64_MSR_STIMER3_CONFIG: {
        int timer = (idx - HV_X64_MSR_STIMER0_CONFIG) / 2;
        wrmsr_timer_config(cpu, timer, val);
        break;
    }
    case HV_X64_MSR_STIMER0_COUNT:
    case HV_X64_MSR_STIMER1_COUNT:
    case HV_X64_MSR_STIMER2_COUNT:
    case HV_X64_MSR_STIMER3_COUNT: {
        int timer = (idx - HV_X64_MSR_STIMER0_COUNT) / 2;
        wrmsr_timer_count(cpu, timer, val);
        break;
    }
    case HV_X64_MSR_SCONTROL ... HV_X64_MSR_SINT15:
        wrmsr_synic_regs(cpu, &viridian_vcpu[cpu->cpu_index].synic, idx,val);
        break;
        //TODO
#if 0
    case HV_X64_MSR_CRASH_P0:
    case HV_X64_MSR_CRASH_P1:
    case HV_X64_MSR_CRASH_P2:
    case HV_X64_MSR_CRASH_P3:
    case HV_X64_MSR_CRASH_P4:
        BUILD_BUG_ON(HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 >=
                     ARRAY_SIZE(v->arch.hvm_vcpu.viridian.crash_param));

        idx -= HV_X64_MSR_CRASH_P0;
        v->arch.hvm_vcpu.viridian.crash_param[idx] = val;
        break;

    case HV_X64_MSR_CRASH_CTL:
    {
        HV_CRASH_CTL_REG_CONTENTS ctl;

        ctl.AsUINT64 = val;

        if ( !ctl.u.CrashNotify )
            break;

        gprintk(XENLOG_WARNING, "VIRIDIAN CRASH: %lx %lx %lx %lx %lx\n",
                v->arch.hvm_vcpu.viridian.crash_param[0],
                v->arch.hvm_vcpu.viridian.crash_param[1],
                v->arch.hvm_vcpu.viridian.crash_param[2],
                v->arch.hvm_vcpu.viridian.crash_param[3],
                v->arch.hvm_vcpu.viridian.crash_param[4]);
        break;
    }
#endif
    default:
        if ( idx >= VIRIDIAN_MSR_MIN && idx <= VIRIDIAN_MSR_MAX )
            debug_printf("write to unimplemented MSR %#x\n",
                    idx);

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
    case HV_X64_MSR_GUEST_OS_ID:
        *val = viridian.guest_os_id.raw;
        break;

    case HV_X64_MSR_HYPERCALL:
        *val = viridian.hypercall_gpa.raw;
        break;

    case HV_X64_MSR_VP_INDEX:
        *val = cpu->cpu_index;
        break;

    case HV_X64_MSR_TSC_FREQUENCY:
        if ( HVMPV_feature_mask & HVMPV_no_freq )
            return 0;

        *val = (uint64_t)get_tsc_khz() * 1000ull;
        break;

    case HV_X64_MSR_APIC_FREQUENCY:
        if ( HVMPV_feature_mask & HVMPV_no_freq )
            return 0;

        *val = 1000000000ull / APIC_BUS_CYCLE_NS;
        break;

    case HV_X64_MSR_ICR:
        whpx_lock_iothread();
        *val = (((uint64_t)apic_get_icr2(cpu->apic_state) << 32) |
            apic_get_icr(cpu->apic_state));
        whpx_unlock_iothread();
        break;

    case HV_X64_MSR_TPR:
        whpx_lock_iothread();
        *val = apic_get_taskpri(cpu->apic_state);
        whpx_unlock_iothread();
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        *val = viridian_vcpu[cpu->cpu_index].vp_assist.msr.raw;
        break;

    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(HVMPV_feature_mask & HVMPV_reference_tsc) )
            return 0;

        *val = viridian.reference_tsc_msr.raw;
        break;

    case HV_X64_MSR_TIME_REF_COUNT:
        if ( !(HVMPV_feature_mask & HVMPV_time_ref_count) )
            return 0;

        *val = get_clock_ns(vm_clock) / 100;
        break;

    case HV_X64_MSR_STIMER0_CONFIG:
    case HV_X64_MSR_STIMER1_CONFIG:
    case HV_X64_MSR_STIMER2_CONFIG:
    case HV_X64_MSR_STIMER3_CONFIG: {
        int timer = (idx - HV_X64_MSR_STIMER0_CONFIG) / 2;
        *val = rdmsr_timer_config(cpu, timer);
        break;
    }
    case HV_X64_MSR_STIMER0_COUNT:
    case HV_X64_MSR_STIMER1_COUNT:
    case HV_X64_MSR_STIMER2_COUNT:
    case HV_X64_MSR_STIMER3_COUNT: {
        int timer = (idx - HV_X64_MSR_STIMER0_COUNT) / 2;
        *val = rdmsr_timer_count(cpu, timer);
        break;
    }
    case HV_X64_MSR_SCONTROL ... HV_X64_MSR_SINT15:
        *val = rdmsr_synic_regs(cpu, &viridian_vcpu[cpu->cpu_index].synic, idx);
        break;
        // TODO
#if 0
    case HV_X64_MSR_CRASH_P0:
    case HV_X64_MSR_CRASH_P1:
    case HV_X64_MSR_CRASH_P2:
    case HV_X64_MSR_CRASH_P3:
    case HV_X64_MSR_CRASH_P4:
        BUILD_BUG_ON(HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 >=
                     ARRAY_SIZE(v->arch.hvm_vcpu.viridian.crash_param));

        idx -= HV_X64_MSR_CRASH_P0;
        *val = v->arch.hvm_vcpu.viridian.crash_param[idx];
        break;

    case HV_X64_MSR_CRASH_CTL:
    {
        HV_CRASH_CTL_REG_CONTENTS ctl = {
            .u.CrashNotify = 1,
        };

        *val = ctl.AsUINT64;
        break;
    }
#endif

    default:
        if ( idx >= VIRIDIAN_MSR_MIN && idx <= VIRIDIAN_MSR_MAX )
            debug_printf("read from unimplemented MSR %#x\n",
                    idx);

        return 0;
    }

    return 1;
}

void
viridian_timers_pause(void)
{
    CPUState *cpu = first_cpu;

    if (!vm_viridian)
        return;

    whpx_lock_iothread();
    while (cpu) {
        struct viridian_vcpu *v = &viridian_vcpu[cpu->cpu_index];
        int i;

        for (i = 0; i < TIMER_COUNT; i++)
            if (v->timer[i].timer)
                del_timer(v->timer[i].timer);
        cpu = cpu->next_cpu;
    }
    whpx_unlock_iothread();
}

void
viridian_timers_resume(void)
{
    CPUState *cpu = first_cpu;

    if (!vm_viridian)
        return;

    whpx_lock_iothread();
    while (cpu) {
        struct viridian_vcpu *v = &viridian_vcpu[cpu->cpu_index];
        int i;

        for (i = 0; i < TIMER_COUNT; i++)
            if (v->timer[i].timer)
                timer_update(&v->timer[i], v->timer[i].config, v->timer[i].count);
        cpu = cpu->next_cpu;
    }
    whpx_unlock_iothread();
}

static void
viridian_save(QEMUFile *f, void *opaque)
{
    CPUState *cpu = first_cpu;
    while (cpu) {
        teardown_vp_assist(cpu);
        cpu = cpu->next_cpu;
    }

    qemu_put_buffer(f, (uint8_t*) &viridian, sizeof(viridian));
    qemu_put_buffer(f, (uint8_t*) viridian_vcpu, sizeof(viridian_vcpu));
}

static int
viridian_load(QEMUFile *f, void *opaque, int version)
{
    int i, j;

    for (i = 0; i < WHPX_MAX_VCPUS; i++) {
        struct viridian_vcpu *v = &viridian_vcpu[i];

        for (j = 0; j < TIMER_COUNT; j++) {
            if (v->timer[j].timer) {
                free_timer(v->timer[j].timer);
                v->timer[j].timer = NULL;
            }
        }
    }

    qemu_get_buffer(f, (uint8_t*) &viridian, sizeof(viridian));
    qemu_get_buffer(f, (uint8_t*) viridian_vcpu, sizeof(viridian_vcpu));

    /* fixup vp assist page va */
    CPUState *cpu = first_cpu;
    while (cpu) {
        initialize_vp_assist(cpu);
        cpu = cpu->next_cpu;
    }

    /* recreate timers */
    for (i = 0; i < WHPX_MAX_VCPUS; i++) {
        struct viridian_vcpu *v = &viridian_vcpu[i];

        for (j = 0; j < TIMER_COUNT; j++)
            v->timer[j].timer = new_timer_ns(vm_clock, timer_expiry, &v->timer[i]);
    }

    viridian_timers_resume();

    return 0;
}

static void
viridian_init_synic(struct viridian_synic *ic)
{
    int i;

    memset(ic, 0, sizeof(*ic));
    ic->sversion = 1;
    for (i = 0; i < SINT_COUNT; i++)
        ic->sint[i].fields.masked = 1;
}

static void
viridian_init_timers(struct viridian_vcpu *v)
{
    int i;

    for (i = 0; i < TIMER_COUNT; i++) {
        memset(&v->timer[i], 0, sizeof(v->timer[i]));
        v->timer[i].cpu_index = v->index;
        v->timer[i].timer_index = i;
        v->timer[i].timer = new_timer_ns(vm_clock, timer_expiry, &v->timer[i]);
    }
}

void
viridian_init(void)
{
    int i;

    register_savevm(NULL, "whpx-viridian", 0, 1, viridian_save, viridian_load, NULL);
    for (i = 0; i < WHPX_MAX_VCPUS; i++) {
        viridian_vcpu[i].index = i;
        viridian_init_synic(&viridian_vcpu[i].synic);
        viridian_init_timers(&viridian_vcpu[i]);
    }
}
