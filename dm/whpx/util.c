/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/os.h>
#include <dm/cpu.h>
#include "whpx.h"
#include "winhvglue.h"
#include "winhvplatform.h"
#include "winhvemulation.h"
#include "util.h"

uint64_t tsum_setregs;
uint64_t count_setregs;

uint64_t tsum_getregs;
uint64_t count_getregs;

uint64_t tsum_runvp;
uint64_t count_runvp;

uint64_t tsum_xlate;
uint64_t count_xlate;


const char *get_whv_register_name_str(WHV_REGISTER_NAME x)
{
    switch (x) {
    case 0x00000000: return "Rax";
    case 0x00000001: return "Rcx";
    case 0x00000002: return "Rdx";
    case 0x00000003: return "Rbx";
    case 0x00000004: return "Rsp";
    case 0x00000005: return "Rbp";
    case 0x00000006: return "Rsi";
    case 0x00000007: return "Rdi";
    case 0x00000008: return "R8";
    case 0x00000009: return "R9";
    case 0x0000000A: return "R10";
    case 0x0000000B: return "R11";
    case 0x0000000C: return "R12";
    case 0x0000000D: return "R13";
    case 0x0000000E: return "R14";
    case 0x0000000F: return "R15";
    case 0x00000010: return "Rip";
    case 0x00000011: return "Rflags";
    case 0x00000012: return "Es";
    case 0x00000013: return "Cs";
    case 0x00000014: return "Ss";
    case 0x00000015: return "Ds";
    case 0x00000016: return "Fs";
    case 0x00000017: return "Gs";
    case 0x00000018: return "Ldtr";
    case 0x00000019: return "Tr";
    case 0x0000001A: return "Idtr";
    case 0x0000001B: return "Gdtr";
    case 0x0000001C: return "Cr0";
    case 0x0000001D: return "Cr2";
    case 0x0000001E: return "Cr3";
    case 0x0000001F: return "Cr4";
    case 0x00000020: return "Cr8";
    case 0x00000021: return "Dr0";
    case 0x00000022: return "Dr1";
    case 0x00000023: return "Dr2";
    case 0x00000024: return "Dr3";
    case 0x00000025: return "Dr6";
    case 0x00000026: return "Dr7";
    case 0x00001000: return "Xmm0";
    case 0x00001001: return "Xmm1";
    case 0x00001002: return "Xmm2";
    case 0x00001003: return "Xmm3";
    case 0x00001004: return "Xmm4";
    case 0x00001005: return "Xmm5";
    case 0x00001006: return "Xmm6";
    case 0x00001007: return "Xmm7";
    case 0x00001008: return "Xmm8";
    case 0x00001009: return "Xmm9";
    case 0x0000100A: return "Xmm10";
    case 0x0000100B: return "Xmm11";
    case 0x0000100C: return "Xmm12";
    case 0x0000100D: return "Xmm13";
    case 0x0000100E: return "Xmm14";
    case 0x0000100F: return "Xmm15";
    case 0x00001010: return "FpMmx0";
    case 0x00001011: return "FpMmx1";
    case 0x00001012: return "FpMmx2";
    case 0x00001013: return "FpMmx3";
    case 0x00001014: return "FpMmx4";
    case 0x00001015: return "FpMmx5";
    case 0x00001016: return "FpMmx6";
    case 0x00001017: return "FpMmx7";
    case 0x00001018: return "FpControlStatus";
    case 0x00001019: return "XmmControlStatus";
    case 0x00002000: return "Tsc";
    case 0x00002001: return "Efer";
    case 0x00002002: return "KernelGsBase";
    case 0x00002003: return "ApicBase";
    case 0x00002004: return "Pat";
    case 0x00002005: return "SysenterCs";
    case 0x00002006: return "SysenterEip";
    case 0x00002007: return "SysenterEsp";
    case 0x00002008: return "Star";
    case 0x00002009: return "Lstar";
    case 0x0000200A: return "Cstar";
    case 0x0000200B: return "Sfmask";
    case 0x80000000: return "PendingInterruption";
    case 0x80000001: return "InterruptState";
    case 0x80000002: return "PendingEvent0";
    case 0x80000003: return "PendingEvent1";
    case 0x80000004: return "DeliverabilityNotifications";
    default: return "Unknown";
    }
}

void get_whv_register_descr(WHV_REGISTER_NAME r, WHV_REGISTER_VALUE v, char *buf, int bufsz)
{
    if ((r >= WHvX64RegisterRax && r <= WHvX64RegisterRflags) ||
        (r >= WHvX64RegisterCr0 && r <= WHvX64RegisterCr8) ||
        (r >= WHvX64RegisterTsc && r <= WHvX64RegisterSfmask) ||
        (r >= WHvRegisterPendingInterruption && r <= WHvX64RegisterDeliverabilityNotifications))
    {
        snprintf(buf, bufsz, "%s: %"PRIx64, get_whv_register_name_str(r), v.Reg64);
    } else if (r >= WHvX64RegisterEs && r <= WHvX64RegisterTr) {
        snprintf(buf, bufsz, "%s: base=%"PRIx64" limit=%x sel=%x attr=%x",
            get_whv_register_name_str(r),
            v.Segment.Base, v.Segment.Limit, v.Segment.Selector, v.Segment.Attributes);
    } else if (r >= WHvX64RegisterIdtr && r <= WHvX64RegisterGdtr) {
        snprintf(buf, bufsz, "%s: base=%"PRIx64" limit=%x",
            get_whv_register_name_str(r),
            v.Table.Base, v.Table.Limit);
    } else {
        snprintf(buf, bufsz, "%s: ????",
            get_whv_register_name_str(r));
    }
}

void dump_whv_register_list(WHV_REGISTER_NAME *r, WHV_REGISTER_VALUE *v, int count)
{
    char buf[256] = { };
    int i;

    for (i = 0; i < count; i++) {
        get_whv_register_descr(r[i], v[i], buf, sizeof(buf));
        debug_printf("%s = %s\n", get_whv_register_name_str(r[i]), buf);
    }
}

static const WHV_REGISTER_NAME dump_regs[] = {

    /* X64 General purpose registers */
    WHvX64RegisterRip,
    WHvX64RegisterRflags,

    WHvX64RegisterRax,
    WHvX64RegisterRcx,
    WHvX64RegisterRdx,
    WHvX64RegisterRbx,
    WHvX64RegisterRsp,
    WHvX64RegisterRbp,
    WHvX64RegisterRsi,
    WHvX64RegisterRdi,
    WHvX64RegisterR8,
    WHvX64RegisterR9,
    WHvX64RegisterR10,
    WHvX64RegisterR11,
    WHvX64RegisterR12,
    WHvX64RegisterR13,
    WHvX64RegisterR14,
    WHvX64RegisterR15,

    /* X64 Segment registers */
    WHvX64RegisterEs,
    WHvX64RegisterCs,
    WHvX64RegisterSs,
    WHvX64RegisterDs,
    WHvX64RegisterFs,
    WHvX64RegisterGs,
    WHvX64RegisterLdtr,
    WHvX64RegisterTr,

    /* X64 Table registers */
    WHvX64RegisterIdtr,
    WHvX64RegisterGdtr,

    /* X64 Control Registers */
    WHvX64RegisterCr0,
    WHvX64RegisterCr2,
    WHvX64RegisterCr3,
    WHvX64RegisterCr4,
    WHvX64RegisterCr8,

    /* X64 MSRs */
    WHvX64RegisterTsc,
    WHvX64RegisterEfer,
    WHvX64RegisterKernelGsBase,
    WHvX64RegisterApicBase,
    WHvX64RegisterPat,
    WHvX64RegisterSysenterCs,
    WHvX64RegisterSysenterEip,
    WHvX64RegisterSysenterEsp,
    WHvX64RegisterStar,
    WHvX64RegisterLstar,
    WHvX64RegisterCstar,
    WHvX64RegisterSfmask,

    /* Interrupt / Event Registers */
    WHvRegisterPendingInterruption,
    WHvRegisterInterruptState,
    WHvRegisterPendingEvent0,
    WHvRegisterPendingEvent1,
    WHvX64RegisterDeliverabilityNotifications,
};

void whpx_dump_cpu_state(int cpu_index)
{
    HRESULT hr;
    WHV_REGISTER_VALUE reg_values[RTL_NUMBER_OF(dump_regs)];
    int i;

    hr = WHvGetVirtualProcessorRegisters(whpx_get_partition(), cpu_index,
        dump_regs, RTL_NUMBER_OF(dump_regs), reg_values);
    if (FAILED(hr))
        whpx_panic("WHPX: Failed to get interrupt state registers,"
                     " hr=%08lx", hr);

    debug_printf("VCPU[%d] STATE:\n", cpu_index);
    for (i = 0; i < RTL_NUMBER_OF(dump_regs); i++) {
        char buf[256];
        get_whv_register_descr(dump_regs[i], reg_values[i], buf, sizeof(buf));
        debug_printf("%s ", buf);
        if (i && (i%8 == 0))
            debug_printf("\n");
    }
    debug_printf("\n");
}

WHV_X64_SEGMENT_REGISTER whpx_seg_q2h(const SegmentCache *qs)
{
    WHV_X64_SEGMENT_REGISTER hs;
    unsigned flags = qs->flags;

    hs.Base = qs->base;
    hs.Limit = qs->limit;
    hs.Selector = qs->selector;
    hs.Attributes = (flags >> DESC_TYPE_SHIFT);

    return hs;
}

SegmentCache whpx_seg_h2q(const WHV_X64_SEGMENT_REGISTER *hs)
{
    SegmentCache qs;

    qs.base = hs->Base;
    qs.limit = hs->Limit;
    qs.selector = hs->Selector;

    qs.flags = ((uint32_t)hs->Attributes) << DESC_TYPE_SHIFT;

    return qs;
}

HRESULT whpx_set_vp_registers(
    UINT32 VpIndex,
    const WHV_REGISTER_NAME *RegisterNames,
    UINT32 RegisterCount,
    const WHV_REGISTER_VALUE *RegisterValues
)
{
    uint64_t t0;
    if (PERF_TEST)
        t0 = _rdtsc();
    HRESULT r = WHvSetVirtualProcessorRegisters(whpx_get_partition(), VpIndex,
        RegisterNames, RegisterCount, RegisterValues);
    if (PERF_TEST) {
        tsum_setregs += _rdtsc() - t0;
        count_setregs++;
    }

    return r;
}

HRESULT whpx_get_vp_registers(
    UINT32 VpIndex,
    const WHV_REGISTER_NAME *RegisterNames,
    UINT32 RegisterCount,
    WHV_REGISTER_VALUE *RegisterValues
)
{
    uint64_t t0;
    if (PERF_TEST)
        t0 = _rdtsc();
    HRESULT r = WHvGetVirtualProcessorRegisters(whpx_get_partition(), VpIndex,
        RegisterNames, RegisterCount, RegisterValues);
    if (PERF_TEST) {
        tsum_getregs += _rdtsc() - t0;
        count_getregs++;
    }
    return r;
}

void
whpx_perf_stats(void)
{
    debug_printf("PERF STATS:\n");
    debug_printf("runvp count %"PRId64" avg cycles %"PRId64"\n", count_runvp, count_runvp ? tsum_runvp/count_runvp : 0);
    debug_printf("getregs count %"PRId64" avg cycles %"PRId64"\n", count_getregs, count_getregs ? tsum_getregs/count_getregs : 0);
    debug_printf("setregs count %"PRId64" avg cycles %"PRId64"\n", count_setregs, count_setregs ? tsum_setregs/count_setregs : 0);
    debug_printf("xlate count %"PRId64" avg cycles %"PRId64"\n", count_xlate, count_xlate ? tsum_xlate/count_xlate : 0);

    count_runvp = count_getregs = count_setregs = count_xlate = 0;
    tsum_runvp = tsum_getregs = tsum_setregs = tsum_xlate = 0;
}

int
get_cpu_mhz(void)
{
    DWORD dwMHz;
    HKEY hKey;
    DWORD BufSize = sizeof(DWORD);

    long err = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                               "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                               0,
                               KEY_READ,
                               &hKey);
    if (err != ERROR_SUCCESS)
        return 0;

    RegQueryValueEx(hKey, "~MHz", NULL, NULL, (LPBYTE) &dwMHz, &BufSize);
    RegCloseKey(hKey);

    return (int)dwMHz;
}

// ----------- API INITIALIZATION ---------
#define DEFINE_WHP_API(name) WhpPtr##name name

#define LINK_WHP_API(name)                                              \
    name = (WhpPtr##name)GetProcAddress(platform_module, #name);        \
    if (!name) \
        whpx_panic("failed to link function %s\n", #name);

#define LINK_EMU_API(name)                                              \
    name = (WhpPtr##name)GetProcAddress(emulator_module, #name);        \
    if (!name) \
        whpx_panic("failed to link function %s\n", #name);

DEFINE_WHP_API (WHvGetCapability);
DEFINE_WHP_API (WHvCreatePartition);
DEFINE_WHP_API (WHvSetupPartition);
DEFINE_WHP_API (WHvDeletePartition);
DEFINE_WHP_API (WHvGetPartitionProperty);
DEFINE_WHP_API (WHvSetPartitionProperty);
DEFINE_WHP_API (WHvMapGpaRange);
DEFINE_WHP_API (WHvUnmapGpaRange);
DEFINE_WHP_API (WHvTranslateGva);
DEFINE_WHP_API (WHvCreateVirtualProcessor);
DEFINE_WHP_API (WHvDeleteVirtualProcessor);
DEFINE_WHP_API (WHvRunVirtualProcessor);
DEFINE_WHP_API (WHvCancelRunVirtualProcessor);
DEFINE_WHP_API (WHvGetVirtualProcessorRegisters);
DEFINE_WHP_API (WHvSetVirtualProcessorRegisters);

DEFINE_WHP_API (WHvEmulatorCreateEmulator);
DEFINE_WHP_API (WHvEmulatorDestroyEmulator);
DEFINE_WHP_API (WHvEmulatorTryIoEmulation);
DEFINE_WHP_API (WHvEmulatorTryMmioEmulation);

void
whpx_initialize_api(void)
{
    HMODULE platform_module, emulator_module;

    if (WHvRunVirtualProcessor != NULL)
        return;

    platform_module = LoadLibrary("winhvplatform.dll");
    if (!platform_module)
        whpx_panic("failed to load whp platform module\n");
    emulator_module = LoadLibrary("winhvemulation.dll");
    if (!emulator_module)
        whpx_panic("failed to load whp emulator module\n");

    LINK_WHP_API (WHvGetCapability);
    LINK_WHP_API (WHvCreatePartition);
    LINK_WHP_API (WHvSetupPartition);
    LINK_WHP_API (WHvDeletePartition);
    LINK_WHP_API (WHvGetPartitionProperty);
    LINK_WHP_API (WHvSetPartitionProperty);
    LINK_WHP_API (WHvMapGpaRange);
    LINK_WHP_API (WHvUnmapGpaRange);
    LINK_WHP_API (WHvTranslateGva);
    LINK_WHP_API (WHvCreateVirtualProcessor);
    LINK_WHP_API (WHvDeleteVirtualProcessor);
    LINK_WHP_API (WHvRunVirtualProcessor);
    LINK_WHP_API (WHvCancelRunVirtualProcessor);
    LINK_WHP_API (WHvGetVirtualProcessorRegisters);
    LINK_WHP_API (WHvSetVirtualProcessorRegisters);

    LINK_EMU_API (WHvEmulatorCreateEmulator);
    LINK_EMU_API (WHvEmulatorDestroyEmulator);
    LINK_EMU_API (WHvEmulatorTryIoEmulation);
    LINK_EMU_API (WHvEmulatorTryMmioEmulation);
}
