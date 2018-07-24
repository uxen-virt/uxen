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

uint64_t tmsum_setregs;
uint64_t count_setregs;

uint64_t tmsum_getregs;
uint64_t count_getregs;

uint64_t tmsum_runvp;
uint64_t count_runvp;

uint64_t tmsum_xlate;
uint64_t count_xlate;

uint64_t tmsum_lapic_access;
uint64_t count_lapic_access;

uint64_t tmsum_v4v;
uint64_t count_v4v;

uint64_t tmsum_vmexit[256];
uint64_t count_vmexit[256];

uint64_t count_longspin;

/* all meaningful registers */
static const WHV_REGISTER_NAME all_register_names[] = {
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
    WHvX64RegisterRip,
    WHvX64RegisterRflags,
    WHvX64RegisterEs,
    WHvX64RegisterCs,
    WHvX64RegisterSs,
    WHvX64RegisterDs,
    WHvX64RegisterFs,
    WHvX64RegisterGs,
    WHvX64RegisterLdtr,
    WHvX64RegisterTr,
    WHvX64RegisterIdtr,
    WHvX64RegisterGdtr,
    WHvX64RegisterCr0,
    WHvX64RegisterCr2,
    WHvX64RegisterCr3,
    WHvX64RegisterCr4,
    WHvX64RegisterCr8,
    WHvX64RegisterDr0,
    WHvX64RegisterDr1,
    WHvX64RegisterDr2,
    WHvX64RegisterDr3,
    WHvX64RegisterDr6,
    WHvX64RegisterDr7,
    WHvX64RegisterXmm0,
    WHvX64RegisterXmm1,
    WHvX64RegisterXmm2,
    WHvX64RegisterXmm3,
    WHvX64RegisterXmm4,
    WHvX64RegisterXmm5,
    WHvX64RegisterXmm6,
    WHvX64RegisterXmm7,
    WHvX64RegisterXmm8,
    WHvX64RegisterXmm9,
    WHvX64RegisterXmm10,
    WHvX64RegisterXmm11,
    WHvX64RegisterXmm12,
    WHvX64RegisterXmm13,
    WHvX64RegisterXmm14,
    WHvX64RegisterXmm15,
    WHvX64RegisterFpMmx0,
    WHvX64RegisterFpMmx1,
    WHvX64RegisterFpMmx2,
    WHvX64RegisterFpMmx3,
    WHvX64RegisterFpMmx4,
    WHvX64RegisterFpMmx5,
    WHvX64RegisterFpMmx6,
    WHvX64RegisterFpMmx7,
    WHvX64RegisterFpControlStatus,
    WHvX64RegisterXmmControlStatus,
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
    /* mtrr regs don't seem to be accessible (yet?) */
/*    WHvX64RegisterMsrMtrrCap,
    WHvX64RegisterMsrMtrrDefType,
    WHvX64RegisterMsrMtrrPhysBase0,
    WHvX64RegisterMsrMtrrPhysBase1,
    WHvX64RegisterMsrMtrrPhysBase2,
    WHvX64RegisterMsrMtrrPhysBase3,
    WHvX64RegisterMsrMtrrPhysBase4,
    WHvX64RegisterMsrMtrrPhysBase5,
    WHvX64RegisterMsrMtrrPhysBase6,
    WHvX64RegisterMsrMtrrPhysBase7,
    WHvX64RegisterMsrMtrrPhysBase8,
    WHvX64RegisterMsrMtrrPhysBase9,
    WHvX64RegisterMsrMtrrPhysBaseA,
    WHvX64RegisterMsrMtrrPhysBaseB,
    WHvX64RegisterMsrMtrrPhysBaseC,
    WHvX64RegisterMsrMtrrPhysBaseD,
    WHvX64RegisterMsrMtrrPhysBaseE,
    WHvX64RegisterMsrMtrrPhysBaseF,
    WHvX64RegisterMsrMtrrPhysMask0,
    WHvX64RegisterMsrMtrrPhysMask1,
    WHvX64RegisterMsrMtrrPhysMask2,
    WHvX64RegisterMsrMtrrPhysMask3,
    WHvX64RegisterMsrMtrrPhysMask4,
    WHvX64RegisterMsrMtrrPhysMask5,
    WHvX64RegisterMsrMtrrPhysMask6,
    WHvX64RegisterMsrMtrrPhysMask7,
    WHvX64RegisterMsrMtrrPhysMask8,
    WHvX64RegisterMsrMtrrPhysMask9,
    WHvX64RegisterMsrMtrrPhysMaskA,
    WHvX64RegisterMsrMtrrPhysMaskB,
    WHvX64RegisterMsrMtrrPhysMaskC,
    WHvX64RegisterMsrMtrrPhysMaskD,
    WHvX64RegisterMsrMtrrPhysMaskE,
    WHvX64RegisterMsrMtrrPhysMaskF,
    WHvX64RegisterMsrMtrrFix64k00000,
    WHvX64RegisterMsrMtrrFix16k80000,
    WHvX64RegisterMsrMtrrFix16kA0000,
    WHvX64RegisterMsrMtrrFix4kC0000,
    WHvX64RegisterMsrMtrrFix4kC8000,
    WHvX64RegisterMsrMtrrFix4kD0000,
    WHvX64RegisterMsrMtrrFix4kD8000,
    WHvX64RegisterMsrMtrrFix4kE0000,
    WHvX64RegisterMsrMtrrFix4kE8000,
    WHvX64RegisterMsrMtrrFix4kF0000,
    WHvX64RegisterMsrMtrrFix4kF8000, */
    WHvX64RegisterTscAux,
    WHvRegisterPendingInterruption,
    WHvRegisterInterruptState,
    WHvRegisterPendingEvent0,
    WHvRegisterPendingEvent1,
    WHvX64RegisterDeliverabilityNotifications,
};

static whpx_reg_list_t all_registers;

whpx_reg_list_t *
whpx_all_registers(void)
{
    return &all_registers;
}

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
    case 0x0000200D: return "MsrMtrrCap";
    case 0x0000200E: return "MsrMtrrDefType";
    case 0x00002010: return "MsrMtrrPhysBase0";
    case 0x00002011: return "MsrMtrrPhysBase1";
    case 0x00002012: return "MsrMtrrPhysBase2";
    case 0x00002013: return "MsrMtrrPhysBase3";
    case 0x00002014: return "MsrMtrrPhysBase4";
    case 0x00002015: return "MsrMtrrPhysBase5";
    case 0x00002016: return "MsrMtrrPhysBase6";
    case 0x00002017: return "MsrMtrrPhysBase7";
    case 0x00002018: return "MsrMtrrPhysBase8";
    case 0x00002019: return "MsrMtrrPhysBase9";
    case 0x0000201A: return "MsrMtrrPhysBaseA";
    case 0x0000201B: return "MsrMtrrPhysBaseB";
    case 0x0000201C: return "MsrMtrrPhysBaseC";
    case 0x0000201D: return "MsrMtrrPhysBaseD";
    case 0x0000201E: return "MsrMtrrPhysBaseE";
    case 0x0000201F: return "MsrMtrrPhysBaseF";
    case 0x00002040: return "MsrMtrrPhysMask0";
    case 0x00002041: return "MsrMtrrPhysMask1";
    case 0x00002042: return "MsrMtrrPhysMask2";
    case 0x00002043: return "MsrMtrrPhysMask3";
    case 0x00002044: return "MsrMtrrPhysMask4";
    case 0x00002045: return "MsrMtrrPhysMask5";
    case 0x00002046: return "MsrMtrrPhysMask6";
    case 0x00002047: return "MsrMtrrPhysMask7";
    case 0x00002048: return "MsrMtrrPhysMask8";
    case 0x00002049: return "MsrMtrrPhysMask9";
    case 0x0000204A: return "MsrMtrrPhysMaskA";
    case 0x0000204B: return "MsrMtrrPhysMaskB";
    case 0x0000204C: return "MsrMtrrPhysMaskC";
    case 0x0000204D: return "MsrMtrrPhysMaskD";
    case 0x0000204E: return "MsrMtrrPhysMaskE";
    case 0x0000204F: return "MsrMtrrPhysMaskF";
    case 0x00002070: return "MsrMtrrFix64k00000";
    case 0x00002071: return "MsrMtrrFix16k80000";
    case 0x00002072: return "MsrMtrrFix16kA0000";
    case 0x00002073: return "MsrMtrrFix4kC0000";
    case 0x00002074: return "MsrMtrrFix4kC8000";
    case 0x00002075: return "MsrMtrrFix4kD0000";
    case 0x00002076: return "MsrMtrrFix4kD8000";
    case 0x00002077: return "MsrMtrrFix4kE0000";
    case 0x00002078: return "MsrMtrrFix4kE8000";
    case 0x00002079: return "MsrMtrrFix4kF0000";
    case 0x0000207A: return "MsrMtrrFix4kF8000";
    case 0x0000207B: return "TscAux";
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

void
dump_phys_mem(uint64_t paddr, int len)
{
    uint64_t l = len;
    assert(l%4 == 0);
    uint8 *p = whpx_ram_map(paddr, &l);
    uint8_t *porg = p;
    if (p) {
        while (l) {
            debug_printf("@%08"PRIx64" = %02x%02x%02x%02x\n", paddr, p[0], p[1], p[2], p[3]);
            p += 4;
            paddr += 4;
            l -= 4;
        }
        whpx_ram_unmap(porg);
    }
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
    uint64_t t0 = 0;
    if (whpx_perf_stats)
        t0 = _rdtsc();
    HRESULT r = WHvSetVirtualProcessorRegisters(whpx_get_partition(), VpIndex,
        RegisterNames, RegisterCount, RegisterValues);
    if (whpx_perf_stats) {
        tmsum_setregs += _rdtsc() - t0;
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
    uint64_t t0 = 0;
    if (whpx_perf_stats)
        t0 = _rdtsc();
    HRESULT r = WHvGetVirtualProcessorRegisters(whpx_get_partition(), VpIndex,
        RegisterNames, RegisterCount, RegisterValues);
    if (whpx_perf_stats) {
        tmsum_getregs += _rdtsc() - t0;
        count_getregs++;
    }
    return r;
}

void
whpx_reset_perf_stats(void)
{
    count_runvp = count_getregs = count_setregs = count_xlate = count_v4v = 0;
    tmsum_runvp = tmsum_getregs = tmsum_setregs = tmsum_xlate = tmsum_v4v = 0;

    count_lapic_access = 0;
    tmsum_lapic_access = 0;

    count_longspin = 0;

    memset(tmsum_vmexit, 0, sizeof(tmsum_vmexit));
    memset(count_vmexit, 0, sizeof(count_vmexit));
}

uint8_t
whpx_er_byte_encode(int er)
{
    if (er >= 0x2000)
        er = er - 0x2000 + 200;
    else if (er >= 0x1000)
        er = er - 0x1000 + 100;
    assert(er < 256);

    return (uint8_t) er;
}

int
whpx_er_byte_decode(uint8_t exit_reason_byte)
{
    int er = exit_reason_byte;

    if (er >= 200)
        er = er - 200 + 0x2000;
    else if (er >= 100)
        er = er - 100 + 0x1000;

    return er;
}

static
char *whpx_er_describe(int exit_reason)
{
    switch (exit_reason) {
    case WHvRunVpExitReasonNone: return "none";
    case WHvRunVpExitReasonMemoryAccess: return "mmio";
    case WHvRunVpExitReasonX64IoPortAccess: return "portio";
    case WHvRunVpExitReasonUnrecoverableException: return "uexcp";
    case WHvRunVpExitReasonInvalidVpRegisterValue: return "invreg";
    case WHvRunVpExitReasonUnsupportedFeature: return "unsupp";
    case WHvRunVpExitReasonX64InterruptWindow: return "irqwnd";
    case WHvRunVpExitReasonX64Halt: return "halt";
    case WHvRunVpExitReasonX64MsrAccess: return "msr";
    case WHvRunVpExitReasonX64Cpuid: return "cpuid";
    case WHvRunVpExitReasonException: return "excp";
    case WHvRunVpExitReasonCanceled: return "cancel";
    default: return NULL;
    }
}

void
whpx_dump_perf_stats(void)
{
    static int iter = 1;
    debug_printf("/---------------------------------------------------------------------\n");
    debug_printf("|              WHPX performance stats, iteration=%d:\n", iter++);
    debug_printf("|\n");
    debug_printf("| runvp        count %8"PRId64" avg cycles %8"PRId64"\n", count_runvp, count_runvp ? tmsum_runvp/count_runvp : 0);
    debug_printf("| getregs      count %8"PRId64" avg cycles %8"PRId64"\n", count_getregs, count_getregs ? tmsum_getregs/count_getregs : 0);
    debug_printf("| setregs      count %8"PRId64" avg cycles %8"PRId64"\n", count_setregs, count_setregs ? tmsum_setregs/count_setregs : 0);
    debug_printf("| translategva count %8"PRId64" avg cycles %8"PRId64"\n", count_xlate, count_xlate ? tmsum_xlate/count_xlate : 0);
    debug_printf("| v4vop        count %8"PRId64" avg cycles %8"PRId64"\n", count_v4v, count_v4v ? tmsum_v4v/count_v4v : 0);
    debug_printf("| lapic access count %8"PRId64" avg cycles %8"PRId64"\n", count_lapic_access, count_lapic_access ? tmsum_lapic_access/count_lapic_access : 0);
    debug_printf("| viridianspin count %8"PRId64"\n", count_longspin);
    int i;
    for (i = 0; i < 256; i++) {
        if (count_vmexit[i]) {
            int er = whpx_er_byte_decode(i);
            char *desc = whpx_er_describe(er);
            char buf[8] = { 0 };

            if (desc)
                strncpy(buf, desc, sizeof(buf));
            else
                snprintf(buf, sizeof(buf), "0x%x", er);
            debug_printf("| exit[%-6s] count %8"PRId64" avg cycles %8"PRId64"\n",
                buf, count_vmexit[i], tmsum_vmexit[i] / count_vmexit[i]);
        }
    }
    debug_printf("\\---------------------------------------------------------------------\n");
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

    whpx_reg_list_init(&all_registers, all_register_names);
}
