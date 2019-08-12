/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/os.h>
#include <dm/cpu.h>
#include "whpx.h"
#include "WinHvGlue.h"
#include "WinHvPlatform.h"
#include "WinHvEmulation.h"
#include "util.h"

uint64_t tmsum_setregs;
uint64_t count_setregs;

uint64_t tmsum_getregs;
uint64_t count_getregs;

uint64_t tmsum_runvp;
uint64_t count_runvp;

uint64_t tmsum_xlate;
uint64_t count_xlate;

uint64_t count_request_irq;
uint64_t tmsum_request_irq;

uint64_t tmsum_lapic_access;
uint64_t count_lapic_access;

uint64_t tmsum_v4v;
uint64_t count_v4v;

uint64_t tmsum_vmexit[256];
uint64_t count_vmexit[256];

uint64_t count_longspin;

uint64_t count_hpet;

uint64_t count_reftime;

uint64_t count_synthtimer;

uint64_t count_synthic;

bool whpx_has_suspend_time = false;

MapViewOfFile3_t MapViewOfFile3P;
VirtualAlloc2_t VirtualAlloc2P;
NtQuerySystemInformation_t NtQuerySystemInformationP;

/* all meaningful registers which are saved in vcpu context */
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
    WHvX64RegisterXCr0,
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
    //WHvX64RegisterSpecCtrl,
    //WHvX64RegisterPredCmd,
    WHvX64RegisterApicId,
    WHvX64RegisterApicVersion,
    WHvRegisterPendingInterruption,
    WHvRegisterInterruptState,
    //WHvRegisterPendingEvent,
    WHvX64RegisterDeliverabilityNotifications,
    WHvRegisterInternalActivityState,
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
    case WHvX64RegisterRax: return "Rax";
    case WHvX64RegisterRcx: return "Rcx";
    case WHvX64RegisterRdx: return "Rdx";
    case WHvX64RegisterRbx: return "Rbx";
    case WHvX64RegisterRsp: return "Rsp";
    case WHvX64RegisterRbp: return "Rbp";
    case WHvX64RegisterRsi: return "Rsi";
    case WHvX64RegisterRdi: return "Rdi";
    case WHvX64RegisterR8: return "R8";
    case WHvX64RegisterR9: return "R9";
    case WHvX64RegisterR10: return "R10";
    case WHvX64RegisterR11: return "R11";
    case WHvX64RegisterR12: return "R12";
    case WHvX64RegisterR13: return "R13";
    case WHvX64RegisterR14: return "R14";
    case WHvX64RegisterR15: return "R15";
    case WHvX64RegisterRip: return "Rip";
    case WHvX64RegisterRflags: return "Rflags";
    case WHvX64RegisterEs: return "Es";
    case WHvX64RegisterCs: return "Cs";
    case WHvX64RegisterSs: return "Ss";
    case WHvX64RegisterDs: return "Ds";
    case WHvX64RegisterFs: return "Fs";
    case WHvX64RegisterGs: return "Gs";
    case WHvX64RegisterLdtr: return "Ldtr";
    case WHvX64RegisterTr: return "Tr";
    case WHvX64RegisterIdtr: return "Idtr";
    case WHvX64RegisterGdtr: return "Gdtr";
    case WHvX64RegisterCr0: return "Cr0";
    case WHvX64RegisterCr2: return "Cr2";
    case WHvX64RegisterCr3: return "Cr3";
    case WHvX64RegisterCr4: return "Cr4";
    case WHvX64RegisterCr8: return "Cr8";
    case WHvX64RegisterDr0: return "Dr0";
    case WHvX64RegisterDr1: return "Dr1";
    case WHvX64RegisterDr2: return "Dr2";
    case WHvX64RegisterDr3: return "Dr3";
    case WHvX64RegisterDr6: return "Dr6";
    case WHvX64RegisterDr7: return "Dr7";
    case WHvX64RegisterXCr0: return "XCr0";
    case WHvX64RegisterXmm0: return "Xmm0";
    case WHvX64RegisterXmm1: return "Xmm1";
    case WHvX64RegisterXmm2: return "Xmm2";
    case WHvX64RegisterXmm3: return "Xmm3";
    case WHvX64RegisterXmm4: return "Xmm4";
    case WHvX64RegisterXmm5: return "Xmm5";
    case WHvX64RegisterXmm6: return "Xmm6";
    case WHvX64RegisterXmm7: return "Xmm7";
    case WHvX64RegisterXmm8: return "Xmm8";
    case WHvX64RegisterXmm9: return "Xmm9";
    case WHvX64RegisterXmm10: return "Xmm10";
    case WHvX64RegisterXmm11: return "Xmm11";
    case WHvX64RegisterXmm12: return "Xmm12";
    case WHvX64RegisterXmm13: return "Xmm13";
    case WHvX64RegisterXmm14: return "Xmm14";
    case WHvX64RegisterXmm15: return "Xmm15";
    case WHvX64RegisterFpMmx0: return "FpMmx0";
    case WHvX64RegisterFpMmx1: return "FpMmx1";
    case WHvX64RegisterFpMmx2: return "FpMmx2";
    case WHvX64RegisterFpMmx3: return "FpMmx3";
    case WHvX64RegisterFpMmx4: return "FpMmx4";
    case WHvX64RegisterFpMmx5: return "FpMmx5";
    case WHvX64RegisterFpMmx6: return "FpMmx6";
    case WHvX64RegisterFpMmx7: return "FpMmx7";
    case WHvX64RegisterFpControlStatus: return "FpControlStatus";
    case WHvX64RegisterXmmControlStatus: return "XmmControlStatus";
    case WHvX64RegisterTsc: return "Tsc";
    case WHvX64RegisterEfer: return "Efer";
    case WHvX64RegisterKernelGsBase: return "KernelGsBase";
    case WHvX64RegisterApicBase: return "ApicBase";
    case WHvX64RegisterPat: return "Pat";
    case WHvX64RegisterSysenterCs: return "SysenterCs";
    case WHvX64RegisterSysenterEip: return "SysenterEip";
    case WHvX64RegisterSysenterEsp: return "SysenterEsp";
    case WHvX64RegisterStar: return "Star";
    case WHvX64RegisterLstar: return "Lstar";
    case WHvX64RegisterCstar: return "Cstar";
    case WHvX64RegisterSfmask: return "Sfmask";
    case WHvX64RegisterMsrMtrrCap: return "MsrMtrrCap";
    case WHvX64RegisterMsrMtrrDefType: return "MsrMtrrDefType";
    case WHvX64RegisterMsrMtrrPhysBase0: return "MsrMtrrPhysBase0";
    case WHvX64RegisterMsrMtrrPhysBase1: return "MsrMtrrPhysBase1";
    case WHvX64RegisterMsrMtrrPhysBase2: return "MsrMtrrPhysBase2";
    case WHvX64RegisterMsrMtrrPhysBase3: return "MsrMtrrPhysBase3";
    case WHvX64RegisterMsrMtrrPhysBase4: return "MsrMtrrPhysBase4";
    case WHvX64RegisterMsrMtrrPhysBase5: return "MsrMtrrPhysBase5";
    case WHvX64RegisterMsrMtrrPhysBase6: return "MsrMtrrPhysBase6";
    case WHvX64RegisterMsrMtrrPhysBase7: return "MsrMtrrPhysBase7";
    case WHvX64RegisterMsrMtrrPhysBase8: return "MsrMtrrPhysBase8";
    case WHvX64RegisterMsrMtrrPhysBase9: return "MsrMtrrPhysBase9";
    case WHvX64RegisterMsrMtrrPhysBaseA: return "MsrMtrrPhysBaseA";
    case WHvX64RegisterMsrMtrrPhysBaseB: return "MsrMtrrPhysBaseB";
    case WHvX64RegisterMsrMtrrPhysBaseC: return "MsrMtrrPhysBaseC";
    case WHvX64RegisterMsrMtrrPhysBaseD: return "MsrMtrrPhysBaseD";
    case WHvX64RegisterMsrMtrrPhysBaseE: return "MsrMtrrPhysBaseE";
    case WHvX64RegisterMsrMtrrPhysBaseF: return "MsrMtrrPhysBaseF";
    case WHvX64RegisterMsrMtrrPhysMask0: return "MsrMtrrPhysMask0";
    case WHvX64RegisterMsrMtrrPhysMask1: return "MsrMtrrPhysMask1";
    case WHvX64RegisterMsrMtrrPhysMask2: return "MsrMtrrPhysMask2";
    case WHvX64RegisterMsrMtrrPhysMask3: return "MsrMtrrPhysMask3";
    case WHvX64RegisterMsrMtrrPhysMask4: return "MsrMtrrPhysMask4";
    case WHvX64RegisterMsrMtrrPhysMask5: return "MsrMtrrPhysMask5";
    case WHvX64RegisterMsrMtrrPhysMask6: return "MsrMtrrPhysMask6";
    case WHvX64RegisterMsrMtrrPhysMask7: return "MsrMtrrPhysMask7";
    case WHvX64RegisterMsrMtrrPhysMask8: return "MsrMtrrPhysMask8";
    case WHvX64RegisterMsrMtrrPhysMask9: return "MsrMtrrPhysMask9";
    case WHvX64RegisterMsrMtrrPhysMaskA: return "MsrMtrrPhysMaskA";
    case WHvX64RegisterMsrMtrrPhysMaskB: return "MsrMtrrPhysMaskB";
    case WHvX64RegisterMsrMtrrPhysMaskC: return "MsrMtrrPhysMaskC";
    case WHvX64RegisterMsrMtrrPhysMaskD: return "MsrMtrrPhysMaskD";
    case WHvX64RegisterMsrMtrrPhysMaskE: return "MsrMtrrPhysMaskE";
    case WHvX64RegisterMsrMtrrPhysMaskF: return "MsrMtrrPhysMaskF";
    case WHvX64RegisterMsrMtrrFix64k00000: return "MsrMtrrFix64k00000";
    case WHvX64RegisterMsrMtrrFix16k80000: return "MsrMtrrFix16k80000";
    case WHvX64RegisterMsrMtrrFix16kA0000: return "MsrMtrrFix16kA0000";
    case WHvX64RegisterMsrMtrrFix4kC0000: return "MsrMtrrFix4kC0000";
    case WHvX64RegisterMsrMtrrFix4kC8000: return "MsrMtrrFix4kC8000";
    case WHvX64RegisterMsrMtrrFix4kD0000: return "MsrMtrrFix4kD0000";
    case WHvX64RegisterMsrMtrrFix4kD8000: return "MsrMtrrFix4kD8000";
    case WHvX64RegisterMsrMtrrFix4kE0000: return "MsrMtrrFix4kE0000";
    case WHvX64RegisterMsrMtrrFix4kE8000: return "MsrMtrrFix4kE8000";
    case WHvX64RegisterMsrMtrrFix4kF0000: return "MsrMtrrFix4kF0000";
    case WHvX64RegisterMsrMtrrFix4kF8000: return "MsrMtrrFix4kF8000";
    case WHvX64RegisterTscAux: return "TscAux";
    case WHvX64RegisterSpecCtrl: return "SpecCtrl";
    case WHvX64RegisterPredCmd: return "PredCmd";
    case WHvX64RegisterApicId: return "ApicId";
    case WHvX64RegisterApicVersion: return "ApicVersion";
    case WHvRegisterPendingInterruption: return "PendingInterruption";
    case WHvRegisterInterruptState: return "InterruptState";
    case WHvRegisterPendingEvent: return "PendingEvent";
    case WHvX64RegisterDeliverabilityNotifications: return "DeliverabilityNotifications";
    case WHvRegisterInternalActivityState: return "InternalActivityState";
    default: return "Unknown";
    }
}

void get_whv_register_descr(WHV_REGISTER_NAME r, WHV_REGISTER_VALUE v, char *buf, int bufsz)
{
    if ((r >= WHvX64RegisterRax && r <= WHvX64RegisterRflags) ||
        (r >= WHvX64RegisterCr0 && r <= WHvX64RegisterCr8) ||
        (r >= WHvX64RegisterTsc && r <= WHvX64RegisterSfmask) ||
        (r >= WHvRegisterPendingInterruption && r <= WHvX64RegisterDeliverabilityNotifications) ||
        (r == WHvX64RegisterXCr0))
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

    WHvX64RegisterXCr0,

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
    WHvRegisterPendingEvent,
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
    count_request_irq = 0;
    tmsum_request_irq = 0;

    count_lapic_access = 0;
    tmsum_lapic_access = 0;

    count_longspin = 0;
    count_hpet = 0;
    count_reftime = 0;

    count_synthtimer = count_synthic = 0;

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
    case WHvRunVpExitReasonX64ApicEoi: return "apiceoi";
    case WHvRunVpExitReasonX64Halt: return "halt";
    case WHvRunVpExitReasonX64MsrAccess: return "msr";
    case WHvRunVpExitReasonX64Cpuid: return "cpuid";
    case WHvRunVpExitReasonException: return "excp";
    case WHvRunVpExitReasonCanceled: return "cancel";
    default: return NULL;
    }
}

static uint64_t
safediv(uint64_t a, uint64_t b)
{
  return b ? a/b : 0;
}

void
whpx_dump_perf_stats(void)
{
    static int iter = 1;
    debug_printf("/---------------------------------------------------------------------\n");
    debug_printf("|              WHPX performance stats, iteration=%d:\n", iter++);
    debug_printf("|\n");
    debug_printf("| runvp        count %8"PRId64" avg cycles %8"PRId64"\n", count_runvp, safediv(tmsum_runvp, count_runvp));
    debug_printf("| getregs      count %8"PRId64" avg cycles %8"PRId64"\n", count_getregs, safediv(tmsum_getregs, count_getregs));
    debug_printf("| setregs      count %8"PRId64" avg cycles %8"PRId64"\n", count_setregs, safediv(tmsum_setregs, count_setregs));
    debug_printf("| translategva count %8"PRId64" avg cycles %8"PRId64"\n", count_xlate, safediv(tmsum_xlate, count_xlate));
    debug_printf("| reqirq       count %8"PRId64" avg cycles %8"PRId64"\n", count_request_irq, safediv(tmsum_request_irq, count_request_irq));
    debug_printf("| v4vop        count %8"PRId64" avg cycles %8"PRId64"\n", count_v4v, safediv(tmsum_v4v, count_v4v));
    debug_printf("| lapic access count %8"PRId64" avg cycles %8"PRId64"\n", count_lapic_access, safediv(tmsum_lapic_access, count_lapic_access));
    debug_printf("| viridianspin count %8"PRId64"\n", count_longspin);
    debug_printf("| hpet         count %8"PRId64"\n", count_hpet);
    debug_printf("| synthtimer   count %8"PRId64"\n", count_synthtimer);
    debug_printf("| synthic      count %8"PRId64"\n", count_synthic);
    debug_printf("| reftime      count %8"PRId64"\n", count_reftime);

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
            debug_printf("| ext[%-7s] count %8"PRId64" avg cycles %8"PRId64"\n",
                buf, count_vmexit[i], safediv(tmsum_vmexit[i], count_vmexit[i]));
        }
    }
    debug_printf("\\---------------------------------------------------------------------\n");
}

int
get_registry_cpu_mhz(void)
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
DEFINE_WHP_API (WHvGetVirtualProcessorInterruptControllerState);
DEFINE_WHP_API (WHvSetVirtualProcessorInterruptControllerState);
DEFINE_WHP_API (WHvRequestInterrupt);
DEFINE_WHP_API (WHvGetVirtualProcessorXsaveState);
DEFINE_WHP_API (WHvSetVirtualProcessorXsaveState);
DEFINE_WHP_API (WHvQueryGpaRangeDirtyBitmap);
DEFINE_WHP_API (WHvGetPartitionCounters);
DEFINE_WHP_API (WHvGetVirtualProcessorCounters);
DEFINE_WHP_API (WHvSuspendPartitionTime);
DEFINE_WHP_API (WHvResumePartitionTime);

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
    LINK_WHP_API (WHvGetVirtualProcessorInterruptControllerState);
    LINK_WHP_API (WHvSetVirtualProcessorInterruptControllerState);
    LINK_WHP_API (WHvRequestInterrupt);
    LINK_WHP_API (WHvGetVirtualProcessorXsaveState);
    LINK_WHP_API (WHvSetVirtualProcessorXsaveState);
    LINK_WHP_API (WHvQueryGpaRangeDirtyBitmap);
    LINK_WHP_API (WHvGetPartitionCounters);
    LINK_WHP_API (WHvGetVirtualProcessorCounters);

    WHvSuspendPartitionTime = (WhpPtrWHvSuspendPartitionTime)
        GetProcAddress(platform_module, "WHvSuspendPartitionTime");
    WHvResumePartitionTime = (WhpPtrWHvResumePartitionTime)
        GetProcAddress(platform_module, "WHvResumePartitionTime");
    if (WHvSuspendPartitionTime && WHvResumePartitionTime)
        whpx_has_suspend_time = true;

    LINK_EMU_API (WHvEmulatorCreateEmulator);
    LINK_EMU_API (WHvEmulatorDestroyEmulator);
    LINK_EMU_API (WHvEmulatorTryIoEmulation);
    LINK_EMU_API (WHvEmulatorTryMmioEmulation);

    whpx_reg_list_init(&all_registers, all_register_names);

    HMODULE kernel = LoadLibrary("KernelBase.dll");
    if (!kernel)
        whpx_panic("failed to load KernelBase module");

    MapViewOfFile3P = (void*)GetProcAddress(kernel, "MapViewOfFile3");
    assert(MapViewOfFile3P);

    VirtualAlloc2P = (void*)GetProcAddress(kernel, "VirtualAlloc2");
    assert(VirtualAlloc2P);

    HMODULE ntdll = LoadLibrary("ntdll.dll");
    if (!ntdll)
      whpx_panic("failed to load ntdll module");

    NtQuerySystemInformationP = (void*)GetProcAddress(ntdll, "NtQuerySystemInformation");
    assert(NtQuerySystemInformationP);

    debug_printf("whpx time suspend available: %d\n", whpx_has_suspend_time ? 1:0);
}
