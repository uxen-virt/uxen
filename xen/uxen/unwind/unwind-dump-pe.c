/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifdef _WIN32
#define ERR_WINDOWS
#endif
#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "pe.h"
#include "unwind-dump-pe.h"

#define output_n(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#define output(fmt, ...) output_n(fmt "\n", ## __VA_ARGS__)

static const char *
reg_name(int reg)
{
    switch (reg) {
    case 0: return "rax";
    case 1: return "rcx";
    case 2: return "rdx";
    case 3: return "rbx";
    case 4: return "rsp";
    case 5: return "rbp";
    case 6: return "rsi";
    case 7: return "rdi";
    case 8: return "r8";
    case 9: return "r9";
    case 10: return "r10";
    case 11: return "r11";
    case 12: return "r12";
    case 13: return "r13";
    case 14: return "r14";
    case 15: return "r15";
    default: errx(1, "invalid register");
    }
}

static const char *
op_name(int op)
{
    switch (op) {
    case UWOP_PUSH_NONVOL: return "UWOP_PUSH_NONVOL";
    case UWOP_ALLOC_LARGE: return "UWOP_ALLOC_LARGE";
    case UWOP_ALLOC_SMALL: return "UWOP_ALLOC_SMALL";
    case UWOP_SET_FPREG: return "UWOP_SET_FPREG";
    case UWOP_SAVE_NONVOL: return "UWOP_SAVE_NONVOL";
    case UWOP_SAVE_NONVOL_FAR: return "UWOP_SAVE_NONVOL_FAR";
    case UWOP_SAVE_XMM128: return "UWOP_SAVE_XMM128";
    case UWOP_SAVE_XMM128_FAR: return "UWOP_SAVE_XMM128_FAR";
    case UWOP_PUSH_MACHFRAME: return "UWOP_PUSH_MACHFRAME";
    default: errx(1, "invalid unwind code");
    }
}

static void
dump_unwind_xdata(struct _UNWIND_INFO *ui, int max)
{
    UNWIND_CODE *code;
    int c, count;

    if (ui->Flags & UNW_FLAG_CHAININFO)
        output("XXX fixme chainifo");
    output("  version %x, flags %x, prolog %x, codes %x", ui->Version,
           ui->Flags, ui->SizeOfProlog, ui->CountOfCodes);
    if (ui->FrameRegister)
        output("  frame reg %d (%s), frame offs %xh", ui->FrameRegister,
               reg_name(ui->FrameRegister), ui->FrameOffset * 16);
    if (ui->CountOfCodes > max)
        errx(1, "_UNWIND_INFO codes extend past end: %x > %x",
             ui->CountOfCodes, max);

    for (c = 0; c < ui->CountOfCodes; c++) {
        code = &ui->UnwindCode[c];
        output_n("  %02x: offs %x, unwind op %x, op info %x     %s%s",
                 c, code->CodeOffset, code->UnwindOp, code->OpInfo,
                 code->CodeOffset < 0x10 ? " " : "",
                 op_name(code->UnwindOp));
        switch(code->UnwindOp) {
        default: errx(1, "invalid unwind code");
        case UWOP_PUSH_NONVOL:
            output(" reg: %s.", reg_name(code->OpInfo));
            break;
        case UWOP_ALLOC_LARGE:
            c++;
            if (c >= ui->CountOfCodes)
                errx(1, "missing second code for UWOP_ALLOC_LARGE");
            if (code->OpInfo) {
                if (c + 1 >= ui->CountOfCodes)
                    errx(1, "missing third code for UWOP_ALLOC_LARGE");
                count = *(DWORD *)&ui->UnwindCode[c];
                c++;
            } else
                count = ui->UnwindCode[c].FrameOffset * sizeof(uint64_t);
            output(" FrameOffset: %x.", count);
            break;
        case UWOP_ALLOC_SMALL:
            count = (code->OpInfo + 1) * sizeof(uint64_t);
            output(" FrameOffset: %x.", count);
            break;
        case UWOP_SET_FPREG:
            output(".");
            break;
        case UWOP_SAVE_NONVOL:
        case UWOP_SAVE_NONVOL_FAR:
        case UWOP_SAVE_XMM:
        case UWOP_SAVE_XMM_FAR:
        case UWOP_SAVE_XMM128:
        case UWOP_SAVE_XMM128_FAR:
        case UWOP_PUSH_MACHFRAME:
            output(" XXX fixme");
            break;
        }
    }
    output("");
}

void
dump_unwind(uint8_t *xdata, long int size_xdata,
            uint8_t *pdata, long int size_pdata)
{
    int i;
    struct _RUNTIME_FUNCTION *rf;

    for (i = 0; i < size_pdata / sizeof(struct _RUNTIME_FUNCTION); i++) {
        rf = &((struct _RUNTIME_FUNCTION *)pdata)[i];
        if (!rf->BeginAddress && !rf->EndAddress && !rf->UnwindData)
            continue;
        output("begin %08lx end %08lx unwind %08lx", rf->BeginAddress,
               rf->EndAddress, rf->UnwindData);
        if (rf->UnwindData + sizeof(struct _UNWIND_INFO) >= size_xdata)
            errx(1, "UnwindData out of bounds: %"PRIx64" >= %lx",
                 rf->UnwindData + sizeof(struct _UNWIND_INFO), size_xdata);
        dump_unwind_xdata((struct _UNWIND_INFO *)&xdata[rf->UnwindData],
                          (size_xdata -
                           (rf->UnwindData + sizeof(struct _UNWIND_INFO))) /
                          sizeof(UNWIND_CODE));
    }
}
