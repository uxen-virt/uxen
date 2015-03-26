/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/types.h>
#include <xen/kernel.h>

#include <uxen/uxen.h>

#include "pe.h"
#include "unwind-pe.h"

#define xdata_start _uxen_info.ui_xdata_start
#define xdata_end _uxen_info.ui_xdata_end
#define pdata_start _uxen_info.ui_pdata_start
#define pdata_end _uxen_info.ui_pdata_end

static uint64_t
get_reg(int reg, struct cpu_user_regs *regs)
{
    switch (reg) {
    case 0: return regs->rax;
    case 1: return regs->rcx;
    case 2: return regs->rdx;
    case 3: return regs->rbx;
    case 4: return regs->rsp;
    case 5: return regs->rbp;
    case 6: return regs->rsi;
    case 7: return regs->rdi;
    case 8: return regs->r8;
    case 9: return regs->r9;
    case 10: return regs->r10;
    case 11: return regs->r11;
    case 12: return regs->r12;
    case 13: return regs->r13;
    case 14: return regs->r14;
    case 15: return regs->r15;
    default: return 0;
    }
}

static void
set_reg(int reg, uint64_t val, struct cpu_user_regs *regs)
{
    switch (reg) {
    case 0: regs->rax = val; return;
    case 1: regs->rcx = val; return;
    case 2: regs->rdx = val; return;
    case 3: regs->rbx = val; return;
    case 4: regs->rsp = val; return;
    case 5: regs->rbp = val; return;
    case 6: regs->rsi = val; return;
    case 7: regs->rdi = val; return;
    case 8: regs->r8 = val; return;
    case 9: regs->r9 = val; return;
    case 10: regs->r10 = val; return;
    case 11: regs->r11 = val; return;
    case 12: regs->r12 = val; return;
    case 13: regs->r13 = val; return;
    case 14: regs->r14 = val; return;
    case 15: regs->r15 = val; return;
    default: return;
    }
}

static int
unwind_pe_epilog(uintptr_t *_eip, uintptr_t *_esp, uintptr_t end,
                 struct cpu_user_regs *regs, int fp_reg)
{
    uintptr_t eip = *_eip;
    uintptr_t esp = *_esp;
    uint64_t code;

    code = *(uint64_t *)eip;
    if ((code & 0xffffff) == 0xc48348) { /* add $0xXX, %rsp */
        esp += (int8_t)(code >> 24);
        eip += 4;
    } else if ((code & 0xffffff) == 0xc48148) { /* add $0xXXXXXXXX, %rsp */
        esp += (int32_t)(code >> 24);
        eip += 7;
    } else if (fp_reg &&
               (code & 0x3fffff) == (0x208d48 | ((fp_reg & 0x7) << 16) |
                                     (fp_reg >> 3))) {
        /* lea XX(%rfp_reg), %rsp */
        esp = get_reg(fp_reg, regs);
        switch ((code >> 22) & 0x3) {
        case 0:
            /* lea (%rfp_reg), %rsp */
            eip += 3;
            break;
        case 1:
            /* lea 0xXX(%rfp_reg), %rsp */
            esp += (int8_t)(code >> 24);
            eip += 4;
            break;
        case 2:
            /* lea 0xXXXXXXXX(%rfp_reg), %rsp */
            esp += (int32_t)(code >> 24);
            eip += 7;
            break;
        }
    }

    while (eip < end) {
        code = *(uint64_t *)eip;

        if ((code & 0xf8) == 0x58) { /* pop %rXX [0..7] */
            set_reg(code & 0x7, *(uint64_t *)esp, regs);
            esp += sizeof(uint64_t);
            eip++;
            continue;
        } else if ((code & 0xf8fb) == 0x5841) { /* pop %rXX [8..15]*/
            set_reg((code & 0x7) + 8, *(uint64_t *)esp, regs);
            esp += sizeof(uint64_t);
            eip += 2;
            continue;
        } else if ((code & 0xf7) == 0xc3) { /* ret */
            break;
        }

        return 1;
    }

    *_eip = *(uintptr_t *)esp;
    *_esp = esp + sizeof(uint64_t);
    return 0;
}

int
unwind_pe(uintptr_t *_eip, uintptr_t *_esp, struct cpu_user_regs *regs,
          int check_epilog)
{
    struct _RUNTIME_FUNCTION *rf;
    struct _UNWIND_INFO *ui;
    uintptr_t eip = *_eip;
    uintptr_t esp = *_esp;
    uintptr_t offset;
    int c, adjust, apply_adjust;

    if (!pdata_start || !pdata_end || !xdata_start || !xdata_end) {
        printk(XENLOG_ERR "%s: [xp]data missing\n", __FUNCTION__);
        return -EINVAL;
    }

    if (!is_kernel_text(eip)) {
        /* printk("%s: eip %p not in text segment\n", __FUNCTION__, _p(eip)); */
        return -ENOENT;
    }

    offset = kernel_text_offset(eip);

    rf = (struct _RUNTIME_FUNCTION *)pdata_start;
    while (rf < (struct _RUNTIME_FUNCTION *)pdata_end) {
        if (rf->BeginAddress <= offset && rf->EndAddress > offset)
            break;
        rf++;
    }
    if (rf >= (struct _RUNTIME_FUNCTION *)pdata_end) {
        /* printk("%s: eip %p not found -- leaf function\n", __FUNCTION__, */
        /*        _p(eip)); */
        goto out;
    }

    offset -= rf->BeginAddress;

    ui = (struct _UNWIND_INFO *)(xdata_start + rf->UnwindData);
    if (&ui[1] > (struct _UNWIND_INFO *)xdata_end ||
        &ui->UnwindCode[ui->CountOfCodes] > (UNWIND_CODE *)xdata_end) {
        printk(XENLOG_ERR "%s: unwind data out of bounds\n", __FUNCTION__);
        return -EINVAL;
    }

    if (offset > ui->SizeOfProlog && check_epilog &&
        !unwind_pe_epilog(_eip, _esp, eip - offset + rf->EndAddress,
                          regs, ui->FrameRegister))
        return 0;

    for (c = 0; c < ui->CountOfCodes; c++) {
        adjust = 0;
        apply_adjust = (offset >= ui->UnwindCode[c].CodeOffset);
        switch (ui->UnwindCode[c].UnwindOp) {
        case UWOP_PUSH_NONVOL:
            set_reg(ui->UnwindCode[c].OpInfo, *(uint64_t *)esp, regs);
            adjust = sizeof(uint64_t);
            break;
        case UWOP_ALLOC_LARGE:
            c++;
            if (c >= ui->CountOfCodes) {
                printk(XENLOG_ERR "%s: unwind data out of bounds\n",
                       __FUNCTION__);
                return -EINVAL;
            }
            if (ui->UnwindCode[c].OpInfo) {
                if (c + 1 >= ui->CountOfCodes) {
                    printk(XENLOG_ERR "%s: unwind data out of bounds\n",
                           __FUNCTION__);
                    return -EINVAL;
                }
                adjust = *(DWORD *)&ui->UnwindCode[c];
                c++;
            } else
                adjust = ui->UnwindCode[c].FrameOffset * sizeof(uint64_t);
            break;
        case UWOP_ALLOC_SMALL:
            adjust = (ui->UnwindCode[c].OpInfo + 1) * sizeof(uint64_t);
            break;
        case UWOP_SET_FPREG:
            esp = get_reg(ui->FrameRegister, regs) - ui->FrameOffset * 16;
            break;
        case UWOP_SAVE_NONVOL:
            if (c + 1 >= ui->CountOfCodes) {
                printk(XENLOG_ERR "%s: unwind data out of bounds\n",
                       __FUNCTION__);
                return -EINVAL;
            }
            /* XXX untested */
            set_reg(ui->UnwindCode[c].OpInfo,
                    ((uint64_t *)esp)[ui->UnwindCode[c + 1].FrameOffset], regs);
            c++;
            break;
        case UWOP_SAVE_NONVOL_FAR:
            if (c + 2 >= ui->CountOfCodes) {
                printk(XENLOG_ERR "%s: unwind data out of bounds\n",
                       __FUNCTION__);
                return -EINVAL;
            }
            /* XXX untested */
            set_reg(ui->UnwindCode[c].OpInfo,
                    *(uint64_t *)(esp + ui->UnwindCode[c + 1].FrameOffset +
                                  (ui->UnwindCode[c + 2].FrameOffset << 16)),
                    regs);
            c++; c++;
            break;
        case UWOP_SAVE_XMM:
        case UWOP_SAVE_XMM128:
            c++;
            break;
        case UWOP_SAVE_XMM_FAR:
        case UWOP_SAVE_XMM128_FAR:
            c++; c++;
            break;
        case UWOP_PUSH_MACHFRAME:
            break;
        default:
            printk(XENLOG_ERR "%s: unknown unwind opcode %x in %x\n",
                   __FUNCTION__, ui->UnwindCode[c].UnwindOp, rf->UnwindData);
            return -EINVAL;
        }
        if (apply_adjust)
            esp += adjust;
    }

  out:
    *_eip = *(uintptr_t *)esp;
    *_esp = esp + sizeof(uint64_t);

    return 0;
}
