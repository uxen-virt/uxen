/*
 * io.c: Handling I/O and interrupts.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/event.h>
#include <xen/hypercall.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/trace.h>
#include <asm/hvm/emulate.h>
#include <public/sched.h>
#include <xen/iocap.h>
#include <public/hvm/ioreq.h>

int handle_mmio(void)
{
    struct hvm_emulate_ctxt ctxt;
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    hvm_emulate_prepare(&ctxt, guest_cpu_user_regs());

    rc = hvm_emulate_one(&ctxt);

    if ( vio->io_state == HVMIO_awaiting_completion )
        vio->io_state = HVMIO_handle_mmio_awaiting_completion;
    else
        vio->mmio_gva = 0;

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        gdprintk(XENLOG_WARNING,
                 "MMIO emulation failed @ %04x:%lx: "
                 "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                 hvmemul_get_seg_reg(x86_seg_cs, &ctxt)->sel,
                 ctxt.insn_buf_eip,
                 ctxt.insn_buf[0], ctxt.insn_buf[1],
                 ctxt.insn_buf[2], ctxt.insn_buf[3],
                 ctxt.insn_buf[4], ctxt.insn_buf[5],
                 ctxt.insn_buf[6], ctxt.insn_buf[7],
                 ctxt.insn_buf[8], ctxt.insn_buf[9]);
        return 0;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_exception(ctxt.exn_vector, ctxt.exn_error_code, 0);
        break;
    default:
        break;
    }

    hvm_emulate_writeback(&ctxt);

    return 1;
}

int handle_pio(uint16_t port, int size, int dir)
{
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    unsigned long data, reps = 1;
    int rc;

    if ( dir == IOREQ_WRITE )
        data = guest_cpu_user_regs()->eax;

    rc = hvmemul_do_pio(port, &reps, size, 0, dir, 0, &data);

    switch ( rc )
    {
    case X86EMUL_OKAY:
        if ( dir == IOREQ_READ )
            memcpy(&guest_cpu_user_regs()->eax, &data, vio->io_size);
        break;
    case X86EMUL_RETRY:
        if ( vio->io_state != HVMIO_awaiting_completion )
            return 0;
        /* Completion in hvm_io_assist() with no re-emulation required. */
        ASSERT(dir == IOREQ_READ);
        vio->io_state = HVMIO_handle_pio_awaiting_completion;
        break;
    default:
        gdprintk(XENLOG_ERR, "Weird HVM ioemulation status %d.\n", rc);
        domain_crash(curr->domain);
        break;
    }

    return 1;
}

void hvm_io_assist(void)
{
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    ioreq_t *p = get_ioreq(curr);
    ioreq_t *dm_p = get_dm_ioreq(curr);
    enum hvm_io_state io_state;

    rmb(); /* see IORESP_READY /then/ read contents of ioreq */

    if (p->state == STATE_IOREQ_READY) {
        dm_p->state = STATE_IOREQ_NONE;
        p->dir = dm_p->dir;
        p->data_is_ptr = dm_p->data_is_ptr;
        p->type = dm_p->type;
        p->size = dm_p->size;
        p->addr = dm_p->addr;
        p->count = dm_p->count;
        p->df = dm_p->df;
        p->data = dm_p->data;
    }
    p->state = STATE_IOREQ_NONE;

    io_state = vio->io_state;
    vio->io_state = HVMIO_none;

    switch ( io_state )
    {
    case HVMIO_awaiting_completion:
        vio->io_state = HVMIO_completed;
        vio->io_data = p->data;
        break;
    case HVMIO_handle_mmio_awaiting_completion:
        vio->io_state = HVMIO_completed;
        vio->io_data = p->data;
        (void)handle_mmio();
        break;
    case HVMIO_handle_pio_awaiting_completion:
        memcpy(&guest_cpu_user_regs()->eax,
               &p->data, vio->io_size);
        break;
    default:
        break;
    }

    if ( p->state == STATE_IOREQ_NONE )
        vcpu_end_shutdown_deferral(curr);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
