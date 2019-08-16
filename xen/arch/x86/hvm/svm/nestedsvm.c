/*
 * nestedsvm.c: Nested Virtualization
 * Copyright (c) 2011, Advanced Micro Devices, Inc
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
 *
 */

#include <asm/hvm/support.h>
#include <asm/hvm/svm/emulate.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/nestedsvm.h>
#include <asm/hvm/svm/svmdebug.h>
#include <asm/paging.h> /* paging_mode_hap */
#include <asm/event.h> /* for local_event_delivery_(en|dis)able */
#include <asm/p2m.h> /* p2m_get_pagetable, p2m_get_nestedp2m */


void svm_vmexit_do_stgi(struct cpu_user_regs *regs, struct vcpu *v)
{

    if ( !nestedhvm_enabled(v->domain) ) {
        hvm_inject_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE, 0);
        return;
    }

    BUG();
}

void svm_vmexit_do_clgi(struct cpu_user_regs *regs, struct vcpu *v)
{

    if ( !nestedhvm_enabled(v->domain) ) {
        hvm_inject_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE, 0);
        return;
    }

    BUG();
}
