/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <asm/hvm/attovm.h>
#include <public/attovm.h>

long do_attovm_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    long ret = 0;

    switch (op) {
    case ATTOVMOP_seal: {
        struct domain *d = NULL;
        struct attovm_op_seal seal;

        ret = -EFAULT;
        if (copy_from_guest(&seal, arg, 1))
            break;
        if ((ret = rcu_lock_remote_target_domain_by_id(seal.domain_id, &d)))
            break;
        ret = attovm_seal(d, &seal.definition);
        rcu_unlock_domain(d);
        break;
    }
    case ATTOVMOP_get_guest_pages: {
        struct domain *d = NULL;
        struct attovm_op_get_guest_pages ggp;

        ret = -EFAULT;
        if (copy_from_guest(&ggp, arg, 1))
            break;
        if ((ret = rcu_lock_remote_target_domain_by_id(ggp.domain_id, &d)))
            break;
        ret = attovm_get_guest_pages(d, ggp.pfn, ggp.count, ggp.buffer);
        rcu_unlock_domain(d);
        break;
    }
    case ATTOVMOP_get_guest_cpu_state: {
        struct domain *d = NULL;
        struct attovm_op_get_guest_cpu_state gcs;

        ret = -EFAULT;
        if (copy_from_guest(&gcs, arg, 1))
            break;
        if ((ret = rcu_lock_remote_target_domain_by_id(gcs.domain_id, &d)))
            break;
        ret = attovm_get_guest_cpu_state(
            d, gcs.vcpu_id, gcs.buffer, gcs.buffer_size);
        rcu_unlock_domain(d);
        break;
    }
    case ATTOVMOP_kbd_focus: {
        struct domain *d = NULL;
        struct attovm_op_kbd_focus op;

        ret = -EFAULT;
        if (copy_from_guest(&op, arg, 1))
            break;
        if ((ret = rcu_lock_remote_target_domain_by_id(op.domain_id, &d)))
            break;
        ret = attovm_kbd_focus(d, op.offer_focus);
        rcu_unlock_domain(d);
        break;
    }

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}


