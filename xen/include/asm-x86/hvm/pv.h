/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __ASM_HVM_PV_H__
#define __ASM_HVM_PV_H__

#include <asm/hvm/ax.h>
#include <asm/hvm/xen_pv.h>

#define pv_ept_flush(p2m) do {                  \
        if (ax_pv_ept)                          \
            ax_pv_ept_flush(p2m);               \
        else if (xen_pv_ept)                    \
            xen_pv_ept_flush(p2m);              \
    } while (0)

#define pv_ept_write(p2m, target, gfn, epte, need_sync) do {            \
        if (ax_pv_ept) {                                                \
            ax_pv_ept_write(p2m, target, gfn, epte, need_sync);         \
            (need_sync) = 0;                                            \
        } else if (xen_pv_ept) {                                        \
            xen_pv_ept_write(p2m, target, gfn, epte, need_sync);        \
            (need_sync) = 0;                                            \
        }                                                               \
    } while (0)

#define pv_split_super_page(p2m, level, gfn, new_entry, invept) do {    \
        if (ax_pv_ept) {                                                \
            printk(KERN_ERR                                             \
                   "AX_PV_EPT: splitting page - leaving to async path\n"); \
            /* FIXME Eventually: */                                     \
            /* ax_pv_ept_write(p2m, level, gfn, new_entry, needs_sync); */ \
        } else if (xen_pv_ept)                                          \
            printk(KERN_ERR                                             \
                   "XEN_PV_EPT: splitting page - leaving to async path\n"); \
    } while (0)

#endif  /* __ASM_HVM_PV_H__ */
