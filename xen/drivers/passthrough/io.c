/*
 * Copyright (c) 2006, Intel Corporation.
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
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Xiaohui Xin <xiaohui.xin@intel.com>
 */

#include <xen/event.h>
#include <xen/iommu.h>
#include <xen/irq.h>
#include <asm/hvm/irq.h>
#include <asm/hvm/iommu.h>
#include <asm/hvm/support.h>
#include <xen/hvm/irq.h>
#include <xen/tasklet.h>

struct rangeset *__read_mostly mmio_ro_ranges;

void pt_pirq_init(struct domain *d, struct hvm_pirq_dpci *dpci)
{
    INIT_LIST_HEAD(&dpci->digl_list);
    dpci->gmsi.dest_vcpu_id = -1;
}

static int __init setup_mmio_ro_ranges(void)
{
    mmio_ro_ranges = rangeset_new(NULL, "r/o mmio ranges",
                                  RANGESETF_prettyprint_hex);
    return 0;
}
__initcall(setup_mmio_ro_ranges);
