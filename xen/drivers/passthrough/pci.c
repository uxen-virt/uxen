/*
 * Copyright (C) 2008,  Netronome Systems, Inc.
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

#include <xen/sched.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/list.h>
#include <xen/prefetch.h>
#include <xen/iommu.h>
#include <xen/irq.h>
#include <asm/hvm/iommu.h>
#include <asm/hvm/irq.h>
#include <xen/delay.h>
#include <xen/keyhandler.h>
#include <xen/radix-tree.h>
#include <xen/tasklet.h>
#ifdef CONFIG_X86
#include <asm/msi.h>
#endif

spinlock_t pcidevs_lock = SPIN_LOCK_UNLOCKED;


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
