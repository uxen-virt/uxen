/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <xen/keyhandler.h>
#include <xsm/xsm.h>


static int
bar0_handler(void *context, int bar, int dir, uint32_t addr, uint32_t size,
             void *val)
{
    return X86EMUL_UNHANDLEABLE;
}

static int
bar1_handler(void *context, int bar, int dir, uint32_t addr, uint32_t size,
             void *val)
{
    return X86EMUL_UNHANDLEABLE;
}

int
pci_test_init(struct domain *d)
{
    u16 bdf = PCI_BDF(0,0x1e,0);

    if (!d->domain_id)
        return 0;

    hvm_register_pcidev_with_lock(d, SERVID_INTERNAL, bdf);
    register_pciconfig_handler(d, PCI_BDF_TO_CF8(bdf), PCI_CONFIG_SPACE_SIZE,
                               pci_device_config_handler);

    hvm_pcidev_set_ids(d, bdf, 0x5836, 0xc2ff, 0x070001, 0x01, 0x5836, 0xc2ff);

    hvm_pcidev_set_bar(d, bdf, 0, PCI_TYPE_IO, 0, 0x10, bar0_handler, NULL);
    hvm_pcidev_set_bar(d, bdf, 1, PCI_TYPE_MMIO, 0, 0x1000, bar1_handler, NULL);

    return 0;
}
