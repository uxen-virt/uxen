/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>

#include "dm.h"
#include "monitor.h"

#include "xen.h"
#include "uxen.h"

#include <xenctrl.h>

#include "qemu_glue.h"
#include "dev.h"
#include "qemu/hw/pci.h"

#if defined(CONFIG_SLIRP) && defined(SLIRP_THREADED)
#include "slirp/libslirp.h"
#endif

int xen_pci_slot_get_pirq(PCIDevice *pci_dev, int irq_num)
{
    return irq_num + ((pci_dev->devfn >> 3) << 2);
}

void xen_piix3_set_irq(void *opaque, int irq_num, int level)
{
    xc_hvm_set_pci_intx_level(xc_handle, vm_id, 0, 0, irq_num >> 2,
                              irq_num & 3, level);
}

void xen_piix_pci_write_config_client(uint32_t address, uint32_t val, int len)
{
    int i;

    /* Scan for updates to PCI link routes (0x60-0x63). */
    for (i = 0; i < len; i++) {
        uint8_t v = (val >> (8 * i)) & 0xff;
        if (v & 0x80) {
            v = 0;
        }
        v &= 0xf;
        if (((address + i) >= 0x60) && ((address + i) <= 0x63)) {
            xc_hvm_set_pci_link_route(xc_handle, vm_id, address + i - 0x60, v);
        }
    }
}

int
xen_register_pcidev(PCIDevice *pci_dev)
{
    uint32_t bdf = 0;
    int rc = 0;

    if (pci_dev->xen_serverid != 1)
        debug_break();

    /* Fix : missing bus id to be more generic */
    bdf |= pci_dev->devfn;

    rc = xc_hvm_register_pcidev(xc_handle, vm_id, pci_dev->xen_serverid, bdf);

    return rc;
}

void
xen_map_iorange(uint64_t addr, uint64_t size, int is_mmio,
		unsigned int serverid)
{

    xc_hvm_map_io_range_to_ioreq_server(xc_handle, vm_id, serverid, is_mmio,
                                        addr, addr + size - 1);
}

void
xen_unmap_iorange(uint64_t addr, uint64_t size, int is_mmio,
		  unsigned int serverid)
{

    xc_hvm_unmap_io_range_from_ioreq_server(xc_handle, vm_id, serverid,
                                            is_mmio, addr);
}

int xen_hvm_track_dirty_vram_enabled = 1;
int
xen_hvm_track_dirty_vram(uint32_t pfn, uint32_t nr, uint8_t *bitmap,
			 uint16_t want_events)
{

    if (xen_hvm_track_dirty_vram_enabled == 0) {
	if (bitmap)
	    memset(bitmap, 0xff, nr / 8);
	return 0;
    }

    return xc_hvm_track_dirty_vram(xc_handle, vm_id, pfn, nr, bitmap,
				   want_events);
}

#ifdef MONITOR
void
mc_toggle_hvm_tracking(Monitor *mon, dict args)
{

    xen_hvm_track_dirty_vram_enabled = 1 - xen_hvm_track_dirty_vram_enabled;
    monitor_printf(mon, "hvm_track_dirty_vram now %s\n",
                   xen_hvm_track_dirty_vram_enabled ? "enabled" : "disabled");
}
#endif  /* MONITOR */

/* Xen Interrupt Controller */

static void xen_set_irq(void *opaque, int irq, int level)
{
    xc_hvm_set_isa_irq_level(xc_handle, vm_id, irq, level);
}

qemu_irq *xen_interrupt_controller_init(void)
{
    return qemu_allocate_irqs(xen_set_irq, NULL, 16);
}

#ifdef MONITOR
void
mc_xen_key(Monitor *mon, dict args)
{
    const char *keys;

    keys = dict_get_string(args, "keys");
    assert(keys);

    uxen_xc_keyhandler(keys);
}
#endif  /* MONITOR */
