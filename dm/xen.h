/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _XEN_H_
#define _XEN_H_

#include "irq.h"

int xen_pci_slot_get_pirq(PCIDevice *pci_dev, int irq_num);
void xen_piix3_set_irq(void *opaque, int irq_num, int level);
void xen_piix_pci_write_config_client(uint32_t address, uint32_t val, int len);

int xen_register_pcidev(PCIDevice *pci_dev);
void xen_map_iorange(uint64_t addr, uint64_t size, int is_mmio,
		     unsigned int serverid);
void xen_unmap_iorange(uint64_t addr, uint64_t size, int is_mmio,
		       unsigned int serverid);

int xen_hvm_track_dirty_vram(uint32_t pfn, uint32_t nr, uint8_t *bitmap,
			     uint16_t want_events);

qemu_irq *xen_interrupt_controller_init(void);

#endif	/* _XEN_H_ */
