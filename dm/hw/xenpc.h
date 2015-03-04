/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _XENPC_H_
#define _XENPC_H_

extern DriveInfo drives_table[];

PCIBus *i440fx_init(PCII440FXState **pi440fx_state, int *piix_devfn,
                    qemu_irq *pic,
                    MemoryRegion *address_space_mem,
                    MemoryRegion *address_space_io,
                    ram_addr_t ram_size,
                    target_phys_addr_t pci_hole_start,
                    target_phys_addr_t pci_hole_size,
                    target_phys_addr_t pci_hole64_start,
                    target_phys_addr_t pci_hole64_size,
                    MemoryRegion *pci_memory,
                    MemoryRegion *ram_memory);

i2c_bus *piix4_pm_init(PCIBus *bus, int devfn, uint32_t smb_io_base,
                       qemu_irq sci_irq
                       /* , qemu_irq cmos_s3, qemu_irq smi_irq */);

int uxendisp_init(PCIBus *bus);

SerialState *serial_init(int base, qemu_irq irq, int baudbase,
                         CharDriverState *chr);

void cmos_set_s3_resume(void);

#endif  /* _XENPC_H_ */
