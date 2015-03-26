/*
 * QEMU PCI VGA Emulator.
 *
 * Copyright (c) 2003 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/*
 * uXen changes:
 *
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
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

#include <dm/qemu_glue.h>
#include <dm/bh.h>
#include <dm/dev.h>
#include <dm/dma.h>
#include <dm/console.h>
#include <dm/vga.h>
#include <dm/vmstate.h>
#include <dm/vram.h>
#include <dm/qemu/hw/vga_int.h>
#include "pci.h"

typedef struct UXENVGAState {
    PCIDevice dev;
    VGACommonState vga;
} UXENVGAState;

static const VMStateDescription vmstate_vga_uxen = {
    .name = "vga",
    .version_id = 4,
    .minimum_version_id = 4,
    .minimum_version_id_old = 3,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(dev, UXENVGAState),
        VMSTATE_STRUCT(vga, UXENVGAState, 0, vmstate_vga_common, VGACommonState),
        VMSTATE_END_OF_LIST()
    }
};

static int uxen_vga_initfn(PCIDevice *dev)
{
    UXENVGAState *d = DO_UPCAST(UXENVGAState, dev, dev);
    VGACommonState *s = &d->vga;

    // vga + console init
    vga_common_init(s, vm_vga_mb << 20);
    vga_init(s, pci_address_space(dev), pci_address_space_io(dev), true);

    s->ds = graphic_console_init(s->update, s->invalidate,
                                 s->text_update, s);

    /* XXX: VGA_RAM_SIZE must be a power of two */
    pci_register_bar(&d->dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH, &s->vram);

    if (!dev->rom_bar) {
        /* compatibility with pc-0.13 and older */
        vga_init_vbe(s, pci_address_space(dev));
    }

    return 0;
}

static int uxen_vga_exitfn(PCIDevice *dev)
{
    UXENVGAState *d = DO_UPCAST(UXENVGAState, dev, dev);
    VGACommonState *s = &d->vga;

    vga_exit(s);

    return 0;
}

int uxen_vga_init(PCIBus *bus)
{
    pci_create_simple(bus, -1, "uxen-vga");
    return 0;
}

static PCIDeviceInfo vga_info = {
    .qdev.name    = "uxen-vga",
    .qdev.size    = sizeof(UXENVGAState),
    .qdev.vmsd    = &vmstate_vga_uxen,
    .no_hotplug   = 1,
    .init         = uxen_vga_initfn,
    .exit         = uxen_vga_exitfn,
    .romfile      = "vgabios-stdvga.bin",

    .vendor_id    = PCI_VENDOR_ID_XEN,
    .device_id    = PCI_DEVICE_ID_UXEN_VGA,
    .class_id     = PCI_CLASS_DISPLAY_VGA,

    .subsystem_vendor_id = PCI_VENDOR_ID_XEN,
    .subsystem_id = PCI_DEVICE_ID_XEN_SUBSYS1,
};

static void vga_register(void)
{
    pci_qdev_register(&vga_info);
}
device_init(vga_register);
