/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/pci.h>
#include <dm/qemu/net.h>

#include <dm/block.h>
#include <dm/dmpdev.h>
#include <dm/hw.h>
#include <dm/firmware.h>

#include <dm/whpx/whpx.h>

#include "xenpc.h"
#include "xenrtc.h"

#include <xen/hvm/e820.h>

#include "uxen_platform.h"

const char *serial_devices[MAX_SERIAL_PORTS] = { NULL, };
CharDriverState *serial_hds[MAX_SERIAL_PORTS];

static ISADevice *rtc = NULL;

ISADevice *rtc_init(int base_year, qemu_irq intercept_irq);

void rtc_set_memory(ISADevice *dev, int addr, int val)
{
    extern void uxen_rtc_set_memory(ISADevice *dev, int addr, int val);
    extern void qemu_rtc_set_memory(ISADevice *dev, int addr, int val);

    if (!whpx_enable)
        uxen_rtc_set_memory(dev, addr, val);
    else
        qemu_rtc_set_memory(dev, addr, val);
}

/* BIOS debug ports and APM power control */

static void
bios_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    static const char shutdown_str[8] = "Shutdown";
    static int shutdown_index = 0;

    debug_printf("bochs bios write addr %x\n", addr);
    switch(addr) {
        /* Bochs BIOS messages */
    case 0x400:
    case 0x401:
        errx(1, "BIOS panic at rombios.c, line %d", val);
    case 0x402:
    case 0x403:
#ifdef DEBUG_BIOS
        debug_printf("%c", val);
#endif
        break;
    case 0x8900:                /* APM power state control */
        if (val == shutdown_str[shutdown_index]) {
            shutdown_index++;
            if (shutdown_index == 8) {
                shutdown_index = 0;
                vm_set_run_mode(DESTROY_VM);
            }
        } else
            shutdown_index = 0;
        break;

        /* LGPL'ed VGA BIOS messages */
    case 0x501:
    case 0x502:
        errx(1, "VGA BIOS panic, line %d", val);
    case 0x500:
    case 0x503:
#ifdef DEBUG_BIOS
        debug_printf("%c", val);
#endif
        break;
    }
}

static void
bios_ioport_deprecated_write(void *opaque, uint32_t addr, uint32_t data)
{
    if (!whpx_enable)
        debug_printf("bios deprecated write at %x val %x\n", addr, data);
}

static uint32_t
bios_ioport_deprecated_read(void *opaque, uint32_t addr)
{
    if (!whpx_enable)
        debug_printf("bios deprecated read at %x\n", addr);
    return 0xffffffff;
}

static void
bios_ioport_init(void)
{

    register_ioport_write(0x400, 1, 2, bios_ioport_write, NULL);
    register_ioport_write(0x401, 1, 2, bios_ioport_write, NULL);
    register_ioport_write(0x402, 1, 1, bios_ioport_write, NULL);
    register_ioport_write(0x403, 1, 1, bios_ioport_write, NULL);

    register_ioport_write(0x8900, 1, 1, bios_ioport_write, NULL);

    register_ioport_write(0x501, 1, 2, bios_ioport_write, NULL);
    register_ioport_write(0x502, 1, 2, bios_ioport_write, NULL);
    register_ioport_write(0x500, 1, 1, bios_ioport_write, NULL);
    register_ioport_write(0x503, 1, 1, bios_ioport_write, NULL);

    register_ioport_write(0x510, 2, 2, bios_ioport_deprecated_write, NULL);
    register_ioport_read(0x511, 1, 1, bios_ioport_deprecated_read, NULL);
    register_ioport_write(0x511, 1, 1, bios_ioport_deprecated_write, NULL);
    register_ioport_write(0x80, 1, 1, bios_ioport_deprecated_write, NULL);
    register_ioport_write(0xf0, 1, 1, bios_ioport_deprecated_write, NULL);
    register_ioport_read(0x92, 1, 1, bios_ioport_deprecated_read, NULL);
    register_ioport_write(0x92, 1, 1, bios_ioport_deprecated_write, NULL);
}

/* convert boot_device letter to something recognizable by the bios */
static int
boot_device2nibble(char boot_device)
{
    switch(boot_device) {
    case 'a':
    case 'b':
        return 0x01; /* floppy boot */
    case 'c':
        return 0x02; /* hard drive boot */
    case 'd':
        return 0x03; /* CD-ROM boot */
    case 'n':
        return 0x04; /* Network boot */
    }
    return 0;
}

static void
cmos_init_hd(int type_ofs, int info_ofs, BlockDriverState *hd)
{
    int cylinders, heads, sectors;

    bdrv_get_geometry_hint(hd, &cylinders, &heads, &sectors);
    rtc_set_memory(rtc, type_ofs, 47);
    rtc_set_memory(rtc, info_ofs, cylinders);
    rtc_set_memory(rtc, info_ofs + 1, cylinders >> 8);
    rtc_set_memory(rtc, info_ofs + 2, heads);
    rtc_set_memory(rtc, info_ofs + 3, 0xff);
    rtc_set_memory(rtc, info_ofs + 4, 0xff);
    rtc_set_memory(rtc, info_ofs + 5, 0xc0 | ((heads > 8) << 3));
    rtc_set_memory(rtc, info_ofs + 6, cylinders);
    rtc_set_memory(rtc, info_ofs + 7, cylinders >> 8);
    rtc_set_memory(rtc, info_ofs + 8, sectors);
}

static void
cmos_init(DriveInfo **hd_table)
{
    uint64_t ram_size = vm_mem_mb << 20;
    int nbds, bds[3] = { 0, };
    uint64_t val;
    int i;

    /* various important CMOS locations needed by PC/Bochs bios */

    /* memory size */
    val = 640; /* base memory in K */
    rtc_set_memory(rtc, 0x15, val);
    rtc_set_memory(rtc, 0x16, val >> 8);

    val = (ram_size / 1024) - 1024;
    if (val > 65535)
        val = 65535;
    rtc_set_memory(rtc, 0x17, val);
    rtc_set_memory(rtc, 0x18, val >> 8);
    rtc_set_memory(rtc, 0x30, val);
    rtc_set_memory(rtc, 0x31, val >> 8);

    if (ram_size >= PCI_HOLE_START) {
        val = ram_size - PCI_HOLE_START;
        rtc_set_memory(rtc, 0x5b, val >> 16);
        rtc_set_memory(rtc, 0x5c, val >> 24);
        rtc_set_memory(rtc, 0x5d, val >> 32);
    }

    if (ram_size > (16 * 1024 * 1024))
        val = (ram_size / 65536) - ((16 * 1024 * 1024) / 65536);
    else
        val = 0;
    if (val > 65535)
        val = 65535;
    rtc_set_memory(rtc, 0x34, val);
    rtc_set_memory(rtc, 0x35, val >> 8);

    /* set the number of CPU */
    rtc_set_memory(rtc, 0x5f, vm_vcpus - 1);

    /* set boot devices, and disable floppy signature check if requested */
#define PC_MAX_BOOT_DEVICES 3
    nbds = strlen(boot_order);
    if (nbds > PC_MAX_BOOT_DEVICES)
        errx(1, "too many boot devices");

    for (i = 0; i < nbds; i++) {
        bds[i] = boot_device2nibble(boot_order[i]);
        if (bds[i] == 0)
            errx(1, "invalid boot device: '%c'", boot_order[i]);
    }

    rtc_set_memory(rtc, 0x3d, (bds[1] << 4) | bds[0]);
    rtc_set_memory(rtc, 0x38, (bds[2] << 4) | 0x1);

    /* floppy type */
    rtc_set_memory(rtc, 0x10, 0);

    val = 0;
    val |= 0x02; /* FPU is there */
    val |= 0x04; /* PS/2 mouse installed */
    rtc_set_memory(rtc, RTC_REG_EQUIPMENT_BYTE, val);

    /* hard drives */
    rtc_set_memory(rtc, 0x12,
                   (hd_table[0] ? 0xf0 : 0) | (hd_table[1] ? 0x0f : 0));
    if (hd_table[0])
        cmos_init_hd(0x19, 0x1b, hd_table[0]->bdrv);
    if (hd_table[1])
        cmos_init_hd(0x1a, 0x24, hd_table[1]->bdrv);

    val = 0;
    for (i = 0; i < 4; i++) {
        if (hd_table[i]) {
            int cylinders, heads, sectors, translation;
            /* NOTE: bdrv_get_geometry_hint() returns the physical
                geometry.  It is always such that: 1 <= sects <= 63, 1
                <= heads <= 16, 1 <= cylinders <= 16383. The BIOS
                geometry can be different if a translation is done. */
            translation = bdrv_get_translation_hint(hd_table[i]->bdrv);
            if (translation == BIOS_ATA_TRANSLATION_AUTO) {
                bdrv_get_geometry_hint(hd_table[i]->bdrv,
                                       &cylinders, &heads, &sectors);
                if (cylinders <= 1024 && heads <= 16 && sectors <= 63) {
                    /* No translation. */
                    translation = 0;
                } else {
                    /* LBA translation. */
                    translation = 1;
                }
            } else {
                translation--;
            }
            val |= translation << (i * 2);
        }
    }
    rtc_set_memory(rtc, 0x39, val);
}

/* set CMOS shutdown status register (index 0xF) as S3_resume(0xFE)
   BIOS will read it and start S3 resume at POST Entry*/
void
cmos_set_s3_resume(void)
{
    if (rtc)
        rtc_set_memory(rtc, 0xf, 0xfe);
}

void
pc_init_xen(void)
{
    int i;
    uint64_t ram_size = vm_mem_mb << 20;
    uint64_t above_4g_mem_size, below_4g_mem_size;
    PCIBus *pci_bus;
    PCII440FXState *i440fx_state;
    int piix3_devfn = -1;
    qemu_irq *pic;
    DriveInfo *hd[MAX_IDE_BUS * MAX_IDE_DEVS];
    int nr_ide = 0;
    DriveInfo *hd_ich[MAX_ICH_DEVS];
    int nr_ich = 0;
#ifdef HAS_AUDIO
    const char *m;
#endif

    if (ram_size >= PCI_HOLE_START ) {
        above_4g_mem_size = ram_size - PCI_HOLE_START;
        below_4g_mem_size = PCI_HOLE_START;
    } else {
        above_4g_mem_size = 0;
        below_4g_mem_size = ram_size;
    }

    bios_ioport_init();

    pic = !whpx_enable ? xen_interrupt_controller_init()
                       : whpx_interrupt_controller_init();
    pci_bus = i440fx_init(&i440fx_state, &piix3_devfn, pic,
                          system_iomem, system_ioport, ram_size,
                          below_4g_mem_size,
                          0x100000000ULL - below_4g_mem_size,
                          0x100000000ULL + above_4g_mem_size,
                          ((uint64_t)1 << 62),
                          system_iomem, NULL);

    isa_bus_irqs(pic);

#ifdef CONFIG_PASSTHROUGH
    intel_pch_init(pci_bus);
#endif

    uxendisp_init(pci_bus);

#ifdef CONFIG_PASSTHROUGH
    /* Pass-through Initialization
     * init libpci even direct_pci is null, as can hotplug a dev runtime
     */
    rc = pt_init(pci_bus);
    if (rc < 0)
        errx(1, "Error: Initialization failed for pass-through devices");
#endif

    rtc = !whpx_enable ? isa_create_simple("xenrtc")
                       : rtc_init(2000, NULL);

    process_config_devices();

#if 0
    pci_xen_platform_init(pci_bus);
    platform_fixed_ioport_init();
#endif

    pci_create_simple(pci_bus, -1, "uxen-platform");

    for (i = 0; i < MAX_SERIAL_PORTS; i++)
        if (serial_hds[i]) {
            ISADevice *dev = isa_try_create("isa-serial");
            if (!dev)
                errx(1, "create isa-serial %d failed", i);
            qdev_prop_set_uint32(&dev->qdev, "index", i);
            qdev_prop_set_chr(&dev->qdev, "chardev", serial_hds[i]);
            if (qdev_init(&dev->qdev) < 0)
                errx(1, "init isa-serial %d failed", i);
        }

#ifdef CONFIG_NET
    if (!vm_use_v4v_net) {
        for (i = 0; i < MAX_NICS; i++) {
            if (nd_table[i].used) {
                if (!nd_table[i].netdev && !nd_table[i].vlan)
                    nd_table[i].vlan = qemu_find_vlan(0, 1);
                pci_nic_init_nofail(&nd_table[i], "e1000", NULL);
            }
        }
    } else {
        for (i = 0; !i; ++i) {
            if (nd_table[i].used) {
                if (!nd_table[i].netdev && !nd_table[i].vlan)
                    nd_table[i].vlan = qemu_find_vlan(0, 1);
                uxenplatform_nic_init(&nd_table[i], "uxen_net");
            }
        }
        for (; i < MAX_NICS; i++) {
            if (nd_table[i].used) {
                if (!nd_table[i].netdev && !nd_table[i].vlan)
                    nd_table[i].vlan = qemu_find_vlan(0, 1);
                uxenplatform_nic_init(&nd_table[i], "null_net");
            }
        }
    }
#endif

    for (i = 0; i < MAX_IDE_BUS * MAX_IDE_DEVS; i++) {
	if (drives_table[i].bdrv && !bdrv_prepare(drives_table + i)) {
	    hd[i] = &drives_table[i];
	    nr_ide++;
	} else
	    hd[i] = NULL;
    }
    for (i = 0; i < MAX_ICH_DEVS; i++) {
        if (drives_table[MAX_IDE_BUS * MAX_IDE_DEVS + i].bdrv &&
            !bdrv_prepare(drives_table + MAX_IDE_BUS * MAX_IDE_DEVS + i)) {
	    hd_ich[i] = &drives_table[MAX_IDE_BUS * MAX_IDE_DEVS + i];
	    nr_ich++;
	} else
	    hd_ich[i] = NULL;
    }

    if (nr_ide) {
        PCIDevice *pci_piix3_xen_ide_init(PCIBus *bus,
                                          DriveInfo **hd_table, int devfn);
        pci_piix3_xen_ide_init(pci_bus, hd, piix3_devfn + 1);
    }
    if (nr_ich) {
        PCIDevice *pci_ich_ide_init(PCIBus *bus, DriveInfo **hd_table,
                                    int devfn);
        pci_ich_ide_init(pci_bus, hd_ich, -1);
    }

#ifdef HAS_TPM
    if (has_tpm_device_danger())
        tpm_tis_init(&isa_get_irq(11));
#endif

    //FIXME
#ifndef __APPLE__
    int uxenhid_create_devices(void);
    // FIXME: uxenhid on whp
    if (!whpx_enable)
        uxenhid_create_devices();
#endif

    isa_create_simple("uxen_debug");

    isa_create_simple("i8042");

    if (dmpdev_enabled)
        isa_create_simple("dmpdev");

    if (smc_enabled())
        isa_create_simple("isa-applesmc");

#ifdef HAS_AUDIO
    m = dict_get_string(vm_audio, "type");

    if (m && !strcmp(m, "hda")) {
	int intel_hda_and_codec_init(PCIBus *bus);
	intel_hda_and_codec_init(pci_bus);
    } else {
	int uxenaudio_init(PCIBus *bus);
	uxenaudio_init(pci_bus);
    }
#endif

    cmos_init(hd);

    {
	extern void uxen_stor_late_register(void);
	uxen_stor_late_register();
    }

#if !defined(QEMU_UXEN)
    if (usb_enabled)
        usb_uhci_piix3_init(pci_bus, piix3_devfn + 2);
#endif  /* QEMU_UXEN */

    /* if (acpi_enabled) */ {
#if 0
        uint8_t *eeprom_buf = calloc(1, 8 * 256);
        i2c_bus *smbus;
#endif

#if 0
        /* TODO: Populate SPD eeprom data.  */
        smbus =
#endif
            piix4_pm_init(pci_bus, piix3_devfn + 3, 0xb100, isa_get_irq(9));

#if 0
	if (smbus)
	    for (i = 0; i < 8; i++)
		smbus_eeprom_device_init(smbus, 0x50 + i,
                                         eeprom_buf + (i * 256));
#endif
    }

#if 0
    if (i440fx_state)
        i440fx_init_memory_mappings(i440fx_state);
#endif
}
