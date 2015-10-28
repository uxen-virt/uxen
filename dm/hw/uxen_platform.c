/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/irq.h>
#include <dm/qemu/net.h>
#include <dm/dm.h>
#include "pci.h"
#include "pci-ram.h"

#include "uxen_platform.h"
#include <uxen/platform_interface.h>
#include <dm/control.h>
#include <xc_private.h>

#undef DPRINTF

#define DEBUG_PLATFORM

#ifdef DEBUG_PLATFORM
#define DPRINTF(fmt, ...) do { \
        debug_printf("%s: " fmt, __FUNCTION__, ## __VA_ARGS__);  \
} while (0)
#else
#define DPRINTF(fmt, ...) do { } while (0)
#endif

#define RAM_BAR_SIZE TARGET_PAGE_SIZE

struct platform_bus {
    BusState qbus;
    MemoryRegion io;
};

typedef struct PCI_uxen_platform_state {
    PCIDevice dev;
    MemoryRegion ctl_mmio_bar;
    struct ctl_mmio ctl_mmio;
    BH *balloon_status_bh;
    uint64_t ftime;

    MemoryRegion state_bar;

    void *state_ptr;

    struct platform_bus *bus;
} PCI_uxen_platform_state;

static struct PCI_uxen_platform_state *uxp_dev = NULL;

#define ADDR_SIZE(addr, size) ((addr) << 4 | (size))

static void
update_state_pointer(void *ram_ptr, void *opaque)
{
    PCI_uxen_platform_state *s = opaque;

    s->state_ptr = ram_ptr;
    if (s->state_ptr) {
        struct uxp_state_bar *r = (struct uxp_state_bar *) s->state_ptr;

        memset(r, 0, RAM_BAR_SIZE);

        r->magic = UXEN_STATE_BAR_MAGIC;
        r->v4v_running = 0;
    }
}

static void
platform_get_ftime(PCI_uxen_platform_state *s)
{
    /*
     * 64bit value representing the number of 100-nanosecond intervals
     * since January 1, 1601 (UTC)
     */
#if defined(_WIN32)
    SYSTEMTIME stime;
    FILETIME ftime;

    GetSystemTime(&stime);
    SystemTimeToFileTime(&stime, &ftime);

    s->ftime = ftime.dwHighDateTime;
    s->ftime <<= 32;
    s->ftime |= ftime.dwLowDateTime;
#else
    /* Implement me */
    s->ftime = 0ULL;
#endif
}

static uint64_t
ctl_mmio_read(void *opaque, uint64_t addr, unsigned size)
{
    PCI_uxen_platform_state *s = opaque;
    uint64_t ret;

    switch (ADDR_SIZE(addr, size)) {
    case ADDR_SIZE(offsetof(struct ctl_mmio, cm_events),
                   sizeof(s->ctl_mmio.cm_events)):
        DPRINTF("read cm_events: 0x%x\n", s->ctl_mmio.cm_events);
        ret = s->ctl_mmio.cm_events & s->ctl_mmio.cm_events_enabled;
        s->ctl_mmio.cm_events ^= ret;
        qemu_set_irq(uxp_dev->dev.irq[0], 0);
        return ret;
    case ADDR_SIZE(offsetof(struct ctl_mmio, cm_balloon_min),
                   sizeof(s->ctl_mmio.cm_balloon_min)):
        DPRINTF("read cm_balloon_min: 0x%"PRIx64" (MiB)\n", balloon_min_mb);
        return balloon_min_mb;
    case ADDR_SIZE(offsetof(struct ctl_mmio, cm_balloon_max),
                   sizeof(s->ctl_mmio.cm_balloon_max)):
        DPRINTF("read cm_balloon_max: 0x%"PRIx64" (MiB)\n", balloon_max_mb);
        return balloon_max_mb;
    case ADDR_SIZE(offsetof(struct ctl_mmio, cm_filetime_low),
                   sizeof(s->ctl_mmio.cm_filetime_low)):
        platform_get_ftime(s);
        DPRINTF("read cm_filetime_low: %"PRIu64"\n", s->ftime % 0xFFFFFFFF);
        return s->ftime & 0xFFFFFFFFULL;
    case ADDR_SIZE(offsetof(struct ctl_mmio, cm_filetime_high),
                   sizeof(s->ctl_mmio.cm_filetime_high)):
        DPRINTF("read cm_filetime_high: %"PRIu64"\n", s->ftime >> 32);
        return s->ftime >> 32;
    default:
        DPRINTF("read from physical address 0x%"PRIx64" size %d\n", addr, size);
        break;
    }

    return 0;
}

static void
ctl_mmio_write(void *opaque, uint64_t addr, uint64_t data, unsigned size)
{
    PCI_uxen_platform_state *s = opaque;

    switch (ADDR_SIZE(addr, size)) {
    case ADDR_SIZE(offsetof(struct ctl_mmio, cm_events_enabled),
                   sizeof(s->ctl_mmio.cm_events_enabled)):
        DPRINTF("write cm_events_enabled: 0x%"PRIx64"\n", data);
        s->ctl_mmio.cm_events_enabled = data;
        qemu_set_irq(uxp_dev->dev.irq[0],
                     (s->ctl_mmio.cm_events & s->ctl_mmio.cm_events_enabled) ?
                     1 : 0);
        return;
    case ADDR_SIZE(offsetof(struct ctl_mmio, cm_balloon_current),
                   sizeof(s->ctl_mmio.cm_balloon_current)):
        //DPRINTF("write cm_balloon_current: 0x%x (MiB)\n", (uint32_t) data);
        s->ctl_mmio.cm_balloon_current = data;
        bh_schedule(s->balloon_status_bh);
        return;
    default:
        DPRINTF("write of 0x%"PRIx64" to physical address 0x%"PRIx64
                " size %d\n", data, addr, size);
        break;
    }
}

static const MemoryRegionOps ctl_mmio_handler = {
    .read = &ctl_mmio_read,
    .write = &ctl_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

void
uxen_platform_time_update(void)
{

    if (!uxp_dev)
        return;

    uxp_dev->ctl_mmio.cm_events |= CTL_MMIO_EVENT_SYNC_TIME;
    if (uxp_dev->ctl_mmio.cm_events & uxp_dev->ctl_mmio.cm_events_enabled)
        qemu_set_irq(uxp_dev->dev.irq[0], 1);
}

int
uxen_platform_set_balloon_size(int min_mb, int max_mb)
{
    if (!uxp_dev)
        return -1;

    balloon_min_mb = min_mb;
    balloon_max_mb = max_mb;
    uxp_dev->ctl_mmio.cm_balloon_min = min_mb;
    uxp_dev->ctl_mmio.cm_balloon_max = max_mb;
    uxp_dev->ctl_mmio.cm_events |= CTL_MMIO_EVENT_SET_BALLOON;
    if (uxp_dev->ctl_mmio.cm_events & uxp_dev->ctl_mmio.cm_events_enabled)
        qemu_set_irq(uxp_dev->dev.irq[0], 1);
    return 0;
}

static void
uxen_platform_hotplug(void)
{

    if (!uxp_dev)
        return;

    uxp_dev->ctl_mmio.cm_events |= CTL_MMIO_EVENT_HOTPLUG;
    if (uxp_dev->ctl_mmio.cm_events & uxp_dev->ctl_mmio.cm_events_enabled)
        qemu_set_irq(uxp_dev->dev.irq[0], 1);
}

int uxen_platform_get_balloon_size(int *current, int *min, int *max)
{
    if (!uxp_dev)
        return -1;

    if (current)
        *current = uxp_dev->ctl_mmio.cm_balloon_current;
    if (min)
        *min = uxp_dev->ctl_mmio.cm_balloon_min;
    if (max)
        *max = uxp_dev->ctl_mmio.cm_balloon_max;

    return 0;
}

static int uxen_platform_post_load(void *opaque, int version_id)
{
    PCI_uxen_platform_state *s = opaque;

    pci_ram_post_load(&s->dev, version_id);

    if (s->ctl_mmio.cm_events & s->ctl_mmio.cm_events_enabled)
        qemu_set_irq(s->dev.irq[0], 1);

    return 0;
}

static void uxen_platform_pre_save(void *opaque)
{
    PCI_uxen_platform_state *s = opaque;

    pci_ram_pre_save(&s->dev);
}

static void
uxen_platform_post_save(void *opaque)
{
    PCI_uxen_platform_state *s = opaque;

    pci_ram_post_save(&s->dev);
}

static const VMStateDescription vmstate_uxen_platform_ctl_mmio = {
    .name = "uxen-platform-ctl-mmio",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields = (VMStateField []) {
        VMSTATE_UINT32(cm_events_enabled, struct ctl_mmio),
        VMSTATE_UINT32(cm_events, struct ctl_mmio),
        VMSTATE_UINT32(cm_balloon_min, struct ctl_mmio),
        VMSTATE_UINT32(cm_balloon_max, struct ctl_mmio),
        VMSTATE_UINT32(cm_balloon_current, struct ctl_mmio),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_uxen_platform = {
    .name = "uxen-platform",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .pre_save = uxen_platform_pre_save,
    .post_load = uxen_platform_post_load,
    .post_save = uxen_platform_post_save,
    .resume = uxen_platform_post_load,
    .fields = (VMStateField []) {
        VMSTATE_PCI_DEVICE(dev, PCI_uxen_platform_state),
        VMSTATE_STRUCT(ctl_mmio, PCI_uxen_platform_state, 0,
                       vmstate_uxen_platform_ctl_mmio, struct ctl_mmio),
        VMSTATE_END_OF_LIST()
    }
};

static void
uxen_platform_balloon_notify(void *opaque)
{
    PCI_uxen_platform_state *s = opaque;
    char size_str[16];

    snprintf(size_str, sizeof(size_str), "%u", s->ctl_mmio.cm_balloon_current);
    control_send_status("balloon-size", size_str, NULL);
}


static uint64_t
ram_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    PCI_uxen_platform_state *s = opaque;
    uint64_t ret = ~0;

    if (!s->state_ptr)
        return ret;

    switch (size) {
    case 8:
        ret = *(uint64_t *)(s->state_ptr + addr);
        break;
    case 4:
        ret = *(uint32_t *)(s->state_ptr + addr);
        break;
    case 2:
        ret = *(uint16_t *)(s->state_ptr + addr);
        break;
    case 1:
        ret = *(uint8_t *)(s->state_ptr + addr);
        break;
    }

    DPRINTF("platform: ram_read%d(%"PRIx64")=%"PRIx64, size * 8, addr, ret);

    return ret;
}

static void
ram_write(void *opaque, target_phys_addr_t addr, uint64_t val, unsigned size)
{
    PCI_uxen_platform_state *s = opaque;

    DPRINTF("platform: ram_write%d(%"PRIx64",%"PRIx64")", size * 8, addr, val);

    if (!s->state_ptr)
        return;

    switch (size) {
    case 8:
        *(uint64_t *)(s->state_ptr + addr) = val;
        break;
    case 4:
        *(uint32_t *)(s->state_ptr + addr) = val;
        break;
    case 2:
        *(uint16_t *)(s->state_ptr + addr) = val;
        break;
    case 1:
        *(uint8_t *)(s->state_ptr + addr) = val;
        break;
    }
}

static const MemoryRegionOps uxen_platform_ram_ops = {
    .read = ram_read,
    .write = ram_write
};

/* uXen platform Bus */

static void
bus_io_write(void *opaque, target_phys_addr_t addr, uint64_t val,
             unsigned size)
{

}

static uint64_t
bus_io_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    struct platform_bus *b = opaque;
    uint64_t val = ~0;
    UXenPlatformDevice *d;
    DeviceState *dev;
    int devid, i = 0;

    addr &= (UXENBUS_DEVICE_CONFIG_LENGTH * UXENBUS_DEVICE_COUNT) - 1;
    devid = addr / UXENBUS_DEVICE_CONFIG_LENGTH;
    addr &= UXENBUS_DEVICE_CONFIG_LENGTH - 1;

    dev = TAILQ_FIRST(&b->qbus.children);
    while (dev && i++ < devid)
        dev = TAILQ_NEXT(dev, sibling);
    if (!dev)
        goto out;
    d = DO_UPCAST(UXenPlatformDevice, qdev, dev);
    if (addr + size > UXENBUS_DEVICE_CONFIG_LENGTH)
        goto out;
    if (d->config)
        memcpy(&val, d->config + addr, size);

out:
    return val;
}

static const MemoryRegionOps bus_io_ops = {
    .read = bus_io_read,
    .write = bus_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static struct BusInfo platform_bus_info = {
    .name = "uxenplatform",
    .size = sizeof(struct platform_bus),
};

static int platform_qdev_init(DeviceState *qdev, DeviceInfo *base)
{
    UXenPlatformDevice *d = DO_UPCAST(UXenPlatformDevice, qdev, qdev);
    UXenPlatformDeviceInfo *info = DO_UPCAST(UXenPlatformDeviceInfo, qdev, base);
    DeviceState *dev;
    struct uxp_bus_device *cfg;
    uint8_t instance_id = 0;
    int ret;

    d->config = malloc(UXENBUS_DEVICE_CONFIG_LENGTH);
    if (!d->config)
        return -1;

    TAILQ_FOREACH(dev, &qdev->parent_bus->children, sibling) {
        UXenPlatformDevice *sibling = DO_UPCAST(UXenPlatformDevice, qdev, dev);
        struct uxp_bus_device *cfg2 = (void *)sibling->config;

        if (cfg2 && sibling != d &&
            cfg2->device_type == info->devtype &&
            cfg2->instance_id >= instance_id)
            instance_id = cfg2->instance_id + 1;
    }

    cfg = (void *)d->config;
    cfg->device_type = info->devtype;
    cfg->instance_id = instance_id;
    cfg->prop_list.property_type = UXENBUS_PROPERTY_TYPE_LIST_END;
    cfg->prop_list.length = 0;

    ret = info->init(d);
    if (ret) {
        free(d->config);
        d->config = NULL;
        return ret;
    }

    if (qdev->hotplugged)
        uxen_platform_hotplug();

    return 0;
}

static int platform_qdev_exit(DeviceState *qdev)
{
    UXenPlatformDevice *d = DO_UPCAST(UXenPlatformDevice, qdev, qdev);
    UXenPlatformDeviceInfo *info = DO_UPCAST(UXenPlatformDeviceInfo, qdev,
                                             qdev->info);
    int ret = 0;

    if (d->config) {
        free(d->config);
        d->config = NULL;
    }

    if (info->exit)
        ret = info->exit(d);

    return ret;
}

static int platform_qdev_unplug(DeviceState *qdev)
{
    UXenPlatformDevice *d = DO_UPCAST(UXenPlatformDevice, qdev, qdev);
    UXenPlatformDeviceInfo *info = DO_UPCAST(UXenPlatformDeviceInfo, qdev,
                                             qdev->info);
    int ret = 0;

    if (d->config) {
        free(d->config);
        d->config = NULL;
    }

    if (info->unplug)
        ret = info->unplug(d);

    uxen_platform_hotplug();

    return ret;
}

void uxenplatform_qdev_register(UXenPlatformDeviceInfo *info)
{
    info->qdev.init = platform_qdev_init;
    info->qdev.exit = platform_qdev_exit;
    info->qdev.unplug = platform_qdev_unplug;
    info->qdev.bus_info = &platform_bus_info;
    qdev_register(&info->qdev);
}

int
uxenplatform_device_add_property(UXenPlatformDevice *dev, uint8_t property_type,
                                 void *property, size_t property_len)
{
    struct uxp_bus_device *cfg = (void *)dev->config;
    struct uxp_bus_device_property *prop = &cfg->prop_list;
    struct uxp_bus_device_property *end = (void *)(dev->config +
                                                   UXENBUS_DEVICE_CONFIG_LENGTH -
                                                   sizeof(*prop));

    while (prop <= end && prop->property_type != UXENBUS_PROPERTY_TYPE_LIST_END)
        prop = UXENBUS_PROP_NEXT(prop);

    if (prop->property_type != UXENBUS_PROPERTY_TYPE_LIST_END ||
        UXENBUS_PROP_NEXT_L(prop, property_len) > end)
        return -1; /* Not enough space */

    prop->property_type = property_type;
    prop->length = property_len;
    memcpy(prop + 1, property, property_len);
    prop = UXENBUS_PROP_NEXT(prop);

    prop->property_type = UXENBUS_PROPERTY_TYPE_LIST_END;
    prop->length = 0;

    return 0;
}

int
uxenplatform_device_get_instance_id(UXenPlatformDevice *dev)
{
    struct uxp_bus_device *cfg = (void *)dev->config;

    return cfg->instance_id;
}

UXenPlatformDevice *uxenplatform_device_create(const char *name)
{
    DeviceState *dev;

    if (!uxp_dev || !uxp_dev->bus)
        return NULL;

    dev = qdev_create(&uxp_dev->bus->qbus, name);

    return DO_UPCAST(UXenPlatformDevice, qdev, dev);
}

UXenPlatformDevice *uxenplatform_create_simple(const char *model)
{
    UXenPlatformDevice *dev;

    dev = uxenplatform_device_create(model);
    if (!dev)
        return NULL;

    if (qdev_init(&dev->qdev) < 0) {
        qdev_free(&dev->qdev);
        return NULL;
    }

    return dev;
}

UXenPlatformDevice *uxenplatform_nic_init(NICInfo *nd, const char *model)
{
    UXenPlatformDevice *dev;

    dev = uxenplatform_device_create(model);
    if (!dev)
        return NULL;

    qdev_set_nic_properties(&dev->qdev, nd);
    if (qdev_init(&dev->qdev) < 0) {
        qdev_free(&dev->qdev);
        return NULL;
    }

    return dev;
}

/* init */

static int
uxen_platform_initfn(PCIDevice *dev)
{
    PCI_uxen_platform_state *d = DO_UPCAST(PCI_uxen_platform_state, dev, dev);
    uint8_t *pci_conf;

    if (uxp_dev)
        return EEXIST;
    uxp_dev = d;

    pci_conf = d->dev.config;

    pci_set_word(pci_conf + PCI_COMMAND, 0
                 /* PCI_COMMAND_IO | PCI_COMMAND_MEMORY */);

    pci_config_set_prog_interface(pci_conf, 0);

    pci_conf[PCI_INTERRUPT_PIN] = 1;

    memory_region_init_io(&d->ctl_mmio_bar, &ctl_mmio_handler, d,
                          "uxen-ctl-mmio", 0x1000);
    pci_register_bar(&d->dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH,
                     &d->ctl_mmio_bar);

    d->balloon_status_bh = bh_new(uxen_platform_balloon_notify, d);

    memory_region_init_io (&d->state_bar, &uxen_platform_ram_ops, d,
                           "uxen_platform ram", RAM_BAR_SIZE);
    memory_region_add_ram_range(&d->state_bar, 0, RAM_BAR_SIZE,
                                update_state_pointer, d);

    pci_register_bar(&d->dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->state_bar);

    d->bus = FROM_QBUS(struct platform_bus,
                       qbus_create(&platform_bus_info, &dev->qdev, NULL));
    d->bus->qbus.allow_hotplug = 1;

    memory_region_init_io(&d->bus->io, &bus_io_ops, d->bus, "platform.bus_io",
                          UXENBUS_DEVICE_CONFIG_LENGTH * UXENBUS_DEVICE_COUNT);
    pci_register_bar(&d->dev, 2, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->bus->io);

    return 0;
}

static int
uxen_platform_exitfn (PCIDevice * dev)
{
    PCI_uxen_platform_state *s = DO_UPCAST(PCI_uxen_platform_state, dev, dev);

    memory_region_destroy(&s->bus->io);
    qbus_free(&s->bus->qbus);
    s->bus = NULL;
    memory_region_del_ram_range(&s->state_bar, 0);
    memory_region_destroy (&s->state_bar);
    memory_region_destroy(&s->ctl_mmio_bar);

    return 0;
}


static PCIDeviceInfo uxen_platform_info = {
    .init = uxen_platform_initfn,
    .exit = uxen_platform_exitfn,
    .qdev.name = "uxen-platform",
    .qdev.desc = "uXen platform pci device",
    .qdev.size = sizeof(PCI_uxen_platform_state),
    .qdev.vmsd = &vmstate_uxen_platform,

    .vendor_id =  PCI_VENDOR_ID_XEN,
    .device_id = PCI_DEVICE_ID_UXEN_PLATFORM,
    .class_id = PCI_CLASS_OTHERS << 8 | 0x80,
    .subsystem_vendor_id = PCI_VENDOR_ID_XEN,
    .subsystem_id = PCI_DEVICE_ID_UXEN_PLATFORM,
    .config_write = pci_ram_config_write,
    .revision = 1,
};

static void uxen_platform_register(void)
{
    pci_qdev_register(&uxen_platform_info);
}
device_init(uxen_platform_register);

#ifdef MONITOR
void
mc_vm_balloon_size(Monitor *mon, const dict args)
{
    uxen_platform_set_balloon_size(
        dict_get_integer(args, "min"),
        dict_get_integer(args, "max"));
}
#endif
