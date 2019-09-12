/*
 * Copyright 2016-2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#include <linux/vmalloc.h>

#include <xen/version.h>
#include <xen/xen.h>
#include <xen/memory.h>
#include <uxen/platform_interface.h>

#include <uxen-util.h>
#include <uxen-platform.h>

#define DRV_NAME    "uxenplatform"

#ifndef PCI_DEVICE_ID_UXEN_PLATFORM
#define PCI_DEVICE_ID_UXEN_PLATFORM 0x5173
#endif

static struct bus_type *uxen_bus = NULL;
static int irq_initialized = 0;
static void __iomem *bar_ctl = NULL;
static unsigned long bar_ctl_length = 0;
static void __iomem *bar_ram = NULL;
static unsigned long bar_ram_length = 0;
static void __iomem *bar_busio = NULL;
static unsigned long bar_busio_length = 0;

static struct pci_driver pci_platform_driver;
static int device_get_property(struct uxen_device *dev, int prop_id,
                               void *prop, size_t *prop_len);

static int scan_device_removed(struct device *_dev, void *data)
{
    size_t i;
    struct uxp_bus_device __iomem *uxp_dev;
    struct uxen_device *dev = dev_to_uxen(_dev);
    struct uxen_driver *drv = drv_to_uxen(_dev->driver);

    for (i = 0; bar_busio && i < UXENBUS_DEVICE_COUNT; i++) {
        uxp_dev = (struct uxp_bus_device *) (((unsigned char *) bar_busio) +
                i * UXENBUS_DEVICE_CONFIG_LENGTH);

        if ((i + 1) * UXENBUS_DEVICE_CONFIG_LENGTH > bar_busio_length)
            break;

        if (ioread8(&uxp_dev->device_type) == UXENBUS_DEVICE_NOT_PRESENT)
            continue;

        if (ioread8(&uxp_dev->device_type) == dev->type &&
            ioread8(&uxp_dev->instance_id) == dev->instance) {

            return 0;
        }
    }

    printk(KERN_INFO "uxenplatform: removing device type %d instance %d\n",
                     (int) dev->type, (int) dev->instance);
    if (dev && drv && drv->remove)
        drv->remove(dev);
    device_unregister(_dev);

    return 0;
}

static int scan_device_added(struct device *_dev, void *data)
{
    struct uxp_bus_device __iomem *uxp_dev = (struct uxp_bus_device *)data;
    struct uxen_device *dev = dev_to_uxen(_dev);

    return !!(dev->type == ioread8(&uxp_dev->device_type) &&
            dev->instance == ioread8(&uxp_dev->instance_id));
}

static void device_release(struct device *_dev)
{
    struct uxen_device *dev = dev_to_uxen(_dev);

    kfree(dev);
}

static void scan_devices(void)
{
    struct uxp_bus_device __iomem *uxp_dev;
    size_t i;

    if (!bar_busio || !uxen_bus)
        return;

    bus_for_each_dev(uxen_bus, NULL, NULL, scan_device_removed);

    for (i = 0; i < UXENBUS_DEVICE_COUNT; i++) {
        uxp_dev = (struct uxp_bus_device *) (((unsigned char *) bar_busio) +
                i * UXENBUS_DEVICE_CONFIG_LENGTH);

        if ((i + 1) * UXENBUS_DEVICE_CONFIG_LENGTH > bar_busio_length)
            break;

        if (ioread8(&uxp_dev->device_type) == UXENBUS_DEVICE_NOT_PRESENT)
            continue;

        if (bus_for_each_dev(uxen_bus, NULL, uxp_dev, scan_device_added) == 0) {
            struct uxen_device *dev;
            int r;

            dev = kzalloc(sizeof(*dev), GFP_KERNEL);
            if (!dev)
                continue;

            dev->type = ioread8(&uxp_dev->device_type);
            dev->instance = ioread8(&uxp_dev->instance_id);
            dev->slot = i;
            dev->dev.bus = uxen_bus;
            dev->dev.release = device_release;
            dev->get_property = device_get_property;
            if (dev->type < sizeof(uxenbus_device_names) / sizeof(uxenbus_device_names[0]))
                dev_set_name(&dev->dev, "%s-%d", uxenbus_device_names[dev->type], dev->instance);
            else
	        dev_set_name(&dev->dev, "uxen-dev-%d-%d", dev->type, dev->instance);
            if ((r = device_register(&dev->dev)) == 0) {
                printk(KERN_INFO "uxenplatform: new device type %d instance %d\n",
                                 (int) dev->type, (int) dev->instance);
            } else {
                printk(KERN_ERR "%s: failed device_register err %d\n", __FUNCTION__, r);
                kfree(dev);
            }
        }
    }
}

static int device_get_property(struct uxen_device *dev, int prop_id, void *prop, size_t *prop_len)
{
    unsigned char prop_type, len, i;
    struct uxp_bus_device_property __iomem *p;
    struct uxp_bus_device __iomem *uxp_dev;

    if (!bar_busio || !bar_busio_length)
        return -ENODEV;

    if (dev->slot >= UXENBUS_DEVICE_COUNT)
       return -ENODEV;

    uxp_dev = (struct uxp_bus_device *) (((unsigned char *) bar_busio) +
              dev->slot * UXENBUS_DEVICE_CONFIG_LENGTH);

    if (dev->type != ioread8(&uxp_dev->device_type) || dev->instance !=
        ioread8(&uxp_dev->instance_id)) {

        return -ENODEV;
    }

    p = &uxp_dev->prop_list;
    prop_type = ioread8(&p->property_type);
    while (prop_type != UXENBUS_PROPERTY_TYPE_LIST_END) {
        if (prop_type == prop_id)
            break;

        p = UXENBUS_PROP_NEXT_L(p, ioread8(&p->length));
        prop_type = ioread8(&p->property_type);
    }

    if (prop_type != prop_id)
        return -ENOENT;

    len = ioread8(&p->length);
    if (*prop_len < len)
        return -EINVAL;

    for (i = 0; i < len; i++) {
        *(((unsigned char *) prop) + i) = ioread8(((unsigned char *) (p + 1)) +
                i);
    }
    *prop_len = len;

    return 0;
}

static irqreturn_t pci_platform_irq(int irq, void *dev_id)
{
    return IRQ_HANDLED;
}

static void pci_platform_remove(struct pci_dev *pdev)
{
    if (irq_initialized) {
        free_irq(pdev->irq, pdev);
        irq_initialized = 0;
    }
    if (bar_ctl)
        pci_iounmap(pdev, bar_ctl);
    if (bar_ram)
        pci_iounmap(pdev, bar_ram);
    if (bar_busio)
        pci_iounmap(pdev, bar_busio);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
}

static int pci_platform_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    int ret = -1;

    if (!uxen_bus)
        return -ENODEV;

    ret = pci_enable_device(pdev);
    if (ret)
        goto out;

    ret = pci_request_region(pdev, 0, pci_name(pdev));
    if (ret)
        goto cleanup;
    bar_ctl_length = pci_resource_len(pdev, 0);
    if (bar_ctl_length && !(bar_ctl = pci_iomap(pdev, 0, bar_ctl_length))) {
        ret = -ENOMEM;
        goto cleanup;
    }

    ret = pci_request_region(pdev, 1, pci_name(pdev));
    if (ret)
        goto cleanup;
    bar_ram_length = pci_resource_len(pdev, 1);
    if (bar_ram_length && !(bar_ram = pci_iomap(pdev, 1, bar_ram_length))) {
        ret = -ENOMEM;
        goto cleanup;
    }
    ret = pci_request_region(pdev, 2, pci_name(pdev));
    if (ret)
        goto cleanup;
    bar_busio_length = pci_resource_len(pdev, 2);
    if (bar_busio_length && !(bar_busio = pci_iomap(pdev, 2, bar_busio_length))) {
        ret = -ENOMEM;
        goto cleanup;
    }

    DBG("bar ctl len %lu", bar_ctl_length);
    DBG("bar ram len %lu", bar_ram_length);
    DBG("bar io len %lu", bar_busio_length);

    ret = request_irq(pdev->irq, pci_platform_irq,
                    IRQF_NOBALANCING | IRQF_TRIGGER_RISING, DRV_NAME, pdev);
    if (ret) {
        dev_warn(&pdev->dev, "request_irq failed err=%d\n", ret);
        goto cleanup;
    }
    irq_initialized = 1;

    scan_devices();

out:
    return ret;
cleanup:
    if (irq_initialized) {
       free_irq(pdev->irq, pdev);
       irq_initialized = 0;
    }
    if (bar_ram)
        pci_iounmap(pdev, bar_ram);
    if (bar_ctl)
        pci_iounmap(pdev, bar_ctl);
    if (bar_busio)
        pci_iounmap(pdev, bar_busio);
    pci_disable_device(pdev);
    goto out;
}


static struct pci_device_id pci_platform_tbl[]
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
    __devinitdata
#endif
    = {
        {PCI_VENDOR_ID_XEN, PCI_DEVICE_ID_UXEN_PLATFORM,
                PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
        {0,}
};

MODULE_DEVICE_TABLE(pci, pci_platform_tbl);
static struct pci_driver pci_platform_driver = {
    .name   =           DRV_NAME,
    .probe  =           pci_platform_probe,
    .remove =           pci_platform_remove,
    .id_table =         pci_platform_tbl,
};

void pci_platform_exit(void)
{
    pci_unregister_driver(&pci_platform_driver);
}

int pci_platform_init(struct bus_type *_uxen_bus)
{
    int ret = 0;

    uxen_bus = _uxen_bus;
    ret = pci_register_driver(&pci_platform_driver);
    if (ret)
        goto out;

    printk(KERN_INFO "uxenplatform device initialized\n");
out:
    return ret;
}
