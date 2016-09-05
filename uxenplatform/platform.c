/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/init.h>
#include <linux/device.h>
#include <linux/module.h>

#include <uxen-hypercall.h>
#include <uxen-platform.h>
#include "ax.h"
#include "pci.h"

extern void uxen_v4v_suspend(void);
extern void uxen_v4v_resume(void);

static int bus_match(struct device *_dev, struct device_driver *_drv)
{
    struct uxen_device *dev = dev_to_uxen(_dev);
    struct uxen_driver *drv = drv_to_uxen(_drv);

    return !!(dev && drv && dev->type == drv->type);
}

static int bus_probe(struct device *_dev)
{
    struct uxen_device *dev = dev_to_uxen(_dev);
    struct uxen_driver *drv = drv_to_uxen(_dev->driver);

    return drv && drv->probe ? drv->probe(dev) : -ENODEV;
}

static int bus_remove(struct device *_dev)
{
    struct uxen_device *dev = dev_to_uxen(_dev);
    struct uxen_driver *drv = drv_to_uxen(_dev->driver);

    if (dev && drv && drv->remove)
       drv->remove(dev);
    return 0;
}

static int bus_suspend(struct device *_dev, pm_message_t state)
{
    struct uxen_device *dev = dev_to_uxen(_dev);
    struct uxen_driver *drv = drv_to_uxen(_dev->driver);

    if (drv->suspend)
        drv->suspend(dev);
    uxen_v4v_suspend();
    return 0;
}

static int bus_resume(struct device *_dev)
{
    struct uxen_device *dev = dev_to_uxen(_dev);
    struct uxen_driver *drv = drv_to_uxen(_dev->driver);

    uxen_v4v_resume();
    if (drv->resume)
        drv->resume(dev);
    return 0;
}

static int device_remove(struct device *_dev, void *data)
{
    struct uxen_device *dev = dev_to_uxen(_dev);
    struct uxen_driver *drv = drv_to_uxen(_dev->driver);

    if (dev && drv && drv->remove)
        drv->remove(dev);
    device_unregister(_dev);
    return 0;
}

static struct bus_type uxen_bus = {
    .name =		"uxen",
    .match =		bus_match,
    .probe =		bus_probe,
    .remove =		bus_remove,
    .suspend =          bus_suspend,
    .resume =           bus_resume,
};

int uxen_driver_register(struct uxen_driver *drv)
{
    drv->drv.bus = &uxen_bus;
    return driver_register(&drv->drv);
}
EXPORT_SYMBOL_GPL(uxen_driver_register);

void uxen_driver_unregister(struct uxen_driver *drv)
{
    driver_unregister(&drv->drv);
}
EXPORT_SYMBOL_GPL(uxen_driver_unregister);

static int __init uxen_platform_init(void)
{
    int ret = -ENODEV;

    ret = bus_register(&uxen_bus);
    if (ret) {
        printk(KERN_WARNING "%s: bus_register failed err=%d", __FUNCTION__, ret);
        return ret;
    }

#ifdef LX_TARGET_AX
    ret = ax_platform_init(&uxen_bus);
#elif defined(LX_TARGET_UXEN)
    ret = pci_platform_init(&uxen_bus);
#else
    ret = -ENODEV;
#endif

    if (ret)
        bus_unregister(&uxen_bus);

    return ret;
}

static void __exit uxen_platform_exit(void)
{
    bus_for_each_dev(&uxen_bus, NULL, NULL, device_remove);
    bus_unregister(&uxen_bus);

#ifdef LX_TARGET_AX
    ax_platform_exit();
#elif defined(LX_TARGET_UXEN)
    pci_platform_exit();
#endif
}

module_init(uxen_platform_init);
module_exit(uxen_platform_exit);
MODULE_AUTHOR("paulian.marinca@bromium.com");
MODULE_DESCRIPTION("uXen Linux platform driver");
MODULE_LICENSE("GPL");
