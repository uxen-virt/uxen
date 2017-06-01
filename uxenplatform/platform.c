/*
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/init.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/kthread.h>

#include <uxen-hypercall.h>
#include <uxen-platform.h>
#include "ax.h"
#include "pci.h"

static struct task_struct *entropy_thread;

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

    if (drv && drv->suspend)
        drv->suspend(dev);
    uxen_v4v_suspend();
    return 0;
}

static int bus_resume(struct device *_dev)
{
    struct uxen_device *dev = dev_to_uxen(_dev);
    struct uxen_driver *drv = drv_to_uxen(_dev->driver);

    uxen_v4v_resume();
    if (drv && drv->resume)
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

extern void add_hwgenerator_randomness(const char *buffer, size_t count,
    size_t entropy);

/*
 * FIXME: this fills entropy pool (on demand) from tsc values, so it is always full.
 * Pretty terrible and likely not random enough
 */
static int
uxen_entropy_thread(void *data)
{
    for (;;) {
        uint64_t tsc = rdtsc();
        add_hwgenerator_randomness((const char*)&tsc, sizeof(tsc), sizeof(tsc)*8);
    }

    return 0;
}

static int __init uxen_platform_init(void)
{
    int ret = -ENODEV;

    ret = bus_register(&uxen_bus);
    if (ret) {
        printk(KERN_WARNING "%s: bus_register failed err=%d", __FUNCTION__, ret);
        return ret;
    }

#ifndef CONFIG_PCI
    /* no pci, assume ax vm */
    ret = ax_platform_init(&uxen_bus);
#else
    if (axen_hypervisor())
      ret = ax_platform_init(&uxen_bus);
    else if (uxen_hypervisor())
      ret = pci_platform_init(&uxen_bus);
    else
      ret = -ENODEV;
#endif

    if (ret) {
        bus_unregister(&uxen_bus);
        goto out;
    }

    entropy_thread = kthread_run(uxen_entropy_thread, NULL, "uxentropy");
    if (!entropy_thread) {
      ret = -ENOMEM;
      goto out;
    }
out:

    return ret;
}

static void __exit uxen_platform_exit(void)
{
    if (entropy_thread)
        kthread_stop(entropy_thread);
    bus_for_each_dev(&uxen_bus, NULL, NULL, device_remove);
    bus_unregister(&uxen_bus);

#ifndef CONFIG_PCI
    ax_platform_exit();
#else
    if (axen_hypervisor())
      ax_platform_exit();
    else if (uxen_hypervisor())
      pci_platform_exit();
#endif
}

module_init(uxen_platform_init);
module_exit(uxen_platform_exit);
MODULE_AUTHOR("paulian.marinca@bromium.com");
MODULE_DESCRIPTION("uXen Linux platform driver");
MODULE_LICENSE("GPL");
