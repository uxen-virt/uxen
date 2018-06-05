/*
 * Copyright 2016-2018, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_PLATFORM_H_
#define _UXEN_PLATFORM_H_

#include <linux/device.h>

#define UXEN_PLATFORM_DEBUG 1

#if UXEN_PLATFORM_DEBUG
#define DBG(fmt, ...) printk(KERN_DEBUG "(uxen-debug) %s: " fmt "\n", __FUNCTION__, ## __VA_ARGS__)
#else
#define DBG(fmt, ...) do { } while(0)
#endif

struct uxen_device {
    struct device dev;
    int type;
    int instance;
    size_t slot;
    void *priv;

    int (*get_property)(struct uxen_device *dev, int prop_id, void *prop, size_t *prop_len);
};

struct uxen_driver {
    struct device_driver drv;
    int type;
    int (*probe) (struct uxen_device *dev);
    int (*remove) (struct uxen_device *dev);
    int (*suspend) (struct uxen_device *dev);
    int (*resume) (struct uxen_device *dev);
};

static inline struct uxen_device *dev_to_uxen(struct device *_dev)
{
    return _dev ? container_of(_dev, struct uxen_device, dev) : NULL;
}

static inline struct uxen_driver *drv_to_uxen(struct device_driver *_drv)
{
    return _drv ? container_of(_drv, struct uxen_driver, drv) : NULL;
}

static inline int uxen_device_get_property(struct uxen_device *dev, int prop_id,
                                           void *prop, size_t *prop_len)
{
    if (!dev->get_property)
        return -ENODEV;
    return dev->get_property(dev, prop_id, prop, prop_len);
}


int uxen_driver_register(struct uxen_driver *drv);
void uxen_driver_unregister(struct uxen_driver *drv);

extern int protvm_use_secure_keyboard;

#endif
