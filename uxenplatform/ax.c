/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/device.h>
#include <linux/slab.h>
#include <uxen-platform.h>
#include <uxen/platform_interface.h>

static int device_net_get_property(struct uxen_device *dev,
                                   int prop_id, void *prop, size_t *prop_len)
{
    if (prop_id == UXENBUS_PROPERTY_TYPE_MTU && *prop_len == sizeof(u16)) {
        *((u16 *) prop) = htons(16384);
        return 0;
    }

    if (prop_id == UXENBUS_PROPERTY_TYPE_MACADDR && *prop_len == 6) {
        // 52:54:00:12:34:56
        *(((u8 *) prop) + 0) = 0x52;
        *(((u8 *) prop) + 1) = 0x54;
        *(((u8 *) prop) + 2) = 0x00;
        *(((u8 *) prop) + 3) = 0x12;
        *(((u8 *) prop) + 4) = 0x34;
        *(((u8 *) prop) + 5) = 0x56;

        return 0;
    }

    return -EINVAL;
}

static void device_release(struct device *_dev)
{
    struct uxen_device *dev = dev_to_uxen(_dev);

    kfree(dev);
}

int ax_platform_init(struct bus_type *uxen_bus)
{
    int err;
    struct uxen_device *dev;

    // add nic
    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;
    dev->type = UXENBUS_DEVICE_TYPE_NET;
    dev->dev.bus = uxen_bus;
    dev->dev.release = device_release;
    dev->get_property = device_net_get_property;
    dev_set_name(&dev->dev, "%s-0", "uxennet");

    if ((err = device_register(&dev->dev))) {
        printk(KERN_WARNING "%s: device_register failed %d", __FUNCTION__, err);
        kfree(dev);
    }

    // add hid
    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;
    dev->type = UXENBUS_DEVICE_TYPE_HID;
    dev->dev.bus = uxen_bus;
    dev->dev.release = device_release;
    dev_set_name(&dev->dev, "%s-0", "uxenhid");

    if ((err = device_register(&dev->dev))) {
        printk(KERN_WARNING "%s: device_register failed %d", __FUNCTION__, err);
        kfree(dev);
    }

    return 0;
}

void ax_platform_exit(void)
{

}
