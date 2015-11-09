/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <ctype.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include "block.h"
#include "dev.h"
#include "opts.h"
#include "sysbus.h"
#include "qemu_qdev-prop.h"

dict config_devices = NULL;
static int dev_hotplug = 0;

static BusState _main_system_bus = {
    .info = &system_bus_info,
    .parent = NULL,
    .name = "main-system-bus",
    .children = TAILQ_HEAD_INITIALIZER(_main_system_bus.children),
};
static BusState *main_system_bus = &_main_system_bus;

SLIST_HEAD(, DeviceInfo) device_info_list =
    SLIST_HEAD_INITIALIZER(&device_info_list);

void dev_machine_creation_done(void)
{
    dev_hotplug = 1;
}

static DeviceInfo *
dev_find_info(BusInfo *bus_info, const char *name)
{
    DeviceInfo *info;

    SLIST_FOREACH(info, &device_info_list, next) {
	if (bus_info && bus_info != info->bus_info)
	    continue;
	if (!strcmp(name, info->name))
	    return info;
    }

    return NULL;
}

DeviceState *
dev_create_from_info(BusState *bus, DeviceInfo *info)
{
    DeviceState *dev;

    dev = calloc(1, info->size);
    dev->info = info;
    dev->parent_bus = bus;
    qdev_prop_set_defaults(dev, dev->info->props);
    qdev_prop_set_defaults(dev, dev->parent_bus->info->props);
    TAILQ_INSERT_HEAD(&bus->children, dev, sibling);
    if (dev_hotplug)
        dev->hotplugged = 1;
    dev->instance_id_alias = -1;

    return dev;
}

DeviceState *
dev_create(BusState *bus, const char *name)
{
    DeviceState *dev;

    dev = dev_try_create(bus, name);
    if (!dev)
	errx(1, "dev_create %s for bus %s", name,
	     bus ? bus->info->name : "system default");

    return dev;
}

DeviceState *
dev_try_create(BusState *bus, const char *name)
{
    DeviceInfo *info;

    if (!bus)
	bus = main_system_bus;

    info = dev_find_info(bus->info, name);
    if (!info)
	return NULL;

    return dev_create_from_info(bus, info);
}

int
dev_init(DeviceState *dev)
{
    int ret;

    ret = dev->info->init(dev, dev->info);
    if (ret < 0) {
	dev_free(dev);
	return ret;
    }
    if (dev->info->vmsd)
        vmstate_register_with_alias_id(dev, -1, dev->info->vmsd, dev,
                                       dev->instance_id_alias,
                                       dev->alias_required_for_version);

    if (dev->info->reset)
	dev->info->reset(dev);

    return 0;
}

void
dev_init_nofail(DeviceState *dev)
{
    DeviceInfo *info = dev->info;

    if (dev_init(dev) < 0)
	errx(1, "dev_init %s failed", info->name);
}

void
dev_free(DeviceState *dev)
{
    Property *prop;

    if (dev->info->exit)
	dev->info->exit(dev);

    TAILQ_REMOVE(&dev->parent_bus->children, dev, sibling);
    for (prop = dev->info->props; prop && prop->name; prop++)
        if (prop->info->free)
            prop->info->free(dev, prop);

    free(dev);
}

void
dev_register(DeviceInfo *info)
{
    SLIST_INSERT_HEAD(&device_info_list, info, next);
}

BusState *
dev_get_parent_bus(DeviceState *dev)
{
    return dev->parent_bus;
}

void
bus_create_inplace(BusState *bus, BusInfo *info,
		   DeviceState *parent, const char *name)
{
    char *c;

    bus->info = info;
    bus->parent = parent;

    if (name)
	bus->name = strdup(name);
    else if (parent && parent->id)
	asprintf((char **)&bus->name, "%s.%d", parent->id,
		 parent->num_child_bus);
    else {
	asprintf((char **)&bus->name, "%s.%d", info->name,
		 parent ? parent->num_child_bus : 0);
	for (c = (char *)bus->name; *c; c++)
	    *c = tolower(*c);
    }
    TAILQ_INIT(&bus->children);
    if (parent) {
	LIST_INSERT_HEAD(&parent->child_bus, bus, sibling);
	parent->num_child_bus++;
    }
}

void
bus_free(BusState *bus)
{
    DeviceState *dev;

    while ((dev = TAILQ_FIRST(&bus->children)) != NULL) {
        dev_free(dev);
    }
    if (bus->parent) {
        LIST_REMOVE(bus, sibling);
        bus->parent->num_child_bus--;
    }
    if (bus->name)
        free((char *)bus->name);

    free(bus);
}

BusState *
bus_create(BusInfo *info, DeviceState *parent, const char *name)
{
    BusState *bus;

    bus = calloc(1, info->size);
    bus_create_inplace(bus, info, parent, name);
    return bus;
}

void
dev_reset_all(DeviceState *dev)
{
    debug_break();
}

static BusState *
find_bus(BusState *bus, const BusInfo *info)
{
    DeviceState *dev/* , *ret */;
    BusState *child, *ret;

    TAILQ_FOREACH(dev, &bus->children, sibling) {
        LIST_FOREACH(child, &dev->child_bus, sibling) {
            if (child->info == info)
                return child;
            ret = find_bus(child, info);
            if (ret)
                return ret;
        }
    }

    return NULL;
}

static int
set_property(const char *name, const char *value, void *opaque)
{
    DeviceState *dev = opaque;

    if (strcmp(name, "driver") == 0)
        return 0;
    if (strcmp(name, "bus") == 0)
        return 0;
    if (strcmp(name, "id") == 0)
        return 0;

    return qdev_prop_parse(dev, name, value);
}

void
process_config_devices(void)
{
    dict v;
    unsigned int i;
    const char *driver, *id;
    DeviceInfo *info;
    BusState *bus;
    DeviceState *dev;
    int ret;

    if (!config_devices)
        return;

    ARRAY_FOREACH(v, config_devices, i) {
        driver = dict_get_string(v, "driver");
        if (!driver)
            errx(1, "%s: device with no 'driver'", __FUNCTION__);
        info = dev_find_info(NULL, driver);
        if (!info)
            errx(1, "%s: unknown device driver '%s'", __FUNCTION__, driver);
        bus = NULL;
        if (info->bus_info)
            bus = find_bus(main_system_bus, info->bus_info);
        if (!bus)
            bus = main_system_bus;
        dev = dev_create_from_info(bus, info);
        if (!dev)
            errx(1, "%s: failed to create device with driver '%s'",
                 __FUNCTION__, driver);
        id = dict_get_string(v, "id");
        if (id) {
            dev->id = strdup(id);
            if (!dev->id)
                err(1, "%s: stdrup", __FUNCTION__);
        }
        ret = dict_opt_foreach(v, set_property, dev, 1);
        if (ret != 0)
            errx(1, "%s: failed to set properties for device with driver '%s'",
                 __FUNCTION__, driver);
        ret = dev_init(dev);
        if (ret < 0)
            errx(1, "%s: failed to init device with driver '%s'",
                 __FUNCTION__, driver);
    }
}

int dev_unplug(DeviceState *dev)
{
    if (!dev->parent_bus->allow_hotplug)
        return -1;

    assert(dev->info->unplug != NULL);

    return dev->info->unplug(dev);
}
