/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DEV_H_
#define _DEV_H_

#include "dict.h"
#include "irq.h"
#include "qemu_queue.h"
#include "vmstate.h"

#include "qemu/module.h"

dict config_devices;

enum {
    DEV_NVECTORS_UNSPECIFIED = -1,
};

struct DeviceState {
    const char *id;
    int hotplugged;
    DeviceInfo *info;
    BusState *parent_bus;
    LIST_HEAD(, BusState) child_bus;
    int num_child_bus;
    TAILQ_ENTRY(DeviceState) sibling;
    int instance_id_alias;
    int alias_required_for_version;
};

struct Property {
    const char   *name;
    PropertyInfo *info;
    int          offset;
    int          bitnr;
    void         *defval;
};

enum PropertyType {
    PROP_TYPE_UNSPEC = 0,
    PROP_TYPE_UINT8,
    PROP_TYPE_UINT16,
    PROP_TYPE_UINT32,
    PROP_TYPE_INT32,
    PROP_TYPE_UINT64,
    PROP_TYPE_TADDR,
    PROP_TYPE_MACADDR,
    PROP_TYPE_DRIVE,
    PROP_TYPE_CHR,
    PROP_TYPE_STRING,
    PROP_TYPE_NETDEV,
    PROP_TYPE_VLAN,
    PROP_TYPE_PTR,
    PROP_TYPE_BIT,
};

struct PropertyInfo {
    const char *name;
    size_t size;
    enum PropertyType type;
    int (*parse)(DeviceState *dev, Property *prop, const char *str);
    int (*print)(DeviceState *dev, Property *prop, char *dest, size_t len);
    void (*free)(DeviceState *dev, Property *prop);
};

typedef char *(*bus_get_dev_path)(DeviceState *dev);
// typedef int (qbus_resetfn)(BusState *bus);

struct BusInfo {
    const char *name;
    size_t size;
    bus_get_dev_path get_dev_path;
    // qbus_resetfn *reset;
    Property *props;
};

struct BusState {
    DeviceState *parent;
    BusInfo *info;
    const char *name;
    int allow_hotplug;
    int qdev_allocated;
    TAILQ_HEAD(ChildrenHead, DeviceState) children;
    LIST_ENTRY(BusState) sibling;
};

typedef int (*qdev_initfn)(DeviceState *dev, DeviceInfo *info);
typedef int (*qdev_event)(DeviceState *dev);
typedef void (*qdev_resetfn)(DeviceState *dev);

struct DeviceInfo {
    const char *name;
    const char *desc;
    size_t size;
    Property *props;

    qdev_resetfn reset;

    const VMStateDescription *vmsd;

    qdev_initfn init;
    qdev_event unplug;
    qdev_event exit;
    BusInfo *bus_info;

    SLIST_ENTRY(DeviceInfo) next;
};

DeviceState *dev_create(BusState *bus, const char *name);
DeviceState *dev_try_create(BusState *bus, const char *name);
int dev_init(DeviceState *dev);
void dev_init_nofail(DeviceState *dev);
void dev_free(DeviceState *dev);

void dev_register(DeviceInfo *info);
BusState *dev_get_parent_bus(DeviceState *dev);
void bus_create_inplace(BusState *bus, BusInfo *info,
			DeviceState *parent, const char *name);
BusState *bus_create(BusInfo *info, DeviceState *parent, const char *name);
void dev_reset_all(DeviceState *dev);
void bus_free(BusState *bus);

void process_config_devices(void);

#endif	/* _DEV_H_ */
