/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/pci.h>
#include <dm/qemu/net.h>

#include <dm/block.h>
#include <dm/dmpdev.h>
#include <dm/hw.h>
#include <dm/firmware.h>

#include "uxen_platform.h"
#include <uxen/platform_interface.h>

struct null_net_state {
    UXenPlatformDevice dev;
    NICState *nic;
    NICConf conf;
};

static int
null_net_can_receive(VLANClientState *nc)
{
    return 1;
}

static ssize_t
null_net_receive(VLANClientState *nc, const uint8_t *buf, size_t size)
{
    return size;
}

static void
null_net_cleanup(VLANClientState *nc)
{
}

static NetClientInfo null_net_client_info = {
    .type = NET_CLIENT_TYPE_NIC,
    .size = sizeof (NICState),
    .can_receive = null_net_can_receive,
    .receive = null_net_receive,
    .cleanup = null_net_cleanup,
};

static int
null_net_initfn(UXenPlatformDevice *dev)
{
    struct null_net_state *s = DO_UPCAST(struct null_net_state, dev, dev);
    extern unsigned slirp_mru;
    uint16_t mru;

    qemu_macaddr_default_if_unset(&s->conf.macaddr);

    s->nic = qemu_new_nic(&null_net_client_info,
                          &s->conf,
                          dev->qdev.info->name,
                          dev->qdev.id, s);

    qemu_format_nic_info_str(&s->nic->nc, s->conf.macaddr.a);

    uxenplatform_device_add_property(dev, UXENBUS_PROPERTY_TYPE_MACADDR,
                                     s->conf.macaddr.a, 6);
    mru = htons(slirp_mru);
    uxenplatform_device_add_property(dev, UXENBUS_PROPERTY_TYPE_MTU,
                                     &mru, 2);

    return 0;
}

static const VMStateDescription vmstate_null_net = {
    .name = "null_net",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields = (VMStateField[]) {
        VMSTATE_MACADDR(conf.macaddr, struct null_net_state),
        VMSTATE_END_OF_LIST ()
    },
};

static UXenPlatformDeviceInfo null_net_info = {
    .qdev.name = "null_net",
    .qdev.size = sizeof (struct null_net_state),
    .qdev.vmsd = &vmstate_null_net,
    .init = null_net_initfn,
    .devtype = UXENBUS_DEVICE_TYPE_NULL_NET,
    .qdev.props = (Property[]) {
        DEFINE_NIC_PROPERTIES(struct null_net_state, conf),
        DEFINE_PROP_END_OF_LIST (),
    },
};

static void
null_register_devices (void)
{
    uxenplatform_qdev_register(&null_net_info);
}

device_init(null_register_devices);
