/*
 * Copyright 2015, Bromium, Inc.
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

#define NULL_NET_MAX 6

struct null_net_state {
    ISADevice dev;
    NICState *nic;
    NICConf conf;
    uint8_t disabled;
};

struct null_enum_state {
    ISADevice dev;
    unsigned int index;
    struct null_net_state *nics[NULL_NET_MAX];
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
null_net_initfn(ISADevice *dev)
{
    struct null_net_state *s = DO_UPCAST(struct null_net_state, dev, dev);

    qemu_macaddr_default_if_unset(&s->conf.macaddr);

    s->nic = qemu_new_nic(&null_net_client_info,
                          &s->conf,
                          dev->qdev.info->name,
                          dev->qdev.id, s);

    qemu_format_nic_info_str(&s->nic->nc, s->conf.macaddr.a);

    return 0;
}

static const VMStateDescription vmstate_null_net = {
    .name = "null_net",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields = (VMStateField[]) {
        VMSTATE_MACADDR(conf.macaddr, struct null_net_state),
        VMSTATE_UINT8(disabled, struct null_net_state),
        VMSTATE_END_OF_LIST ()
    },
};

static ISADeviceInfo null_net_info = {
    .qdev.name = "null_net",
    .qdev.size = sizeof (struct null_net_state),
    .qdev.vmsd = &vmstate_null_net,
    .init = null_net_initfn,
    .qdev.props = (Property[]) {
        DEFINE_NIC_PROPERTIES(struct null_net_state, conf),
        DEFINE_PROP_END_OF_LIST (),
    },
};

/*******************************************************/

static void
null_enum_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    struct null_enum_state *s = opaque;
    struct null_net_state *n;

    addr &= 0xF;

    debug_printf("%s: addr=%x val=%x\n", __FUNCTION__, addr, val);

    switch (addr) {
    case 0:
        s->index = val & 0xff;
        break;
    case 1:
        n = s->nics[s->index];
        if (!n)
            break;
        n->disabled = val;
        break;
    default:
        break;
    }
}

static uint32_t
null_enum_ioport_read(void *opaque, uint32_t addr)
{
    uint32_t ret;
    struct null_enum_state *s = opaque;
    struct null_net_state *n;

    addr &= 0xF;

    if (s->index >= NULL_NET_MAX)
        return 0xff;
    n = s->nics[s->index];

    switch (addr) {
    case 0:
        ret = s->index;
        break;
    case 1:
        ret = 0;
        if (n)
            ret = n->disabled ? 0x0D : 0x0F;
        break;
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
        ret = n ? n->conf.macaddr.a[addr - 2] : 0xff;
        break;
    default:
        ret = 0xff;
    }

    debug_printf("%s: addr=%x ret=%x\n", __FUNCTION__, addr, ret);

    return ret;
}

static int
null_enum_initfn(ISADevice *dev)
{
    struct null_enum_state *s = DO_UPCAST(struct null_enum_state, dev, dev);

    debug_printf("%s\n", __FUNCTION__);

    register_ioport_read(0x820, 16, 1, null_enum_ioport_read, s);
    register_ioport_write(0x820, 16, 1, null_enum_ioport_write, s);

    return 0;
}

int
null_enum_add_child(ISADevice *dev, unsigned int index, ISADevice *child)
{
    struct null_enum_state *s = DO_UPCAST(struct null_enum_state, dev, dev);
    struct null_net_state *n = DO_UPCAST(struct null_net_state, dev, child);

    debug_printf("%s: index=%d child=%p\n", __FUNCTION__, index, child);

    if (index >= NULL_NET_MAX)
        return -1;

    s->nics[index] = n;

    return 0;
}

static const VMStateDescription vmstate_null_enum = {
    .name = "null_enum",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(index, struct null_enum_state),
        VMSTATE_END_OF_LIST (),
    },
};

static ISADeviceInfo null_enum_info = {
    .qdev.name = "null_enum",
    .qdev.size = sizeof (struct null_enum_state),
    .qdev.vmsd = &vmstate_null_enum,
    .init = null_enum_initfn,
    .qdev.props = (Property[]) {
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void
null_register_devices (void)
{
    isa_qdev_register(&null_net_info);
    isa_qdev_register(&null_enum_info);
}

device_init(null_register_devices);
