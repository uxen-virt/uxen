/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <xen/xen.h>
#include <uxen/platform_interface.h>

#include <uxen-v4vlib.h>
#include <uxen-platform.h>
#include <uxen-util.h>

#define DEFAULT_MTU 1500
#define V4V_BASE_PORT 0xc0000
#define V4V_RING_LEN 131072

struct uxennet_dev {
    struct net_device *ndev;
    uxen_v4v_ring_t *recv_ring;
    v4v_addr_t dest_addr;
    int ready;
    u32 vmtu;
    u32 if_num;
    unsigned char vmac[6];
    int vmac_ok;
    struct tasklet_struct tasklet;
};

static int uxennet_eth_open(struct net_device *ndev)
{
    struct uxennet_dev *dev = netdev_priv(ndev);

    /* the device is ready */
    netif_carrier_on(ndev);
    netif_start_queue(ndev);
    dev->ready = 1;

    return 0;
}

static int uxennet_eth_close(struct net_device *ndev)
{
    netif_tx_disable(ndev);
    return 0;
}

static int
uxennet_eth_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
    ssize_t r;
    struct uxennet_dev *dev = netdev_priv(ndev);

    if (!dev->recv_ring) {
        netif_stop_queue(ndev);
        return NETDEV_TX_BUSY;
    }

    r = uxen_v4v_send_from_ring(dev->recv_ring, &dev->dest_addr, skb->data, skb->len,
                                V4V_PROTO_DGRAM);

    if (r > 0 && r == skb->len) {
        dev->ndev->stats.tx_packets++;
        dev->ndev->stats.tx_bytes += skb->len;
    } else {
        ndev->stats.tx_dropped++;
    }

    dev_kfree_skb_any(skb);
    return NETDEV_TX_OK;
}

static int uxennet_eth_change_mtu(struct net_device *dev, int mtu)
{
    return 0;
}

static void uxennet_irq(void *opaque)
{
    struct uxennet_dev *dev = opaque;

    tasklet_schedule(&dev->tasklet);
}

static void uxennet_softirq(unsigned long opaque)
{
    ssize_t len;
    size_t readlen = 0;
    struct uxennet_dev *dev = (struct uxennet_dev *) opaque;
    struct net_device *ndev = dev->ndev;

    if (!dev->ready)
        return;

    BUG_ON(dev->recv_ring == NULL);

    while (readlen <= V4V_RING_LEN) {
        struct sk_buff *skb;

        len = uxen_v4v_copy_out(dev->recv_ring, NULL, NULL, NULL, 0, 0);
        if (len <= 0)
            break;
        readlen += len;

        skb = netdev_alloc_skb(ndev, len);
        if (!skb) {
            uxen_v4v_copy_out(dev->recv_ring, NULL, NULL, NULL, 0, 1);
            ndev->stats.rx_errors++;
            ndev->stats.rx_dropped++;
            continue;
        }

        uxen_v4v_copy_out(dev->recv_ring, NULL, NULL, skb_put(skb, len), len, 1);
        skb->protocol = eth_type_trans(skb, ndev);

        if (netif_rx(skb) == NET_RX_DROP) {
            ndev->stats.rx_errors++;
            ndev->stats.rx_dropped++;
        } else {
            ndev->stats.rx_packets++;
            ndev->stats.rx_bytes += len;
        }
    }

    if (readlen)
        uxen_v4v_notify();
}

static const struct net_device_ops uxennet_eth_netdev_ops = {
    .ndo_open               = uxennet_eth_open,
    .ndo_stop               = uxennet_eth_close,
    .ndo_start_xmit         = uxennet_eth_start_xmit,
    .ndo_change_mtu         = uxennet_eth_change_mtu,
    .ndo_validate_addr      = eth_validate_addr,
    .ndo_set_mac_address    = eth_mac_addr,
};

static int netdev_enable(struct net_device *ndev)
{
    ndev->netdev_ops = &uxennet_eth_netdev_ops;

    return register_netdev(ndev);
}

static int v4v_ring_init(struct uxennet_dev *dev)
{
    int ret = 0;

    dev->dest_addr.port = V4V_BASE_PORT + dev->if_num;
    dev->dest_addr.domain = V4V_DOMID_DM;
    tasklet_init(&dev->tasklet, uxennet_softirq, (unsigned long) dev);
    dev->recv_ring = uxen_v4v_ring_bind(dev->dest_addr.port, dev->dest_addr.domain,
                                        V4V_RING_LEN, uxennet_irq, dev);
    if (!dev->recv_ring) {
        ret = -ENOMEM;
        goto out;
    }
    if (IS_ERR(dev->recv_ring)) {
        ret = PTR_ERR(dev->recv_ring);
        dev->recv_ring = NULL;
        goto out;
    }

    ret = 0;

out:
    if (ret)
        tasklet_kill(&dev->tasklet);
    return ret;
}

static void v4v_ring_free(struct uxennet_dev *dev)
{
    if (dev->recv_ring) {
        uxen_v4v_ring_free(dev->recv_ring);
        tasklet_kill(&dev->tasklet);
    }
    dev->recv_ring = NULL;
}

static int uxennet_probe(struct uxen_device *device)
{
    int ret = 0;
    struct net_device *ndev;
    struct uxennet_dev *dev;
    size_t sz;
    u16 mtu;

    ndev = alloc_etherdev(sizeof(struct uxennet_dev));
    if (!ndev) {
        ret = -ENOMEM;
        goto out;
    }
    dev = netdev_priv(ndev);
    memset(dev, 0, sizeof(*dev));
    dev->ndev = ndev;
    SET_NETDEV_DEV(ndev, &device->dev);
    netif_stop_queue(ndev);

    dev->if_num = device->instance;
    device->priv = dev;

    mtu = 0;
    sz = sizeof(mtu);
    ret = uxen_device_get_property(device, UXENBUS_PROPERTY_TYPE_MTU, &mtu, &sz);
    if (ret)
        mtu = DEFAULT_MTU;
    else
        mtu = ntohs(mtu);
    dev->vmtu = mtu;
    ndev->mtu = mtu;

    memset(dev->vmac, 0, sizeof(dev->vmac));
    sz = sizeof(dev->vmac);
    ret = uxen_device_get_property(device, UXENBUS_PROPERTY_TYPE_MACADDR, dev->vmac, &sz);
    if (ret) {
        printk(KERN_INFO "%s: cannot obain MAC adders err %d\n", __FUNCTION__, ret);
        goto cleanup;
    }

    memcpy(ndev->dev_addr, &dev->vmac[0], 6);
    dev->vmac_ok = 1;

    printk(KERN_INFO "uxennet: MTU %u\n", (unsigned) dev->vmtu);
    printk(KERN_INFO "uxennet: MAC %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
           dev->vmac[0], dev->vmac[1], dev->vmac[2],
           dev->vmac[3], dev->vmac[4], dev->vmac[5]);

    dev->ready = 0;
    ret = v4v_ring_init(dev);
    if (ret)
        goto cleanup;

    ret = netdev_enable(ndev);
    if (ret)
        goto cleanup;

out:
    return ret;

cleanup:
    free_netdev(ndev);
    ndev = NULL;
    device->priv = NULL;
    goto out;
}

static int uxennet_remove(struct uxen_device *device)
{
    struct uxennet_dev *dev = device->priv;

    if (!dev)
        return -EINVAL;

    if (dev->ndev) {
        unregister_netdev(dev->ndev);
        free_netdev(dev->ndev);
        dev->ndev = NULL;
    }

    v4v_ring_free(dev);

    return 0;
}

static struct uxen_driver uxennet_driver = {
    .drv = {
        .name = "uxennet",
        .owner = THIS_MODULE,
    },
    .type = UXENBUS_DEVICE_TYPE_NET,
    .probe = uxennet_probe,
    .remove = uxennet_remove,
};

static int __init uxennet_init(void)
{
    return uxen_driver_register(&uxennet_driver);
}

static void __exit uxennet_exit(void)
{
    uxen_driver_unregister(&uxennet_driver);
}

module_init(uxennet_init);
module_exit(uxennet_exit);
MODULE_AUTHOR("paulian.marinca@bromium.com");
MODULE_DESCRIPTION("uXen net");
MODULE_LICENSE("GPL");
