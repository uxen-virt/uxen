/*
 * Copyright 2016-2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/init.h>
#include <linux/device.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/module.h>

#include <uxen-v4vlib.h>
#include <uxen-platform.h>
#include <uxenkbddefs.h>

static unsigned char keycodes[256] = { 0 };

struct uxenkbd_dev {
    struct device dev;
    struct input_dev *idev;
    uxen_v4v_ring_t *uxen_ring;
    v4v_addr_t uxen_dest_addr;
    int ready;
    int dev_registered;
    struct tasklet_struct tasklet;
};

static struct uxenkbd_dev ukbd;

static void uxenkbd_irq(void *opaque)
{
    struct uxenkbd_dev *dev = opaque;

    tasklet_schedule(&dev->tasklet);
}

static int uxenkbd_status(struct input_dev *idev, unsigned int type,
                            unsigned int code, int value)
{
    return 0; // FIXME
}

static inline int is_event_supported(unsigned int code,
				     unsigned long *bm, unsigned int max)
{
	return code <= max && test_bit(code, bm);
}

static void uxenkbd_softirq(unsigned long opaque)
{
    struct uxenkbd_dev *dev = (struct uxenkbd_dev *) opaque;
    size_t readlen;
    ssize_t len;

    if (!dev->ready || !dev->idev)
        return;

    if (!dev->uxen_ring)
        return;

    readlen = 0;
    while (readlen <= UXEN_KBD_RING_LEN) {
        struct ns_event_msg_kbd_input kdata;

        len = uxen_v4v_copy_out(dev->uxen_ring, NULL, NULL, NULL, 0, 0);
        if (len <= 0)
            break;
        if (len < sizeof(kdata.hdr))
            goto consume;
        if (len < UXEN_MIN_KBD_PKT_LEN)
            goto consume;
        if (len > sizeof(kdata))
            len = sizeof(kdata);


        uxen_v4v_copy_out(dev->uxen_ring, NULL, NULL, &kdata, len, 0);
        if (kdata.hdr.proto != NS_EVENT_MSG_KBD_INPUT)
            goto consume;

        if (!protvm_use_secure_keyboard) {
            u8 trans_keycode;

            input_event(dev->idev, EV_MSC, MSC_SCAN, kdata.scancode & 0x7f);
            trans_keycode = keycodes[kdata.scancode & 0x7f];
            input_report_key(dev->idev, trans_keycode, (kdata.scancode & 0x80) ? 0 : 1);
            input_sync(dev->idev);
        }

        consume:
            len = uxen_v4v_copy_out(dev->uxen_ring, NULL, NULL, NULL, 0, 1);
            if (len > 0)
                readlen += len;
    }

    if (readlen)
        uxen_v4v_notify();
}

static int v4v_init_rings(struct uxenkbd_dev *dev)
{
    int ret = -1;

    dev->uxen_dest_addr.port = UXEN_KBD_V4V_PORT;
    dev->uxen_dest_addr.domain = V4V_DOMID_DM;

    tasklet_init(&dev->tasklet, uxenkbd_softirq, (unsigned long) dev);

    dev->uxen_ring = uxen_v4v_ring_bind(dev->uxen_dest_addr.port, dev->uxen_dest_addr.domain,
                                       UXEN_KBD_RING_LEN, uxenkbd_irq, dev);
    if (!dev->uxen_ring) {
        ret = -ENOMEM;
        goto out;
    }
    if (IS_ERR(dev->uxen_ring)) {
        ret = PTR_ERR(dev->uxen_ring);
        dev->uxen_ring = NULL;
        goto out;
    }

    if (protvm_use_secure_keyboard)
        printk("uxenkbd: using secure keyboard\n");
    ret = 0;

out:
    if (ret)
        tasklet_kill(&dev->tasklet);
    return ret;
}

static void v4v_rings_free(struct uxenkbd_dev *dev)
{
    if (dev->uxen_ring)
        tasklet_kill(&dev->tasklet);
    if (dev->uxen_ring)
        uxen_v4v_ring_free(dev->uxen_ring);
    dev->uxen_ring = NULL;
}

static void ukbd_device_release(struct device *dev)
{

}

static void ukbd_free(void)
{
    v4v_rings_free(&ukbd);
    if (ukbd.idev)
        input_unregister_device(ukbd.idev);
    if (ukbd.dev_registered)
        device_unregister(&ukbd.dev);
}

static int __init uxenkbd_init(void)
{
    int ret = 0, i;

    memset(&ukbd, 0, sizeof(ukbd));
    dev_set_name(&ukbd.dev, "uxenkbd");
    ukbd.dev.release = ukbd_device_release;
    if ((ret = device_register(&ukbd.dev))) {
        printk(KERN_WARNING "%s: cannot register device , err %d\n",
                __FUNCTION__, ret);
        goto cleanup;
    }
    ukbd.dev_registered = 1;

    ret = v4v_init_rings(&ukbd);
    if (ret)
        goto cleanup;

    ukbd.idev = input_allocate_device();
    if (!ukbd.idev) {
        ret = -ENOMEM;
        goto cleanup;
    }
    input_set_drvdata(ukbd.idev, &ukbd);
    ukbd.idev->event = uxenkbd_status;

    /* FIXME! is it really 1 to 1 ? */
    for (i = 0; i < ARRAY_SIZE(keycodes); i++)
        keycodes[i] = i;

    ukbd.idev->name = "uXen keyboard";
    ukbd.idev->id.bustype = BUS_HOST;
    ukbd.idev->dev.parent = &ukbd.dev;
    ukbd.idev->keycode = keycodes;
    ukbd.idev->keycodesize = sizeof(unsigned short);
    ukbd.idev->keycodemax = ARRAY_SIZE(keycodes);

    for (i = 0; i < ARRAY_SIZE(keycodes); i++) {
        if (keycodes[i] != KEY_RESERVED)
            __set_bit(keycodes[i], ukbd.idev->keybit);
    }
    input_set_capability(ukbd.idev, EV_MSC, MSC_SCAN);
    __set_bit(EV_KEY, ukbd.idev->evbit);
    __set_bit(EV_REP, ukbd.idev->evbit);

    ret = input_register_device(ukbd.idev);
    if (ret)
        goto cleanup;

    ukbd.ready = 1;

out:
    return ret;
cleanup:
    ukbd_free();
    goto out;
}

static void __exit uxenkbd_exit(void)
{
    ukbd_free();
}

module_init(uxenkbd_init);
module_exit(uxenkbd_exit);
MODULE_AUTHOR("paulian.marinca@bromium.com");
MODULE_DESCRIPTION("uXen Linux kbd input driver");
MODULE_LICENSE("GPL");
