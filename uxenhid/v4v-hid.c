/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/input.h>
#include <linux/hid.h>

#include <xen/xen.h>
#include <uxen/platform_interface.h>

#include <uxen-hypercall.h>
#include <uxen-v4vlib.h>
#include <uxen-util.h>
#include <uxen-platform.h>

#include <uxenhid-common.h>

#define V4V_RING_LEN 131072
#define REPORT_BUFFER_DEFAULT_LEN 1024

#define DEBUG_UXENHID

#ifdef DEBUG_UXENHID
#define DPRINTF(fmt, ...) printk(KERN_INFO "uxenhid: " fmt, ##__VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#endif

struct uxenhid_request {
	struct list_head entry;
	struct completion comp;
	u8 report_id;
	u8 report_type;
	u8 *buf;
	size_t buf_len;
	int result;
};

struct uxenhid_sendv {
	struct list_head entry;
	struct completion comp;
	size_t count;
	v4v_iov_t iov[];
};

struct uxenhid_dev {
	struct hid_device *hdev;
	v4v_addr_t peer;
	uxen_v4v_ring_t *ring;
	spinlock_t v4v_lock;

	struct completion report_desc_completion;
	u8 *report_desc;
	size_t report_desc_len;

	struct list_head req_list;
	spinlock_t req_lock;
	struct list_head snd_list;
	spinlock_t snd_lock;

	u8 *report_buffer;
	size_t report_buffer_len;

	struct tasklet_struct tasklet;
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0))
static int hid_report_len(struct hid_report *report)
{
        /* equivalent to DIV_ROUND_UP(report->size, 8) + !!(report->id > 0) */
        return ((report->size - 1) >> 3) + 1 + (report->id > 0);
}
#endif

/* Requests */
static struct uxenhid_request *
request_lookup(struct uxenhid_dev *dev, u8 report_id, u8 report_type)
{
	struct uxenhid_request *req;

	BUG_ON(!spin_is_locked(&dev->req_lock));

	list_for_each_entry(req, &dev->req_list, entry) {
		if (req->report_id == req->report_id &&
		    req->report_type == req->report_type)
		    return req;
	}

	return NULL;
}

/* V4V */

static void v4v_ring_event(void *opaque)
{
	struct uxenhid_dev *dev = (void *)opaque;

	tasklet_schedule(&dev->tasklet);
}

static void uxenhid_bh(unsigned long opaque)
{
	struct uxenhid_dev *dev = (void *)opaque;
	UXENHID_MSG_HEADER hdr;
	ssize_t len;
	struct uxenhid_sendv *sendv, *sendv_t;

	spin_lock(&dev->v4v_lock);
	/* TX */
	spin_lock(&dev->snd_lock);
	list_for_each_entry_safe(sendv, sendv_t, &dev->snd_list, entry) {
		if (uxen_v4v_sendv_from_ring(dev->ring, &dev->peer, sendv->iov,
					     sendv->count, V4V_PROTO_DGRAM) < 0)
			break;
		list_del(&sendv->entry);
		complete(&sendv->comp);
	}
	spin_unlock(&dev->snd_lock);

	/* RX */
	len = uxen_v4v_copy_out(dev->ring, NULL, NULL, &hdr, sizeof(hdr), 0);
	while (len >= 0) {
		if (len < sizeof(hdr)) {
			uxen_v4v_copy_out(dev->ring, NULL, NULL, NULL, 0, 1);
			len = uxen_v4v_copy_out(dev->ring, NULL, NULL, &hdr,
						sizeof(hdr), 0);
			continue;
		}
		if (hdr.type == UXENHID_REQUEST_REPORT_DESCRIPTOR &&
		    hdr.msglen < (65536 + sizeof (hdr)) &&
		    !dev->report_desc) {

			dev->report_desc_len = (u16)(hdr.msglen - sizeof (hdr));
			if ((dev->report_desc = kmalloc(dev->report_desc_len,
							GFP_ATOMIC))) {
				uxen_v4v_copy_out_offset(dev->ring, NULL, NULL,
						         dev->report_desc,
						         sizeof(hdr) + hdr.msglen,
						         1, sizeof (hdr));
				complete(&dev->report_desc_completion);
			}
		}
		if (hdr.type == UXENHID_FEATURE_REPORT &&
		    hdr.msglen >= (sizeof(u8) + sizeof(hdr))) {
			u8 report_id;
			struct uxenhid_request *req;

			/* Read report id without consuming */
			uxen_v4v_copy_out_offset(dev->ring, NULL, NULL, &report_id,
						 sizeof(hdr) + sizeof(u8), 0,
						 sizeof(hdr));

			spin_lock(&dev->req_lock);
			req = request_lookup(dev, report_id, HID_FEATURE_REPORT);
			if (req) {
				list_del(&req->entry);
				spin_unlock(&dev->req_lock);
				if (req->buf_len < (hdr.msglen - sizeof(hdr))) {
					uxen_v4v_copy_out(dev->ring, NULL, NULL, NULL,
					0, 1);
					req->result = -ENOMEM;
				} else {
					uxen_v4v_copy_out_offset(dev->ring,
								 NULL, NULL,
								 req->buf,
								 sizeof(hdr) + hdr.msglen,
								 1,
								 sizeof(hdr));
					req->result = hdr.msglen - sizeof(hdr);
				}
				complete(&req->comp);

				goto next;
			}
			spin_unlock(&dev->req_lock);

			/*
			 * This feature report was not queried, treat is as a normal
			 * report.
			 */
			hdr.type = UXENHID_REPORT;
		}

		if (hdr.type == UXENHID_REPORT &&
		    hdr.msglen >= (sizeof(u8) + sizeof(hdr))) {
			u8 report_id;
			struct uxenhid_request *req;

			/* Read report id without consuming */
			uxen_v4v_copy_out_offset(dev->ring, NULL, NULL, &report_id,
					         sizeof(hdr) + sizeof(u8), 0,
						 sizeof(hdr));

			spin_lock(&dev->req_lock);
			req = request_lookup(dev, report_id, HID_INPUT_REPORT);
			if (req) {
				list_del(&req->entry);
				spin_unlock(&dev->req_lock);
				if (req->buf_len < (hdr.msglen - sizeof(hdr))) {
					uxen_v4v_copy_out(dev->ring, NULL, NULL, NULL, 0, 1);
					req->result = -ENOMEM;
				} else {
					uxen_v4v_copy_out_offset(dev->ring,
							         NULL, NULL,
							         req->buf,
							         sizeof(hdr) + hdr.msglen,
								 1,
							         sizeof(hdr));
					req->result = hdr.msglen - sizeof(hdr);
				}
				complete(&req->comp);

				goto next;
			}
			spin_unlock(&dev->req_lock);

			if (dev->report_buffer &&
			    dev->report_buffer_len >= (hdr.msglen - sizeof(hdr))) {
				uxen_v4v_copy_out_offset(dev->ring, NULL, NULL,
						         dev->report_buffer,
						         sizeof(hdr) + hdr.msglen, 1,
						         sizeof(hdr));
				hid_input_report(dev->hdev, HID_INPUT_REPORT,
						 dev->report_buffer,
						 hdr.msglen - sizeof(hdr),
						 1);

				goto next;
			}
		}

		/* Consume */
		uxen_v4v_copy_out(dev->ring, NULL, NULL, NULL, 0, 1);
next:
		len = uxen_v4v_copy_out(dev->ring, NULL, NULL, &hdr, sizeof (hdr), 0);
	}
	spin_unlock(&dev->v4v_lock);

	uxen_v4v_notify();
}

static int
uxenhid_v4v_send(struct uxenhid_dev *dev, struct iovec *iov, size_t iov_len)
{
	size_t i;
	ssize_t s = 0;
	struct uxenhid_sendv *sendv;

	sendv = kmalloc(sizeof(struct uxenhid_sendv) + iov_len * sizeof(v4v_iov_t),
		        GFP_KERNEL);
	if (!sendv)
		return -ENOMEM;

	for (i = 0; i < iov_len; i++) {
		sendv->iov[i].iov_base = (uint64_t)(uintptr_t)iov[i].iov_base;
		sendv->iov[i].iov_len = (uint64_t)iov[i].iov_len;
	}
	sendv->count = iov_len;
	init_completion(&sendv->comp);

	spin_lock_bh(&dev->snd_lock);
	if (!list_empty(&dev->snd_list) ||
	    (s = uxen_v4v_sendv_from_ring(dev->ring, &dev->peer, sendv->iov, iov_len,
					  V4V_PROTO_DGRAM)) == -EAGAIN) {
		list_add_tail(&sendv->entry, &dev->snd_list);
		spin_unlock_bh(&dev->snd_lock);
		wait_for_completion(&sendv->comp);
	} else
		spin_unlock_bh(&dev->snd_lock);

	kfree(sendv);

	if (s < 0)
		return s;

	return 0;
}

static int uxenhid_v4v_device_start(struct uxenhid_dev *dev)
{
	UXENHID_MSG_HEADER hdr;
	struct iovec iov[1];

	hdr.type = UXENHID_DEVICE_START;
	hdr.msglen = sizeof(UXENHID_MSG_HEADER);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);

	return uxenhid_v4v_send(dev, iov, 1);
}

static int uxenhid_v4v_device_stop(struct uxenhid_dev *dev)
{
	UXENHID_MSG_HEADER hdr;
	struct iovec iov[1];

	hdr.type = UXENHID_DEVICE_STOP;
	hdr.msglen = sizeof(UXENHID_MSG_HEADER);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);

	return uxenhid_v4v_send(dev, iov, 1);
}

static int uxenhid_v4v_request_report_descriptor(struct uxenhid_dev *dev)
{
	UXENHID_MSG_HEADER hdr;
	struct iovec iov[1];

	hdr.type = UXENHID_REQUEST_REPORT_DESCRIPTOR;
	hdr.msglen = sizeof(UXENHID_MSG_HEADER);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);

	return uxenhid_v4v_send(dev, iov, 1);
}

static int uxenhid_v4v_feature_request(struct uxenhid_dev *dev, u8 report_id)
{
	UXENHID_MSG_HEADER hdr;
	struct iovec iov[2];

	hdr.type = UXENHID_FEATURE_QUERY;
	hdr.msglen = sizeof(UXENHID_MSG_HEADER) + sizeof(u8);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = &report_id;
	iov[1].iov_len = sizeof(u8);

	return uxenhid_v4v_send(dev, iov, 2);
}

static int uxenhid_v4v_output_report(struct uxenhid_dev *dev, u8 report_id,
				     u8 *buf, size_t len)
{
	UXENHID_MSG_HEADER hdr;
	struct iovec iov[3];

	hdr.type = UXENHID_REPORT;
	hdr.msglen = sizeof(UXENHID_MSG_HEADER) + sizeof(u8) + len;
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = &report_id;
	iov[1].iov_len = sizeof(u8);
	iov[2].iov_base = buf;
	iov[2].iov_len = len;

	return uxenhid_v4v_send(dev, iov, 3);
}

static int uxenhid_v4v_output_raw_report(struct uxenhid_dev *dev, u8 *buf, size_t len)
{
	UXENHID_MSG_HEADER hdr;
	struct iovec iov[2];

	hdr.type = UXENHID_REPORT;
	hdr.msglen = sizeof(UXENHID_MSG_HEADER) + len;
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = buf;
	iov[1].iov_len = len;

	return uxenhid_v4v_send(dev, iov, 2);
}

/* HID Low-Level Driver */

static int uxenhid_start(struct hid_device *hdev)
{
	return 0;
}

static void uxenhid_stop(struct hid_device *hdev)
{
}

static int uxenhid_open(struct hid_device *hdev)
{
	return 0;
}

static void uxenhid_close(struct hid_device *hdev)
{
}

static int uxenhid_parse(struct hid_device *hdev)
{
	struct uxenhid_dev *dev = hdev->driver_data;
	struct hid_report_enum *report_enum;
	struct hid_report *report;
	size_t size = 0;
	int ret;

	ret = hid_parse_report(hdev, dev->report_desc, dev->report_desc_len);
	if (ret)
		return ret;

	report_enum = hdev->report_enum + HID_INPUT_REPORT;
	list_for_each_entry(report, &report_enum->report_list, list) {
		size_t s = hid_report_len(report);
		if (s > size)
			size = s;
	}

	if (size > dev->report_buffer_len) {
		spin_lock_bh(&dev->v4v_lock);
		kfree(dev->report_buffer);
		dev->report_buffer_len = 0;
		dev->report_buffer = kmalloc(size, GFP_KERNEL);
		if (!dev->report_buffer)
			return -ENOMEM;
		dev->report_buffer_len = size;
		spin_unlock_bh(&dev->v4v_lock);
	}

	return 0;
}

static int uxenhid_output_report(struct hid_device *hdev, __u8 *buf, size_t count)
{
	struct uxenhid_dev *dev = hdev->driver_data;

	return uxenhid_v4v_output_raw_report(dev, buf, count);
}

static int uxenhid_get_report(struct uxenhid_dev *dev, unsigned char report_id,
			      u8 *buf, size_t len, uint8_t rtype)
{
	struct uxenhid_request *req;
	int ret;

	switch (rtype) {
	case HID_FEATURE_REPORT:
	case HID_INPUT_REPORT:
		break;
	case HID_OUTPUT_REPORT:
	default:
		return -EINVAL;
	}

	req = kmalloc(sizeof(struct uxenhid_request), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	init_completion(&req->comp);
	req->report_id = report_id;
	req->report_type = rtype;
	req->buf = buf;
	req->buf_len = len;

	spin_lock_bh(&dev->req_lock);
	list_add_tail(&req->entry, &dev->req_list);
	spin_unlock_bh(&dev->req_lock);

	if (rtype == HID_FEATURE_REPORT) {
		ret = uxenhid_v4v_feature_request(dev, report_id);
		if (ret) {
			spin_lock_bh(&dev->req_lock);
			list_del(&req->entry);
			spin_unlock_bh(&dev->req_lock);
			goto release;
		}
	}

	wait_for_completion(&req->comp);
	ret = req->result;

release:
	kfree(req);

	return ret;
}

static int uxenhid_set_report(struct uxenhid_dev *dev, unsigned char report_id,
			      u8 *buf, size_t len, uint8_t rtype)
{
	switch (rtype) {
	case HID_OUTPUT_REPORT:
		return uxenhid_v4v_output_report(dev, report_id, buf, len);
	case HID_FEATURE_REPORT:
	case HID_INPUT_REPORT:
	default:
		return -EINVAL;
	}
}

static int uxenhid_raw_request(struct hid_device *hdev, unsigned char reportnum,
			       __u8 *buf, size_t len, unsigned char rtype,
			       int reqtype)
{
	struct uxenhid_dev *dev = hdev->driver_data;

	switch (reqtype) {
	case HID_REQ_GET_REPORT:
		return uxenhid_get_report(dev, reportnum, buf, len, rtype);
	case HID_REQ_SET_REPORT:
		return uxenhid_set_report(dev, reportnum, buf, len, rtype);
	default:
		return -EIO;
	}
}

static struct hid_ll_driver uxenhid_ll_driver = {
	.start = uxenhid_start,
	.stop = uxenhid_stop,
	.open = uxenhid_open,
	.close = uxenhid_close,
	.parse = uxenhid_parse,
	.raw_request = uxenhid_raw_request,
	.output_report = uxenhid_output_report,
};

/* Device Initialization */

static int v4v_ring_init(struct uxenhid_dev *dev)
{
	int ret = 0;

	spin_lock_init(&dev->v4v_lock);
	dev->peer.port = 0xe0000;
	dev->peer.domain = V4V_DOMID_DM;
	dev->ring = uxen_v4v_ring_bind(dev->peer.port, dev->peer.domain,
				       V4V_RING_LEN, v4v_ring_event, dev);
	if (!dev->ring)
		return -ENOMEM;
	if (IS_ERR(dev->ring))
		ret = PTR_ERR(dev->ring);

	return ret;
}

static void v4v_ring_free(struct uxenhid_dev *dev)
{
	if (dev->ring)
		uxen_v4v_ring_free(dev->ring);

	dev->ring = NULL;
}

static struct completion probe_event;

static int uxenhid_probe(struct uxen_device *device)
{
	int ret = 0;
	struct uxenhid_dev *dev;
	struct hid_device *hdev;

	dev = kmalloc(sizeof(struct uxenhid_dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto err_dev_alloc;
	}

	hdev = hid_allocate_device();
	if (!hdev) {
		ret = -ENOMEM;
		goto err_hid_alloc;
	}

	hdev->driver_data = dev;
	hdev->ll_driver = &uxenhid_ll_driver;
	hdev->dev.parent = &device->dev; /* ...not sure */
	hdev->bus = BUS_ISAPNP; /* ...or something else */
	hdev->version = 0x0001;
	hdev->vendor = 0x2345;
	hdev->product = 0x4564;
	snprintf(hdev->name, sizeof(hdev->name), "uXenHID %04hX:%04hX",
		 hdev->vendor, hdev->product);

	dev->hdev = hdev;

	tasklet_init(&dev->tasklet, uxenhid_bh, (unsigned long)dev);
	dev->report_desc = NULL;
	dev->report_desc_len = 0;
	init_completion(&dev->report_desc_completion);
	INIT_LIST_HEAD(&dev->req_list);
	spin_lock_init(&dev->req_lock);
	INIT_LIST_HEAD(&dev->snd_list);
	spin_lock_init(&dev->snd_lock);

	dev->report_buffer = kmalloc(REPORT_BUFFER_DEFAULT_LEN, GFP_KERNEL);
	if (!dev->report_buffer)
		goto err_report_buf_alloc;
	dev->report_buffer_len = REPORT_BUFFER_DEFAULT_LEN;

	device->priv = dev;

	ret = v4v_ring_init(dev);
	if (ret)
		goto err_v4v_ring;

	ret = uxenhid_v4v_device_start(dev);
	if (ret)
		goto err_start;

	ret = uxenhid_v4v_request_report_descriptor(dev);
	if (ret)
		goto err_req_desc;

	wait_for_completion(&dev->report_desc_completion);

	ret = hid_add_device(hdev);
	if (ret)
		goto err_hid_add;

	complete(&probe_event);

	return ret;
err_hid_add:
	kfree(dev->report_desc);
err_req_desc:
	uxenhid_v4v_device_stop(dev);
err_start:
	v4v_ring_free(dev);
err_v4v_ring:
	kfree(dev->report_buffer);
	dev->report_buffer_len = 0;
err_report_buf_alloc:
	hid_destroy_device(hdev);
err_hid_alloc:
	kfree(dev);
err_dev_alloc:
	complete(&probe_event);
	return ret;
}

static int uxenhid_remove(struct uxen_device *device)
{
	struct uxenhid_dev *dev = device->priv;

	kfree(dev->report_desc);

	uxenhid_v4v_device_stop(dev);

	v4v_ring_free(dev);
	tasklet_kill(&dev->tasklet);

	kfree(dev->report_buffer);
	dev->report_buffer_len = 0;

	if (dev->hdev)
		hid_destroy_device(dev->hdev);

	kfree(dev);

	return 0;
}

static struct uxen_driver uxenhid_driver = {
    .drv = {
        .name = "uxenhid",
        .owner = THIS_MODULE,
    },
    .type = UXENBUS_DEVICE_TYPE_HID,
    .probe = uxenhid_probe,
    .remove = uxenhid_remove,
};

static int __init uxenhid_init(void)
{
	int ret;

	init_completion(&probe_event);
	ret = uxen_driver_register(&uxenhid_driver);
	if (ret)
	    goto out;
	if (wait_for_completion_timeout(&probe_event, 5 * HZ) == 0) {
		uxen_driver_unregister(&uxenhid_driver);
		printk(KERN_INFO "%s: timeout on uxen_driver_register init\n", __FUNCTION__);
			ret = -ETIMEDOUT;
			goto out;
	}
out:
	return ret;
}

static void __exit uxenhid_exit(void)
{
	uxen_driver_unregister(&uxenhid_driver);
}

module_init(uxenhid_init);
module_exit(uxenhid_exit);
MODULE_AUTHOR("julian.pidancet@bromium.com");
MODULE_DESCRIPTION("uXen HID");
MODULE_LICENSE("GPL");
