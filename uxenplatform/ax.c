/*
 * Copyright 2016-2018, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/kobject.h>
#include <uxen-platform.h>
#include <uxen/platform_interface.h>

extern int use_rdrand;
static struct kobject *ax_kobj;

#define SESSION_KEY_BYTES 64
#define AX_CPUID_QUERYOP 0x35af3471
#define AX_QUERYOP_TSC_KHZ 1
#define AX_QUERYOP_SESSION_KEY 2

static
uint32_t ax_queryop(uint32_t op, uint64_t arg1)
{
  register void* _rax asm ("rax") = (void*)(uintptr_t)AX_CPUID_QUERYOP;
  register void* _rcx asm ("rcx") = (void*)(uintptr_t)op;
  register void* _rdx asm ("rdx") = (void*)(uintptr_t)arg1;
  register void* _r8  asm ("r8")  = (void*)0;

  asm volatile (
    "cpuid"
    : "+r" (_rax), "+r" (_rcx), "+r" (_rdx), "+r" (_r8)
    :
    : "cc"
  );

  return (uint32_t)(uintptr_t)_rax;
}

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

static ssize_t sessionkey_show(struct kobject *kobj, struct kobj_attribute *attr,
                      char *buf)
{
    uint8_t sessionkey[SESSION_KEY_BYTES] = { 0 };
    int i, err;

    err = ax_queryop(AX_QUERYOP_SESSION_KEY, &sessionkey[0]);
    if (err) {
        printk(KERN_WARNING "%s: failed to query session key: %d\n", __FUNCTION__, err);
        return 0;
    }

    for (i = 0; i < SESSION_KEY_BYTES; i++) {
        sprintf(buf + i*2, "%02x", sessionkey[i]);
    }
    sprintf(buf + SESSION_KEY_BYTES * 2, "\n");

    return SESSION_KEY_BYTES * 2 + 1;
}

static ssize_t sessionkey_store(struct kobject *kobj, struct kobj_attribute *attr,
                      char *buf, size_t count)
{
    return 0;
}

static struct kobj_attribute sessionkey_attribute =
  __ATTR(sessionkey, 0440, sessionkey_show,  sessionkey_store);

int ax_platform_init(struct bus_type *uxen_bus)
{
    int err;
    struct uxen_device *dev;

    use_rdrand = arch_has_random();
    if (!use_rdrand) {
      printk(KERN_WARNING "RDRAND not available but required");
      return -ENODEV;
    }

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

    // add fb
    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;
    dev->type = UXENBUS_DEVICE_TYPE_FB;
    dev->dev.bus = uxen_bus;
    dev->dev.release = device_release;
    dev_set_name(&dev->dev, "%s-0", "uxenfb");

    if ((err = device_register(&dev->dev))) {
        printk(KERN_WARNING "%s: device_register failed %d", __FUNCTION__, err);
        kfree(dev);
    }

    // add stor
    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;
    dev->type = UXENBUS_DEVICE_TYPE_STOR;
    dev->dev.bus = uxen_bus;
    dev->dev.release = device_release;
    dev_set_name(&dev->dev, "%s-0", "uxenstor");

    if ((err = device_register(&dev->dev))) {
        printk(KERN_WARNING "%s: device_register failed %d", __FUNCTION__, err);
        kfree(dev);
    }

    ax_kobj = kobject_create_and_add("ax", kernel_kobj);
    if (!ax_kobj) {
      printk(KERN_WARNING "%s: failed to create kobject", __FUNCTION__);
      return -ENOMEM;
    }

    err = sysfs_create_file(ax_kobj, &sessionkey_attribute.attr);
    if (err) {
      printk(KERN_WARNING "%s: failed to create sysfs file: %d\n", __FUNCTION__, err);
      return err;
    }

    return 0;
}

void ax_platform_exit(void)
{
  if (ax_kobj)
    kobject_put(ax_kobj);
}
