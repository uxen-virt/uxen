/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/kobject.h>
#include <linux/proc_fs.h>
#include <linux/miscdevice.h>

#include <asm/uaccess.h>
#include <uxen-platform.h>
#include <uxen-hypercall.h>
#include <uxen/platform_interface.h>
#include <ax_attovm.h>
#include <ax_attovm_stub.h>

static uint64_t features;
static uint64_t appdef_size;
static void *appdef;
static uint64_t secret_salt;
static struct kobject *attovm_kobj;
static struct kobject *ax_kobj;
static struct proc_dir_entry *attovm_proc;
static struct proc_dir_entry *appdef_proc;
static struct miscdevice attovm_secret_dev;
extern int use_rdrand, use_rdseed;


/**
 * sys/kernel/attovm/features
 */
static ssize_t features_show(struct kobject *kobj, struct kobj_attribute *attr,
    char *buf)
{
    sprintf(buf, "0x%016llx\n", features);

    return 19;
}

static ssize_t features_store(struct kobject *kobj, struct kobj_attribute *attr,
    const char *buf, size_t count)
{
    return 0;
}

static struct kobj_attribute features_attribute =
  __ATTR(features, 0440, features_show,  features_store);

static ssize_t appdef_read(struct file * file, char __user * buf, size_t size, loff_t * ppos)
{
    loff_t cur = *ppos;

    if (cur + size > appdef_size)
        size = appdef_size - cur;

    if (copy_to_user(buf, appdef + cur, size))
        return -EFAULT;

    *ppos = cur + size;

    return size;
}

static int appdef_open(struct inode *inode, struct file *file)
{
    size_t map_size;
    void *mem;

    if (appdef)
        return 0;

    map_size = appdef_size + 8;
    map_size = (map_size + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
    mem = ioremap(0x100000000ULL, map_size);
    if (!mem)
        return -ENOMEM;
    appdef = mem + 8;

    return 0;
}

static const struct file_operations appdef_file_ops = {
    .owner = THIS_MODULE,
    .open  = appdef_open,
    .read  = appdef_read,
};


static ssize_t secret_read(struct file * file, char __user * buf, size_t size, loff_t * ppos)
{
    uint8_t secret[ATTOVM_SECRET_KEY_BYTES] = { 0 };
    loff_t cur = *ppos;
    int err;

    if (cur + size > ATTOVM_SECRET_KEY_BYTES)
        size = ATTOVM_SECRET_KEY_BYTES - cur;

    err = attovm_call_query_secret_key(secret, secret_salt);
    if (err) {
        printk(KERN_WARNING "%s: failed to query secret key: %d\n", __FUNCTION__, err);
        return -EFAULT;
    }

    if (copy_to_user(buf, secret + cur, size))
        return -EFAULT;

    *ppos = cur + size;

    return size;
}

static ssize_t secret_write(struct file * file, const char __user * buf, size_t size, loff_t * ppos)
{
    if (size >= sizeof(secret_salt)) {
        if (copy_from_user(&secret_salt, buf, sizeof(secret_salt)))
            return -EFAULT;
        return sizeof(secret_salt);
    }

    return -EFAULT;
}

static const struct file_operations attovm_secret_file_ops = {
    .owner = THIS_MODULE,
    .read  = secret_read,
    .write = secret_write,
};

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

static int init_devices(struct bus_type *uxen_bus)
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

    return 0;
}

static int init_sysfs(void)
{
    int err;

    attovm_kobj = kobject_create_and_add("attovm", kernel_kobj);
    if (!attovm_kobj) {
      printk(KERN_WARNING "%s: failed to create kobject", __FUNCTION__);
      return -ENOMEM;
    }

    err = sysfs_create_file(attovm_kobj, &features_attribute.attr);
    if (err) {
      printk(KERN_WARNING "%s: failed to create sysfs file: %d\n", __FUNCTION__, err);
      return err;
    }

    /* ax only attributes */
    if (axen_hypervisor()) {
        ax_kobj = kobject_create_and_add("ax", attovm_kobj);
        if (!ax_kobj) {
            printk(KERN_WARNING "%s: failed to create kobject", __FUNCTION__);
            return -ENOMEM;
        }
    }

    return 0;
}

static int init_procfs(void)
{
    void *mem;

    attovm_proc = proc_mkdir("attovm", NULL);
    if (!attovm_proc)
        return -ENOMEM;

    appdef_proc = proc_create("appdef", 0, attovm_proc, &appdef_file_ops);
    if (!appdef_proc)
        return -ENOMEM;

    /* figure out appdef size */
    mem = ioremap(0x100000000ULL, PAGE_SIZE);
    if (!mem)
        return -ENOMEM;
    appdef_size = *(uint64_t*)mem;
    iounmap(mem);

    proc_set_size(appdef_proc, appdef_size);

    return 0;
}

int attovm_platform_init(struct bus_type *bus)
{
    int ret;

    use_rdrand = arch_has_random();
    use_rdseed = arch_has_random_seed();
    if (!use_rdrand && !use_rdseed) {
      printk(KERN_WARNING "RDRAND/RDSEED not available but required");
      return -ENODEV;
    }

    ret = init_devices(bus);
    if (ret)
        return ret;
    ret = init_sysfs();
    if (ret)
        return ret;
    ret = init_procfs();
    if (ret)
        return ret;

    if (axen_hypervisor()) {
        attovm_secret_dev.minor = MISC_DYNAMIC_MINOR;
        attovm_secret_dev.name = "attovm_secret";
        attovm_secret_dev.fops = &attovm_secret_file_ops;
        ret = misc_register(&attovm_secret_dev);
        if (ret)
            return ret;
    }

    features = attovm_call_queryop(ATTOCALL_QUERYOP_FEATURES, 0, 0, 0);
    printk("%s: attovm features 0x%x\n", __FUNCTION__, (unsigned) features);

    protvm_use_secure_keyboard = !!(features & ATTOCALL_QUERYOP_FEATURES_PROT_KBD);

    return 0;
}

void attovm_platform_exit(void)
{
    if (axen_hypervisor())
        misc_deregister(&attovm_secret_dev);

    if (appdef_proc)
        proc_remove(appdef_proc);

    if (attovm_proc)
        proc_remove(attovm_proc);

    if (appdef)
        iounmap(appdef);

    if (ax_kobj)
        kobject_put(ax_kobj);

    if (attovm_kobj)
        kobject_put(attovm_kobj);
}


