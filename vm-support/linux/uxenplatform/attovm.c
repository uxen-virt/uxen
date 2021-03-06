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
#include <linux/uaccess.h>
#include <linux/interrupt.h>

#include <uxen-platform.h>
#include <uxen-hypercall.h>
#include <uxen-v4vlib.h>
#include <uxen/platform_interface.h>
#include <ax_attovm.h>
#include <ax_attovm_stub.h>
#include <attocall_dev.h>

#define ATTOCALL_DEV_NAME "attocall"
#define ATTOCALL_CLASS_NAME "ax"


static uint64_t features;
static uint64_t appdef_size;
static void *appdef;
static uint64_t secret_salt;
static struct kobject *attovm_kobj;
static struct kobject *ax_kobj;
static struct proc_dir_entry *attovm_proc;
static struct proc_dir_entry *appdef_proc;
static uxen_v4v_ring_t *echo_ring;
static struct tasklet_struct echo_tasklet;
static struct miscdevice attovm_secret_dev;
extern int use_rdrand, use_rdseed;

int attodev_major = -1;
struct class *attodev_class = NULL;
struct device *attodev_dev = NULL;

#define UXEN_ECHO_PORT 8888
#define UXEN_ECHO_RING_SIZE 4096
#define UXENECHO_PACKED __attribute__((packed))

struct uxenecho_msg {
  uint64_t id;
} UXENECHO_PACKED;

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
  __ATTR(features, 0444, features_show, features_store);

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

    map_size = (appdef_size + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
    mem = ioremap(ATTOVM_APPDEF_PHYSADDR, map_size);
    if (!mem)
        return -ENOMEM;
    appdef = mem;

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


static int attodev_open(struct inode *in, struct file *filep)
{
    return 0;
}

static ssize_t attodev_read(struct file *filep, char *buf, size_t len, loff_t *off)
{
    return -ENOSYS;
}

static ssize_t attodev_write(struct file *filep, const char *buf, size_t len, loff_t *off)
{
    struct attocallev_t ev;

    if (len != sizeof (ev))
        return -EINVAL;
    if (copy_from_user(&ev, buf, len))
        return -EFAULT;

    switch (ev.arg0) {
    case ATTOCALL_KBD_OP:
        return attovm_call_kbd_op (ev.arg1, ev.arg2);
    default:
        return -EPERM;
    }

    return -EINVAL;
}

static int attodev_release(struct inode *in, struct file *filep)
{
    return 0;
}

static struct file_operations attodev_fops =
{
    .open = attodev_open,
    .read = attodev_read,
    .write = attodev_write,
    .release = attodev_release,
};

int init_attocall_dev(void)
{
    attodev_major = register_chrdev (0, ATTOCALL_DEV_NAME, &attodev_fops);
    if (attodev_major < 0)
        return attodev_major;

    attodev_class = class_create(THIS_MODULE, ATTOCALL_CLASS_NAME);
    if (IS_ERR(attodev_class)) {
        unregister_chrdev(attodev_major, ATTOCALL_DEV_NAME);
        return PTR_ERR(attodev_class);
    }

    attodev_dev = device_create(attodev_class, NULL, MKDEV(attodev_major, 0), NULL,
                                 ATTOCALL_DEV_NAME);
    if (IS_ERR(attodev_dev)) {
        class_destroy(attodev_class);
        unregister_chrdev(attodev_major, ATTOCALL_DEV_NAME);
        return PTR_ERR(attodev_dev);
    }

    return 0;
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
    attovm_proc = proc_mkdir("attovm", NULL);
    if (!attovm_proc)
        return -ENOMEM;

    appdef_proc = proc_create("appdef", 0, attovm_proc, &appdef_file_ops);
    if (!appdef_proc)
        return -ENOMEM;

    /* figure out appdef size */
    appdef_size = attovm_call_queryop(ATTOCALL_QUERYOP_APPDEF_SIZE, 0, 0, 0);

    proc_set_size(appdef_proc, appdef_size);

    return 0;
}

static void echo_irq(void *opaque)
{
    tasklet_schedule(&echo_tasklet);
}

static void echo_softirq(unsigned long opaque)
{
    uxen_v4v_ring_t *ring = echo_ring;
    v4v_addr_t from;
    uint32_t proto;
    struct uxenecho_msg msg;
    int len, err;

    if (!ring)
        return;

    for (;;) {
        len = uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 0);
        if (len <= 0 || len < sizeof(msg))
            break;
        uxen_v4v_copy_out(ring, &from, &proto, &msg, sizeof(msg), 1);
        uxen_v4v_notify();
#ifdef ECHO_DEBUG
        printk("echo: request id=%d received\n", (int)msg.id);
#endif
        /* send resp */
        from.domain = V4V_DOMID_DM;
        err = uxen_v4v_send_from_ring(ring, &from, &msg, sizeof(msg),
            V4V_PROTO_DGRAM);
        if (err != len) {
            printk(KERN_WARNING "%s: failed to send echo response: %d\n", __FUNCTION__, err);
            break;
        }
    }
}

int init_echo(void)
{
    int ret = 0;

    tasklet_init(&echo_tasklet, echo_softirq, 0);

    echo_ring = uxen_v4v_ring_bind(UXEN_ECHO_PORT, V4V_DOMID_DM, UXEN_ECHO_RING_SIZE,
        echo_irq, NULL);
    if (!echo_ring) {
        ret = -ENOMEM;
        goto out;
    }
    if (IS_ERR(echo_ring)) {
        ret = PTR_ERR(echo_ring);
        echo_ring = NULL;
        goto out;
    }

    printk("initialized attovm kernel echo\n");

out:
    if (ret) {
        tasklet_kill(&echo_tasklet);
    }
    return ret;
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
    ret = init_attocall_dev();
    if (ret)
        return ret;

    ret = init_echo();
    if (ret)
        return ret;

    attovm_secret_dev.minor = MISC_DYNAMIC_MINOR;
    attovm_secret_dev.name = "attovm_secret";
    attovm_secret_dev.fops = &attovm_secret_file_ops;
    ret = misc_register(&attovm_secret_dev);
    if (ret)
        return ret;

    features = attovm_call_queryop(ATTOCALL_QUERYOP_FEATURES, 0, 0, 0);
    printk("%s: attovm features 0x%x\n", __FUNCTION__, (unsigned) features);

    protvm_use_secure_keyboard = !!(features & ATTOCALL_QUERYOP_FEATURES_PROT_KBD);

    return 0;
}

void attovm_platform_exit(void)
{
    if (echo_ring) {
        uxen_v4v_ring_free(echo_ring);
        tasklet_kill(&echo_tasklet);
        echo_ring = NULL;
    }

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

    if (attodev_dev)
        device_destroy(attodev_class, MKDEV(attodev_major, 0));

    if (attodev_class)
        class_destroy(attodev_class);

    if (attodev_major >= 0)
        unregister_chrdev(attodev_major, ATTOCALL_DEV_NAME);
}


