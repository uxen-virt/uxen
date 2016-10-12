/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
#include <linux/slab.h>
#endif
#include <linux/list.h>
#include <linux/interrupt.h>

#include <xen/xen.h>
#include <xen/v4v.h>

#include <uxen-hypercall.h>
#include <uxen-v4vlib.h>
#include <uxen-util.h>

#include "ax.h"
#include "acpi.h"

#define XENV4V_MAX_RING_LENGTH (4*1024*1024UL)

#ifdef LX_TARGET_AX
typedef void (*ax_irq_handler_t)(struct pt_regs*);
extern void set_ax_irq_handler(ax_irq_handler_t h);
#endif

static int v4v_irq;
static int irq_ok;

static int v4v_suspended;

static u32 last_port;
static rwlock_t ring_list_lock;
static struct list_head ring_list;

static void run_irq_tasklet(unsigned long);
DECLARE_TASKLET(irq_tasklet, run_irq_tasklet, 0);

struct uxen_v4v_ring {
    v4v_ring_t *ring; /* first */
    int in_list;
    int registered;
    int irq_enabled;
    struct list_head node;
    uxen_v4v_callback_t *callback;
    void *callback_opaque;

    v4v_pfn_list_t pfn_list; /* last */
} __attribute__((packed));

/* needs ring_list_lock taken */
static bool port_in_use(u32 port)
{
    struct uxen_v4v_ring *r;

    list_for_each_entry(r, &ring_list, node) {
        if (r->ring->id.addr.port == port)
            return true;
    }

    return false;
}

/* needs ring_list_lock taken */
static u32 get_free_port(void)
{
    u32 port = last_port;
    u32 pass = 0;

    for (;;) {
        port++;
        if (!port)
            port++;
        pass++;
        if (!pass)
            break;

        if (!port_in_use(port))
            return port;
    }

    return 0;
}

static struct uxen_v4v_ring *
ring_create(u32 ring_length)
{
    u32 length, npage, i;
    u8 *v_page;
    struct uxen_v4v_ring *r = ERR_PTR(-ENOMEM);
    v4v_ring_t *v4v_ring;

    if (ring_length != V4V_ROUNDUP(ring_length)) {
        r = ERR_PTR(-EINVAL);
        goto out;
    }

    if (ring_length > XENV4V_MAX_RING_LENGTH) {
        r = ERR_PTR(-EINVAL);
        goto out;
    }

    length = ring_length + sizeof(v4v_ring_t);
    npage = (length + PAGE_SIZE - 1) >> PAGE_SHIFT;
    length = npage * PAGE_SIZE;
    v4v_ring = vmalloc(length);
    if (!r) {
        r = ERR_PTR(-ENOMEM);
        goto out;
    }

    memset(v4v_ring, 0, length);
    v4v_ring->magic = V4V_RING_MAGIC;
    v4v_ring->len = ring_length;
    v4v_ring->id.addr.port = V4V_PORT_NONE;
    v4v_ring->id.addr.domain = V4V_DOMID_NONE;

    r = kmalloc(sizeof(*r) + npage * sizeof(v4v_pfn_t), GFP_KERNEL | __GFP_ZERO);
    if (!r) {
        vfree(v4v_ring);
        r = ERR_PTR(-ENOMEM);
        goto out;
    }

    r->ring = v4v_ring;
    r->pfn_list.magic = V4V_PFN_LIST_MAGIC;
    r->pfn_list.npage = npage;
    v_page = (u8 *) v4v_ring;
    for (i = 0; i < npage; i++) {
        r->pfn_list.pages[i] = virtual_to_pfn(v_page);
        v_page += PAGE_SIZE;
    }

out:
    return r;
}

static void ring_free(struct uxen_v4v_ring *r)
{
    if (r->ring)
        vfree(r->ring);
    kfree(r);
}

void uxen_v4v_ring_free (struct uxen_v4v_ring *r)
{
    if (!r)
        return;

    if (r->registered) {
        int err;

        err = uxen_hypercall_v4v_op(V4VOP_unregister_ring, r->ring, 0, 0, 0, 0);
        if (err)
            printk(KERN_ERR "uxen_hypercall_v4v_op(V4VOP_unregister_ring) failed %d\n", err);
    }

    if (r->in_list) {
        unsigned long flags;

        write_lock_irqsave(&ring_list_lock, flags);
        list_del(&r->node);
        write_unlock_irqrestore(&ring_list_lock, flags);
    }

    ring_free(r);
}
EXPORT_SYMBOL_GPL(uxen_v4v_ring_free);

uxen_v4v_ring_t *uxen_v4v_ring_bind(u32 local_port, domid_t partner_domain,
                                            u32 ring_size, uxen_v4v_callback_t *callback,
                                            void *callback_opaque)
{
    u32 port;
    int err = -EINVAL;
    struct uxen_v4v_ring *r = NULL;
    unsigned long flags;

    r = ring_create(ring_size);
    if (IS_ERR(r))
        goto out;

    r->ring->id.addr.domain = V4V_DOMID_ANY;
    r->ring->id.partner = partner_domain;

    r->callback = callback;
    r->callback_opaque = callback_opaque;

    write_lock_irqsave(&ring_list_lock, flags);
    port = local_port;
    if (port == V4V_PORT_NONE) {
        port = get_free_port();
        if (!port) {
            write_unlock_irqrestore(&ring_list_lock, flags);
            printk(KERN_ERR "%s: cannot obtain free port\n", __FUNCTION__);
            err = -ENOSPC;
            goto cleanup;
        }
        last_port = port;
    } else if (port_in_use(port)) {
        write_unlock_irqrestore(&ring_list_lock, flags);
        printk(KERN_DEBUG "%s: port %u already in use\n", __FUNCTION__, port);
        err = -EADDRINUSE;
        goto cleanup;
    }

    list_add(&r->node, &ring_list);
    r->in_list = 1;
    r->ring->id.addr.port = port;
    write_unlock_irqrestore(&ring_list_lock, flags);

    r->irq_enabled = 1;
    err = uxen_hypercall_v4v_op(V4VOP_register_ring, r->ring, &r->pfn_list, 0, 0, 0);
    if (err) {
        printk(KERN_INFO "%s: uxen_hypercall_v4v_op(V4VOP_register_ring) failed %d\n",
               __FUNCTION__, err);
        goto cleanup;
    }
    r->registered = 1;
out:
    return r;
cleanup:
    r->irq_enabled = 0;
    uxen_v4v_ring_free(r);
    r = ERR_PTR(err);
    goto out;
}
EXPORT_SYMBOL_GPL(uxen_v4v_ring_bind);

ssize_t uxen_v4v_send_from_ring(uxen_v4v_ring_t *r, v4v_addr_t *dst, void *buf,
                                u32 len, u32 protocol)
{
    int err;

    err = uxen_hypercall_v4v_op(V4VOP_send, (void *)&r->ring->id.addr,
                                (void *)dst, (void *)buf,
                                (void *)(uintptr_t)len,
                                (void *)(uintptr_t)protocol);

    return (ssize_t)err;
}
EXPORT_SYMBOL_GPL(uxen_v4v_send_from_ring);

ssize_t uxen_v4v_sendv_from_ring(uxen_v4v_ring_t *r, v4v_addr_t *dst, v4v_iov_t *iov,
                                 u32 niov, u32 protocol)
{
    int err;

    err = uxen_hypercall_v4v_op(V4VOP_sendv, (void *)&r->ring->id.addr,
                                (void *)dst, (void *)iov,
                                (void *)(uintptr_t)niov,
                                (void *)(uintptr_t)protocol);

    return (ssize_t)err;
}
EXPORT_SYMBOL_GPL(uxen_v4v_sendv_from_ring);

int uxen_v4v_notify(void)
{
    return uxen_hypercall_v4v_op(V4VOP_notify, 0, 0, 0, 0, 0);
}
EXPORT_SYMBOL_GPL(uxen_v4v_notify);

struct v4v_ring_data_ex {
    struct v4v_ring_data rd;
    struct v4v_ring_data_ent dt;
} V4V_PACKED;

int uxen_v4v_notify_space(domid_t dst_domain, u32 dst_port, u32 space_required, int *ok)
{
    int ret = 0;
    struct v4v_ring_data_ex ring_data;

    memset(&ring_data, 0, sizeof(ring_data));
    ring_data.rd.magic = V4V_RING_DATA_MAGIC;
    ring_data.rd.nent = 1;
    ring_data.dt.ring.domain = dst_domain;
    ring_data.dt.ring.port = dst_port;
    ring_data.dt.space_required = space_required;

    ret = uxen_hypercall_v4v_op(V4VOP_notify, (void *) &ring_data, 0, 0, 0, 0);
    if (ret)
        goto out;

    if (!(ring_data.dt.flags & V4V_RING_DATA_F_EXISTS)) {
        ret = -ECONNREFUSED;
        goto out;
    }

    *ok = 0;
    if ((ring_data.dt.flags & V4V_RING_DATA_F_SUFFICIENT))
        *ok = 1;
    ret = 0;
out:
    return ret;
}
EXPORT_SYMBOL_GPL(uxen_v4v_notify_space);

static void
run_irq_tasklet(unsigned long opaque)
{
    unsigned long flags;
    struct uxen_v4v_ring *r;

    read_lock_irqsave(&ring_list_lock, flags);
    list_for_each_entry(r, &ring_list, node) {
        if (r->irq_enabled && r->callback)
            r->callback(r->callback_opaque);
    }
    read_unlock_irqrestore(&ring_list_lock, flags);
}

static void
v4v_irq_handler(struct pt_regs *regs)
{
    if (!irq_ok)
      return;
    tasklet_schedule(&irq_tasklet);
}

#if 0
static irqreturn_t uxenv4v_isr(int irq, void *unused)
{
    unsigned long flags;
    struct uxen_v4v_ring *r;

    read_lock_irqsave(&ring_list_lock, flags);
    list_for_each_entry(r, &ring_list, node) {
        if (r->irq_enabled && r->callback)
            r->callback(r->callback_opaque);
    }
    read_unlock_irqrestore(&ring_list_lock, flags);

    return IRQ_HANDLED;
}
#endif

static void driver_cleanup(void)
{
#ifndef LX_TARGET_AX
    if (irq_ok)
        free_irq(v4v_irq, NULL);
#endif
    irq_ok = 0;
#ifdef LX_TARGET_AX
    ax_exit();
#elif defined(LX_TARGET_UXEN)
    acpi_exit();
#endif
}

static int __init uxenv4v_init(void)
{
    int ret = 0;

    rwlock_init (&ring_list_lock);
    INIT_LIST_HEAD(&ring_list);

#ifdef LX_TARGET_AX
    v4v_irq = ax_init_irq_line();
#elif defined(LX_TARGET_UXEN)
    v4v_irq = acpi_init_irq_line();
#else
    v4v_irq = -ENODEV;
#endif


    if (v4v_irq <= 0) {
        ret = -ENODEV;
        goto cleanup;
    }

#ifdef LX_TARGET_AX
    set_ax_irq_handler(v4v_irq_handler);
#else
    ret = request_irq(v4v_irq, uxenv4v_isr, IRQF_TRIGGER_RISING, KBUILD_MODNAME, NULL);
    if (ret)
      goto cleanup;
#endif
    irq_ok = 1;

out:
    return ret;
cleanup:
    driver_cleanup();
    goto out;
}

static void __exit uxenv4v_exit(void)
{
    driver_cleanup();
}

void uxen_v4v_suspend(void)
{
    unsigned long flags;
    struct uxen_v4v_ring *r;

    write_lock_irqsave(&ring_list_lock, flags);
    if (!v4v_suspended) {
        v4v_suspended = 1;
        list_for_each_entry(r, &ring_list, node) {
            r->irq_enabled = 0;
        }
    }
    write_unlock_irqrestore(&ring_list_lock, flags);
}
EXPORT_SYMBOL_GPL(uxen_v4v_suspend);

void uxen_v4v_resume(void)
{
    unsigned long flags;
    int err;

    /* re-register all rings on resume */
    write_lock_irqsave(&ring_list_lock, flags);
    if (v4v_suspended) {
        struct uxen_v4v_ring *r;

        list_for_each_entry(r, &ring_list, node) {
            if (r->registered) {
                r->irq_enabled = 1;
                err = uxen_hypercall_v4v_op(V4VOP_register_ring, r->ring, &r->pfn_list, 0, 0, 0);
                if (err) {
                    printk(KERN_ERR "%s: uxen_hypercall_v4v_op(V4VOP_register_ring) failed %d\n",
                           __FUNCTION__, err);
                    continue;
                }
            }
        }
        v4v_suspended = 0;
    }
    write_unlock_irqrestore(&ring_list_lock, flags);
}
EXPORT_SYMBOL_GPL(uxen_v4v_resume);

module_init(uxenv4v_init);
module_exit(uxenv4v_exit);
MODULE_AUTHOR("paulian.marinca@bromium.com");
MODULE_DESCRIPTION("uXen v4v library");
MODULE_LICENSE("GPL");
