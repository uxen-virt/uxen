/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

/******************************************************************************
 * v4v.c
 *
 * V4V (2nd cut of v2v)
 */
#include <dm/qemu_glue.h>
#include <dm/dm.h>
#include <dm/os.h>
#include <dm/whpx/whpx.h>
#include <dm/whpx/core.h>
#include "v4v_glue.h"
#include "v4v_private.h"
#include "v4v_alloc.h"

#ifndef WHPX_V4V
#include <xen/config.h>
#include <xen/mm.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/v4v.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <xen/keyhandler.h>
#include <xsm/xsm.h>
#include <xen/pci_regs.h>
#include <public/sched.h>
#endif

struct domain dom0;

//#define V4V_DEBUG

static struct v4v_ring_info *v4v_ring_find_info(struct domain *d,
                                                struct v4v_ring_id *id);

static struct v4v_ring_info *v4v_ring_find_info_by_addr(struct domain *d,
                                                        struct v4v_addr *a,
                                                        domid_t p);

static void v4v_ring_remove_mfns(struct v4v_ring_info *ring_info,
                                 int put_pages);
static void v4v_notify_check_pending(pcpu_t *cpu, struct domain *d);
#ifndef WHPX_V4V
static void dump_rings(unsigned char key);
#endif

#define V4V_PCI_BUS  0
#define V4V_PCI_SLOT 0x1f
#define V4V_PCI_FN   0

#define V4V_PCI_INTX 0

/***** locks ****/
/* locking is organized as follows: */

/* the global lock v4v_lock: L1 protects the v4v elements */
/* of all struct domain *d in the system, it does not */
/* protect any of the elements of d->v4v, just their */
/* addresses. By extension since the destruction of */
/* a domain with a non-NULL d->v4v will need to free */
/* the d->v4v pointer, holding this lock gauruntees */
/* that no domains pointers in which v4v is interested */
/* become invalid whilst this lock is held. */

static DEFINE_RWLOCK(v4v_lock); /* L1 */

/* the lock d->v4v->lock: L2:  Read on protects the hash table and */
/* the elements in the hash_table d->v4v->ring_hash, and */
/* the node and id fields in struct v4v_ring_info in the */
/* hash table. Write on L2 protects all of the elements of */
/* struct v4v_ring_info. To take L2 you must already have R(L1) */
/* W(L1) implies W(L2) and L3 */

/* the lock v4v_ring_info *ringinfo; ringinfo->lock: L3: */
/* protects len,tx_ptr the guest ring, the */
/* guest ring_data and the pending list. To take L3 you must */
/* already have R(L2). W(L2) implies L3 */



/*Debugs*/

#ifdef V4V_DEBUG
static void
v4v_hexdump(void *_p, int len)
{
    uint8_t *buf = (uint8_t *)_p;
    int i, j;

    for (i = 0; i < len; i += 16) {
        printk("%p:", &buf[i]);
        for (j = 0; j < 16; j++) {
            int k = i + j;
            if (k < len)
                printk(" %02x", buf[k]);
            else
                printk("   ");
        }
        printk(" ");

        for (j = 0; j < 16; j++) {
            int k = i + j;
            if (k < len)
                printk("%c", ((buf[k] > 32) && (buf[k] < 127)) ? buf[k] : '.');
            else
                printk(" ");
        }

        printk("\n");
    }


}
#endif

/********************** horrible kludges ***************************/

/* fix me for type 1.5 */
static int mfns_dont_belong_xen(struct domain *d)
{
    return IS_HOST(d);
}

static int v4v_can_do_create(pcpu_t *cpu)
{

    return IS_HOST(vmptr(cpu));
}


/*********************** Notification channel misery ****************/

#ifndef WHPX_V4V
static int deliver_via_upcall(struct domain *d)
{
    return 0;
}
#endif

static void
v4v_signal_domain(pcpu_t *cpu, struct domain *d)
{
    whpx_v4v_signal(d);
}

static void
v4v_signal_domid (pcpu_t *cpu, domid_t id)
{
    struct domain *d = get_domain_by_id(id);
    if (!d)
        return;
    v4v_signal_domain(cpu, d);
    put_domain(d);
}


/******************* ring buffer ******************/

/*caller must have L3*/
static void
v4v_ring_unmap(struct v4v_ring_info *ring_info)
{
    int i;

    if (!ring_info->mfn_mapping)
        return;

    for (i = 0; i < ring_info->nmfns; i++) {
        if (!ring_info->mfn_mapping[i])
            continue;
#ifdef V4V_DEBUG
        if (ring_info->mfns)
            warn("%s:%d unmapping page %"PRI_mfn" from %p\n",
                   __FUNCTION__, __LINE__, mfn_x(ring_info->mfns[i]),
                   ring_info->mfn_mapping[i]);
#endif
        unmap_domain_page_global(ring_info->mfn_mapping[i]);
        ring_info->mfn_mapping[i] = NULL;
    }
}

/*caller must have L3*/
static int
v4v_ring_map_page(struct v4v_ring_info *ring_info, int i, uint8_t **page)
{

    if (i >= ring_info->nmfns) {
        warn("%s: ring (vm%u:%x vm%d) %p attempted to map page"
               " %d of %d\n", __FUNCTION__, ring_info->id.addr.domain,
               ring_info->id.addr.port, ring_info->id.partner, ring_info,
               i, ring_info->nmfns);
        return -EFAULT;
    }
    ASSERT(ring_info->mfns);
    ASSERT(ring_info->mfn_mapping);

    if (!ring_info->mfn_mapping[i]) {
        ring_info->mfn_mapping[i] =
            map_domain_page_global(mfn_x(ring_info->mfns[i]));
        if (!ring_info->mfn_mapping[i]) {
            warn("%s: ring (vm%u:%x vm%d) %p attempted to map page"
                   " %d of %d\n", __FUNCTION__, ring_info->id.addr.domain,
                   ring_info->id.addr.port, ring_info->id.partner, ring_info,
                   i, ring_info->nmfns);
            return -EFAULT;
        }
#ifdef V4V_DEBUG
        warn("%s:%d mapping page %"PRI_mfn" to %p\n",
               __FUNCTION__, __LINE__, mfn_x(ring_info->mfns[i]),
               ring_info->mfn_mapping[i]);
#endif
    }

    if (page)
        *page = ring_info->mfn_mapping[i];
    return 0;
}

/*caller must have L3*/
static int
v4v_memcpy_from_guest_ring(void *_dst, struct v4v_ring_info *ring_info,
                           uint32_t offset, uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *src;
    uint8_t *dst = _dst;
    int ret;

    offset &= ~PAGE_MASK;

    while ((offset + len) > PAGE_SIZE) {
        ret = v4v_ring_map_page(ring_info, page, &src);
        if (ret)
            return ret;

#ifdef V4V_DEBUG
        warn("%s:%d memcpy(%p,%p+%d,%ld)\n",
               __FUNCTION__, __LINE__, dst, src, offset, PAGE_SIZE - offset);
#endif
        memcpy(dst, src + offset, PAGE_SIZE - offset);

        page++;
        len -= PAGE_SIZE - offset;
        dst += PAGE_SIZE - offset;
        offset = 0;
    }

    ret = v4v_ring_map_page(ring_info, page, &src);
    if (ret)
        return ret;

#ifdef V4V_DEBUG
    warn("%s:%d memcpy(%p,%p+%d,%d)\n",
           __FUNCTION__, __LINE__, dst, src, offset, len);
#endif
    memcpy(dst, src + offset, len);

    return 0;
}


/*caller must have L3*/
static int
v4v_update_tx_ptr(struct v4v_ring_info *ring_info, uint32_t tx_ptr)
{
    uint8_t *dst;
    volatile uint32_t *p;
    int ret;

    ret = v4v_ring_map_page(ring_info, 0, &dst);
    if (ret)
        return ret;

    p = (volatile uint32_t *)(dst + offsetof(v4v_ring_t, tx_ptr));
    *p = tx_ptr;

    return 0;
}

/*caller must have L3*/
static int
v4v_memcpy_to_guest_ring(pcpu_t *cpu, struct v4v_ring_info *ring_info, uint32_t offset,
                         void *_src, uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *dst;
    uint8_t *src = _src;
    int ret;

    offset &= ~PAGE_MASK;

    while ((offset + len) > PAGE_SIZE) {
        ret = v4v_ring_map_page(ring_info, page, &dst);
        if (ret) {
            warn("%s: ring (vm%u:%x vm%d) %p attempted to map"
                   " page %d of %d\n", __FUNCTION__,
                   ring_info->id.addr.domain, ring_info->id.addr.port,
                   ring_info->id.partner, ring_info, page,
                   ring_info->nmfns);
            return ret;
        }

#ifdef V4V_DEBUG
        warn("%s:%d memcpy(%p+%d,%p,%ld)\n",
               __FUNCTION__, __LINE__, dst, offset, src, PAGE_SIZE - offset);
        v4v_hexdump(src, PAGE_SIZE - offset);
        v4v_hexdump(dst + offset, PAGE_SIZE - offset);
#endif
        memcpy(dst + offset, src, PAGE_SIZE - offset);

        page++;
        len -= (PAGE_SIZE - offset);
        src += (PAGE_SIZE - offset);
        offset = 0;
    }

    ret = v4v_ring_map_page(ring_info, page, &dst);
    if (ret) {
        warn("%s: ring (vm%u:%x vm%d) %p attempted to map page"
               " %d of %d\n", __FUNCTION__, ring_info->id.addr.domain,
               ring_info->id.addr.port, ring_info->id.partner, ring_info,
               page, ring_info->nmfns);
        return ret;
    }

#ifdef V4V_DEBUG
    warn("%s:%d memcpy(%p+%d,%p,%d)\n",
           __FUNCTION__, __LINE__, dst, offset, src, len);
    v4v_hexdump(src, len);
    v4v_hexdump(dst + offset, len);
#endif
    memcpy(dst + offset, src, len);

    return 0;
}

/*caller must have L3*/
static int
v4v_memcpy_to_guest_ring_from_guest(pcpu_t *cpu, struct v4v_ring_info *ring_info,
                                    uint32_t offset,
                                    V4V_GUEST_HANDLE(uint8_t) src_hnd,
                                    uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *dst;
    int ret;

    offset &= ~PAGE_MASK;

    if ((len > V4V_RING_MAX_SIZE) || (offset > V4V_RING_MAX_SIZE)) {
        return -EFAULT;
    }

    while ((offset + len) > PAGE_SIZE) {
        ret = v4v_ring_map_page(ring_info, page, &dst);
        if (ret)
            return ret;

#ifdef V4V_DEBUG
        warn("%s:%d copy_from_guest(%p+%d,%p,%ld)\n",
               __FUNCTION__, __LINE__, dst, offset, (void *)src_hnd,
               PAGE_SIZE - offset);
#endif
        ret = v4v_copy_from_guest_errno(cpu, dst + offset, src_hnd, PAGE_SIZE - offset);
        if (ret)
            return ret;

        page++;
        len -= PAGE_SIZE - offset;
        guest_handle_add_offset(src_hnd, PAGE_SIZE - offset);
        offset = 0;
    }

    ret = v4v_ring_map_page(ring_info, page, &dst);
    if (ret)
        return ret;

#ifdef V4V_DEBUG
    warn("%s:%d copy_from_guest(%p+%d,%p,%d)\n",
           __FUNCTION__, __LINE__, dst, offset, (void *)src_hnd, len);
#endif
    return v4v_copy_from_guest_errno(cpu, (dst + offset), src_hnd, len);
}

/*caller must have L3*/
static int
v4v_ringbuf_get_rx_ptr(struct v4v_ring_info *ring_info, uint32_t *rx_ptr)
{
    uint8_t *src;
    volatile uint32_t *p;
    int ret;

    if (!ring_info->nmfns || ring_info->nmfns < ring_info->npage)
        return -EINVAL;

    ret = v4v_ring_map_page(ring_info, 0, &src);
#ifdef V4V_DEBUG
    warn("%s: mapped %"PRI_mfn" to %p\n", __FUNCTION__,
           mfn_x(ring_info->mfns[0]), src);
#endif
    if (ret)
        return ret;

    p = (volatile uint32_t *)(src + offsetof(v4v_ring_t, rx_ptr));
    *rx_ptr = *p;

    return 0;
}

static uint32_t
v4v_ringbuf_payload_space(struct domain *d, struct v4v_ring_info *ring_info)
{
    v4v_ring_t ring;
    int32_t ret;

    ring.len = ring_info->len;
    if (!ring.len)
        return 0;

    ring.tx_ptr = ring_info->tx_ptr;

    if (v4v_ringbuf_get_rx_ptr(ring_info, (uint32_t*)&ring.rx_ptr))
        return 0;

#ifdef V4V_DEBUG
    warn("%s: tx_ptr=%d rx_ptr=%d\n", __FUNCTION__,
           ring.tx_ptr, ring.rx_ptr);
#endif

    if (ring.rx_ptr == ring.tx_ptr)
        return ring.len - sizeof(struct v4v_ring_message_header);

    ret = ring.rx_ptr - ring.tx_ptr;
    if (ret < 0)
        ret += ring.len;

    ret -= sizeof(struct v4v_ring_message_header);
    ret -= V4V_ROUNDUP(1);

    return (ret < 0) ? 0 : ret;
}

static void
v4v_sanitize_ring(v4v_ring_t *ring, struct v4v_ring_info *ring_info)
{
    uint32_t rx_ptr = ring->rx_ptr;

    ring->tx_ptr = ring_info->tx_ptr;
    ring->len = ring_info->len;

    rx_ptr = V4V_ROUNDUP(rx_ptr);
    if (rx_ptr >= ring_info->len)
        rx_ptr = 0;

    ring->rx_ptr = rx_ptr;
}


static ssize_t
v4v_iov_count(pcpu_t *cpu, V4V_GUEST_HANDLE(v4v_iov_t) iovs, int niov)
{
    v4v_iov_t iov;
    size_t done = 0;
    int ret;

    while (niov--) {
        ret = v4v_copy_from_guest_errno(cpu, &iov, iovs, 1);
        if (ret)
            return ret;

        if (iov.iov_len > V4V_RING_MAX_SIZE)
            return -EINVAL;

        done += iov.iov_len;

        if (done > V4V_RING_MAX_SIZE)
            return -EINVAL;

        guest_handle_add_offset(iovs, 1);
    }

    return done;
}

/*caller must have L3*/
static ssize_t
v4v_ringbuf_insert(pcpu_t *cpu, struct domain *d,
                   struct v4v_ring_info *ring_info,
                   struct v4v_ring_id *src_id, uint32_t proto,
                   V4V_GUEST_HANDLE(uint8_t) buf_hnd, ssize_t *_len,
                   V4V_GUEST_HANDLE(v4v_iov_t) iovs, uint32_t niov)
{
    v4v_ring_t ring;
    struct v4v_ring_message_header mh = { 0 };
    int32_t sp;
    int32_t ret = 0;
    uint32_t iov_len;
    ssize_t len = *_len;

    if (!ring_info->len) {
        /* If the ring has zero length - it's a place holder.  Record
         * zero length for the notification, because when the ring is
         * eventually created, it will be empty and either the message
         * fits, or not */
        *_len = 0;
        return -EAGAIN;
    }

    if (niov) {
        len = v4v_iov_count(cpu, iovs, niov);
        /* warn("%s: sending %u bytes to %i:%u\n", */
        /*        __FUNCTION__, len, dst_addr->domain, dst_addr->port); */
        if (len < 0)
            return len;
        *_len = len;
    }

    if ((V4V_ROUNDUP(len) + sizeof(struct v4v_ring_message_header)) >=
        ring_info->len)
        return -EMSGSIZE;

    do {
        ret = v4v_memcpy_from_guest_ring(&ring, ring_info, 0, sizeof(ring));
        if (ret)
            break;

        v4v_sanitize_ring(&ring, ring_info);

#ifdef V4V_DEBUG
        warn("%s: ring.tx_ptr=%d ring.rx_ptr=%d ring.len=%d"
               " ring_info->tx_ptr=%d len=%d\n", __FUNCTION__,
            ring.tx_ptr, ring.rx_ptr, ring.len, ring_info->tx_ptr,
            (int)len);
#endif

        if (ring.rx_ptr == ring.tx_ptr)
            sp = ring_info->len;
        else {
            sp = ring.rx_ptr - ring.tx_ptr;
            if (sp < 0)
                sp += ring.len;
        }

        if ((V4V_ROUNDUP(len) + sizeof(struct v4v_ring_message_header)) >= sp) {
            ret = -EAGAIN;
            break;
        }

        mh.len = len + sizeof(struct v4v_ring_message_header);
        mh.source = src_id->addr;
        mh.pad = 0;
        mh.protocol = proto;

        ret = v4v_memcpy_to_guest_ring(cpu,
            ring_info, ring.tx_ptr + sizeof(v4v_ring_t), &mh, sizeof(mh));
        if (ret)
            break;

        ring.tx_ptr += sizeof(mh);
        if (ring.tx_ptr == ring_info->len)
            ring.tx_ptr = 0;

        do {
            if (!niov)
                iov_len = len;
            else {
                v4v_iov_t iov;

                ret = v4v_copy_from_guest_errno(cpu, &iov, iovs, 1);
                if (ret)
                    break;

                buf_hnd =
                    guest_handle_from_ptr((uintptr_t)iov.iov_base, uint8_t);
                iov_len = iov.iov_len;

                if (!iov_len) {
                    warn("%s: iov.iov_len=0 iov.iov_base=%"PRIx64" ring (vm%u:%x vm%d)\n", __FUNCTION__,
                           iov.iov_base, ring_info->id.addr.domain,
                           ring_info->id.addr.port, ring_info->id.partner);
                    guest_handle_add_offset(iovs, 1);
                    continue;
                }
            }

            if (iov_len > V4V_MAX_RING_SIZE) {
                ret = -EINVAL;
                break;
            }

            if (unlikely(!guest_handle_okay(buf_hnd, iov_len))) {
                ret = -EFAULT;
                break;
            }

            if (iov_len > len) {
                ret = -EFAULT;
                break;
            }

            if (iov_len) {
                len -= iov_len;
                sp = ring.len - ring.tx_ptr;

                if (iov_len > sp) {
                    ret = v4v_memcpy_to_guest_ring_from_guest(cpu,
                        ring_info, ring.tx_ptr + sizeof(v4v_ring_t),
                        buf_hnd, sp);
                    if (ret)
                        break;

                    ring.tx_ptr = 0;
                    iov_len -= sp;
                    guest_handle_add_offset(buf_hnd, sp);
                }

                ret = v4v_memcpy_to_guest_ring_from_guest(cpu,
                    ring_info, ring.tx_ptr + sizeof(v4v_ring_t),
                    buf_hnd, iov_len);
                if (ret)
                    break;

                ring.tx_ptr += iov_len;

                if (ring.tx_ptr == ring_info->len)
                    ring.tx_ptr = 0;
            }

            if (niov)
                guest_handle_add_offset(iovs, 1);

        } while (niov--);

        if (ret)
            break;

        ring.tx_ptr = V4V_ROUNDUP(ring.tx_ptr);

        if (ring.tx_ptr >= ring_info->len)
            ring.tx_ptr -= ring_info->len;

        mb();
        ring_info->tx_ptr = ring.tx_ptr;
        ret = v4v_update_tx_ptr(ring_info, ring.tx_ptr);
        if (ret)
            break;
    } while (0);

    return ret;
}


/***** pending ******/

/*caller must have L3 */
static void
v4v_pending_remove_ent(struct v4v_pending_ent *ent)
{
    hlist_del(&ent->node);
    free_pending_ent(ent);
}

/*caller must have L3 */
static void
v4v_pending_remove_all(struct v4v_ring_info *info)
{

    struct hlist_node *node, *next;
    struct v4v_pending_ent *pending_ent;


    hlist_for_each_entry_safe(pending_ent, node, next, &info->pending, node)
        v4v_pending_remove_ent(pending_ent);
}

/*Caller must hold L1 */
static void
v4v_pending_notify(pcpu_t *cpu, struct domain *caller_d, struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *pending_ent;


    hlist_for_each_entry_safe(pending_ent, node, next, to_notify, node) {
        hlist_del(&pending_ent->node);
        v4v_signal_domid(cpu, pending_ent->id);
        free_pending_ent(pending_ent);
    }

}

/*caller must have R(L2) */
static void
v4v_pending_find(struct v4v_ring_info *ring_info, uint32_t payload_space,
                 struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *ent;

    spin_lock(&ring_info->lock);
    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node) {
        if (payload_space >= ent->len) {
            hlist_del(&ent->node);
            hlist_add_head(&ent->node, to_notify);
        }
    }
    spin_unlock(&ring_info->lock);
}

/*caller must have L3 */
static int
v4v_pending_queue(struct v4v_ring_info *ring_info, domid_t src_id, int len)
{
    struct v4v_pending_ent *ent;

    ent = alloc_pending_ent();
    if (!ent)
        return -ENOMEM;

    ent->len = len;
    ent->id = src_id;

    hlist_add_head(&ent->node, &ring_info->pending);

    return 0;
}

/* caller must have L3 */
static int
v4v_pending_requeue(struct v4v_ring_info *ring_info, domid_t src_id, int len)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *ent;

    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node)
        if (ent->id == src_id) {
            if (ent->len < len)
                ent->len = len;
            return 0;
        }

    return v4v_pending_queue(ring_info, src_id, len);
}


/* caller must have L3 */
static void
v4v_pending_cancel(struct v4v_ring_info *ring_info, domid_t src_id)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *ent;

    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node) {
        if (ent->id == src_id) {
            hlist_del(&ent->node);
            free_pending_ent(ent);
        }
    }
}


/***** channel sender/receiver validation ******/

static int v4v_dm_domid = 0;

static int
v4v_resolve_token(domid_t *id, uint32_t *port, v4v_idtoken_t *token)
{

    ASSERT(token);

#ifdef WHPX_V4V
    if (!memcmp(token, &v4v_idtoken, sizeof(v4v_idtoken))) {
        *id = WHPX_DOMAIN_ID_SELF;
    } else {
        assert(0);
        return -ENOENT;
    }
#else
    struct domain *partner;
    partner = rcu_lock_domain_by_uuid(token->o, UUID_V4V_TOKEN);
    if (!partner)
        return -ENOENT;
    *id = partner->domain_id;
    rcu_unlock_domain(partner);
#endif
    return 0;
}

#define V4V_VALIDATE_PREAUTH 0x1

static int
v4v_validate_channel(pcpu_t *cpu,
                     domid_t *s_id, uint32_t *s_port,
                     domid_t *d_id, uint32_t *d_port, int flags)
{
    struct domain *d = vmptr(cpu);

    if (IS_HOST(d)) {
        //FIXME
#ifndef WHPX_V4V
        if (!(flags & V4V_VALIDATE_PREAUTH)) {
            int ret = rcu_lock_remote_target_domain_by_id(*d_id, &t);
            if (ret) {
                warn(
                       "%s: host %s vm%u:%x -> vm%u:%x from %S\n",
                       __FUNCTION__, ret == -EPERM ? "not priv" : "not found",
                       *s_id, *s_port, *d_id, *d_port,
                       (printk_symbol)__builtin_return_address(0));
                return ret;
            }
            rcu_unlock_domain(t);
        }
#endif
    } else {
        if (*s_id == V4V_DOMID_ANY)
            *s_id = d->domain_id;
        if (*s_id != d->domain_id) {
            printk(XENLOG_G_ERR
                "%s: !host vm%u s_id vm%u:%x -> vm%u:%x\n",
                __FUNCTION__, d->domain_id, *s_id, *s_port, *d_id, *d_port);
            return -EPERM;
        }
        if (*d_id == V4V_DOMID_DM || *d_id == 0)
            *d_id = v4v_dm_domid;
        else {
            printk(XENLOG_G_ERR "%s: !host !DM vm%u:%x -> vm%u:%x\n",
                __FUNCTION__, *s_id, *s_port, *d_id, *d_port);
            return -EPERM;
        }
    }
    if (*s_id >= V4V_DOMID_SELF && *s_id != V4V_DOMID_ANY) {
        printk(XENLOG_G_WARNING "%s: invalid s_id vm%u:%x -> vm%u:%x\n",
            __FUNCTION__, *s_id, *s_port, *d_id, *d_port);
        return -ENOENT;
    }
    if (*d_id >= V4V_DOMID_SELF && *d_id != V4V_DOMID_ANY) {
        printk(XENLOG_G_WARNING "%s: invalid d_id vm%u:%x -> vm%u:%x\n",
            __FUNCTION__, *s_id, *s_port, *d_id, *d_port);
        return -ENOENT;
    }
    return 0;
}


/*ring data*/

/*Caller should hold R(L1)*/
static int
v4v_fill_ring_data(pcpu_t *cpu, struct domain *src_d,
                   V4V_GUEST_HANDLE(v4v_ring_data_ent_t) data_ent_hnd)
{
    v4v_ring_data_ent_t ent;
    v4v_addr_t src_addr;
    struct domain *dst_d;
    struct v4v_ring_info *ring_info;
    int ret;

    ret = v4v_copy_from_guest_errno(cpu, &ent, data_ent_hnd, 1);
    if (ret)
        return ret;

    src_addr.domain = src_d->domain_id;
    src_addr.port = V4V_PORT_NONE;
    ret = v4v_validate_channel(cpu,
        &src_addr.domain, &src_addr.port,
        &ent.ring.domain, &ent.ring.port, V4V_VALIDATE_PREAUTH);
    if (ret)
        return ret;

#ifdef V4V_DEBUG
    warn("%s: ent.ring.domain=vm%u, ent.ring.port=%d\n",
           __FUNCTION__, ent.ring.domain, ent.ring.port);
#endif

    ent.flags = 0;

    dst_d = get_domain_by_id(ent.ring.domain);

    if (dst_d && dst_d->v4v) {
        read_lock(&dst_d->v4v->lock);

        ring_info = v4v_ring_find_info_by_addr(dst_d, &ent.ring,
                                               src_addr.domain);
        if (ring_info) {
            uint32_t space_avail;

            ent.flags |= V4V_RING_DATA_F_EXISTS;
            ent.max_message_size =
                ring_info->len - sizeof(struct v4v_ring_message_header) -
                V4V_ROUNDUP(1);
            spin_lock(&ring_info->lock);

            space_avail = v4v_ringbuf_payload_space(dst_d, ring_info);

#if 0
            warn("%s: port=%d space_avail=%d space_wanted=%d\n",
                   __FUNCTION__, ring_info->id.addr.port, space_avail,
                   ent.space_required);
#endif

            if (space_avail >= ent.space_required) {
                v4v_pending_cancel(ring_info, src_addr.domain);
                ent.flags |= V4V_RING_DATA_F_SUFFICIENT;
            } else {
                v4v_pending_requeue(ring_info, src_addr.domain,
                                    ent.space_required);
                ent.flags |= V4V_RING_DATA_F_PENDING;
            }

            spin_unlock(&ring_info->lock);

            if (space_avail == ent.max_message_size)
                ent.flags |= V4V_RING_DATA_F_EMPTY;

        }
        read_unlock(&dst_d->v4v->lock);
    }

    if (dst_d)
        put_domain(dst_d);

    ret = v4v_copy_field_to_guest_errno(cpu, data_ent_hnd, &ent, flags);
    if (ret)
        return ret;
    ret = v4v_copy_field_to_guest_errno(cpu, data_ent_hnd, &ent, max_message_size);
    if (ret)
        return ret;
#if 0                           //FIXME sa
    ret = v4v_copy_field_to_guest_errno(cpu, data_ent_hnd, &ent, space_avail);
    if (ret) {
        DEBUG_BANANA;
        return ret;
    }

#ifdef V4V_DEBUG
    warn("    ent.flags=%04x ent.space_avail=%d\n",
           ent.flags, ent.space_avail);
#endif
#endif

    return 0;
}

/*Called should hold no more than R(L1) */
static int
v4v_fill_ring_datas(pcpu_t *cpu, struct domain *d, int nent,
                    V4V_GUEST_HANDLE(v4v_ring_data_ent_t) data_ent_hnd)
{
    int ret = 0;
    read_lock(&v4v_lock);
    while (!ret && nent--) {
        ret = v4v_fill_ring_data(cpu, d, data_ent_hnd);
        guest_handle_add_offset(data_ent_hnd, 1);
    }
    read_unlock(&v4v_lock);
    return ret;
}

/**************************************** ring ************************/

static int
v4v_setup_dom0_mfn_mapping(struct v4v_ring_info *ring_info, uint32_t len)
{
    uint8_t *r = (uint8_t*) ring_info->ring;
    uint32_t l = 0, i = 0;

    ASSERT(!ring_info->mfns);
    ASSERT(!ring_info->mfn_mapping);

    ring_info->mfns = v4v_xmalloc_array(mfn_t, len);
    if (!ring_info->mfns)
        return -ENOMEM;
    ring_info->mfn_mapping = v4v_xmalloc_array(uint8_t *, len);
    if (!ring_info->mfn_mapping)
        return -ENOMEM;

    while (l < len) {
        ring_info->mfn_mapping[i] = r + l;
        ring_info->mfns[i] = 0;
        i += 1;
        l += PAGE_SIZE;
    }

    assert(i <= V4V_MAX_RING_PFNS);
    ring_info->nmfns = i;
    ring_info->npage = i;

    return 0;
}

static int
v4v_find_ring_mfn(pcpu_t *cpu, struct domain *d, v4v_pfn_t pfn, mfn_t *mfn)
{
#ifdef WHPX_V4V
    // CHEAT: just keep guest pfn in the mfn entry, map_domain_page
    // will understand this on whp
    *mfn = pfn;

    return 0;

#else /* WHPX_V4V */

    if (mfns_dont_belong_xen(d)) {
        if (!IS_PRIV_SYS())
            return -EPERM;
        if (!mfn_valid(pfn))
            return -EINVAL;
        *mfn = _mfn(pfn);
    } else {
        p2m_type_t t;

        *mfn = get_gfn_unshare(d, pfn, &t);
        if (mfn_retry(*mfn)) {
#ifdef V4V_DEBUG
            warn("%s: vm%u retry gpfn %"PRI_xen_pfn
                   " ring %p seq %d\n", __FUNCTION__, d->domain_id,
                   pfn, ring_info, i);
#endif
            ret = -ECONTINUATION;
        } else if (!mfn_valid_page(mfn_x(*mfn)) ||
                   !get_page(mfn_to_page(mfn_x(*mfn)), d))
            ret = -EINVAL;

        put_gfn(d, pfn);
    }

    return ret;
#endif
}

static int
v4v_find_ring_mfns(pcpu_t *cpu, struct domain *d, struct v4v_ring_info *ring_info,
                   V4V_GUEST_HANDLE(v4v_pfn_list_t) pfn_list_hnd,
                   uint32_t len)
{
    V4V_GUEST_HANDLE(v4v_pfn_t) pfn_hnd;
    V4V_GUEST_HANDLE(uint8_t) slop_hnd;
    v4v_pfn_list_t pfn_list;
    int i;
    mfn_t mfn;
    int ret = 0;

#ifdef WHPX_V4V
    if (IS_HOST(d))
        return v4v_setup_dom0_mfn_mapping(ring_info, len + sizeof(v4v_ring_t));
#endif

    ret = v4v_copy_from_guest_errno(cpu, &pfn_list, pfn_list_hnd, 1);
    if (ret)
        return ret;

    if (pfn_list.magic != V4V_PFN_LIST_MAGIC)
        return -EINVAL;

    if ((pfn_list.npage << PAGE_SHIFT) < len)
        return -EINVAL;

    slop_hnd = guest_handle_cast(pfn_list_hnd, uint8_t);
    guest_handle_add_offset(slop_hnd, sizeof(v4v_pfn_list_t));
    pfn_hnd = guest_handle_cast(slop_hnd, v4v_pfn_t);

    if (pfn_list.npage > (V4V_MAX_RING_SIZE >> PAGE_SHIFT))
        return -EINVAL;

    if (ring_info->mfns) {
        /* Ring already existed.  Check if it's the same ring,
         * i.e. same number of pages and all translated gpfns still
         * translating to the same mfns */
        if (ring_info->npage != pfn_list.npage)
            i = ring_info->nmfns + 1; /* force re-reg */
        else {
            for (i = 0; i < ring_info->nmfns; i++) {
                v4v_pfn_t pfn;

                ret = v4v_copy_from_guest_offset_errno(cpu, &pfn, pfn_hnd, i, 1);
                if (ret)
                    break;

                ret = v4v_find_ring_mfn(cpu, d, pfn, &mfn);
                if (ret)
                    break;

                if (!mfns_dont_belong_xen(d))
                    put_page(mfn_to_page(mfn_x(mfn)));

                if (mfn_x(mfn) != mfn_x(ring_info->mfns[i]))
                    break;
            }
        }
        if (i != ring_info->nmfns) {
            printk("%s: re-registering existing v4v ring"
                   " (vm%u:%x vm%d), clearing MFN list\n", __FUNCTION__,
                ring_info->id.addr.domain,
                   ring_info->id.addr.port, ring_info->id.partner);
            v4v_ring_remove_mfns(ring_info,
                !mfns_dont_belong_xen(d));
            ASSERT(!ring_info->mfns[0]);
        }
    }

    if (!ring_info->mfns) {
        mfn_t *mfns;
        uint8_t **mfn_mapping;

        mfns = v4v_xmalloc_array(mfn_t, pfn_list.npage);
        if (!mfns)
            return -ENOMEM;

        mfn_mapping = v4v_xmalloc_array(uint8_t *, pfn_list.npage);
        if (!mfn_mapping) {
            v4v_xfree(mfns);
            return -ENOMEM;
        }
        ring_info->mfns = mfns;
        ring_info->mfn_mapping = mfn_mapping;
        ring_info->npage = pfn_list.npage;
    }

    ASSERT(ring_info->npage == pfn_list.npage);

    if (ring_info->nmfns == ring_info->npage)
        return 0;

    for (i = ring_info->nmfns; i < ring_info->npage; i++) {
        v4v_pfn_t pfn;

        if (check_free_pages_needed(0))
            return hypercall_create_retry_continuation(
                /* ring_info->npage - ring_info->nmfns */);

        ret = v4v_copy_from_guest_offset_errno(cpu, &pfn, pfn_hnd, i, 1);
        if (ret)
            break;

        ret = v4v_find_ring_mfn(cpu, d, pfn, &mfn);
        if (ret) {
            if (ret == -EINVAL)
                warn("%s: vm%u passed invalid gpfn %"PRI_xen_pfn
                       " ring (vm%u:%x vm%d) %p seq %d of %d\n", __FUNCTION__,
                       d->domain_id, pfn, ring_info->id.addr.domain,
                       ring_info->id.addr.port, ring_info->id.partner,
                       ring_info, i, ring_info->npage);
            break;
        }

        ring_info->mfns[i] = mfn;
        ring_info->nmfns = i + 1;

#ifdef V4V_DEBUG
        warn("%s: %d: %"PRI_xen_pfn" -> %"PRI_mfn"\n",
               __FUNCTION__, i, pfn, mfn_x(ring_info->mfns[i]));
#endif

        ring_info->mfn_mapping[i] = NULL;
    }

    if (ret && ret != -ECONTINUATION) {
        v4v_ring_remove_mfns(ring_info, !mfns_dont_belong_xen(d));
        return ret;
    }

    ASSERT(ret || ring_info->nmfns == ring_info->npage);
    if (!ret)
        warn("%s: ring (vm%u:%x vm%d) %p mfn_mapping %p"
               " npage %d nmfns %d\n", __FUNCTION__,
               ring_info->id.addr.domain, ring_info->id.addr.port,
               ring_info->id.partner, ring_info, ring_info->mfn_mapping,
               ring_info->npage, ring_info->nmfns);
    return ret;
}

/* caller must hold R(L2) */
static struct v4v_ring_info *
v4v_ring_find_info(struct domain *d, struct v4v_ring_id *id)
{
    uint16_t hash;
    struct hlist_node *node, *next;
    struct v4v_ring_info *ring_info;

    hash = v4v_hash_fn(id);

#ifdef V4V_DEBUG
//    warn("%s: d->v4v=%p, d->v4v->ring_hash[%d]=%p id=%p\n",
//           __FUNCTION__, d->v4v, hash, d->v4v->ring_hash[hash].first, id);
    warn("%s: id.addr.port=%d id.addr.domain=vm%u"
           " id.addr.partner=vm%d\n", __FUNCTION__,
           id->addr.port, id->addr.domain, id->partner);
#endif

    hlist_for_each_entry_safe(ring_info, node, next, &d->v4v->ring_hash[hash], node) {
        if (!memcmp(id, &ring_info->id, sizeof(*id))) {
#ifdef V4V_DEBUG
            warn("%s: ring_info=%p\n", __FUNCTION__, ring_info);
#endif
            return ring_info;
        }
    }
#ifdef V4V_DEBUG
    warn("%s: no ring_info found\n", __FUNCTION__);
#endif

    return NULL;
}

/* caller must hold R(L2) */
static struct v4v_ring_info *
v4v_ring_find_info_by_addr(struct domain *d, struct v4v_addr *a, domid_t p)
{
    struct v4v_ring_id id;
    struct v4v_ring_info *info;

    if (!a)
        return NULL;

    id.addr.port = a->port;
    id.addr.domain = d->domain_id;
    id.partner = p;

    info = v4v_ring_find_info(d, &id);
    if (info)
        return info;

    id.partner = V4V_DOMID_NONE;

    return v4v_ring_find_info(d, &id);
}

/*caller must hold W(L2) */
static void
v4v_ring_remove_mfns(struct v4v_ring_info *ring_info, int put_pages)
{
    int i;

    if (!ring_info->mfns)
        return;
    ASSERT(ring_info->mfn_mapping);

#ifdef V4V_DEBUG
    warn("%s: ring (vm%u:%x vm%d) %p from %S\n",
           __FUNCTION__,
           ring_info->id.addr.domain, ring_info->id.addr.port,
           ring_info->id.partner, ring_info,
           (printk_symbol)__builtin_return_address(0));
#endif
    v4v_ring_unmap(ring_info);

    if (put_pages) {
        for (i = 0; i < ring_info->nmfns; i++)
            if (mfn_x(ring_info->mfns[i]))
                put_page(mfn_to_page(mfn_x(ring_info->mfns[i])));
    }

    v4v_xfree(ring_info->mfns);
    ring_info->mfns = NULL;
    ring_info->npage = 0;
    v4v_xfree(ring_info->mfn_mapping);
    ring_info->mfn_mapping = NULL;
    ring_info->nmfns = 0;
}

#ifndef WHPX_V4V
/*caller must hold W(L2) */
static void
v4v_ring_reset(struct v4v_ring_info *ring_info, int put_pages)
{

    v4v_ring_remove_mfns(ring_info, put_pages);

    ring_info->len = 0;
    ring_info->tx_ptr = 0;
    ring_info->ring = V4V_GUEST_HANDLE_NULL(v4v_ring_t);
    ring_info->nmfns = 0;
}
#endif

/*caller must hold W(L2) */
static void
v4v_ring_remove_info(struct v4v_ring_info *ring_info, int put_pages)
{
    v4v_pending_remove_all(ring_info);
    hlist_del(&ring_info->node);
    v4v_ring_remove_mfns(ring_info, put_pages);
    free_ring_info(ring_info);
}

/* Call from guest to unpublish a ring */
static long
v4v_ring_remove(pcpu_t *cpu, struct domain *d, V4V_GUEST_HANDLE(v4v_ring_t) ring_hnd)
{
    struct v4v_ring ring;
    uint32_t dst_port;
    struct v4v_ring_info *ring_info;
    int ret = 0;

    read_lock(&v4v_lock);

    do {

        if (!d->v4v) {
            ret = -EINVAL;
            break;
        }

        ret = v4v_copy_from_guest_errno(cpu, &ring, ring_hnd, 1);
        if (ret)
            break;

        if (ring.magic != V4V_RING_MAGIC) {
            ret = -EINVAL;
            break;
        }

        ring.id.addr.domain = d->domain_id;
        dst_port = V4V_PORT_NONE;
        ret = v4v_validate_channel(cpu,
            &ring.id.addr.domain, &ring.id.addr.port,
            &ring.id.partner, &dst_port, V4V_VALIDATE_PREAUTH);
        if (ret)
            break;

        write_lock(&d->v4v->lock);
        ring_info = v4v_ring_find_info(d, &ring.id);
        if (ring_info)
            v4v_ring_remove_info(ring_info, !mfns_dont_belong_xen(d)); //Fixme for type1.5
        write_unlock(&d->v4v->lock);

        if (!ring_info) {
            ret = -ENOENT;
            break;
        }

        printk("%s: removed ring (vm%u:%x vm%d)\n",
               __FUNCTION__,
               ring.id.addr.domain, ring.id.addr.port, ring.id.partner);
    } while (0);

    read_unlock(&v4v_lock);

    return ret;
}

/* call from host to make placeholder in a guest for a ring */
static long
v4v_ring_create(pcpu_t *cpu, struct domain *d, V4V_GUEST_HANDLE(v4v_ring_id_t) ring_id_hnd)
{
    struct domain *dst_d = NULL;
    uint32_t dst_port;
    struct v4v_ring_info *ring_info;
    struct v4v_ring_id ring_id;
    int ret = 0;
    uint16_t hash;

    if (!v4v_can_do_create(cpu))
        return -EPERM;

    read_lock(&v4v_lock);

    do {
        ret = v4v_copy_from_guest_errno(cpu, &ring_id, ring_id_hnd, 1);
        if (ret) {
            if (ret != -ERETRY)
                warn("%s: copy_from_guest_errno err %d\n",
                       __FUNCTION__, ret);
            break;
        }

        if (ring_id.partner != V4V_DOMID_ANY)
            ring_id.partner = d->domain_id;
        dst_port = V4V_PORT_NONE;
        ret = v4v_validate_channel(cpu,
            &ring_id.addr.domain, &ring_id.addr.port,
            &ring_id.partner, &dst_port, V4V_VALIDATE_PREAUTH);
        if (ret)
            break;

        dst_d = get_domain_by_id(ring_id.addr.domain);
        if (!dst_d) {
            warn(
                   "%s: vm%u no partner vm for ring (vm%u:%x vm%d)\n",
                   __FUNCTION__, d->domain_id,
                   ring_id.addr.domain, ring_id.addr.port, ring_id.partner);
            ret = -ENOENT;
            break;
        }

        if (!dst_d->v4v) {
            if (!dst_d->is_dying)
                warn(
                       "%s: vm%u no v4v in partner vm for ring "
                       "(vm%u:%x vm%d)\n", __FUNCTION__, d->domain_id,
                       ring_id.addr.domain, ring_id.addr.port, ring_id.partner);
            ret = -ENOENT;
            break;
        }

        write_lock(&dst_d->v4v->lock);
        ring_info = v4v_ring_find_info(dst_d, &ring_id);
        if (ring_info) {
            write_unlock(&dst_d->v4v->lock);
            /* We already have a record for this ring - we're done */
            break;
        }

        ring_info = alloc_ring_info();
        if (!ring_info) {
            write_unlock(&dst_d->v4v->lock);
            warn("%s: no memory for ring (vm%u:%x vm%d)"
                   " %p nmfns %d\n", __FUNCTION__,
                   ring_id.addr.domain, ring_id.addr.port, ring_id.partner,
                   ring_info, ring_info->nmfns);

            ret = -ENOMEM;
            break;
        }

#ifdef WHPX_V4V
        spin_lock_init(&ring_info->lock);
#else
//        spin_lock_init(&ring_info->lock);
        ring_info->lock = 0;
#endif

        ring_info->mfns = NULL;
        ring_info->mfn_mapping = NULL;

        ring_info->npage = 0;
        ring_info->len = 0;
        ring_info->nmfns = 0;

        ring_info->tx_ptr = 0;
        ring_info->ring = V4V_GUEST_HANDLE_NULL(v4v_ring_t);

        ring_info->id = ring_id;
        INIT_HLIST_HEAD(&ring_info->pending);

        hash = v4v_hash_fn(&ring_info->id);
        hlist_add_head(&ring_info->node, &dst_d->v4v->ring_hash[hash]);

        write_unlock(&dst_d->v4v->lock);

        printk("%s: creating placeholder ring (vm%u:%x vm%d)"
               " %p nmfns %d\n", __FUNCTION__,
               ring_id.addr.domain, ring_id.addr.port, ring_id.partner,
               ring_info, ring_info->nmfns);

        //We now require the caller retries the send
        //v4v_pending_queue(ring_info, d->domain_id, 1);

        spin_unlock(&ring_info->lock);
    } while (0);

    if (dst_d)
        put_domain(dst_d);

    read_unlock(&v4v_lock);

    return ret;
}


/* call from guest to publish a ring */
static long
v4v_ring_add(pcpu_t *cpu, struct domain *d, V4V_GUEST_HANDLE(v4v_ring_t) ring_hnd,
             V4V_GUEST_HANDLE(v4v_pfn_list_t) pfn_list_hnd,
             V4V_GUEST_HANDLE(v4v_idtoken_t) idtoken, uint32_t fail_exist)
{
    /* xen_domain_handle_t */ v4v_idtoken_t partner_idtoken;
    domid_t partner_id;
    uint32_t partner_port;
    struct v4v_ring ring;
    struct v4v_ring_info *ring_info;
    uint16_t hash;
    int authorized = 0;
    int ret = 0;

    if (!(guest_handle_is_aligned(ring_hnd, ~PAGE_MASK))) {
        warn("handle not aligned\n");
        return -EINVAL;
    }

    read_lock(&v4v_lock);

    do {
        if (!d->v4v) {
            warn("no v4v\n");
            ret = -EINVAL;
            break;
        }

        ret = v4v_copy_from_guest_errno(cpu, &ring, ring_hnd, 1);
        if (ret)
            break;

        if (ring.magic != V4V_RING_MAGIC) {
            warn("bad magic: %"PRIx64"\n", ring.magic);
            ret = -EINVAL;
            break;
        }

        if ((ring.len <
             (sizeof(struct v4v_ring_message_header) + V4V_ROUNDUP(1) +
              V4V_ROUNDUP(1))) || (V4V_ROUNDUP(ring.len) != ring.len)) {
            warn("too short\n");
            ret = -EINVAL;
            break;
        }

        if (ring.len > V4V_MAX_RING_SIZE) {
            warn("too long\n");
            ret = -EINVAL;
            break;
        }

        ring.id.addr.domain = d->domain_id;
        partner_id = ring.id.partner;
        partner_port = V4V_PORT_NONE;
        if (partner_id == V4V_DOMID_UUID) {
            ret = v4v_copy_from_guest_errno(cpu, &partner_idtoken, idtoken, 1);
            if (ret)
                break;
            ret = v4v_resolve_token(&partner_id, &partner_port,
                                    &partner_idtoken);
            if (ret)
                break;
            authorized = V4V_VALIDATE_PREAUTH;
        }

        ret = v4v_validate_channel(cpu,
            &ring.id.addr.domain, &ring.id.addr.port,
            &partner_id, &partner_port, authorized);
        if (ret)
            break;
        /* return the updated partner id to the caller, unless the
         * requested partner id was V4V_DOMID_DM */
        if (ring.id.partner != V4V_DOMID_DM)
            ring.id.partner = partner_id;

        ret = v4v_copy_field_to_guest_errno(cpu, ring_hnd, &ring, id);
        if (ret)
            break;

        /* update ring.id.partner now if it was V4V_DOMID_DM */
        if (ring.id.partner == V4V_DOMID_DM)
            ring.id.partner = partner_id;

        /* no need for a lock yet, because only we know about this */
        /* set the tx pointer if it looks bogus (we don't reset it
         * always because this might be a re-register after S4) */
        if (ring.tx_ptr >= ring.len ||
            V4V_ROUNDUP(ring.tx_ptr) != ring.tx_ptr) {
            ring.tx_ptr = V4V_ROUNDUP(ring.rx_ptr);

            if (ring.tx_ptr >= ring.len)
                ring.tx_ptr = 0;

            ///XXX: not atomic
            ret = v4v_copy_field_to_guest_errno(cpu, ring_hnd, &ring, tx_ptr);
            if (ret)
                break;
        }

        write_lock(&d->v4v->lock);

        ring_info = v4v_ring_find_info(d, &ring.id);
        if (!ring_info) {
            ring_info = alloc_ring_info();
            if (!ring_info) {
                write_unlock(&d->v4v->lock);
                ret = -ENOMEM;
                break;
            }

#ifdef WHPX_V4V
            spin_lock_init(&ring_info->lock);
#else
            ring_info->lock = 0;
#endif
            spin_lock(&ring_info->lock);

            ring_info->mfns = NULL;
            ring_info->mfn_mapping = NULL;

            ring_info->npage = 0;
            ring_info->len = 0;
            ring_info->nmfns = 0;

            ring_info->tx_ptr = 0;
            ring_info->ring = V4V_GUEST_HANDLE_NULL(v4v_ring_t);

            ring_info->id = ring.id;
            INIT_HLIST_HEAD(&ring_info->pending);

            hash = v4v_hash_fn(&ring_info->id);
            hlist_add_head(&ring_info->node, &d->v4v->ring_hash[hash]);

            write_unlock(&d->v4v->lock);

            printk("%s: registering ring (vm%u:%x vm%d)\n",
                   __FUNCTION__,
                   ring.id.addr.domain, ring.id.addr.port, ring.id.partner);
        } else {
            write_unlock(&d->v4v->lock);

            /* don't allow adding a ring which already exists and is
             * setup fully, i.e. is not a placeholder ring or a ring
             * where v4v_find_ring_mfns or v4v_ring_map_page below
             * failed for retry */
            if (fail_exist && ring_info->len) {
                ret = -EEXIST;
                break;
            }

            spin_lock(&ring_info->lock);
        }

        ring_info->tx_ptr = ring.tx_ptr;
        ring_info->ring = ring_hnd;

        ret = v4v_find_ring_mfns(cpu, d, ring_info, pfn_list_hnd, ring.len);
        if (!ret)
            ret = v4v_ring_map_page(ring_info, 0, NULL);
        if (!ret)
            ring_info->len = ring.len;

        spin_unlock(&ring_info->lock);
    } while (0);

    if (!ret)
        v4v_notify_check_pending(cpu, d);

    read_unlock(&v4v_lock);

    return ret;
}

/**************************** io ***************************/

/*Caller must hold v4v_lock and hash_lock*/
static void
v4v_notify_ring(struct domain *d, struct v4v_ring_info *ring_info,
                struct hlist_head *to_notify)
{
    uint32_t space;

    spin_lock(&ring_info->lock);
    if (ring_info->len)
        space = v4v_ringbuf_payload_space(d, ring_info);
    else
        space = 0;
    spin_unlock(&ring_info->lock);

    if (space)
        v4v_pending_find(ring_info, space, to_notify);
}


/*Caller must hold L1 */
static void
v4v_notify_check_pending(pcpu_t *cpu, struct domain *d)
{
    int i;
    HLIST_HEAD(to_notify);

    read_lock(&d->v4v->lock);

    mb();

    for (i = 0; i < V4V_HTABLE_SIZE; i++) {
        struct hlist_node *node, *next;
        struct v4v_ring_info *ring_info;

        hlist_for_each_entry_safe(ring_info, node, next, &d->v4v->ring_hash[i],
                                  node)
            v4v_notify_ring(d, ring_info, &to_notify);
    }
    read_unlock(&d->v4v->lock);

    if (!hlist_empty(&to_notify))
        v4v_pending_notify(cpu, d, &to_notify);
}

/*notify hypercall*/
static long
v4v_notify(pcpu_t *cpu, struct domain *d, V4V_GUEST_HANDLE(v4v_ring_data_t) ring_data_hnd)
{
    v4v_ring_data_t ring_data;
    int ret = 0;

    read_lock(&v4v_lock);

    if (!d->v4v) {
        read_unlock(&v4v_lock);
        return -ENODEV;
    }

    v4v_notify_check_pending(cpu, d);

    do {
        if (!guest_handle_is_null(ring_data_hnd)) {
            /* Quick sanity check on ring_data_hnd */
            ret = v4v_copy_field_from_guest_errno(cpu, &ring_data, ring_data_hnd, magic);
            if (ret)
                break;

            if (ring_data.magic != V4V_RING_DATA_MAGIC) {
                ret = -EINVAL;
                break;
            }

            ret = v4v_copy_from_guest_errno(cpu, &ring_data, ring_data_hnd, 1);
            if (ret)
                break;

            {
                V4V_GUEST_HANDLE(v4v_ring_data_ent_t) ring_data_ent_hnd;
                V4V_GUEST_HANDLE(uint8_t) slop_hnd =
                    guest_handle_cast(ring_data_hnd, uint8_t);
                guest_handle_add_offset(slop_hnd, sizeof(v4v_ring_data_t));
                ring_data_ent_hnd =
                    guest_handle_cast(slop_hnd, v4v_ring_data_ent_t);
                ret = v4v_fill_ring_datas(cpu, d, ring_data.nent, ring_data_ent_hnd);
            }
        }
    } while (0);

    read_unlock(&v4v_lock);

    return ret;
}

#if 0
/*Hypercall to do the poke*/
static size_t
v4v_poke(v4v_addr_t *dst_addr)
{
    v4v_addr_t src_addr;

    if (!dst_addr)
        return -EINVAL;

    src_addr.domain = current->domain->domain_id;
    src_addr.port = V4V_PORT_NONE;
    ret = v4v_validate_channel(cpu,
        &src_addr.domain, &src_addr.port,
        &dst_addr->domain, &dst_addr->port, V4V_VALIDATE_PREAUTH);
    if (ret)
        return ret;

    v4v_signal_domid(dst_addr->domain);

    return 0;
}
#endif


/* Hypercall to do the send */
static size_t
v4v_send(pcpu_t *cpu, struct domain *src_d, v4v_addr_t *src_addr,
         v4v_addr_t *dst_addr, uint32_t proto,
         V4V_GUEST_HANDLE(void) buf, ssize_t len,
         V4V_GUEST_HANDLE(v4v_iov_t) iovs, size_t niov)
{
    struct domain *dst_d = NULL;
    struct v4v_ring_id src_id;
    struct v4v_ring_info *ring_info;
    int ret = 0;

    if (!dst_addr)
        return -EINVAL;

    read_lock(&v4v_lock);
    if (!src_d->v4v) {
        ret = -EINVAL;
        goto out;
    }

    ret = v4v_validate_channel(cpu,
        &src_addr->domain, &src_addr->port,
        &dst_addr->domain, &dst_addr->port, V4V_VALIDATE_PREAUTH);
    if (ret)
        goto out;

    src_id.addr.port = src_addr->port;
    src_id.addr.domain = src_addr->domain;
    src_id.partner = dst_addr->domain;

    dst_d = get_domain_by_id(dst_addr->domain);
    if (!dst_d || !dst_d->v4v) {
        warn("%s: connection refused, src (vm%u:%x) "
               "dst (vm%u:%x)\n",
               __FUNCTION__,
               src_id.addr.domain, src_id.addr.port,
               dst_addr->domain, dst_addr->port);
        ret = -ECONNREFUSED;
        goto out;
    }

#ifdef __V4V_XSM__
    /* XSM: verify if src is allowed to send to dst */
    if (xsm_v4v_send(src_d, dst_d) != 0) {
        warn("V4V: XSM REJECTED %i -> %i\n",
               src_addr->domain, dst_addr->domain);
        ret = -EPERM;
        goto out;
    }
#endif
#ifdef __V4V_TABLES__
    /* V4VTables*/
    if (v4v_tables_check(src_addr, dst_addr) != 0) {
        warn("V4V: V4VTables REJECTED %i:%u -> %i:%u\n",
               src_addr->domain, src_addr->port,
               dst_addr->domain, dst_addr->port);
        ret = -EPERM;
        goto out;
    }
#endif

    read_lock(&dst_d->v4v->lock);
    do {
        ring_info =
            v4v_ring_find_info_by_addr(dst_d, dst_addr, src_addr->domain);
        if (!ring_info) {
            v4v_signal_domain(cpu, dst_d);
            warn("%s: connection refused, src (vm%u:%x) "
                   "dst (vm%u:%x)\n",
                   __FUNCTION__,
                   src_id.addr.domain, src_id.addr.port,
                   dst_addr->domain, dst_addr->port);
            ret = -ECONNREFUSED;
            break;
        }

        spin_lock(&ring_info->lock);
        ret = v4v_ringbuf_insert(cpu, dst_d, ring_info, &src_id, proto,
                                 guest_handle_cast(buf, uint8_t), &len,
                                 iovs, niov);
        if (ret == -EAGAIN) {
            /* Schedule a notification when space is there */
            if (v4v_pending_requeue(ring_info, src_addr->domain, len))
                ret = -ENOMEM;
        }
        spin_unlock(&ring_info->lock);

        if (!ret)
            v4v_signal_domain(cpu, dst_d);
    } while (0);
    read_unlock(&dst_d->v4v->lock);

  out:
    if (dst_d)
        put_domain(dst_d);
    read_unlock(&v4v_lock);

    return ret ? : len;
}


/**************** hypercall glue ************/
long
do_v4v_op(pcpu_t *cpu, struct domain *d,
          int cmd, V4V_GUEST_HANDLE(void) arg1,
          V4V_GUEST_HANDLE(void) arg2, V4V_GUEST_HANDLE(void) arg3,
          uint32_t arg4, uint32_t arg5)
{
#ifndef WHPX_V4V
    struct domain *d = current->domain;
#endif
    long rc = -EFAULT;

#ifdef V4V_DEBUG
    warn("->do_v4v_op(%d,%p,%p,%p,%d,%d)\n", cmd,
           arg1, arg2, arg3, arg4, arg5);
#endif

#ifndef WHPX_V4V
    /* don't allow host callers via generic hypercall interface */
    if (IS_HOST(d) && !IS_PRIV_SYS())
        return -EPERM;
#endif

    domain_lock(d);

    switch (cmd) {
    case V4VOP_register_ring: {
        V4V_GUEST_HANDLE(v4v_ring_t) ring_hnd =
            guest_handle_cast(arg1, v4v_ring_t);
        V4V_GUEST_HANDLE(v4v_pfn_list_t) pfn_list_hnd =
            guest_handle_cast(arg2, v4v_pfn_list_t);
        V4V_GUEST_HANDLE(v4v_idtoken_t) idtoken =
            guest_handle_cast(arg3, v4v_idtoken_t);

        if (unlikely(!guest_handle_okay(ring_hnd, 1)))
            goto out;
        if (unlikely(!guest_handle_okay(pfn_list_hnd, 1))) //FIXME
            goto out;
        if (unlikely(!guest_handle_okay(idtoken, 1)))
            goto out;

        rc = v4v_ring_add(cpu, d, ring_hnd, pfn_list_hnd, idtoken, arg4);
        break;
    }
    case V4VOP_unregister_ring: {
        V4V_GUEST_HANDLE(v4v_ring_t) ring_hnd =
            guest_handle_cast(arg1, v4v_ring_t);
        if (unlikely(!guest_handle_okay(ring_hnd, 1)))
            goto out;
        rc = v4v_ring_remove(cpu, d, ring_hnd);
        break;
    }
    case V4VOP_send: {
        v4v_addr_t src, dst;
        uint32_t len = arg4;
        uint32_t protocol = arg5;
        V4V_GUEST_HANDLE(v4v_addr_t) src_hnd =
            guest_handle_cast(arg1, v4v_addr_t);
        V4V_GUEST_HANDLE(v4v_addr_t) dst_hnd =
            guest_handle_cast(arg2, v4v_addr_t);

        if (unlikely(!guest_handle_okay(src_hnd, 1))) {
            goto out;
        }
        rc = v4v_copy_from_guest_errno(cpu, &src, src_hnd, 1);
        if (rc) {
            goto out;
        }

        if (unlikely(!guest_handle_okay(dst_hnd, 1))) {
            goto out;
        }
        rc = v4v_copy_from_guest_errno(cpu, &dst, dst_hnd, 1);
        if (rc) {
            goto out;
        }

        src.domain = d->domain_id;

        rc = v4v_send(cpu, d, &src, &dst, protocol, arg3, len,
                      guest_handle_from_ptr(NULL, v4v_iov_t), 0);
        break;
    }
    case V4VOP_sendv: {
        v4v_addr_t src, dst;
        uint32_t niov = arg4;
        uint32_t protocol = arg5;
        V4V_GUEST_HANDLE(v4v_addr_t) src_hnd =
            guest_handle_cast(arg1, v4v_addr_t);
        V4V_GUEST_HANDLE(v4v_addr_t) dst_hnd =
            guest_handle_cast(arg2, v4v_addr_t);
        V4V_GUEST_HANDLE(v4v_iov_t) iovs =
            guest_handle_cast(arg3, v4v_iov_t);

        if (unlikely(!guest_handle_okay(src_hnd, 1)))
            goto out;
        rc = v4v_copy_from_guest_errno(cpu, &src, src_hnd, 1);
        if (rc)
            goto out;

        if (unlikely(!guest_handle_okay(dst_hnd, 1)))
            goto out;
        rc = v4v_copy_from_guest_errno(cpu, &dst, dst_hnd, 1);
        if (rc)
            goto out;

        if (unlikely(!guest_handle_okay(iovs, niov)))
            goto out;

        src.domain = d->domain_id;

        rc = v4v_send(cpu, d, &src, &dst, protocol,
                      guest_handle_from_ptr(NULL, void), 0, iovs, niov);
        break;
    }
    case V4VOP_notify: {
        V4V_GUEST_HANDLE(v4v_ring_data_t) ring_data_hnd =
            guest_handle_cast(arg1, v4v_ring_data_t);
        rc = v4v_notify(cpu, d, ring_data_hnd);
        break;
    }
#ifdef __V4V_TABLES__
    case V4VOP_viptables_add:
    case V4VOP_viptables_del:
    case V4VOP_viptables_list:
        rc = do_v4v_tables_op(cmd, arg1, arg2, arg3, arg4, arg5);
        break;
#endif
    case V4VOP_create_ring: {
        V4V_GUEST_HANDLE(v4v_ring_id_t) ring_id_hnd =
            guest_handle_cast(arg1, v4v_ring_id_t);
        if (unlikely(!guest_handle_okay(ring_id_hnd, 1)))
            goto out;
        rc = v4v_ring_create(cpu, d, ring_id_hnd);
        break;
    }
#if 0
    case V4VOP_poke: {
        v4v_addr_t dst;
        V4V_GUEST_HANDLE(v4v_addr_t) dst_hnd =
            guest_handle_cast(arg1, v4v_addr_t);
        rc = copy_from_guest_errno(&dst, dst_hnd, 1);
        if (rc)
            goto out;

        warn("%s: poking vm%u\n", __FUNCTION__, dst.domain);

        rc = v4v_poke(&dst);
        break;
    }
    case V4VOP_test:
        warn("V4VOP_test called with args: %p %p %p %x %x\n",
               arg1.p, arg2.p, arg3.p, arg4, arg5);
        rc = 0;
        break;
    case V4VOP_debug:
        warn("V4VOP_debug\n");
        dump_rings('4');
        rc = 0;
        break;
#endif
    default:
        rc = -ENOSYS;
        break;
    }
out:
    domain_unlock(d);
#ifdef V4V_DEBUG
    warn("<-do_v4v_op()=%d\n", (int)rc);
#endif
    return rc;
}

int do_v4v_op_cpuid(
    pcpu_t *cpu,
    uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10, uint64_t r8, uint64_t r9)
{
    int cmd = (int) rdi;
    V4V_GUEST_HANDLE(void) arg1 = (void*) (uintptr_t) rsi;
    V4V_GUEST_HANDLE(void) arg2 = (void*) (uintptr_t) rdx;
    V4V_GUEST_HANDLE(void) arg3 = (void*) (uintptr_t) r10;
    uint32_t arg4 = (uint32_t)r8;
    uint32_t arg5 = (uint32_t)r9;
    struct domain *d = vmptr(cpu);
    int rc;


//    printk("V4V op %d: args=%p %p %p %x %x host=%d domid=%d\n", cmd, arg1, arg2, arg3, arg4, arg5, IS_HOST(d), d->domain_id);
    rc = do_v4v_op(cpu, d, cmd, arg1, arg2, arg3, arg4, arg5);
//    printk("V4V op %d DONE: args=%p %p %p %x %x host=%d domid=%d %d\n", cmd, arg1, arg2, arg3, arg4, arg5, IS_HOST(d), d->domain_id, (int)rc);
    if (rc < 0 && rc != -EAGAIN) {
        warn("FAIL V4V op %d: error=%d args=%p %p %p %x %x host=%d domid=%d\n", cmd, rc, arg1, arg2, arg3, arg4, arg5, IS_HOST(d), d->domain_id);
    }
    return rc;
}

int do_v4v_op_dom0(
    uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10, uint64_t r8, uint64_t r9)
{
    int cmd = (int) rdi;
    V4V_GUEST_HANDLE(void) arg1 = (void*) (uintptr_t) rsi;
    V4V_GUEST_HANDLE(void) arg2 = (void*) (uintptr_t) rdx;
    V4V_GUEST_HANDLE(void) arg3 = (void*) (uintptr_t) r10;
    uint32_t arg4 = (uint32_t)r8;
    uint32_t arg5 = (uint32_t)r9;
    int rc;


//    printk("V4V op %d: args=%p %p %p %x %x host=YES\n", cmd, arg1, arg2, arg3, arg4, arg5);
    rc = do_v4v_op(NULL, &dom0, cmd, arg1, arg2, arg3, arg4, arg5);
//    printk("V4V op %d DONE: args=%p %p %p %x %x host=YES %d\n", cmd, arg1, arg2, arg3, arg4, arg5, (int)rc);
    if (rc < 0 && rc != -EAGAIN) {
        warn("FAIL V4V op %d: error=%d args=%p %p %p %x %x host=YES\n", cmd, rc, arg1, arg2, arg3, arg4, arg5);
    }
    return rc;
}


/**************** init *******************/

void
v4v_destroy(struct domain *d)
{
    int i;


//    BUG_ON(!d->is_dying);
    write_lock(&v4v_lock);

#ifdef V4V_DEBUG
    warn("%s:%d: d->v=%p\n", __FUNCTION__, __LINE__, d->v4v);
#endif

    if (d->v4v) {
        for (i = 0; i < V4V_HTABLE_SIZE; i++) {
            struct hlist_node *node, *next;
            struct v4v_ring_info *ring_info;
            hlist_for_each_entry_safe(ring_info, node, next,
                                      &d->v4v->ring_hash[i], node)
                v4v_ring_remove_info(ring_info, !mfns_dont_belong_xen(d));
        }
        free_v4v_domain(d->v4v);
    }

    d->v4v = NULL;
    write_unlock(&v4v_lock);
}

int
v4v_init(struct domain *d)
{
    struct v4v_domain *v4v;
    int i;
#if 0
    uint8_t one = 1;
#endif

    v4v = alloc_v4v_domain();
    if (!v4v)
        return -ENOMEM;

    rwlock_init(&v4v->lock);

    for (i = 0; i < V4V_HTABLE_SIZE; i++) {
        INIT_HLIST_HEAD(&v4v->ring_hash[i]);
    }

    write_lock(&v4v_lock);
    d->v4v = v4v;
    write_unlock(&v4v_lock);

    return 0;
}

#ifndef WHPX_V4V
static void
v4v_shutdown_for_suspend(struct domain *d)
{
    int i;

    if (!d)
        return;

#ifndef WHPX_V4V
    /* cannot be called on crash path as can cause deadlock over v4v_lock */
    BUG_ON(d->shutdown_code == SHUTDOWN_crash);
#endif

    write_lock(&v4v_lock);

    if (get_domain(d)) {
          if (d && d->v4v) {
              for (i = 0; i < V4V_HTABLE_SIZE; i++) {
                  struct hlist_node *node, *next;
                  struct v4v_ring_info *ring_info;
                  hlist_for_each_entry_safe(ring_info, node,
                                            next, &d->v4v->ring_hash[i], node)
                      v4v_ring_reset(ring_info, !mfns_dont_belong_xen(d));
              }
          }
          put_domain(d);
    }

    write_unlock(&v4v_lock);
}
#endif

#ifndef WHPX_V4V
static void
v4v_resume(struct domain *d)
{

    if (!d)
        return;

    if (!get_domain(d))
        return;

    v4v_signal_domain(d);
    put_domain(d);
}
#endif


/*************************** debug ********************************/
#ifndef WHPX_V4V
static void
dump_domain_ring(struct domain *d, struct v4v_ring_info *ring_info)
{
    uint32_t rx_ptr;


    warn("  ring: domid=vm%u port=0x%08x partner=vm%d nmfns=%d\n",
           d->domain_id, ring_info->id.addr.port,
           ring_info->id.partner, ring_info->nmfns);

    if (!ring_info->len)
        warn("   (Placeholder)\n");
    else {
        if (v4v_ringbuf_get_rx_ptr(ring_info, &rx_ptr)) {
            warn("   Failed to read rx_ptr\n");
            return;
        }
        warn("   tx_ptr=%d rx_ptr=%d len=%d\n",
               ring_info->tx_ptr, rx_ptr, ring_info->len);
    }
}
#endif

#ifndef WHPX_V4V
static void
dump_domain_rings(struct domain *d)
{
    int i;

    warn(" vm%u:\n", d->domain_id);

    if (!d->v4v)
        return;

    read_lock(&d->v4v->lock);

    for (i = 0; i < V4V_HTABLE_SIZE; i++) {
        struct hlist_node *node;
        struct v4v_ring_info *ring_info;

        hlist_for_each_entry(ring_info, node, &d->v4v->ring_hash[i], node)
            dump_domain_ring(d, ring_info);
    }


    read_unlock(&d->v4v->lock);

    warn("\n");

    //XXX: without this the subsequent upcall calls KeQueueDpc on the host in
    //exception handling context appears to break delivery of the timer dpc
    //to the idle thread.

    if (!deliver_via_upcall(d))
        v4v_signal_domain(d);
}

static void
dump_rings(unsigned char key)
{
    struct domain *d;

    warn("\n\nV4V ring dump:\n");
    read_lock(&v4v_lock);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain(d)
        dump_domain_rings(d);

    rcu_read_unlock(&domlist_read_lock);

    read_unlock(&v4v_lock);
}

struct keyhandler dump_v4v_rings = {
    .diagnostic = 1,
    .u.fn = dump_rings,
    .desc = "dump v4v ring states and interrupt"
};

static int __init
setup_dump_rings(void)
{
    register_keyhandler('4', &dump_v4v_rings);
    return 0;
}

__initcall(setup_dump_rings);
#endif

spinlock_t v4v_alloc_lock;

void
v4v_early_init(void)
{
    critical_section_init(&v4v_alloc_lock);
    rwlock_init(&v4v_lock);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
