/******************************************************************************
 * v4v.c
 *
 * V4V (2nd cut of v2v)
 *
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

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

/* #define V4V_DEBUG */

#ifdef V4V_DEBUG
#define v4v_xfree(a) do {                                               \
        printk(XENLOG_ERR "%s:%d xfree(%p)\n", __FUNCTION__, __LINE__,  \
               (void *)a);                                              \
        xfree(a);                                                       \
    } while(0)
#define v4v_xmalloc(a) ({                                               \
            void *ret = xmalloc(a);                                     \
            printk(XENLOG_ERR "%s:%d xmalloc(%s)=%p\n", __FUNCTION__,   \
                   __LINE__, #a , ret);                                 \
            ret; })
#define v4v_xmalloc_array(a, b) ({                                      \
            void *ret = xmalloc_array(a, b);                            \
            printk(XENLOG_ERR "%s:%d xmalloc_array(%s,%d)=%p\n",        \
                   __FUNCTION__, __LINE__, #a ,b, ret);                 \
            ret; })
#define v4v_tracepoint do {                                             \
        printk(XENLOG_ERR "%s:%d v4v trace\n", __FUNCTION__, __LINE__); \
    } while(0)
#else
#define v4v_tracepoint do { /* nothing */ } while(0)
#define v4v_xfree(a) xfree(a)
#define v4v_xmalloc(a) xmalloc(a)
#define v4v_xmalloc_array(a,b) xmalloc_array(a,b)
#endif


DEFINE_XEN_GUEST_HANDLE (uint8_t);
static struct v4v_ring_info *v4v_ring_find_info (struct domain *d,
        struct v4v_ring_id *id);

static struct v4v_ring_info *v4v_ring_find_info_by_addr (struct domain *d,
        struct v4v_addr *a,
        domid_t p);

static void v4v_notify_check_pending(struct domain *d);
static void dump_rings (unsigned char key);

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

static DEFINE_RWLOCK (v4v_lock); /* L1 */

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
v4v_hexdump (void *_p, int len)
{
    uint8_t *buf = (uint8_t *) _p;
    int i, j;

    for (i = 0; i < len; i += 16) {
        printk(XENLOG_ERR "%p:", &buf[i]);
        for (j = 0; j < 16; ++j) {
            int k = i + j;
            if (k < len) {
                printk(" %02x", buf[k]);
            } else {
                printk("   ");
            }
        }
        printk(" ");

        for (j = 0; j < 16; ++j) {
            int k = i + j;
            if (k < len) {
                printk("%c", ((buf[k] > 32) && (buf[k] < 127)) ? buf[k] : '.');
            } else {
                printk(" ");
            }
        }

        printk("\n");
    }


}
#endif

/********************** horrible kludges ***************************/

/* fix me for type 1.5 */
static int mfns_dont_belong_xen(struct domain *d)
{
    return !d->domain_id;
}

static int v4v_can_do_create(void)
{
#if 0
    /* Dom0 not priv in uXen */
    return IS_PRIV(current->domain);
#else
    return !current->domain->domain_id;
#endif
}


/*********************** Notification channel misery ****************/

static int deliver_via_upcall(struct domain *d)
{
    return !d->domain_id; //XXX: FIXME - we need a better name/test for this
}


static void
v4v_signal_domain (struct domain *d)
{

    if (!uxen_info->ui_running) {
        printk(XENLOG_ERR "%s: not ready ui_running=%d\n", __FUNCTION__,
               uxen_info->ui_running);
        BUG();
        return;
    }

    if (!d) {
        printk(XENLOG_ERR "%s: called with no domain\n", __FUNCTION__);
        BUG();
        return;
    }

    if (!d->v4v)  /* This can happen if the domain is being destroyed */
        return;

    if (deliver_via_upcall(d)) {
        if (uxen_info->ui_signal_v4v)
            uxen_info->ui_signal_v4v();
    } else {
#if 0
        hvm_pci_intx_assert(d, V4V_PCI_SLOT, V4V_PCI_INTX);
        hvm_pci_intx_deassert(d, V4V_PCI_SLOT, V4V_PCI_INTX);
#else
        hvm_isa_irq_assert(d, 7);
        hvm_isa_irq_deassert(d, 7);
#endif
    }
}

static void
v4v_signal_domid (domid_t id)
{
    struct domain *d = get_domain_by_id (id);
    if (!d)
        return;
    v4v_signal_domain (d);
    put_domain (d);
}


/******************* ring buffer ******************/

/*caller must have L3*/
static void
v4v_ring_unmap (struct v4v_ring_info *ring_info)
{
    int i;

    if (!ring_info->mfn_mapping) return;

    for (i = 0; i < ring_info->npage; ++i) {
        if (!ring_info->mfn_mapping[i])
            continue;
#ifdef V4V_DEBUG
        if (ring_info->mfns)
            printk(XENLOG_ERR "%s:%d unmapping page %"PRI_mfn" from %p\n",
                   __FUNCTION__, __LINE__, mfn_x(ring_info->mfns[i]),
                   ring_info->mfn_mapping[i]);
#endif
        unmap_domain_page (ring_info->mfn_mapping[i]);
        ring_info->mfn_mapping[i] = NULL;
    }
}

/*caller must have L3*/
static uint8_t *
v4v_ring_map_page (struct v4v_ring_info *ring_info, int i)
{
    if (i >= ring_info->npage)
        return NULL;
    if (!ring_info->mfn_mapping)
        return NULL;
    if (ring_info->mfn_mapping[i])
        return ring_info->mfn_mapping[i];


    if (!ring_info->mfns || !ring_info->mfn_mapping) {
        printk(XENLOG_ERR "%s: no mfns/mfn_mapping for ring_info at %p,"
               " id: vm%u for vm%d p:%x len:%d mfns:%p[%d]\n", __FUNCTION__,
               ring_info, ring_info->id.addr.domain, ring_info->id.partner,
               ring_info->id.addr.port, ring_info->len, ring_info->mfns,
               ring_info->npage);
        return NULL;
    }

    ring_info->mfn_mapping[i] = map_domain_page (mfn_x (ring_info->mfns[i]));
#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s:%d mapping page %"PRI_mfn" to %p\n",
           __FUNCTION__, __LINE__, mfn_x(ring_info->mfns[i]),
           ring_info->mfn_mapping[i]);
#endif
    return ring_info->mfn_mapping[i];
}

/*caller must have L3*/
static int
v4v_memcpy_from_guest_ring (void *_dst, struct v4v_ring_info *ring_info,
                            uint32_t offset, uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *src;
    uint8_t *dst = _dst;


    offset &= PAGE_SIZE - 1;

    while ((offset + len) > PAGE_SIZE) {
        src = v4v_ring_map_page (ring_info, page);

        if (!src)
            return -EFAULT;

#ifdef V4V_DEBUG
        printk(XENLOG_ERR "%s:%d memcpy(%p,%p+%d,%ld)\n",
               __FUNCTION__, __LINE__, dst, src, offset, PAGE_SIZE - offset);
#endif
        memcpy (dst, src + offset, PAGE_SIZE - offset);


        page++;
        len -= PAGE_SIZE - offset;
        dst += PAGE_SIZE - offset;
        offset = 0;
    }

    src = v4v_ring_map_page (ring_info, page);
    if (!src)
        return -EFAULT;

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s:%d memcpy(%p,%p+%d,%d)\n",
           __FUNCTION__, __LINE__, dst, src, offset, len);
#endif
    memcpy (dst, src + offset, len);

    return 0;
}


/*caller must have L3*/
static int
v4v_update_tx_ptr (struct v4v_ring_info *ring_info, uint32_t tx_ptr)
{
    uint8_t *dst = v4v_ring_map_page (ring_info, 0);
    volatile uint32_t *p = (uint32_t *)(dst + offsetof (v4v_ring_t, tx_ptr));
    if (!dst)
        return -EFAULT;
    *p = tx_ptr;
    return 0;
}

/*caller must have L3*/
static int
v4v_memcpy_to_guest_ring (struct v4v_ring_info *ring_info, uint32_t offset,
                          void *_src, uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *dst;
    uint8_t *src = _src;

    offset &= PAGE_SIZE - 1;

    while ((offset + len) > PAGE_SIZE) {
        dst = v4v_ring_map_page (ring_info, page);

        if (!dst)
            return -EFAULT;

#ifdef V4V_DEBUG
        printk(XENLOG_ERR "%s:%d memcpy(%p+%d,%p,%ld)\n",
               __FUNCTION__, __LINE__, dst, offset, src, PAGE_SIZE - offset);
        v4v_hexdump (src, PAGE_SIZE - offset);
        v4v_hexdump (dst + offset, PAGE_SIZE - offset);
#endif
        memcpy (dst + offset, src, PAGE_SIZE - offset);

        page++;
        len -= (PAGE_SIZE - offset);
        src += (PAGE_SIZE - offset);
        offset = 0;
    }

    dst = v4v_ring_map_page (ring_info, page);

    if (!dst) {
        printk(XENLOG_ERR "%s: ring (vm%u:%x vm%d) %p attempted to map page"
               " %d of %d\n", __FUNCTION__, ring_info->id.addr.domain,
               ring_info->id.addr.port, ring_info->id.partner, ring_info,
               page, ring_info->npage);
        return -EFAULT;
    }

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s:%d memcpy(%p+%d,%p,%d)\n",
           __FUNCTION__, __LINE__, dst, offset, src, len);
    v4v_hexdump (src, len);
    v4v_hexdump (dst + offset, len);
#endif
    memcpy (dst + offset, src, len);

    return 0;
}

struct list_head viprules = LIST_HEAD_INIT(viprules);

/*caller must have L3*/
static int
v4v_memcpy_to_guest_ring_from_guest (struct v4v_ring_info *ring_info,
                                     uint32_t offset,
                                     XEN_GUEST_HANDLE (uint8_t) src_hnd,
                                     uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *dst;

    offset &= PAGE_SIZE - 1;

    if ((len > V4V_RING_MAX_SIZE) || (offset > V4V_RING_MAX_SIZE))
        return -EFAULT;

    while ((offset + len) > PAGE_SIZE) {
        dst = v4v_ring_map_page (ring_info, page);

        if (!dst)
            return -EFAULT;

#ifdef V4V_DEBUG
        printk(XENLOG_ERR "%s:%d copy_from_guest(%p+%d,%p,%ld)\n",
               __FUNCTION__, __LINE__, dst, offset, (void *) src_hnd.p,
               PAGE_SIZE - offset);
#endif
        if (copy_from_guest ((dst + offset), src_hnd, PAGE_SIZE - offset))
            return -EFAULT;


        page++;
        len -= PAGE_SIZE - offset;
        guest_handle_add_offset (src_hnd, PAGE_SIZE - offset);
        offset = 0;
    }

    dst = v4v_ring_map_page (ring_info, page);

    if (!dst)
        return -EFAULT;

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s:%d copy_from_guest(%p+%d,%p,%d)\n",
           __FUNCTION__, __LINE__, dst, offset, (void *)src_hnd.p, len);
#endif
    if (copy_from_guest ((dst + offset), src_hnd, len))
        return -EFAULT;

    return 0;
}

/*caller must have L3*/
static int
v4v_ringbuf_get_rx_ptr (struct domain *d, struct v4v_ring_info *ring_info,
                        uint32_t *rx_ptr)
{
    v4v_ring_t *ringp;

    if (ring_info->npage == 0)
        return -1;

    ringp = (v4v_ring_t *) v4v_ring_map_page (ring_info, 0);
    //ringp = map_domain_page (mfn_x (ring_info->mfns[0]));
#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s: mapped %"PRI_mfn" to %p\n", __FUNCTION__,
           mfn_x(ring_info->mfns[0]), ringp);
#endif
    if (!ringp)
        return -1;

    *rx_ptr = *(volatile uint32_t *) &ringp->rx_ptr;

    //unmap_domain_page ((void*)ringp);
    //v4v_ring_unmap (ring_info);



    return 0;
}



uint32_t
v4v_ringbuf_payload_space (struct domain *d,
                           struct v4v_ring_info *ring_info)
{
    v4v_ring_t ring;
    int32_t ret;

    ring.len = ring_info->len;
    if (!ring.len) return 0;

    ring.tx_ptr = ring_info->tx_ptr;

    if (v4v_ringbuf_get_rx_ptr (d, ring_info, &ring.rx_ptr))
        return 0;

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s: tx_ptr=%d rx_ptr=%d\n", __FUNCTION__,
           ring.tx_ptr, ring.rx_ptr);
#endif

    if (ring.rx_ptr == ring.tx_ptr)
        return ring.len - sizeof (struct v4v_ring_message_header);

    ret = ring.rx_ptr - ring.tx_ptr;
    if (ret < 0)
        ret += ring.len;

    ret -= sizeof (struct v4v_ring_message_header);
    ret -= V4V_ROUNDUP (1);

    return (ret < 0) ? 0 : ret;
}


static void v4v_sanitize_ring(v4v_ring_t *ring, struct v4v_ring_info *ring_info)
{
    uint32_t rx_ptr = ring->rx_ptr;

    ring->tx_ptr = ring_info->tx_ptr;
    ring->len = ring_info->len;

    rx_ptr = V4V_ROUNDUP(rx_ptr);
    if (rx_ptr >= ring_info->len) rx_ptr = 0;

    ring->rx_ptr = rx_ptr;
}


/*caller must have L3*/
static size_t
v4v_ringbuf_insert (struct domain *d,
                    struct v4v_ring_info *ring_info,
                    struct v4v_ring_id *src_id, uint32_t proto,
                    XEN_GUEST_HANDLE (void) buf_hnd_void, uint32_t len)
{
    XEN_GUEST_HANDLE (uint8_t) buf_hnd =
        guest_handle_cast (buf_hnd_void, uint8_t);
    v4v_ring_t ring;
    struct v4v_ring_message_header mh = { 0 };
    int32_t sp;
    int32_t happy_ret = len;
    int32_t ret = 0;


    if (!ring_info->len) /*If the ring has zero length - it's a place holder */
        return -EAGAIN;

    if ((V4V_ROUNDUP (len) + sizeof (struct v4v_ring_message_header)) >=
        ring_info->len)
        return -EMSGSIZE;

    do {

        if ((ret =
                 v4v_memcpy_from_guest_ring (&ring, ring_info, 0, sizeof (ring))))
            break;

        v4v_sanitize_ring(&ring, ring_info);


#ifdef V4V_DEBUG
        printk(XENLOG_ERR "%s: ring.tx_ptr=%d ring.rx_ptr=%d ring.len=%d"
               " ring_info->tx_ptr=%d\n", __FUNCTION__,
               ring.tx_ptr, ring.rx_ptr, ring.len, ring_info->tx_ptr);
#endif


        if (ring.rx_ptr == ring.tx_ptr) {
            sp = ring_info->len;
        } else {
            sp = ring.rx_ptr - ring.tx_ptr;
            if (sp < 0)
                sp += ring.len;
        }

        if ((V4V_ROUNDUP (len) + sizeof (struct v4v_ring_message_header)) >= sp) {
            ret = -EAGAIN;
            break;
        }

        mh.len = len + sizeof (struct v4v_ring_message_header);
        mh.source = src_id->addr;
        mh.pad = 0;
        mh.protocol = proto;


        if ((ret =
                 v4v_memcpy_to_guest_ring (ring_info,
                                           ring.tx_ptr + sizeof (v4v_ring_t), &mh,
                                           sizeof (mh))))
            break;

        ring.tx_ptr += sizeof (mh);
        if (ring.tx_ptr == ring_info->len)
            ring.tx_ptr = 0;

        sp = ring.len - ring.tx_ptr;

        if (len > sp) {
            if ((ret =
                     v4v_memcpy_to_guest_ring_from_guest (ring_info,
                             ring.tx_ptr +
                             sizeof (v4v_ring_t),
                             buf_hnd, sp)))
                break;

            ring.tx_ptr = 0;
            len -= sp;
            guest_handle_add_offset (buf_hnd, sp);
        }

        if ((ret =
                 v4v_memcpy_to_guest_ring_from_guest (ring_info,
                         ring.tx_ptr +
                         sizeof (v4v_ring_t), buf_hnd,
                         len)))
            break;

        ring.tx_ptr += V4V_ROUNDUP (len);

        if (ring.tx_ptr == ring_info->len)
            ring.tx_ptr = 0;

        mb ();
        ring_info->tx_ptr = ring.tx_ptr;

        if ((ret = v4v_update_tx_ptr(ring_info, ring.tx_ptr)))
            break;

    } while (1 == 0);

    //v4v_ring_unmap (ring_info);

    return ret ? ret : happy_ret;

}

static ssize_t
v4v_iov_count (XEN_GUEST_HANDLE (v4v_iov_t) iovs, int niov)
{
    v4v_iov_t iov;
    size_t ret = 0;

    while (niov--) {
        if (copy_from_guest (&iov, iovs, 1))
            return -EFAULT;

        if (iov.iov_len > V4V_RING_MAX_SIZE) return -EINVAL;

        ret += iov.iov_len;

        if (ret > V4V_RING_MAX_SIZE) return -EINVAL;

        guest_handle_add_offset (iovs, 1);
    }

    return ret;
}

/*caller must have L3*/
static ssize_t
v4v_ringbuf_insertv (struct domain *d,
                     struct v4v_ring_info *ring_info,
                     struct v4v_ring_id *src_id, uint32_t proto,
                     XEN_GUEST_HANDLE (v4v_iov_t) iovs, uint32_t niov,
                     uint32_t len)
{
    v4v_ring_t ring;
    struct v4v_ring_message_header mh = { 0 };
    int32_t sp;
    int32_t happy_ret;
    int32_t ret = 0;
    uint32_t iov_len;

    happy_ret = len;

    if (!ring_info->len) /*If the ring has zero length - it's a place holder */
        return -EAGAIN;

    if ((V4V_ROUNDUP (len) + sizeof (struct v4v_ring_message_header)) >=
        ring_info->len)
        return -EMSGSIZE;

    do {

        if ((ret =
                 v4v_memcpy_from_guest_ring (&ring, ring_info, 0, sizeof (ring))))
            break;

        v4v_sanitize_ring(&ring, ring_info);

#ifdef V4V_DEBUG
        printk(XENLOG_ERR "%s: ring.tx_ptr=%d ring.rx_ptr=%d ring.len=%d"
               " ring_info->tx_ptr=%d\n", __FUNCTION__,
               ring.tx_ptr, ring.rx_ptr, ring.len, ring_info->tx_ptr);
#endif


        if (ring.rx_ptr == ring.tx_ptr) {
            sp = ring_info->len;
        } else {
            sp = ring.rx_ptr - ring.tx_ptr;
            if (sp < 0)
                sp += ring.len;
        }

        if ((V4V_ROUNDUP (len) + sizeof (struct v4v_ring_message_header)) >= sp) {
            ret = -EAGAIN;
            break;
        }

        mh.len = len + sizeof (struct v4v_ring_message_header);
        mh.source = src_id->addr;
        mh.pad = 0;
        mh.protocol = proto;


        if ((ret =
                 v4v_memcpy_to_guest_ring (ring_info,
                                           ring.tx_ptr + sizeof (v4v_ring_t), &mh,
                                           sizeof (mh))))
            break;

        ring.tx_ptr += sizeof (mh);
        if (ring.tx_ptr == ring_info->len)
            ring.tx_ptr = 0;


        while (niov--) {
            XEN_GUEST_HANDLE (uint8_t) buf_hnd;
            v4v_iov_t iov;

            if (copy_from_guest (&iov, iovs, 1)) {
                ret = -EFAULT;
                break;
            }

            buf_hnd.p = (uint8_t *) (unsigned long)iov.iov_base; //FIXME
            iov_len = iov.iov_len;

            if (!iov_len)  {
                printk(XENLOG_ERR "%s: iov.iov_len=0, iov.iov_base=%"PRIx64"\n",
                       __FUNCTION__, iov.iov_base);
                printk(XENLOG_ERR "%s: ring_info->id = { vm%d -> vm%u:%x }\n",
                       __FUNCTION__, ring_info->id.partner,
                       ring_info->id.addr.domain, ring_info->id.addr.port);
                guest_handle_add_offset (iovs, 1);
                continue;
            }

            if (iov_len > V4V_MAX_RING_SIZE) {
                ret = -EINVAL;
                break;
            }

            if (unlikely (!guest_handle_okay (buf_hnd, iov_len))) {
                ret = -EFAULT;
                break;
            }

            if (iov_len > len)  {
                ret = -EFAULT;
                break;
            }


            if (iov_len) {
                len -= iov_len;
                sp = ring.len - ring.tx_ptr;
    
                if (iov_len > sp) {
                    if ((ret =
                             v4v_memcpy_to_guest_ring_from_guest (ring_info,
                                     ring.tx_ptr +
                                     sizeof (v4v_ring_t),
                                     buf_hnd, sp)))
                        break;
    
                    ring.tx_ptr = 0;
                    iov_len -= sp;
                    guest_handle_add_offset (buf_hnd, sp);
                }
    
                if ((ret =
                         v4v_memcpy_to_guest_ring_from_guest (ring_info,
                                 ring.tx_ptr +
                                 sizeof (v4v_ring_t),
                                 buf_hnd, iov_len)))
                    break;
    
                ring.tx_ptr += iov_len;
    
                if (ring.tx_ptr == ring_info->len)
                    ring.tx_ptr = 0;
            }

            guest_handle_add_offset (iovs, 1);
        }
        if (ret)
            break;

        ring.tx_ptr = V4V_ROUNDUP (ring.tx_ptr);

        if (ring.tx_ptr >= ring_info->len)
            ring.tx_ptr -= ring_info->len;


        mb ();
        ring_info->tx_ptr = ring.tx_ptr;
        if ((ret = v4v_update_tx_ptr(ring_info, ring.tx_ptr)))
            break;
    } while (1 == 0);

    //v4v_ring_unmap (ring_info);

    return ret ? ret : happy_ret;

}



/***** pending ******/

/*caller must have L3 */
static void
v4v_pending_remove_ent (struct v4v_pending_ent *ent)
{
    hlist_del (&ent->node);
    v4v_xfree (ent);
}

/*caller must have L3 */
static void
v4v_pending_remove_all (struct v4v_ring_info *info)
{

    struct hlist_node *node, *next;
    struct v4v_pending_ent *pending_ent;


    hlist_for_each_entry_safe (pending_ent, node, next, &info->pending,
                               node) v4v_pending_remove_ent (pending_ent);
}

/*Caller must hold L1 */
static void
v4v_pending_notify (struct domain *caller_d, struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *pending_ent;


    hlist_for_each_entry_safe (pending_ent, node, next, to_notify, node) {
        hlist_del (&pending_ent->node);
        v4v_signal_domid (pending_ent->id);
        v4v_xfree (pending_ent);
    }

}

/*caller must have R(L2) */
static void
v4v_pending_find (struct v4v_ring_info *ring_info, uint32_t payload_space,
                  struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *ent;

    spin_lock (&ring_info->lock);
    hlist_for_each_entry_safe (ent, node, next, &ring_info->pending, node) {
        if (payload_space >= ent->len) {
            hlist_del (&ent->node);
            hlist_add_head (&ent->node, to_notify);
        }
    }
    spin_unlock (&ring_info->lock);
}

/*caller must have L3 */
static int
v4v_pending_queue (struct v4v_ring_info *ring_info, domid_t src_id, int len)
{
    struct v4v_pending_ent *ent = v4v_xmalloc (struct v4v_pending_ent);
    if (!ent)
        return -ENOMEM;

    ent->len = len;
    ent->id = src_id;

    hlist_add_head (&ent->node, &ring_info->pending);

    return 0;
}

/* caller must have L3 */
static int
v4v_pending_requeue (struct v4v_ring_info *ring_info, domid_t src_id, int len)
{
    struct hlist_node *node;
    struct v4v_pending_ent *ent;

    hlist_for_each_entry (ent, node, &ring_info->pending, node)
    if (ent->id == src_id) {
        if (ent->len < len)
            ent->len = len;
        return 0;
    }

    return v4v_pending_queue (ring_info, src_id, len);
}


/* caller must have L3 */
static void
v4v_pending_cancel (struct v4v_ring_info *ring_info, domid_t src_id)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *ent;

    hlist_for_each_entry_safe (ent, node, next, &ring_info->pending, node) {
        if (ent->id == src_id) {
            hlist_del (&ent->node);
            v4v_xfree (ent);
        }
    }
}



/*ring data*/

/*Caller should hold R(L1)*/
static int
v4v_fill_ring_data (struct domain *src_d,
                    XEN_GUEST_HANDLE (v4v_ring_data_ent_t) data_ent_hnd)
{
    v4v_ring_data_ent_t ent;
    struct domain *dst_d;
    struct v4v_ring_info *ring_info;

    if (copy_from_guest (&ent, data_ent_hnd, 1))
        return -EFAULT;

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s: ent.ring.domain=vm%u, ent.ring.port=%d\n",
           __FUNCTION__, ent.ring.domain, ent.ring.port);
#endif

    ent.flags = 0;

    dst_d = get_domain_by_id (ent.ring.domain);

    if (dst_d && dst_d->v4v) {
        read_lock (&dst_d->v4v->lock);
        ring_info =
            v4v_ring_find_info_by_addr (dst_d, &ent.ring, src_d->domain_id);

        if (ring_info) {
            uint32_t space_avail;

            ent.flags |= V4V_RING_DATA_F_EXISTS;
            ent.max_message_size =
                ring_info->len - sizeof (struct v4v_ring_message_header) -
                V4V_ROUNDUP (1);
            spin_lock (&ring_info->lock);

            space_avail = v4v_ringbuf_payload_space (dst_d, ring_info);

#if 0
            printk(XENLOG_ERR "%s: port=%d space_avail=%d space_wanted=%d\n",
                   __FUNCTION__, ring_info->id.addr.port, space_avail,
                   ent.space_required);
#endif

            if (space_avail >= ent.space_required) {
                v4v_pending_cancel (ring_info, src_d->domain_id);
                ent.flags |= V4V_RING_DATA_F_SUFFICIENT;
            } else {
                v4v_pending_requeue (ring_info, src_d->domain_id,
                                     ent.space_required);
                ent.flags |= V4V_RING_DATA_F_PENDING;
            }

            spin_unlock (&ring_info->lock);

            if (space_avail == ent.max_message_size)
                ent.flags |= V4V_RING_DATA_F_EMPTY;

        }
        read_unlock (&dst_d->v4v->lock);
    }

    if (dst_d)
        put_domain (dst_d);

    if (copy_field_to_guest (data_ent_hnd, &ent, flags))
        return -EFAULT;
#if 0                           //FIXME sa
    if (copy_field_to_guest (data_ent_hnd, &ent, space_avail)) {
        DEBUG_BANANA;
        return -EFAULT;
    }

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "    ent.flags=%04x ent.space_avail=%d\n",
           ent.flags, ent.space_avail);
#endif
#endif

    return 0;
}

/*Called should hold no more than R(L1) */
static int
v4v_fill_ring_datas (struct domain *d, int nent,
                     XEN_GUEST_HANDLE (v4v_ring_data_ent_t) data_ent_hnd)
{
    int ret = 0;
    read_lock (&v4v_lock);
    while (!ret && nent--) {
        ret = v4v_fill_ring_data (d, data_ent_hnd);
        guest_handle_add_offset (data_ent_hnd, 1);
    }
    read_unlock (&v4v_lock);
    return ret;
}

/**************************************** ring ************************/




static int
v4v_find_ring_mfns (struct domain *d, struct v4v_ring_info *ring_info,
                    XEN_GUEST_HANDLE (v4v_pfn_list_t) pfn_list_hnd)
{
    XEN_GUEST_HANDLE (v4v_pfn_t) pfn_hnd;
    v4v_pfn_list_t pfn_list;
    int i, j, ret = 0;
    mfn_t *mfns;
    uint8_t **mfn_mapping;
    unsigned long mfn;
#if 0
    struct page_info *page;
#endif

    if (copy_from_guest (&pfn_list, pfn_list_hnd, 1))
        return -EFAULT;


    if (pfn_list.magic != V4V_PFN_LIST_MAGIC)
        return -EINVAL;

    if ((pfn_list.npage << PAGE_SHIFT) < ring_info->len)
        return -EINVAL;

    {
        XEN_GUEST_HANDLE (uint8_t) slop_hnd =
            guest_handle_cast (pfn_list_hnd, uint8_t);
        guest_handle_add_offset (slop_hnd, sizeof (v4v_pfn_list_t));
        pfn_hnd = guest_handle_cast (slop_hnd, v4v_pfn_t);
    }

    if (pfn_list.npage  > (V4V_MAX_RING_SIZE >> PAGE_SHIFT))
        return -EINVAL;

    mfns = v4v_xmalloc_array (mfn_t, pfn_list.npage);
    if (!mfns)
        return -ENOMEM;

    mfn_mapping = v4v_xmalloc_array (uint8_t *, pfn_list.npage);
    if (!mfn_mapping) {
        v4v_xfree (mfns);
        return -ENOMEM;
    }



    for (i = 0; i < pfn_list.npage; ++i) {
        v4v_pfn_t pfn;
        if (copy_from_guest_offset (&pfn, pfn_hnd, i, 1)) {
            ret = -EFAULT;
            break;
        }

#if 0
        page = get_page_from_gfn (d, pfn, NULL, P2M_ALLOC);
        if (unlikely(!page)) {
            printk(XENLOG_ERR "%s: vm%d passed invalid gmfn %"PRI_mfn
                   " ring %p seq %d\n", __FUNCTION__, d->domain_id,
                   pfn, ring_info, i);
            ret = -EINVAL;
            break;
        }
        mfn = page_to_mfn (page);
        if ( !mfn_valid(mfn) ) {
            printk(XENLOG_ERR "%s: vm%d passed invalid mfn %"PRI_mfn
                   " ring %p seq %d\n", __FUNCTION__, d->domain_id,
                   mfn, ring_info, i);
            ret = -EINVAL;
            put_page(page);
            break;
        }
        if ( !get_page_type(page, PGT_writable_page) ) {
            printk(XENLOG_ERR "%s: vm%d passed wrong type mfn %"PRI_mfn
                   " ring %p seq %d\n", __FUNCTION__, d->domain_id,
                   mfn, ring_info, i);
            ret = -EINVAL;
            break;
        }
#else

        if (mfns_dont_belong_xen(d)) {
            mfn = pfn;
        } else {

            mfn = get_gfn_untyped(d, pfn);

            if ( !mfn_valid(mfn) ||
                 !get_page_and_type(mfn_to_page(mfn), d, PGT_writable_page) ) {
                put_gfn(d, pfn); //XXX: JMM check surely don't put if mfn is invalid

                printk(XENLOG_ERR "%s: vm%u passed invalid mfn %"PRI_mfn
                       " ring %p seq %d\n", __FUNCTION__, d->domain_id,
                       mfn, ring_info, i);
                ret = -EINVAL;
                break;
            }
        }
#endif

        mfns[i] = _mfn(mfn);

#ifdef V4V_DEBUG
        printk(XENLOG_ERR "%s: %d: %"PRIx64" -> %"PRI_mfn"\n", __FUNCTION__,
               i, pfn, mfn_x(mfns[i]));
#endif
        if (mfn_x (mfns[i]) == INVALID_MFN) {
            v4v_xfree (mfn_mapping);
            v4v_xfree (mfns);
            return -EINVAL;
        }
        mfn_mapping[i] = NULL;
    }

    if (!ret) {
        ring_info->npage = pfn_list.npage;
        ring_info->mfns = mfns;
        printk(XENLOG_ERR "%s: vm%u ring (vm%u:%x vm%d) %p mfn_mapping %p\n",
               __FUNCTION__, current->domain->domain_id,
               ring_info->id.addr.domain, ring_info->id.addr.port,
               ring_info->id.partner, ring_info, mfn_mapping);
        ring_info->mfn_mapping = mfn_mapping;
    } else {
        j = i;
        for (i = 0; i < j; ++i)
            if (mfn_x(mfns[i]) != 0)
                put_page_and_type(mfn_to_page(mfn_x(mfns[i])));
        v4v_xfree (mfn_mapping);
        v4v_xfree (mfns);
    }
    return ret;
}


/* caller must hold R(L2) */
static struct v4v_ring_info *
v4v_ring_find_info (struct domain *d, struct v4v_ring_id *id)
{
    uint16_t hash;
    struct hlist_node *node;
    struct v4v_ring_info *ring_info;

    hash = v4v_hash_fn (id);

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s: d->v4v=%p, d->v4v->ring_hash[%d]=%p id=%p\n",
           __FUNCTION__, d->v4v, hash, d->v4v->ring_hash[hash].first, id);
    printk(XENLOG_ERR "%s: id.addr.port=%d id.addr.domain=vm%u"
           " id.addr.partner=vm%d\n", __FUNCTION__,
           id->addr.port, id->addr.domain, id->partner);
#endif

    hlist_for_each_entry (ring_info, node, &d->v4v->ring_hash[hash], node) {
        if (!memcmp (id, &ring_info->id, sizeof (*id))) {
#ifdef V4V_DEBUG
            printk(XENLOG_ERR "%s: ring_info=%p\n", __FUNCTION__, ring_info);
#endif
            return ring_info;
        }
    }
#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s: no ring_info found\n", __FUNCTION__);
#endif

    return NULL;
}

/* caller must hold R(L2) */
static struct v4v_ring_info *
v4v_ring_find_info_by_addr (struct domain *d, struct v4v_addr *a, domid_t p)
{
    struct v4v_ring_id id;
    struct v4v_ring_info *ret;

    if (!a)
        return NULL;

    id.addr.port = a->port;
    id.addr.domain = d->domain_id;
    id.partner = p;

    ret = v4v_ring_find_info (d, &id);
    if (ret)
        return ret;

    id.partner = V4V_DOMID_NONE;

    return v4v_ring_find_info (d, &id);
}

/*caller must hold W(L2) */
static void v4v_ring_remove_mfns (struct v4v_ring_info *ring_info, int put_pages)
{
    int i;
    if (ring_info->mfns) {
        if (put_pages)
            for (i = 0; i < ring_info->npage; ++i)
                if (mfn_x(ring_info->mfns[i]) != 0)
                    put_page_and_type(mfn_to_page(mfn_x(ring_info->mfns[i])));
        v4v_xfree (ring_info->mfns);
    }
    ring_info->mfns = NULL;
}

/*caller must hold W(L2) */
static void
v4v_ring_reset(struct v4v_ring_info *ring_info, int put_pages)
{

    v4v_ring_unmap(ring_info);
    v4v_ring_remove_mfns(ring_info, put_pages);

    ring_info->len = 0;
    ring_info->tx_ptr = 0;
    ring_info->ring = XEN_GUEST_HANDLE_NULL(v4v_ring_t);
    ring_info->npage = 0;
}

/*caller must hold W(L2) */
static void
v4v_ring_remove_info (struct v4v_ring_info *ring_info, int put_pages)
{
    v4v_pending_remove_all (ring_info);
    v4v_ring_unmap (ring_info);
    hlist_del (&ring_info->node);
    v4v_ring_remove_mfns(ring_info, put_pages);
    v4v_xfree (ring_info);
}

/* Call from guest to unpublish a ring */
static long
v4v_ring_remove (struct domain *d, XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd)
{
    struct v4v_ring ring;
    struct v4v_ring_info *ring_info;
    int ret = 0;

    read_lock (&v4v_lock);

    do {

        if (!d->v4v) {
            ret = -EINVAL;
            break;
        }

        if (copy_from_guest (&ring, ring_hnd, 1)) {
            ret = -EFAULT;
            break;
        }

        if (ring.magic != V4V_RING_MAGIC) {
            ret = -EINVAL;
            break;
        }

        ring.id.addr.domain = d->domain_id;

        write_lock (&d->v4v->lock);
        ring_info = v4v_ring_find_info (d, &ring.id);

        if (ring_info)
            v4v_ring_remove_info (ring_info, !mfns_dont_belong_xen(d)); //Fixme for type1.5

        write_unlock (&d->v4v->lock);

        if (!ring_info) {
            ret = -ENOENT;
            break;
        }

    } while (1 == 0);

    read_unlock (&v4v_lock);

    return ret;
}

/* call from host to make placeholder in a guest for a ring */
static long
v4v_ring_create (struct domain *d, XEN_GUEST_HANDLE (v4v_ring_id_t) ring_id_hnd)
{
    struct domain *dst_d = NULL;
    struct v4v_ring_info *ring_info;
    struct v4v_ring_id ring_id;
    int ret = 0;
    uint16_t hash;


    if (!v4v_can_do_create())
        return -EPERM;

    read_lock (&v4v_lock);

    do {

        if (copy_from_guest (&ring_id, ring_id_hnd, 1)) {
            ret = -EFAULT;
            break;
        }


        if (ring_id.partner != V4V_DOMID_ANY)
            ring_id.partner = current->domain->domain_id;

        dst_d = get_domain_by_id (ring_id.addr.domain);

        if (!dst_d) {
            ret = -ENOENT;
            break;
        }


        if (!dst_d->v4v) {
            ret = -ENOENT;
            break;
        }

        write_lock (&dst_d->v4v->lock);
        ring_info = v4v_ring_find_info (dst_d, &ring_id);

        if (ring_info) {
            write_unlock (&dst_d->v4v->lock);
            /* We already have a record for this ring - we're done */
            break;
        }

        ring_info = v4v_xmalloc (struct v4v_ring_info);
        if (!ring_info) {
            ret = -ENOMEM;
            break;
        }
        spin_lock_init (&ring_info->lock);
        INIT_HLIST_HEAD (&ring_info->pending);

        ring_info->mfns = NULL;
        ring_info->mfn_mapping = NULL;
        ring_info->len = 0;

        ring_info->tx_ptr = 0;
        ring_info->ring = XEN_GUEST_HANDLE_NULL(v4v_ring_t);
        ring_info->npage = 0;

        spin_lock (&ring_info->lock);
        ring_info->id = ring_id;

        hash = v4v_hash_fn (&ring_id);
        hlist_add_head (&ring_info->node, &dst_d->v4v->ring_hash[hash]);
        write_unlock (&dst_d->v4v->lock);

        printk(XENLOG_INFO "%s: vm%u creating placeholder ring (vm%u:%x vm%d)"
               "\n", __FUNCTION__, current->domain->domain_id,
               ring_id.addr.domain, ring_id.addr.port, ring_id.partner);

        //We now require the caller retries the send
        //v4v_pending_queue (ring_info, d->domain_id, 1);

        spin_unlock (&ring_info->lock);

    } while (1 == 0);

    if (dst_d)
        put_domain (dst_d);

    read_unlock (&v4v_lock);
    return ret;
}


/* call from guest to publish a ring */
static long
v4v_ring_add (struct domain *d, XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd,
              XEN_GUEST_HANDLE (v4v_pfn_list_t) pfn_list_hnd)
{
    struct v4v_ring ring;
//  struct v4v_ring_data ring_data = { 0 };
    struct v4v_ring_info *ring_info;
    uint16_t hash;
    int ret = 0;

    if ((long) ring_hnd.p & (PAGE_SIZE - 1))
        return -EINVAL;

    read_lock (&v4v_lock);

    do {
        if (!d->v4v) {
            ret = -EINVAL;
            break;
        }

        if (copy_from_guest (&ring, ring_hnd, 1)) {
            ret = -EFAULT;
            break;
        }

        if (ring.magic != V4V_RING_MAGIC) {
            ret = -EINVAL;
            break;
        }

        if ((ring.len <
             (sizeof (struct v4v_ring_message_header) + V4V_ROUNDUP (1) +
              V4V_ROUNDUP (1))) || (V4V_ROUNDUP (ring.len) != ring.len)) {
            ret = -EINVAL;
            break;
        }

        if (ring.len > V4V_MAX_RING_SIZE) {
            ret = -EINVAL;
            break;
        }

        ring.id.addr.domain = d->domain_id;
        if (copy_field_to_guest (ring_hnd, &ring, id)) {
            ret = -EFAULT;
            break;
        }

        /* no need for a lock yet, because only we know about this */
        /* set the tx pointer if it looks bogus (we don't reset it always because this might be a re-register after S4) */
        if ((ring.tx_ptr >= ring.len)
            || (V4V_ROUNDUP (ring.tx_ptr) != ring.tx_ptr)) {

            ring.tx_ptr = V4V_ROUNDUP(ring.rx_ptr);

            if (ring.tx_ptr >= ring.len) {
                ring.tx_ptr = 0;
            }

            copy_field_to_guest (ring_hnd, &ring, tx_ptr); ///XXX: not atomic
        }

        write_lock (&d->v4v->lock);
        ring_info = v4v_ring_find_info (d, &ring.id);

        if (!ring_info) {
            ring_info = v4v_xmalloc (struct v4v_ring_info);
            if (!ring_info) {
                write_unlock(&d->v4v->lock);
                ret = -ENOMEM;
                break;
            }

            spin_lock_init (&ring_info->lock);
            spin_lock (&ring_info->lock);

            ring_info->mfns = NULL;
            ring_info->mfn_mapping = NULL;

            ring_info->id = ring.id;
            INIT_HLIST_HEAD (&ring_info->pending);

            hash = v4v_hash_fn (&ring.id);
            hlist_add_head (&ring_info->node, &d->v4v->ring_hash[hash]);

            write_unlock (&d->v4v->lock);

            printk(XENLOG_INFO "%s: vm%u registering ring (vm%u:%x vm%d)\n",
                   __FUNCTION__, current->domain->domain_id,
                   ring.id.addr.domain, ring.id.addr.port, ring.id.partner);
        } else {
            write_unlock (&d->v4v->lock);

            spin_lock (&ring_info->lock);
            /* Ring info already existed. If mfn list was already
             * populated remove the MFN's from list and then add the
             * new list.
             */
            printk(XENLOG_INFO "%s: vm%d re-registering existing v4v ring"
                   " (%d:%x %d), clearing MFN list\n", __FUNCTION__,
                   current->domain->domain_id, ring.id.addr.domain,
                   ring.id.addr.port, ring.id.partner);
            v4v_ring_remove_mfns(ring_info,
                                 !mfns_dont_belong_xen(current->domain));

            if (ring_info->mfns)
                xfree (ring_info->mfns);
            ring_info->mfns = NULL;
        }

        ring_info->len = ring.len;
        ring_info->tx_ptr = ring.tx_ptr;
        ring_info->ring = ring_hnd;

        ret = v4v_find_ring_mfns (d, ring_info, pfn_list_hnd);
        spin_unlock (&ring_info->lock);

    } while (1 == 0);

    v4v_notify_check_pending(d);

    read_unlock (&v4v_lock);
    return ret;
}


/**************************** io ***************************/

/*Caller must hold v4v_lock and hash_lock*/
static void
v4v_notify_ring (struct domain *d, struct v4v_ring_info *ring_info,
                 struct hlist_head *to_notify)
{
    uint32_t space;

    spin_lock (&ring_info->lock);
    if (ring_info->len)
        space = v4v_ringbuf_payload_space (d, ring_info);
    else space = 0;
    spin_unlock (&ring_info->lock);
    if (space)
        v4v_pending_find (ring_info, space, to_notify);

}


/*Caller must hold L1 */
static void v4v_notify_check_pending(struct domain *d)
{
    int i;
    HLIST_HEAD (to_notify);

    read_lock (&d->v4v->lock);

    mb();

    for (i = 0; i < V4V_HTABLE_SIZE; ++i) {
        struct hlist_node *node, *next;
        struct v4v_ring_info *ring_info;

        hlist_for_each_entry_safe (ring_info, node,
                                   next, &d->v4v->ring_hash[i],
                                   node)
        v4v_notify_ring (d, ring_info, &to_notify);
    }
    read_unlock (&d->v4v->lock);



    if (!hlist_empty (&to_notify)) {
        v4v_pending_notify (d, &to_notify);
    }
}


/*notify hypercall*/
static long
v4v_notify (struct domain *d,
            XEN_GUEST_HANDLE (v4v_ring_data_t) ring_data_hnd)
{
    v4v_ring_data_t ring_data;
    int ret = 0;

    read_lock (&v4v_lock);

    if (!d->v4v) {
        read_unlock (&v4v_lock);
        return -ENODEV;
    }

    v4v_notify_check_pending(d);

    do {
        if (!guest_handle_is_null (ring_data_hnd)) {
            /* Quick sanity check on ring_data_hnd */
            if (copy_field_from_guest (&ring_data, ring_data_hnd, magic)) {
                ret = -EFAULT;
                break;
            }

            if (ring_data.magic != V4V_RING_DATA_MAGIC) {
                ret = -EINVAL;
                break;
            }

            if (copy_from_guest (&ring_data, ring_data_hnd, 1)) {
                ret = -EFAULT;
                break;
            }


            {
                XEN_GUEST_HANDLE (v4v_ring_data_ent_t) ring_data_ent_hnd;
                XEN_GUEST_HANDLE (uint8_t) slop_hnd =
                    guest_handle_cast (ring_data_hnd, uint8_t);
                guest_handle_add_offset (slop_hnd, sizeof (v4v_ring_data_t));
                ring_data_ent_hnd =
                    guest_handle_cast (slop_hnd, v4v_ring_data_ent_t);
                ret = v4v_fill_ring_datas (d, ring_data.nent, ring_data_ent_hnd);

            }
        }
    } while (1 == 0);

    read_unlock (&v4v_lock);

    return ret;
}

#if 0
/*Hypercall to do the poke*/
static size_t
v4v_poke (v4v_addr_t *dst_addr)
{
    if (!dst_addr)
        return -EINVAL;

    v4v_signal_domid (dst_addr->domain);

    return 0;
}
#endif


/*Hypercall to do the send*/
static size_t
v4v_send (struct domain *src_d, v4v_addr_t *src_addr,
          v4v_addr_t *dst_addr, uint32_t proto,
          XEN_GUEST_HANDLE (void) buf, size_t len)
{
    struct domain *dst_d;
    struct v4v_ring_id src_id;
    struct v4v_ring_info *ring_info;
    int ret = 0;

    if (!dst_addr)
        return -EINVAL;

    if (len > V4V_MAX_RING_SIZE) return -EINVAL;

    read_lock (&v4v_lock);
    if (!src_d->v4v) {
        read_unlock (&v4v_lock);
        return -EINVAL;
    }

#if 0
    read_lock (&src_d->v4v->lock);
    ring_info = v4v_ring_find_info_by_addr (src_d, src_addr, dst_addr->domain);
    if (ring_info) {
        src_id = ring_info->id;
    } else {
        src_id.addr.port = V4V_PORT_NONE;
        src_id.addr.partner = dst_addr->domain;
    }
    read_unlock (&src_d->v4v->lock);
#endif

    src_id.addr.port = src_addr->port;
    src_id.addr.domain = src_d->domain_id;
    src_id.partner = dst_addr->domain;

    dst_d = get_domain_by_id (dst_addr->domain);
    if (!dst_d) {
        read_unlock (&v4v_lock);
        return -ECONNREFUSED;
    }

#ifdef __V4V_XSM__
    /* XSM: verify if src is allowed to send to dst */
    if (xsm_v4v_send(src_d, dst_d) != 0) {
        read_unlock (&v4v_lock);
        printk(XENLOG_ERR "V4V: XSM REJECTED %i -> %i\n",
               src_addr->domain, dst_addr->domain);
        return -EPERM;
    }
#endif
#ifdef __V4V_TABLES__
    /* V4VTables*/
    if (v4v_tables_check(src_addr, dst_addr) != 0) {
        read_unlock (&v4v_lock);
        printk(XENLOG_ERR "V4V: V4VTables REJECTED %i:%u -> %i:%u\n",
               src_addr->domain, src_addr->port,
               dst_addr->domain, dst_addr->port);
        return -EPERM;
    }
#endif

    do {

        if (!dst_d->v4v) {
            ret = -ECONNREFUSED;
            break;
        }

        read_lock (&dst_d->v4v->lock);
        ring_info =
            v4v_ring_find_info_by_addr (dst_d, dst_addr, src_addr->domain);

        if (!ring_info) {
            v4v_signal_domain (dst_d);
            ret = -ECONNREFUSED;
        } else {
//    printk(XENLOG_ERR "V4V: sending %u bytes to %i:%u\n",(unsigned) len,dst_addr->domain, dst_addr->port);

            spin_lock (&ring_info->lock);
            ret =
                v4v_ringbuf_insert (dst_d, ring_info, &src_id, proto, buf, len);
            if (ret == -EAGAIN) {
                /* Schedule a notification when space is there */
                if (v4v_pending_requeue (ring_info, src_d->domain_id, len))
                    ret = -ENOMEM;
            }
            spin_unlock (&ring_info->lock);

            if (ret >= 0) {
                v4v_signal_domain (dst_d);
            }

        }
        read_unlock (&dst_d->v4v->lock);

    } while (1 == 0);

    put_domain (dst_d);
    read_unlock (&v4v_lock);
    return ret;
}

/*Hypercall to do the send*/
static size_t
v4v_sendv (struct domain *src_d, v4v_addr_t *src_addr,
           v4v_addr_t *dst_addr, uint32_t proto,
           XEN_GUEST_HANDLE (v4v_iov_t) iovs, size_t niov)
{
    struct domain *dst_d;
    struct v4v_ring_id src_id;
    struct v4v_ring_info *ring_info;
    int ret = 0;


    if (!dst_addr)
        return -EINVAL;

    read_lock (&v4v_lock);
    if (!src_d->v4v) {
        read_unlock (&v4v_lock);
        return -EINVAL;
    }

    src_id.addr.port = src_addr->port;
    src_id.addr.domain = src_d->domain_id;
    src_id.partner = dst_addr->domain;

    dst_d = get_domain_by_id (dst_addr->domain);
    if (!dst_d) {
        read_unlock (&v4v_lock);
        return -ECONNREFUSED;
    }

#ifdef __V4V_XSM__
    /* XSM: verify if src is allowed to send to dst */
    if (xsm_v4v_send(src_d, dst_d) != 0) {
        read_unlock (&v4v_lock);
        printk(XENLOG_ERR "V4V: XSM REJECTED %i -> %i\n",
               src_addr->domain, dst_addr->domain);
        return -EPERM;
    }
#endif
#ifdef __V4V_TABLES__
    /* V4VTables*/
    if (v4v_tables_check(src_addr, dst_addr) != 0) {
        read_unlock (&v4v_lock);
        printk(XENLOG_ERR "V4V: V4VTables REJECTED %i:%u -> %i:%u\n",
               src_addr->domain, src_addr->port,
               dst_addr->domain, dst_addr->port);
        return -EPERM;
    }
#endif


    do {

        if (!dst_d->v4v) {
            ret = -ECONNREFUSED;
            break;
        }

        read_lock (&dst_d->v4v->lock);
        ring_info =
            v4v_ring_find_info_by_addr (dst_d, dst_addr, src_addr->domain);

        if (!ring_info) {
            v4v_signal_domain (dst_d);
            ret = -ECONNREFUSED;
        } else {
            ssize_t len = v4v_iov_count (iovs, niov);

//    printk(XENLOG_ERR "V4V: sendving %u bytes to %i:%u\n",len,dst_addr->domain, dst_addr->port);

            if (len < 0) {
                ret = len;
                read_unlock (&dst_d->v4v->lock);
                break;
            }

            spin_lock (&ring_info->lock);
            ret =
                v4v_ringbuf_insertv (dst_d, ring_info, &src_id, proto, iovs,
                                     niov, len);
            if (ret == -EAGAIN) {
                /* Schedule a notification when space is there */
                if (v4v_pending_requeue (ring_info, src_d->domain_id, len)) {
                    ret = -ENOMEM;
                }
            }
            spin_unlock (&ring_info->lock);

            if (ret >= 0) {
                v4v_signal_domain (dst_d);
            }

        }
        read_unlock (&dst_d->v4v->lock);

    } while (1 == 0);

    put_domain (dst_d);
    read_unlock (&v4v_lock);
    return ret;
}


/**************** hypercall glue ************/
long
do_v4v_op (int cmd, XEN_GUEST_HANDLE (void) arg1,
           XEN_GUEST_HANDLE (void) arg2,
           XEN_GUEST_HANDLE (void) arg3, uint32_t arg4, uint32_t arg5)
{
    struct domain *d = current->domain;
    long rc = -EFAULT;

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "->do_v4v_op(%d,%p,%p,%p,%d,%d)\n", cmd,
           arg1.p, arg2.p, arg3.p, arg4, arg5);
#endif

    domain_lock (d);
    switch (cmd) {
        case V4VOP_register_ring: {
                XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd =
                    guest_handle_cast (arg1, v4v_ring_t);
                XEN_GUEST_HANDLE (v4v_pfn_list_t) pfn_list_hnd =
                    guest_handle_cast (arg2, v4v_pfn_list_t);

                if (unlikely (!guest_handle_okay (ring_hnd, 1)))
                    goto out;
                if (unlikely (!guest_handle_okay (pfn_list_hnd, 1))) //FIXME
                    goto out;

                rc = v4v_ring_add (d, ring_hnd, pfn_list_hnd);
                break;
            }
        case V4VOP_unregister_ring: {
                XEN_GUEST_HANDLE (v4v_ring_t) ring_hnd =
                    guest_handle_cast (arg1, v4v_ring_t);
                if (unlikely (!guest_handle_okay (ring_hnd, 1)))
                    goto out;
                rc = v4v_ring_remove (d, ring_hnd);
                break;
            }
        case V4VOP_send: {
                v4v_addr_t src, dst;
                uint32_t len = arg4;
                uint32_t protocol = arg5;
                XEN_GUEST_HANDLE (v4v_addr_t) src_hnd =
                    guest_handle_cast (arg1, v4v_addr_t);
                XEN_GUEST_HANDLE (v4v_addr_t) dst_hnd =
                    guest_handle_cast (arg2, v4v_addr_t);

                if (unlikely (!guest_handle_okay (src_hnd, 1)))
                    goto out;
                if (copy_from_guest (&src, src_hnd, 1))
                    goto out;

                if (unlikely (!guest_handle_okay (dst_hnd, 1)))
                    goto out;
                if (copy_from_guest (&dst, dst_hnd, 1))
                    goto out;

                src.domain = current->domain->domain_id;

                rc = v4v_send (d, &src, &dst, protocol, arg3, len);
                break;
            }
        case V4VOP_sendv: {
                v4v_addr_t src, dst;
                uint32_t niov = arg4;
                uint32_t protocol = arg5;
                XEN_GUEST_HANDLE (v4v_addr_t) src_hnd =
                    guest_handle_cast (arg1, v4v_addr_t);
                XEN_GUEST_HANDLE (v4v_addr_t) dst_hnd =
                    guest_handle_cast (arg2, v4v_addr_t);
                XEN_GUEST_HANDLE (v4v_iov_t) iovs =
                    guest_handle_cast (arg3, v4v_iov_t);

                if (unlikely (!guest_handle_okay (src_hnd, 1)))
                    goto out;
                if (copy_from_guest (&src, src_hnd, 1))
                    goto out;

                if (unlikely (!guest_handle_okay (dst_hnd, 1)))
                    goto out;
                if (copy_from_guest (&dst, dst_hnd, 1))
                    goto out;

                if (unlikely (!guest_handle_okay (iovs, niov)))
                    goto out;

                src.domain = current->domain->domain_id;

                rc = v4v_sendv (d, &src, &dst, protocol, iovs, niov);
                break;
            }
        case V4VOP_notify: {
                XEN_GUEST_HANDLE (v4v_ring_data_t) ring_data_hnd =
                    guest_handle_cast (arg1, v4v_ring_data_t);
                rc = v4v_notify (d, ring_data_hnd);
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
                XEN_GUEST_HANDLE (v4v_ring_id_t) ring_id_hnd =
                    guest_handle_cast (arg1, v4v_ring_id_t);
                if (unlikely (!guest_handle_okay (ring_id_hnd, 1)))
                    goto out;
                rc = v4v_ring_create (d, ring_id_hnd);
                break;
            }
#if 0
        case V4VOP_poke: {
                v4v_addr_t dst;
                XEN_GUEST_HANDLE (v4v_addr_t) dst_hnd =
                    guest_handle_cast (arg1, v4v_addr_t);
                if (copy_from_guest (&dst, dst_hnd, 1))
                    goto out;

                printk(XENLOG_ERR "%s: poking vm%u\n", __FUNCTION__,
                       dst.domain);

                rc = v4v_poke(&dst);
            }
            break;
        case V4VOP_test:
            printk(XENLOG_ERR "V4VOP_test called with args: %p %p %p %x %x\n",
                   arg1.p, arg2.p, arg3.p, arg4, arg5);
            rc = 0;
            break;
        case V4VOP_debug:
            printk(XENLOG_ERR "V4VOP_debug\n");
            dump_rings('4');
            rc = 0;
            break;
#endif
        default:
            rc = -ENOSYS;
            break;
    }
out:
    domain_unlock (d);
#ifdef V4V_DEBUG
    printk(XENLOG_ERR "<-do_v4v_op()=%d\n", (int) rc);
#endif
    return rc;
}




/**************** init *******************/

void
v4v_destroy (struct domain *d)
{
    int i;


    BUG_ON (!d->is_dying);
    write_lock (&v4v_lock);

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "%s:%d: d->v=%p\n", __FUNCTION__, __LINE__, d->v4v);
#endif

    if (d->v4v)
        for (i = 0; i < V4V_HTABLE_SIZE; ++i) {
            struct hlist_node *node, *next;
            struct v4v_ring_info *ring_info;
            hlist_for_each_entry_safe (ring_info, node,
                                       next, &d->v4v->ring_hash[i],
                                       node) v4v_ring_remove_info (ring_info, !mfns_dont_belong_xen(d));
        }

    d->v4v = NULL;
    write_unlock (&v4v_lock);
}


static int
handle_v4v_portio(int dir, uint32_t port, uint32_t size, uint32_t *val)
{
    return X86EMUL_UNHANDLEABLE;

}


int
v4v_init (struct domain *d)
{
    struct v4v_domain *v4v;
    int i;
#if 0
    uint8_t one = 1;
#endif

    v4v = v4v_xmalloc (struct v4v_domain);
    if (!v4v)
        return -ENOMEM;

    rwlock_init (&v4v->lock);

    for (i = 0; i < V4V_HTABLE_SIZE; ++i) {
        INIT_HLIST_HEAD (&v4v->ring_hash[i]);
    }

    write_lock (&v4v_lock);
    d->v4v = v4v;
    write_unlock (&v4v_lock);

    if (!deliver_via_upcall(d)) {
#if 0
        u16 bdf = PCI_BDF(V4V_PCI_BUS, V4V_PCI_SLOT, V4V_PCI_FN);

        hvm_register_pcidev_with_lock(d, SERVID_INTERNAL, bdf);
        register_pciconfig_handler(d, PCI_BDF_TO_CF8(bdf), PCI_CONFIG_SPACE_SIZE, pci_device_config_handler);

        hvm_pcidev_set_ids(d, bdf, V4V_PCI_VENDOR, V4V_PCI_DEVICE, V4V_PCI_CLASS, V4V_PCI_REVISION,
                           V4V_PCI_VENDOR, V4V_PCI_DEVICE);


        hvm_pcidev_set_config(d, bdf, PCI_INTERRUPT_PIN, sizeof(one), &one);
#endif

        register_portio_handler(d, 0x330, 8, handle_v4v_portio);
    }

    return 0;
}

void
v4v_shutdown(struct domain *d)
{
    int i;

    if (!d)
        return;

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

void
v4v_resume(struct domain *d)
{

    if (!d)
        return;

    if (!get_domain(d))
        return;

    v4v_signal_domain(d);
    put_domain(d);
}


/*************************** debug ********************************/

static void
dump_domain_ring (struct domain *d, struct v4v_ring_info *ring_info)
{
    uint32_t rx_ptr;


    printk(XENLOG_ERR "  ring: domid=vm%u port=0x%08x partner=vm%d npage=%d\n",
           d->domain_id, ring_info->id.addr.port,
           ring_info->id.partner, ring_info->npage);

    if (!ring_info->len) {
        printk(XENLOG_ERR "   (Placeholder)\n");
    } else {
        if (v4v_ringbuf_get_rx_ptr (d, ring_info, &rx_ptr)) {
            printk(XENLOG_ERR "   Failed to read rx_ptr\n");
            return;
        }
        printk(XENLOG_ERR "   tx_ptr=%d rx_ptr=%d len=%d\n",
               ring_info->tx_ptr, rx_ptr, ring_info->len);
    }
}

static void
dump_domain_rings (struct domain *d)
{
    int i;

    printk(XENLOG_ERR " vm%u:\n", d->domain_id);

    if (!d->v4v) return;

    read_lock (&d->v4v->lock);

    for (i = 0; i < V4V_HTABLE_SIZE; ++i) {
        struct hlist_node *node;
        struct v4v_ring_info *ring_info;

        hlist_for_each_entry (ring_info, node, &d->v4v->ring_hash[i], node)
        dump_domain_ring (d, ring_info);
    }


    read_unlock (&d->v4v->lock);

    printk(XENLOG_ERR "\n");

    //XXX: without this the subsequent upcall calls KeQueueDpc on the host in
    //exception handling context appears to break delivery of the timer dpc
    //to the idle thread.

    if (!deliver_via_upcall(d))
        v4v_signal_domain (d);
}

static void
dump_rings (unsigned char key)
{
    struct domain *d;

    printk(XENLOG_ERR "\n\nV4V ring dump:\n");
    read_lock (&v4v_lock);

    rcu_read_lock (&domlist_read_lock);

    for_each_domain (d) dump_domain_rings (d);

    rcu_read_unlock (&domlist_read_lock);

    read_unlock (&v4v_lock);
}

struct keyhandler dump_v4v_rings = {
    .diagnostic = 1,
    .u.fn = dump_rings,
    .desc = "dump v4v ring states and interrupt"
};

static int __init
setup_dump_rings (void)
{
    register_keyhandler ('4', &dump_v4v_rings);
    return 0;
}

__initcall (setup_dump_rings);




/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
