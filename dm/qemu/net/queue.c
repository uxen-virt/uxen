/*
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2009 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

// #include "net/queue.h"
// #include "qemu-queue.h"

#include <dm/qemu_glue.h>
#include "queue.h"

#if defined(DEBUG)
static int net_queue_sent = 0;
static int net_queue_dropped = 0;
static int net_queue_queued = 0;
static int net_queue_depth = 0;
static int net_queue_maxdepth = 0;
#define STAT_NET_QUEUE_SENT() net_queue_sent++
#define STAT_NET_QUEUE_DROPPED() do { \
        net_queue_dropped++;          \
        net_queue_depth--;            \
    } while (0)
#define STAT_NET_QUEUE_QUEUED() do {                    \
        net_queue_queued++;                             \
        net_queue_depth++;                              \
        if (net_queue_depth > net_queue_maxdepth)       \
            net_queue_maxdepth = net_queue_depth;       \
    } while (0)
#define STAT_NET_QUEUE_DEQUEUE() net_queue_depth--
#else
#define STAT_NET_QUEUE_SENT() do { /**/ } while (0)
#define STAT_NET_QUEUE_DROPPED() do { /**/ } while (0)
#define STAT_NET_QUEUE_QUEUED() do { /**/ } while (0)
#define STAT_NET_QUEUE_DEQUEUE() do { /**/ } while (0)
#endif

/* The delivery handler may only return zero if it will call
 * qemu_net_queue_flush() when it determines that it is once again able
 * to deliver packets. It must also call qemu_net_queue_purge() in its
 * cleanup path.
 *
 * If a sent callback is provided to send(), the caller must handle a
 * zero return from the delivery handler by not sending any more packets
 * until we have invoked the callback. Only in that case will we queue
 * the packet.
 *
 * If a sent callback isn't provided, we just drop the packet to avoid
 * unbounded queueing.
 */

struct NetPacket {
    QTAILQ_ENTRY(NetPacket) entry;
    VLANClientState *sender;
    unsigned flags;
    int size;
    NetPacketSent *sent_cb;
    uint8_t data[0];
};

struct NetQueue {
    NetPacketDeliver *deliver;
    NetPacketDeliverIOV *deliver_iov;
    void *opaque;

    QTAILQ_HEAD(packets, NetPacket) packets;

    unsigned delivering : 1;
};

NetQueue *qemu_new_net_queue(NetPacketDeliver *deliver,
                             NetPacketDeliverIOV *deliver_iov,
                             void *opaque)
{
    NetQueue *queue;

    queue = g_malloc0(sizeof(NetQueue));

    queue->deliver = deliver;
    queue->deliver_iov = deliver_iov;
    queue->opaque = opaque;

    QTAILQ_INIT(&queue->packets);

    queue->delivering = 0;

    return queue;
}

void qemu_del_net_queue(NetQueue *queue)
{
    NetPacket *packet, *next;

    QTAILQ_FOREACH_SAFE(packet, &queue->packets, entry, next) {
        QTAILQ_REMOVE(&queue->packets, packet, entry);
        STAT_NET_QUEUE_DROPPED();
        g_free(packet);
    }

    g_free(queue);
}

static ssize_t qemu_net_queue_append(NetQueue *queue,
                                     VLANClientState *sender,
                                     unsigned flags,
                                     const uint8_t *buf,
                                     size_t size,
                                     NetPacketSent *sent_cb)
{
    NetPacket *packet;

    packet = g_malloc(sizeof(NetPacket) + size);
    packet->sender = sender;
    packet->flags = flags;
    packet->size = size;
    packet->sent_cb = sent_cb;
    memcpy(packet->data, buf, size);

    QTAILQ_INSERT_TAIL(&queue->packets, packet, entry);
    STAT_NET_QUEUE_QUEUED();

    return size;
}

static ssize_t qemu_net_queue_append_iov(NetQueue *queue,
                                         VLANClientState *sender,
                                         unsigned flags,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         NetPacketSent *sent_cb)
{
    NetPacket *packet;
    size_t max_len = 0;
    int i;

    for (i = 0; i < iovcnt; i++) {
        max_len += iov[i].iov_len;
    }

    packet = g_malloc(sizeof(NetPacket) + max_len);
    packet->sender = sender;
    packet->sent_cb = sent_cb;
    packet->flags = flags;
    packet->size = 0;

    for (i = 0; i < iovcnt; i++) {
        size_t len = iov[i].iov_len;

        memcpy(packet->data + packet->size, iov[i].iov_base, len);
        packet->size += len;
    }

    QTAILQ_INSERT_TAIL(&queue->packets, packet, entry);
    STAT_NET_QUEUE_QUEUED();

    return packet->size;
}

static ssize_t qemu_net_queue_deliver(NetQueue *queue,
                                      VLANClientState *sender,
                                      unsigned flags,
                                      const uint8_t *data,
                                      size_t size)
{
    ssize_t ret = -1;

    queue->delivering = 1;
    ret = queue->deliver(sender, flags, data, size, queue->opaque);
    queue->delivering = 0;

    return ret;
}

static ssize_t qemu_net_queue_deliver_iov(NetQueue *queue,
                                          VLANClientState *sender,
                                          unsigned flags,
                                          const struct iovec *iov,
                                          int iovcnt)
{
    ssize_t ret = -1;

    queue->delivering = 1;
    ret = queue->deliver_iov(sender, flags, iov, iovcnt, queue->opaque);
    queue->delivering = 0;

    return ret;
}

ssize_t qemu_net_queue_send(NetQueue *queue,
                            VLANClientState *sender,
                            unsigned flags,
                            const uint8_t *data,
                            size_t size,
                            NetPacketSent *sent_cb)
{
    ssize_t ret;

    if (queue->delivering) {
        return qemu_net_queue_append(queue, sender, flags, data, size, NULL);
    }

    ret = qemu_net_queue_deliver(queue, sender, flags, data, size);
    if (ret <= 0) {
        qemu_net_queue_append(queue, sender, flags, data, size, sent_cb);
        return 0;
    } else
        STAT_NET_QUEUE_SENT();

    qemu_net_queue_flush(queue);

    return ret;
}

ssize_t qemu_net_queue_send_iov(NetQueue *queue,
                                VLANClientState *sender,
                                unsigned flags,
                                const struct iovec *iov,
                                int iovcnt,
                                NetPacketSent *sent_cb)
{
    ssize_t ret;

    if (queue->delivering) {
        return qemu_net_queue_append_iov(queue, sender, flags, iov, iovcnt, NULL);
    }

    ret = qemu_net_queue_deliver_iov(queue, sender, flags, iov, iovcnt);
    if (ret <= 0) {
        qemu_net_queue_append_iov(queue, sender, flags, iov, iovcnt, sent_cb);
        return 0;
    }

    qemu_net_queue_flush(queue);

    return ret;
}

void qemu_net_queue_purge(NetQueue *queue, VLANClientState *from)
{
    NetPacket *packet, *next;

    QTAILQ_FOREACH_SAFE(packet, &queue->packets, entry, next) {
        if (packet->sender == from) {
            QTAILQ_REMOVE(&queue->packets, packet, entry);
            STAT_NET_QUEUE_DROPPED();
            g_free(packet);
        }
    }
}

void qemu_net_queue_flush(NetQueue *queue)
{
    while (!QTAILQ_EMPTY(&queue->packets)) {
        NetPacket *packet;
        int ret;

        packet = QTAILQ_FIRST(&queue->packets);
        QTAILQ_REMOVE(&queue->packets, packet, entry);
        STAT_NET_QUEUE_DEQUEUE();

        ret = qemu_net_queue_deliver(queue,
                                     packet->sender,
                                     packet->flags,
                                     packet->data,
                                     packet->size);
        if (ret <= 0) {
            QTAILQ_INSERT_HEAD(&queue->packets, packet, entry);
            STAT_NET_QUEUE_QUEUED();
            break;
        } else
            STAT_NET_QUEUE_SENT();

        if (packet->sent_cb) {
            packet->sent_cb(packet->sender, ret);
        }

        g_free(packet);
    }
}

#if defined(DEBUG)
void
do_info_net_queue(void)
{
    debug_printf("net queue sent %d dropped %d queued %d max depth %d\n",
                 net_queue_sent, net_queue_dropped,
                 net_queue_queued, net_queue_maxdepth);
    if (net_queue_depth)
        debug_printf("net queue current depth %d\n", net_queue_depth);
}
#endif
