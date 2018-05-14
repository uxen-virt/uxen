/*
 * Copyright 2015-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/pci.h>
#include <dm/qemu/net.h>

#include <dm/block.h>
#include <dm/dmpdev.h>
#include <dm/hw.h>
#include <dm/firmware.h>

#include "uxen_v4v.h"

#include "uxen_platform.h"
#include <uxen/platform_interface.h>

#include <time.h>
#include <sys/time.h>

#define ETHER_ADDR_LEN 6
#define ETH_MTU     (65536 + 14)
#define ETH_MINTU   60


#define PACKET_LEN ( sizeof(uxen_net_packet_api_t)+ETH_MTU)

#define MAX_QD_PACKETS  30

//#define RING_SIZE 131072
#define RING_SIZE 524288
//#define RING_SIZE 1048576

#define PCAP 0
/* #define LOG_DEBUG 1 */

//#define LOG_QUEUE

typedef struct __attribute__ ((packed))
{
    v4v_datagram_t dg;
    uint8_t data[];
}
uxen_net_packet_api_t;

#define PACKET_IDLE             0
#define PACKET_WAITING_COMPLETION   1

typedef struct uxen_net_packet {
    struct uxen_net_packet *next, *prev;
    uxen_net_packet_api_t *packet;
    uint32_t len;
    uint32_t buf_size;
#if defined(_WIN32)
    v4v_async_t async;
#endif
    int state;
} uxen_net_packet_t;

typedef struct {
    struct uxen_net_packet *head, *tail;
} uxen_net_packet_list_t;


static uxen_net_packet_list_t queue, free_list;
static unsigned int queue_len;

typedef struct uxen_net {
    UXenPlatformDevice dev;
    NICState *nic;
    NICConf conf;
    v4v_context_t v4v;
    v4v_addr_t dest;

    ioh_event tx_event;

    uint8_t *rx_buf;

    v4v_ring_t *ring;

    int32_t fish;

#if PCAP
    FILE *pcap;
    int pcap_last_tx_nr;
#endif
} uxen_net_t;

/******** tcp checksums **********/

#if 1

struct ethhdr {
    unsigned char dst[6];
    unsigned char src[6];
    uint16_t prot;
};


struct iphdr {
    unsigned int ihl: 4;
    unsigned int version: 4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct udphdr {
    uint16_t uh_sport;            /* source port */
    uint16_t uh_dport;            /* destination port */
    uint16_t uh_ulen;             /* udp length */
    uint16_t uh_sum;              /* udp checksum */
};


struct tcphdr {
    uint16_t th_sport;            /* source port */
    uint16_t th_dport;            /* destination port */
    uint32_t th_seq;              /* sequence number */
    uint32_t th_ack;              /* acknowledgement number */
    uint8_t th_x2: 4;             /* (unused) */
    uint8_t th_off: 4;            /* data offset */
    uint8_t th_flags;
#define TH_FIN        0x01
#define TH_SYN        0x02
#define TH_RST        0x04
#define TH_PUSH       0x08
#define TH_ACK        0x10
#define TH_URG        0x20
    uint16_t th_win;              /* window */
    uint16_t th_sum;              /* checksum */
    uint16_t th_urp;              /* urgent pointer */
};


uint16_t
checksum (uint8_t *packet, size_t len, uint32_t sum)
{

    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    while (len > 1) {
        uint16_t w = ((packet[0] << 8) & 0xFF00) + (packet[1] & 0xFF);
        sum += w;
        packet += 2;
        len -= 2;
    }

    if (len)
        sum += packet[0] << 8;

    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // one's complement the result
    sum = ~sum;

    return (uint16_t) sum;
}

static uint32_t
partial_sum (void *_d, size_t len)
{
    uint8_t *packet = (uint8_t *) _d;
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t w = ((packet[0] << 8) & 0xFF00) + (packet[1] & 0xFF);
        sum += w;
        packet += 2;
        len -= 2;
    }

    return sum;
}

static void
fix_checksum_udp (uint32_t saddr, uint32_t daddr, uint8_t *packet,
                  size_t len)
{
    struct udphdr *u = (struct udphdr *) packet;
#if 0
    uint32_t sum = 0;
    if (len < sizeof (struct udphdr))
        return;

    u->uh_sum = 0;

    sum += partial_sum (&saddr, sizeof (saddr));
    sum += partial_sum (&daddr, sizeof (daddr));
    sum += 11 << 8;
    sum += len;

    u->uh_sum = htons (checksum (packet, len, sum));

    debug_printf("fixed udp checksum to %04x\n", ntohs(u->uh_sum));
#else
    if (len < sizeof (struct udphdr))
        return;

    u->uh_sum = 0;
#endif
}

static void
fix_checksum_tcp (uint32_t saddr, uint32_t daddr, uint8_t *packet,
                  size_t len)
{
    struct tcphdr *t = (struct tcphdr *) packet;
    uint32_t sum = 0;
    if (len < sizeof (struct tcphdr))
        return;

    t->th_sum = 0;

    sum += partial_sum (&saddr, sizeof (saddr));
    sum += partial_sum (&daddr, sizeof (daddr));
    sum += 6;
    sum += len;

    t->th_sum = htons (checksum (packet, len, sum));

    // debug_printf("fixed tcp checksum to %04x\n", ntohs(t->th_sum));

}

static void
fix_checksum_ip (uint8_t *packet, size_t len)
{
    size_t hl, ilen;
    struct iphdr *i = (struct iphdr *) packet;
    if (len < sizeof (struct iphdr))
        return;

    hl = i->ihl << 2;

    if (len < hl)
        return;

    i->check = 0;
    i->check = htons (checksum (packet, sizeof (struct iphdr), 0));

    len -= hl;
    packet += hl;



    ilen = ntohs (i->tot_len);
    if (ilen < hl)
        return;

    ilen -= hl;

    if (len < ilen)
        return;




    /*tcp*/
    if (i->protocol == 6)
        fix_checksum_tcp (i->saddr, i->daddr, packet, ilen);

    /*udp*/
    if (i->protocol == 17)
        fix_checksum_udp (i->saddr, i->daddr, packet, ilen);

}



static void
fix_checksum (uint8_t *packet, size_t len)
{
    struct ethhdr *e = (struct ethhdr *) packet;
    if (len < sizeof (struct ethhdr))
        return;

    /*Not ip*/
    if (e->prot != htons (0x800))
        return;

    len -= sizeof (struct ethhdr);
    packet += sizeof (struct ethhdr);

    fix_checksum_ip (packet, len);
}


#endif



/****************** packet capture *******************/



#if PCAP
static int
uxen_net_log_packet (uxen_net_t *s, uint8_t *p, size_t len, int dir)
{
    static int nr = 0;
    struct timeval tv;
    uint32_t d;
//uint16_t w;

    gettimeofday (&tv, NULL);

#if 1
    d = tv.tv_sec;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = tv.tv_usec;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = len;
    fwrite (&d, sizeof (d), 1, s->pcap);
    fwrite (&d, sizeof (d), 1, s->pcap);
    fwrite (p, 1, len, s->pcap);

#else
    d = tv.tv_sec;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = tv.tv_usec;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = len + 2;
    fwrite (&d, sizeof (d), 1, s->pcap);
    fwrite (&d, sizeof (d), 1, s->pcap);
//fwrite(p,1,len,s->pcap);

    w = htons (dir);
    fwrite (&w, sizeof (w), 1, s->pcap);

    w = htons (1);
    fwrite (&w, sizeof (w), 1, s->pcap);

    w = 6;
    fwrite (&w, sizeof (w), 1, s->pcap);

    fwrite (p + 6, 6, 1, s->pcap);

    w = 0;
    fwrite (&w, sizeof (w), 1, s->pcap);

    fwrite (p + 12, len - 12, 1, s->pcap);
#endif

    fflush (s->pcap);

    nr++;

    return nr;
}


static int
uxen_net_log_init (uxen_net_t *s)
{
    uint32_t d;
    uint16_t w;
    char name[1024];

    mkdir("\\pcap");

    sprintf(name, "\\pcap\\uxen_net.%d.pcap", domid);

    s->pcap = fopen (name, "wb");
    if (!s->pcap)
        return -1;

    d = 0xa1b2c3d4;
    fwrite (&d, sizeof (d), 1, s->pcap);
    w = 2;
    fwrite (&w, sizeof (w), 1, s->pcap);
    w = 4;
    fwrite (&w, sizeof (w), 1, s->pcap);
    d = 0;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = 0;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = ETH_MTU;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = 1;                        //113;
    fwrite (&d, sizeof (d), 1, s->pcap);

    return 0;
}
#endif

/******************   packet Q *************************/

static void packet_insert_head(uxen_net_packet_list_t *list, uxen_net_packet_t *packet)
{
    assert(list);
    assert(packet);
    assert(!packet->next);
    assert(!packet->prev);

    if (!list->head) {
        list->head = packet;
    } else {
        packet->next = list->head;
        list->head->prev = packet;
        list->head = packet;
    }

    if (!list->tail) {
        list->tail = packet;
    }
}


static void packet_insert_tail(uxen_net_packet_list_t *list, uxen_net_packet_t *packet)
{
    assert(list);
    assert(packet);
    assert(!packet->next);
    assert(!packet->prev);

    if (!list->tail) {
        list->tail = packet;
    } else {
        packet->prev = list->tail;
        list->tail->next = packet;
        list->tail = packet;
    }

    if (!list->head) {
        list->head = packet;
    }
}

static void packet_remove(uxen_net_packet_list_t *list, uxen_net_packet_t *packet)
{
    assert(packet);

    if (!packet->prev) {
        list->head = packet->next;
    } else {
        packet->prev->next = packet->next;
    }

    if (!packet->next) {
        list->tail = packet->prev;
    } else {
        packet->next->prev = packet->prev;
    }

    packet->next = packet->prev = NULL;
}

static uxen_net_packet_t *packet_new(void)
{
    uxen_net_packet_t *ret;

    ret = free_list.head;

    if (ret) {
        packet_remove(&free_list, ret);
        return ret;
    }

    ret = (uxen_net_packet_t *) malloc(sizeof(uxen_net_packet_t));
    memset(ret, 0, sizeof(*ret));

    ret->packet = malloc(PACKET_LEN);
    ret->buf_size = PACKET_LEN;

    return ret;
}

static void packet_done(uxen_net_packet_t *packet)
{

    packet_insert_head(&free_list, packet);
}

static void packet_free_list(uxen_net_packet_list_t *list)
{
    uxen_net_packet_t *p;
    while ((p = list->head)) {
        packet_remove(list, p);
        if (p->packet) free(p->packet);
        free(p);
    }
}



/******************** TX path ***************************/


/* OSX: keep sending messages in the queue to v4v guest port until destination
 *      ring is full or queue is empty. Unsent packets will be retried later.
 * Windows: If the current packet has been submitted, remove it from the queue
 *          if it's been sent, then send the next packet but leave it on the
 *          queue until we get its completion.
 */

#if !defined(_WIN32)
static void
uxen_net_run_tx_q(uxen_net_t *s)
{
    ssize_t sent;
    uxen_net_packet_t *p;

    while ((p = queue.head))  {
        sent = v4v_sendto(
            &s->v4v.v4v_channel, s->dest, p->packet->data, p->len, 0 /*flags*/);
        if (sent <= 0)
            break;
        packet_remove(&queue, p);
        packet_done(p);
        queue_len--;
    }
}
#else
static void
uxen_net_run_tx_q(uxen_net_t *s)
{
    uxen_net_packet_t *p;
    unsigned len;
    int err;
    size_t writ;

    while ((p = queue.head))  {
#ifdef LOG_QUEUE
        debug_printf("uxn: runtxq packet %p state %d size %d\n",
                     p, p->state, p->len);
#endif
        switch (p->state) {
            case PACKET_IDLE:
                len = p->len + sizeof (uxen_net_packet_api_t);

                p->packet->dg.addr = s->dest;

                dm_v4v_async_init(&s->v4v, &p->async, s->tx_event);

                err = dm_v4v_send(
                    &s->v4v,
                    (v4v_datagram_t*)p->packet,
                    len,
                    &p->async);

                if (err && err != ERROR_IO_PENDING)
                    /* The transmit failed so we'll leave the packet to
                     * transmit another time */
                    return;
#ifdef LOG_QUEUE
                debug_printf("uxn: send, pending\n");
#endif
                /* it's in the send buffer we've done everything we can */
                p->state = PACKET_WAITING_COMPLETION;
                break;

            case PACKET_WAITING_COMPLETION:
                if (!dm_v4v_async_is_completed(&p->async)) {
#ifdef LOG_QUEUE
                    debug_printf("uxn: waiting\n");
#endif
                    /* Still nothing doing, this IO is still running,
                     * so that all */
                    return;
                }

                if ((err = dm_v4v_async_get_result(&p->async, &writ, false))) {
                    if (err == ERROR_IO_INCOMPLETE) {
#ifdef LOG_QUEUE
                        debug_printf("uxn: waited, waiting\n");
#endif
                        /* Still nothing doing, this IO is still
                         * running, so that all */
                        return;
                    }

                    warnx("uxn: fail path 3 err %x, retrying but next time",
                          err);
                    p->state = PACKET_IDLE;
                    return;
                }

                len = p->len + sizeof (uxen_net_packet_api_t);

                if (writ != len) {
                    warnx("uxn: fail path 4 wrote only %d of %d bytes err %x,"
                        " retrying", (int)writ, len, err);
                    /* We failed to transmit, retry */
                    p->state = PACKET_IDLE;
                    break;
                }

#ifdef LOG_QUEUE
                debug_printf("uxn: waited, good -> next\n");
#endif

                /*Success, send the next one */

                packet_remove(&queue, p);
                packet_done(p);
                queue_len--;

                break;
        }
    }
}
#endif /* _WIN32 */

static void
uxen_net_write_event (void *_s)
{
    uxen_net_t *s = (uxen_net_t *) _s;

#ifdef LOG_QUEUE
    debug_printf("uxn: write_event\n");
#endif

    ioh_event_reset(&s->tx_event);

    uxen_net_run_tx_q(s);
    if (queue_len < MAX_QD_PACKETS)
        qemu_flush_queued_packets(&s->nic->nc);

}


static int
uxen_net_can_receive (VLANClientState *nc)
{
//  uxen_net_t *s = DO_UPCAST (NICState, nc, nc)->opaque;

    if (queue_len > MAX_QD_PACKETS )
        return 0;

    return 1;
}


static ssize_t
uxen_net_receive (VLANClientState *nc, const uint8_t *buf, size_t size)
{
    uxen_net_t *s = DO_UPCAST (NICState, nc, nc)->opaque;
    uxen_net_packet_t *p = packet_new();
    //unsigned int len;

    if (!p) return 0;

    if (size > ETH_MTU)
        size = ETH_MTU;

    p->state = PACKET_IDLE;
    p->len = size;

    memcpy (p->packet->data, buf, size);

    if (size < ETH_MINTU)  {
        memset(p->packet->data + size, 0, ETH_MINTU - size);
        p->len = ETH_MINTU;
    }

    fix_checksum (p->packet->data, p->len);

#if PCAP
    s->pcap_last_tx_nr = uxen_net_log_packet (s, p->packet->data, p->len, 0);
#endif

    queue_len++;
    packet_insert_tail(&queue, p);

#ifdef LOG_QUEUE
    debug_printf("uxn: queued a tx packet of size %"PRIdSIZE"\n", size);
#endif

    uxen_net_run_tx_q(s);

    return size;
}


/*********************** RX path ***************************/


static void
uxen_net_read_event (void *_s)
{
    uxen_net_t *s = (uxen_net_t *) _s;
    ssize_t len;
    v4v_addr_t from;
    uint32_t protocol;

    do {
        len = v4v_copy_out (s->ring, &from, &protocol, s->rx_buf, ETH_MTU, 1);
        if (len < 0)
            break;
        if (len > ETH_MTU)
            len = ETH_MTU;

#ifdef LOG_QUEUE
        debug_printf("uxn: read_event got packet of size %"PRIdSIZE"\n", len);
#endif
        if (len == 1)
            debug_printf("uxn: read_event got poke back\n");

#if PCAP
        uxen_net_log_packet (s, s->rx_buf, len, 4);
#endif

        if (len < 14) continue;

        // debug_printf("uxn: dispatched a packet of %"PRIdSIZE" bytes\n", len);

        memcpy (&s->rx_buf[6], &s->conf.macaddr.a[0], 6); //why?
        qemu_send_packet (&s->nic->nc, s->rx_buf, len);
    } while (1);

    if (!dm_v4v_notify(&s->v4v))
        return;
    /* XXX: do we really want to run the tx queue here? If it's safe to send
     * some more, surely our tx event would have fired? If we really do want to
     * run the tx queue, why only if we managed to notify that we're ready to
     * receive more? */
    uxen_net_run_tx_q(s);
    if (queue_len < MAX_QD_PACKETS)
        qemu_flush_queued_packets(&s->nic->nc);
}

/*******************************************************/

static void
uxen_net_pre_save (void *opaque)
{
    //uxen_net_t *s = opaque;
}


static int
uxen_net_post_load (void *opaque, int version_id)
{
    uxen_net_t *s = opaque;

    debug_printf("%s: load mac is %02x:%02x:%02x:%02x:%02x:%02x\n",
                 __FUNCTION__, s->conf.macaddr.a[0], s->conf.macaddr.a[1],
                 s->conf.macaddr.a[2], s->conf.macaddr.a[3],
                 s->conf.macaddr.a[4], s->conf.macaddr.a[5]);

    return 0;
}


static const VMStateDescription vmstate_uxen_net = {
    .name = "uxen_net",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .post_load = uxen_net_post_load,
    .pre_save = uxen_net_pre_save,
    .fields = (VMStateField[])
    {
        VMSTATE_UNUSED (4),
        VMSTATE_MACADDR (conf.macaddr, uxen_net_t),
        VMSTATE_INT32 (fish, uxen_net_t),
        VMSTATE_END_OF_LIST ()
    },
};

static void
uxen_net_cleanup (VLANClientState *nc)
{
    uxen_net_t *s = DO_UPCAST (NICState, nc, nc)->opaque;

    ioh_del_wait_object (&s->tx_event, NULL);
    ioh_del_wait_object (&s->v4v.recv_event, NULL);
    packet_free_list(&queue);
    packet_free_list(&free_list);

    ioh_event_close(&s->tx_event);

    dm_v4v_close(&s->v4v);
    free (s->rx_buf);

    s->nic = NULL;
}

static NetClientInfo uxen_net_net_info = {
    .type = NET_CLIENT_TYPE_NIC,
    .size = sizeof (NICState),
    .can_receive = uxen_net_can_receive,
    .receive = uxen_net_receive,
    .cleanup = uxen_net_cleanup,
};


static int
uxen_net_initfn (UXenPlatformDevice *dev)
{
    v4v_bind_values_t bind = { };
    int v4v_opened = 0;
    int error;
    extern unsigned slirp_mru;
    uxen_net_t *s = DO_UPCAST (uxen_net_t, dev, dev);
    uint16_t mru;

    qemu_macaddr_default_if_unset (&s->conf.macaddr);


    do {
#if PCAP
        if (uxen_net_log_init (s))
            break;
#endif

        if (!dm_v4v_have_v4v ()) {
            debug_printf("uxen_net_isa_initfn - no v4v detected on the host\n");
            break;
        }

        s->rx_buf = (uint8_t *) malloc (ETH_MTU);
        if (!s->rx_buf)
            break;

        if ((error = dm_v4v_open(&s->v4v, RING_SIZE))) {
            debug_printf("%s: v4v_open failed (%x)\n",
                         __FUNCTION__, error);
            break;
        }

        v4v_opened++;


        bind.ring_id.addr.port = 0xc0000;
        bind.ring_id.addr.domain = V4V_DOMID_ANY;
        bind.ring_id.partner = V4V_DOMID_UUID;
        memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));

        if ((error = dm_v4v_bind(&s->v4v, &bind))) {
            debug_printf("%s: v4v_bind failed (%x)\n",
                         __FUNCTION__, error);
            break;
        }

        s->dest.domain = bind.ring_id.partner;
        s->dest.port = bind.ring_id.addr.port;

        error = dm_v4v_ring_map(&s->v4v, &s->ring);
        if (!s->ring) {
            debug_printf("%s: failed to map v4v ring (%x)\n",
                         __FUNCTION__, error);
            break;
        }

        if ((error = dm_v4v_init_tx_event(&s->v4v, &s->tx_event))) {
            debug_printf("%s: failed to create transmit event (%x)\n",
                         __FUNCTION__, error);
            break;
        }

        ioh_add_wait_object (&s->v4v.recv_event, uxen_net_read_event, s, NULL);
        ioh_add_wait_object (&s->tx_event, uxen_net_write_event, s, NULL);

        s->nic = qemu_new_nic (&uxen_net_net_info, &s->conf,
                               dev->qdev.info->name, dev->qdev.id, s);

        qemu_format_nic_info_str (&s->nic->nc, s->conf.macaddr.a);

        uxenplatform_device_add_property(dev, UXENBUS_PROPERTY_TYPE_MACADDR,
                                         s->conf.macaddr.a, 6);
        mru = htons(slirp_mru);
        uxenplatform_device_add_property(dev, UXENBUS_PROPERTY_TYPE_MTU,
                                         &mru, 2);

        debug_printf("%s: mac is %02x:%02x:%02x:%02x:%02x:%02x\n"
                     " slirp_mru(guest mtu) is %d\n", __FUNCTION__,
                     s->conf.macaddr.a[0], s->conf.macaddr.a[1],
                     s->conf.macaddr.a[2], s->conf.macaddr.a[3],
                     s->conf.macaddr.a[4], s->conf.macaddr.a[5],
                     slirp_mru);

        return 0;
    } while (1);

    if (v4v_opened)
        dm_v4v_close (&s->v4v);
    if (s->rx_buf)
        free (s->rx_buf);

    return -1;
}

static UXenPlatformDeviceInfo uxen_net_info = {
    .qdev.name = "uxen_net",
    .qdev.size = sizeof (uxen_net_t),
    .qdev.vmsd = &vmstate_uxen_net,
    .init = uxen_net_initfn,
    .devtype = UXENBUS_DEVICE_TYPE_NET,
    .qdev.props = (Property[])
    {
        DEFINE_NIC_PROPERTIES (uxen_net_t, conf),
        DEFINE_PROP_END_OF_LIST (),
    }
    ,
};

static void
uxen_net_register_devices (void)
{
    uxenplatform_qdev_register(&uxen_net_info);
}

device_init (uxen_net_register_devices);
