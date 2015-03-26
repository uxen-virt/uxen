/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/pci.h>
#include <dm/qemu/net.h>

#include <dm/block.h>
#include <dm/dmpdev.h>
#include <dm/hw.h>
#include <dm/firmware.h>

#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#if defined(_WIN32)
#define _POSIX
#endif
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
    OVERLAPPED overlapped;
    int state;
} uxen_net_packet_t;

typedef struct {
    struct uxen_net_packet *head, *tail;
} uxen_net_packet_list_t;


static uxen_net_packet_list_t queue, free_list;
static unsigned int queue_len;

typedef struct uxen_net {
    ISADevice dev;
    NICState *nic;
    NICConf conf;
    v4v_context_t a;
    v4v_addr_t dest;

    OVERLAPPED notify_overlapped;
    BOOLEAN notify_pending;

    HANDLE tx_event;

    uint8_t *rx_buf;

    v4v_ring_t *ring;

    int32_t fish;

#if PCAP
    FILE *pcap;
    int pcap_last_tx_nr;
#endif
} uxen_net_t;

/******* debug fns ******/

#if 0
static char *
dword_ptr_to_a (DWORD *p)
{
    static char ret[128];

    if (!p)
        return "null";

    sprintf (ret, "&(%u)", (unsigned)*p);

    return ret;
}

#if 0                           /* unused */
static BOOLEAN
wrap_readfile(HANDLE h, void *buf, DWORD bytes_in, DWORD *bytes_out,
              OVERLAPPED *o)
{
    BOOLEAN ret;

    ret = ReadFile(h, buf, bytes_in, bytes_out, o);

    debug_printf("uxn: ReadFile(%p,%p,%u,%s,%p)=%s\n", h, o,
                 bytes_in, dword_ptr_to_a(bytes_out), o,
                 ret ? "true" : "false");
    return ret;
}
#endif

static BOOLEAN
wrap_writefile(HANDLE h, void *buf, DWORD bytes_in, DWORD *bytes_out,
               OVERLAPPED *o)
{
    BOOLEAN ret;

    ret = WriteFile(h, buf, bytes_in, bytes_out, o);

    debug_printf("uxn: WriteFile(%p,%p,%u,%s,%p)=%s\n", h, o,
                 bytes_in, dword_ptr_to_a(bytes_out), o,
                 ret ? "true" : "false");

    return ret;
}


static BOOLEAN
wrap_getoverlappedresult(HANDLE h, OVERLAPPED *o, DWORD *bytes,
                         BOOLEAN wait)
{
    BOOLEAN ret;

    ret = GetOverlappedResult(h, o, bytes, wait);

    debug_printf("uxn: GetOverlappedResult(%p,%p,%s,%s)=%s\n", h, o,
                 dword_ptr_to_a(bytes), wait ? "true" : "false",
                 ret ? "true" : "false");

    return ret;
}


static DWORD
wrap_getlasterror (void)
{
    DWORD ret;
    char *str = "?";

    ret = GetLastError();
    switch (ret) {
    case ERROR_IO_INCOMPLETE:
        str = "ERROR_IO_INCOMPLETE";
        break;
    case ERROR_IO_PENDING:
        str = "ERROR_IO_PENDING";
        break;
    }
    debug_printf("uxn: GetLastError()=0x%x (%s)\n", ret, str);

    return ret;
}

#define WriteFile wrap_writefile
#define ReadFile wrap_readfile
#define GetLastError wrap_getlasterror
#define GetOverlappedResult wrap_getoverlappedresult
#endif


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


#if 0
static int retry_transmit(uxen_net_t *s)
{
    DWORD err;
#if PCAP
    debug_printf("uxn: packet %d failed to transmit - retransmitting\n",
                 s->pcap_last_tx_nr);
#else
    debug_printf("uxn: packet failed to transmit - retransmitting\n");
#endif
    s->write_pending = FALSE;

    if (WriteFile(s->a.v4v_handle, s->write_packet, s->write_packet_len,
                  NULL, &s->write_overlapped)) {
        Wwarn("uxn: fail path 1");
        return 1;
    }

    err = ERROR_IO_INCOMPLETE;

    switch (err) {
        case ERROR_IO_INCOMPLETE:
            s->write_pending = TRUE;
            return 0;
        default:
            warnx("uxn: fail path 2 %x", err);
    }

    return 1;
}



static int
uxen_net_receive_complete (uxen_net_t *s, BOOLEAN wait)
{
    DWORD writ, err;

    if (!s->write_pending)
        return 1;

    if (GetOverlappedResult
        (s->a.v4v_handle, &s->write_overlapped, &writ, wait)) {
        s->write_pending = FALSE;

        if (writ != s->write_packet_len ) {
            Wwarn("uxn: fail path 3 %lx");
            return retry_transmit(s);
        } else if (!s->guest_has_ring) {
            warnx("uxn: success - guest now has ring");
            s->guest_has_ring = TRUE;
        }

        return 1;
    }


    err = GetLastError();



    switch (err) {
        case ERROR_IO_INCOMPLETE:
            return 0;
        case ERROR_VC_DISCONNECTED:
            warnx("uxn: fail path 4 %x", err);
            return retry_transmit(s);
    }

    warnx("uxn: fail path 5 %x", err);

    /* XXX: does false mean complete? in this case */
    s->write_pending = FALSE;

    return 1;
}

static int
uxen_net_can_receive (VLANClientState *nc)
{
    uxen_net_t *s = DO_UPCAST (NICState, nc, nc)->opaque;

    if ((!s->guest_has_ring) && (s->have_first_packet))
        return 0;

    return 1;
}

static void
uxen_net_startup_timer(void *opaque)
{
    uxen_net_t *s = (uxen_net_t *)opaque;

    debug_printf("uxn: timer in wp=%d ghr=%d\n", s->write_pending,
                 s->guest_has_ring);

    if (s->write_pending)
        uxen_net_receive_complete (s, FALSE);

    if (!s->write_pending && s->have_first_packet && !s->guest_has_ring)
        retry_transmit(s);

    if (s->startup_timer && !s->guest_has_ring && s->have_first_packet)
        qemu_mod_timer(s->startup_timer, qemu_get_clock(rt_clock) + 5);

    debug_printf("uxn: timer out wp=%d ghr=%d\n", s->write_pending,
                 s->guest_has_ring);
}


static ssize_t
uxen_net_receive (VLANClientState *nc, const uint8_t *buf, size_t size)
{
    uxen_net_t *s = DO_UPCAST (NICState, nc, nc)->opaque;
    uint8_t c[1024];

    if (s->startup_timer && !s->guest_has_ring)
        qemu_mod_timer(s->startup_timer, qemu_get_clock(rt_clock) + 5);

    s->have_first_packet = TRUE;

    if ((s->write_pending) && (!uxen_net_receive_complete (s, FALSE))) {
        warnx("uxn: fail path 6");
        return -1;
    }

    s->dest.domain = vm_id;       // This aparently gets set after our init function.
    s->write_packet->dg.addr = s->dest;
    s->write_packet->dg.flags = 0;

    if (size > ETH_MTU)
        size = ETH_MTU;

    if (size < ETH_MINTU) {
        memcpy (c, buf, size);
        memset(c + size, 0, ETH_MINTU - size);
        buf = c;
        size = ETH_MINTU;
    }




    memcpy (s->write_packet->data, buf, size);
    fix_checksum (s->write_packet->data, size);

    memset (&s->write_overlapped, 0, sizeof (OVERLAPPED));

    s->write_packet_len = size + sizeof (uxen_net_packet_api_t);


    // debug_printf("v4v-send %d.%d %d\n", s->write_packet->addr.domain,
    //              s->write_packet->addr.port, len);

#if PCAP
    s->pcap_last_tx_nr = uxen_net_log_packet(s, s->write_packet->data, size, 0);
#endif


    if (WriteFile(s->a.v4v_handle, s->write_packet, s->write_packet_len,
                  NULL, &s->write_overlapped)) {
        warnx("uxn: fail path 7");
        return size;
    }

    if (GetLastError () == ERROR_IO_PENDING) {
        s->write_pending = TRUE;
#if 0
        uxen_net_receive_complete (s, TRUE);
#endif
        return size;
    }

    warnx("uxn: fail path 8");

    return -1;
}


#if 0
static ssize_t
wrap_uxen_net_receive (VLANClientState *nc, const uint8_t *buf, size_t size)
{
    struct timeval tv;
    ssize_t ret = -1;
    static LONG guard;

    if (InterlockedIncrement (&guard) != 1) {
        debug_printf("nr: TREATCHERY UNMASKED!\n");
        InterlockedDecrement (&guard);
    } else {
        gettimeofday (&tv, NULL);
        debug_printf("nr in  %d.%06d\n", (int)tv.tv_sec, (int)tv.tv_usec);
        ret = uxen_net_receive (nc, buf, size);
        debug_printf("   out %d.%06d\n", (int)tv.tv_sec, (int)tv.tv_usec);
        InterlockedDecrement (&guard);
    }

    return ret;
}
#endif
#endif

static void uxen_net_run_tx_q(uxen_net_t *s)
{
    uxen_net_packet_t *p;
    unsigned len;
    DWORD err;
    DWORD writ;

    while ((p = queue.head))  {
#ifdef LOG_QUEUE
        debug_printf("uxn: runtxq packet %p state %d size %d\n",
                     p, p->state, p->len);
#endif
        switch (p->state) {
            case PACKET_IDLE:
                len = p->len + sizeof (uxen_net_packet_api_t);

                /*Irritatingly packets arrive here before vm_id gets set, so we need to change the address on each retry*/
                s->dest.domain = vm_id;
                p->packet->dg.addr = s->dest;

                memset (&p->overlapped, 0, sizeof (OVERLAPPED));
                p->overlapped.hEvent = s->tx_event;

                if (WriteFile (s->a.v4v_handle, p->packet, len, NULL, &p->overlapped)) {
                    /* as we're asynchronous, this should never succeed */
                    warnx("uxn: fail path 1");
                    packet_remove(&queue, p);
                    packet_done(p);
                    queue_len--;
                    break;
                }

                err = GetLastError ();

                if (GetLastError () == ERROR_IO_PENDING) {
#ifdef LOG_QUEUE
                    debug_printf("uxn: send, pending\n");
#endif
                    /* it's in the send buffer we've done everything we can */
                    p->state = PACKET_WAITING_COMPLETION;
                    return;
                }

                warnx("uxn: fail path 2 err %lx", err);

                /* The transmit failed so we'll leave the packet to
                 * transmit another time */
                return;

                break;
            case PACKET_WAITING_COMPLETION:

                if (!HasOverlappedIoCompleted(&p->overlapped))  {
#ifdef LOG_QUEUE
                    debug_printf("uxn: waiting\n");
#endif
                    /* Still nothing doing, this IO is still running,
                     * so that all */
                    return;
                }



                if (!GetOverlappedResult (s->a.v4v_handle, &p->overlapped, &writ, FALSE)) {

                    err = GetLastError ();
                    if (err == ERROR_IO_INCOMPLETE) {
#ifdef LOG_QUEUE
                        debug_printf("uxn: waited, waiting\n");
#endif
                        /* Still nothing doing, this IO is still
                         * running, so that all */
                        return;
                    }

                    warnx("uxn: fail path 3 err %lx, retrying but next time",
                          err);
                    p->state = PACKET_IDLE;
                    return;
                }

                err = GetLastError ();

                len = p->len + sizeof (uxen_net_packet_api_t);

                if (writ != len) {
                    warnx("uxn: fail path 4 wrote only %ld of %d bytes err %lx,"
                          " retrying", writ, len, err);
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


static void
uxen_net_write_event (void *_s)
{
    uxen_net_t *s = (uxen_net_t *) _s;

#ifdef LOG_QUEUE
    debug_printf("uxn: write_event\n");
#endif

    ResetEvent(s->tx_event);

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


static int
uxen_net_notify_complete (uxen_net_t *s, BOOLEAN wait)
{
    DWORD writ;

    if (!s->notify_pending)
        return 1;

    if (GetOverlappedResult
        (s->a.v4v_handle, &s->notify_overlapped, &writ, wait)) {
        s->notify_pending = FALSE;
        return 1;
    }

    if (GetLastError () == ERROR_IO_INCOMPLETE)
        return 0;

    /* XXX: does false mean complete? in this case */
    s->notify_pending = FALSE;

    return 1;
}



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


    if ((s->notify_pending) && (!uxen_net_notify_complete (s, FALSE))) {
        return;
    }
    memset (&s->notify_overlapped, 0, sizeof (OVERLAPPED));

    gh_v4v_notify(&s->a, &s->notify_overlapped);

    s->notify_pending = TRUE;

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

/******************ACPI interface******************************/

static uint32_t
uxen_net_ioport_read (void *opaque, uint32_t addr)
{
    extern unsigned slirp_mru;
// extern unsigned slirp_mtu;
    uxen_net_t *s = (uxen_net_t *) opaque;
    uint8_t ret;

    addr &= 15;

    if (!addr) {
        ret = 0x5a;
    } else if ((addr > 0) && (addr <= ETHER_ADDR_LEN)) {
        ret = s->conf.macaddr.a[addr - 1];
    } else if (addr == 8) {
        ret = slirp_mru & 0xff;
    } else if (addr == 9) {
        ret = slirp_mru >> 8;
    } else {
        ret = 0xff;
    }

    if (addr)
        debug_printf("uxn: ioport read 0x%x => 0x%x\n", addr, ret);

    return ret;
}

/*******************************************************/


static void
uxen_net_cleanup (VLANClientState *nc)
{
    uxen_net_t *s = DO_UPCAST (NICState, nc, nc)->opaque;

    ioh_del_wait_object (&s->tx_event, NULL);
    ioh_del_wait_object (&s->a.recv_event, NULL);
    packet_free_list(&queue);
    packet_free_list(&free_list);

    CloseHandle(&s->tx_event);

    v4v_close (&s->a);
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
have_v4v (void)
{
    v4v_context_t c = { 0 };

    if (v4v_open (&c, 4096, NULL)) {
        v4v_close (&c);
        return 1;
    }

    return 0;
}

static int
uxen_net_isa_initfn (ISADevice *dev)
{
    DWORD t;
    v4v_ring_id_t r;
    v4v_mapring_values_t mr;
    OVERLAPPED o = { 0 };
    int v4v_opened = 0;
    extern unsigned slirp_mru;
    uxen_net_t *s = DO_UPCAST (uxen_net_t, dev, dev);

    qemu_macaddr_default_if_unset (&s->conf.macaddr);


    do {
#if PCAP
        if (uxen_net_log_init (s))
            break;
#endif

        if (!have_v4v ()) {
            debug_printf("uxen_net_isa_initfn - no v4v detected on the host\n");
            break;
        }

        s->rx_buf = (uint8_t *) malloc (ETH_MTU);
        if (!s->rx_buf)
            break;

        s->a.flags = V4V_FLAG_OVERLAPPED;
        memset (&o, 0, sizeof (o));

        if (!v4v_open (&s->a, RING_SIZE, &o))
            break;

        if (!GetOverlappedResult (s->a.v4v_handle, &o, &t, TRUE))
            break;

        v4v_opened++;


        r.addr.port = 0xc0000;
        r.addr.domain = V4V_DOMID_ANY;
        r.partner = vm_id;

        memset (&o, 0, sizeof (o));

        if (!v4v_bind (&s->a, &r, &o))
            break;

        if (!GetOverlappedResult (s->a.v4v_handle, &o, &t, TRUE))
            break;

        memset (&o, 0, sizeof (o));

        mr.ring = NULL;
        if (!v4v_map (&s->a, &mr, &o))
            break;

        if (!GetOverlappedResult (s->a.v4v_handle, &o, &t, TRUE))
            break;

        s->ring = mr.ring;
        if (!s->ring)
            break;

        s->tx_event = CreateEvent(NULL, FALSE, FALSE, NULL);

        if (!s->tx_event)
            break;


        ioh_add_wait_object (&s->a.recv_event, uxen_net_read_event, s, NULL);
        ioh_add_wait_object (&s->tx_event, uxen_net_write_event, s, NULL);

        s->dest.domain = vm_id;
        s->dest.port = 0xc0000;

        register_ioport_read (0x320, 16, 1, uxen_net_ioport_read, s);

        s->nic = qemu_new_nic (&uxen_net_net_info, &s->conf,
                               dev->qdev.info->name, dev->qdev.id, s);

        qemu_format_nic_info_str (&s->nic->nc, s->conf.macaddr.a);

        debug_printf("%s: mac is %02x:%02x:%02x:%02x:%02x:%02x\n"
                     " slirp_mru(guest mtu) is %d\n", __FUNCTION__,
                     s->conf.macaddr.a[0], s->conf.macaddr.a[1],
                     s->conf.macaddr.a[2], s->conf.macaddr.a[3],
                     s->conf.macaddr.a[4], s->conf.macaddr.a[5],
                     slirp_mru);

        return 0;
    } while (1);

    if (v4v_opened)
        v4v_close (&s->a);
    if (s->rx_buf)
        free (s->rx_buf);

    return -1;
}

static ISADeviceInfo uxen_net_isa_info = {
    .qdev.name = "uxen_net",
    .qdev.size = sizeof (uxen_net_t),
    .qdev.vmsd = &vmstate_uxen_net,
    .init = uxen_net_isa_initfn,
    .qdev.props = (Property[])
    {
        DEFINE_NIC_PROPERTIES (uxen_net_t, conf),
        DEFINE_PROP_END_OF_LIST (),
    }
    ,
};



static void
uxen_net_isa_register_devices (void)
{
    isa_qdev_register (&uxen_net_isa_info);
}

device_init (uxen_net_isa_register_devices);
