/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/char.h>
#include <dm/timer.h>
#include "nickel.h"
#include "proto.h"
#include "tcpip.h"
#include "dhcp.h"
#include "access-control.h"
#include "buff.h"
#include "lava.h"
#include "log.h"

#define HFWD_CONNECT_DELAY_MS 300
#define HFWD_EOF_POLL_MS      200
#define GC_TIMER    (1 * 60 * 1000)     /* 1 mins */
#define UDP_SOCK_EXPIRE (2 * 60 * 1000) /* 2 mins */
#define TCP_FIN_WAIT    (2 * 1000) /* 2 sec */
#define MAX_COUNT_FIN_WAIT     4
#define STATS_MS        (4 * 1000) /* 4 sec */

#define DELAY_ACK_MIN_MS    5
#define DELAY_ACK_MAX_MS    40
#define RETRANSMIT_TIMEOUT  600
#define RETRANSMIT_REPEAT   20
#define PING_PROBE_PERIOD_MS    (10 * 1000) /* 10 sec */
#define PING_PROBE_RESET_N      100
#define PING_RTT_LAT_WARN_MS    100 /* 100ms */

#define MAX_RETRANSMIT_PER_PACKET   10

#define MAX_16_WIN  (64 * 1024 - 2)
#define SND_WIN_SHIFT   1

#define WST_UNKN    0
#define WST_SENT    1
#define WST_ACKED   2

#define SEQ_CMP(seq1, seq2)     ((int32_t) ((uint32_t) (seq1) - (uint32_t) (seq2)))

#define DBG4(so, fmt, ...) do {                                               \
    NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR" f:0x%x (G:%hu -> %s:%hu) -- " fmt, \
            __FUNCTION__, (uintptr_t) (so), (uintptr_t) (so)->chr,            \
            (unsigned) (so)->flags,                                           \
            NI_NTOHS((so)->gaddr.sin_port), inet_ntoa((so)->faddr.sin_addr),  \
            NI_NTOHS((so)->faddr.sin_port), ## __VA_ARGS__);                  \
    } while(1 == 0)

struct ni_socket {
    LIST_ENTRY(ni_socket) entry;
    uint8_t type;
    uint8_t state;
    uint32_t flags;
    int64_t ts_created;
    int64_t ts_closed;
    struct nickel *ni;
    CharDriverState *chr;

    /* network order */
    struct sockaddr_in faddr;
    struct sockaddr_in gaddr;

    /* TCP */
    struct buff sent_q;
    Timer *fwd_timer;
    int64_t delay_ac_ts;
    int64_t ack_1_ts;
    int64_t ack_2_ts;
    int64_t poll_eof_ts;
    uint32_t fwd_n;
    uint8_t zero_win;
    uint8_t win_state;
    uint32_t chr_win;
    size_t bufd_len;
    uint8_t *bufd_data;
    /* host order */
    uint32_t rcv_iss;
    uint32_t rcv_off_ack; /* offset from G we acked */
    uint32_t snd_iss;
    uint32_t snd_off_nxt;
    uint32_t snd_off_ack; /* offset from us that G acked */
    uint16_t snd_mss;
    uint32_t snd_win;
    uint8_t snd_win_shift;
    uint32_t rcv_win;
    uint8_t rcv_win_shift;
    uint16_t rcv_mss;
    int g_use_win_scaling;
    int n_fin_retransmit;

    /* LAVA */
    struct lava_event *lv;
};

#define TS_CLOSED               0
#define TS_SYN_RECVD            1
#define TS_SYNACK_SENT          2
#define TS_ESTABLISHED          3
#define TS_CONN_RST             4
#define TS_SYN_SENT             5

#define TF_FIN_RECV             0x1
#define TF_FIN_SENT             0x2
#define TF_CLOSED               0x4
#define TF_HOSTFWD              0x8
#define TF_FWDCLOSE             0x10
#define TF_CLOSERETRY           0x20
#define TF_VMFWD                0x40
#define TF_RST_PENDING          0x80
#define TF_DELAYED_ACK          0x100
#define TF_DELETE               0x200
#define TF_INPUT                0x400
#define TF_NAV                  0x800
#define TF_CONNECTING           0x1000
#define TF_RETRANSMISSION       0x2000
#define TF_RETRANSMISSION_FIN   0x4000
#define TF_RETRANSMISSION_RST   0x8000
#define TF_FREED                0x10000
#define TF_FIN_ACKED            0x20000

#define IS_DEL(so)              (!!((so)->flags & TF_DELETE))

static void buff_output(struct nickel *ni, struct buff *bf);
static int
tcp_send(struct ni_socket *so, int flags, const uint8_t *data, size_t len);
static int tcp_respond_rst(struct nickel *ni, const struct tcp *tcp, uint32_t saddr, uint32_t daddr);
static int tcp_rst(struct ni_socket *so);
static int tcp_input(struct nickel *ni, struct ip *ip, const uint8_t *pkt, size_t len,
        uint32_t saddr, uint32_t daddr);
static int icmp_input(struct nickel *ni, const uint8_t *pkt, size_t len,
        uint32_t saddr, uint32_t daddr);
static int udp_input(struct nickel *ni, const uint8_t *pkt, size_t len,
        uint32_t saddr, uint32_t daddr);
static void udp_respond(struct ni_socket *so, const uint8_t *pkt, size_t len);
static void fwd_connect_cb(void *opaque);
static uint16_t tcp_get_free_port(struct nickel *ni);
static inline void get_bf_seq_len(struct ni_socket *so, struct buff *bf, uint32_t *seq, uint32_t *len);
static void remove_buff(struct ni_socket *so, struct buff *bf);

static uint32_t get_iss(void)
{
    return (uint32_t) (os_get_clock() / 10000LL); /* 0.1ms unit */
}

static void send_close(struct ni_socket *so, bool rst)
{
    if (!so->chr)
        return;
    qemu_chr_send_event(so->chr, rst ? CHR_EVENT_NI_RST : CHR_EVENT_NI_CLOSE);
}

static void socket_reset(struct ni_socket *so)
{
    struct buff *bf, *bf_n;

    if (so->type != IPPROTO_TCP)
        return;

    so->flags &= ~TF_FIN_RECV;
    so->flags &= ~TF_FIN_SENT;
    so->flags &= ~TF_DELAYED_ACK;
    so->flags &= ~TF_RETRANSMISSION;
    so->flags &= ~TF_RETRANSMISSION_FIN;
    so->flags &= ~TF_RETRANSMISSION_RST;
    so->flags &= ~TF_RST_PENDING;
    so->snd_iss = so->snd_off_nxt = so->snd_off_ack = so->rcv_iss = so->rcv_off_ack = 0;
    so->zero_win = 0; so->ack_1_ts = so->ack_2_ts = so->poll_eof_ts = 0;
    so->chr_win = 0;
    so->win_state = WST_UNKN;

    so->chr_win = 0;

    RLIST_FOREACH_SAFE(bf, &so->sent_q, so_entry, bf_n) {
        if (NLOG_LEVEL > 4) {
            uint32_t seq = 0, len = 0;

            get_bf_seq_len(so, bf, &seq, &len);
            NETLOG4("%s: so %"PRIxPTR" removed buff with seq %u len %u", __FUNCTION__,
                   (uintptr_t) so, seq, len);
        }
        remove_buff(so, bf);
    }
    ni_priv_free(so->bufd_data);
    so->bufd_data = NULL;
    so->bufd_len = 0;
}

static struct ni_socket *
socket_create(struct nickel *ni, uint8_t type, bool queue)
{
    struct ni_socket *so = NULL;

    so = calloc(1, sizeof(*so));
    if (!so)
        goto out;
    so->ni = ni;
    so->type = type;
    so->ts_created = get_clock_ms(vm_clock);

    if (type == IPPROTO_TCP) {
        if (queue)
            LIST_INSERT_HEAD(&ni->tcp, so, entry);
        RLIST_INIT(&so->sent_q, so_entry);
    } else {
        if (queue)
            LIST_INSERT_HEAD(&ni->udp, so, entry);
    }

    if (type == IPPROTO_TCP) {
        atomic_inc(&ni->number_tcp_sockets);
        atomic_inc(&ni->number_total_tcp_sockets);
    } else if (type == IPPROTO_UDP) {
        atomic_inc(&ni->number_udp_sockets);
    }

    if (!ni->tcpip_stats_ts || ni->tcpip_stats_ts + STATS_MS < so->ts_created) {
        ni->tcpip_stats_ts = so->ts_created;

        NETLOG4("%s: #tcp %lu #udp %lu", __FUNCTION__, (unsigned long) so->ni->number_tcp_sockets,
                (unsigned long) so->ni->number_udp_sockets);
    }
out:
    return so;
}

static struct ni_socket *
socket_free(struct ni_socket *so)
{
    int64_t now;
    bool queued = false;

    assert(!(so->flags & TF_FREED));

    if ((so->flags & TF_INPUT)) {
        so->flags |= TF_DELETE;
        return so;
    }

    so->flags |= TF_FREED;

    if (!(so->flags & TF_CLOSED) && so->chr)
        send_close(so, false);
    so->chr = NULL;
    if (so->ni->tcp_lst_so == so)
        so->ni->tcp_lst_so = NULL;
    if (so->entry.le_prev) {
        LIST_REMOVE(so, entry);
        queued = true;
    }

    if (so->fwd_timer)
        free_timer(so->fwd_timer);
    so->fwd_timer = NULL;

    if (so->type == IPPROTO_TCP) {
        NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) -- TCP last rcv_win %u snd_off_nxt %u snd_off_ack %u",
                __FUNCTION__,
                (uintptr_t) so, (uintptr_t) so->chr, NI_NTOHS(so->gaddr.sin_port),
                inet_ntoa(so->faddr.sin_addr),
                NI_NTOHS(so->faddr.sin_port),
                (unsigned int) so->rcv_win,
                (unsigned int) so->snd_off_nxt,
                (unsigned int) so->snd_off_ack);
        if (queued) {
            atomic_dec(&so->ni->number_tcp_sockets);
            if ((so->flags & TF_NAV))
                atomic_dec(&so->ni->number_tcp_nav_sockets);
        }
        socket_reset(so);

    } else if (so->type == IPPROTO_UDP) {
        if (queued)
            atomic_dec(&so->ni->number_udp_sockets);
    }

    now = get_clock_ms(vm_clock);
    if (!so->ni->tcpip_stats_ts || so->ni->tcpip_stats_ts + STATS_MS < now) {
        so->ni->tcpip_stats_ts = now;

        NETLOG4("%s: #tcp %lu #udp %lu", __FUNCTION__, (unsigned long) so->ni->number_tcp_sockets,
                (unsigned long) so->ni->number_udp_sockets);
    }

    if (so->lv)
        tcpip_lava_submit(so);
    so->lv = NULL;

    LIST_INSERT_HEAD(&so->ni->gc_tcpip, so, entry);
    return NULL;
}

static void socket_gc(void *opaque)
{
    struct nickel *ni = (struct nickel *) opaque;
    struct ni_socket *so, *so_next;

    LIST_FOREACH_SAFE(so, &ni->gc_tcpip, entry, so_next) {
        LIST_REMOVE(so, entry);
        free(so);
    }
}

static struct ni_socket *
find_socket_tcp(struct nickel *ni, uint32_t gaddr, uint16_t gport, uint32_t faddr,
        uint16_t fport)
{
    struct ni_socket *so = NULL;

    if (ni->tcp_lst_so && !IS_DEL(ni->tcp_lst_so) && ni->tcp_lst_so->gaddr.sin_port == gport  &&
            ni->tcp_lst_so->faddr.sin_addr.s_addr == faddr &&
            ni->tcp_lst_so->faddr.sin_port == fport &&
            ni->tcp_lst_so->gaddr.sin_addr.s_addr == gaddr) {

        return ni->tcp_lst_so;

    }

    LIST_FOREACH(so, &ni->tcp, entry) {
        if (so != ni->tcp_lst_so && !IS_DEL(so) &&
                so->gaddr.sin_port == gport &&
                so->faddr.sin_addr.s_addr == faddr &&
                so->faddr.sin_port == fport &&
                so->gaddr.sin_addr.s_addr == gaddr)
            break;
    }

    if (so)
        ni->tcp_lst_so = so;

    return so;
}

static struct ni_socket *
find_socket_udp(struct nickel *ni, uint32_t gaddr, uint16_t gport, uint32_t faddr,
        uint16_t fport)
{
    struct ni_socket *so = NULL;

    LIST_FOREACH(so, &ni->udp, entry) {
        if (!IS_DEL(so) && so->faddr.sin_addr.s_addr == faddr &&
                so->gaddr.sin_addr.s_addr == gaddr &&
                so->faddr.sin_port == fport &&
                so->gaddr.sin_port == gport)
            break;
    }
    return so;
}

static int tcp_close_socket(struct ni_socket *so, bool rst)
{
    if (rst)
        tcp_rst(so);
    if ((so->flags & TF_CLOSED)) {
        so = socket_free(so);
        goto out;
    }

    if ((so->flags & TF_HOSTFWD)) {
        DBG4(so, "closed");
        so->state = TS_CLOSED;
        if (so->fwd_timer)
            free_timer(so->fwd_timer);
        so->fwd_timer = NULL;
    }
    if (so->chr)
        send_close(so, rst);
    else
        so->flags |= TF_CLOSED;
out:
    return 0;
}

static uint32_t get_snd_win(struct ni_socket *so)
{
    uint32_t s = 0, max = MAX_16_WIN;

    if (!so->chr)
        goto out;

    s = max;
    if (so->chr->chr_can_write)
        s = qemu_chr_can_write(so->chr);

    if (so->g_use_win_scaling)
        max <<= so->snd_win_shift;

    if (s > max)
        s = max;
out:
    return s;
}

static uint32_t get_rcv_win(struct ni_socket *so, struct tcp *tcp)
{
    return so->g_use_win_scaling ? (((uint32_t) (NI_NTOHS(tcp->th_win))) << so->rcv_win_shift)
                                 : (uint32_t) NI_NTOHS(tcp->th_win);
}

static uint16_t checksum(uint32_t start, uint8_t *b, size_t len)
{
    register uint32_t sum = 0;

    sum += start;
    while (len > 1) {
        sum += *((uint16_t *)b);
        b += 2;
        len -= 2;
    }

    if (len > 0)
        sum += *b;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t) (~sum & 0xffff);
}

static void ip_checksum(struct ip *ip, size_t tlen)
{
    ip->ip_sum = 0;
    ip->ip_sum = checksum(0, (uint8_t*)ip, sizeof(*ip));
}

static void tcp_checksum(struct ip *ip, struct tcp *tcp, size_t tlen)
{
    uint32_t sum = 0;
    uint8_t prot[2];

    prot[0] = 0; // zeros
    prot[1] = ip->ip_p; // protocol from IP header

    sum += ((uint16_t*) (&ip->ip_src))[0];
    sum += ((uint16_t*) (&ip->ip_src))[1];
    sum += ((uint16_t*) (&ip->ip_dst))[0];
    sum += ((uint16_t*) (&ip->ip_dst))[1];
    sum += *((uint16_t*) prot);
    sum += NI_HTONS(tlen);
    tcp->th_sum = 0;
    tcp->th_sum = checksum(sum, (uint8_t*)tcp, tlen);
}

static void udp_checksum(struct ip *ip, struct udp *udp, size_t ulen)
{
    uint32_t sum = 0;
    uint8_t prot[2];

    prot[0] = 0; // zeros
    prot[1] = ip->ip_p; // protocol from IP header

    sum += ((uint16_t*) (&ip->ip_src))[0];
    sum += ((uint16_t*) (&ip->ip_src))[1];
    sum += ((uint16_t*) (&ip->ip_dst))[0];
    sum += ((uint16_t*) (&ip->ip_dst))[1];
    sum += *((uint16_t*) prot);
    sum += NI_HTONS(ulen);
    udp->uh_sum = 0;
    udp->uh_sum = checksum(sum, (uint8_t*)udp, ulen);
}

static size_t eth_write(struct nickel *ni, uint8_t *b)
{
    struct ethhdr *eh = (struct ethhdr *) b;

    memcpy(&eh->h_dest, ni->eth_vm, ETH_ALEN);
    memcpy(&eh->h_source, ni->eth_nickel, ETH_ALEN);
    eh->h_proto = NI_HTONS(ETH_P_IP);

    return sizeof(*eh);
}

static void ip_write(struct nickel *ni, uint8_t type, uint32_t saddr, uint32_t daddr, struct ip *ip,
        size_t tlen)
{
    memset(ip, 0, sizeof(*ip));
    ip->ip_v = IP_V4;
    ip->ip_hl = sizeof(*ip) >> 2;
    ip->ip_len = NI_HTONS(tlen);
    ip->ip_id = NI_HTONS(ni->ip_id++);
    ip->ip_ttl = 33;
    ip->ip_p = type;
    ip->ip_src = saddr;
    ip->ip_dst = daddr;
}

static void arp_input(struct nickel *ni, const uint8_t *pkt, size_t len)
{
    struct arphdr *ah;
    uint8_t *arp_reply;
    struct ethhdr *reh;
    struct arphdr *rah;
    int ar_op;
    struct buff *bf = NULL;
    size_t l;

    if (len < ETH_HLEN + sizeof(*ah))
        goto out;
    ah = (struct arphdr *) (pkt + ETH_HLEN);
    ar_op = NI_NTOHS(ah->ar_op);
    switch(ar_op) {
    case ARPOP_REQUEST:
        if (ah->ar_tip == ah->ar_sip) {
            /* Gratuitous ARP */
            goto out;
        }

        if (ah->ar_tip != ni->host_addr.s_addr)
            goto out;
        l = MAX(ETH_HLEN + sizeof(struct arphdr), 256);
        bf = ni_netbuff(ni, l);
        if (!bf)
            goto out;
        arp_reply = bf->m;
        reh = (struct ethhdr *)arp_reply;
        rah = (struct arphdr *)(arp_reply + ETH_HLEN);

        /* ARP request for alias/dns mac address */
        memcpy(reh->h_dest, pkt + ETH_ALEN, ETH_ALEN);
        memcpy(reh->h_source, ni->eth_nickel, ETH_ALEN);
        reh->h_proto = NI_HTONS(ETH_P_ARP);

        rah->ar_hrd = NI_HTONS(1);
        rah->ar_pro = NI_HTONS(ETH_P_IP);
        rah->ar_hln = ETH_ALEN;
        rah->ar_pln = 4;
        rah->ar_op = NI_HTONS(ARPOP_REPLY);
        memcpy(rah->ar_sha, reh->h_source, ETH_ALEN);
        rah->ar_sip = ah->ar_tip;
        memcpy(rah->ar_tha, ah->ar_sha, ETH_ALEN);
        rah->ar_tip = ah->ar_sip;
        ni_buff_output(ni, bf);
        break;
    default:
        break;
    }

out:
    return;
}

#define PING_MAGIC  0x91ce1114
struct ping_probe {
    uint16_t cksum;
    uint32_t magic;
    uint32_t n;
    uint16_t g_ip_id;
    uint16_t h_ip_id;
    uint64_t n_pkt_rx;
    uint64_t n_pkt_tx;
    uint64_t s_pkt_rx;
    uint64_t s_pkt_tx;
    uint32_t len;
    uint64_t us_sent;
};

struct icmp_ping {
    struct icmp icmp;
    uint16_t id;
    uint16_t seq;
};

static int icmp_echoreply(struct nickel *ni, const uint8_t *pkt, size_t len,
        uint32_t saddr, uint32_t daddr)
{
    struct icmp_ping *header;
    struct ping_probe *probe;
    size_t off = 0;
    int64_t us_now;

    header = (struct icmp_ping *) pkt;
    if (len < sizeof(*header))
        return -1;

    off += sizeof(*header);
    len -= sizeof(*header);

    probe = (struct ping_probe *) (pkt + off);
    if (len < sizeof(*probe))
        return -1;

    if (probe->magic != PING_MAGIC) {
        NETLOG("%s: PING bad magic %x", __FUNCTION__, probe->magic);
        return -1;
    }

    if (probe->cksum != checksum(0, (uint8_t *) ((&probe->cksum) + 1),
                len - 2)) {

        NETLOG("%s: PING invalid checksum", __FUNCTION__);
        return -1;
    }

    ni->ping_warn = 1;
    us_now = os_get_clock() / 1000LL;
    us_now = us_now - probe->us_sent;
    if (ni->us_max_ping_rtt < us_now) {
        ni->us_max_ping_rtt = us_now;
        NETLOG3("PING rtt %luus drx %u %0.03fKiB dtx %u %0.03fKiB",
                (unsigned long) us_now,
                (unsigned int) (ni->n_pkt_rx - probe->n_pkt_rx),
                (double) ((ni->s_pkt_rx - probe->s_pkt_rx) >> 10),
                (unsigned int) (ni->n_pkt_tx - probe->n_pkt_tx),
                (double) ((ni->s_pkt_tx - probe->s_pkt_tx) >> 10));
    }

    return 0;
}

static int icmp_ping_probe(struct nickel *ni)
{
    struct buff *bf;
    size_t pkt_len, off, l, ip_l, icmp_l;
    struct ip *ip;
    struct icmp_ping *ping;
    struct ping_probe *probe;
    uint8_t *pkt;
    static uint16_t seq_no = 0;

    pkt_len = ETH_HLEN + sizeof(struct ip) + sizeof(struct icmp_ping) +
        sizeof(struct ping_probe) + 64;

    bf = ni_netbuff(ni, pkt_len);
    if (!bf)
        return -1;

    off = 0;
    pkt = bf->m;

    l = ETH_HLEN;
    eth_write(ni, pkt + off);
    pkt_len -= l;
    off += l;

    ip = (struct ip *) (pkt + off);
    ip_l = pkt_len;
    l = sizeof(*ip);
    ip_write(ni, IPPROTO_ICMP, ni->host_addr.s_addr, ni->dhcp_startaddr.s_addr,
            ip, pkt_len);
    pkt_len -= l;
    off += l;

    ping = (struct icmp_ping *) (pkt + off);
    l = sizeof(*ping);
    icmp_l = pkt_len;
    ping->icmp.type = ICMP_ECHO;
    ping->seq = NI_HTONS(seq_no++);
    pkt_len -= l;
    off += l;

    probe = (struct ping_probe *) (pkt + off);
    probe->magic = PING_MAGIC;
    probe->n = seq_no;
    probe->g_ip_id = ni->g_last_ip;
    probe->h_ip_id = ni->ip_id;
    probe->n_pkt_rx = ni->n_pkt_rx;
    probe->n_pkt_tx = ni->n_pkt_tx;
    probe->s_pkt_rx = ni->s_pkt_rx;
    probe->s_pkt_tx = ni->s_pkt_tx;
    probe->us_sent = (uint64_t) (os_get_clock() / 1000LL);
    probe->cksum = checksum(0, (uint8_t *) probe, pkt_len);

    ping->icmp.cksum = 0;
    ping->icmp.cksum = checksum(0, (uint8_t *) ping, icmp_l);
    ip_checksum(ip, ip_l);

    ni->ping_probe_n++;
    ni_buff_output(ni, bf);
    return 0;
}

static void buff_output(struct nickel *ni, struct buff *bf)
{
    if (ni->eth_vm_resolved)
        ni_buff_output(ni, bf);
    else
        RLIST_INSERT_TAIL(&ni->noarp_output_list, bf, entry);
}

static int
tcp_send(struct ni_socket *so, int flags, const uint8_t *data, size_t len)
{
    int ret = -1;
    uint8_t *pkt;
    size_t pkt_len, off = 0, l, ip_l, tcp_l;
    struct tcp *tcp;
    struct ip *ip;
    size_t opt_len = 0;
    struct buff *bf = NULL;
    uint16_t win = 0;

    if (!data)
        len = 0;

    /* TCP options */
    if ((flags & TH_SYN)) {
        opt_len = 4 + 3; /* MSS  + SAck */

        if (!so->ni->tcp_disable_window_scale)
            opt_len += 3; /* Window Scale option */
    }
    if (opt_len)
        opt_len = (opt_len + 3) & ((size_t) ~3); /* multiple of 4 */

    pkt_len = ETH_HLEN + sizeof(struct ip) + sizeof(struct tcp) +
                opt_len + len;
    bf = ni_netbuff(so->ni, pkt_len);
    if (!bf)
        goto out;
    pkt = bf->m;

    l = eth_write(so->ni, pkt + off);
    pkt_len -= l;
    off += l;

    ip = (struct ip *) (pkt + off);
    ip_l = pkt_len;
    l = sizeof(*ip);
    ip_write(so->ni, so->type, so->faddr.sin_addr.s_addr,
            so->gaddr.sin_addr.s_addr, ip, pkt_len);
    pkt_len -= l;
    off += l;

    /* standard TCP header */
    tcp = (struct tcp *) (pkt + off);
    tcp_l = pkt_len;
    l = sizeof(*tcp);

    memset(tcp, 0, sizeof(*tcp));
    tcp->th_sport = so->faddr.sin_port;
    tcp->th_dport = so->gaddr.sin_port;

    tcp->th_seq = NI_HTONL(so->snd_iss + so->snd_off_nxt);
    tcp->th_ack = NI_HTONL(so->rcv_iss + so->rcv_off_ack);
    tcp->th_off = (sizeof(*tcp) + opt_len) >> 2;

    so->snd_win = get_snd_win(so);
    win = MAX(so->snd_win, MAX_16_WIN);
    if (!(flags & TH_SYN))
        win = (uint16_t) (so->g_use_win_scaling ? (so->snd_win >> so->snd_win_shift) : so->snd_win);
    tcp->th_win = NI_HTONS(win);

    pkt_len -= l;
    off += l;

    /* TCP options (MSS, Window Scale, etc.) */
    if (opt_len) {
        uint8_t *po = pkt + off;

        pkt_len -= opt_len;
        off += opt_len;

        // MSS 4 bytes
        assert(opt_len >= 4);
        *po++ = 0x02; // MSS
        *po++ = 0x04;
        *((uint16_t*) po) = NI_HTONS(so->ni->tcp_mss);
        po += 2;
        opt_len -= 4;

        // SACK
        assert(opt_len >= 2);
        *po++ = 0x04; // SACK
        *po++ = 0x02;
        opt_len -= 2;

        if (!so->ni->tcp_disable_window_scale) {
            // Window Scale 3 bytes
            assert(opt_len >= 3);
            *po++ = 0x03; // WScale
            *po++ = 0x03;
            *po++ = SND_WIN_SHIFT;
            opt_len -= 3;
        }

        // make sure the remaining are nulls
        if (opt_len > 0)
            memset(po, 0, opt_len);
    }

    /* TCP data */
    if (len) {
        int64_t now = get_clock_ms(vm_clock);

        if ((so->flags & TF_NAV)) {
            so->ni->tcpip_last_tcp_data = now;
            atomic_add(&so->ni->tcp_nav_rx, (uint32_t) len);
        }

        memcpy(pkt + off, data, len);
        so->ack_2_ts = now;

        bf->ts = now;
        bf->state = BFS_SOCKET;
        RLIST_INSERT_TAIL(&so->sent_q, bf, so_entry);
    }
    so->snd_off_nxt += (uint32_t) len;

    tcp->th_flags |= flags;
    if (flags & TH_ACK)
        so->flags &= ~(TF_DELAYED_ACK);

    /* checksum */
    tcp_checksum(ip, tcp, tcp_l);
    ip_checksum(ip, ip_l);

    buff_output(so->ni, bf);
    ret = 0;
out:
    return ret;
}

static int tcp_rst(struct ni_socket *so)
{
    int ret;

    so->state = TS_CONN_RST;
    ret = tcp_send(so, TH_ACK|TH_RST, NULL, 0);

    NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) -- RST sent",
            __FUNCTION__,
            (uintptr_t) so, (uintptr_t) so->chr, NI_NTOHS(so->gaddr.sin_port),
            inet_ntoa(so->faddr.sin_addr),
            NI_NTOHS(so->faddr.sin_port));

    socket_reset(so);

    return ret;
}

static int tcp_respond_rst(struct nickel *ni, const struct tcp *s_tcp, uint32_t saddr, uint32_t daddr)
{
    int ret = -1;
    uint8_t *pkt;
    size_t pkt_len, off = 0, l, ip_l, tcp_l;
    struct tcp *tcp;
    struct ip *ip;
    struct buff *bf = NULL;

    pkt_len = ETH_HLEN + sizeof(struct ip) + sizeof(struct tcp);
    bf = ni_netbuff(ni, pkt_len);
    if (!bf)
        goto out;
    pkt = bf->m;

    l = eth_write(ni, pkt + off);
    pkt_len -= l;
    off += l;

    ip = (struct ip *) (pkt + off);
    ip_l = pkt_len;
    l = sizeof(*ip);
    ip_write(ni, IPPROTO_TCP, daddr, saddr, ip, pkt_len);
    pkt_len -= l;
    off += l;

    tcp = (struct tcp *) (pkt + off);
    tcp_l = pkt_len;
    l = sizeof(*tcp);

    memset(tcp, 0, sizeof(*tcp));
    tcp->th_sport = s_tcp->th_dport;
    tcp->th_dport = s_tcp->th_sport;
    tcp->th_seq = s_tcp->th_ack;
    tcp->th_ack = s_tcp->th_seq;
    tcp->th_off = sizeof(*tcp) >> 2;
    tcp->th_win = 0;

    pkt_len -= l;
    off += l;

    tcp->th_flags = TH_RST;

    /* checksum */
    tcp_checksum(ip, tcp, tcp_l);
    ip_checksum(ip, ip_l);

    buff_output(ni, bf);
    ret = 0;
out:
    return ret;
}

static int tcp_get_options(uint8_t *opt, size_t maxlen, uint16_t *mss, int *win_shift)
{
    size_t i = 0;
    uint8_t ot = 0, ol = 0;
    int n_opt = 0;

    while (i < maxlen) {
        uint8_t c = opt[i++];

        if (ol) {
            ol--;
            if (!ol)
                ot = 0;
            continue;
        }

        if (ot == 0 || ot == 1) {
            ot = c;
            continue;
        }

        ol = c;
        if (ol < 2) {
            NETLOG("%s: error on parsing TCP options", __FUNCTION__);
            break;
        }
        ol -= 2;
        if (ol == 0)
            ot = 0;

        /* TCP MSS 0x02 */
        if (ot == 0x02 && ol == 2 && ol + i <= maxlen) {
            *mss = NI_NTOHS(*((uint16_t*) (opt + i)));
            i += ol;
            ot = ol = 0;
            if (++n_opt == 2)
                break;

            continue;
        }

        /* TCP Window Scale 0x03 */
        if (ot == 0x03 && ol == 1 && ol + i <= maxlen) {
            *win_shift = (int) (*(opt + i));
            i += ol;
            ot = ol = 0;
            if (++n_opt == 2)
                break;

            continue;
        }
    }

    return 0;
}

static inline void get_bf_seq_len(struct ni_socket *so, struct buff *bf, uint32_t *seq, uint32_t *len)
{
    struct tcp *tcp = (struct tcp *) (bf->m + ETH_HLEN + sizeof(struct ip));

    *seq = (uint32_t) NI_NTOHL(tcp->th_seq) - so->snd_iss;
    *len = (uint32_t) (bf->len - (ETH_HLEN + sizeof(struct ip) + ((uint32_t) (tcp->th_off) << 2)));

}

static void remove_buff(struct ni_socket *so, struct buff *bf)
{
    RLIST_REMOVE(bf, so_entry);
    for (;;) {
        if (cmpxchg(&bf->state, BFS_SENT, BFS_SOCKET) == BFS_SENT) {
            buff_free(&bf);
            break;
        }

        if (cmpxchg(&bf->state, BFS_SOCKET, BFS_FREE) == BFS_SOCKET)
            break;
    }
}

static void retransmit_packet(struct ni_socket *so, struct buff *bf)
{
    struct ip *ip;
    struct tcp *tcp;

    assert(so->type == IPPROTO_TCP);
    assert(so->state == TS_ESTABLISHED);
    assert(bf->state == BFS_SENT);

    ip = (struct ip*) (bf->m + ETH_HLEN);
    tcp = (struct tcp *) (bf->m + ETH_HLEN + sizeof(struct ip));

    ip->ip_id = NI_HTONS(so->ni->ip_id++);
    ip->ip_ttl = 34;

    tcp->th_win = NI_HTONS((uint16_t) (so->g_use_win_scaling ?
                (so->snd_win >> so->snd_win_shift) : so->snd_win));
    tcp->th_ack =  NI_HTONL(so->rcv_iss + so->rcv_off_ack);

    tcp_checksum(ip, tcp, bf->len - ETH_HLEN - sizeof(struct ip));
    ip_checksum(ip, bf->len - ETH_HLEN);

#if DEBUG_RETRANSMIT
    NETLOG4("%s: so %"PRIxPTR" seq %u len %u", __FUNCTION__,
            (uintptr_t) so, NI_NTOHL(tcp->th_seq) - so->snd_iss,
            (unsigned int) (bf->len - ETH_HLEN - sizeof(struct ip) - sizeof(struct tcp)));
#endif

    bf->retransmit ++;
    bf->ts = get_clock_ms(vm_clock);
    bf->state = BFS_SOCKET;
    so->flags |= TF_RETRANSMISSION;
    buff_output(so->ni, bf);
}

static void packets_acked(struct ni_socket *so, uint32_t off_ack)
{
    struct buff *bf, *bf_n;

    RLIST_FOREACH_SAFE(bf, &so->sent_q, so_entry, bf_n) {
        uint32_t seq = 0, len = 0;

        get_bf_seq_len(so, bf, &seq, &len);
        if (SEQ_CMP(off_ack, seq + len) < 0)
            break;

        /* packet acked, free */
        remove_buff(so, bf);
    }
}

#if FREE_SACKED_ACKS
static void packets_acked_range(struct ni_socket *so, uint32_t left, uint32_t right)
{
    struct buff *bf, *bf_n;

#if DEBUG_RETRANSMIT
    NETLOG4("%s: so %" "win %u left %u right %u", __FUNCTION__, (uintptr_t) so,
            (unsigned int) so->rcv_win,
            (unsigned int) left,
            (unsigned int) right);
#endif

    RLIST_FOREACH_SAFE(bf, &so->sent_q, so_entry, bf_n) {
        uint32_t seq = 0, len = 0;

        get_bf_seq_len(so, bf, &seq, &len);
        if (SEQ_CMP(seq, left) < 0)
            continue;

        if (SEQ_CMP(right, seq + len) < 0)
            break;

        remove_buff(so, bf);
    }
}
#endif

static uint32_t sack_received(struct ni_socket *so, uint32_t off_ack, uint8_t *po, size_t olen)
{
    uint32_t ret, left;
#if FREE_SACKED_ACKS
    uint32_t right = 0;
#endif

    ret = off_ack;
    while (olen >= 4 + 4) {
        left = NI_NTOHL(*((uint32_t *) po)) - so->snd_iss;
        po += 4;
#if FREE_SACKED_ACKS
        right = NI_NTOHL(*((uint32_t *) po)) - so->snd_iss;
#endif
        po += 4;
        olen -= (4 + 4);

        if (SEQ_CMP(left, off_ack) > 0 && (ret == off_ack || SEQ_CMP(left, ret) < 0))
            ret = left;

        /* SACK ranges are just advisory, so it could be dengerous to discard them */
#if FREE_SACKED_ACKS
        packets_acked_range(so, left, right);
#endif

    }

    return ret;
}

static void retransmit_queue(struct ni_socket *so, bool sack, uint32_t sack_to)
{
    struct buff *bf;
    int64_t now;

    now = get_clock_ms(vm_clock);
    RLIST_FOREACH(bf, &so->sent_q, so_entry) {
        uint32_t seq = 0, len = 0;

        if (bf->state != BFS_SENT)
            continue;

        if (sack) {
            get_bf_seq_len(so, bf, &seq, &len);
            if (SEQ_CMP(sack_to, seq) <= 0)
                break;
        }

        if (!bf->retransmit || now - bf->ts > RETRANSMIT_REPEAT) {
#if DEBUG_RETRANSMIT
            NETLOG4("%s: so %"PRIxPTR" retransmission pkt len %lu", __FUNCTION__, 
                    (uintptr_t) so, bf->len);
#endif
            retransmit_packet(so, bf);
            if (!sack)
                break;
        }
    }
}

static void tcp_send_fin(struct ni_socket *so, CharDriverState *chr_saved)
{
    if (!RLIST_EMPTY(&so->sent_q, so_entry)) {
        so->ts_closed = get_clock_ms(vm_clock);
        so->flags |= (TF_RETRANSMISSION | TF_RETRANSMISSION_FIN);
        NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR"/%"PRIxPTR" (G:%hu -> %s:%hu) -- retransmission FIN",
                __FUNCTION__,
                (uintptr_t) so, (uintptr_t) so->chr, (uintptr_t) chr_saved,
                NI_NTOHS(so->gaddr.sin_port),
                inet_ntoa(so->faddr.sin_addr),
                NI_NTOHS(so->faddr.sin_port));
    } else if (!(so->flags & TF_FIN_SENT)) {
        so->ts_closed = get_clock_ms(vm_clock);
        tcp_send(so, TH_ACK|TH_FIN, NULL, 0);
        so->snd_off_nxt += 1;
        so->flags |= TF_FIN_SENT;

        NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR"/%"PRIxPTR" (G:%hu -> %s:%hu) -- FIN sent",
                __FUNCTION__,
                (uintptr_t) so, (uintptr_t) so->chr, (uintptr_t) chr_saved,
                NI_NTOHS(so->gaddr.sin_port),
                inet_ntoa(so->faddr.sin_addr),
                NI_NTOHS(so->faddr.sin_port));
    }
}

static int so_chr_is_eof(struct ni_socket *so)
{
    return !!(so->chr && qemu_chr_eof(so->chr));
}

static void fwd_connect_cb(void *opaque)
{
    struct ni_socket *so = opaque;

    if (so->state == TS_SYN_SENT) {
        so->fwd_n++;
        if (so->fwd_n < 2)
            goto inc_timer;
        so->fwd_n = 0;
        so->state = TS_CLOSED;
    }

    if (so->state == TS_CLOSED) {
        uint16_t port;

        /* check for chr betrayal */
        if (so_chr_is_eof(so)) {
            DBG4(so, "host peer hung up while sending SYNs");
            qemu_chr_send_event(so->chr, CHR_EVENT_NI_CLOSE);
            goto free_timer;
        }
        socket_reset(so);
        so->snd_iss = get_iss();
        port = tcp_get_free_port(so->ni);
        if (port)
            so->faddr.sin_port = port;
        else
            NETLOG("%s: failed to obtain free port", __FUNCTION__);

        tcp_send(so, TH_SYN, NULL, 0);
        so->state = TS_SYN_SENT;
        so->snd_off_nxt = 1;
        goto inc_timer;
    }

    if (so->state == TS_ESTABLISHED)
        goto free_timer;

inc_timer:
    mod_timer(so->fwd_timer, get_clock_ms(vm_clock) + HFWD_CONNECT_DELAY_MS);
    return;
free_timer:
    free_timer(so->fwd_timer);
    so->fwd_timer = NULL;
}

static void tcpip_timer(struct nickel *ni, int64_t now, int *timeout)
{
    struct ni_socket *so, *so_n;
    int64_t diff;

    if (ni->ping_sent_ts && now - ni->ping_sent_ts > PING_RTT_LAT_WARN_MS) {
        if (!ni->ping_warn) {
            NETLOG("%s: PING rtt timeout > %u ms", __FUNCTION__, PING_RTT_LAT_WARN_MS);
            ni->ping_warn = 1;
        }
        if (now - ni->ping_sent_ts > PING_PROBE_PERIOD_MS) {
            ni->ping_sent_ts = 0;
            ni->ping_warn = 0;
            if (ni->ping_probe_n > PING_PROBE_RESET_N) {
                ni->ping_probe_n = 0;
                ni->us_max_ping_rtt = 0;
            }
        }
    }

    LIST_FOREACH_SAFE(so, &ni->udp, entry, so_n) {
        if (IS_DEL(so) || (so->flags & TF_CLOSED) || !so->chr) {
            so = socket_free(so);
            continue;
        }
        diff = so->ts_created + UDP_SOCK_EXPIRE - now;
        if (diff <= 0)
            send_close(so, false);
        else if ((int64_t) (*timeout) > diff)
            *timeout = (int) diff;
    }

    LIST_FOREACH_SAFE(so, &ni->tcp, entry, so_n) {
        if (IS_DEL(so)) {

            so = socket_free(so);
            continue;
        }

        /* delayed ACK */
        if (so->state == TS_ESTABLISHED && (so->flags & TF_DELAYED_ACK)) {
            diff = so->delay_ac_ts - now;
            if (diff <= DELAY_ACK_MIN_MS)
                tcp_send(so, TH_ACK, NULL, 0);
            else if ((int64_t) (*timeout) > diff)
                *timeout = diff;
        }

        /* retransmission */
        if (so->state == TS_ESTABLISHED && !RLIST_EMPTY(&so->sent_q, so_entry)) {
            struct buff *bf;
            int tmo = (so->flags & TF_RETRANSMISSION) ? RETRANSMIT_REPEAT :
                                                        RETRANSMIT_TIMEOUT;

            RLIST_FOREACH(bf, &so->sent_q, so_entry) {
                diff = now - bf->ts;
                if (bf->retransmit > MAX_RETRANSMIT_PER_PACKET) {
                    uint32_t seq = 0, len = 0;

                    get_bf_seq_len(so, bf, &seq, &len);
                    NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) "
                            "-- MAX_RETRANSMIT_PER_PACKET bf seq %u "
                            "len %u rcv_win %u/%d snd_off_nxt %u snd_off_ack %u",
                            __FUNCTION__,
                            (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                            inet_ntoa(so->faddr.sin_addr),
                            NI_NTOHS(so->faddr.sin_port),
                            (unsigned int) seq, (unsigned int) len,
                            (unsigned int) so->rcv_win,
                            (int) (so->g_use_win_scaling ? so->rcv_win_shift : -1),
                            (unsigned int) so->snd_off_nxt,
                            (unsigned int) so->snd_off_ack);

                    bf->retransmit = 1;
                    so->flags &= ~TF_RETRANSMISSION;
                    tcp_send(so, TH_ACK, NULL, 0);
                    break;
                }
                if ((!bf->retransmit && (so->flags & TF_RETRANSMISSION)) || diff >= tmo) {

                    if (bf->state == BFS_SENT)
                        retransmit_packet(so, bf);
                    break;
                }

                diff = tmo - diff;
                if (diff > 0 && (int64_t) (*timeout) > diff)
                   *timeout = (int) diff;

                break;
            }
        }

        if ((so->flags & TF_RST_PENDING))
            tcp_rst(so);

        if ((so->flags & TF_CLOSED)) {
            if (so->state == TS_CONN_RST) {

                so = socket_free(so);
                continue;
            }

            if (so->n_fin_retransmit > MAX_COUNT_FIN_WAIT) {
                tcp_send(so, TH_RST, NULL, 0);
                NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) -- RST sent FINACKED=%d",
                        __FUNCTION__,
                        (uintptr_t) so, (uintptr_t) so->chr, NI_NTOHS(so->gaddr.sin_port),
                        inet_ntoa(so->faddr.sin_addr),
                        NI_NTOHS(so->faddr.sin_port), (int) !!(so->flags & TF_FIN_ACKED));

                so = socket_free(so);
                continue;
            }
            diff = so->ts_closed + TCP_FIN_WAIT - now;
            if (diff <= 0) {
                so->n_fin_retransmit++;
                if (!(so->flags & TF_FIN_ACKED)) {
                    NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) -- FIN sent %s",
                            __FUNCTION__,
                            (uintptr_t) so, (uintptr_t) so->chr, NI_NTOHS(so->gaddr.sin_port),
                            inet_ntoa(so->faddr.sin_addr),
                            NI_NTOHS(so->faddr.sin_port),
                            (so->flags & TF_FIN_SENT) ? "retransmission" : "");
                    if ((so->flags & TF_FIN_SENT))
                        so->snd_off_nxt--;
                    tcp_send(so, TH_FIN|TH_ACK, NULL, 0);
                    so->flags |= TF_FIN_SENT;
                    so->snd_off_nxt += 1;
                }
                so->ts_closed = now;
            } else if ((int64_t) (*timeout) > diff)
                *timeout = (int) diff;
        }

        if (so->poll_eof_ts && so->state == TS_ESTABLISHED) {
            diff = so->poll_eof_ts + HFWD_EOF_POLL_MS - now;
            if (diff <= 0) {
                if (so_chr_is_eof(so)) {
                    DBG4(so, "host peer hung up");
                    so->poll_eof_ts = 0;
                    qemu_chr_send_event(so->chr, CHR_EVENT_NI_CLOSE);
                } else {
                    so->poll_eof_ts = now;
                    diff = HFWD_EOF_POLL_MS;
                }
           }
           if (diff > 0 && (int64_t) (*timeout) > diff)
                *timeout = (int) diff;
        }
    }
}

static uint16_t tcp_get_free_port(struct nickel *ni)
{
    uint16_t port = ni->tcp_last_free_port;
    bool pass = false;

    while (port < ni->tcp_free_port_end) {
        struct ni_socket *so;
        bool match = false;

        LIST_FOREACH(so, &ni->tcp, entry) {
            if (so->faddr.sin_addr.s_addr == ni->host_addr.s_addr &&
                    so->faddr.sin_port == htons(port)) {
                match = true;
                break;
            }
        }

        if (match) {
            port ++;
            if (port >= ni->tcp_free_port_end && !pass) {
                pass = true;
                port = ni->tcp_free_port_base + 1;
            }
        }
        else
            break;
    }

    if (port < ni->tcp_free_port_end) {
        ni->tcp_last_free_port = port + 1;
        if (ni->tcp_last_free_port == ni->tcp_free_port_end)
            ni->tcp_last_free_port = ni->tcp_free_port_base + 1;
        return htons(port);
    }

    return 0;
}

struct lava_event *
tcpip_lava_get(struct ni_socket *so)
{
    if (!so)
        return NULL;

    return so->lv;
}

int tcpip_lava_submit(struct ni_socket *so)
{
    int ret = -1;

    if (!so->lv)
        goto out;

    lava_event_complete(so->lv, true);
    so->lv = NULL;
out:
    return ret;
}

struct ni_socket *
tcp_listen_create(struct nickel *ni, CharDriverState *chr, uint32_t faddr, uint16_t fport,
        uint32_t gaddr, uint16_t gport, uint32_t flags)
{
    struct ni_socket *so = NULL;

    so = socket_create(ni, IPPROTO_TCP, true);
    if (!so)
        goto out;
    if (!faddr)
        faddr = ni->host_addr.s_addr;
    if (!fport)
        fport = tcp_get_free_port(ni);
    if (!fport) {
        NETLOG("%s: failed to obtain free port", __FUNCTION__);
        socket_free(so);
        return NULL;
    }
    if (!gaddr)
        gaddr = ni->dhcp_startaddr.s_addr;
    so->faddr.sin_addr.s_addr = faddr;
    so->gaddr.sin_addr.s_addr = gaddr;
    so->gaddr.sin_port = gport;
    so->faddr.sin_port = fport;
    so->snd_iss = get_iss();
    so->snd_win = MAX_16_WIN;
    so->rcv_mss = 1460;

    if ((flags & SS_HOSTFWD))
        so->flags |= TF_HOSTFWD;
    if ((flags & SS_FWDCLOSE))
        so->flags |= TF_FWDCLOSE;
    if ((flags & SS_CLOSERETRY))
        so->flags |= TF_CLOSERETRY;

    so->chr = chr;
out:
    return so;
}

struct sockaddr_in tcpip_get_gaddr(void *so_opaque)
{
    struct ni_socket *so = (struct ni_socket *) so_opaque;

    return so->gaddr;
}

void tcpip_event(struct ni_socket *so, int event)
{
    if (so->type != IPPROTO_TCP)
        return;

    if (event == CHR_EVENT_OPENED) {
        if ((so->flags & TF_CONNECTING) && so->state == TS_SYN_RECVD) {
            so->rcv_off_ack = 1;
            tcp_send(so, TH_SYN|TH_ACK, NULL, 0);
            so->snd_off_nxt = 1;
            so->state = TS_SYNACK_SENT;
        }
        so->flags &= ~TF_CONNECTING;
        return;
    }

    if (!(so->flags & TF_HOSTFWD))
        return;

    if (event == CHR_EVENT_EOF) {
        if (so->fwd_timer) {
            free_timer(so->fwd_timer);
            so->fwd_timer = NULL;
        }
        so->state = TS_CLOSED;
        tcp_send_fin(so, NULL);
        if (!RLIST_EMPTY(&so->sent_q, so_entry))
            so->flags |= TF_RETRANSMISSION_RST;
    }
}

void tcpip_set_sock_type(struct ni_socket *so, uint32_t typef)
{
    if ((typef & SS_VMFWD))
        so->flags |= TF_VMFWD;
    if ((typef & SS_NAV))
        so->flags |= TF_NAV;
}

void tcpip_set_chr(struct ni_socket *so, CharDriverState *chr)
{
    so->chr = chr;
}

int tcpip_send_fin(struct ni_socket *so)
{
    if (so->type != IPPROTO_TCP || so->state != TS_ESTABLISHED)
        return -1;

    if ((so->flags & TF_FIN_SENT))
        return 0;

    tcp_send_fin(so, NULL);
    return 0;
}

void tcpip_close(struct ni_socket *so)
{
    void *chr_saved = (void *) so->chr;

    so->flags |= TF_CLOSED;
    so->ts_closed = get_clock_ms(vm_clock);

    if (so->fwd_timer) {
        free_timer(so->fwd_timer);
        so->fwd_timer = NULL;
    }

    if (!so->chr || so->type != IPPROTO_TCP || so->state != TS_ESTABLISHED) {
        so->chr = NULL;
        if (so->type == IPPROTO_TCP)
            tcp_rst(so);
        so = socket_free(so);
        return;
    }

    so->chr = NULL;

    if ((so->flags & TF_FIN_ACKED) && (so->flags & TF_FIN_RECV)) {
        so = socket_free(so);
        return;
    }

    if ((so->flags & TF_FIN_SENT))
        return;

    tcp_send_fin(so, chr_saved);
}

size_t tcpip_can_output(struct ni_socket *so)
{
    size_t ret = 0;

    if (so->type == IPPROTO_UDP)
        return so->ni->mtu - NI_TCPIP_HLEN;

    if (so->state == TS_ESTABLISHED) {
        bool retransmission = !!(so->flags & TF_RETRANSMISSION);

        if (so->rcv_win == 0)
            goto win_out;
        if (retransmission) {
            ret = so->chr_win;
            goto win_out;
        }

        if (so->win_state == WST_SENT)
            goto win_out;
        if ((uint32_t) (so->snd_off_nxt - so->snd_off_ack) >= so->rcv_win)
            goto win_out;

        ret = so->rcv_win - ((uint32_t) (so->snd_off_nxt - so->snd_off_ack));
        if (so->win_state == WST_UNKN) {
            size_t mx = so->rcv_win;

            if (so->g_use_win_scaling)
                mx >>= so->rcv_win_shift;
            if (ret > mx)
                ret = mx;
            if (ret > so->rcv_mss)
                ret = so->rcv_mss;
        }

        win_out:
        so->chr_win = ret;
        if (!ret) {
            so->zero_win = 1;
            if ((so->flags & TF_HOSTFWD) && !so->poll_eof_ts && so->chr && so->chr->chr_eof) {
                DBG4(so, "zero win - starting eof poll timer");
                so->poll_eof_ts = get_clock_ms(vm_clock);
            }
        }
        goto out;
    }

    if ((so->flags & TF_HOSTFWD) && !so->fwd_timer) {
        DBG4(so, "scheduling TCP SYNs");
        so->fwd_timer = ni_new_vm_timer(so->ni, 1, fwd_connect_cb, so);
    }
out:
    return ret;
}

static void tcp_send_data(struct ni_socket *so, const uint8_t *data, int size)
{
    size_t mss = MIN(so->rcv_mss, so->ni->tcp_mss);
    bool split_pkt = (so->win_state == WST_UNKN);

    assert(data && size >= 0);

    if (size > 0 && so->win_state == WST_UNKN)
        so->win_state = WST_SENT;

    while (size > 0) {
        size_t chunk = size < mss ? size : mss;

        if (split_pkt) {
            size_t l = chunk / 2;

            tcp_send(so, TH_ACK, data, l);
            data += l;
            size -= l;
            chunk -= l;

            split_pkt = false;
        }
        tcp_send(so, TH_ACK | ((size <= mss) ? TH_PUSH : 0), data, chunk);
        data += chunk;
        size -= chunk;
    }
}

static void tcp_send_bufd_data(struct ni_socket *so)
{
    if (!so->bufd_data)
        return;

    if (so->bufd_len) {
#if DEBUG_RETRANSMIT
        NETLOG4("%s: so %"PRIxPTR" seq %u -- retransmit, sending buffered %u bytes",
                __FUNCTION__, (uintptr_t) so,
                (unsigned int) so->snd_off_nxt,
                (unsigned int) so->bufd_len);
#endif

        tcp_send_data(so, so->bufd_data, so->bufd_len);
    }
    ni_priv_free(so->bufd_data);
    so->bufd_data = NULL;
    so->bufd_len = 0;
}

void tcpip_output(struct ni_socket *so, const uint8_t *data, int size)
{
    if (size < 0 || !data)
        goto out;

    if (so->type == IPPROTO_TCP) {

        if (so->state != TS_ESTABLISHED) {
            NETLOG("%s: so %"PRIxPTR" chr %"PRIxPTR
                    " -- bug! trying to send %d bytes while not TS_ESTABLISHED "
                    " -- data will be lost", __FUNCTION__, (uintptr_t)so, (uintptr_t)so->chr, size);
            goto out;
        }

        if (!(so->flags & TF_RETRANSMISSION)) {
            if (so->bufd_len)
                tcp_send_bufd_data(so);
            tcp_send_data(so, data, size);
        } else {
            /* at retransmission time we buffer the data we promised we have space for */
            uint8_t *tmp;

            tmp = ni_priv_realloc(so->bufd_data, so->bufd_len + size);
            if (!tmp) {
                warnx("%s: malloc failure -- data will be lost!", __FUNCTION__);
                goto out;
            }
            so->bufd_data = tmp;
            memcpy(so->bufd_data + so->bufd_len, data, size);
            so->bufd_len += size;

#if DEBUG_RETRANSMIT
            NETLOG4("%s: so %"PRIxPTR" -- retransmit, buffered %d data", __FUNCTION__,
                    (uintptr_t) so, size);
#endif
        }

        if (so->chr_win >= size)
            so->chr_win -= size;
        else
            so->chr_win = 0;

        goto out;
    }

    if (so->type == IPPROTO_UDP) {
        udp_respond(so, data, size);

        goto out;
    }

out:
    return;
}

void tcpip_win_update(struct ni_socket *so)
{
    if (so->type != IPPROTO_TCP)
        return;
    if (so->state != TS_ESTABLISHED)
        return;
    if (so->snd_win != get_snd_win(so))
        tcp_send(so, TH_ACK, NULL, 0);
}

static int tcp_input(struct nickel *ni, struct ip *ip, const uint8_t *pkt, size_t len,
        uint32_t saddr, uint32_t daddr)
{
    int ret = -1;
    struct tcp *tcp;
    struct ni_socket *so = NULL;
    size_t doff, s;
    uint32_t seq_off = 0;
    bool q_buff_change = false, q_send_ack = false, q_send_rst = false;
    bool ack_ok = false, ack_all_ok = false;
    int64_t now;

    tcp = (struct tcp *) pkt;
    if (len < sizeof(*tcp))
        goto out;
    doff = (size_t) (tcp->th_off) << 2;
    if (doff < sizeof(*tcp) || doff > len)
        goto out;

    now = get_clock_ms(vm_clock);

    if (!ni->ping_sent_ts) {
        ni->ping_sent_ts = now;
        icmp_ping_probe(ni);
    }

    so = find_socket_tcp(ni, saddr, tcp->th_sport, daddr, tcp->th_dport);
    if (!so) {
        CharDriverState *chr;

        if ((tcp->th_flags & (TH_SYN | TH_FIN | TH_RST | TH_URG | TH_ACK)) !=  TH_SYN)
           goto close_rst;

        /* access control */
        if (ni->ac_enabled) {
            struct sockaddr_in sa, da;

            sa.sin_addr.s_addr = saddr;
            sa.sin_port = tcp->th_sport;
            da.sin_addr.s_addr = daddr;
            da.sin_port = tcp->th_dport;

            if (ac_tcp_input_syn(ni, sa, da) < 0) {
                struct lava_event *lv;

                lv = lava_event_create(ni, sa, da, true);
                if (lv) {
                    lava_event_set_denied(lv);
                    lava_event_complete(lv, true);
                }
                goto close_rst;
            }
        }

        so = socket_create(ni, IPPROTO_TCP, true);
        if (!so)
            goto close_rst;
        so->flags |= TF_INPUT;

        so->ni = ni;
        so->faddr.sin_addr.s_addr = daddr;
        so->gaddr.sin_addr.s_addr = saddr;
        so->gaddr.sin_port = tcp->th_sport;
        so->faddr.sin_port = tcp->th_dport;
        so->snd_iss = get_iss();
        so->snd_win = MAX_16_WIN;
        so->rcv_mss = 1460;

        // TCP options for SYN
        s = (size_t) (tcp->th_off << 2);
        s -= sizeof(*tcp);
        if (s > 0) {
            uint16_t mss = 0;
            int win_shift = -1;

            tcp_get_options((uint8_t *) (tcp + 1), s, &mss, &win_shift);

            if (mss)
                so->rcv_mss = mss;
            if (!so->ni->tcp_disable_window_scale && win_shift >= 0) {
                so->rcv_win_shift = win_shift;
                so->g_use_win_scaling = 1;
            }
        }

        so->lv = lava_event_create(so->ni, so->gaddr, so->faddr, true);

        so->flags &= ~TF_NAV;
        so->flags |= TF_CONNECTING;
        chr = ni_tcp_connect(ni, so->gaddr, so->faddr, so);
        if ((so->flags & TF_NAV))
            atomic_inc(&so->ni->number_tcp_nav_sockets);
        if (!chr)
            goto close_rst;
        so->chr = chr;

        /* SYN RECVD */
        so->state = TS_SYN_RECVD;
        so->ack_1_ts = now;
        so->rcv_iss = NI_NTOHL(tcp->th_seq);
        so->rcv_off_ack = 1;
        so->rcv_win = NI_NTOHS(tcp->th_win);
        if (so->g_use_win_scaling)
            so->snd_win_shift = SND_WIN_SHIFT;
        if (so->chr)
            so->snd_win = qemu_chr_can_write(so->chr);
    }
    ret = 0;
    so->flags |= TF_INPUT;
    if (IS_DEL(so))
        goto out;

    if (so->state == TS_CLOSED)
        goto out;

    if (so->state == TS_SYN_RECVD && (so->flags & TF_CONNECTING))
        goto out;

    if ((so->flags & TF_RST_PENDING))
        goto close_rst;

    if (so->state == TS_SYN_SENT) {
        assert((so->flags & TF_HOSTFWD));
        assert(so->fwd_timer);

        /* retrial RST */
        if ((tcp->th_flags & TH_RST) && (tcp->th_flags & TH_ACK)) {

            if (((uint32_t) NI_NTOHL(tcp->th_ack)) != so->snd_iss + 1) {
                NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- strange, "
                        "received RST but wrong ack %u %u, TCP flags %x. accept it though.",
                        __FUNCTION__,
                        (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                        inet_ntoa(so->faddr.sin_addr),
                        NI_NTOHS(so->faddr.sin_port),
                        NI_NTOHS(ip->ip_id),
                        ni->g_last_ip,
                        (unsigned int) NI_NTOHL(tcp->th_ack),
                        (unsigned int) so->snd_iss + 1, (unsigned) tcp->th_flags);
            }

            so->state = TS_CLOSED;
            if ((so->flags & TF_CLOSERETRY) && so->fwd_timer) {
                free_timer(so->fwd_timer);
                so->fwd_timer = NULL;
            }
            if (so->chr)
                qemu_chr_send_event(so->chr, CHR_EVENT_NI_REFUSED);

            goto out;
        }

        if ((tcp->th_flags & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK))
            goto out;

        /* SYN ACK received */
        if (NI_NTOHL(tcp->th_ack) != so->snd_iss + so->snd_off_nxt)
            goto out;

        // TCP options
        s = (size_t) (tcp->th_off << 2);
        s -= sizeof(*tcp);
        if (s > 0) {
            uint16_t mss = 0;
            int win_shift = -1;
            tcp_get_options((uint8_t *) (tcp + 1), s, &mss, &win_shift);

            if (mss)
                so->rcv_mss = mss;
            if (!so->ni->tcp_disable_window_scale && win_shift >= 0) {
                so->rcv_win_shift = win_shift;
                so->g_use_win_scaling = 1;
            }
        }

        so->rcv_iss = NI_NTOHL(tcp->th_seq);
        /* since is a SYN packet, no window scaling yet */
        so->rcv_win = (uint32_t) NI_NTOHS(tcp->th_win);
        if (so->g_use_win_scaling)
            so->snd_win_shift = SND_WIN_SHIFT;
        s = 0;
        if (so->chr)
            s = qemu_chr_can_write(so->chr);
        so->snd_win = s;

        so->snd_off_ack = (uint32_t) NI_NTOHL(tcp->th_ack) - so->snd_iss;
        so->rcv_off_ack = 1;
        tcp_send(so, TH_ACK, NULL, 0);
        so->state = TS_ESTABLISHED;
        NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR
                " (G:%hu -> %s:%hu) ip_id %hu/%hu rwin %u rwshift %d mss %u "
                "swin %u swshift %d mss %u "
                "-- connection established",
                __FUNCTION__,
                (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                inet_ntoa(so->faddr.sin_addr),
                NI_NTOHS(so->faddr.sin_port),
                NI_NTOHS(ip->ip_id),
                ni->g_last_ip,
                (unsigned int) so->rcv_win,
                (int) (so->g_use_win_scaling ? so->rcv_win_shift : -1),
                (unsigned int) so->rcv_mss,
                (unsigned int) so->snd_win,
                (int) (so->g_use_win_scaling ? so->snd_win_shift : -1),
                (unsigned int) so->snd_mss);
        q_buff_change = true;

        so->ni->number_tcp_established++;
        if (so->lv)
            lava_event_set_established(so->lv, so->ni->number_tcp_established);

        if (so->fwd_timer) {
            free_timer(so->fwd_timer);
            so->fwd_timer = NULL;
        }

        goto out;
    }

    /* XXX check seq_no here ! */
    if ((tcp->th_flags & TH_RST) || so->state == TS_CONN_RST) {
        if (so->state == TS_ESTABLISHED)
            NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- RST received, "
                    "TCP flags %x",
                    __FUNCTION__,
                    (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                    inet_ntoa(so->faddr.sin_addr),
                    NI_NTOHS(so->faddr.sin_port),
                    NI_NTOHS(ip->ip_id),
                    ni->g_last_ip, (unsigned) tcp->th_flags);

        goto close_rst;
    }

    if (so->state == TS_SYN_RECVD) {
        if (doff != len) /* data in SYN packet not allowed !*/ {
            NETLOG("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- strange, "
                    "data in SYN packet ? len %u TCP flags %x. RST connection.",
                    __FUNCTION__,
                    (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                    inet_ntoa(so->faddr.sin_addr),
                    NI_NTOHS(ip->ip_id),
                    ni->g_last_ip,
                    NI_NTOHS(so->faddr.sin_port),
                    (unsigned int) (len - doff), (unsigned) tcp->th_flags);
            goto close_rst;
        }
        tcp_send(so, TH_SYN|TH_ACK, NULL, 0);
        so->snd_off_nxt = 1;
        so->state = TS_SYNACK_SENT;
        goto out;
    }

    if (so->state == TS_SYNACK_SENT) {
        if (!(tcp->th_flags & TH_ACK))
            goto out;
        if (NI_NTOHL(tcp->th_ack) != so->snd_iss + so->snd_off_nxt)
            goto out;
        so->rcv_win = get_rcv_win(so, tcp);
        so->state = TS_ESTABLISHED;
        NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR
                " (G:%hu -> %s:%hu) ip_id %hu/%hu win %u wshift %d mss %u -- "
                "connection established %lu ms",
                __FUNCTION__,
                (uintptr_t) so, (uintptr_t) so->chr, NI_NTOHS(so->gaddr.sin_port),
                inet_ntoa(so->faddr.sin_addr),
                NI_NTOHS(so->faddr.sin_port),
                NI_NTOHS(ip->ip_id),
                ni->g_last_ip,
                (unsigned int) so->rcv_win,
                (int) (so->g_use_win_scaling ? so->rcv_win_shift : -1),
                (unsigned int) so->rcv_mss, (unsigned long) (now - so->ack_1_ts));
        so->ack_1_ts = 0;
        q_buff_change = true;
        so->ni->number_tcp_established++;
        if (so->lv)
            lava_event_set_established(so->lv, so->ni->number_tcp_established);
    }

    assert(so->state == TS_ESTABLISHED);

    if ((tcp->th_flags & TH_SYN))
        goto out;

    /* treat snd stream, ACK */
    while ((tcp->th_flags & TH_ACK)) {
        bool sack = false;
        uint32_t sack_to = 0;
        uint32_t off_ack = ((uint32_t) NI_NTOHL(tcp->th_ack)) - so->snd_iss;
        uint32_t win = 0;

        if (off_ack - so->snd_off_ack > so->snd_off_nxt - so->snd_off_ack) {
            NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- strange, "
                    "out of order ACK? %u %u %u",
                    __FUNCTION__,
                    (uintptr_t) so, (uintptr_t) so->chr, NI_NTOHS(so->gaddr.sin_port),
                    inet_ntoa(so->faddr.sin_addr),
                    NI_NTOHS(so->faddr.sin_port),
                    NI_NTOHS(ip->ip_id),
                    ni->g_last_ip,
                    (unsigned int) off_ack,
                    (unsigned int) so->snd_off_ack,
                    (unsigned int) so->snd_off_nxt);
            break;
        }
        ack_ok = true;
        win = get_rcv_win(so, tcp);
        so->win_state = WST_ACKED;
        if (ack_ok && off_ack == so->snd_off_nxt)
            ack_all_ok = true;

        if ((so->flags & TF_FIN_SENT) && ack_all_ok)
            so->flags |= TF_FIN_ACKED;

        packets_acked(so, off_ack);
        /* check SAck for need to retransmit */
        {
            size_t s = (size_t) (tcp->th_off << 2) - sizeof(*tcp);
            uint8_t *po = (uint8_t *) (tcp + 1), ol = 0, ot = 0;

            while (s-- > 0) {
                uint8_t c = *po++;

                if (ol) {
                    ol--;
                    if (!ol)
                        ot = 0;
                    continue;
                }

                if (ot == 0 || ot == 1) {
                    ot = c;
                    continue;
                }

                ol = c;
                if (ol < 2) {
                    NETLOG("%s: so %"PRIxPTR" error on parsing TCP options", __FUNCTION__,
                           (uintptr_t) so);
                    break;
                }
                ol -= 2;
                if (ol == 0)
                    ot = 0;

                if (ot == 0x05) { // SAck
                    if ((size_t) ol > s) {
                        NETLOG("%s: so %"PRIxPTR" error on parsing SAck option", __FUNCTION__,
                               (uintptr_t) so);
                        break;
                    }
                    if (ol >= 4 + 4) {
                        sack = true;
                        sack_to = sack_received(so, off_ack, po, (size_t) ol);
                        if (!RLIST_EMPTY(&so->sent_q, so_entry))
                            so->flags |= TF_RETRANSMISSION;
                    }
                    break;
                }
            }
        }

        if ((so->flags & TF_RETRANSMISSION)) {
            if (!RLIST_EMPTY(&so->sent_q, so_entry)) {
                if (sack && ((sack_to == off_ack) || SEQ_CMP(sack_to, off_ack) < 0))
                    sack = false;
                retransmit_queue(so, sack, sack_to);
            } else {
                so->flags &= ~TF_RETRANSMISSION;
                if (so->bufd_len)
                    tcp_send_bufd_data(so);
                q_buff_change = true;

#if DEBUG_RETRANSMIT
                NETLOG4("%s: so %"" retransmission off %s", __FUNCTION__, (uintptr_t) so,
                        (so->flags & TF_RETRANSMISSION_RST) ? "RST" :
                        ((so->flags & TF_RETRANSMISSION_FIN) ? "FIN" :
                        "-"));
#endif

                if ((so->flags & TF_RETRANSMISSION_FIN)) {
                    so->flags &= ~TF_RETRANSMISSION_FIN;

                    NETLOG4("%s: so %"PRIxPTR" retransmission off FIN %s", __FUNCTION__,
                            (uintptr_t) so, (so->flags & TF_RETRANSMISSION_RST) ? "(RST)" : "");

                    if (!(so->flags & TF_FIN_SENT)) {
                        tcp_send(so, TH_FIN|TH_ACK, NULL, 0);
                        so->snd_off_nxt += 1;
                        so->flags |= TF_FIN_SENT;
                    }
                    if ((so->flags & TF_RETRANSMISSION_RST))
                        tcp_send(so, TH_RST|TH_ACK, NULL, 0);
                    so->flags &= ~TF_RETRANSMISSION_RST;

                    goto out;
                }

            }
        }
        /* hmm, we do not believe they would shrink the window without
         * us having sent some more data ;-) */
        if (off_ack == so->snd_off_ack && win < so->rcv_win) {
            NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- strange, "
                    "shrinking window from %u to %u, we don't believe that",
                    __FUNCTION__,
                    (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                    inet_ntoa(so->faddr.sin_addr),
                    NI_NTOHS(so->faddr.sin_port),
                    NI_NTOHS(ip->ip_id),
                    (unsigned short) ni->g_last_ip,
                    (unsigned int) so->rcv_win, (unsigned int) win);
            break;
        }

        // this is the latest correct window size, update
        so->snd_off_ack = off_ack;
        so->rcv_win = win;
        if (so->zero_win && so->rcv_win > 0 && !(so->flags & TF_RETRANSMISSION)) {
            so->zero_win = 0;
            so->poll_eof_ts = 0;
            if (so->chr)
                q_buff_change = true;
        }

        break;
    }

    /* treat recv stream */
    seq_off = ((uint32_t) NI_NTOHL(tcp->th_seq) - so->rcv_iss);
    do {
        if (SEQ_CMP(seq_off, so->rcv_off_ack) < 0) {
            q_send_ack = true;
            if (seq_off == so->rcv_off_ack - 1) {
                NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR
                        " (G:%hu -> %s:%hu) ip_id %hu/%hu -- Keep-Alive packet? "
                        "seq_off %u rcv_off_ack %u win %u len %u",
                        __FUNCTION__,
                        (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                        inet_ntoa(so->faddr.sin_addr),
                        NI_NTOHS(so->faddr.sin_port),
                        NI_NTOHS(ip->ip_id),
                        ni->g_last_ip,
                        (unsigned int) seq_off,
                        (unsigned int) so->rcv_off_ack,
                        (unsigned int) so->snd_win,
                        (unsigned int) (len - doff));

                break;
            }

            NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- strange, "
                    "seq_no out of window seq_off %u rcv_off_ack %u win %u",
                    __FUNCTION__,
                    (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                    inet_ntoa(so->faddr.sin_addr),
                    NI_NTOHS(so->faddr.sin_port),
                    NI_NTOHS(ip->ip_id),
                    ni->g_last_ip,
                    (unsigned int) seq_off,
                    (unsigned int) so->rcv_off_ack,
                    (unsigned int) so->snd_win);
            break;
        }
        /* grab the data */
        if (doff < len) {
            int sent = 0;

            q_send_ack = true;
            if (seq_off + (len - doff) - so->rcv_off_ack > so->snd_win) {
                NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- strange, "
                        "seq_no out of window, seq_off %u rcv_off_ack %u "
                        "len %u win %u",
                        __FUNCTION__,
                        (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                        inet_ntoa(so->faddr.sin_addr),
                        NI_NTOHS(so->faddr.sin_port),
                        NI_NTOHS(ip->ip_id),
                        ni->g_last_ip,
                        (unsigned int) seq_off,
                        (unsigned int) so->rcv_off_ack,
                        (unsigned int) (len - doff),
                        (unsigned int) so->snd_win);
                break;
            }
            if (seq_off != so->rcv_off_ack) {
                NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- strange, "
                        "seq_no out of order?, seq_off %u rcv_off_ack %u "
                        "len %u win %u",
                        __FUNCTION__,
                        (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                        inet_ntoa(so->faddr.sin_addr),
                        NI_NTOHS(so->faddr.sin_port),
                        NI_NTOHS(ip->ip_id),
                        ni->g_last_ip,
                        (unsigned int) seq_off,
                        (unsigned int) so->rcv_off_ack,
                        (unsigned int) (len - doff),
                        (unsigned int) so->snd_win);

                break;
            }
            if ((so->flags & TF_NAV)) {
                so->ni->tcpip_last_tcp_data = now;
                atomic_add(&so->ni->tcp_nav_tx, (uint32_t) (len - doff));
            }
            if (so->chr)
                sent = qemu_chr_write(so->chr, pkt + doff, len - doff);
            if (sent != len - doff) {
                NETLOG2("%s: s:%"PRIxPTR" c:%"PRIxPTR
                        " (G:%hu -> %s:%hu) ip_id %hu/%hu -- consumed less, "
                        "G would need to re-transmit ! "
                        " len %u consumed %u snd_win %u/%u/%u",
                        __FUNCTION__,
                        (uintptr_t)so, (uintptr_t) so->chr, NI_NTOHS(so->gaddr.sin_port),
                        inet_ntoa(so->faddr.sin_addr),
                        NI_NTOHS(so->faddr.sin_port),
                        NI_NTOHS(ip->ip_id),
                        ni->g_last_ip,
                        (unsigned int) (len - doff),
                        (unsigned int) sent,
                        (unsigned int) so->snd_win,
                        (unsigned int) so->snd_win,
                        (unsigned int) get_snd_win(so));
            }
            if (sent > 0) {
                int64_t delta = 0;

                so->rcv_off_ack += (uint32_t) sent;

                if (so->ack_1_ts > 0 && so->ack_2_ts > 0) {
                    delta = so->ack_2_ts - so->ack_1_ts;
                    if (!delta)
                        delta++;
                }
                so->ack_1_ts = now;
                so->ack_2_ts = 0;
                if (sent == len - doff && !(so->flags & TF_DELAYED_ACK) &&
                        delta && delta < DELAY_ACK_MAX_MS) {

                    so->flags |= TF_DELAYED_ACK;
                    so->delay_ac_ts = now + DELAY_ACK_MAX_MS;
                    q_send_ack = false;
                }
            }
        }
    } while (1 == 0);

    if ((tcp->th_flags & TH_FIN)) {
        NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) ip_id %hu/%hu -- FIN received, "
                "TCP flags %x",
                __FUNCTION__,
                (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                inet_ntoa(so->faddr.sin_addr),
                NI_NTOHS(so->faddr.sin_port),
                NI_NTOHS(ip->ip_id),
                ni->g_last_ip, (unsigned) tcp->th_flags);
        q_send_ack = true;
        if ((so->flags & TF_FIN_RECV))
            goto out;

        so->flags |= TF_FIN_RECV;
        so->rcv_off_ack += 1;

        if (so->chr)
            send_close(so, false);
    }

out:
    if (q_send_ack && so && !IS_DEL(so))
        tcp_send(so, TH_ACK, NULL, 0);

    if (so && (so->flags & TF_FIN_ACKED) && (so->flags & TF_FIN_RECV)) {
        if (!(so->flags & TF_CLOSED) && so->chr)
            send_close(so, false);
        else
            so = socket_free(so);
    }

    if (q_buff_change && so && !IS_DEL(so) && so->chr)
        qemu_chr_send_event(so->chr, CHR_EVENT_BUFFER_CHANGE);

    if (q_send_rst && so && !IS_DEL(so))
        tcp_rst(so);

    /* last */
    if (so)
        so->flags &= ~TF_INPUT;
    if (so && IS_DEL(so))
        so = socket_free(so);

    return ret;
close_rst:
    if (so)
        tcp_close_socket(so, true);
    else
        tcp_respond_rst(ni, tcp, saddr, daddr);
    ret = 0;
    goto out;
}

static int icmp_input(struct nickel *ni, const uint8_t *i_pkt, size_t i_len,
        uint32_t saddr, uint32_t daddr)
{
    struct icmp *icmp;
    struct buff *bf;
    struct ip *ip;
    size_t pkt_len, l, off, ip_l;
    uint8_t *pkt;

    icmp = (struct icmp *) i_pkt;
    if (i_len < sizeof(*icmp))
        return -1;

    if (daddr != ni->host_addr.s_addr || (icmp->type != ICMP_ECHO &&
        icmp->type != ICMP_ECHOREPLY)) {

        lava_send_icmp(ni, daddr, icmp->type, true); /* always set denied = true for now */
    }

    if (!ni->eth_vm_resolved)
        return 0;

    if (daddr != ni->host_addr.s_addr)
        return 0;

    if (icmp->type == ICMP_ECHOREPLY)
        return icmp_echoreply(ni, i_pkt, i_len, saddr, daddr);

    if (icmp->type != ICMP_ECHO)
        return 0;

    off = 0;
    pkt_len = ETH_HLEN + sizeof(struct ip) + i_len;
    bf = ni_netbuff(ni, pkt_len);
    if (!bf)
        return -1;
    pkt = bf->m;

    l = ETH_HLEN;
    eth_write(ni, pkt + off);
    pkt_len -= l;
    off += l;

    ip = (struct ip *) (pkt + off);
    ip_l = pkt_len;
    l = sizeof(*ip);
    ip_write(ni, IPPROTO_ICMP, daddr, saddr, ip, pkt_len);
    pkt_len -= l;
    off += l;

    assert(pkt_len == i_len);
    memcpy(pkt + off, (uint8_t *) i_pkt, pkt_len);
    icmp = (struct icmp *) (pkt + off);

    icmp->type = ICMP_ECHOREPLY;
    icmp->cksum = 0;
    icmp->cksum = checksum(0, pkt + off, pkt_len);
    ip_checksum(ip, ip_l);

    ni_buff_output(ni, bf);
    return 0;
}

static struct ni_socket *
udp_socket_create(struct nickel *ni, struct udp *udp, uint32_t saddr,
        uint32_t daddr)
{
    struct ni_socket *so = NULL;

    so = socket_create(ni, IPPROTO_UDP, true);
    if (!so)
        goto out;
    so->gaddr.sin_addr.s_addr = saddr;
    so->faddr.sin_addr.s_addr = daddr;
    so->gaddr.sin_port = udp->uh_sport;
    so->faddr.sin_port = udp->uh_dport;
out:
    return so;
}


static int udp_input(struct nickel *ni, const uint8_t *pkt, size_t len,
        uint32_t saddr, uint32_t daddr)
{
    int ret = -1;
    struct udp *udp;
    struct ni_socket *so = NULL;
    struct lava_event *lv = NULL;

    if (len < sizeof(*udp))
        goto out;
    udp = (struct udp *) pkt;
    if (NI_NTOHS(udp->uh_ulen) > len)
        goto out;
    so = find_socket_udp(ni, saddr, udp->uh_sport, daddr, udp->uh_dport);
    if (!so) {
        CharDriverState *chr;
        struct sockaddr_in sa, da;

        sa.sin_addr.s_addr = saddr;
        sa.sin_port = udp->uh_sport;
        da.sin_addr.s_addr = daddr;
        da.sin_port = udp->uh_dport;

        lv = lava_event_create(ni, sa, da, false);
        if ((daddr == 0xffffffff || daddr == ni->host_addr.s_addr) && !ni->disable_dhcp &&
            NI_NTOHS(udp->uh_dport) == BOOTP_SERVER) {

            dhcp_input(ni, pkt, len, saddr, daddr);
            goto out;
        }

        if (ni->ac_enabled) {
            if (ac_udp_input(ni, sa, da) < 0) {
                if (lv)
                    lava_event_set_denied(lv);

                goto out;
            }
        }

        so = udp_socket_create(ni, udp, saddr, daddr);
        if (!so)
            goto out;

        if (lv)
            so->lv = lv;
        else
            so->lv = lava_event_create(so->ni, so->gaddr, so->faddr, false);
        lv = NULL;

        so->flags |= TF_INPUT;
        chr = ni_udp_open(ni, so->gaddr, so->faddr, so);
        if (!chr) {
            so->flags |= TF_CLOSED;
            so = socket_free(so);
            goto out;
        }
        so->chr = chr;
    }
    so->flags |= TF_INPUT;

    pkt += sizeof(*udp);
    len = NI_NTOHS(udp->uh_ulen) - sizeof(*udp);
    ret = 0;
    if (so->chr)
        ret = qemu_chr_write(so->chr, pkt, len);
out:
    if (lv) {
        lava_event_complete(lv, true);
        lv = NULL;
    }
    if (so && so->lv)
        lava_event_complete(so->lv, false);
    if (so)
        so->flags &= ~TF_INPUT;
    if (so && IS_DEL(so))
        so = socket_free(so);
    return ret;
}

void udp_send(struct nickel *ni, struct buff *bf, struct sockaddr_in saddr, struct sockaddr_in daddr)
{
    size_t pkt_len, off = 0, l, ip_l;
    uint8_t *pkt;
    struct ip *ip;
    struct udp *udp;

    pkt = bf->m;
    pkt_len = bf->len;

    l = eth_write(ni, pkt + off);
    pkt_len -= l;
    off += l;

    ip = (struct ip *) (pkt + off);
    ip_l = pkt_len;
    l = sizeof(*ip);
    ip_write(ni, IPPROTO_UDP, saddr.sin_addr.s_addr, daddr.sin_addr.s_addr,
            ip, pkt_len);
    pkt_len -= l;
    off += l;

    udp = (struct udp *) (pkt + off);
    udp->uh_sport = saddr.sin_port;
    udp->uh_dport = daddr.sin_port;
    udp->uh_ulen  = NI_HTONS(pkt_len);

    udp_checksum(ip, udp, pkt_len);
    ip_checksum(ip, ip_l);

    buff_output(ni, bf);
}

static void udp_respond(struct ni_socket *so, const uint8_t *data, size_t len)
{
    struct buff *bf;
    size_t pkt_len;
    uint8_t *pkt;

    pkt_len = ETH_HLEN + sizeof(struct ip) + sizeof(struct udp) +
                + len;
    bf = ni_netbuff(so->ni, pkt_len);
    if (!bf)
        return;
    pkt = bf->m;
    if (len)
        memcpy(pkt + ETH_HLEN + sizeof(struct ip) + sizeof(struct udp),
            data, len);
    udp_send(so->ni, bf, so->faddr, so->gaddr);
}

void tcpip_input(struct nickel *ni, const uint8_t *pkt, size_t len)
{
    struct ip *ip;
    size_t hlen, dlen;
    int proto;

    if (len <= ETH_HLEN)
        goto out;

    if (memcmp(pkt + ETH_ALEN, ni->eth_nickel, ETH_ALEN) == 0)
        goto out;
    if (!ni->eth_vm_resolved && memcmp(pkt + ETH_ALEN, ni->eth_vm, ETH_ALEN)) {
        struct buff *bf, *bf_n;

        memcpy(ni->eth_vm, pkt + ETH_ALEN, ETH_ALEN);
        ni->eth_vm_resolved = 1;

        RLIST_FOREACH_SAFE(bf, &ni->noarp_output_list, entry, bf_n) {
            struct ethhdr *eh;

            RLIST_REMOVE(bf, entry);
            eh = (struct ethhdr *) (bf->m);
            if (bf->len >= ETH_HLEN)
                memcpy(&eh->h_dest, ni->eth_vm, ETH_ALEN);
            ni_buff_output(ni, bf);
        }
    }

    proto = NI_NTOHS(*(uint16_t *)(pkt + 12));
    if (proto == ETH_P_ARP) {
        arp_input(ni, pkt, len);
        return;
    }
    if (proto != ETH_P_IP)
        goto out;
    pkt += ETH_HLEN;
    len -= ETH_HLEN;

    ip = (struct ip *) pkt;
    if (sizeof(*ip) > len)
        goto out;
    if (ip->ip_v != IP_V4)
        goto out;
    hlen = ip->ip_hl << 2;
    if (hlen < sizeof(*ip) || len < hlen)
        goto out;

    dlen = NI_NTOHS(ip->ip_len);
    if (dlen < hlen || len < dlen)
        goto out;
    dlen -= hlen;

    proto = ip->ip_p;
    if (proto == IPPROTO_TCP)
        tcp_input(ni, ip, pkt + hlen, dlen, ip->ip_src, ip->ip_dst);
    else if (proto == IPPROTO_UDP)
        udp_input(ni, pkt + hlen, dlen, ip->ip_src, ip->ip_dst);
    else if (proto == IPPROTO_ICMP)
        icmp_input(ni, pkt + hlen, dlen, ip->ip_src, ip->ip_dst);
    ni->g_last_ip = NI_NTOHS(ip->ip_id);
out:
    return;
}

static void tcp_socket_save(QEMUFile *f, struct ni_socket *so, uint32_t *n_sbf, uint32_t *n_lv)
{
    qemu_put_byte(f, so->state);
    qemu_put_be32(f, so->flags);

    qemu_put_be32(f, (uint32_t) sizeof(so->faddr));
    qemu_put_buffer(f, (uint8_t *) &so->faddr, sizeof(so->faddr));
    qemu_put_be32(f, (uint32_t) sizeof(so->gaddr));
    qemu_put_buffer(f, (uint8_t *) &so->gaddr, sizeof(so->gaddr));

    qemu_put_be32(f, so->fwd_n);
    qemu_put_byte(f, so->zero_win);
    qemu_put_byte(f, so->win_state);
    qemu_put_be32(f, so->rcv_iss);
    qemu_put_be32(f, so->rcv_off_ack);
    qemu_put_be32(f, so->snd_iss);
    qemu_put_be32(f, so->snd_off_nxt);
    qemu_put_be32(f, so->snd_off_ack);
    qemu_put_be16(f, so->snd_mss);
    qemu_put_be32(f, so->snd_win);
    qemu_put_be16(f, so->snd_win_shift);
    qemu_put_be32(f, so->rcv_win);
    qemu_put_be16(f, so->rcv_win_shift);
    qemu_put_be16(f, so->rcv_mss);
    qemu_put_byte(f, so->g_use_win_scaling);

    qemu_put_be32(f, so->chr_win);
    qemu_put_be32(f, (uint32_t) so->bufd_len);
    if (so->bufd_len) {
        assert(so->bufd_data);
        qemu_put_buffer(f, so->bufd_data, (uint32_t) so->bufd_len);
    }

    if (!(so->flags & (TF_CLOSED | TF_RST_PENDING))) {
        struct buff *bf;

        RLIST_FOREACH(bf, &so->sent_q, so_entry) {
            qemu_put_byte(f, 1);
            qemu_put_be32(f, (uint32_t) bf->len);
            qemu_put_buffer(f, bf->m, (uint32_t) bf->len);
            (*n_sbf)++;
        }
    }
    qemu_put_byte(f, 0); /* marker end retransmission queue */

    if (so->chr && so->chr->chr_save)
        so->chr->chr_save(so->chr, f);
    /* put save data end marker */
    qemu_put_be32(f, 0);

    if (so->lv) {
        lava_event_save_and_clear(f, so->lv);
        so->lv = NULL;
        if (n_lv)
            (*n_lv)++;
    }
    qemu_put_be32(f, 0); /* end lava marker */
}

static int tcp_socket_load(QEMUFile *f, struct nickel *ni, int version_id, uint32_t *n_sbf,
        uint32_t *n_lv)
{
    int err = 0;
    struct ni_socket *so, _so;
    uint32_t l;
    bool skip_so = false;

    so = socket_create(ni, IPPROTO_TCP, false);
    if (!so) {
        err = -1;
        warnx("%s: malloc failure", __FUNCTION__);
        so = &_so;
    }

    so->state = qemu_get_byte(f);
    so->flags = qemu_get_be32(f);
    so->flags |= TF_INPUT;
    if (!(so->flags & TF_VMFWD))
        so->flags |= (TF_RST_PENDING | TF_CLOSED);

    if (so != &_so && (so->flags & TF_NAV))
        atomic_inc(&ni->number_tcp_nav_sockets);

    l = qemu_get_be32(f);
    if (l == sizeof(so->faddr)) {
        qemu_get_buffer(f, (uint8_t *) &so->faddr, l);
    } else {
        err = -1;
        warnx("%s: error on sizeof faddr", __FUNCTION__);
        qemu_file_skip(f, l);
    }
    l = qemu_get_be32(f);
    if (l == sizeof(so->gaddr)) {
        qemu_get_buffer(f, (uint8_t *) &so->gaddr, l);
    } else {
        err = -1;
        warnx("%s: error on sizeof gaddr", __FUNCTION__);
        qemu_file_skip(f, l);
    }

    so->fwd_n = qemu_get_be32(f);
    so->zero_win = qemu_get_byte(f);
    if (version_id >= 15)
        so->win_state = qemu_get_byte(f);
    so->rcv_iss = qemu_get_be32(f);
    so->rcv_off_ack = qemu_get_be32(f);
    so->snd_iss = qemu_get_be32(f);
    so->snd_off_nxt = qemu_get_be32(f);
    so->snd_off_ack = qemu_get_be32(f);
    so->snd_mss = qemu_get_be16(f);
    so->snd_win = qemu_get_be32(f);
    so->snd_win_shift = qemu_get_be16(f);
    so->rcv_win = qemu_get_be32(f);
    so->rcv_win_shift = qemu_get_be16(f);
    so->rcv_mss = qemu_get_be16(f);
    so->g_use_win_scaling = qemu_get_byte(f);

    if (version_id >= 15) {
        int64_t now = get_clock_ms(vm_clock);

        so->chr_win = qemu_get_be32(f);
        so->bufd_len = qemu_get_be32(f);
        if (so->bufd_len) {
            so->bufd_data = ni_priv_malloc(so->bufd_len);
            if (!so->bufd_data) {
                err = -1;
                warnx("%s: malloc failure", __FUNCTION__);
                qemu_file_skip(f, so->bufd_len);
            } else {
                qemu_get_buffer(f, so->bufd_data, so->bufd_len);
            }
        }

        RLIST_INIT(&so->sent_q, so_entry);
        while (qemu_get_byte(f)) {
            struct buff *bf;
            uint32_t len;

            len = qemu_get_be32(f);
            if (err) {
                qemu_file_skip(f, len);
                continue;
            }
            bf = ni_netbuff(ni, len);
            if (!bf) {
                err = -1;
                warnx("%s: malloc failure", __FUNCTION__);
                qemu_file_skip(f, len);
                continue;
            }
            qemu_get_buffer(f, (unsigned char *) bf->m, bf->len);
            bf->ts = now;
            bf->state = BFS_SENT;
            RLIST_INSERT_TAIL(&so->sent_q, bf, so_entry);
            (*n_sbf)++;
        }
    }


    if (!err && !(so->flags & TF_RST_PENDING)) {
        so->chr = ni_tcp_connect(ni, so->gaddr, so->faddr, so);
        if (!so->chr)
            skip_so = true;
    }

    if (so->chr && so->chr->chr_restore) {
        so->chr->chr_restore(so->chr, f);
    } else {
        while ((l = qemu_get_be32(f)))
            qemu_file_skip(f, l);
    }

    if (version_id >= 16) {
        so->lv = lava_event_restore(ni, f);
        if (so->lv && n_lv)
            (*n_lv)++;
    }

    if (!err && !skip_so) {
        NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) f:%d/%x rwin %u rwshift %d mss %u "
                "swin %u swshift %d mss %u snd_off_nxt %u snd_off_ack %u rcv_off_ack %u "
                "-- connection %s",
                __FUNCTION__,
                (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                inet_ntoa(so->faddr.sin_addr),
                NI_NTOHS(so->faddr.sin_port),
                (int) so->state, (unsigned int) so->flags,
                (unsigned int) so->rcv_win,
                (int) (so->g_use_win_scaling ? so->rcv_win_shift : -1),
                (unsigned int) so->rcv_mss,
                (unsigned int) so->snd_win,
                (int) (so->g_use_win_scaling ? so->snd_win_shift : -1),
                (unsigned int) so->snd_mss,
                (unsigned int) so->snd_off_nxt,
                (unsigned int) so->snd_off_ack,
                (unsigned int) so->rcv_off_ack,
                (so->flags & TF_RST_PENDING) ? "RST" : "resumed");

        LIST_INSERT_HEAD(&ni->tcp, so, entry);
        atomic_inc(&ni->number_tcp_sockets);
        atomic_inc(&ni->number_total_tcp_sockets);
    }

    so->flags &= ~TF_INPUT;
    if ((err || skip_so) && so != &_so)
        socket_free(so);

    return err;
}

void tcpip_save(QEMUFile *f, struct nickel *ni)
{
    struct ni_socket *so;
    unsigned long n1, n2;
    uint32_t n_sbf = 0, n_lv = 0;

    NETLOG("%s: saving tcp state", __FUNCTION__);
    /* save gobal vars */
    qemu_put_be16(f, ni->ip_id);
    qemu_put_be16(f, ni->tcp_last_free_port);
    qemu_put_be32(f, ni->number_tcp_established);

    n1 = n2 = 0;
    LIST_FOREACH(so, &ni->tcp, entry) {
        n1++;
        if (so->state != TS_ESTABLISHED)
            continue;

        n2++;
        qemu_put_byte(f, 1); /* is a socket */
        tcp_socket_save(f, so, &n_sbf, &n_lv);
    }
    qemu_put_byte(f, 0); /* end of sockets */
    NETLOG("%s: saved %lu of %lu tcp sockets", __FUNCTION__, n2, n1);
    if (n_sbf)
        NETLOG("%s: %u retransmission buffs saved", __FUNCTION__, (unsigned int) n_sbf);
    if (n_lv)
        NETLOG("%s: %u lava sockets saved", __FUNCTION__, (unsigned int) n_lv);
}

int tcpip_load(QEMUFile *f, struct nickel *ni, int version_id)
{
    int ret = 0;
    unsigned long n = 0;
    uint32_t n_sbf = 0, n_lv = 0;

    ni->ip_id = qemu_get_be16(f);
    NETLOG("%s: loading tcp state, ip_id %hu", __FUNCTION__, ni->ip_id);
    if (version_id >= 14) {
        ni->tcp_last_free_port = qemu_get_be16(f);
        NETLOG("%s: last free port %hu", __FUNCTION__, ni->tcp_last_free_port);
    }

    if (version_id >= 16) {
        ni->number_tcp_established = qemu_get_be32(f);
        NETLOG("%s: number established TCP connections %u", __FUNCTION__,
                (unsigned int) ni->number_tcp_established);
    }

    /* sockets */
    while (qemu_get_byte(f)) {
        if (tcp_socket_load(f, ni, version_id, &n_sbf, &n_lv) < 0) {
            warnx("%s: error on tcp_socket_load!", __FUNCTION__);
            ret = -1;
        } else {
            n++;
        }
    }

    NETLOG("%s: %lu tcp sockets loaded", __FUNCTION__, n);
    if (n_sbf)
        NETLOG("%s: %u retransmission buffs loaded", __FUNCTION__, (unsigned int) n_sbf);
    if (n_lv)
        NETLOG("%s: %u lava sokets loaded", __FUNCTION__, (unsigned int) n_lv);

    return ret;
}

void tcpip_prepare(struct nickel *ni, int *timeout)
{
    if (!ni->vm_paused)
        tcpip_timer(ni, get_clock_ms(vm_clock), timeout);
    lava_timer(ni, get_clock_ms(rt_clock));
}

void tcpip_init(struct nickel *ni)
{
    ni->tcp_free_port_base = 20000;
    ni->tcp_free_port_end = 40000;
    ni->tcp_last_free_port = ni->tcp_free_port_base + 1;

    ni_schedule_bh_permanent(ni, socket_gc, ni);
}

void tcpip_post_init(struct nickel *ni)
{
    unsigned int mtu = NI_DEFAULT_MTU;

#if defined(_WIN32)
    extern unsigned slirp_mru, slirp_mtu;

    mtu = MIN(slirp_mtu, slirp_mru);
    mtu = MIN(mtu, NI_MAX_MTU);
#endif

    ni->mtu = mtu;
    assert(ni->mtu > NI_TCPIP_HLEN);
    ni->tcp_mss = (uint16_t) ((ni->mtu - NI_TCPIP_HLEN) & 0xFFFF);
    NETLOG("%s: Nickel MTU set at %u, TCP MSS %hu", __FUNCTION__,
            (unsigned int) ni->mtu, ni->tcp_mss);
}

void tcpip_flush(struct nickel *ni)
{
    struct ni_socket *so;

    LIST_FOREACH(so, &ni->tcp, entry) {
        if (so->lv)
            lava_event_complete(so->lv, false);
    }

    LIST_FOREACH(so, &ni->udp, entry) {
        if (so->lv)
            lava_event_complete(so->lv, false);
    }
}

void tcpip_exit(struct nickel *ni)
{
    struct ni_socket *so;

    LIST_FOREACH(so, &ni->tcp, entry) {
        if (so->lv)
            tcpip_lava_submit(so);
        if (so->snd_off_nxt != so->snd_off_ack &&
           (so->state == TS_ESTABLISHED || so->state == TS_CONN_RST)) {

            NETLOG4("%s: s:%"PRIxPTR" c:%"PRIxPTR" (G:%hu -> %s:%hu) -- snd ack mismatch! "
                    "iss %u rcv_win %u/%d snd_off_nxt %u snd_off_ack %u",
                    __FUNCTION__,
                    (uintptr_t)so, (uintptr_t)so->chr, NI_NTOHS(so->gaddr.sin_port),
                    inet_ntoa(so->faddr.sin_addr),
                    NI_NTOHS(so->faddr.sin_port),
                    (unsigned int) so->snd_iss,
                    (unsigned int) so->rcv_win,
                    (int) (so->g_use_win_scaling ? so->rcv_win_shift : -1),
                    (unsigned int) so->snd_off_nxt,
                    (unsigned int) so->snd_off_ack);
        }
    }

    LIST_FOREACH(so, &ni->udp, entry) {
        if (so->lv)
            tcpip_lava_submit(so);
    }
}
