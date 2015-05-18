/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/ioh.h>

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define _POSIX
#endif
#include <time.h>
#include <sys/time.h>

#include <dm/async-op.h>
#include <dm/char.h>
#if NEXT_STAGE
#include <dm/monitor.h>
#endif
#include <dm/ns.h>
#include <dm/opts.h>
#include <dm/qemu_glue.h>
#include <dm/qemu/net.h>
#include <dm/queue2.h>
#include <dm/base64.h>
#include <dm/priv-heap.h>

#include <dm/libnickel.h>
#include "buff.h"
#include "nickel.h"
#include "service.h"
#include "tcpip.h"
#include "access-control.h"
#include "lava.h"
#include "log.h"
#include "rpc.h"
#include "socket.h"
#include "dns/dns-fake.h"

#if defined(__APPLE__)
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

#include <dm/control.h>
#include <sys/time.h>
#if defined(__APPLE__)
#include <unistd.h>
#endif

#include "proto.h"

int ni_log_level = 1;

static heap_t ni_priv_heap;
static unsigned int ni_priv_heap_err;
unsigned slirp_mru = NI_DEFAULT_MTU, slirp_mtu = NI_DEFAULT_MTU;

#define MAX_ALLOC_LEN    ((size_t) (((size_t)(-1)) >> 1))
#define FRAME_ALIGN_MASK       (4 - 1)
#define DEFAULT_TIMEOUT_MS 600000 /* 10 min */
#define LOOP_DELAY_WARN 800 /* ms */

#if defined(NICKEL_THREADED)
static void queue_input(struct nickel *ni, struct buff *bf);
#endif
static void output(struct nickel *ni, struct buff *bf0, bool send);

/* emulated hosts use the MAC addr 52:55:IP:IP:IP:IP */
static const uint8_t special_ethaddr[ETH_ALEN] = {
    0x52, 0x55, 0x00, 0x00, 0x00, 0x00
};

struct nc_nickel_s {
    VLANClientState nc;
    QTAILQ_ENTRY(nc_nickel_s) entry;
    struct nickel *ni;
    struct nickel _ni;
    uint8_t padding[16];
};

static int get_str_sep(char *buf, int buf_size, const char **pp, int sep)
{
    const char *p, *p1;
    int len;
    p = *pp;
    p1 = strchr(p, sep);
    if (!p1)
        return -1;
    len = p1 - p;
    p1++;
    if (buf_size > 0) {
        if (len > buf_size - 1)
            len = buf_size - 1;
        memcpy(buf, p, len);
        buf[len] = '\0';
    }
    *pp = p1;
    return 0;
}

static void lock_outq(struct nickel *ni)
{
#if defined(NICKEL_THREADED)
    critical_section_enter(&ni->queue_out_mx);
#endif
}

static void unlock_outq(struct nickel *ni)
{
#if defined(NICKEL_THREADED)
    critical_section_leave(&ni->queue_out_mx);
#endif
}

static QTAILQ_HEAD(nc_list, nc_nickel_s) nc_list =
    QTAILQ_HEAD_INITIALIZER(nc_list);

int pcap_user_enable = 0;
static void pcap_usertrig_cb(void *opaque);

int ni_can_output(struct nickel *ni)
{
    struct nc_nickel_s *snc = (struct nc_nickel_s *) ni->nc_opaque;

    return qemu_can_send_packet(&snc->nc);
}

/* PCAP */
typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        uint32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

static int64_t epoch_ts = 0LL;

static int64_t
get_epoch_ts(void)
{
    int64_t ret, diff = 0LL;
    int i;

    for (i = 0; i < 10; i++) {
        int64_t t1, t2;
        struct timeval tv;

        t1 = get_clock_ns(rt_clock);
        gettimeofday(&tv, NULL);
        t2 = get_clock_ns(rt_clock);
        if (!diff || diff > t2 - t1) {
            diff = t2 - t1;
            ret = CLOCK_BASE * tv.tv_sec + tv.tv_usec * 1000
                - ((t2 + t1) >> 1);
            if (diff < 10000LL)
                break;
        }
    }

    return ret;
}

static int
pcap_fileinit(struct nickel *s)
{
    bool appending = false;
    pcap_hdr_t pcap_gh = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1
    };

    if (s->pcapf)
        return 0;

    if (!s->pcap_fpath)
        return -1;

    appending = (access(s->pcap_fpath, F_OK) != -1);
    s->pcapf = fopen(s->pcap_fpath, appending ? "ab" : "wb");
    debug_printf("%s: pcap file %s\n", __FUNCTION__, s->pcap_fpath);
    if (!s->pcapf) {
        if (!s->pcap_user_enable)
            warnx("%s: cannot create pcap file", __FUNCTION__);
        return -1;
    }

    if (appending) {
        fseek(s->pcapf, 0L, SEEK_END);
        appending = ftell(s->pcapf) != 0L;
    }

    setvbuf(s->pcapf, (char *)NULL, _IOFBF, BUFSIZ);
    if (!appending)
        fwrite((void*)&pcap_gh, sizeof(pcap_gh), 1, s->pcapf);

    return 0;
}

static int pcap_config(struct nickel *s, const yajl_val arg)
{
    int ret = -1;
    uint32_t pcap_user_duration = 0;
    const char *fpath = NULL;
    int user_enable = 0;

    if (YAJL_IS_OBJECT(arg)) {
        int max_len;

        fpath = yajl_object_get_string(arg, "file");
        if (!fpath) {
            warnx("tcpdump map: \"file\" key needs to exist and be a string");
            goto out;
        }
        user_enable = yajl_object_get_bool_default(arg, "user-capture-enable", 0);
        pcap_user_duration = yajl_object_get_integer_default(arg, "start-capture-sec", 0);
        max_len = yajl_object_get_integer_default(arg, "max-packet-len", -1);
        if (max_len <= 0) {
            warnx("max-packet-len wrong value, needs to be > 0 integer");
        } else {
            s->pcap_max_len = max_len;
            NETLOG("pcap: max packet len saved set to %u bytes", s->pcap_max_len);
        }
    } else {
        fpath = YAJL_GET_STRING(arg);
    }

    if (!fpath) {
        warnx("tcpdump arg wrong type: expect string (or map)");
        goto out;
    }

    s->pcap_fpath = strdup(fpath);
    if (!s->pcap_fpath) {
        warnx("malloc failure");
        goto out;
    }
    debug_printf("user_enable %d\n", user_enable);
    if (user_enable) {
        s->pcap_user_enable = 1;
        s->pcap_user_duration = pcap_user_duration;
        pcap_user_enable = 1;
    }

    if (!user_enable && pcap_fileinit(s))
        goto out;
    else if (pcap_user_duration) {
        BH *bh;

        bh = bh_new(pcap_usertrig_cb, NULL);
        if (!bh) {
            warnx("%s: bh_new failure", __FUNCTION__);
            goto out;
        }
        bh_schedule_one_shot(bh);
    }
    ret = 0;
out:
    return ret;
}

int64_t ni_get_pcap_ts(uint32_t *sec, uint32_t *usec)
{
    int64_t now;

    now = get_clock_ns(rt_clock) + epoch_ts;
    if (sec)
        *sec = now / CLOCK_BASE;
    if (usec)
        *usec = (now/1000) % 1000000LL;

    return now;
}

static void
dump_packet(struct nickel *s, const uint8_t *buf, size_t len)
{
    static uint64_t ts = 0;
    pcaprec_hdr_t ph;
    uint64_t now;

    if (!s->pcap_user_duration && !s->pcapf)
        return;
    if (s->pcap_user_duration && !s->pcap_timer)
        return;
    if (s->pcap_user_duration && !s->pcapf && pcap_fileinit(s))
        return;

    now = ni_get_pcap_ts(&ph.ts_sec, &ph.ts_usec);
    ph.incl_len = ph.orig_len = len;
    if (s->pcap_max_len && s->pcap_max_len < len)
        ph.incl_len = s->pcap_max_len;
    fwrite((void*)&ph, sizeof(ph), 1, s->pcapf);
    fwrite((void*)buf, ph.incl_len, 1, s->pcapf);

    if (!ts || now-ts > CLOCK_BASE*5) {
        ts = now;
        fflush(s->pcapf);
    }
}

static void pcap_timer_cb(void *opaque)
{
    struct nickel *s = opaque;

    if (!s->pcap_timer)
        return;

    if (s->pcapf) {
        fclose(s->pcapf);
        s->pcapf = NULL;
    }
    free_timer(s->pcap_timer);
    s->pcap_timer = NULL;
}

static void pcap_usertrig_cb(void *opaque)
{
    struct nc_nickel_s *nc;
    uint32_t duration = 0;

    if (opaque) {
        duration = *(((uint32_t*) opaque));
        free(opaque);
    }

    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *s;

        s = nc->ni;
        assert(s);
        if (!s->pcap_user_enable)
            continue;
        if (duration)
            s->pcap_user_duration = duration;
        if (!s->pcap_user_duration)
            continue;
        if (!s->pcap_timer) {
            if (pcap_fileinit(s))
                continue;
            s->pcap_timer = new_timer_ms(rt_clock, pcap_timer_cb, s);
            if (!s->pcap_timer)
                break;
        }
        mod_timer(s->pcap_timer, get_clock_ms(rt_clock) + s->pcap_user_duration * 1000);
    }
}

void ni_pcap_usertrig(void)
{
    if (!pcap_user_enable)
        return;

    control_send_command("nc_UserTriggerGlobalPcapDump", NULL, NULL, NULL);
}

int
ni_pcap_global_dump(void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque)
{
    int duration;
    uint32_t *v = NULL;
    BH *bh;

    if (!pcap_user_enable)
        goto out;
    duration = dict_get_integer_default(d, "duration", 0);
    debug_printf("%s: received a nc_GlobalPcapDump request, duration = %d\n",
            __FUNCTION__, duration);
    if (!duration)
        goto out;
    v = calloc(1, sizeof(*v));
    if (!v)
        goto err;
    *v = duration;
    bh = bh_new(pcap_usertrig_cb, v);
    if (!bh)
        goto err;
    bh_schedule_one_shot(bh);
out:
    return 0;
err:
    free(v);
    goto out;
}

static void debug_dmp(struct nickel *ni, const uint8_t *buf, size_t len, bool input)
{
    struct ip *ip;
    struct udp *udp;
    int p_len, off, iphlen;
    pcaprec_hdr_t ph;
    char *str1 = NULL, *str2 = NULL;

    off = 0;
    p_len = len;
    if (p_len <= ETH_HLEN)
        goto out;

    if (ntohs(*(uint16_t *)(buf + 12)) != ETH_P_IP)
        goto out;

    off += ETH_HLEN;
    p_len -= ETH_HLEN;
    if (p_len <= sizeof(*ip))
        goto out;
    ip = (struct ip *) (buf + off);
    iphlen = ip->ip_hl << 2;
    if (ip->ip_v != IP_V4 || (ip->ip_p != IPPROTO_UDP &&
        ip->ip_p != IPPROTO_ICMP)) {

        goto out;
    }
    if (iphlen >= p_len)
        goto out;

    if (ip->ip_p == IPPROTO_ICMP)
        goto write;

    /* udp, check port */
    off += iphlen;
    p_len -= iphlen;
    udp = (struct udp *) (buf + off);
    if (p_len < sizeof(*udp))
        goto write;

    /* we debug DNS but not other UDP services */
    {
        struct in_addr ssaddr = { .s_addr = ip->ip_src };
        struct in_addr sdaddr = { .s_addr = ip->ip_dst };

        if (input && ntohs(udp->uh_dport) != 53 && ni_is_udp_vmfwd(ni, sdaddr, udp->uh_dport))
            goto out;
        if (!input && ntohs(udp->uh_sport) != 53 && ni_is_udp_vmfwd(ni, ssaddr, udp->uh_sport))
            goto out;
    }

write:
    ni_get_pcap_ts(&ph.ts_sec, &ph.ts_usec);
    ph.incl_len = ph.orig_len = len;

    str1 = base64_encode((const unsigned char *)&ph, sizeof(ph));
    str2 = base64_encode((const unsigned char *)buf, len);
    if (!str1 || !str2) {
        warnx("%s: base64_encode failed", __FUNCTION__);
        goto out;
    }
    debug_printf("DNET %s %s\n", str1, str2);
out:
    free(str2);
    free(str1);
}

/* END PCAP */

#if defined(CONFIG_VBOXDRV)
void vbsfSaveHandleTable(QEMUFile *f);
int vbsfLoadHandleTable(QEMUFile *f);
#endif

static void
state_save(QEMUFile *f, void *opaque)
{
    struct nickel *ni = opaque;
    unsigned long n = 0;
    struct buff *bf, *bf_n;

    NETLOG("%s: saving nickel state", __FUNCTION__);
    qemu_put_byte(f, ni->eth_vm_resolved ? 1 : 0);
    if (ni->eth_vm_resolved)
        qemu_put_buffer(f, ni->eth_vm, ETH_ALEN);

    lock_outq(ni);
    RLIST_FOREACH_SAFE(bf, &ni->output_list, entry, bf_n) {
        RLIST_REMOVE(bf, entry);
        if (bf->len) {
            n++;
            qemu_put_byte(f, 1); /* is a buff */
            qemu_put_be32(f, bf->len);
            qemu_put_buffer(f, bf->m, bf->len);
        }
        buff_free(&bf);
    }
    unlock_outq(ni);
    qemu_put_byte(f, 0); /* end of buffs */
    NETLOG("%s: saved %lu outbufs", __FUNCTION__, n);

    tcpip_save(f, ni);
    ac_save(f, ni);
    fakedns_save_state(f);

#if defined(CONFIG_VBOXDRV)
    vbsfSaveHandleTable(f);
#endif
}

static int
state_load(QEMUFile *f, void *opaque, int version_id)
{
    int ret = -1;
    struct nickel *ni = opaque;
    uint32_t l;
    struct buff *bf;
    unsigned long n = 0;

    NETLOG("%s: loading nickel state", __FUNCTION__);
    if (qemu_get_byte(f)) {
        ni->eth_vm_resolved = 1;
        qemu_get_buffer(f, (unsigned char *) ni->eth_vm, ETH_ALEN);
        NETLOG("%s: vm mac addr %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", __FUNCTION__,
                ni->eth_vm[0], ni->eth_vm[1], ni->eth_vm[2],
                ni->eth_vm[3], ni->eth_vm[4], ni->eth_vm[5]);
    }

    while (qemu_get_byte(f)) {
        l = qemu_get_be32(f);
        bf = ni_netbuff(ni, l);
        if (!bf) {
            warnx("malloc failure");
            qemu_file_skip(f, l);
            continue;
        }
        n++;
        bf->opaque = ni;
        bf->len = l;
        qemu_get_buffer(f, (unsigned char *) bf->m, l);
        RLIST_INSERT_TAIL(&ni->output_list, bf, entry);
    }
    NETLOG("%s: loaded %lu outbufs", __FUNCTION__, n);

    if (tcpip_load(f, ni, version_id) < 0) {
        warnx("%s: tcpip_load failed!", __FUNCTION__);
        goto out;
    }

    if (ac_load(f, ni, version_id) < 0) {
        warnx("%s: ac_load failed!", __FUNCTION__);
        goto out;
    }

    if (fakedns_load_state(f, version_id) < 0) {
        warnx("%s: fakedns_load_state failed!", __FUNCTION__);
        goto out;
    }

#if defined(CONFIG_VBOXDRV)
    {
        int err;

        err = vbsfLoadHandleTable(f);
        if (err) {
            warnx("vbsfLoadHandleTable error code 0x%x", err);
            goto out;
        } else
            warnx("vbsfLoadHandleTable load ok");
    }
#endif
    ret = 0;
out:
    return ret;
}

void * ni_priv_calloc(size_t nmemb, size_t size)
{
    return priv_calloc(ni_priv_heap, nmemb, size);
}

void * ni_priv_malloc(size_t nmemb)
{
    return priv_malloc(ni_priv_heap, nmemb);
}

void * ni_priv_realloc(void *ptr, size_t size)
{
    return priv_realloc(ni_priv_heap, ptr, size);
}

void ni_priv_free(void *ptr)
{
    return priv_free(ni_priv_heap, ptr);
}

char * ni_priv_strdup(const char *s)
{
    return priv_strdup(ni_priv_heap, s);
}

char * ni_priv_strndup(const char *s, size_t n)
{
    return priv_strndup(ni_priv_heap, s, n);
}

struct buff *
ni_netbuff(struct nickel *ni, size_t len)
{
    struct buff *bf;

    if (!buff_new_priv(&bf, (len + FRAME_ALIGN_MASK) &
                ((size_t) (~(FRAME_ALIGN_MASK))))) {
        warnx("%s: malloc failure", __FUNCTION__);
        return NULL;
    }
    bf->opaque = ni;
    bf->len = len;

    return bf;
}

static void ni_input(struct nickel *ni, const uint8_t *buf, size_t len)
{
#if defined(NICKEL_THREADED)
    struct buff *bf;

    bf = ni_netbuff(ni, len);
    if (!bf)
        return;
    memcpy(bf->m, buf, len);
    bf->len = len;
    queue_input(ni, bf);
#else
    tcpip_input(ni, buf, len);
#endif
}


void ni_output(struct nickel *ni, const uint8_t *pkt, int pkt_len)
{
    struct nc_nickel_s *snc = (struct nc_nickel_s *) ni->nc_opaque;

    if (ni->debug_dns_udp_icmp)
        debug_dmp(ni, pkt, pkt_len, false);
    dump_packet(ni, pkt, pkt_len);

    atomic_inc(&ni->n_pkt_rx);
    atomic_add(&ni->if_rx, (uint32_t) pkt_len);
    ni->s_pkt_rx += (uint64_t) pkt_len;

    qemu_send_packet(&snc->nc, pkt, pkt_len);
}

#if defined(NICKEL_THREADED)
static void queue_input(struct nickel *ni, struct buff *bf)
{
    critical_section_enter(&ni->queue_in_mx);
    RLIST_INSERT_TAIL(&ni->in_bufq, bf, entry);
    ni->inq_n++;
    if (ni->inq_n > ni->inq_max)
        ni->inq_max = ni->inq_n;
    critical_section_leave(&ni->queue_in_mx);
    ioh_event_set(&ni->deqin_ev);
}

static void ni_input_buff(struct nickel *ni, struct buff *bf)
{
    tcpip_input(ni, bf->m, bf->len);
    buff_free(&bf);
}

static void dequeue_input(void *opaque)
{
    struct nickel *ni = opaque;
    struct buff *bf;

    for (;;) {
       critical_section_enter(&ni->queue_in_mx);
       if (RLIST_EMPTY(&ni->in_bufq, entry)) {
            critical_section_leave(&ni->queue_in_mx);
            break;
       }
       bf = RLIST_FIRST(&ni->in_bufq, entry);
       RLIST_REMOVE(bf, entry);
       ni->inq_n--;
       critical_section_leave(&ni->queue_in_mx);

       ni_input_buff(ni, bf);
    }
}
#endif

void dequeue_output(void *opaque)
{
    struct nickel *ni = opaque;

    output(ni, NULL, true);
}

static int
hostfwd(struct nickel *ni, const yajl_val object)
{
    struct in_addr host_addr = { .s_addr = 0 };
    struct in_addr vm_addr = { .s_addr = 0 };
    int host_port, vm_port;
    const char *host_pipe = NULL;
    const char *p;
    int is_udp;

    p = yajl_object_get_string(object, "proto");
    if (!p || !strcmp(p, "tcp"))
        is_udp = 0;
    else if (!strcmp(p, "udp"))
        is_udp = 1;
    else
        goto fail_syntax;

    p = yajl_object_get_string(object, "host_pipe");
    if (p)
        host_pipe = p;

    p = yajl_object_get_string(object, "host_addr");
    if (p && !inet_aton(p, &host_addr))
        goto fail_syntax;

    host_port = yajl_object_get_integer(object, "host_port");
    if (host_port < 1 || host_port > 65535)
        goto fail_syntax;

    p = yajl_object_get_string(object, "vm_addr");
    if (p && !inet_aton(p, &vm_addr))
        goto fail_syntax;

    vm_port = yajl_object_get_integer(object, "vm_port");
    if (vm_port < 1 || vm_port > 65535)
        goto fail_syntax;

    if (host_pipe) {
        int close_on_retry, reconnect_on_close;

	reconnect_on_close = yajl_object_get_bool_default(object, "reconnect-on-close", 0);
        close_on_retry = yajl_object_get_bool_default(object, "close-on-guest-retry", 0);
        if (ni_add_hostfwd_pipe(ni, is_udp, host_pipe, host_addr, host_port, vm_addr, vm_port,
                                  reconnect_on_close, close_on_retry) < 0) {

            error_report("could not set up host forwarding rule");
            return -1;
        }
    } else {
        if (ni_add_hostfwd(ni, is_udp, host_addr, host_port,
                              vm_addr, vm_port) < 0) {
            warn("%s: add_hostfwd failed", __FUNCTION__);
            error_report("could not set up host forwarding rule");
            return -1;
        }
    }
    return 0;

 fail_syntax:
    error_report("invalid host forwarding rule");
    return -1;
}

static int
vmfwd(struct nickel *ni, const yajl_val object)
{
    struct in_addr host_addr = { .s_addr = INADDR_ANY };
    struct in_addr vm_addr = { .s_addr = INADDR_ANY };
    int host_port, vm_port = 0;
    const char *host_file = NULL;
    yajl_val host_service = NULL;
    const char *p;
    yajl_val v;
    int is_udp;
    uint64_t byte_limit = 0;
    int64_t tmp;

    p = yajl_object_get_string(object, "proto");
    if (!p || !strcmp(p, "tcp"))
        is_udp = 0;
    else if (!strcmp(p, "udp"))
        is_udp = 1;
    else
        goto fail_syntax;

    p = yajl_object_get_string(object, "host_file");
    if (p)
        host_file = p;

    v = yajl_object_get_object(object, "host_service");
    if (v)
        host_service = v;

    host_port = yajl_object_get_integer(object, "host_port");
    if (host_port < 1 || host_port > 65535)
        goto fail_syntax;

    p = NULL;
    tmp = yajl_object_get_integer_default(object, "byte-count-limit", -1);
    if (tmp > 0)
        byte_limit = tmp;
    else
        p = yajl_object_get_string(object, "byte-count-limit");
    if (p) {
        char tmp[25];
        int plen;
        uint32_t multipl = 1;

        do {
            plen = strlen(p);
            if (!plen || plen > 24)
                break;
            memcpy(tmp, p, plen);
            tmp[plen] = 0;
            switch (tmp[plen - 1]) {
            case 'G':
            case 'g':
                multipl = 1024 * 1024 * 1024;
                break;
            case 'M':
            case 'm':
                multipl = 1024 * 1024;
                break;
            case 'K':
            case 'k':
                multipl = 1024;
                break;
            }
            if (multipl > 1 && plen < 2)
                break;
            if (multipl > 1)
                tmp[plen - 1] = 0;
            if (sscanf(tmp, "%" PRIu64, &byte_limit) > 0)
                byte_limit *= multipl;
            else
                byte_limit = 0;
            if (!(byte_limit + 1) || !(byte_limit + 2))
                byte_limit = 0;
        } while (1 == 0);
        if (!byte_limit)
            warnx("%s: byte-count-limit wrong value (too large number ?)", __FUNCTION__);
    }

    if (byte_limit && !is_udp) {
        byte_limit = 0;
        warnx("%s: byte-count-limit is only supported for udp vmfwd at the moment", __FUNCTION__);
    }

    if (byte_limit)
        debug_printf("%s: byte_limit for vmfwd -> :%d set at %" PRIu64 " bytes\n", __FUNCTION__, host_port, byte_limit);

    if (host_file) {
        CharDriverState *chr;
        void *opaque;

        chr = qemu_chr_open("nickel-file", host_file, NULL, &ni->io_handlers);
        if (!chr) {
            error_report("could not open file %s", host_file);
            return -1;
        }

        opaque = ni_vmfwd_add(ni, is_udp, chr,
                                 host_addr, host_port, vm_addr, vm_port, byte_limit);
        if (!opaque) {
            error_report("could not set up vm forwarding rule");
            return -1;
        }
    } else if (host_service) {
        void *opaque;
        const char *name;
        struct ns_desc *nsd;

        /* FIXME */
        {
            const char *serv = yajl_object_get_string(host_service, "service");
            if (serv && !strcmp(serv, "shared-folders")) {
#if defined(CONFIG_VBOXDRV)
                extern int sf_parse_config(yajl_val config);
                sf_parse_config(host_service);
#endif
                return 0;
            }
        }

        nsd = ns_find_service(yajl_object_get_string(host_service, "service"),
                              is_udp);
        if (nsd == NULL) {
            error_report("unknown service %s for vm service forwarding",
                         yajl_object_get_string(host_service, "service"));
            return -1;
        }

        opaque = ni_vmfwd_add_service(ni, is_udp,
                                         nsd->service_open,
                                         host_service,
                                         host_addr, host_port, vm_addr,
                                         vm_port, byte_limit);
        if (!opaque) {
            error_report("could not set up vm service forwarding rule");
            return -1;
        }

        name = dict_get_string(host_service, "service");
        if (name && strcmp(name, "dns-resolver") == 0)
            ni->dns_resolver_ok = 1;
        if (name && strcmp(name, "http-proxy") == 0)
            ni->http_proxy_svc_ok = 1;
        if (name && strcmp(name, "webdav") == 0)
            ni->webdav_svc_ok = 1;

    } else
        goto fail_syntax;

    return 0;

 fail_syntax:
    error_report("invalid guest forwarding rule");
    return -1;
}

#if NEXT_STAGE
#ifdef MONITOR
void
ic_slirp(Monitor *mon)
{
    SlirpState *s;

    QTAILQ_FOREACH(s, &nickel_stacks, entry) {
        monitor_printf(mon, "VLAN %d (%s):\n",
                       s->nc.vlan ? s->nc.vlan->id : -1,
                       s->nc.name);
        ni_connection_info(s->slirp, mon);
    }
#ifdef SLIRP_THREADED
    monitor_printf(mon, "nickel threaded: queue max depth in:%lu, out:%lu\n", inq_max, outq_max);
#endif
}
#endif  /* MONITOR */
#endif

static int ac_config(struct nickel *ni, const yajl_val d)
{
    ni->ac_default_policy = yajl_object_get_integer_default(d, "default-policy", -1);
    ni->ac_allow_well_known_ports = yajl_object_get_bool_default(d, "allow_well_known_ports", 0);
    ni->ac_max_tcp_conn = yajl_object_get_integer_default(d, "max-tcp-connections", 0);
    ni->ac_block_other_udp_icmp = yajl_object_get_bool_default(d, "block-other-udp-icmp", 0);

    ni->lava_events_per_host = 1;
    if (yajl_object_get_bool_default(d, "lava-all-events", 0))
        ni->lava_events_per_host = 0;

    ni->ac_enabled = 1;
    ac_init(ni);

    return 0;
}

static int
config_option(const char *name, const yajl_val arg, void *opaque)
{
    struct nickel *ni = opaque;
    yajl_val v;
    int i;

    if (!strcmp(name, "hostfwd")) {
        if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
            warnx("hostfwd arg wrong type: expect map or array of map");
        else
            YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
                if (!YAJL_IS_OBJECT(v)) {
                    warnx("hostfwd arg wrong type: expect map");
                    continue;
                }
                if (hostfwd(ni, v) < 0)
                    /* ignore -- goto error */;
            }
    } else
    if (!strcmp(name, "vmfwd")) {
        if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
            warnx("vmfwd arg wrong type: expect map or array of map");
        else
            YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
                if (!YAJL_IS_OBJECT(v)) {
                    warnx("vmfwd arg wrong type: expect map");
                    continue;
                }
                if (vmfwd(ni, v) < 0)
                    /* ignore -- goto error */;
            }
    } else if (!strcmp(name, "proxyfwd")) {
        if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
            warnx("proxyfwd arg wrong type: expect map or array of map");
        else
            YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
                if (!YAJL_IS_OBJECT(v)) {
                    warnx("proxyfwd arg wrong type: expect map");
                    continue;
                }
                if (ni_proxyfwd(ni, v) < 0)
                    /* ignore -- goto error */;
            }
    } else if (!strcmp(name, "disable-tcp-window-scale")) {
        if (YAJL_IS_TRUE(arg))
            ni->tcp_disable_window_scale = 1;
        else if (YAJL_IS_FALSE(arg))
            ni->tcp_disable_window_scale = 0;
    } else if (!strcmp(name, "tcpdump")) {
        if (pcap_config(ni, arg))
            /* ignore -- goto error */;
    } else if (!strcmp(name, "debug-dns-udp-icmp")) {
        if (YAJL_IS_TRUE(arg))
            ni->debug_dns_udp_icmp = 1;
        if (ni->debug_dns_udp_icmp)
            debug_printf("nickel: debug-dns-udp-icmp active - will dump ICMP, DNS and some other "
                    "UDP packets\n");

    } else if (!strcmp(name, "access_control")) {
        if (!YAJL_IS_OBJECT(arg))
            warnx("access_control arg wrong type: expect map");
        else if (ac_config(ni, arg))
            /* ignore -- goto error */;

    } else if (!strcmp(name, "log_level")) {
        if (YAJL_IS_INTEGER(arg)) {
            ni->log_level = YAJL_GET_INTEGER(arg);
            if (ni->log_level > ni_log_level)
                ni_log_level = ni->log_level;
            NETLOG("log level %d", ni_log_level);
        } else
            warnx("log_level arg wrong type: expect integer");
    } else if (!strcmp(name, "disable_dhcp")) {
        if (YAJL_IS_TRUE(arg)) {
            ni->disable_dhcp = 1;
            NETLOG("dhcp disabled");
        } else if (!YAJL_IS_FALSE(arg)) {
            warnx("disable_dhcp arg wrong type: expect boolean");
        }
#if defined(_WIN32)
    } else if (!strcmp(name, "crash-dump-on-ipc-rst")) {
        if (YAJL_IS_TRUE(arg)) {
            ni->crash_dump_on_ipc_rst = 1;
            NETLOG2("crash dump on ipc tcp connection reset enabled");
        } else if (!YAJL_IS_FALSE(arg)) {
            warnx("crash_dump_on_ipc_rst arg wrong type: expect boolean");
        }
#endif
    } else {
        warnx("nickel: invalid option %s", name);
    }

    return 0;
}

/* lib */
Timer *
ni_new_vm_timer(struct nickel *ni, int64_t delay_ms, void (*cb)(void *opaque), void *opaque)
{
    Timer *t;

#if defined(NICKEL_THREADED)
    t = new_timer_ms_ex(ni->active_timers, vm_clock, cb, opaque);
#else
    t = new_timer_ms(vm_clock, cb, opaque);
#endif

    if (!t)
        return NULL;
    mod_timer(t, get_clock_ms(vm_clock) + delay_ms);
    return t;
}

int ni_schedule_bh(struct nickel *ni, void (*async_cb)(void *), void (*finish_cb)(void *),
        void *opaque)
{
    return async_op_add(ni->async_op_ctx, opaque, &ni->event, async_cb, finish_cb);
}

int ni_schedule_bh_permanent(struct nickel *ni, void (*cb)(void *), void *opaque)
{
    return async_op_add_bh(ni->async_op_ctx, opaque, cb);
}

uint32_t ni_get_hostaddr(struct nickel *ni)
{
    return ni->host_addr.s_addr;
}

CharDriverState *
ni_tcp_connect(struct nickel *ni, struct sockaddr_in saddr,
        struct sockaddr_in daddr, void *opaque)
{
    struct ni_socket *so = opaque;
    CharDriverState *chr = NULL;

    if (daddr.sin_addr.s_addr == ni->host_addr.s_addr) {
        if (ni_is_tcp_vmfwd(ni, daddr.sin_addr, daddr.sin_port)) {
            tcpip_set_sock_type(so, SS_VMFWD);
            chr = ni_tcp_vmfwd_open(ni, saddr, daddr, so);
            if (chr)
                ni_event(so, CHR_EVENT_OPENED);

            goto out;
        }

        /* do not allow connections to the loopback address
         * if there is access control in place */
        if (ni->ac_enabled)
            goto out;

    } else if ((daddr.sin_addr.s_addr & ni->network_mask.s_addr) ==
               ni->network_addr.s_addr) {

        goto out;
    }

    tcpip_set_sock_type(so, SS_NAV);
    chr = ni_prx_open(ni, false, saddr, daddr, so);
out:
    return chr;
}

CharDriverState *
ni_udp_open(struct nickel *ni, struct sockaddr_in gaddr,
        struct sockaddr_in faddr, void *opaque)
{
    struct ni_socket *so = opaque;
    CharDriverState *chr = NULL;

    if (ni_is_udp_vmfwd(ni, faddr.sin_addr, faddr.sin_port)) {
        chr = ni_udp_vmfwd_open(ni, gaddr, faddr, opaque);
    } else if ((!ni->ac_enabled && faddr.sin_addr.s_addr == ni->host_addr.s_addr) ||
               (faddr.sin_addr.s_addr & ni->network_mask.s_addr) !=
               ni->network_addr.s_addr) {

        chr = ni_prx_open(ni, true, gaddr, faddr, so);
    }

    return chr;
}

void ni_close(void *opaque)
{
    struct ni_socket *so = opaque;

    tcpip_close(so);
}

size_t ni_can_recv(void *opaque)
{
    struct ni_socket *so = opaque;

    return tcpip_can_output(so);
}

int ni_send_fin(void *opaque)
{
    struct ni_socket *so = opaque;

    return tcpip_send_fin(so);
}

void ni_recv(void *opaque, const uint8_t *buf, int size)
{
    struct ni_socket *so = opaque;

    tcpip_output(so, buf, size);
}

void ni_buf_change(void *opaque)
{
    struct ni_socket *so = opaque;

    tcpip_win_update(so);
}

void ni_send(void *opaque)
{
    struct ni_socket *so = opaque;

    tcpip_win_update(so);
}

void ni_event(void *opaque, int event)
{
    struct ni_socket *so = opaque;

    tcpip_event(so, event);
}

static void free_or_sent(struct buff *bf)
{
    for (;;) {
        if (cmpxchg(&bf->state, BFS_FREE, BFS_SENT) == BFS_FREE) {
            buff_free(&bf);
            break;
        }

        if (cmpxchg(&bf->state, BFS_SOCKET, BFS_SENT) == BFS_SOCKET)
            break;
    }
}

static void output(struct nickel *ni, struct buff *bf0, bool send)
{
    while (send)  {
        struct buff *bf;

        lock_outq(ni);
        if (RLIST_EMPTY(&ni->output_list, entry)) {
            unlock_outq(ni);
            break;
        }
        bf = RLIST_FIRST(&ni->output_list, entry);

        RLIST_REMOVE(bf, entry);
        unlock_outq(ni);

        ni_output(ni, bf->m, bf->len);

        free_or_sent(bf);
    }

    if (!bf0)
        return;

    if (send) {

        ni_output(ni, bf0->m, bf0->len);

        free_or_sent(bf0);
        return;
    }

    lock_outq(ni);
    RLIST_INSERT_TAIL(&ni->output_list, bf0, entry);
    unlock_outq(ni);
    if (!send)
        ioh_event_set(&ni->deqout_ev);
}

void ni_buff_output(struct nickel *ni, struct buff *bf)
{
#if defined(NICKEL_THREADED)
    output(ni, bf, false);
#else
    output(ni, bf, true);
#endif
}

struct in_addr ni_get_addr(void)
{
    struct nc_nickel_s *nc;
    struct in_addr a = { .s_addr = 0 };

    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni;

        ni = nc->ni;
        assert(ni);
        a = ni->host_addr;
        break;
    }

    return a;
}

static struct nickel *
get_first_nickel(void)
{
    struct nc_nickel_s *nc;

    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni;

        ni = nc->ni;
        assert(ni);
        return ni;
    }
    return NULL;
}

void ni_stats(unsigned int *tcp_nb_conn, unsigned int *tcp_nb_total,
     unsigned int *net_last, unsigned int *net_rx_rate, unsigned int *net_tx_rate,
     unsigned int *net_nav_rx_rate, unsigned int *net_nav_tx_rate)
{
    struct nickel *ni = get_first_nickel();
    int64_t now;
    static int64_t last_ts = 0;

    if (!ni)
        return;

    now = get_clock_ms(rt_clock);
    if (!last_ts || last_ts + 10 * 1000 < now) {
        ni->if_rx = 0;
        ni->if_tx = 0;
        ni->tcp_nav_rx = 0;
        ni->tcp_nav_tx = 0;
    }

    *tcp_nb_conn = (unsigned int) ni->number_tcp_nav_sockets;
    *tcp_nb_total = (unsigned int) ni->number_total_tcp_sockets;
    *net_last = (unsigned int) (ni->tcpip_last_tcp_data ? now - ni->tcpip_last_tcp_data : 0);
    *net_rx_rate = (unsigned int) ni->if_rx;
    *net_tx_rate = (unsigned int) ni->if_tx;
    *net_nav_rx_rate = (unsigned int) ni->tcp_nav_rx;
    *net_nav_tx_rate = (unsigned int) ni->tcp_nav_tx;

    ni->if_rx = 0;
    ni->if_tx = 0;
    ni->tcp_nav_rx = 0;
    ni->tcp_nav_tx = 0;
    last_ts = now;
}


#if defined(NICKEL_THREADED)
#if defined(_WIN32)
static DWORD WINAPI ni_thread_run(void *opaque)
#elif defined(__APPLE__)
static void * ni_thread_run(void *opaque)
#endif
{
    struct nickel *ni = opaque;
    int timeout, wait_time = 0;
    int64_t delay_ms = 0;

#if defined(_WIN32)
    NETLOG("%s: ni %lx pid %lu thid %lu a %lx %lx", __FUNCTION__, ni,
            (unsigned long) GetProcessIdOfThread(ni->threadh),
            (unsigned long) GetCurrentThreadId(), ni_thread_run, &opaque);
#elif defined(__APPLE__)
    NETLOG("%s: ni %lx pid %lu a %lx %lx", __FUNCTION__, ni,
            (unsigned long) getpid(), ni_thread_run, &opaque);
#endif

    while (!ni->exit_request) {

        if (cmpxchg(&ni->suspend_request, 1, 2) == 1) {
            ioh_event_set(&ni->suspend_ok_ev);
            NETLOG("%s: nickel thread suspended", __FUNCTION__);
            ioh_event_wait(&ni->suspend_ev);
            ni->suspend_request = 0;
        }

        if (ni->exit_request)
            break;

        timeout = DEFAULT_TIMEOUT_MS;
        ni_prepare(ni, &timeout);

        if (delay_ms) {
            delay_ms = get_clock_ms(vm_clock) - delay_ms;
            delay_ms -= wait_time;

            if (delay_ms > LOOP_DELAY_WARN)
                NETLOG("%s: warning! blocking networking thread? latency %lu ms",
                        __FUNCTION__, (unsigned long) delay_ms);
        }
        delay_ms = get_clock_ms(vm_clock);
        ioh_wait_for_objects(&ni->io_handlers, &ni->wait_objects, ni->active_timers,
                &timeout, &wait_time);
    }

    NETLOG("%s: thread exit", __FUNCTION__);
    return 0;
}
#endif

int ni_rpc_ac_event(void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque)
{
    struct nc_nickel_s *nc;

    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni = nc->ni;

        assert(ni);
        rpc_ac_event(ni, opaque, id, opt, d, command_opaque);
    }

    return control_send_ok(opaque, opt, id, NULL);
}

int ni_rpc_http_event(void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque)
{
    struct nc_nickel_s *nc;

    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni = nc->ni;

        assert(ni);
        rpc_http_event(ni, opaque, id, opt, d, command_opaque);
    }

    return control_send_ok(opaque, opt, id, NULL);
}

int ni_add_wait_object(struct nickel *ni, ioh_event *event, WaitObjectFunc *func, void *opaque)
{
    return ioh_add_wait_object(event, func, opaque, &ni->wait_objects);
}

void ni_del_wait_object(struct nickel *ni, ioh_event *event)
{
    ioh_del_wait_object(event, &ni->wait_objects);
}

#ifndef _WIN32
int ni_add_wait_fd(struct nickel *ni, int fd, int events, WaitObjectFunc2 *func2, void *opaque)
{
    return ioh_add_wait_fd(fd, events, func2, opaque, &ni->wait_objects);
}

void ni_del_wait_fd(struct nickel *ni, int fd)
{
    ioh_del_wait_fd(fd, &ni->wait_objects);
}
#endif

void ni_prepare(struct nickel *ni, int *timeout)
{
    struct nc_nickel_s *nc;

    if (ni) {
        ioh_event_reset(&ni->event);
        async_op_process(ni->async_op_ctx);
        tcpip_prepare(ni, timeout);
        so_prepare(ni, timeout);

        return;
    }

    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni = nc->ni;

        tcpip_prepare(ni, timeout);
        so_prepare(ni, timeout);
        async_op_process(ni->async_op_ctx);
    }

}

static void post_init(struct nickel *ni)
{
    tcpip_post_init(ni);
    ac_post_init(ni);
}

void ni_start(void)
{
    struct nc_nickel_s *nc;
    struct tm _tm, *tm;
    struct timeval tv;
    time_t ltime;

    gettimeofday(&tv, NULL);
    ltime = (time_t)tv.tv_sec;
    tm = localtime_r(&ltime, &_tm);
    if (tm) {
        NETLOG("start %d-%02d-%02d %02d:%02d:%02d ts %"PRId64,
               tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
               tm->tm_min, tm->tm_sec, get_clock_ms(rt_clock));
    }

    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni = nc->ni;

        assert(ni);
        post_init(ni);
#if defined(NICKEL_THREADED)
        if (create_thread(&ni->threadh, ni_thread_run, ni) < 0) {
            ni->threadh = 0;
            warnx("%s: cannot create nickel thread", __FUNCTION__);
            continue;
        }
        elevate_thread(ni->threadh);
#endif
    }
}

void ni_exit(void)
{
    struct nc_nickel_s *nc;

    NETLOG("%s: network exiting ...", __FUNCTION__);
#if defined(NICKEL_THREADED)
    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni = nc->ni;

        assert(ni);
        ni->exit_request = 1;
        ni->suspend_request = 2;
        ioh_event_set(&ni->suspend_ev);
        ioh_event_set(&ni->deqin_ev);
        if (ni->threadh) {
            wait_thread(ni->threadh);
            close_thread_handle(ni->threadh);
        }
    }
    NETLOG("%s: thread exit ok", __FUNCTION__);
#endif

    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni = nc->ni;

        assert(ni);
        ac_exit(ni);
        tcpip_exit(ni);
        fakedns_exit(ni);
        if (ni->pcapf)
            fflush(ni->pcapf);
        if (ni->async_op_ctx) {
            NETLOG("%s: waiting for async op threads", __FUNCTION__);
            async_op_exit_wait(ni->async_op_ctx);
            ni->async_op_ctx = NULL;
            NETLOG("%s: async op exit ok", __FUNCTION__);
        }

        NETLOG("%s: rx %u %.03fMiB, tx %u %.03fMiB", __FUNCTION__,
            (unsigned int) ni->n_pkt_rx, ((double) (ni->s_pkt_rx >> 10)) / 1024,
            (unsigned int) ni->n_pkt_tx, ((double) (ni->s_pkt_tx >> 10)) / 1024);
    }
    NETLOG("%s: ... network exit ok", __FUNCTION__);
    fflush(stderr);
}

void ni_suspend_flush(void)
{
    struct nc_nickel_s *nc;

    /* this list is readonly, no locks necessary */
    QTAILQ_FOREACH(nc, &nc_list, entry) {
        struct nickel *ni = nc->ni;

        assert(ni);
#if defined(NICKEL_THREADED)
        ioh_event_reset(&ni->suspend_ok_ev);
        ioh_event_reset(&ni->suspend_ev);
        if (cmpxchg(&ni->suspend_request, 0, 1) == 0) {
            NETLOG("%s: nickel thread suspend request", __FUNCTION__);
            ioh_event_set(&ni->event);
            ioh_event_wait(&ni->suspend_ok_ev);
        }
#endif
        tcpip_flush(ni);
        output(ni, NULL, true);
        lava_flush(ni);
        if (ni->pcapf)
            fflush(ni->pcapf);
    }
    NETLOG("%s: flushed", __FUNCTION__);
}

void ni_wakeup_loop(struct nickel *ni)
{
    ioh_event_set(&ni->event);
}


static ssize_t net_nickel_receive(VLANClientState *nc, const uint8_t *buf, size_t size)
{
    struct nc_nickel_s *snc = DO_UPCAST(struct nc_nickel_s, nc, nc);
    struct nickel *ni = snc->ni;

    if (ni->debug_dns_udp_icmp)
        debug_dmp(ni, buf, size, true);
    dump_packet(ni, buf, size);

    atomic_inc(&ni->n_pkt_tx);
    atomic_add(&ni->if_tx, (uint32_t) size);
    ni->s_pkt_tx += (uint64_t) size;

    ni_input(ni, buf, size);

    return size;
}

static void net_nickel_cleanup(VLANClientState *nc)
{
    struct nc_nickel_s *snc = DO_UPCAST(struct nc_nickel_s, nc, nc);
    struct nickel *s = snc->ni;

    NETLOG("%s", __FUNCTION__);
    QTAILQ_REMOVE(&nc_list, snc, entry);

    if (s->pcapf) {
        fclose(s->pcapf);
        s->pcapf = NULL;
    }
    free(s->pcap_fpath);
    s->pcap_fpath = NULL;
    if (s->pcap_timer) {
        free_timer(s->pcap_timer);
        s->pcap_timer = NULL;
    }
}

static NetClientInfo net_nickel_info = {
    .type = NET_CLIENT_TYPE_USER,
    .size = sizeof(struct nc_nickel_s),
    .receive = net_nickel_receive,
    .cleanup = net_nickel_cleanup,
};

int net_init_nickel(QemuOpts *opts, Monitor *mon, const char *name, VLANState *vlan)
{
    int ret = -1;
    struct nc_nickel_s *nc_n;
    struct nickel *ni = NULL;
    const char *vnet;
    uintptr_t ni_p = 0;

    struct in_addr net  = { .s_addr = htonl(0x0a000200) }; /* 10.0.2.0 */
    struct in_addr mask = { .s_addr = htonl(0xffffff00) }; /* 255.255.255.0 */
    struct in_addr host = { .s_addr = htonl(0x0a000202) }; /* 10.0.2.2 */
    struct in_addr dhcp = { .s_addr = htonl(0x0a00020f) }; /* 10.0.2.15 */

    epoch_ts = get_epoch_ts();
    if (!vlan)
        vlan = qemu_find_vlan(0, 1);

    vnet = qemu_opt_get(opts, "net");
    if (vnet) {
        uint32_t addr;
        char buf[20];

        if (get_str_sep(buf, sizeof(buf), &vnet, '/') < 0) {
            if (!inet_aton(vnet, &net))
                goto out;
            addr = ntohl(net.s_addr);
            if (!(addr & 0x80000000)) {
                mask.s_addr = htonl(0xff000000); /* class A */
            } else if ((addr & 0xfff00000) == 0xac100000) {
                mask.s_addr = htonl(0xfff00000); /* priv. 172.16.0.0/12 */
            } else if ((addr & 0xc0000000) == 0x80000000) {
                mask.s_addr = htonl(0xffff0000); /* class B */
            } else if ((addr & 0xffff0000) == 0xc0a80000) {
                mask.s_addr = htonl(0xffff0000); /* priv. 192.168.0.0/16 */
            } else if ((addr & 0xffff0000) == 0xc6120000) {
                mask.s_addr = htonl(0xfffe0000); /* tests 198.18.0.0/15 */
            } else if ((addr & 0xe0000000) == 0xe0000000) {
                mask.s_addr = htonl(0xffffff00); /* class C */
            } else {
                mask.s_addr = htonl(0xfffffff0); /* multicast/reserved */
            }
        } else {
            int shift;
            char *end;

            if (!inet_aton(buf, &net))
                goto out;
            shift = strtol(vnet, &end, 10);
            if (*end != '\0') {
                if (!inet_aton(vnet, &mask))
                    goto out;
            } else if (shift < 4 || shift > 32) {
                goto out;
            } else {
                mask.s_addr = htonl(0xffffffff << (32 - shift));
            }
        }
        net.s_addr &= mask.s_addr;
        host.s_addr = net.s_addr | (htonl(0x0202) & ~mask.s_addr);
        dhcp.s_addr = net.s_addr | (htonl(0x020f) & ~mask.s_addr);
    }

    nc_n = (struct nc_nickel_s *) qemu_new_net_client(&net_nickel_info, vlan, NULL, "user", name);
    if (!nc_n) {
        warnx("%s: qemu_new_net_client failed", __FUNCTION__);
        goto out;
    }
    ni_p = (uintptr_t) (&nc_n->_ni);
    ni_p = (ni_p + 7) & ~((uintptr_t) 7);
    ni = (struct nickel *) ni_p;
    memset(ni, 0, sizeof(*ni));

    nc_n->ni = ni;
    ni->nc_opaque = (void *) nc_n;

#if defined(_WIN32) || defined(__APPLE__)
    if (ni_priv_heap == NULL) {
        warnx("%s: priv_heap_create FAILED, err %u", __FUNCTION__, ni_priv_heap_err);
        ret = -1;
        goto out;
    }
#endif

    if (!buff_new(&ni->bf_dbg, 256))
        goto mem_err;
    LIST_INIT(&ni->sock_list);
    LIST_INIT(&ni->defered_list);
    RLIST_INIT(&ni->output_list, entry);
    RLIST_INIT(&ni->noarp_output_list, entry);
    LIST_INIT(&ni->tcp);
    LIST_INIT(&ni->udp);
    LIST_INIT(&ni->gc_tcpip);
    LIST_INIT(&ni->tcp_vmfwd);
    LIST_INIT(&ni->udp_vmfwd);
    LIST_INIT(&ni->prx_fwd);
    ni->async_op_ctx = async_op_init();
    ioh_event_init(&ni->event);
    ioh_event_init(&ni->deqout_ev);
    if (!ioh_event_valid(&ni->event) || !ioh_event_valid(&ni->deqout_ev)) {
        warnx("%s: ioh_event_init failed", __FUNCTION__);
        ret = -1;
        goto out;
    }
    ioh_add_wait_object(&ni->deqout_ev, dequeue_output, ni, NULL);

#if defined(NICKEL_THREADED)
    RLIST_INIT(&ni->in_bufq, entry);
    critical_section_init(&ni->queue_in_mx);
    critical_section_init(&ni->queue_out_mx);

    ni->active_timers = calloc(1, 2 * sizeof(TimerQueue));
    if (!ni->active_timers)
        goto mem_err;
    timers_init(ni->active_timers);
    ioh_queue_init(&ni->io_handlers);
    ioh_init_wait_objects(&ni->wait_objects);
    ioh_event_init(&ni->deqin_ev);
    ioh_event_init(&ni->start_event);
    ioh_event_init(&ni->suspend_ev);
    ioh_event_init(&ni->suspend_ok_ev);
    if (!ioh_event_valid(&ni->deqin_ev) || !ioh_event_valid(&ni->start_event)) {
        warnx("%s: ioh_event_init failed", __FUNCTION__);
        ret = -1;
        goto out;
    }
    ioh_add_wait_object(&ni->deqin_ev, dequeue_input, ni, &ni->wait_objects);
#endif
    ioh_add_wait_object(&ni->event, NULL, NULL, &ni->wait_objects);

    ni->tcp_disable_window_scale = 1;
    ni->mtu = NI_DEFAULT_MTU;
    ni->tcp_mss = (uint16_t) (ni->mtu - NI_TCPIP_HLEN);
    ni->network_addr = net;
    ni->network_mask = mask;
    ni->host_addr = host;
    ni->dhcp_startaddr = dhcp;
    memcpy(ni->eth_nickel, special_ethaddr, sizeof(special_ethaddr));
    memcpy(ni->eth_nickel + 2, (uint8_t *) (&host.s_addr), 4);

    tcpip_init(ni);
    so_init(ni);
    ac_init(ni);
    fakedns_init(ni);

    register_savevm(NULL, "nickel", 0, 16,
                    state_save, state_load, ni);

    QTAILQ_INSERT_TAIL(&nc_list, nc_n, entry);

    (void)qemu_opt_foreach_object(opts, config_option, ni, 0);
    /* check we have dns-resolver and http-proxy service or otherwise add them */
    if (!ni->dns_resolver_ok) {
        dict d, s;

        d = dict_new();
        s = dict_new();
        if (!d || !s)
            goto mem_err;

        dict_put_integer(d, "host_port", 53);
        dict_put_string(d, "proto", "udp");
        dict_put_string(s, "service", "dns-resolver");
        yajl_object_set(d, "host_service", s);
        if (vmfwd(ni, d) == 0) {
            ni->dns_resolver_ok = 1;
            NETLOG("%s: adding dns-resolver service", __FUNCTION__);
        } else {
            warnx("%s: failure adding dns-resolver service", __FUNCTION__);
        }

        dict_free(d);
    }

    if (!ni->tcp_service_ok) {
        ni_proxyfwd_add(ni, "tcp-service", false);
        NETLOG("tcp service automatically enabled");
    }

    if (!ni->ac_enabled) {
        ni_proxyfwd_add(ni, "udp-service", true);
        NETLOG("udp service automatically enabled");
    }

    if (ni->tcp_disable_window_scale)
        NETLOG("%s: TCP window scale option DISABLED", __FUNCTION__);

    ret = 0;
out:
    return ret;
mem_err:
    warnx("%s: malloc failure", __FUNCTION__);
    ret = -1;
    goto out;
}

static void __attribute__((constructor)) nickel_static_init(void)
{
    ni_priv_heap_err = priv_heap_create(&ni_priv_heap);
}
