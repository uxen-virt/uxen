/*
 * Copyright 2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/dict.h>
#include <dm/dict-rpc.h>
#include <dm/control.h>
#include "nickel.h"
#include "dns/dns.h"
#include "log.h"
#include "rpc.h"
#include "lava.h"

#if defined(_WIN32)
PCSTR WSAAPI inet_ntop (INT Family, PVOID pAddr, PSTR pStringBuf, size_t StringBufSize);
#endif

#define DEFAULT_RPC_EVENT_LEN   256
#define NUMBER_EVENTS_TRIGGER   6
#define LAVA_RPC_FLUSH_TIMEOUT  (8 * 1000) /* 8 sec */

#define U32BF(a)            (((uint32_t) 1) << (a))

#define LVI_STARTED       U32BF(0)
#define LVI_CONNECTED     U32BF(1)
#define LVI_SUBMITTED     U32BF(2)

#define LVF_TCP                 U32BF(0)
#define LVF_ESTABLISHED         U32BF(1)
#define LVF_LOCAL               U32BF(2)
#define LVF_PROXY               U32BF(3)
#define LVF_DENIED              U32BF(4)
#define LVF_GPROXY              U32BF(5)
#define LVF_REMOTE_ESTABLISHED  U32BF(6)
#define LVF_ICMP                U32BF(7)

struct lava_event_sv {
    uint32_t internal;
    uint32_t flags;
    uint32_t conn_id;
    uint16_t guest_port;
    struct net_addr remote_addr;
    uint16_t remote_port;
};

struct lava_event {
    struct nickel *ni;
    uint32_t internal;

    uint32_t flags;
    uint32_t conn_id;
    uint16_t guest_port;
    char *http_method;
    char *http_domain;
    char *http_url;
    uint16_t http_port;
    struct net_addr remote_addr;
    uint16_t remote_port;
};

static struct buff lava_rpc_list;
static size_t lava_rpc_count = 0;
static ioh_event lava_event;
static ioh_event lava_flushed_event;
static critical_section lava_list_lock;
static uxen_thread lava_thread;
static bool lava_initialized = false;
static uint32_t lava_exit_requested = 0;
static uint32_t lava_flush_requested = 0;

#if defined(_WIN32)
static DWORD WINAPI lava_thread_run(void *opaque)
#elif defined(__APPLE__)
static void * lava_thread_run(void *opaque)
#endif
{
    struct nickel *ni = (struct nickel *) opaque;
    struct buff *bf, *bf_n;

    for (;;) {
        bool flush = false;

        ioh_event_reset(&lava_event);

        flush = (lava_flush_requested != 0);
        if (flush)
            lava_flush_requested = 0;

        while (!lava_exit_requested &&
               ((flush && lava_rpc_count > 0) || (lava_rpc_count >= NUMBER_EVENTS_TRIGGER))) {

            int n, i;
            size_t len;
            char *rpc_buf, *s;
            dict d;

            n = 0;
            len = 0;
            critical_section_enter(&lava_list_lock);
            RLIST_FOREACH_SAFE(bf, &lava_rpc_list, entry, bf_n) {
                n++;
                len += bf->len;
                if (n >= NUMBER_EVENTS_TRIGGER)
                    break;
            }
            critical_section_leave(&lava_list_lock);

            len += (n + 1 + 1);
            rpc_buf = ni_priv_calloc(1, len);
            if (!rpc_buf) {
                warnx("%s: malloc error", __FUNCTION__);
                break;
            }

            s = rpc_buf;
            i = 0;
            critical_section_enter(&lava_list_lock);
            RLIST_FOREACH_SAFE(bf, &lava_rpc_list, entry, bf_n) {
                if (len <= bf->len + 1)
                    break;
                if (i > 0) {
                    *s++ = ' ';
                    len -= 1;
                }
                i++;
                memcpy(s, BUFF_TO(bf, char *), bf->len);
                s += bf->len;
                len -= bf->len;
                RLIST_REMOVE(bf, entry);
                lava_rpc_count--;
                buff_free(&bf);

                if (i == n)
                    break;
            }
            critical_section_leave(&lava_list_lock);

            d = dict_new();
            if (d) {
                NETLOG5("%s:LAVA_RPC: %s", __FUNCTION__, rpc_buf);
                dict_put_string(d, "events", rpc_buf);
                ni_rpc_send(ni, "nc_LavaEvents", d, NULL, NULL);
                dict_free(d);
            }
            ni_priv_free(rpc_buf);
            rpc_buf = NULL;
        }

        if (flush)
            ioh_event_set(&lava_flushed_event);

        if (lava_exit_requested)
            break;

        ioh_event_wait(&lava_event);
    }

    NETLOG("%s: exiting", __FUNCTION__);
    return 0;
}

#define MLEN_FIELD 256

static char *
lv_encode_string(const char *str, size_t max_len)
{
    char *resp = NULL;
    char buf[MLEN_FIELD + 1], *p;
    const char *q;
    size_t i;
    bool exit_loop;

    if (!str)
        goto out;

    memset(buf, 0, MLEN_FIELD + 1);
    if (max_len > MLEN_FIELD)
        max_len = MLEN_FIELD;

    q = str;
    i = 0;
    exit_loop = false;
    while (!exit_loop && *q && i <= max_len) {
        switch (*q) {
        case ' ':
            if (i + 2 > max_len) {
                exit_loop = true;
                break;
            }
            buf[i++] = '%';
            buf[i++] = '2';
            buf[i++] = '0';
            break;
        case '"':
            if (i + 2 > max_len) {
                exit_loop = true;
                break;
            }
            buf[i++] = '%';
            buf[i++] = '2';
            buf[i++] = '2';
            break;
        default:
            buf[i++] = *q;
            break;
        }

        q++;
    }

#if defined(_WIN32)
    resp = buff_priv_ansi_utf8_encode(buf);
    if (resp)
        goto out;

    NETLOG("%s: enconding to UTF8 failed, forcing ASCII", __FUNCTION__);
    p = buf;
    while (*p) {
        if ((*p & 0x80))
            *p = '.';
        p++;
    }
#else
    (void) p;
#endif

    resp = ni_priv_strdup(buf);
    if (!resp)
        warnx("%s: malloc error", __FUNCTION__);

out:
    return resp;
}

void lava_timer(struct nickel *ni, int64_t now)
{
    static int64_t ts_last_flush = 0;
    int64_t diff;

    if (!lava_initialized)
        return;

    if (!ts_last_flush) {
        ts_last_flush = now;
        return;
    }

    diff = ts_last_flush + LAVA_RPC_FLUSH_TIMEOUT - now;
    if (diff < 0) {
        if (lava_rpc_count > 0) {
            lava_flush_requested = 1;
            ioh_event_set(&lava_event);
        }
        ts_last_flush = now;
    }
}

static void lv_set_remote(struct lava_event *lv, const struct net_addr *a, uint16_t port)
{
    memset(&lv->remote_addr, 0, sizeof(lv->remote_addr));
    if (a)
        lv->remote_addr = *a;
    lv->remote_port = port;
}

static struct lava_event *
lv_create(struct nickel *ni)
{
    struct lava_event *lv;

    lv = calloc(1, sizeof(*lv));
    if (!lv) {
        warnx("%s: malloc error", __FUNCTION__);
        return NULL;
    }

    lv->ni = ni;
    return lv;
}

static void lv_free(struct lava_event *lv)
{
    ni_priv_free(lv->http_method);
    ni_priv_free(lv->http_domain);
    ni_priv_free(lv->http_url);
    free(lv);
}

int lava_send_icmp(struct nickel *ni, uint32_t daddr, uint8_t type, bool denied)
{
    int ret = -1;
    struct buff *bf = NULL;
    uint32_t flags = 0;
    struct in_addr _daddr;
    const char *str_daddr = NULL;

    if (!lava_initialized || !ni->ac_event_log_enabled)
        goto out;

    if (buff_new_priv(&bf, DEFAULT_RPC_EVENT_LEN) == NULL)
        goto mem_err;
    RLIST_INIT(bf, entry);

    flags |= LVF_ICMP;
    if (denied)
        flags |= LVF_DENIED;
    if ((flags >> 8) != 0) {
        static bool first_warn = true;

        if (first_warn) {
            NETLOG("%s: WARNING ! upper part of flags is set", __FUNCTION__);
            first_warn = false;
        }
    }
    flags |= (((uint32_t) type) << 8);

    _daddr.s_addr = daddr;
    str_daddr = inet_ntoa(_daddr);
    if (!str_daddr)
        str_daddr = "";

    if (buff_appendf(bf, "\"%u\",\"%u\",\"%hu\",\"%s\",\"%s\",\"%s\",\"%hu\",\"%s\",\"%hu\"",
            (unsigned) flags, (unsigned) 0, (uint16_t) 0, "", "", "", (uint16_t) 0, str_daddr,
            (uint16_t) 0) < 0) {

        goto mem_err;
    }

    critical_section_enter(&lava_list_lock);
    RLIST_INSERT_TAIL(&lava_rpc_list, bf, entry);
    lava_rpc_count++;
    critical_section_leave(&lava_list_lock);

    if (lava_rpc_count > NUMBER_EVENTS_TRIGGER)
        ioh_event_set(&lava_event);

    ret = 0;
out:
    return ret;
mem_err:
    warnx("%s: malloc error", __FUNCTION__);
    buff_free(&bf);
    goto out;
}

static void lv_submit_and_reset(struct lava_event *lv)
{
    struct buff *bf = NULL;
    char *remote_ip = NULL;

    if (buff_new_priv(&bf, DEFAULT_RPC_EVENT_LEN) == NULL)
        goto mem_err;
    RLIST_INIT(bf, entry);

    if (lv->remote_addr.family) {
        size_t s_len;
        bool ipv4 = true;

        if (lv->remote_addr.family != AF_INET)
            ipv4 = false;

        s_len = ipv4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
        remote_ip = calloc(1, s_len + 1);
        if (remote_ip) {
            void *addr;

            addr = ipv4 ? (void *) &lv->remote_addr.ipv4 : (void *) &lv->remote_addr.ipv6;
            inet_ntop(lv->remote_addr.family, addr, remote_ip, s_len);
        }
    }

    if (buff_appendf(bf, "\"%u\",\"%u\",\"%hu\",\"%s\",\"%s\",\"%s\",\"%hu\",\"%s\",\"%hu\"",
            (unsigned) lv->flags, (unsigned) lv->conn_id, ntohs(lv->guest_port),
            lv->http_method ? lv->http_method : "",
            lv->http_domain ? lv->http_domain : "",
            lv->http_url ? lv->http_url : "",
            lv->http_port,
            remote_ip ? remote_ip : "",
            ntohs(lv->remote_port)) < 0) {

        goto mem_err;
    }

    free(remote_ip);
    remote_ip = NULL;

    critical_section_enter(&lava_list_lock);
    RLIST_INSERT_TAIL(&lava_rpc_list, bf, entry);
    lava_rpc_count++;
    critical_section_leave(&lava_list_lock);

    if (lava_rpc_count > NUMBER_EVENTS_TRIGGER)
        ioh_event_set(&lava_event);

    lv->internal |= LVI_SUBMITTED;
    lv->ni->number_lava_events++;
out:
    lv->internal &= ~LVI_STARTED;
    lv->flags &= ((~LVF_DENIED) & (~LVF_PROXY) & (~LVF_REMOTE_ESTABLISHED));
    ni_priv_free(lv->http_method);
    lv->http_method = NULL;
    ni_priv_free(lv->http_domain);
    lv->http_domain = NULL;
    ni_priv_free(lv->http_url);
    lv->http_url = NULL;
    lv->remote_port = 0;
    memset(&lv->remote_addr, 0, sizeof(lv->remote_addr));
    lv->http_port = 0;
    return;

mem_err:
    warnx("%s: malloc error", __FUNCTION__);
    buff_free(&bf);
    goto out;
}

struct lava_event *
lava_event_create(struct nickel *ni, struct sockaddr_in sa, struct sockaddr_in da, bool tcp)
{
    struct lava_event *lv = NULL;

    if (!lava_initialized || !ni->ac_event_log_enabled)
        goto out;

    lv = lv_create(ni);
    if (!lv)
         goto out;
    lv->internal |= LVI_STARTED;
    if (tcp)
        lv->flags |= LVF_TCP;
    lv->guest_port = sa.sin_port;
    lv->remote_addr.family = AF_INET;
    lv->remote_addr.ipv4 = da.sin_addr;
    lv->remote_port = da.sin_port;

    if ((da.sin_addr.s_addr & ni->network_mask.s_addr) == ni->network_addr.s_addr)
        lava_event_set_local(lv);
out:
    return lv;
}

void lava_event_set_denied(struct lava_event *lv)
{
    if (!lv)
        return;
    lv->internal |= LVI_STARTED;
    lv->flags |= LVF_DENIED;
}

void lava_event_set_local(struct lava_event *lv)
{
    if (!lv)
        return;
    lv->internal |= LVI_STARTED;
    lv->flags |= LVF_LOCAL;
}

void lava_event_set_proxy(struct lava_event *lv)
{
    if (!lv || !(lv->internal & LVI_CONNECTED))
        return;
    lv->internal |= LVI_STARTED;
    lv->flags |= LVF_PROXY;
}

void lava_event_set_established(struct lava_event *lv, uint32_t conn_id)
{
    if (!lv)
        return;
    lv->internal |= LVI_STARTED;
    if (!(lv->flags & LVF_ESTABLISHED)) {
        lv->flags |= LVF_ESTABLISHED;
        lv->conn_id = conn_id;
    }
}

void lava_event_set_http(struct lava_event *lv, const char *method,
        const char *domain, const char *url, uint16_t port)
{
    if (!lv)
        return;
    lv->internal |= LVI_STARTED;
    lv->flags |= LVF_GPROXY;
    if (lv->http_method)
        ni_priv_free(lv->http_method);
    lv->http_method = lv_encode_string(method, 128);
    if (lv->http_domain)
        ni_priv_free(lv->http_domain);
    lv->http_domain = lv_encode_string(domain, 256);
    if (lv->http_url)
        ni_priv_free(lv->http_url);
    lv->http_url = lv_encode_string(url, 256);
    lv->http_port = port;
}

void lava_event_remote_connect(struct lava_event *lv)
{
    if (!lv)
        return;
    lv->internal |= LVI_CONNECTED;
}

void lava_event_remote_disconnect(struct lava_event *lv)
{
    if (!lv || !(lv->internal & LVI_CONNECTED))
        return;
    if ((lv->internal & LVI_STARTED) && !lv->ni->lava_events_per_host)
        lv_submit_and_reset(lv);
    lv->internal &= ~LVI_CONNECTED;
}

void lava_event_remote_set(struct lava_event *lv, const struct net_addr *a, uint16_t port)
{
    if (!lv || !(lv->internal & LVI_CONNECTED))
        return;
    lv->internal |= LVI_STARTED;
    lv_set_remote(lv, a, port);
}

void lava_event_remote_established(struct lava_event *lv, struct net_addr *a, uint16_t port)
{
    if (!lv || !(lv->internal & LVI_CONNECTED))
        return;

    lv->internal |= LVI_STARTED;
    lv->flags |= LVF_REMOTE_ESTABLISHED;
    lv_set_remote(lv, a, port);
    lv_submit_and_reset(lv);
}

void lava_event_complete(struct lava_event *lv, bool del)
{
    if (!lv)
        return;

    if ((lv->internal & LVI_STARTED) && (!lv->ni->lava_events_per_host ||
         !(lv->internal & LVI_SUBMITTED))) {

        lv_submit_and_reset(lv);
    }
    if (del)
        lv_free(lv);
}

void lava_event_save_and_clear(QEMUFile *f, struct lava_event *lv)
{
    struct lava_event_sv lvs;

    memset(&lvs, 0, sizeof(lvs));
    lvs.internal = lv->internal;
    lvs.flags = lv->flags;
    lvs.conn_id = lv->conn_id;
    lvs.guest_port = lv->guest_port;
    lvs.remote_addr = lv->remote_addr;
    lvs.remote_port = lv->remote_port;

    qemu_put_be32(f, sizeof(lvs));
    qemu_put_buffer(f, (uint8_t *) &lvs, sizeof(lvs));

    lv_free(lv);
}

struct lava_event *
lava_event_restore(struct nickel *ni, QEMUFile *f)
{
    struct lava_event *lv = NULL;
    struct lava_event_sv lvs;
    unsigned len;

    len = qemu_get_be32(f);
    if (!len)
        goto out;
    if (len != sizeof(lvs)) {
        warnx("%s: expected len %u got %u", __FUNCTION__,
                (unsigned) sizeof(lvs), len);
        qemu_file_skip(f, len);
        goto consume;
    }

    qemu_get_buffer(f, (uint8_t *) &lvs, sizeof(lvs));
    lv = lv_create(ni);
    if (!lv)
        goto consume;
    lv->internal = lvs.internal;
    lv->internal &= (~LVI_CONNECTED) & (~LVI_STARTED);
    lv->flags = lvs.flags;
    lv->conn_id = lvs.conn_id;
    lv->guest_port = lvs.guest_port;
    lv->remote_addr = lvs.remote_addr;
    lv->remote_port = lvs.remote_port;
consume:
    while ((len = qemu_get_be32(f)))
        qemu_file_skip(f, len);
out:
    return lv;
}

void lava_flush(struct nickel *ni)
{
    if (!lava_initialized)
        return;

    ioh_event_reset(&lava_flushed_event);
    lava_flush_requested = 1;
    ioh_event_set(&lava_event);
    ioh_event_wait(&lava_flushed_event);
    NETLOG("%s: flushed", __FUNCTION__);
}

int lava_init(struct nickel *ni)
{
    critical_section_init(&lava_list_lock);
    memset(&lava_rpc_list, 0, sizeof(lava_rpc_list));
    RLIST_INIT(&lava_rpc_list, entry);
    ioh_event_init(&lava_event);
    ioh_event_init(&lava_flushed_event);
    if (!ioh_event_valid(&lava_event) || !ioh_event_valid(&lava_flushed_event)) {
        NETLOG("%s: FAILED to create event(s)", __FUNCTION__);
        goto error;
    }

    if (create_thread(&lava_thread, lava_thread_run, ni) < 0) {
        NETLOG("%s: FAILED to create thread", __FUNCTION__);
        goto error;
    }

    lava_initialized = true;
    ni->ac_event_log_enabled = 1;

    if (ni->lava_events_per_host)
        NETLOG("%s: reduced number of LAVA events (per remote connection)", __FUNCTION__);

    NETLOG("%s: Event Log enabled", __FUNCTION__);
    return 0;

error:
    return -1;
}

void lava_exit(struct nickel *ni)
{
    if (!lava_initialized)
        return;

    ni->ac_event_log_enabled = 0;
    lava_exit_requested = 1;
    ioh_event_set(&lava_event);
    wait_thread(lava_thread);

    lava_initialized = false;
    ioh_event_close(&lava_event);
    ioh_event_close(&lava_flushed_event);
    critical_section_free(&lava_list_lock);
    NETLOG("%s: exit #events %u", __FUNCTION__, (unsigned) ni->number_lava_events);
}
