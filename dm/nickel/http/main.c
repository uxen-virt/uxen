/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#if defined(_WIN32)
#define _POSIX
#endif
#include <time.h>
#include <sys/time.h>

#include <dm/queue2.h>
#include <dm/base64.h>
#include <dm/dict.h>
#include <dm/dict-rpc.h>
#include <dm/qemu_glue.h>
#include <dm/ns.h>
#include <dm/rbtree.h>
#include <dm/webdav.h>

#include <socket.h>
#include <nickel.h>
#include <buff.h>
#include <log.h>
#include <service.h>
#include <dns/dns.h>
#include <dns/dns-fake.h>
#include "access-control.h"
#include "strings.h"
#include "proxy.h"
#include "parser.h"
#include "auth.h"
#include "tls.h"
#include "rpc.h"
#include "ntlm.h"
#include "lava.h"

#define NTLM_MAKE_USERNAME_UPPERCASE
#define HP_IDLE_MAX_TIMEOUT         (60 * 1000) /* 60 secs */
#define HPD_DEBUG_CHECK_MS          (4 * 1000) /* 4 secs */
#define MAX_RETRY_HTTP_REQ          3

#define U32BF(a)            (((uint32_t) 1) << (a))
#define U64BF(a)            (((uint64_t) 1) << (a))

#define SO_READBUFLEN   (16 * 1024)
#define MAX_SRV_BUFLEN  (128 * 1024)
#define MIN_GUEST_BUF   (64 * 1024)
#define MAX_GUEST_BUF   (16 * 1024 * 1024)
#define MAX_SAVE_REQ_PRX (512 * 1024)
#define BUF_CHUNK   (2 * 1024)

#define SO_STATE_MAP(XX)                \
    XX(0, INIT)                         \
    XX(1, RESOLVED)                     \
    XX(2, RECONNECT)                    \
    XX(3, CONNECTING)                   \
    XX(4, CONNECTED)

enum so_state_t {
#define XX(num, name) S_##name = num,
  SO_STATE_MAP(XX)
#undef XX
};

static const char *so_states[] = {
#define XX(num, name) #name,
    SO_STATE_MAP(XX)
#undef XX
};

#define HP_STATE_MAP(XX)                \
    XX(0,  NEW)                         \
    XX(1,  GET_REQUEST)                 \
    XX(2,  RESPONSE)                    \
    XX(3,  RESPONSE_CONSUME)            \
    XX(4,  AUTH_TRY)                    \
    XX(5,  AUTH_SEND)                   \
    XX(6,  AUTHENTICATED)               \
    XX(7,  WAIT)                        \
    XX(8,  PASS)                        \
    XX(9,  GPDIRECT)               \
    XX(10, TUNNEL)                      \
    XX(11, FLUSH_CLOSE)                 \
    XX(12, IGNORE)

enum hp_state_t {
#define XX(num, name) HP_##name = num,
  HP_STATE_MAP(XX)
#undef XX
};

enum cx_save_state {
    CXSV_CONTINUE = 0, /* needs to be 0 */
    CXSV_RESET,
    CXSV_CONNFAILED,

    CXSV_LAST_STATE
};

static const char *hp_states[] = {
#define XX(num, name) #name,
    HP_STATE_MAP(XX)
#undef XX
};

#define GET_CONST_SCHEMA(s)                       \
    (strcasecmp("http", s) == 0  ? "http" :       \
    (strcasecmp("https", s) == 0 ? "https" :      \
    (strcasecmp("ftp", s) == 0   ? "ftp" : NULL)))

#define HF_TUNNEL           U32BF(0)
#define HF_TLS              U32BF(1)
#define HF_NEEDS_RECONNECT  U32BF(2)
#define HF_RESP_RECEIVED    U32BF(3)
#define HF_RESP_WAITING     U32BF(4)
#define HF_SRV_SUSPENDED    U32BF(5)
#define HF_CLT_SUSPENDED    U32BF(6)
#define HF_TLS_CERT_DONE    U32BF(7)
#define HF_READ_PENDING     U32BF(8)
#define HF_CLT_FIN          U32BF(9)
#define HF_CLT_FIN_OK       U32BF(10)
#define HF_407_MESSAGE      U32BF(11)
#define HF_407_MESSAGE_OK   U32BF(12)
#define HF_CLOSED           U32BF(13)
#define HF_RESOLVED         U32BF(14)
#define HF_BINARY_STREAM    U32BF(15)
#define HF_HTTP_CLOSE       U32BF(16)
#define HF_CLOSING          U32BF(17)
#define HF_REUSABLE         U32BF(18)
#define HF_REUSE_READY      U32BF(19)
#define HF_RESTARTABLE      U32BF(20)
#define HF_RESTART_OK       U32BF(21)
#define HF_IP_CHECKED       U32BF(22)
#define HF_LAVA_STUB_SENT   U32BF(23)
#define HF_PINNED           U32BF(24)
#define HF_KEEP_ALIVE       U32BF(25)
#define HF_FATAL_ERROR      U32BF(26)
#define HF_PARSE_ERROR      U32BF(27)
#define HF_SAVE_REQ_RTRY    U32BF(28)
#define HF_SAVE_REQ_PRX     U32BF(29)
#define HF_MONITOR_407      U32BF(30)

#define IS_RESOLVED(hp) ((hp)->flags & HF_RESOLVED)
#define IS_TUNNEL(hp)   ((hp)->flags & HF_TUNNEL)
#define IS_LONGREQ(hp)  ((hp)->cx && ((hp)->cx->flags & CXF_LONG_REQ))

#define HMSG_DNS_LOOKUP_FAILED  1
#define HMSG_CONNECT_FAILED     2
#define HMSG_BAD_REQUEST        3
#define HMSG_CONNECT_OK         4
#define HMSG_CONNECT_ABORTED_SSL    5
#define HMSG_CONNECT_DENIED     6

#define TLS_HANDSHAKE_STEP(hp) (((hp)->flags & HF_TLS) && !((hp)->flags &   \
            HF_TLS_CERT_DONE) && (!(hp)->proxy || (IS_TUNNEL(hp) &&         \
            (hp)->hstate == HP_TUNNEL)))

#define STAT_PRINT_MS   (10 * 1000)

/* DEBUG */
#define HLOG0(ll, fmt, ...) do {                                               \
            if (NLOG_LEVEL < ll) break;                                        \
            dbg_hp(ll, hp);                                                    \
            buff_appendf(hp->ni->bf_dbg, " [%s] " fmt "\n",  __FUNCTION__,     \
                    ## __VA_ARGS__);                                           \
            fwrite(BUFF_CSTR(hp->ni->bf_dbg), hp->ni->bf_dbg->len, 1, stderr); \
        } while (1 == 0)

#define HLOG(fmt, ...) HLOG0(1, fmt, ## __VA_ARGS__)
#define HLOG2(fmt, ...) HLOG0(2, fmt, ## __VA_ARGS__)
#define HLOG3(fmt, ...) HLOG0(3, fmt, ## __VA_ARGS__)
#define HLOG4(fmt, ...) HLOG0(4, fmt, ## __VA_ARGS__)
#define HLOG5(fmt, ...) HLOG0(5, fmt, ## __VA_ARGS__)
#define HLOG6(fmt, ...) HLOG0(6, fmt, ## __VA_ARGS__)

#define CXL0(ll, fmt, ...) do {                                                \
            if (NLOG_LEVEL < ll) break;                                        \
            cx_dbg(ll, cx);                                                    \
            buff_appendf(cx->ni->bf_dbg, " [%s] - " fmt "\n",  __FUNCTION__,     \
                    ## __VA_ARGS__);                                           \
            fwrite(BUFF_CSTR(cx->ni->bf_dbg), cx->ni->bf_dbg->len, 1, stderr); \
        } while (1 == 0)

#define CXL(fmt, ...)  CXL0(1, fmt, ## __VA_ARGS__)
#define CXL2(fmt, ...) CXL0(2, fmt, ## __VA_ARGS__)
#define CXL3(fmt, ...) CXL0(3, fmt, ## __VA_ARGS__)
#define CXL4(fmt, ...) CXL0(4, fmt, ## __VA_ARGS__)
#define CXL5(fmt, ...) CXL0(5, fmt, ## __VA_ARGS__)
#define CXL6(fmt, ...) CXL0(6, fmt, ## __VA_ARGS__)

#define HR(ll, fmt, ...) HLOG0(ll, "%d " fmt, ret, ## __VA_ARGS__)
#define HLOG_DMP(bbf, bbl)                                        \
    do {                                                        \
        HLOG("DMP:");                                           \
        if (bbf)                                                \
            netlog_print_esc(NULL, bbf, bbl);                   \
    } while (1 == 0)

#define CXF_HOST_RESOLVED       U64BF(0)
#define CXF_NI_ESTABLISHED      U64BF(1)
#define CXF_NI_FIN              U64BF(2)
#define CXF_FLUSH_CLOSE         U64BF(3)
#define CXF_PRX_DECIDED         U64BF(4)
#define CXF_GUEST_PROXY         U64BF(5)
#define CXF_SUSPENDED           U64BF(6)
#define CXF_TUNNEL_GUEST        U64BF(7)
#define CXF_IGNORE              U64BF(8)
#define CXF_407_MESSAGE         U64BF(9)
#define CXF_RPC_PROXY_URL       U64BF(10)
#define CXF_TUNNEL_DETECTED     U64BF(11)
#define CXF_TUNNEL_RESPONSE     U64BF(12)
#define CXF_TUNNEL_RESPONSE_OK  U64BF(13)
#define CXF_CLOSED              U64BF(14)
#define CXF_TLS                 U64BF(15)
#define CXF_HTTP                U64BF(16)
#define CXF_BINARY              U64BF(17)
#define CXF_TLS_DETECT_OK       U64BF(18)
#define CXF_HEADERS_OK          U64BF(19)
#define CXF_LONG_REQ            U64BF(20)
#define CXF_PROXY_SUSPEND       U64BF(21)
#define CXF_CLOSING             U64BF(22)
#define CXF_ACCEPTED            U64BF(23)
#define CXF_GPROXY_REQUEST      U64BF(25)
#define CXF_FORCE_CLOSE         U64BF(26)
#define CXF_HEAD_REQUEST        U64BF(27)
#define CXF_HEAD_REQUEST_SENT   U64BF(28)
#define CXF_TUNNEL_GUEST_SENT   U64BF(29)
#define CXF_LOCAL_WEBDAV        U64BF(30)
#define CXF_LOCAL_WEBDAV_COMPLETE   U64BF(31)
#define CXF_RESET_STATE             U64BF(32)

struct hpd_t;
RLIST_HEAD(http_ctx_list, http_ctx);
struct http_ctx {
    LIST_ENTRY(http_ctx) entry;
    RLIST_ENTRY(http_ctx_list) direct_hp_list;
    struct hpd_t *hpd;
    struct nickel *ni;
    struct clt_ctx *cx;
    struct socket *so;
    struct http_server h;
    struct net_addr *a;
    enum so_state_t cstate;
    enum hp_state_t hstate;
    enum hp_state_t hwait_state;
    uint32_t flags;
    int http_req_rtry_cnt;
    struct buff *clt_out;
    struct buff *c407_buff;

    struct http_auth *auth;
    struct proxy_t *proxy;
    struct tls_state_t *tls;

    uint32_t refcnt;
    int64_t idle_ts;

#if VERBSTATS
    int64_t srv_ts;
    uint32_t clt_bytes;
    uint32_t srv_bytes;
    uint32_t srv_lat[LAT_STAT_NUMBER * 2];
    int srv_lat_idx;
#endif
};

struct dns_connect_ctx {
    struct http_ctx *hp;
    char *domain;
    uint16_t port;
    int containment_check;
    int proxy_on;
    struct dns_response response;
};

struct hpd_t {
    LIST_ENTRY(hpd_t) entry;
    struct nickel *ni;
    struct http_ctx direct_hp_list;
    struct clt_ctx direct_cx_list;
    struct http_ctx *hp;
    int nr_hp;
    int nr_cx;
    int needs_continue;
    struct rb_node hpd_rbnode;
};

static int64_t prx_refresh_id = 0;
static int max_socket_per_proxy = 12;
static char *webdav_host_dir = NULL;
static Timer *hp_idle_timer = NULL;
static int disable_crl_check = 0;
static int no_transparent_proxy = 0;
static rb_tree_t hpd_rbtree;
static int hpd_rbtree_init = 0;
static int hpd_needs_continue = 0;
static Timer *hpd_debug_timer = NULL;

static void hp_get(struct http_ctx *hp);
static void hp_put(struct http_ctx *hp);
static void hp_free(struct http_ctx *hp);
static CharDriverState *
cx_accept(void *opaque, struct nickel *ni, struct socket *so);
static int srv_write(struct http_ctx *hp, const uint8_t *b, size_t blen);
static int srv_connect(struct http_ctx *hp, const struct net_addr *a, uint16_t port);
static int srv_connect_ipv4(struct http_ctx *hp, uint32_t srv_addr, uint16_t srv_port);
static int srv_connect_list(struct http_ctx *hp, struct net_addr *a, uint16_t srv_port);
static int srv_connect_direct(struct http_ctx *hp);
static int srv_connect_dns_direct(struct http_ctx *hp);
static int srv_connect_dns_resolved(struct http_ctx *hp, struct net_addr *a);
static int srv_connect_proxy(struct http_ctx *hp, struct proxy_t *proxy);
static void srv_response_received(struct http_ctx *hp);
static int srv_reconnect(struct http_ctx *hp);
static void rpc_user_agent_cb(void *opaque, dict d);
static int rpc_connect_proxy(struct http_ctx *hp, const char *in_server, uint16_t port,
        struct proxy_t *bad_proxy, const char *alternative_proxies);
static void rpc_on_event(void *opaque);
static int create_http_header(bool prx_auth, const char *sv_name, int use_head, uint16_t sv_port,
        struct http_header *horig, struct http_header *hadd, struct buff **pbuf);
static int create_connect_header(char *prev_connect_headers, const char *sv_name,
                                 uint16_t sv_port, struct http_header *hadd, struct buff **pbuf);
static void on_fakeip_blocked(struct in_addr addr);
static void on_fakeip_update(struct in_addr fkaddr, struct net_addr *a);
static int prompt_credentials(struct http_ctx *hp);
static void set_settings(struct nickel *ni, yajl_val config);
static int start_authenticate(struct http_ctx *hp);
static void wakeup_client(struct http_ctx *hp);
static int dns_connect_proxy_async(struct http_ctx *hp);
static void dns_lookup_sync(void *opaque);
static int dbg_hp(int log_level, struct http_ctx *hp);

static CharDriverState *
ns_cx_open(void *opaque, struct nickel *ni, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr, yajl_val config);
static CharDriverState *
cx_open(void *opaque, struct nickel *ni, struct sockaddr_in saddr, struct sockaddr_in daddr);
static void cx_close(struct clt_ctx *cx);
static void cx_free(struct clt_ctx *cx);
static void cx_get(struct clt_ctx *cx);
static void cx_put(struct clt_ctx *cx);
static int cx_parser_create_request(struct clt_ctx *cx);
static int cx_proxy_decide(struct clt_ctx *cx);
static void cx_proxy_set(struct clt_ctx *cx, struct proxy_t *proxy);
static int cx_chr_can_read(void *opaque);
static int cx_chr_can_write(void *opaque);
static ssize_t cx_write(struct clt_ctx *cx, uint8_t *p, size_t l);
static void cx_chr_read(void *opaque, const uint8_t *buf, int size);
static int cx_chr_write(CharDriverState *chr, const uint8_t *buf, int len_buf);
static void cx_chr_event(CharDriverState *chr, int event);
static struct clt_ctx * cx_create(struct nickel *ni);
static int cx_guest_write(struct clt_ctx *cx);
static int cx_hp_connect(struct clt_ctx *cx, bool *connect_now);
static int cx_hp_disconnect(struct clt_ctx *cx);
static int on_cx_hp_connect(struct clt_ctx *cx);
static void cx_lava_connect(struct clt_ctx *cx);
static int cx_process(struct clt_ctx *cx, const uint8_t *buf, int len_buf);
static int cx_proxy_response(struct clt_ctx *cx, int msg, bool close);
static int cx_srv_fin(struct clt_ctx *cx);
static int cx_dbg(int log_level, struct clt_ctx *cx);
static int cx_webdav_process(struct clt_ctx *cx, const uint8_t *buf, int len_buf);
static void hp_close(struct http_ctx *hp);
static int hp_connecting_containment(struct http_ctx *hp, const struct net_addr *a, uint16_t port);
static int hp_cx_connect_buffs(struct http_ctx *hp, bool sep_out);
static int hp_cx_connect_next(struct http_ctx *hp, struct proxy_t *proxy);
static struct http_ctx * cx_hp_connect_proxy(struct clt_ctx *cx);
static void hp_cx_buf_ready(struct http_ctx *hp);
static int hp_clt_process(struct http_ctx *hp, const uint8_t *buf, int len_buf);
static void hp_event(void *opaque, uint32_t evt, int err);
static int hp_srv_process(struct http_ctx *hp);
static void proxy_connect_cx_next(struct proxy_t *proxy);
static void proxy_wakeup_list(struct proxy_t *proxy);

static void cx_remove_hpd(struct clt_ctx *cx);
static struct hpd_t * hp_create_hpd(struct http_ctx *hp);
static void hp_remove_hpd(struct http_ctx *hp);
static void hpd_add_cx(struct hpd_t *hpd, struct clt_ctx *cx);
static void hpd_add_hp(struct hpd_t *hpd, struct http_ctx *hp);
static void hpd_cleanup(struct hpd_t *hpd);
static void hpd_cx_continue(struct hpd_t *hpd);
static int hpd_compare_key(void *ctx, const void *b, const void *key);
static int hpd_compare_nodes(void *ctx, const void *parent, const void *node);

static LIST_HEAD(, http_ctx) http_list = LIST_HEAD_INITIALIZER(&http_list);
static LIST_HEAD(, clt_ctx) cx_list = LIST_HEAD_INITIALIZER(&cx_list);
static LIST_HEAD(, http_ctx) http_gc_list = LIST_HEAD_INITIALIZER(&http_gc_list);
static LIST_HEAD(, clt_ctx) cx_gc_list = LIST_HEAD_INITIALIZER(&cx_gc_list);
static LIST_HEAD(, hpd_t) hpd_list = LIST_HEAD_INITIALIZER(&hpd_list);

static char *user_agent = NULL;
static const char *hc_prx_srv = NULL;
static uint32_t hc_prx_addr = 0;
static uint16_t hc_prx_port = 0;
struct ntlm_ctx *custom_ntlm = NULL;
static const rb_tree_ops_t hpd_rbtree_ops = {
    .rbto_compare_nodes = hpd_compare_nodes,
    .rbto_compare_key = hpd_compare_key,
    .rbto_node_offset = offsetof(struct hpd_t, hpd_rbnode),
    .rbto_context = NULL
};

#if defined(_WIN32)
#define _POSIX
#endif
#include <time.h>
#include <sys/time.h>
static int dbg_hp(int log_level, struct http_ctx *hp)
{
    int ret = -1;
    struct tm _tm, *tm;
    time_t ltime;
    struct timeval tv;
    char prefix[3 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 1 + 1];

    if (!hp)
        goto out;

    BUFF_RESET(hp->ni->bf_dbg);
    gettimeofday(&tv, NULL);
    ltime = (time_t)tv.tv_sec;
    tm = localtime_r(&ltime, &_tm);
    if (tm) {
        snprintf(prefix, sizeof(prefix), "%03d-%02d:%02d:%02d.%03d ",
                 tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec,
                 (int)(tv.tv_usec / 1000));
        BUFF_APPENDSTR(hp->ni->bf_dbg, prefix);
    }
    netlog_prefix(log_level, hp->ni->bf_dbg);
    BUFF_APPENDSTR(hp->ni->bf_dbg, "(svr)");
    if (hp->so && so_dbg(hp->ni->bf_dbg, hp->so) < 0)
        goto out;
    ret = buff_appendf(hp->ni->bf_dbg, " hp:%" PRIxPTR " cx:%" PRIxPTR " so:%"
            PRIxPTR " hpd:%"PRIxPTR " f:%x %s %s %s p:%hu %s",
            (uintptr_t) hp, (uintptr_t) hp->cx, (uintptr_t) hp->so, (uintptr_t) hp->hpd, hp->flags,
            so_states[hp->cstate],
            hp_states[hp->hstate], hp->hstate == HP_WAIT ? hp_states[hp->hwait_state] : "",
            ntohs(hp->h.daddr.sin_port), log_level > 4 && hp->h.sv_name ? hp->h.sv_name : "");
out:
    return ret;
}

static int cx_dbg(int log_level, struct clt_ctx *cx)
{
    int ret = -1;
    struct tm _tm, *tm;
    time_t ltime;
    struct timeval tv;
    char prefix[3 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 1 + 1];

    if (!cx)
        goto out;

    BUFF_RESET(cx->ni->bf_dbg);
    gettimeofday(&tv, NULL);
    ltime = (time_t)tv.tv_sec;
    tm = localtime_r(&ltime, &_tm);
    if (tm) {
        snprintf(prefix, sizeof(prefix), "%03d-%02d:%02d:%02d.%03d ",
                 tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec,
                 (int)(tv.tv_usec / 1000));
        BUFF_APPENDSTR(cx->ni->bf_dbg, prefix);
    }
    netlog_prefix(log_level, cx->ni->bf_dbg);
    BUFF_APPENDSTR(cx->ni->bf_dbg, "(clt)");
    ret = buff_appendf(cx->ni->bf_dbg, " cx:%"PRIxPTR" hp:%"PRIxPTR" tcp:%"PRIxPTR
            " c:%"PRIxPTR" hpd:%"PRIxPTR" f:%"PRIx64" p:%hu %s",
            (uintptr_t) cx, (uintptr_t) cx->hp, (uintptr_t) cx->ni_opaque,
            (uintptr_t) cx->chr, (uintptr_t) cx->hpd, cx->flags, ntohs(cx->h.daddr.sin_port),
            log_level > 4 && cx->h.sv_name ? cx->h.sv_name : "");

out:
    return ret;
}

static void hpd_debug_timer_cb(void *unused)
{
    int64_t now = get_clock_ms(rt_clock);
    struct http_ctx *hp;
    bool print_once = false;

    LIST_FOREACH(hp, &http_list, entry) {
        if (hp->hpd && hp->hpd->hp == hp) {
            struct hpd_t *hpd = hp->hpd;


            if (!print_once) {
                NETLOG("--- HPD stats ---");
                print_once = true;
            }

            NETLOG("%s%s:%hu #hp %d #cx %d", hpd->nr_cx > 0 ? " -> " : "",
                    hp->h.sv_name ? hp->h.sv_name : "-",
                    ntohs(hp->h.daddr.sin_port), (int) hpd->nr_hp, (int) hpd->nr_cx);
        }
    }

    if (print_once)
        NETLOG("--- HPD END ---");

    if (hpd_debug_timer)
        mod_timer(hpd_debug_timer, now + HPD_DEBUG_CHECK_MS);
}

static int hpd_compare_key(void *ctx, const void *b, const void *key)
{
    const struct hpd_t *hpd = b;
    const struct http_server *hk = key;
    const struct http_server *hn;

    assert(hpd->hp);
    hn = &(hpd->hp->h);

    if (hk->daddr.sin_port > hn->daddr.sin_port)
        return 1;
    else if (hk->daddr.sin_port < hn->daddr.sin_port)
        return -1;
    if (!hk->sv_name && !hn->sv_name)
        return 0;
    if (!hk->sv_name)
        return -1;
    if (!hn->sv_name)
        return 1;
    return strcasecmp(hk->sv_name, hn->sv_name);
}

static int hpd_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct hpd_t * const hpd = node;

    assert(hpd->hp);
    return hpd_compare_key(ctx, parent, &(hpd->hp->h));
}

static void hpd_cleanup(struct hpd_t *hpd)
{
    if (!hpd->hp) {
        if (RLIST_EMPTY(&hpd->direct_hp_list, direct_hp_list)) {
            struct clt_ctx *cx, *_cx;

            RLIST_FOREACH_SAFE(cx, &hpd->direct_cx_list, direct_cx_list, _cx) {
                RLIST_REMOVE(cx, direct_cx_list);
                hpd->nr_cx--;
                cx->hpd = NULL;
                cx_process(cx, NULL, 0);
            }

            rb_tree_remove_node(&hpd_rbtree, hpd);
            LIST_REMOVE(hpd, entry);
            NETLOG5("HPD %"PRIxPTR " FREED", (uintptr_t) hpd);
            free(hpd);
            return;
        }

        hpd->hp = RLIST_FIRST(&hpd->direct_hp_list, direct_hp_list);
    }

    hpd_needs_continue = 1;
    hpd->needs_continue = 1;
    ni_wakeup_loop(hpd->ni);
}

static void hpd_add_cx(struct hpd_t *hpd, struct clt_ctx *cx)
{
    if (!RLIST_EMPTY(cx, direct_cx_list))
        return;
    assert(!cx->hpd);
    CXL5("WLIST ADD N %d HPD %"PRIxPTR, hpd->nr_cx, (uintptr_t) hpd);
    RLIST_INSERT_TAIL(&hpd->direct_cx_list, cx, direct_cx_list);
    cx->hpd = hpd;
    hpd->nr_cx++;
}

static void cx_remove_hpd(struct clt_ctx *cx)
{
    if (RLIST_EMPTY(cx, direct_cx_list))
        return;
    assert(cx->hpd);
    RLIST_REMOVE(cx, direct_cx_list);
    cx->hpd->nr_cx--;
    CXL5("HPD %"PRIxPTR " WLIST REMOVE N %d", (uintptr_t) cx->hpd, cx->hpd->nr_cx);
    hpd_cleanup(cx->hpd);
    cx->hpd = NULL;
}

static void hpd_add_hp(struct hpd_t *hpd, struct http_ctx *hp)
{
    if (hp->hpd == hpd || !RLIST_EMPTY(hp, direct_hp_list))
        return;
    assert(!hp->hpd);
    HLOG5("WLIST ADD N %d HPD %"PRIxPTR, hpd->nr_hp, (uintptr_t) hpd);
    RLIST_INSERT_TAIL(&hpd->direct_hp_list, hp, direct_hp_list);
    hp->hpd = hpd;
    hpd->nr_hp++;
    if (!hpd->hp)
        hpd->hp = hp;
}

static void hp_remove_hpd(struct http_ctx *hp)
{
    if (RLIST_EMPTY(hp, direct_hp_list))
        return;

    assert(hp->hpd);
    RLIST_REMOVE(hp, direct_hp_list);
    hp->hpd->nr_hp--;
    HLOG5("HPD %"PRIxPTR " WLIST REMOVE N %d", (uintptr_t) hp->hpd, hp->hpd->nr_hp);
    if (hp->hpd->hp == hp)
        hp->hpd->hp = NULL;
    hpd_cleanup(hp->hpd);
    hp->hpd = NULL;
}

static struct hpd_t *
hp_create_hpd(struct http_ctx *hp)
{
    struct hpd_t *hpd;

    hpd = calloc(1, sizeof(*hpd));
    if (!hpd) {
        warnx("%s: malloc", __FUNCTION__);
        goto cleanup;
    }
    hpd->ni = hp->ni;
    LIST_INSERT_HEAD(&hpd_list, hpd, entry);
    RLIST_INIT(&hpd->direct_cx_list, direct_cx_list);
    RLIST_INIT(&hpd->direct_hp_list, direct_hp_list);

    assert(RLIST_EMPTY(hp, direct_hp_list));
    assert(!hp->hpd);
    hpd_add_hp(hpd, hp);
    if (rb_tree_insert_node(&hpd_rbtree, hpd) != hpd)
        goto cleanup;

    HLOG5("HPD %"PRIxPTR " CREATE", (uintptr_t) hpd);
    return hpd;
cleanup:
    if (hpd) {
        if (!RLIST_EMPTY(hp, direct_hp_list))
            RLIST_REMOVE(hp, direct_hp_list);
        hp->hpd = NULL;
        LIST_REMOVE(hpd, entry);
        free(hpd);
    }
    return NULL;
}

static void hpd_cx_continue(struct hpd_t *hpd)
{
    struct clt_ctx *cx;

    if (RLIST_EMPTY(&hpd->direct_cx_list, direct_cx_list))
        return;
    cx = RLIST_FIRST(&hpd->direct_cx_list, direct_cx_list);
    RLIST_REMOVE(cx, direct_cx_list);
    hpd->nr_cx--;
    cx->hpd = NULL;
    CXL5("HPD %"PRIxPTR " CONTINUE", (uintptr_t) hpd);
    cx_process(cx, NULL, 0);
}

static int prepare_clt_auth(struct http_ctx *hp)
    {
    int ret = -1;

    assert(hp->proxy);
    if (!hp->auth && !(hp->auth = http_auth_create(hp->ni, hp, hp->proxy)))
            goto out;

    if (http_auth_clt(hp->auth))
        goto out;

    ret = 0;
out:
    return ret;
}

static int prepare_clt_out(struct http_ctx *hp, bool prx_auth)
{
    int ret = -1;
    size_t len = 256;
    struct http_header *auth_header = NULL;
    size_t hlen = 0;
    bool appended = false;
    bool use_head = false;

    if (prx_auth && IS_LONGREQ(hp) && hp->auth && (!hp->auth->type || !hp->auth->last_step))
        use_head = true;
    HLOG5("use_head %d", use_head ? 1 : 0);

    assert(hp->cx);

    hp->cx->flags &= ~CXF_HEAD_REQUEST_SENT;
    if (prx_auth) {
        assert(hp->auth);
        auth_header = hp->auth->auth_header;
    }
    if (!hp->cx->srv_parser && parser_create_response(&hp->cx->srv_parser, hp->cx))
        goto out;
    parser_reset(hp->cx->srv_parser);
    assert(IS_TUNNEL(hp) || hp->cx->clt_parser);
    if (!IS_TUNNEL(hp)) {
        len += hp->cx->clt_parser->h.hint_size;
        hlen = hp->cx->clt_parser->h.header_length;
    }
    if (!hp->clt_out && !BUFF_NEW_MX_PRIV(&hp->clt_out, len, MIN_GUEST_BUF))
        goto out;

    assert(hp->clt_out != hp->cx->in);
    BUFF_RESET(hp->clt_out);
    if (IS_TUNNEL(hp)) {
        if (create_connect_header(hp->cx->connect_header_lines, hp->h.sv_name, hp->h.daddr.sin_port, auth_header, &hp->clt_out))
            goto out;
    } else {
        if (create_http_header(prx_auth, hp->h.sv_name, use_head,
                     hp->h.daddr.sin_port, &hp->cx->clt_parser->h, auth_header, &hp->clt_out))
            goto out;
        if (use_head) {
            hp->cx->flags |= CXF_HEAD_REQUEST;
            HLOG5("CXF_HEAD_REQUEST");
        }
    }

    if (!IS_TUNNEL(hp) && !IS_LONGREQ(hp) && hp->cx->in && hp->cx->in->len &&
            BUFF_APPENDB(hp->clt_out, hp->cx->in) < 0)
        goto out;

    /* body data ? */
    if (!appended && !IS_TUNNEL(hp) && !IS_LONGREQ(hp) && hp->cx->in && BUFF_BUFFERED(hp->cx->in) > hlen) {
        if (BUFF_APPENDFROM(hp->clt_out, hp->cx->in, hlen) < 0)
            goto out;
        appended = true;
    }

    if (!prx_auth) {
        if (!appended && hp->cx->in && BUFF_BUFFERED(hp->cx->in) > hlen) {
            if (BUFF_APPENDFROM(hp->clt_out, hp->cx->in, hlen) < 0)
                goto out;
            appended = true;
        }

        if (hp->cx->in)
            buff_put(hp->cx->in);
        buff_get(hp->clt_out);
        hp->cx->in = hp->clt_out;
        BUFF_UNCONSUME(hp->clt_out);
        wakeup_client(hp);

        goto out_ok;
    }

    if (!IS_TUNNEL(hp) && !use_head && IS_LONGREQ(hp) && hp->auth->last_step) {
        if (!appended && hp->cx->in && BUFF_BUFFERED(hp->cx->in) > hlen) {
            if (BUFF_APPENDFROM(hp->clt_out, hp->cx->in, hlen) < 0)
                goto out;
            appended = true;
        }
        buff_put(hp->cx->in);
        buff_get(hp->clt_out);
        hp->cx->in = hp->clt_out;
        hp->hstate = HP_AUTH_TRY;
        if (hp->auth->authorized) {
            hp->hstate = HP_AUTHENTICATED;
            start_authenticate(hp);
        }
        wakeup_client(hp);
    }

out_ok:
    ret = 0;
out:
    if (hp->clt_out)
        HLOG5("clt_out has %d bytes buffered", (int) BUFF_BUFFERED(hp->clt_out));
    return ret;
}

static int start_direct(struct http_ctx *hp)
{
    int ret = -1;

    assert(hp->cx);

    http_auth_free(&hp->auth);
    if (hp_cx_connect_buffs(hp, false) < 0)
        goto out;

    assert(hp->clt_out);
    BUFF_UNCONSUME(hp->clt_out);

    ret = 0;
out:
    return ret;
}

static int start_gproxy_direct(struct http_ctx *hp)
{
    int ret = -1;

    assert(hp->cx);

    http_auth_free(&hp->auth);
    if (hp_cx_connect_buffs(hp, true) < 0)
        goto out;

    if (cx_parser_create_request(hp->cx))
        goto out;
    if (hp->cx->srv_parser)
        parser_reset(hp->cx->srv_parser);
    assert(hp->clt_out);
    BUFF_RESET(hp->clt_out);

    ret = 0;
out:
    return ret;
}

static int start_authenticate(struct http_ctx *hp)
{
    http_auth_reset(hp->auth);

    if (hp->cx) {
        hp->cx->flags &= ~CXF_PROXY_SUSPEND;

        /* in case of an unexpected 407 */
        if (hp->proxy && (hp->cx->flags & CXF_GUEST_PROXY))
            hp->flags |= (HF_MONITOR_407 | HF_SAVE_REQ_PRX);
    }
    return hp_cx_connect_buffs(hp, false);
}

static int start_http(struct http_ctx *hp)
{
    int ret = -1;

    if (hp->cx)
        hp->cx->flags |= CXF_PROXY_SUSPEND;
    if (hp_cx_connect_buffs(hp, true) < 0)
        goto out;
    assert(hp->cx && hp->cx->in);
    if (hp->proxy && !hp->auth) {
        assert(hp->proxy->name);
        hp->auth = http_auth_create(hp->ni, hp, hp->proxy);
        if (!hp->auth)
            goto out;
    }
    if (hp->cx->srv_parser)
        parser_reset(hp->cx->srv_parser);

    ret = 0;
out:
    return ret;
}

static int start_tunnel(struct http_ctx *hp)
{
    int ret = -1;

    assert(hp->cx);
    assert(hp->cx->in);
    HLOG5("TUNNEL");
    if (hp->cx->out)
        BUFF_RESET(hp->cx->out);
    if (hp_cx_connect_buffs(hp, false) < 0)
        goto out;
    if (hp->clt_out)
        BUFF_UNCONSUME(hp->clt_out);
    srv_write(hp, NULL, 0);
    if (hp->clt_out && hp->clt_out->size < BUF_CHUNK)
        buff_adj(hp->clt_out, BUF_CHUNK);
    if (hp->clt_out->mx_size < MIN_GUEST_BUF)
        hp->clt_out->mx_size = MIN_GUEST_BUF;
    hp->flags |= HF_BINARY_STREAM;
    if (hp->cx->clt_parser)
        parser_free(&hp->cx->clt_parser);
    if (hp->cx->srv_parser)
        parser_free(&hp->cx->srv_parser);
    if (hp->auth)
        http_auth_free(&hp->auth);
    free(hp->cx->connect_header_lines);
    hp->cx->connect_header_lines = NULL;
    ret = 0;
out:
    return ret;
}

static int end_407_message(struct http_ctx *hp)
{
    struct clt_ctx *cx;

    cx = hp->cx;
    if (!cx)
        return -1;

    assert((hp->flags & (HF_407_MESSAGE | HF_407_MESSAGE_OK)) ==
           (HF_407_MESSAGE | HF_407_MESSAGE_OK));
    assert(hp->c407_buff);

    /* replace "HTTP 407" with "HTTP 200", not to confuse the guest browser */
    do {
        char *s, *p, *q;

        s = BUFF_BEGINNING(hp->c407_buff);
        p = strchr(s, '\r');
        if (!p)
            break;
        q = strchr(s, ' ');
        if (!q || q - s > p - s)
            break;
        q = strstr(q, "407");
        if (q) {
            if (q - s > p - s)
                break;
            memcpy(q, "200", 3);
        }
    } while (1 == 0);

    if (cx->out) {
        buff_put(cx->out);
        cx->out = NULL;
    }
    cx->out = hp->c407_buff;
    hp->c407_buff = NULL;

    if (cx->hp) {
        if (cx->hp->cx == cx) {
            cx_put(cx->hp->cx);
            cx->hp->cx = NULL;
        }
        hp_put(cx->hp);
        hp_close(cx->hp);
        cx->hp = NULL;
    }

    cx->flags |= (CXF_FLUSH_CLOSE | CXF_IGNORE);
    cx->flags &= ((~CXF_SUSPENDED) & (~CXF_PROXY_SUSPEND));
    BUFF_CONSUME_ALL(cx->out);

    return cx_guest_write(cx);
}

static int start_407_message(struct http_ctx *hp)
{
    int ret = 0;

    if (!hp->cx)
        goto out_close;
    hp->flags |= HF_407_MESSAGE;
    if (!hp->cx->in || IS_TUNNEL(hp) || (hp->flags & HF_TLS))
        goto out_close;

    hp->cx->flags |= CXF_PROXY_SUSPEND;

    if ((hp->flags & HF_407_MESSAGE_OK)) {
        end_407_message(hp);
        goto out_close;
    }

out:
    return ret;
out_close:
    hp_close(hp);
    ret = -1;
    goto out;
}

static int add_headers(struct buff *buf, struct http_header *h, bool use_head, bool prx_headers)
{
    int i, ret = -1;

    for (i = 0; i <= h->crt_header; i++) {
        if (!h->headers[i].name || !h->headers[i].name->len ||
            !h->headers[i].value)
            continue;
        if (use_head && !strcasecmp(BUFF_CSTR(h->headers[i].name), S_HEADER_CONTENT_LENGTH))
            continue;
        if (prx_headers && !strncasecmp(BUFF_CSTR(h->headers[i].name), S_PROXY_CONNECTION,
            STRLEN(S_PROXY_CONNECTION))) {

            if (BUFF_APPENDSTR(buf, S_CONNECTION) < 0)
                goto out;
        } else if (BUFF_APPENDB(buf, h->headers[i].name) < 0) {
            goto out;
        }
        if (buff_append(buf, S_COLON S_SPACE, STRLEN(S_COLON S_SPACE)) < 0)
            goto out;
        if (BUFF_APPENDB(buf, h->headers[i].value) < 0)
            goto out;
        if (buff_append(buf, S_END, STRLEN(S_END)) < 0)
            goto out;
    }

    ret = 0;
out:
    return ret;
}

static int create_http_header(bool prx_auth, const char *sv_name, int use_head, uint16_t sv_port,
        struct http_header *horig, struct http_header *hadd, struct buff **pbuf)
{
    int ret = -1;
    char tmpb[64];
    struct buff *buf = *pbuf;
    const char *method = NULL;
    const char *s_url = NULL;

    NETLOG5("create_http_header: sv_name %s, horig->method %s, horig->url %s",
            sv_name ? sv_name : "(null)",
            horig && horig->method ? horig->method : "(null)",
            horig && horig->url ? BUFF_CSTR(horig->url) : "(null)");
    if (!horig) {
        NETLOG("%s: ERROR - bug, no horig", __FUNCTION__);
        goto out;
    }
    if (!buf && !BUFF_NEW_PRIV(buf, pbuf, horig->hint_size + 256))
        goto mem_err;
    if (buf->size < (horig->hint_size + 256) && (buff_adj(buf, horig->hint_size + 256) < 0))
        goto mem_err;

    /* url */
    if (!sv_name || !horig->method || !horig->url || !horig->url->len) {
        NETLOG("%s: ERROR - bug, sv_name or horig invalid", __FUNCTION__);
        goto out;
    }

    method = horig->method;
    if (use_head)
        method = S_HEAD;
    if (BUFF_APPENDSTR(buf, method) < 0)
        goto mem_err;
    if (buff_append(buf, S_SPACE, STRLEN(S_SPACE)) < 0)
        goto mem_err;

    if (prx_auth && strncasecmp((const char *)horig->url->m, S_SCHEME_HTTP, STRLEN(S_SCHEME_HTTP)) &&
        strncasecmp((const char *)horig->url->m, S_SCHEME_FTP, STRLEN(S_SCHEME_FTP))) {

        if (buff_append(buf, S_SCHEME_HTTP, STRLEN(S_SCHEME_HTTP)) < 0)
            goto mem_err;
        if (BUFF_APPENDSTR(buf, sv_name) < 0)
            goto mem_err;
        if (sv_port != htons(80)) {
            tmpb[15] = 0;
            snprintf(tmpb, 15, S_COLON "%u", ntohs(sv_port));
            if (BUFF_APPENDSTR(buf, tmpb) < 0)
                goto mem_err;
        }
    }

    /* transform "absolute URL" into "relative URL" */
    if (!prx_auth && strncasecmp((const char *)horig->url->m, S_SCHEME_HTTP,
                    STRLEN(S_SCHEME_HTTP)) == 0) {

        /* find the third '/' or empty */
        const char *p = (const char *) horig->url->m;

        p = strchr(p, '/');
        if (p) {
            p = strchr(p + 1, '/');
            if (p) {
                p = strchr(p + 1, '/');
                s_url = p ? p : "/";
            }
        }

    }

    if (s_url) {
        if (BUFF_APPENDSTR(buf, s_url) < 0)
            goto mem_err;
    } else {
        if (BUFF_APPENDB(buf, horig->url) < 0)
            goto mem_err;
    }

    tmpb[63] = 0;
    snprintf(tmpb, 63, S_SPACE S_HTTP_VERSION_TEMPLATE S_END, horig->http_major, horig->http_minor);
    if (BUFF_APPENDSTR(buf, tmpb) < 0)
        goto mem_err;

    /* header fields */
    if (horig && add_headers(buf, horig, use_head, !prx_auth) < 0)
        goto mem_err;

    /* additional headers */
    if (hadd && add_headers(buf, hadd, use_head, false) < 0)
        goto mem_err;

    if (buff_append(buf, S_END, STRLEN(S_END)) < 0)
        goto mem_err;

    ret = 0;
out:
    return ret;
mem_err:
    warnx("%s: memory error", __FUNCTION__);
    goto out;
}

static int create_connect_header(char *prev_connect_headers, const char *sv_name,
                                       uint16_t sv_port, struct http_header *hadd,
                                       struct buff **pbuf)
{
    int ret = -1;
    char tmpb[64];
    struct buff *buf = *pbuf;

    if (!sv_name)
        goto out;
    if (!buf && !BUFF_NEW_PRIV(buf, pbuf, 256))
        goto out;

    if (!prev_connect_headers) {
        if (buff_append(buf, S_CONNECT S_SPACE, STRLEN(S_CONNECT S_SPACE)) < 0)
            goto out;
        if (BUFF_APPENDSTR(buf, sv_name) < 0)
            goto out;

        tmpb[63] = 0;
        snprintf(tmpb, 63, S_COLON "%hu" S_SPACE S_HTTP11 S_END, ntohs(sv_port));
        if (BUFF_APPENDSTR(buf, tmpb) < 0)
            goto out;

        /* "Host: domain-name:port" field */
        if (buff_append(buf, S_HOST S_COLON S_SPACE, STRLEN(S_HOST S_COLON S_SPACE)) < 0)
            goto out;
        if (BUFF_APPENDSTR(buf, sv_name) < 0)
            goto out;
        if (ntohs(sv_port) != 443) {
            tmpb[63] = 0;
            if (snprintf(tmpb, 63, S_COLON "%hu",  ntohs(sv_port)) < 0)
                goto out;
            if (BUFF_APPENDSTR(buf, tmpb) < 0)
                goto out;
        }
        if (buff_append(buf, S_END, STRLEN(S_END)) < 0)
            goto out;

        if (user_agent) {
            if (buff_append(buf, S_USER_AGENT S_COLON S_SPACE,
                STRLEN(S_USER_AGENT S_COLON S_SPACE)) < 0) {

                goto out;
            }
            if (BUFF_APPENDSTR(buf, user_agent) < 0)
                goto out;
            if (buff_append(buf, S_END, STRLEN(S_END)) < 0)
                goto out;
        } else {
            NETLOG("%s: WARNING - no user-agent specified", __FUNCTION__);
        }

        if (buff_append(buf, S_CONNECTION S_COLON S_SPACE S_KEEPALIVE S_END,
                    STRLEN(S_CONNECTION S_COLON S_SPACE S_KEEPALIVE S_END)) < 0) {

            goto out;
        }
    } else {
        BUFF_RESET(buf);
        if (buff_append(buf, prev_connect_headers, strlen(prev_connect_headers)) < 0)
            goto out;
    }

    /* additional headers */
    if (hadd && add_headers(buf, hadd, false, false) < 0)
        goto out;

    if (buff_append(buf, S_END, STRLEN(S_END)) < 0)
        goto out;

    ret = 0;

out:
    return ret;
}

static struct http_ctx * hp_create(struct nickel *ni)
{
    struct http_ctx *hp = NULL;

    hp = calloc(1, sizeof(*hp));
    if (!hp)
        goto mem_err;
    hp->ni = ni;

    hp_get(hp);
    hp->cstate = S_INIT;
    LIST_INSERT_HEAD(&http_list, hp, entry);
    RLIST_INIT(hp, direct_hp_list);
out:
    return hp;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    if (hp) {
        LIST_REMOVE(hp, entry);
        free(hp);
        hp = NULL;
    }
    goto out;
}

static void hp_get(struct http_ctx *hp)
{
    atomic_inc(&hp->refcnt);
}

static void hp_put(struct http_ctx *hp)
{
    if (!hp)
        return;

    assert(hp->refcnt);
    atomic_dec(&hp->refcnt);
}

static void hp_close(struct http_ctx *hp)
{
    struct proxy_t *proxy = hp->proxy;

    if ((hp->flags & (HF_CLOSING | HF_CLOSED)))
        return;

    hp->flags |= HF_CLOSING;
    hp->flags &= (~HF_RESTARTABLE & ~HF_REUSABLE);
    if (hp->entry.le_prev)
        LIST_REMOVE(hp, entry);
    hp->entry.le_prev = NULL;
#if VERBSTATS
    if (hp->srv_lat_idx) {
        char tmp_buf[(12 + 1) * 2 * LAT_STAT_NUMBER + 1];
        int i, j = 0, llen;

        memset(tmp_buf, 0, sizeof(tmp_buf));
        for (i = 0; i < hp->srv_lat_idx; i += 2) {
            llen = snprintf(tmp_buf + j, sizeof(tmp_buf) - j - 1, " %u:%u", hp->srv_lat[i],
                    hp->srv_lat[i + 1]);
            if (llen <= 0)
                break;
            j += llen;
        }
        HLOG2("tx %u rx %u%s", hp->clt_bytes, hp->srv_bytes, tmp_buf);
    } else {
        HLOG2("tx %u rx %u", hp->clt_bytes, hp->srv_bytes);
    }
#endif

    if (hp->cx)
        cx_hp_disconnect(hp->cx);
    hp->cx = NULL;
    if (hp->so)
        so_close(hp->so);
    hp->so = NULL;
    hp->hstate = HP_IGNORE;
    if (hp->clt_out) {
        buff_put(hp->clt_out);
        hp->clt_out = NULL;
    }
    if (hp->c407_buff) {
        buff_put(hp->c407_buff);
        hp->c407_buff = NULL;
    }

    hp->flags |= HF_CLOSED;

    hp_remove_hpd(hp);

    hp_put(hp);
    LIST_INSERT_HEAD(&http_gc_list, hp, entry);
    hp->flags &= ~HF_CLOSING;

    if (proxy) {
        proxy->wakeup_list = 1;
        ni_wakeup_loop(hp->ni);
    }
}

static void hp_free(struct http_ctx *hp)
{
    assert((hp->flags & HF_CLOSED));

    if (hp->so) {
        so_close(hp->so);
        hp->so = NULL;
    }

    free(hp->h.sv_name);
    hp->h.sv_name = NULL;
    hp->h.daddr.sin_port = 0;
    hp->h.daddr.sin_addr.s_addr = 0;
    hp->h.daddr.sin_family = AF_INET;
    free(hp->a);
    hp->a = NULL;
    hp->cstate = S_INIT;
    hp->hwait_state = 0;

    http_auth_free(&hp->auth);
    hp->proxy = NULL;
    if ((hp->flags & HF_TLS) && hp->tls)
        tls_free(&hp->tls);

    if (hp->clt_out)
        buff_put(hp->clt_out);
    hp->clt_out = NULL;

    free(hp);
}

static int hp_connect_reinit(struct http_ctx *hp)
{
    hp->hstate = HP_NEW;
    hp->flags &= ~HF_KEEP_ALIVE;

    if (hp->cx) {
        bool split_buffs = true;

        if (hp->cx->proxy && (hp->flags & HF_MONITOR_407))
            hp->flags |= HF_SAVE_REQ_PRX;
        if (!hp->cx->proxy && (hp->cx->flags & CXF_GUEST_PROXY)) {
            hp->flags |= HF_SAVE_REQ_RTRY;
            hp->http_req_rtry_cnt = 0;
        }

        if (!hp->cx->proxy && !(hp->cx->flags & CXF_GUEST_PROXY))
            split_buffs = false;
        if (hp_cx_connect_buffs(hp, split_buffs) < 0)
            return -1;

        if (hp->cx->srv_parser)
            parser_reset(hp->cx->srv_parser);
    }

    return 0;
}

static int hp_cx_connect_next(struct http_ctx *hp, struct proxy_t *proxy)
{
    struct clt_ctx *cx = NULL;

    if (hp) {
        assert(!hp->cx);
        proxy = hp->proxy;
    }
    if (!proxy)
        return 0;

    if (RLIST_EMPTY(&proxy->w_list, w_list)) {
        PRXL5("WLIST EMPTY");
        return 0;
    }

    PRXL5("WLIST N %d", proxy_number_waiting(proxy));

    while (!RLIST_EMPTY(&proxy->w_list, w_list)) {
        cx = RLIST_FIRST(&proxy->w_list, w_list);
        RLIST_REMOVE(cx, w_list);
        cx_put(cx);
        if (!(cx->flags & CXF_CLOSED))
            break;
        cx = NULL;
    }

    PRXL5("WAKE UP WLIST N %d", proxy_number_waiting(proxy));
    if (!cx)
        return 0;

    assert(!cx->hp);

    if (hp) {
        if (!hp->cx) {
            cx_get(cx);
            hp->cx = cx;
        }
        if (!cx->hp) {
            hp_get(hp);
            cx->hp = hp;
            if (on_cx_hp_connect(cx) < 0)
                return -1;
        }
        free(hp->h.sv_name);
        if (cx->h.sv_name)
            hp->h.sv_name = strdup(cx->h.sv_name);
        hp->h.daddr.sin_port = cx->h.daddr.sin_port;
        if (hp_connect_reinit(hp) < 0)
            return -1;
    } else {
        hp = cx_hp_connect_proxy(cx);
    }

    CXL5("WLIST RESUME cx_process, px:%"PRIxPTR, (uintptr_t) proxy);
    return cx_process(cx, NULL, 0);
}

static int hp_cx_connect_buffs(struct http_ctx *hp, bool sep_out)
{
    if (!hp->cx)
        return 0;
    if (!hp->cx->out && !buff_new_priv(&hp->cx->out, SO_READBUFLEN))
        goto mem_err;

    if (sep_out) {
        if (hp->clt_out != NULL && hp->clt_out == hp->cx->in) {
            buff_put(hp->clt_out);
            hp->clt_out = NULL;
        }
        if (hp->clt_out != NULL)
            BUFF_RESET(hp->clt_out);
        if (hp->clt_out == NULL && !BUFF_NEW_MX_PRIV(&hp->clt_out,
            hp->cx->in ? hp->cx->in->size : SO_READBUFLEN, MAX_GUEST_BUF)) {

            goto mem_err;
        }
    } else {
        if (hp->clt_out && hp->clt_out != hp->cx->in) {
            buff_put(hp->clt_out);
            hp->clt_out = NULL;
        }
        if (hp->cx->in && !hp->clt_out) {
            buff_get(hp->cx->in);
            hp->clt_out = hp->cx->in;
        }
    }

    return 0;
mem_err:
    warnx("%s: hp %"PRIxPTR" malloc", __FUNCTION__, (uintptr_t) hp);
    return -1;
}

static void hp_dns_proxy_check_domain_cb(void *opaque)
{
    struct dns_connect_ctx *dns = opaque;
    struct http_ctx *hp;

    hp = dns->hp;
    hp_put(hp);
    if ((hp->flags & HF_CLOSED))
        goto out;
    if (dns->response.denied) {
        HLOG("%s DENIED by containment", dns->domain ? dns->domain : "(null)");
        if (hp->cx)
            cx_close(hp->cx);
        hp_close(hp);
    }
out:
    dns_response_free(&dns->response);
    free(dns->domain);
    free(dns);
}

static int hp_dns_proxy_check_domain(struct http_ctx *hp)
{
    int ret = -1;
    struct in_addr addr = {.s_addr = 0};
    struct sockaddr_in saddr;
    struct dns_connect_ctx *dns = NULL;

    assert(hp->proxy);

    if (!hp->ni->ac_enabled || !hp->h.sv_name)
        goto out_allow;

    if (inet_aton(hp->h.sv_name, &addr) != 0) {
        if (!ac_is_ip_allowed(hp->ni, &addr)) {
            HLOG("IP %s DENIED by containment", hp->h.sv_name);
            goto out;
        }

        goto out_allow;
    }

    if (!ac_is_dnsname_allowed(hp->ni, hp->h.sv_name)) {
        HLOG("%s DENIED by containment", hp->h.sv_name);
        goto out;
    }

    dns = calloc(1, sizeof(*dns));
    if (!dns)
        goto mem_err;

    dns->hp = hp;
    dns->domain = strdup(hp->h.sv_name);
    dns->containment_check = 1;
    dns->proxy_on = 1;
    if (!dns->domain)
        goto mem_err;

    hp_get(hp);
    if (ni_schedule_bh(hp->ni, dns_lookup_sync, hp_dns_proxy_check_domain_cb, dns)) {
        HLOG("unet_schedule_bh FAILURE");
        hp_put(hp);
        free(dns->domain);
        free(dns);
        goto out;
    }

out_allow:
    ret = 0;
out:
    if (!(hp->flags & HF_LAVA_STUB_SENT)) {
        hp->flags |= HF_LAVA_STUB_SENT;
        memset(&saddr, 0, sizeof(saddr));
        if (hp->cx && hp->cx->ni_opaque)
            saddr = tcpip_get_gaddr(hp->cx->ni_opaque);
    }
    return ret;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    ret = -1;
    goto out;
}

static int on_cx_hp_connect(struct clt_ctx *cx)
{
    cx_lava_connect(cx);
    if (cx->hp && (cx->flags & CXF_407_MESSAGE) && start_407_message(cx->hp) < 0)
        return -1;

    return 0;
}

static void hp_gc_idle_sockets(int64_t now, bool close)
{
    struct http_ctx *hp, *hp_next;
    int64_t timeout = -1;

    LIST_FOREACH_SAFE(hp, &http_list, entry, hp_next) {
        int64_t diff;

        if (hp->cx || !hp->idle_ts)
            continue;
        diff = now - hp->idle_ts;
        if (close && diff >= HP_IDLE_MAX_TIMEOUT) {
            HLOG5("HP_IDLE_MAX_TIMEOUT");
            hp_close(hp);
        } else if (timeout < 0 || timeout > diff) {
            timeout = diff;
        }
    }

    if (timeout >= 0)
        mod_timer(hp_idle_timer, now + timeout);
}

static void hp_idle_timer_cb(void *unused)
{
    hp_gc_idle_sockets(get_clock_ms(rt_clock), true);
}

static int hp_set_idle_timer(struct http_ctx *hp)
{
    int now = get_clock_ms(rt_clock);

    hp->idle_ts = now;
    if (!hp_idle_timer) {
        hp_idle_timer = ni_new_rt_timer(hp->ni, HP_IDLE_MAX_TIMEOUT, hp_idle_timer_cb, NULL);
        return hp_idle_timer ? 0 : -1;
    }

    hp_gc_idle_sockets(now, false);
    return 0;
}

static struct http_ctx *
cx_hp_connect_proxy(struct clt_ctx *cx)
{
    struct http_ctx *hp;

    assert(cx->proxy);
    assert(!cx->hp);
    hp = hp_create(cx->ni);
    if (!hp) {
        warnx("%s: cx %"PRIxPTR" malloc", __FUNCTION__, (uintptr_t) cx);
        goto out;
    }

    if (!hp->cx) {
        cx_get(cx);
        hp->cx = cx;
    }
    if (!cx->hp) {
        hp_get(hp);
        cx->hp = hp;
        if (on_cx_hp_connect(cx) < 0)
            goto close_hp;
    }

    if (cx->h.sv_name)
        hp->h.sv_name = strdup(cx->h.sv_name);
    hp->h.daddr.sin_port = cx->h.daddr.sin_port;

    hp->proxy = cx->proxy;
    if (!(cx->flags & CXF_GUEST_PROXY)) {
        hp->h.daddr.sin_family = AF_INET;
        hp->h.daddr.sin_addr = cx->h.daddr.sin_addr;
        hp->flags |= HF_RESOLVED;
    } else {
        // GPROXY to HPROXY
        if (hp_dns_proxy_check_domain(hp) < 0) {
            cx_proxy_response(cx, HMSG_CONNECT_DENIED, true);
            goto out;
        }
    }

    hp->cstate = S_INIT;
    if (hp_connect_reinit(hp) < 0)
        goto close_hp;
    if (hp->proxy && (cx->flags & CXF_GUEST_PROXY) &&
        !(cx->flags & (CXF_TUNNEL_GUEST | CXF_TLS | CXF_BINARY))) {

        hp->flags |= HF_REUSABLE;
    }
    if ((hp->proxy || (cx->flags & CXF_GUEST_PROXY)) &&
         !(cx->flags & (CXF_TUNNEL_GUEST | CXF_TLS | CXF_BINARY))) {

        hp->flags |= (HF_RESTARTABLE | HF_RESTART_OK);
        assert(cx->out);
        if (!cx->srv_parser && parser_create_response(&cx->srv_parser, cx))
            goto close_hp;
    }
    if (srv_connect_proxy(hp, hp->proxy) < 0)
        goto close_hp;

out:
    CXL5("out hp %"PRIxPTR, (uintptr_t) hp);
    return hp;
close_hp:
    if (hp)
        hp_close(hp);
    hp = NULL;
    goto out;
}

static void cx_lava_connect(struct clt_ctx *cx)
{
    struct lava_event *lv;

    lv = tcpip_lava_get(cx->ni_opaque);
    if (!lv)
        return;

    lava_event_remote_connect(lv);
    if (cx->hp && cx->hp->cstate == S_CONNECTED) {
        struct net_addr a;
        uint16_t port;

        a = so_get_remote_addr(cx->hp->so);
        port = so_get_remote_port(cx->hp->so);
        lava_event_remote_established(lv, &a, port);
    }
}

static int cx_hp_connect(struct clt_ctx *cx, bool *connect_now)
{
    int ret = 0;
    struct http_ctx *hp = NULL;
    int n_all = 0, n_http = 0, n_alone = 0;

    if ((cx->flags & CXF_CLOSED))
        goto out;

    CXL5("start, CXF_PRX_DECIDED is %d", (int) !!((cx->flags & CXF_PRX_DECIDED)));
    assert(!cx->hp);
    if ((cx->flags & CXF_LOCAL_WEBDAV))
        goto out;
    if (!(cx->flags & CXF_PRX_DECIDED))
        goto out;

    if (!RLIST_EMPTY(cx, w_list))
        goto out;
    if (!RLIST_EMPTY(cx, direct_cx_list))
        goto out;

    if (!cx->proxy) {
        struct hpd_t *hpd = NULL;
        int not_binary = !(cx->flags & (CXF_TUNNEL_GUEST | CXF_TLS | CXF_BINARY));

        hp = NULL;
        if ((cx->flags & CXF_GUEST_PROXY) && not_binary && hpd_rbtree_init &&
            (hpd = rb_tree_find_node(&hpd_rbtree, &cx->h))) {

            struct http_ctx *lhp;

            RLIST_FOREACH(lhp, &hpd->direct_hp_list, direct_hp_list) {
                if (!lhp->cx && (lhp->flags & HF_REUSABLE) && (lhp->flags & HF_REUSE_READY) &&
                    !(lhp->flags & (HF_CLOSING|HF_CLOSED))) {

                    hp = lhp;
                    CXL5("DIRECT REUSED HP %"PRIxPTR, (uintptr_t) hp);
                    break;
                }
            }
        }

        if (!hp) {
            if (hpd && hpd->nr_hp >= max_socket_per_proxy) {
                hpd_add_cx(hpd, cx);
                *connect_now = true;
                goto out;
            }
            hp = hp_create(cx->ni);
            if (!hp) {
                warnx("%s: malloc", __FUNCTION__);
                goto err;
            }
        }

        if (!hp->cx) {
            cx_get(cx);
            hp->cx = cx;
        }
        if (!cx->hp) {
            hp_get(hp);
            cx->hp = hp;
            if (on_cx_hp_connect(cx) < 0)
                goto err;
        }

        if (cx->h.sv_name && !hp->h.sv_name)
            hp->h.sv_name = strdup(cx->h.sv_name);
        hp->h.daddr.sin_port = cx->h.daddr.sin_port;

        if (!hpd && (cx->flags & CXF_GUEST_PROXY) && not_binary &&
            hpd_rbtree_init && !(hpd = hp_create_hpd(hp))) {

            goto err;
        }
        if (hpd)
            hpd_add_hp(hpd, hp);

        if (!(cx->flags & CXF_GUEST_PROXY)) {
            hp->h.daddr.sin_family = AF_INET;
            hp->h.daddr.sin_addr = cx->h.daddr.sin_addr;
            hp->flags |= HF_RESOLVED;
        }

        if (hp_connect_reinit(hp) < 0)
            goto err;

        if ((cx->flags & CXF_GUEST_PROXY) &&
            !(cx->flags & (CXF_TUNNEL_GUEST | CXF_TLS | CXF_BINARY))) {

            hp->flags |= (HF_RESTARTABLE | HF_RESTART_OK | HF_REUSABLE | HF_REUSE_READY);
            assert(cx->out);
            if (!cx->srv_parser && parser_create_response(&cx->srv_parser, cx))
                goto err;
        }

        *connect_now = true;
        if (hp->cstate == S_INIT) {
            if (srv_connect_direct(hp) < 0)
                goto err;
            *connect_now = false;
        }

        goto out;
    }

    /* proxy */
    if ((cx->flags & (CXF_TLS | CXF_BINARY | CXF_TUNNEL_GUEST))) {
        hp = cx_hp_connect_proxy(cx);
        goto out;
    }

    LIST_FOREACH(hp, &http_list, entry) {
        n_all++;
        if (hp->proxy != cx->proxy ||
            (hp->flags & (HF_HTTP_CLOSE | HF_TLS | HF_BINARY_STREAM | HF_TUNNEL))) {

            continue;
        }
        n_http++;
        if (hp->cx)
            continue;
        n_alone++;
        if ((hp->flags & HF_REUSE_READY))
            break;
    }
    CXL5("ALL %d HTTP %d ALONE %d, proxy %"PRIxPTR", hp found %"PRIxPTR, n_all, n_http,
         n_alone, (uintptr_t) cx->proxy, (uintptr_t) hp);

    if (hp) {
        assert(!hp->cx);

        free(hp->h.sv_name);
        if (cx->h.sv_name)
            hp->h.sv_name = strdup(cx->h.sv_name);
        hp->h.daddr.sin_port = cx->h.daddr.sin_port;
        if (hp_dns_proxy_check_domain(hp) < 0) {
            CXL4("ac DENIED while reusing the proxy socket");
            cx_proxy_response(cx, HMSG_CONNECT_DENIED, true);
            hp = NULL;
            goto out;
        }

        if (!hp->cx) {
            cx_get(cx);
            hp->cx = cx;
        }
        assert(!cx->hp);
        if (!cx->hp) {
            hp_get(hp);
            cx->hp = hp;
            if (on_cx_hp_connect(cx) < 0)
                goto err;
        }

        if (hp_connect_reinit(hp) < 0)
            goto out;
        *connect_now = true;

        CXL5("HP REUSED from LIST  proxy %"PRIxPTR, (uintptr_t) cx->proxy);
        goto out;
    }

    if (n_http >= max_socket_per_proxy) {
        cx_get(cx);
        RLIST_INSERT_TAIL(&cx->proxy->w_list, cx, w_list);
        CXL5("WLIST ADD N %d proxy %"PRIxPTR,
                proxy_number_waiting(cx->proxy),
                (uintptr_t) cx->proxy);
        *connect_now = true;

        goto out;
    }

    if (!cx->hp)
        hp = cx_hp_connect_proxy(cx);

out:
    CXL5("HP_CONNECTED hp %"PRIxPTR, (uintptr_t) hp);
    return ret;
err:
    if (hp)
        hp_close(hp);
    ret = -1;
    goto out;
}

static void proxy_connect_cx_next(struct proxy_t *proxy)
{
    struct http_ctx *hp;
    int n_sockets = 0;

    PRXL5("");
    if (RLIST_EMPTY(&proxy->w_list, w_list))
        return;

    PRXL5("WLIST NOT EMPTY N %d", proxy_number_waiting(proxy));
    LIST_FOREACH(hp, &http_list, entry) {
        if (hp->proxy != proxy ||
            (hp->flags & (HF_HTTP_CLOSE | HF_TLS | HF_BINARY_STREAM | HF_TUNNEL))) {

            continue;
        }

        n_sockets++;
        if (hp->cx)
            continue;
        if ((hp->flags & HF_REUSE_READY))
            break;
    }

    PRXL5("n_sockets %d", n_sockets);
    if (n_sockets >= max_socket_per_proxy && !hp)
        return;

    hp_cx_connect_next(hp, proxy);
}

void proxy_wakeup_list(struct proxy_t *proxy)
{
    if (proxy->wakeup_list) {
        proxy->wakeup_list = 0;
        if (!PROXY_IS_DIRECT(proxy))
            proxy_connect_cx_next(proxy);
    }
}

static int cx_hp_disconnect_ex(struct clt_ctx *cx, bool no_cx_close)
{
    int ret = 0;
    struct http_ctx *hp = NULL;
    struct proxy_t *proxy = NULL;
    bool f_cx_close = false;
    bool f_cx_closing = false;
    bool f_hp_closing = false;
    bool f_cx_guest_write = false;
    struct nickel *ni;

    ni = cx->ni;
    if (!cx->hp)
        goto out;

    f_cx_closing = (cx->flags & CXF_CLOSING) != 0;
    f_hp_closing = (cx->hp->flags & HF_CLOSING) != 0;

    cx->flags &= ((~CXF_HEAD_REQUEST) & (~CXF_HEAD_REQUEST_SENT));
    hp = cx->hp;
    hp_put(cx->hp);
    cx->hp = NULL;
    lava_event_remote_disconnect(tcpip_lava_get(cx->ni_opaque));

    proxy = hp->proxy;
    if (hp->cx) {
        assert(hp->cx == cx);
        cx_put(hp->cx);
        hp->cx = NULL;
    }
    if (hp->clt_out) {
        buff_put(hp->clt_out);
        hp->clt_out = NULL;
    }

    hp->flags &= (~HF_SAVE_REQ_PRX & ~HF_SAVE_REQ_RTRY);

    if ((f_hp_closing || f_cx_closing) && hp && (hp->flags & HF_FATAL_ERROR) &&
         !(cx->flags & CXF_FLUSH_CLOSE)) {

        cx->flags |= CXF_FORCE_CLOSE;
        f_cx_close = true;
    }

    if (!f_cx_closing && cx->srv_parser) {
        CXL5("SRV_PARSER RESET");
        parser_reset(cx->srv_parser);
    }

    if ((hp->flags & HF_HTTP_CLOSE)) {

        if (!(cx->flags & CXF_GPROXY_REQUEST)) {
            if (!cx->out || BUFF_BUFFERED(cx->out) == 0) {
                cx_close(cx);
            } else {
                cx->flags |= CXF_FLUSH_CLOSE;
                f_cx_guest_write = true;
            }
        }
        hp_close(hp);
        hp = NULL;
        goto out;
    }

    if (f_hp_closing) {
        HLOG5("f_hp_closing");
        f_cx_close = true;
        goto out;
    }

    if ((hp->flags & HF_CLOSED)) {
        f_cx_close = true;
        hp = NULL;
        goto out;
    }

    if ((hp->flags & HF_PARSE_ERROR)) {
        HLOG5("HF_PARSE_ERROR closing");
        hp_close(hp);
        hp = NULL;
        goto out;
    }

    if (!hp->proxy && !f_hp_closing && (hp->flags & HF_REUSABLE) &&
        (hp->flags & HF_REUSE_READY) && (hp->flags & HF_KEEP_ALIVE) &&
        hp->h.sv_name && hp->h.daddr.sin_port) {

        hp_connect_reinit(hp);
        if (hp_set_idle_timer(hp) < 0) {
            HLOG("hp_set_idle_timer FAILED!");
            hp_close(hp);
            hp = NULL;
        }
        goto out;
    }

    if (!hp->proxy || !(hp->flags & HF_REUSABLE) || !(hp->flags & HF_REUSE_READY) ||
        (hp->flags & HF_PINNED)) {

        hp_close(hp);
        hp = NULL;
        goto out;
    }

    if ((hp->flags & (HF_TLS | HF_TUNNEL))) {
        hp_close(hp);
        hp = NULL;
        goto out;
    }

out:
    CXL5("HP_DISCONNECTED, hp %"PRIxPTR, (uintptr_t) hp);
    if (hp)
        HLOG5("proxy %"PRIxPTR, (uintptr_t) hp->proxy);

    if (hp && (hp->flags & HF_REUSABLE)) {
        hp->flags |= HF_REUSE_READY;
        if (proxy) {
            proxy->wakeup_list = 1;
            ni_wakeup_loop(ni);
        }
    }

    if (f_cx_close && !no_cx_close)
        cx_close(cx);
    else if (cx && f_cx_guest_write && cx_guest_write(cx) < 0 && !no_cx_close)
        cx_close(cx);

    if (hp && hp->hpd) {
        hpd_needs_continue = 1;
        hp->hpd->needs_continue = 1;
        ni_wakeup_loop(ni);
    }

    if ((cx->flags & CXF_CLOSED)) {
        CXL5("CXF_CLOSED already");
        ret = -1;
    }

    return ret;
}

static int cx_hp_disconnect(struct clt_ctx *cx)
{
    return cx_hp_disconnect_ex(cx, false);
}

static int cx_hp_reconnect_direct(struct clt_ctx *cx)
{
    struct http_ctx *hp = NULL;

    cx->flags &= ((~CXF_HEAD_REQUEST) & (~CXF_HEAD_REQUEST_SENT) & (~CXF_PROXY_SUSPEND));
    if (cx->hp) {
        hp = cx->hp;
        if (hp->cx)
            cx_put(hp->cx);
        hp->cx = NULL;
        hp_put(hp);
        hp_close(hp);
        hp = NULL;
        cx->hp = NULL;
        lava_event_remote_disconnect(tcpip_lava_get(cx->ni_opaque));
    }
    cx_proxy_set(cx, NULL);
    return cx_process(cx, NULL, 0);
}

static int hp_srv_ready(struct http_ctx *hp)
{
    int ret = 0;

    hp->cstate = S_CONNECTED;
    assert(hp->so);

    if (!hp->proxy && hp->hstate >= HP_RESPONSE) {
        hp->hstate = HP_PASS;
        if (start_direct(hp) < 0) {
            ret = -1;
            goto out;
        }
    }

    wakeup_client(hp);
    srv_write(hp, NULL, 0);
    if (hp_clt_process(hp, NULL, 0) < 0 || hp_srv_process(hp) < 0) {
        hp_close(hp);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int cx_proxy_response(struct clt_ctx *cx, int msg, bool close)
{
    int ret = -1;
    static const char tls_fatal_alert[7] = {21, 3, 3, 0, 2, 2, 80};

    if ((cx->flags & CXF_CLOSED))
        goto out;

    CXL4("sending msg type %d, close %d", msg, close ? 1 : 0);

    if (!cx->out && !buff_new_priv(&cx->out, SO_READBUFLEN)) {
        warnx("%s: cx %"PRIxPTR" malloc", __FUNCTION__, (uintptr_t) cx);
        goto out;
    }

    BUFF_RESET(cx->out);
    if (msg == HMSG_DNS_LOOKUP_FAILED) {
        buff_appendf(cx->out, "HTTP/1.0 504 DNS ERROR\r\n"
                "Content-Length: 0\r\nProxy-Connection: Close\r\n\r\n");
    } else if (msg == HMSG_CONNECT_FAILED) {
        buff_appendf(cx->out, "HTTP/1.0 504 CONNECT FAILED\r\n"
                "Content-Length: 0\r\nProxy-Connection: Close\r\n\r\n");
    } else if (msg == HMSG_CONNECT_DENIED) {
        buff_appendf(cx->out, "HTTP/1.0 403 DENIED\r\n"
                "Content-Length: 0\r\nProxy-Connection: Close\r\n\r\n");
    } else if (msg == HMSG_CONNECT_ABORTED_SSL) {
        buff_append(cx->out, tls_fatal_alert, sizeof(tls_fatal_alert));
    } else if (msg == HMSG_BAD_REQUEST) {
        buff_appendf(cx->out, "HTTP/1.0 400 BAD REQUEST\r\n"
                "Content-Length: 0\r\nProxy-Connection: Close\r\n\r\n");
    } else if (msg == HMSG_CONNECT_OK) {
        buff_appendf(cx->out, "HTTP/1.0 200 Connection established\r\n\r\n");
    } else {
        goto out;
    }

    if (close)
        cx->flags |= (CXF_FLUSH_CLOSE | CXF_IGNORE);

    BUFF_CONSUME_ALL(cx->out);
    if (cx_guest_write(cx) < 0)
        goto out;

    ret = 0;

out:
    return ret;
}

static void wakeup_client(struct http_ctx *hp)
{
    if (hp->cx && hp->cx->ni_opaque)
        ni_buf_change(hp->cx->ni_opaque);
}

static int srv_reconnect(struct http_ctx *hp)
{
    if (!hp->so)
        return -1;

    if (hp->cx && hp->cx->out)
        BUFF_RESET(hp->cx->out);
    if (hp->cx && hp->cx->srv_parser)
        parser_reset(hp->cx->srv_parser);
    http_auth_reset(hp->auth);
    if (hp->auth)
        hp->auth->was_authorized = 0;
    if (hp->clt_out)
        BUFF_UNCONSUME(hp->clt_out);

    hp->cstate = S_RECONNECT;
    HLOG3("so_reconnect");
    return so_reconnect(hp->so);
}

static int srv_reconnect_wait(struct http_ctx *hp)
{
    hp->flags |= HF_NEEDS_RECONNECT;
    hp->cstate = S_RECONNECT;
    http_auth_reset(hp->auth);

    if (!hp->so)
        return 0;

    return so_closesocket(hp->so);
}

static int srv_reconnect_bad_proxy(struct http_ctx *hp)
{
    int ret = -1;
    char *alternative_proxies;

    HLOG4("");
    if (!hp->cx || !hp->proxy || hp->cstate == S_CONNECTED)
        goto out;

    /* too late */
    if ((hp->flags & HF_RESP_RECEIVED))
        goto out;

    /* try to obtain an alternative proxy */
    alternative_proxies = hp->cx->alternative_proxies;
    hp->cx->alternative_proxies = NULL;
    http_auth_free(&hp->auth);
    proxy_reset(hp->proxy);

    hp->cstate = S_RESOLVED;
    HLOG4("rpc_connect_proxy");
    ret = rpc_connect_proxy(hp, hp->h.sv_name, hp->h.daddr.sin_port, hp->proxy, alternative_proxies);
    /* if no alternative, we just tell hostsvr about last bad proxy and give up */
    if (!alternative_proxies)
        ret = -1;
    free(alternative_proxies);
out:
    return ret;
}

static int srv_connecting(struct http_ctx *hp)
{
    int ret = 0;

    assert(hp->so);
#if VERBSTATS
    hp->srv_ts = get_clock_ms(rt_clock);
    HLOG3("");
#endif
    hp->cstate = S_CONNECTING;
    if (hp_clt_process(hp, NULL, 0) < 0)
        ret = -1;

    return ret;
}

static int srv_connected(struct http_ctx *hp)
{
    int ret = 0;
    struct net_addr a;
    uint16_t port;
    struct lava_event *lv = NULL;

    if (hp->cx)
        lv = tcpip_lava_get(hp->cx->ni_opaque);

    assert(hp->so);
    a = so_get_remote_addr(hp->so);
    port = so_get_remote_port(hp->so);
    lava_event_remote_established(lv, &a, port);
    if (hp_connecting_containment(hp, &a, hp->h.daddr.sin_port) < 0) {
        HLOG("DENIED by containment");
        if (hp->cx) {
            lava_event_set_denied(lv);
            cx_proxy_response(hp->cx, HMSG_CONNECT_DENIED, true);
        }
        ret = -1;
        goto out;
    }

    if (hp->cx && !(hp->cx->flags & CXF_NI_ESTABLISHED)) {
        hp->cx->flags |= CXF_NI_ESTABLISHED;
        if (hp->cx->ni_opaque)
            ni_event(hp->cx->ni_opaque, CHR_EVENT_OPENED);
    }
    if (hp->cx && !hp->cx->out && !buff_new_priv(&hp->cx->out, SO_READBUFLEN)) {
        warnx("%s: malloc", __FUNCTION__);
        ret = -1;
        goto out;
    }
    if (hp->proxy && (hp->auth || (hp->auth = http_auth_create(hp->ni,
                        hp, hp->proxy)))) {

        hp->auth->sessions++;
    }
#if VERBSTATS
    HLOG3("CONNECTED to %s(%s):%hu in %lums / %lums",
            hp->proxy ? hp->proxy->name : (hp->h.sv_name ? hp->h.sv_name : "?"),
            a.family == AF_INET ? inet_ntoa(a.ipv4) : (a.family == AF_INET6 ? "ipv6" : "?"),
            ntohs(port), (unsigned long) (get_clock_ms(rt_clock) - hp->srv_ts),
            hp->cx ? (unsigned long) (get_clock_ms(rt_clock) - hp->cx->created_ts) : 0);
    hp->srv_ts = get_clock_ms(rt_clock);
    if (hp->cx)
        hp->cx->created_ts = hp->srv_ts;
#endif

    /* update hyb chosen connected to address */
    if (hp->proxy && hp->proxy->a && hp->proxy->a[0].family && hp->proxy->a[1].family) {
        struct net_addr c_addr;

        c_addr = so_get_remote_addr(hp->so);
        dns_hyb_update(hp->proxy->a, c_addr);
    }
    if (!hp->proxy && hp->a && hp->a[0].family && hp->a[1].family) {
        struct net_addr c_addr;

        c_addr = so_get_remote_addr(hp->so);
        dns_hyb_update(hp->a, c_addr);
    }
    if (!hp->proxy && fakedns_is_fake(&hp->h.daddr.sin_addr)) {
        struct net_addr *a;

        a = fakedns_get_ips(hp->h.daddr.sin_addr);
        if (a) {
            struct net_addr c_addr;

            c_addr = so_get_remote_addr(hp->so);
            dns_hyb_update(a, c_addr);
        }
    }

    if (hp->cx && (hp->cx->flags & CXF_TUNNEL_DETECTED)) {
        hp->cx->flags |= CXF_TUNNEL_RESPONSE;
        if (cx_proxy_response(hp->cx, HMSG_CONNECT_OK, false) < 0)
            cx_close(hp->cx);
    }

    hp->cstate = S_CONNECTED;
    ret = hp_srv_ready(hp);
out:
    return ret;
}

static void srv_tls_check_complete(void *opaque, int revoked, uint32_t err_code)
{
    struct http_ctx *hp = opaque;

    hp_put(hp);
    if ((hp->flags & HF_CLOSED))
        goto out;

    if (revoked) {
        dict d;

        HLOG("cert chain revoked (code %u), closing TLS socket",
                (unsigned int) err_code);
        HLOG3("sending RPC to hostsvr and closing TLS socket");
        d = dict_new();
        if (d) {
            dict_put_string(d, "endpoint", hp->h.sv_name);
            dict_put_integer(d, "cert_status", kCertificateStatusRevoked);
            ni_rpc_send(hp->ni, "nc_AdviseSecureConnectionCertificateStatus", d, NULL, NULL);
            dict_free(d);
        }

        goto out_close;
    }

    if (hp->tls)
        tls_free(&hp->tls);
    HLOG3("certs ok, resuming TLS stream");
    if (hp->cx) {
        hp->cx->flags &= ~CXF_SUSPENDED;
        wakeup_client(hp);
        if (cx_guest_write(hp->cx) < 0)
            goto out_close;
    }

out:
    return;

out_close:
    hp_close(hp);
    goto out;
}

static int srv_read(struct http_ctx *hp)
{
    int ret = 0;
    size_t len = 0;
    ssize_t max_allowed = 0;

    if (hp->cstate != S_CONNECTED) {
        HLOG2("%s: strange, hp->cstate = %d", __FUNCTION__, (int) hp->cstate);
        goto out;
    }

    hp->flags &= ~HF_RESTART_OK;

    assert(hp->so);
    if (!hp->cx) {
        if ((hp->flags & HF_REUSABLE)) {
            uint8_t tmp_buf[2];

            len = so_read(hp->so, tmp_buf, 1);
            if (len > 0) {
                HLOG("ERROR - received data on an idle reusable socket! closing connection.");
                hp_close(hp);
            }
        }

        goto out;
    }

    if ((hp->flags & HF_SRV_SUSPENDED))
        goto out_pending;

    if (!hp->cx->out && !buff_new_priv(&hp->cx->out, SO_READBUFLEN))
        goto out;

    len = BUFF_FREEDOM(hp->cx->out);
    max_allowed = (ssize_t) MAX_SRV_BUFLEN - (ssize_t) BUFF_BUFFERED(hp->cx->out);
    if (max_allowed < 0)
        max_allowed = 0;
    if (!len && max_allowed <= 0) {
        HLOG5("WARNING - MAX_SRV_BUFLEN %d reached", MAX_SRV_BUFLEN);
        goto out_pending;
    }

    if (max_allowed > 0 && max_allowed > len) {
        size_t avail;

        avail = so_read_available(hp->so);
        if (avail > len)
            len = avail;
        if (len > max_allowed)
            len = max_allowed;
    }

    if (len == 0)
        goto out_pending;

    if (len > BUFF_FREEDOM(hp->cx->out) && BUFF_ENLARGE(hp->cx->out, len + BUF_CHUNK) < 0)
        goto out_pending;

    hp->flags &= ~(HF_READ_PENDING);
    len = so_read(hp->so, hp->cx->out->m + hp->cx->out->len, len);
    if (len == 0)
        goto out;

    hp->flags &= ~HF_SAVE_REQ_RTRY;
#ifdef VERBSTATS
    if (hp->srv_lat_idx < LAT_STAT_NUMBER * 2) {
        int64_t now = get_clock_ms(rt_clock);

        hp->srv_lat[hp->srv_lat_idx] = (uint32_t) (now - hp->srv_ts);
        hp->srv_lat[hp->srv_lat_idx + 1] = (uint32_t) len;
        hp->srv_lat_idx += 2;

        hp->srv_ts = now;
    }
#endif


    hp->srv_bytes += len;
    BUFF_ADVANCE(hp->cx->out, len);

    HLOG5("read %d", (int) len);
    if (NLOG_LEVEL > 5 && !hide_log_sensitive_data)
        HLOG_DMP(BUFF_CSTR(hp->cx->out), hp->cx->out->len);

    if (!hp->proxy && hp->hstate < HP_RESPONSE) {
        hp->hstate = HP_PASS;
        hp->flags |= HF_BINARY_STREAM;
        if (start_direct(hp) < 0)
            goto err;
    }

    if (hp->proxy && hp->hstate < HP_RESPONSE) {
        HLOG2("hp->hstate < HP_RESPONSE");
        HLOG("error: strange, received srv data when not expected. "
                "state %d, len = %u", hp->hstate, (unsigned int) len);
        BUFF_UNCONSUME(hp->cx->out);
        if (!hide_log_sensitive_data)
            HLOG_DMP(BUFF_CSTR(hp->cx->out), hp->cx->out->len);

        goto err;
    }

    if (TLS_HANDSHAKE_STEP(hp)) {
        int r;

        r = tls_read(hp->tls, (hp->cx->out->m) + (hp->cx->out->len - len),
                len, false);
        BUFF_CONSUME_ALL(hp->cx->out);

        if (r == TLSR_CONTINUE)
            goto carry_on;

        if (r == TLSR_ERROR) {
            HLOG("WARNING - TLS error(1), I am not able to check cert revocation");
            hp->flags |= HF_TLS_CERT_DONE;
            tls_free(&hp->tls);

            goto carry_on;
        }

        if (r == TLSR_DONE_CHECK) {
            hp->flags |= HF_TLS_CERT_DONE;
            tls_cert_send_hostsvr(hp->tls, hp->h.sv_name);

            if (disable_crl_check) {
                hp->flags |= HF_TLS_CERT_DONE;
                tls_free(&hp->tls);

                goto carry_on;
            }

            HLOG2("TLS parsing done, checking cert chain ");
            hp_get(hp);
            if (tls_async_cert_check(hp->tls, srv_tls_check_complete, hp) < 0) {
                hp_put(hp);
                HLOG("WARNING - TLS error(2), I am not able to check cert revocation");
                tls_free(&hp->tls);

                goto carry_on;
            }

            if (hp->cx)
                hp->cx->flags |= CXF_SUSPENDED;
            goto out;
        }

        if (r == TLSR_DONE_SKIP) {
            HLOG4("TLS parsing skip");
            hp->flags |= HF_TLS_CERT_DONE;
            tls_free(&hp->tls);

            goto carry_on;
        }

        HLOG("ERROR - unknown tls_read state %d", r);
        hp->flags |= HF_TLS_CERT_DONE;
        tls_free(&hp->tls);

        goto carry_on;
    }

carry_on:
    if (hp_srv_process(hp) < 0)
        goto err;
    if (hp->cx && hp->cx->out)
        hp->flags &= (~HF_RESP_WAITING);
out:
    HLOG5("out ret %d", ret);
    return ret;
out_pending:
    HLOG5("out_pending");
    hp->flags |= HF_READ_PENDING;
    goto out;
err:
    HLOG("ERROR");
    hp->flags |= HF_FATAL_ERROR;
    ret = -1;
    goto out;
}

static int srv_closing(struct http_ctx *hp, int err)
{
    int ret = 0;

    assert(hp->so);
    HLOG3(" err %d", err);

    if (hp->cstate == S_CONNECTED && hp->cx && !(hp->cx->flags & CXF_GUEST_PROXY)) {
        if (hp->cx->out && BUFF_BUFFERED(hp->cx->out)) {
            hp->cx->flags |= CXF_FLUSH_CLOSE;
            ret = cx_guest_write(hp->cx);
        } else {
            ret = cx_srv_fin(hp->cx);
        }

        goto out;
    }

    if ((hp->flags & HF_HTTP_CLOSE))
        goto close;

    if (hp->cstate != S_CONNECTED && hp->cx && !hp->proxy && (hp->cx->flags & CXF_GUEST_PROXY) &&
        hp->hstate != HP_FLUSH_CLOSE &&
        cx_proxy_response(hp->cx, HMSG_CONNECT_FAILED, true) == 0) {

        goto out;
    }

    if (hp->hstate == HP_IGNORE || hp->hstate == HP_FLUSH_CLOSE)
        goto out;

    if ((hp->flags & HF_NEEDS_RECONNECT) || hp->cstate == S_RECONNECT)
        goto out;

    if (hp->hstate == HP_WAIT) {
        hp->flags |= HF_NEEDS_RECONNECT;
        hp->cstate = S_RECONNECT;
        HLOG3("needs_reconnect");
        goto out;
    }

    if (hp->cx && !hp->proxy && (hp->cx->flags & CXF_GUEST_PROXY) && (hp->flags & HF_RESTARTABLE) &&
        (hp->flags & HF_RESTART_OK) && (hp->flags & HF_SAVE_REQ_RTRY) && hp->clt_out &&
        BUFF_BUFFERED(hp->clt_out)) {

            if (hp->http_req_rtry_cnt >= MAX_RETRY_HTTP_REQ) {
                HLOG3("MAX_RETRY_HTTP_REQ %d reached, closing socket", (int) MAX_RETRY_HTTP_REQ);
                goto close;
            }
            hp->http_req_rtry_cnt++;
            HLOG3("needs_reconnect, http_req_rtry_cnt %d", (int) hp->http_req_rtry_cnt);
            BUFF_WR_UNCONSUME(hp->clt_out);
            if (srv_reconnect(hp) == 0)
                goto out;
    }

    if (!hp->proxy || hp->hstate == HP_TUNNEL || hp->hstate == HP_PASS ||
            hp->hstate == HP_GPDIRECT || hp->hstate == HP_AUTHENTICATED) {

        goto close;
    }

    if ((hp->flags & HF_RESP_RECEIVED) || !hp->auth)
        goto close;

    if (hp->hstate >= HP_RESPONSE && hp->hstate <= HP_AUTH_SEND) {
        bool same_proxy;

        HLOG3("srv_reconnect auth_sessions = %d", hp->auth->sessions);
        same_proxy = http_auth_srv_closing(hp->auth) == 0;
        if (same_proxy && srv_reconnect(hp) < 0)
            goto close;
        if (!same_proxy && srv_reconnect_bad_proxy(hp) < 0)
            goto close;

        hp->hstate = HP_AUTH_SEND;
        wakeup_client(hp);
        if (hp_clt_process(hp, NULL, 0) < 0 || hp_srv_process(hp) < 0)
            goto out_close;

        goto out;
    }

    /* if there is a proxy list perhaps we can connect to the next one */
    if (srv_reconnect_bad_proxy(hp) == 0)
        goto out;

close:
    if (hp->cx && hp->cx->out && hp->cx->out->len > 0) {
        hp->cx->flags |= CXF_FLUSH_CLOSE;
        HLOG2("flush closing");
        if (cx_guest_write(hp->cx) < 0)
            cx_close(hp->cx);
    }
    HLOG3("closing, err %d", err);
    ret = -1;

    if ((hp->flags & HF_RESP_WAITING))
        HLOG3("server closed before response!");

out_close:
    ret = -1;
out:
    return ret;
}

static int srv_write(struct http_ctx *hp, const uint8_t *b, size_t blen)
{
    int ret = 0, r = 0;
    size_t len = 0;
    bool sched_wakeup = true;
    bool written = false;

    if ((hp->flags & HF_CLT_FIN_OK))
        goto out;

    HLOG5("blen %lu", (unsigned long) blen);
    if (hp->clt_out) {
        BUFF_CONSUME_ALL(hp->clt_out);

        if ((hp->flags & (HF_SAVE_REQ_PRX | HF_SAVE_REQ_RTRY)) &&
            ((ssize_t) BUFF_BUFFERED(hp->clt_out)) > (((ssize_t) MAX_GUEST_BUF) - BUF_CHUNK * 2)) {

            HLOG3("WARN buffered too much, cannot save any more req data");
            hp->flags &= (~HF_SAVE_REQ_PRX & ~HF_SAVE_REQ_RTRY);
        } else if ((hp->flags & HF_SAVE_REQ_PRX) && BUFF_BUFFERED(hp->clt_out) > MAX_SAVE_REQ_PRX) {
            HLOG4("WARN buffered too much, clearing save-req flag");
            hp->flags &= ~HF_SAVE_REQ_PRX;
        }

        if (!(hp->flags & (HF_SAVE_REQ_PRX | HF_SAVE_REQ_RTRY)))
            BUFF_WR_GC(hp->clt_out);

        assert(hp->clt_out->wr_len <= hp->clt_out->size);
        len = BUFF_WR_CLEN(hp->clt_out);
    }
    if (hp->clt_out && len) {
        r = 0;
        if (hp->so)
            r = so_write(hp->so, BUFF_WR_BEGINNING(hp->clt_out), len);
        if (r > 0) {
            written = true;
            if (NLOG_LEVEL > 5 && !hide_log_sensitive_data)
                HLOG_DMP(BUFF_BEGINNING(hp->clt_out), r);
            hp->clt_bytes += r;
            if ((hp->flags & HF_REUSABLE))
                hp->flags &= ~HF_REUSE_READY;
            if (TLS_HANDSHAKE_STEP(hp) && tls_read(hp->tls, (uint8_t *) BUFF_BEGINNING(hp->clt_out),
                        r, true) < 0) {
                HLOG("WARNING - TLS error(1), might not be able to check cert revocation");
            }
            BUFF_WR_ADVANCE(hp->clt_out, r);
            if (!hp->cx || !(hp->cx->flags & CXF_GUEST_PROXY) ||
                !(hp->flags & (HF_SAVE_REQ_PRX | HF_SAVE_REQ_RTRY)) ||
                !(hp->flags & HF_RESTARTABLE)) {

                hp->flags &= (~HF_SAVE_REQ_PRX & ~HF_SAVE_REQ_RTRY);
                BUFF_WR_GC(hp->clt_out);
            }
            HLOG5("sent buff %d of %u bytes", r, (unsigned int) len);
        }
        if (r < len) {
            sched_wakeup = false;
            goto out;
        }
    }

    if ((!len || r == len) && (hp->flags & HF_CLT_FIN)) {
        if (hp->so) {
            so_shutdown(hp->so);
            HLOG4("so_shutdown");
        }
        hp->flags |= HF_CLT_FIN_OK;
        goto out;
    }

    if (!blen || !b)
        goto out;

    if (NLOG_LEVEL > 5 && !hide_log_sensitive_data)
        HLOG_DMP((const char *)b, blen);

    ret = 0;
    if (hp->so)
        ret = so_write(hp->so, b, blen);
    if (ret > 0) {
        written = true;
        hp->clt_bytes += ret;
        if ((hp->flags & HF_REUSABLE))
            hp->flags &= ~HF_REUSE_READY;
        hp->flags &= (~HF_SAVE_REQ_RTRY & ~HF_SAVE_REQ_PRX);
        HLOG5("sent %d of %d bytes", ret, (int) blen);
    }
    if (ret < blen)
        sched_wakeup = false;
    if (ret > 0 && TLS_HANDSHAKE_STEP(hp) && tls_read(hp->tls, b, ret, true) < 0) {
        HLOG("WARNING - TLS error(2), might not be able to check cert revocation");
    }
    if (ret < 0)
        ret = 0;
    blen -= ret;
out:
    if (b && blen > 0) {
        size_t spc;

        assert(hp->clt_out);

        spc = BUFF_FREEDOM(hp->clt_out) + hp->clt_out->mx_size - hp->clt_out->size;
        if (blen > spc)
            blen = spc;
        buff_append(hp->clt_out, (const char*) b + ret, blen);
        ret += blen;
        HLOG5("BUFFERED %lu ", (unsigned long) blen);
    }
    if (sched_wakeup)
        wakeup_client(hp);
    if (written && hp->cx && (hp->cx->flags & CXF_HEAD_REQUEST)) {
        hp->cx->flags &= ~CXF_HEAD_REQUEST;
        hp->cx->flags |= CXF_HEAD_REQUEST_SENT;
    }
    return ret;
}

static int srv_writing(struct http_ctx *hp)
{
    assert(hp->so);
    wakeup_client(hp);
    return srv_write(hp, NULL, 0);
}

static void hp_cx_buf_ready(struct http_ctx *hp)
{
    if (!hp)
        return;

    if ((hp->flags & HF_READ_PENDING)) {
        hp->flags &= ~(HF_READ_PENDING);
        if (hp->so)
            so_buf_ready(hp->so);
    }
}

static int hp_clt_process(struct http_ctx *hp, const uint8_t *buf, int len_buf)
{
    int ret = 0;
    struct clt_ctx *cx;
    bool nobuf_write = false;
    bool prx_auth = false;
    int buf_written = 0;

    if (!hp)
        goto out;
    cx = hp->cx;
    if (!cx)
        goto out;

    assert(cx->hp == hp);

    if (hp->hstate == HP_IGNORE || hp->hstate == HP_FLUSH_CLOSE)
        goto out;

    if ((cx->flags & CXF_TLS) && !(cx->hp->flags & HF_TLS)) {
        hp->flags |= HF_TLS;
        if (hp->proxy)
            hp->flags |= HF_TUNNEL;
        if (tls_check_enabled()) {
            hp->tls = tls_new(hp->ni, hp);
            if (!hp->tls) {
                HLOG("error on tls_new");
                goto err;
            }
        } else {
            hp->flags |= HF_TLS_CERT_DONE;
        }
        HLOG3("TLS");
    }

    if (hp->hstate == HP_TUNNEL)
        goto write;
    if (hp->hstate == HP_AUTH_SEND)
        goto auth_srv_send;

    if (hp->hstate == HP_PASS || hp->hstate == HP_GPDIRECT)
        goto write;

    if (NLOG_LEVEL > 5 && !hide_log_sensitive_data && buf)
        HLOG_DMP((const char *)buf, len_buf);

    if (hp->hstate == HP_AUTHENTICATED || hp->hstate == HP_AUTH_TRY)
        goto write;

    if (hp->hstate >= HP_RESPONSE)
        goto out;

    if (hp->hstate == HP_NEW) {

        if ((cx->flags & CXF_TLS))
            hp->flags |= HF_TLS;
        if (hp->proxy && (cx->flags & (CXF_BINARY | CXF_TLS))) {
            hp->flags |= HF_TUNNEL;
            nobuf_write = true;
            goto auth_srv_send;
        }

        /********* no proxy ***********/
        /* SSL and no proxy */
        if (!hp->proxy && ((hp->flags & HF_TLS) | (hp->cx->flags & (CXF_TLS | CXF_BINARY)))) {

            hp->hstate = HP_PASS;
            if (start_direct(hp) < 0)
                goto err;

            goto write;
        }

        if (!hp->proxy) {
            /* direct, but change URL to "relative" */
            if ((hp->cx->flags & CXF_GUEST_PROXY)) {

                hp->hstate = HP_GPDIRECT;
                if (start_gproxy_direct(hp) < 0)
                    goto err;

                goto write_clt_out;
            }

            /* no Gproxy, no HProxy, PASS */
            hp->hstate = HP_PASS;
            if (start_direct(hp) < 0)
                goto err;

            goto write;
        }

        /********* proxy **************/
        assert(hp->proxy);
        hp->hstate = HP_GET_REQUEST;
        if (start_http(hp)) {
            HLOG("ERROR - start_http error");
            goto err;
        }
    }

    /* wait for more data ? */
    assert(hp->hstate == HP_GET_REQUEST);
    if (!(cx->flags & CXF_LONG_REQ) && cx->clt_parser->parse_state != PS_MCOMPLETE)
        goto out;

    hp->hstate = HP_RESPONSE;

    /* through */

    if (!hp->proxy)
        goto out;

    /* through */

auth_srv_send:
    prx_auth = true;
    assert(hp->proxy);
    HLOG4("auth_srv_send");
    hp->hstate = HP_RESPONSE;
    if (IS_TUNNEL(hp))
        nobuf_write = true;
    assert(nobuf_write || len_buf == ret);
    if (prepare_clt_auth(hp) < 0)
        goto err;
    if (hp->auth->logon_required) {
        HLOG2("logon_required");
        hp->auth->sessions = 0;
        hp->hwait_state = HP_AUTH_SEND;
        hp->hstate = HP_WAIT;
        hp->auth->logon_required = 0;
        hp->auth->needs_reconnect = 0;
        /* force needs_reconnect */
        srv_reconnect_wait(hp);

        if (prompt_credentials(hp) < 0) {
            HLOG("prompt_credentials error");
            goto err;
        }

        goto out;
    }
    if (hp->auth->needs_reconnect) {
        hp->auth->needs_reconnect = 0;
        srv_reconnect(hp);
    }

write_clt_out:
    if (prepare_clt_out(hp, prx_auth) < 0)
        goto err;

    /* through */

write:
    buf_written = srv_write(hp, buf && !nobuf_write ? buf + ret : NULL,
            buf ? len_buf - ret : 0);

    /* through */

out:
    ret += buf_written;

    /* through */

out_ret:
    HLOG5("out %d", ret);
    return ret;
err:
    HLOG("ERROR, closing socket");
    hp->hstate = HP_IGNORE;
    hp->flags |= HF_FATAL_ERROR;
    hp_close(hp);
    ret = -1;
    goto out_ret;
}

static int cx_closing(struct clt_ctx *cx, bool rst)
{
    int ret = 0;

    if (rst) {
        cx->flags |= CXF_FORCE_CLOSE;
        goto out_close;
    }
    if ((cx->flags & CXF_NI_FIN))
        goto out_close;
    cx->flags |= CXF_NI_FIN;

    if (!cx->hp || (cx->flags & CXF_GUEST_PROXY) || (cx->hp->flags & HF_REUSABLE))
        goto out_close;

    cx->hp->flags |= HF_CLT_FIN;
    if (srv_write(cx->hp, NULL, 0) < 0)
        goto out_close;
out:
    return ret;
out_close:
    cx_close(cx);
    ret = -1;
    goto out;
}

static int hp_srv_process(struct http_ctx *hp)
{
    int ret = 0;
    bool resp_complete = false;
    bool conn_close = false;
    bool done_reconnect = false;
    int auth_state;
    size_t lparsed = 0;
    bool needs_consume = false;
    bool remove_hpd = false;

    if (!hp->cx)
        goto out;

    if (hp->cstate != S_CONNECTED)
        goto out;

    if (hp->hstate == HP_IGNORE || hp->hstate == HP_FLUSH_CLOSE)
        goto out;

    /* do we need to parse here ? */
    if ((!(hp->flags & HF_PARSE_ERROR) && ((hp->flags & HF_RESTARTABLE) || hp->proxy)) &&
       hp->cx->out->len && (hp->hstate != HP_TUNNEL)) {

        bool headers_just_received = false;
        bool parse_error = false;

        lparsed = HTTP_PARSE_BUFF(hp->cx->srv_parser, hp->cx->out);
        needs_consume = true;
        if (lparsed != hp->cx->out->len)
            parse_error = true;

        if (!(hp->flags & HF_RESP_RECEIVED) && hp->cx->srv_parser->h.status_code &&
            hp->cx->srv_parser->h.status_code != 407) {

            srv_response_received(hp);
        }

        conn_close = hp->cx->srv_parser->conn_close != 0;
        resp_complete = hp->cx->srv_parser->parse_state == PS_MCOMPLETE;
        if (!hp->cx->srv_parser->headers_parsed && (resp_complete ||
                    hp->cx->srv_parser->parse_state == PS_HCOMPLETE)) {

            headers_just_received = true;
            hp->cx->srv_parser->headers_parsed = 1;
            hp->flags &= ~HF_KEEP_ALIVE;
            if (!conn_close && ((hp->cx->srv_parser->h.http_major == 1 &&
                hp->cx->srv_parser->h.http_minor > 0) || hp->cx->srv_parser->keep_alive)) {

                hp->flags |= HF_KEEP_ALIVE;
            } else {
                HLOG5("NOT KEEP_ALIVE");
            }

            if (hp->cx->srv_parser->h.status_code != 407 && hp->c407_buff) {
                hp->flags &= ~HF_407_MESSAGE_OK;
                buff_free(&hp->c407_buff);
            }
        }

        if (hp->cx->srv_parser->headers_parsed && hp->cx->srv_parser->h.status_code == 407) {
            if (!hp->c407_buff && !buff_new_priv(&hp->c407_buff, SO_READBUFLEN))
                goto mem_err;

            if (headers_just_received) {
                BUFF_RESET(hp->c407_buff);
                if (BUFF_APPENDFROM(hp->c407_buff, hp->cx->out, 0) < 0)
                    goto mem_err;
            } else if (BUFF_APPENDB(hp->c407_buff, hp->cx->out) < 0) {
                goto mem_err;
            }

            if (resp_complete) {
                hp->flags |= HF_407_MESSAGE_OK;
                if ((hp->flags & HF_407_MESSAGE)) {
                    end_407_message(hp);
                    goto out_close;
                }
            }
        }

        /* the HTTP response to a HEAD request or a 1xx, 204 or 304 response must not contain
         * body */
        if ((resp_complete || hp->cx->srv_parser->parse_state == PS_HCOMPLETE) &&
            ((hp->cx->flags & CXF_HEAD_REQUEST_SENT) ||
             (hp->cx->srv_parser->h.status_code >= 100 && hp->cx->srv_parser->h.status_code < 200) ||
             hp->cx->srv_parser->h.status_code == 204 || hp->cx->srv_parser->h.status_code == 304)) {

               hp->cx->flags &= ~CXF_HEAD_REQUEST_SENT;
               resp_complete = true;
               hp->cx->srv_parser->parse_state = PS_MCOMPLETE;
               HLOG5("NO BODY resp_complete");
        }
        if (!(hp->cx->flags & (CXF_TLS|CXF_BINARY|CXF_TUNNEL_GUEST)) &&
                hp->cx->srv_parser->http_close) {

            hp->flags |= HF_HTTP_CLOSE;
        }

        if (parse_error) {
            HLOG2("HTTP parse error. lparsed %u for %u, errno %d pl %d ml "
                    "%d cl %ld",
                    (unsigned int) lparsed, (unsigned int) hp->cx->out->len,
                    (int) hp->cx->srv_parser->parser.http_errno,
                    (int) hp->cx->srv_parser->parsed_len,
                    (int) hp->cx->srv_parser->message_len,
                    (long) hp->cx->srv_parser->parser.content_length);

            hp->flags &= (~HF_RESTARTABLE & ~HF_RESTART_OK & ~HF_REUSABLE & ~HF_REUSE_READY);
            hp->flags |= HF_PARSE_ERROR;
            hp->cx->flags |= CXF_RESET_STATE;
            if (hp->hpd)
                remove_hpd = true;
            HLOG5("HF_PARSE_ERROR, CXF_RESET_STATE");
            if (!hp->cx->srv_parser->h.status_code || hp->cx->srv_parser->h.status_code == 407) {
                HLOG("ERROR - HTTP parse error. cannot obtain HTTP response code or got 407 code %d",
                     (int) hp->cx->srv_parser->h.status_code);
                if (!hide_log_sensitive_data) {
                    BUFF_UNCONSUME(hp->cx->out);
                    HLOG_DMP(BUFF_CSTR(hp->cx->out), hp->cx->out->len);
                }
                goto err;
            }

            if ((hp->cx->srv_parser->parse_state == PS_HCOMPLETE ||
               hp->cx->srv_parser->parse_state == PS_MCOMPLETE)) {

                hp->cx->srv_parser->http_close = 1;
                hp->flags |= HF_HTTP_CLOSE;
            }

            if (hp->proxy && hp->hstate == HP_RESPONSE) {
                HLOG2("http parse error, ignoring as authorized anyway ...");
                goto authorize;
            }
        }

        if ((hp->cx->flags & CXF_GUEST_PROXY) && headers_just_received &&
             hp->cx->srv_parser->h.status_code == 401) {

             size_t i;
             bool has_www_authenticate = false;
             bool has_proxy_support = false;
             bool pin_connection = false;

             for (i = 0; i <= hp->cx->srv_parser->h.crt_header; i++) {
                struct header_field *hdr;

                if (i >= NUM_HEADERS)
                    break;
                hdr = hp->cx->srv_parser->h.headers + i;

                if (!hdr->name || !hdr->value)
                    continue;
                if (strcasecmp(BUFF_CSTR(hdr->name), S_WWW_AUTHENTICATE) == 0 &&
                    (strncasecmp(BUFF_CSTR(hdr->value), "NTLM", 4) == 0 ||
                     strncasecmp(BUFF_CSTR(hdr->value), "Negotiate", 9) == 0 ||
                     strncasecmp(BUFF_CSTR(hdr->value), "Kerberos", 8) == 0)) {

                    has_www_authenticate = true;
                }

                if (strcasecmp(BUFF_CSTR(hdr->name), S_PROXY_SUPPORT) == 0 &&
                    strcasecmp(BUFF_CSTR(hdr->value), S_PS_SESSION_BASED_AUTH) == 0) {

                    has_proxy_support = true;
                }
             }

             if (has_www_authenticate && (!hp->proxy || has_proxy_support))
                 pin_connection = true;

             if (pin_connection) {
                 hp->flags &= ((~HF_REUSABLE) & (~HF_REUSE_READY));
                 hp->flags |= HF_PINNED;
             }

             if (pin_connection && has_www_authenticate && !has_proxy_support) {
                 size_t extra_hlen = STRLEN(S_HDR_PS_SESSION_BASED_AUTH);
                 char *p;
                 size_t len;

                 HLOG4("adding Proxy-Support header line");
                 if (BUFF_FREEDOM(hp->cx->out) < extra_hlen && BUFF_ENLARGE(hp->cx->out,
                             extra_hlen) < 0) {

                    HLOG("malloc ERROR");
                    goto err;
                 }

                 p = BUFF_BEGINNING(hp->cx->out);
                 len = BUFF_BUFFERED(hp->cx->out);

                 if (len > 2 && hp->cx->srv_parser->h.header_length > 2 &&
                     len >= hp->cx->srv_parser->h.header_length) {

                     size_t pos;

                     pos = hp->cx->srv_parser->h.header_length - 2; /* before last \r\n */
                     memmove(p + pos + extra_hlen, p + pos, len - pos);
                     memcpy(p + pos, S_HDR_PS_SESSION_BASED_AUTH, extra_hlen);
                     hp->cx->out->len += extra_hlen;
                     hp->cx->out->m[hp->cx->out->len] = 0;
                 } else {
                    HLOG("WARNING - strange header len %u, buffered %u",
                            (unsigned) hp->cx->srv_parser->h.header_length,
                            (unsigned) len);
                 }
             }
        }
    }

    if ((hp->hstate == HP_TUNNEL || hp->hstate == HP_PASS || hp->hstate == HP_GPDIRECT ||
            hp->hstate == HP_AUTHENTICATED)) {

        goto write_guest;
    }

    if (!hp->cx->out || !hp->cx->srv_parser)
        goto out;

    assert(hp->proxy);


    if (BUFF_BUFFERED(hp->cx->out) >= MAX_SRV_BUFLEN - BUF_CHUNK) {
        HLOG("ERROR - MAX_SRV_BUFLEN (%d) reached", (int) MAX_SRV_BUFLEN);
        goto err;
    }

    /* we have to wait for more data ? */
    if (!resp_complete && hp->cx->srv_parser->parse_state != PS_HCOMPLETE)
        goto out;

    if (hp->hstate == HP_AUTH_SEND)
        goto auth_srv_send;

    if (hp->hstate == HP_RESPONSE_CONSUME) {
        BUFF_RESET(hp->cx->out);
        if (!resp_complete)
            goto out;
        hp->hstate = hp->hwait_state;

        if (hp->hstate == HP_TUNNEL)
            goto prepare_tunnel;

        if (hp->hstate == HP_AUTH_SEND)
            goto auth_srv_send;

        HLOG("ERROR - strange hwait_state %d", hp->hstate);
        goto err;
    }

    HLOG3("received HTTP %d", hp->cx->srv_parser->h.status_code);

    if (hp->proxy && (hp->cx->flags & CXF_GUEST_PROXY) &&
        hp->cx->srv_parser->h.status_code != 407) {

        hp->flags |= HF_MONITOR_407;
        hp->flags &= ~HF_SAVE_REQ_PRX;
    }

    if (hp->hstate == HP_AUTH_TRY) {
        if (hp->cx->srv_parser->h.status_code == 407) {
            HLOG("ERROR - oops long_req but still not authorized. pity ...");
            BUFF_UNCONSUME(hp->cx->out);
            if (!hide_log_sensitive_data)
                HLOG_DMP(BUFF_CSTR(hp->cx->out), hp->cx->out->len);

            goto err;
        }

        NETLOG2("%s: long_req with success :-)", __FUNCTION__);
        goto authorize;
    }
    if (hp->hstate != HP_RESPONSE)
        goto out;
    /* headers complete */
    auth_state = http_auth_srv(hp->auth, &hp->cx->srv_parser->h);
    if (auth_state == AUTH_ERR) {
        HLOG("ERROR - http-auth error");
        BUFF_UNCONSUME(hp->cx->out);
        if (!hide_log_sensitive_data)
            HLOG_DMP(BUFF_CSTR(hp->cx->out), hp->cx->out->len);

        goto err;
    }

    if (auth_state == AUTH_RESTART) {
        struct clt_ctx *cx;

        cx = hp->cx;
        HLOG3("prompted for auth, need to retry the request");
        if (!(hp->flags & HF_SAVE_REQ_PRX)) {
            HLOG("ERROR - cannot retry the request as HF_SAVE_REQ_PRX is not set!");
            goto err;
        }
        if ((hp->flags & HF_PINNED)) {
            HLOG("ERROR - cannot retry the request as HF_PINNED is set!");
            goto err;
        }
        hp->flags &= (~HF_HTTP_CLOSE & ~HF_FATAL_ERROR & ~HF_REUSABLE);
        if (cx->out)
            BUFF_RESET(cx->out);
        if (cx->srv_parser)
            parser_reset(cx->srv_parser);
        if (cx_hp_disconnect(cx) < 0)
            goto err;
        if (cx_process(cx, NULL, 0) < 0)
            goto err;

        goto out;
    }

    if (auth_state == AUTH_PROGRESS) {
        BUFF_RESET(hp->cx->out);

        /* AUTH_PROGRESS and message complete */
        if (resp_complete)
            goto auth_srv_send;

        hp->hstate = HP_RESPONSE_CONSUME;
        hp->hwait_state = HP_AUTH_SEND;
        goto out;
    }

    if (auth_state == AUTH_PASS) {
        /* is http and authorized */
        if (!IS_TUNNEL(hp))
            goto authorize;

        /* HTTP CONNECT response, consume it and ignore the response */
        if (hp->cx->srv_parser->h.status_code != 200) {
            HLOG("ERROR - failed, AUTH_PASS but CONNECT response != 200 %d",
                    hp->cx->srv_parser->h.status_code);
            BUFF_UNCONSUME(hp->cx->out);
            if (!hide_log_sensitive_data)
                HLOG_DMP(BUFF_CSTR(hp->cx->out), hp->cx->out->len);

            goto err;
        }

        goto prepare_tunnel;
    }

    HLOG("error, strange auth_state %d", auth_state);
    goto err;

prepare_tunnel:
    hp->hstate = HP_TUNNEL;
    if (start_tunnel(hp))
        goto err;
    goto out;

auth_srv_send:
    HLOG4("auth_srv_send");
    hp->hstate = HP_RESPONSE;
    if (conn_close) {
        if (http_auth_srv_closing(hp->auth)) {
            HLOG("Connection: close received and auth would not reconnect");
            goto err;
        }
        srv_reconnect(hp);
        done_reconnect = true;
    }
    if (!hp->auth->logon_required && prepare_clt_auth(hp) < 0)
        goto err;
    if (!hp->auth->logon_required && hp->auth->needs_reconnect) {
        srv_reconnect(hp);
        done_reconnect = true;
    }
    if (hp->auth->logon_required) {
        HLOG2("logon_required");
        hp->auth->sessions = 0;
        hp->hwait_state = HP_AUTH_SEND;
        hp->hstate = HP_WAIT;
        hp->auth->logon_required = 0;
        hp->auth->needs_reconnect = 0;
        /* force needs_reconnect */
        srv_reconnect_wait(hp);
        done_reconnect = true;

        if (prompt_credentials(hp) < 0) {
            HLOG("prompt_credentials error");
            goto err;
        }

        goto out;
    }
    if (conn_close && !done_reconnect) {
        srv_reconnect(hp);
        done_reconnect = true;
    }
    hp->auth->needs_reconnect = 0;
    if (prepare_clt_out(hp, true) < 0)
        goto err;
    srv_write(hp, NULL, 0);
    goto out;

authorize:
    hp->hstate = HP_AUTHENTICATED;
    start_authenticate(hp);
    /* through */
write_guest:
    if (hp->cx && hp->cx->out) {
        BUFF_CONSUME_ALL(hp->cx->out);
        needs_consume = false;
    }
    if (hp->cx)
        ret = cx_guest_write(hp->cx);
    wakeup_client(hp);
    /* through */
out:
    if (conn_close && !done_reconnect) {
        hp->flags |= HF_HTTP_CLOSE;
        hp->flags &= (~HF_REUSABLE & ~HF_REUSE_READY);
    }
    if (needs_consume && hp->cx && hp->cx->out)
        BUFF_CONSUME_ALL(hp->cx->out);
    if ((remove_hpd || (hp->flags & HF_PINNED)) && hp->hpd)
        hp_remove_hpd(hp);
    return ret;
err:
    HLOG("ERROR");
    hp->flags |= HF_FATAL_ERROR;
out_close:
    needs_consume = false;
    hp_close(hp);
    ret = -1;
    goto out;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    goto err;
}

static void srv_response_received(struct http_ctx *hp)
{
    hp->flags |= HF_RESP_RECEIVED;

    if (hp->cx && hp->cx->alternative_proxies) {
        free(hp->cx->alternative_proxies);
        hp->cx->alternative_proxies = NULL;
    }
}

static void refresh_prompt_cred_states(int cancel)
{
    struct http_ctx *hp, *hp_next;

    LIST_FOREACH_SAFE(hp, &http_list, entry, hp_next) {
        if (cancel) {
            if (hp->proxy && start_407_message(hp) < 0)
                hp_close(hp);

            continue;
        }

        if (hp->hstate != HP_WAIT)
            continue;

        if ((hp->flags & HF_NEEDS_RECONNECT)) {
            hp->flags &= (~HF_NEEDS_RECONNECT);
            srv_reconnect(hp);
        }
        hp->hstate = hp->hwait_state;
        hp->hwait_state = 0;
        wakeup_client(hp);
        if (hp_clt_process(hp, NULL, 0) < 0 || hp_srv_process(hp) < 0) {
            hp_close(hp);
            continue;
        }
        HLOG2("refresh prompt");
    }

    if (cancel)
        proxy_cache_reset();

}

static int prompt_credentials(struct http_ctx *hp)
{
    int ret = 0;
    dict d = NULL;
    char buf[64];
    const char *target_name;

    target_name = hp->proxy->name;
    if (hp->proxy->canon_name && (hp->proxy->ct == AUTH_TYPE_NEGOTIATE ||
                                  hp->proxy->ct == AUTH_TYPE_KERBEROS)) {

        target_name = hp->proxy->canon_name;
    }

    proxy_cache_reset();
    HLOG2("Prompting for credentials, proxy %s:%hu (target name %s)", hp->proxy->name,
            ntohs(hp->proxy->port), target_name);
    d = dict_new();
    if (!d) {
        ret = -1;
        goto out;
    }
    dict_put_string(d, "proxy_server_hostname", target_name);
    buf[63] = 0;
    snprintf(buf, 63, "%lu", (unsigned long) 0); // XXX no actual need of "proxy_server" value
    dict_put_string(d, "proxy_server", buf);
    dict_put_integer(d, "proxy_port", ntohs(hp->proxy->port));
    dict_put_integer(d, "ct", hp->proxy->ct);
    dict_put_string(d, "realm", hp->proxy->realm ?
            hp->proxy->realm : "");
    buf[63] = 0;
    snprintf(buf, 63, "%" PRId64, prx_refresh_id);
    dict_put_string(d, "last_refresh", buf);
    ret = ni_rpc_send(hp->ni, "nc_PromptForCredentials", d, NULL, NULL);
out:
    if (d)
        dict_free(d);
    return ret;
}

static int srv_connect_direct(struct http_ctx *hp)
{
    int ret = 0;

    assert(hp->h.sv_name && hp->h.daddr.sin_port);
    if (!hp->h.sv_name) {
        HLOG("ERROR - bug!, sv_name NULL");
        ret = -1;
        goto out;
    }

    hp->proxy = NULL;
    if (hp->auth)
        hp->auth->proxy = NULL;
    if (hp->cx)
        hp->cx->proxy = NULL;

    if (hp->cx && (hp->cx->flags & CXF_GUEST_PROXY)) {
        struct net_addr _a[2], *a;

        a = &_a[0];
        memset(&_a[0], 0, sizeof(_a));
        if (inet_aton(hp->h.sv_name, &a->ipv4) != 0) {
            hp->h.daddr.sin_addr = a->ipv4;
            hp->flags |= HF_RESOLVED;
        } else if (inet_pton(AF_INET6, hp->h.sv_name, (void *) &a->ipv6) == 1) {
            a->family = AF_INET6;
            hp->flags |= HF_RESOLVED;
            hp->cstate = S_RESOLVED;
            ret = srv_connect_dns_resolved(hp, a);
            goto out;
        }
    }

    if (!IS_RESOLVED(hp)) {
        if (hp->a) {
            free(hp->a);
            hp->a = NULL;
        }
        ret = srv_connect_dns_direct(hp);

        goto out;
    }

    if (!fakedns_is_fake(&hp->h.daddr.sin_addr)) {
        hp->cstate = S_RESOLVED;
        if ((ret = srv_connect_ipv4(hp, hp->h.daddr.sin_addr.s_addr, hp->h.daddr.sin_port)))
            goto out;
    } else {
        struct net_addr *a;

        a = fakedns_get_ips(hp->h.daddr.sin_addr);
        if (a && a[0].family) {
            hp->cstate = S_RESOLVED;
            ret = srv_connect_dns_resolved(hp, a);
            goto out;
        }

        /* We have not yet obtained the real ip ...
         * There must be already a dns lookup in progress with callbacks from the dns-fake code,
         * so no need to do it here.
        */
    }

out:
    return ret;
}

static void dns_lookup_sync(void *opaque)
{
    struct dns_connect_ctx *dns = opaque;

    if (!dns->domain)
        return;

    NETLOG2("%s: dns lookup for %s", __FUNCTION__, dns->domain);
    assert(dns->hp);
    if (dns->containment_check)
        dns->response = dns_lookup_containment(dns->hp->ni, dns->domain, dns->proxy_on);
    else
        dns->response = dns_lookup(dns->domain);
}

static void dns_proxy_connect_cb(void *opaque)
{
    struct dns_connect_ctx *dns = opaque;
    struct http_ctx *hp;

    hp = dns->hp;
    hp_put(hp);
    if ((hp->flags & HF_CLOSED))
        goto out;

    assert(hp->proxy);
    if (dns->response.denied) {
        HLOG("%s DENIED by containment", dns->domain ? dns->domain : "(null)");
        if (hp->cx && (hp->cx->flags & CXF_GUEST_PROXY))
            cx_proxy_response(hp->cx, HMSG_CONNECT_DENIED, true);
        hp_close(hp);
        goto out;
    }
    if (dns->response.err || !dns->response.a || !dns->response.a[0].family) {
        HLOG("ERROR - dns lookup fail for %s", dns->domain ? dns->domain : "(null)");
        if (srv_reconnect_bad_proxy(hp) < 0)
            hp_close(hp);
        goto out;
    }

    free(hp->proxy->a);
    hp->proxy->a = dns_ips_dup(dns->response.a);
    if (!hp->proxy->a) {
        warnx("%s: malloc", __FUNCTION__);
        goto out;
    }
    hp->proxy->resolved = 1;
    hp->cstate = S_RESOLVED;
    free(hp->proxy->canon_name);
    hp->proxy->canon_name = NULL;
    if (dns->response.canon_name)
        hp->proxy->canon_name = strdup(dns->response.canon_name);

    if (srv_connect_list(hp, hp->proxy->a, hp->proxy->port) < 0) {
        HLOG("srv_connect_list fail");
        if (srv_reconnect_bad_proxy(hp) < 0)
            hp_close(hp);
        goto out;
    }

out:
    dns_response_free(&dns->response);
    free(dns->domain);
    free(dns);
}

static void dns_direct_connect_cb(void *opaque)
{
    struct dns_connect_ctx *dns = opaque;
    struct http_ctx *hp;

    hp = dns->hp;
    hp_put(hp);
    if ((hp->flags & HF_CLOSED))
        goto out;

    assert(!hp->proxy);
    if (dns->response.denied) {
        HLOG("%s DENIED by containment", dns->domain ? dns->domain : "(null)");
        if (hp->cx && (hp->cx->flags & CXF_GUEST_PROXY))
            cx_proxy_response(hp->cx, HMSG_CONNECT_DENIED, true);
        hp_close(hp);
        goto out;
    }
    if (dns->response.err || !dns->response.a || !dns->response.a[0].family) {
        HLOG("dns lookup fail for %s", dns->domain ? dns->domain : "(null)");
        if ((hp->cx && !(hp->cx->flags & CXF_GUEST_PROXY)) ||
             (hp->cx && cx_proxy_response(hp->cx, HMSG_DNS_LOOKUP_FAILED, true) < 0)) {

            hp_close(hp);
        }
        goto out;
    }
    free(hp->a);
    hp->a = dns_ips_dup(dns->response.a);
    if (!hp->a) {
        warnx("%s: malloc", __FUNCTION__);
        hp_close(hp);
        goto out;
    }
    hp->cstate = S_RESOLVED;
    if (srv_connect_list(hp, hp->a, hp->h.daddr.sin_port) < 0) {
        HLOG("ERROR - srv_connect_list fail");
        if ((hp->cx && !(hp->cx->flags & CXF_GUEST_PROXY)) ||
             (hp->cx && cx_proxy_response(hp->cx, HMSG_CONNECT_FAILED, true) < 0)) {

            hp_close(hp);
        }
        goto out;
    }

out:
    dns_response_free(&dns->response);
    free(dns->domain);
    free(dns);
}

static int dns_connect_proxy_async(struct http_ctx *hp)
{
    int ret = -1;
    struct dns_connect_ctx *dns = NULL;

    assert(hp->proxy);
    assert(hp->proxy->name);
    dns = calloc(1, sizeof(*dns));
    if (!dns)
        goto mem_err;

    dns->hp = hp;
    dns->port = hp->proxy->port;
    dns->domain = strdup(hp->proxy->name);
    if (!dns->domain)
        goto mem_err;

    hp_get(hp);
    if (ni_schedule_bh(hp->ni, dns_lookup_sync, dns_proxy_connect_cb, dns)) {
        hp_put(hp);
        HLOG("unet_schedule_bh FAILURE");
        goto cleanup;
    }

    ret = 0;
out:
    return ret;
cleanup:
    if (dns)
        free(dns->domain);
    free(dns);
    goto out;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    ret = -1;
    goto cleanup;
}

static int srv_connect_dns_direct(struct http_ctx *hp)
{
    int ret = -1;
    struct dns_connect_ctx *dns = NULL;

    assert(!hp->proxy && hp->h.daddr.sin_port);
    dns = calloc(1, sizeof(*dns));
    if (!dns)
        goto mem_err;

    dns->hp = hp;
    dns->port = hp->h.daddr.sin_port;
    dns->domain = strdup(hp->h.sv_name);
    dns->containment_check = 1;
    if (!dns->domain)
        goto mem_err;

    hp_get(hp);
    if (ni_schedule_bh(hp->ni, dns_lookup_sync, dns_direct_connect_cb, dns)) {
        hp_put(hp);
        HLOG("ERROR - unet_schedule_bh failure");
        goto cleanup;
    }

    ret = 0;
out:
    return ret;
cleanup:
    if (dns)
        free(dns->domain);
    free(dns);
    goto out;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    ret = -1;
    goto cleanup;
}

static void on_fakeip_blocked(struct in_addr addr)
{
    struct http_ctx *hp, *hp_next;

    LIST_FOREACH_SAFE(hp, &http_list, entry, hp_next) {
        if (hp->h.daddr.sin_addr.s_addr == addr.s_addr) {
            HLOG("connection G -> %s:%hu denied. closing connection",
                    hp->h.sv_name ? hp->h.sv_name : "(NULL)", ntohs(hp->h.daddr.sin_port));
            hp_close(hp);
        }
    }
}

static void on_fakeip_update(struct in_addr fkaddr, struct net_addr *a)
{
    struct http_ctx *hp, *hp_next;

    LIST_FOREACH_SAFE(hp, &http_list, entry, hp_next) {
        if (hp->h.daddr.sin_addr.s_addr != fkaddr.s_addr)
            continue;

        HLOG3("");
        if (hp->cstate < S_RESOLVED)
            hp->cstate = S_RESOLVED;
        if (hp->cstate == S_RESOLVED && srv_connect_dns_resolved(hp, a) < 0)
            hp_close(hp);
    }
}

static int hp_connecting_containment(struct http_ctx *hp, const struct net_addr *a, uint16_t port)
{
    struct sockaddr_in saddr, daddr;

    if (hp->proxy || (hp->flags & HF_IP_CHECKED))
        return 0;

    if (!hp->cx)
        return 0;

    if (!a || a->family != AF_INET)
        return 0; // XXX check IPv6
    daddr.sin_addr.s_addr = a->ipv4.s_addr;
    daddr.sin_port = port;

    hp->flags |= HF_IP_CHECKED;
    memset(&saddr, 0, sizeof(saddr));
    if (hp->cx && hp->cx->ni_opaque)
        saddr = tcpip_get_gaddr(hp->cx->ni_opaque);
    return ac_gproxy_allow(hp->ni, saddr, daddr) ? 0 : -1;
}

static int srv_connect(struct http_ctx *hp, const struct net_addr *a, uint16_t port)
{
    HLOG4("");
    struct lava_event *lv = NULL;

    if (hp->cx)
        lv = tcpip_lava_get(hp->cx->ni_opaque);
    if (hp->proxy)
        lava_event_set_proxy(lv);

    if (hp_connecting_containment(hp, a, port) < 0) {
        HLOG("connection DENIED");
        if (hp->cx) {
            lava_event_set_denied(lv);
            cx_proxy_response(hp->cx, HMSG_CONNECT_DENIED, true);
        }
        hp->hstate = HP_IGNORE;
        return -1;
    }

    if (!hp->so && !(hp->so = so_create(hp->ni, false, hp_event, hp))) {
        HLOG("ERROR on so_create");
        return -1;
    }

    lava_event_remote_set(lv, a, port);
    return so_connect(hp->so, a, port);
}

static int srv_connect_ipv4(struct http_ctx *hp, uint32_t srv_addr, uint16_t srv_port)
{
    struct net_addr a;

    memset(&a, 0, sizeof(a));
    a.family = AF_INET;
    a.ipv4.s_addr = srv_addr;

    HLOG4("to %s:%hu", inet_ntoa(a.ipv4), ntohs(srv_port));
    return srv_connect(hp, &a, srv_port);
}

static int srv_connect_list(struct http_ctx *hp, struct net_addr *a, uint16_t port)
{
    int ret = -1;
    struct lava_event *lv = NULL;

    if (hp->cx)
        lv = tcpip_lava_get(hp->cx->ni_opaque);
    if (hp->proxy)
        lava_event_set_proxy(lv);

    HLOG4("");

    if (!hp->so && !(hp->so = so_create(hp->ni, false, hp_event, hp))) {
        HLOG("ERROR on so_create");
        goto out;
    }

    assert(a && a[0].family);
    if (a[1].family) {
        const struct net_addr *hyb_addr;

        hyb_addr = dns_hyb_addr(a);
        if (hyb_addr) {
            ret = srv_connect(hp, hyb_addr, port);
        }  else {
            lava_event_remote_set(lv, a, port);
            ret = so_connect_list(hp->so, a, port);
        }
    } else {
        ret = srv_connect(hp, a, port);
    }

out:
    return ret;
}

static int srv_connect_dns_resolved(struct http_ctx *hp, struct net_addr *a)
{
    int ret = -1;

    HLOG4("");

    if (hp->proxy) {
        NETLOG4("%s: already using a proxy. do nothing.", __FUNCTION__);
        ret = 0;
        goto out;
    }

    if (!a || !a[0].family) {
        HLOG2("dns lookup fail for %s", hp->h.sv_name ? hp->h.sv_name : "(null)");
        goto out;
    }

    if (srv_connect_list(hp, a, hp->h.daddr.sin_port)) {
        HLOG("srv_connect_list FAILURE");
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int srv_connect_proxy(struct http_ctx *hp, struct proxy_t *proxy)
{
    struct in_addr addr = {.s_addr = 0};

    assert(proxy);
    hp->proxy = proxy;
    if (hp->auth)
        hp->auth->proxy = proxy;

    if (inet_aton(proxy->name, &addr) != 0) {
        free(proxy->a);
        proxy->a = calloc(1, 2 * sizeof(*(proxy->a)));
        if (!proxy->a) {
            warnx("%s: malloc", __FUNCTION__);
            return -1;
        }
        proxy->a[0].family = AF_INET;
        proxy->a[0].ipv4 = addr;
        proxy->resolved = 1;
        hp->cstate = S_RESOLVED;
        return srv_connect_ipv4(hp, addr.s_addr, proxy->port);
    }

    if (proxy->resolved) {
        hp->cstate = S_RESOLVED;
        return srv_connect_list(hp, proxy->a, proxy->port);
    }

    /* we need to do async lookup */
    return dns_connect_proxy_async(hp);
}

static void get_uset_agent_cb(void *opaque)
{
    struct nickel *ni = opaque;


    if (ni_rpc_send(ni, "nc_GetUserAgent", NULL, rpc_user_agent_cb, NULL))
        NETLOG("%s: ni_rpc_send FAILURE", __FUNCTION__);
}

static void set_settings(struct nickel *ni, yajl_val config)
{
    const char *proxy_str, *tmp;
    char *pstr = NULL, *p;
    const char *custom_ntlm_creds_ = NULL;
    unsigned int port;
    int64_t max_n_socks;
    bool s_max_n_socks = false;

    if (!user_agent) {
        tmp = yajl_object_get_string(config, "user-agent");
        if (tmp) {
            user_agent = strdup(tmp);
            if (!user_agent)
                goto mem_err;
            NETLOG2("%s: user-agent '%s'", __FUNCTION__, user_agent);
        }

        if (!user_agent && ni_schedule_bh(ni, NULL, get_uset_agent_cb, ni) < 0) {
            NETLOG("%s: ERROR - ni_schedule_bh failed", __FUNCTION__);
            goto cleanup;
        }
    }

    disable_crl_check = yajl_object_get_bool_default(config, "disable-crl-check", 0);
    NETLOG("%s: SSL CRL check %s", __FUNCTION__, disable_crl_check ?
           "DISABLED" : "ENABLED");
    no_transparent_proxy = yajl_object_get_bool_default(config, "no-transparent-proxy-mode", 0);
    NETLOG("%s: no-transparent-proxy-mode is %s", __FUNCTION__, no_transparent_proxy ? "ON" : "OFF");

    custom_ntlm_creds_ = yajl_object_get_string(config, "custom-ntlm-creds");
    if (custom_ntlm_creds_) {
        char *p, *q, *tmp = NULL;
        int i, j;

        tmp = strdup(custom_ntlm_creds_);
        if (!tmp)
            goto mem_err;
        custom_ntlm = calloc(1, sizeof(*custom_ntlm));
        if (!custom_ntlm)
            goto mem_err;

        p = tmp;
        q = strchr(p, ' ');
        if (!q) {
            NETLOG("%s: ERROR! malformed custom-ntlm-creds param", __FUNCTION__);
            goto cleanup;
        }
        *q = 0;
        if (q != p) {
            custom_ntlm->w_domain = base64_decode(p, &custom_ntlm->w_domain_len);
            if (!custom_ntlm->w_domain) {
                NETLOG("%s ERROR! base64_decode error", __FUNCTION__);
                goto cleanup;
            }
            custom_ntlm->domain = calloc(1, custom_ntlm->w_domain_len + 1);
            if (!custom_ntlm->domain)
                goto mem_err;

            j = 0;
            for (i = 0; i < custom_ntlm->w_domain_len; i += 2) {
                uint8_t c;

                if (custom_ntlm->w_domain[i + 1] != 0)
                    continue;
                c = custom_ntlm->w_domain[i];
                if (c < 32 || c >= 127)
                    continue;
                custom_ntlm->domain[j++] = c;
            }
        }

        p = q + 1;
        q = strchr(p, ' ');
        if (!q) {
            NETLOG("%s: ERROR! malformed custom-ntlm-creds param", __FUNCTION__);
            goto cleanup;
        }
        *q = 0;
        custom_ntlm->w_username = base64_decode(p, &custom_ntlm->w_username_len);
        if (!custom_ntlm->w_username) {
            NETLOG("%s ERROR! base64_decode error (2)", __FUNCTION__);
            goto cleanup;
        }

#ifdef NTLM_MAKE_USERNAME_UPPERCASE
        for (i = 0; i < custom_ntlm->w_username_len; i += 2) {
            uint8_t c;

            if (custom_ntlm->w_username[i + 1] != 0)
                continue;
            c = custom_ntlm->w_username[i];
            if (c < 32 || c >= 127)
                continue;
            custom_ntlm->w_username[i] = (uint8_t) toupper((int) c);
        }
#endif

        custom_ntlm->username = calloc(1, custom_ntlm->w_username_len + 1);
        if (!custom_ntlm->username)
            goto mem_err;

        j = 0;
        for (i = 0; i < custom_ntlm->w_username_len; i += 2) {
            uint8_t c;

            if (custom_ntlm->w_username[i + 1] != 0)
                continue;
            c = custom_ntlm->w_username[i];
            if (c < 32 || c >= 127)
                continue;
            custom_ntlm->username[j++] = c;
        }
        p = q + 1;
        if (!*p) {
            NETLOG("%s: ERROR! malformed custom-ntlm-creds param, no hash", __FUNCTION__);
            goto cleanup;
        }
        if (strlen(p) != (16 * 2)) {
            NETLOG("%s: ERROR! malformed custom-ntlm-creds param, wrong hash len %u", __FUNCTION__,
                    (unsigned) strlen(p));
            goto cleanup;
        }
        custom_ntlm->ntlm_hash = calloc(1, 32 + 2);
        if (!custom_ntlm->ntlm_hash)
            goto mem_err;
        for (i = 0; i < 16; i++) {
            uint8_t c;

            c = 0;
            for (j = 0; j < 2; j++) {
                uint8_t cc;

                c <<= 4;
                cc = p[i * 2 + j];
                if (cc >= '0' && cc <= '9')
                    cc -= '0';
                else if (cc >= 'A' && cc <= 'F')
                    cc = cc - 'A' + 10;
                else if (cc >= 'a' && cc <= 'f')
                    cc = cc - 'a' + 10;
                else {
                    NETLOG("%s: ERROR! malformed custom-ntlm-creds param, wrong hash encoding",
                          __FUNCTION__);
                    goto cleanup;
                }
                c |= cc;
            }
            custom_ntlm->ntlm_hash[i] = c;
        }
        custom_ntlm->ntlm_hash_len = i;
        gethostname((char *)custom_ntlm->hostname, sizeof(custom_ntlm->hostname));

        free(tmp);
        tmp = NULL;
        custom_ntlm->ok = 1;
        {
            wchar_t *wdomain, *wusername;

            wdomain = calloc(1, custom_ntlm->w_domain_len + 2);
            wusername = calloc(1, custom_ntlm->w_username_len + 2);

            if (wdomain && wusername) {
                memcpy((uint8_t *)wdomain, custom_ntlm->w_domain, custom_ntlm->w_domain_len);
                memcpy((uint8_t *)wusername, custom_ntlm->w_username, custom_ntlm->w_username_len);
                NETLOG("%s: custom NTLM creds set for user %ls\\%ls", __FUNCTION__,
                        wdomain, wusername);
                free(wusername);
                free(wdomain);
            }
        }
    }

    max_n_socks = dict_get_integer_default(config, "max-conn-per-proxy", -1);
    if (max_n_socks > 0) {
        max_socket_per_proxy = (int) max_n_socks;
        s_max_n_socks = true;
    }

    NETLOG("%s: max-conn-per-proxy (or host) set to %d %s", __FUNCTION__, max_socket_per_proxy,
            s_max_n_socks ? "(config set)" : "(default)");

    ni->http_evt_cb = rpc_on_event;

    if (hc_prx_addr)
        goto cleanup;

    proxy_str = yajl_object_get_string(config, "proxy");
    if (!proxy_str) {
        goto cleanup;
    }
    pstr = strdup(proxy_str);
    if (!pstr)
        goto cleanup;
    p = strchr(pstr, ':');
    if (!p || !*p)
        goto cleanup;
    *p++ = 0;
    if (sscanf(p, "%u", &port) <= 0)
        goto cleanup;

    hc_prx_srv = strdup(pstr);
    hc_prx_addr = 0;
    hc_prx_port = htons(port);
    NETLOG2("%s: setting proxy to %s", __FUNCTION__, proxy_str);

cleanup:
    free(pstr);
    if (custom_ntlm && !custom_ntlm->ok) {
        free(custom_ntlm);
        custom_ntlm = NULL;
        NETLOG("%s: custom NTLM settings FAILED !", __FUNCTION__);
    }
    return;

mem_err:
    warnx("%s: malloc", __FUNCTION__);
    goto cleanup;
}

static void rpc_user_agent_cb(void *opaque, dict d)
{
    const char *ua;

    ua = dict_get_string(d, "result");
    if (!ua)
        return;

    free(user_agent);
    user_agent = NULL;

    user_agent = strdup(ua);
    if (!user_agent) {
        warnx("%s: malloc", __FUNCTION__);
        return;
    }
    NETLOG2("%s: user-agent '%s'", __FUNCTION__, user_agent);
}

static void rpc_connect_proxy_cb(void *opaque, dict d)
{
    struct http_ctx *hp = opaque;
    const char *proxy_server;
    int is_direct, ct, cancelled, no_proxy;
    struct proxy_t *proxy = NULL;
    uint16_t port;
    const char *realm = NULL, *alternative_proxies = NULL, *tmp;
    int64_t last_refresh = 0;

    hp_put(hp);
    if ((hp->flags & HF_CLOSED))
        goto out;

    no_proxy = dict_get_integer_default(d, "no_proxy", -1);
    if (no_proxy > 0) {
        HLOG("no more proxy posibilities, closing connection.");
        hp_close(hp);
        goto out;
    }

    is_direct = dict_get_integer_default(d, "is_direct", -1);
    if (is_direct < 0) {
        HLOG("ERROR - 'is_direct' not defined");
        goto error;
    }

    if (is_direct) {
        HLOG2(" direct");
        proxy_cache_add(hp->ni, hp->cx ? hp->cx->schema : NULL,
                        hp->h.sv_name, hp->h.daddr.sin_port, NULL);
        if (hp->cx && hp->cx->proxy) {
            cx_hp_reconnect_direct(hp->cx);
            hp = NULL;
        } else if (srv_connect_direct(hp)) {
            HLOG("srv_connect_direct FAILURE");
            goto error;
        }

        goto out;
    }

    proxy_server = dict_get_string(d, "proxy_server");
    if (!proxy_server) {
        HLOG("ERROR - 'proxy_server' not defined");
        goto error;
    }

    port = dict_get_integer_default(d, "proxy_port", 0);
    if (!port) {
        HLOG("ERROR - 'proxy_port' not defined");
        goto error;
    }
    port = htons(port);

    ct = dict_get_integer_default(d, "challenge_type", 0);
    realm = dict_get_string(d, "realm");

    HLOG2(" proxy: %s:%hu ct: %d", proxy_server, ntohs(port), ct);
    proxy = proxy_save(proxy_server, port, ct, realm);
    if (!proxy) {
        HLOG("ERROR - cannot create proxy struct");
        goto error;
    }

    if ((tmp = dict_get_string(d, "last_refresh")))
        sscanf(tmp, "%" PRId64, &last_refresh);

    if (last_refresh > 0)
        prx_refresh_id = last_refresh;

    cancelled = dict_get_integer_default(d, "cancelled", 0);
    if (cancelled) {
        hp->flags |= HF_407_MESSAGE;
        proxy_cache_reset();
    }

    if (hp->cx && hp->cx->alternative_proxies) {
        free(hp->cx->alternative_proxies);
        hp->cx->alternative_proxies = NULL;
    }
    alternative_proxies = dict_get_string(d, "alternative_proxies");
    if (hp->cx && alternative_proxies && *alternative_proxies)
        hp->cx->alternative_proxies = strdup(alternative_proxies);

    if (srv_connect_proxy(hp, proxy)) {
        HLOG("srv_connect_proxy FAILURE");
        goto error;
    }
    proxy_cache_add(hp->ni, hp->cx ? hp->cx->schema : NULL,
                    hp->h.sv_name, hp->h.daddr.sin_port, proxy);

    if ((hp->flags & (HF_407_MESSAGE | HF_407_MESSAGE_OK)) ==
        (HF_407_MESSAGE | HF_407_MESSAGE_OK) && end_407_message(hp) < 0) {

        goto error;
    }

out:
    return;

error:
    hp_close(hp);
    goto out;
}

static int
rpc_connect_proxy(struct http_ctx *hp, const char *in_server, uint16_t port,
        struct proxy_t *bad_proxy, const char *alternative_proxies)
{
    int ret = -1;
    dict args = NULL;

    char buf[64];

    args = dict_new();
    if (!args)
        goto out;
    dict_put_string(args, "in_server", in_server);
    snprintf(buf, 64, "%lu", (unsigned long) 0); // FIXME! ip address needs to be removed from the RPC call
    dict_put_string(args, "addr", buf);
    dict_put_integer(args, "port", ntohs(port));
    if (hp->cx && hp->cx->schema)
        dict_put_string(args, "schema", hp->cx->schema);
    if (bad_proxy) {
        char *tmp;

        if (asprintf(&tmp, "%s:%d", bad_proxy->name, ntohs(bad_proxy->port)) < 0) {
            warnx("%s: malloc", __FUNCTION__);
            goto out;
        }

        buff_strtolower(tmp);
        dict_put_string(args, "bad_proxy", tmp);
        free(tmp);
    } else {
        dict_put_string(args, "bad_proxy", "");
    }

    dict_put_string(args, "alternative_proxies", alternative_proxies ? alternative_proxies : "");

    HLOG3("nc_GetServerPort");
    if (bad_proxy && !alternative_proxies) {
        if (ni_rpc_send(hp->ni, "nc_GetServerPort", args, NULL, NULL))
            goto out;
    } else {
        hp_get(hp);
        if (ni_rpc_send(hp->ni, "nc_GetServerPort", args, rpc_connect_proxy_cb, hp)) {
            hp_put(hp);
            goto out;
        }
    }

    ret = 0;
out:
    if (args)
        dict_free(args);
    return ret;
}

static void rpc_on_event(void *opaque)
{
    struct ni_rpc_response *r = opaque;
    const char *command;

    command = dict_get_string(r->d, "command");
    if (!command)
        goto out;

    if (!strcmp(command, "nc_ProxyCredentialsChange")) {
        int cancel;
        const char *tmp;

        cancel = dict_get_integer_default(r->d, "cancelled", 0);
        if ((tmp = dict_get_string(r->d, "last_refresh")))
            sscanf(tmp, "%" PRId64, &prx_refresh_id);

        refresh_prompt_cred_states(cancel);
        goto out;
    } else if (!strcmp(command, "nc_ProxyCacheFlush")) {
        proxy_cache_reset();
        goto out;
    }

out:
    dict_free(r->d);
    free(r);
}

static void hp_event(void *opaque, uint32_t evt, int err)
{
    struct http_ctx *hp = opaque;

    if (!hp)
        goto out;

    if ((evt & SO_EVT_CONNECTING) && srv_connecting(hp) < 0)
        goto out_close;
    if ((evt & SO_EVT_CONNECTED) && srv_connected(hp) < 0)
        goto out_close;
    if ((evt & SO_EVT_READ) && srv_read(hp) < 0)
        goto out_close;
    if ((evt & SO_EVT_WRITE) && srv_writing(hp) < 0)
        goto out_close;
    if ((evt & SO_EVT_CLOSING) && srv_closing(hp, err) < 0)
        goto out_close;

out:
    return;

out_close:
    hp_close(hp);
    goto out;
}

static void hp_bh(void *unused)
{
    struct http_ctx *hp, *hp_next;
    struct clt_ctx *cx, *cx_next;
    static int run_once = 0;

    if (!run_once) {
        run_once = 1;

        LIST_FOREACH_SAFE(cx, &cx_list, entry, cx_next) {
            if (!cx->restart_state)
                continue;
            if (cx->restart_state == CXSV_RESET)
                cx_close(cx);
            else if (cx->restart_state == CXSV_CONNFAILED)
                cx_proxy_response(cx, HMSG_CONNECT_FAILED, true);
        }
    }

    LIST_FOREACH_SAFE(hp, &http_gc_list, entry, hp_next) {
        if (hp->refcnt)
            continue;
        LIST_REMOVE(hp, entry);
        hp_free(hp);
    }

    LIST_FOREACH_SAFE(cx, &cx_gc_list, entry, cx_next) {
        if (cx->refcnt)
            continue;
        LIST_REMOVE(cx, entry);
        cx_free(cx);
    }

    proxy_foreach(proxy_wakeup_list);

    if (hpd_needs_continue) {
        struct hpd_t *hpd, *hpd_next;
        hpd_needs_continue = 0;
        LIST_FOREACH_SAFE(hpd, &hpd_list, entry, hpd_next) {
            if (hpd->needs_continue) {
                hpd->needs_continue = 0;
                hpd_cx_continue(hpd);
            }
        }
    }

}

static void hp_init(struct nickel *ni, yajl_val config)
{
    ni_schedule_bh_permanent(ni, hp_bh, NULL);
    dns_http_proxy_enabled();
    set_settings(ni, config);
    http_auth_init();
    fakedns_register_callbacks(on_fakeip_update, on_fakeip_blocked);
    rb_tree_init(&hpd_rbtree, &hpd_rbtree_ops);
    if (NLOG_LEVEL > 4) {
        hpd_debug_timer = ni_new_rt_timer(ni, HPD_DEBUG_CHECK_MS, hpd_debug_timer_cb, NULL);
        if (hpd_debug_timer)
            NETLOG4("hpd stats enabled");
    }
    hpd_rbtree_init = 1;
}

static void cx_webdav_ready(struct clt_ctx *cx)
{
    if (!(cx->flags & CXF_LOCAL_WEBDAV) || !cx->webdav_opaque)
        return;
    dav_write_ready((DavClient *)cx->webdav_opaque);
}

static void cx_webdav_close(struct clt_ctx *cx)
{
    DavClient *dc = (DavClient *) cx->webdav_opaque;

    if (!dc)
        return;

    dav_close(dc);
    free(dc);
    dc = NULL;
    cx->webdav_opaque = NULL;
    cx->flags &= ~CXF_LOCAL_WEBDAV;
    cx_put(cx);
}

static void cx_webdav_do_write(void *opaque, const char *buf, size_t len)
{
    struct clt_ctx *cx = (struct clt_ctx *) opaque;
    int lparsed;

    CXL5("len %u", (unsigned int) len);
    assert((cx->flags & CXF_LOCAL_WEBDAV));
    if ((cx->flags & CXF_CLOSED))
        return;

    assert(cx->out);
    assert(cx->srv_parser);
    buff_append(cx->out, buf, len);
    lparsed = HTTP_PARSE_BUFF(cx->srv_parser, cx->out);
    BUFF_CONSUME_ALL(cx->out);
    cx_guest_write(cx);
    if (lparsed != len || cx->srv_parser->parse_state == PS_MCOMPLETE)
        cx->flags |= CXF_LOCAL_WEBDAV_COMPLETE;
}

static int cx_webdav_process(struct clt_ctx *cx, const uint8_t *buf, int len)
{
    int ret = -1;

    if (!(cx->flags & CXF_LOCAL_WEBDAV))
        goto out;

    if (!webdav_host_dir) {
        yajl_val s;
        const char *dir;

        s = ni_get_service_config(cx->ni, "webdav");
        if (!s)
            goto out;
        dir = yajl_object_get_string(s, "host_dir");
        if (!dir)
            goto out;
        webdav_host_dir = strdup(dir);
        if (!webdav_host_dir)
            goto out;
    }

    if (!cx->webdav_opaque) {
        DavClient *dc;
        DavFSCallbacks callbacks = {
                cx_webdav_do_write,
        };

        if (!cx->out && !buff_new_priv(&cx->out, SO_READBUFLEN))
            goto out;
        BUFF_RESET(cx->out);
        if (!cx->srv_parser && parser_create_response(&cx->srv_parser, cx))
            goto out;

        dc = calloc(1, sizeof(*dc));
        if (!dc)
            goto out;
        if (dav_init(dc, &callbacks, webdav_host_dir, cx) != 0) {
            free(dc);
            goto out;
        }
        cx_get(cx);
        cx->webdav_opaque = dc;
        CXL5("dav_init");
    }

    if (cx->in) {
        size_t l;

        BUFF_CONSUME_ALL(cx->in);
        l = BUFF_CONSUMED(cx->in);
        if (l) {
            if (dav_input((DavClient *) cx->webdav_opaque,
                    (char *) BUFF_BEGINNING(cx->in), l) < 0) {

                goto out;
            }

            CXL5("dav_input l %u", (unsigned int) l);
            buff_gc_consume(cx->in, l);
        }
    }

    if (buf && len && dav_input((DavClient *) cx->webdav_opaque, (char *) buf, len) < 0)
        goto out;
    ret = len;
    CXL5("dav_input len %u", (unsigned int) len);

out:
    return ret;
}

static struct prx_fwd prx = {
    .is_udp = 0,
    .name = "http-proxy",
    .init = hp_init,
    .open = cx_open,
    .accept = cx_accept,
};

static struct ns_desc ns_prx_desc = {
    .service_type = NS_SERVICE_TYPE_TCP,
    .service_name = "http-proxy",
    .service_open = ns_cx_open,
};

static CharDriverState *
cx_accept(void *opaque, struct nickel *ni, struct socket *so)
{
    struct clt_ctx *cx = NULL;
    CharDriverState *chr = NULL;
    struct http_ctx *hp = NULL;

    cx = cx_create(ni);
    chr = calloc(1, sizeof(*chr));
    if (!cx || !chr) {
        warnx("%s: memory error", __FUNCTION__);
        goto cleanup;
    }
    cx->chr = chr;
    cx->chr->refcnt = 1;
    cx->flags |= CXF_NI_ESTABLISHED;
    cx->flags |= (CXF_HOST_RESOLVED | CXF_BINARY | CXF_ACCEPTED | CXF_TLS_DETECT_OK);
    cx->flags |= CXF_PRX_DECIDED;
    cx->ni_opaque = opaque;

    hp = hp_create(ni);
    if (!hp)
        goto cleanup;
    if (!hp->cx) {
        cx_get(cx);
        hp->cx = cx;
    }
    if (!cx->hp) {
        hp_get(hp);
        cx->hp = hp;
        if (on_cx_hp_connect(cx) < 0)
            goto cleanup;
    }
    hp->so = so;
    hp->cstate = S_CONNECTED;
    hp->hstate = HP_PASS;
    hp->flags |= HF_BINARY_STREAM;
    so_update_event(so, hp_event, hp);
    if (start_direct(hp) < 0)
        goto cleanup;

    qemu_chr_add_handlers(chr, cx_chr_can_read, cx_chr_read, NULL, cx);
    chr->chr_write = cx_chr_write;
    chr->chr_send_event = cx_chr_event;
    chr->chr_can_write = cx_chr_can_write;

    return cx->chr;

cleanup:
    if (cx) {
        cx->ni_opaque = NULL;
        cx_close(cx);
    }
    return NULL;
}

static struct clt_ctx *
cx_create(struct nickel *ni)
{
    struct clt_ctx *cx;
    struct buff *bf;

    if (!BUFF_NEW_MX_PRIV(&bf, BUF_CHUNK, MAX_GUEST_BUF))
        goto mem_err;

    cx = calloc(1, sizeof(*cx));
    if (!cx)
        goto mem_err;

    cx->refcnt = 1;
    cx->ni = ni;
    cx->in = bf;
    RLIST_INIT(cx, w_list);
    RLIST_INIT(cx, direct_cx_list);

    LIST_INSERT_HEAD(&cx_list, cx, entry);

#if VERBSTATS
    cx->created_ts = get_clock_ms(rt_clock);
#endif

    return cx;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    return NULL;
}

static void cx_get(struct clt_ctx *cx)
{
    atomic_inc(&cx->refcnt);
}

static void cx_put(struct clt_ctx *cx)
{
    if (!cx)
        return;

    assert(cx->refcnt);
    atomic_dec(&cx->refcnt);
}

static void cx_close(struct clt_ctx *cx)
{
    if ((cx->flags & (CXF_CLOSING | CXF_CLOSED)))
        return;

    cx->flags |= CXF_CLOSING;
    cx->flags |= CXF_IGNORE;

    if (cx->hp)
        cx_hp_disconnect(cx);

    if (!(cx->flags & CXF_FORCE_CLOSE)) {
        cx->flags &= ~CXF_GPROXY_REQUEST;
        if ((cx->flags & CXF_TUNNEL_RESPONSE_OK) && !(cx->flags & CXF_TUNNEL_GUEST_SENT)) {
            cx_proxy_response(cx, HMSG_CONNECT_ABORTED_SSL, true);
            cx->flags |= CXF_TUNNEL_GUEST_SENT;
        }
        if (cx->out && BUFF_BUFFERED(cx->out)) {
            cx->flags |= CXF_FLUSH_CLOSE;
            if (cx_guest_write(cx) == 0)
                goto out;
        }
    }

#if VERBSTATS
    if ((cx->flags & CXF_GUEST_PROXY)) {
        char tmp_buf[(12 + 1) * 2 * LAT_STAT_NUMBER + 1];

        memset(tmp_buf, 0, sizeof(tmp_buf));
        if (cx->clt_lat_idx) {
            int i, j = 0, llen;

            for (i = 0; i < cx->clt_lat_idx; i += 2) {
                llen = snprintf(tmp_buf + j, sizeof(tmp_buf) - j - 1, " %u:%u", cx->clt_lat[i],
                        cx->clt_lat[i + 1]);
                if (llen <= 0)
                    break;
                j += llen;
            }
        }
        CXL3("CLOSE n_rq %u l:%ums L:%ums a:%ums s:%s", cx->number_req,
                cx->lat_min, cx->lat_max,
                cx->number_req ? (cx->lat_sum / cx->number_req) : 0, tmp_buf);
    } else {
        CXL3("CLOSE");
    }
#endif

    if ((cx->flags & CXF_LOCAL_WEBDAV))
        cx_webdav_close(cx);

    if (cx->ni_opaque)
        ni_close(cx->ni_opaque);
    cx->ni_opaque = NULL;
    if (cx->chr)
        qemu_chr_close(cx->chr);
    cx->chr = NULL;
    if (cx->entry.le_prev)
        LIST_REMOVE(cx, entry);
    if (!RLIST_EMPTY(cx, w_list)) {
        RLIST_REMOVE(cx, w_list);
        cx_put(cx);
        if (NLOG_LEVEL > 4 && cx->proxy)
            CXL5("WLIST REMOVE N %d", proxy_number_waiting(cx->proxy));
    }
    if (cx->in) {
        buff_put(cx->in);
        cx->in = NULL;
    }
    if (cx->out) {
        buff_put(cx->out);
        cx->out = NULL;
    }
    if (cx->clt_parser)
        parser_free(&cx->clt_parser);
    if (cx->srv_parser)
        parser_free(&cx->srv_parser);
    free(cx->connect_header_lines);
    cx->connect_header_lines = NULL;
    cx->flags |= (CXF_CLOSED | CXF_IGNORE);

    cx_remove_hpd(cx);

    cx_put(cx);
    LIST_INSERT_HEAD(&cx_gc_list, cx, entry);
out:
    cx->flags &= ~CXF_CLOSING;
}

static void cx_free(struct clt_ctx *cx)
{
    assert((cx->flags & CXF_CLOSED));
    free(cx->h.sv_name);
    cx->h.sv_name = NULL;
    assert(cx->hp == NULL);
    if (cx->in)
        buff_put(cx->in);
    cx->in = NULL;
    if (cx->out)
        buff_put(cx->out);
    cx->out = NULL;
    parser_free(&cx->clt_parser);
    free(cx->alternative_proxies);
    cx->alternative_proxies = NULL;

    free(cx);
}

static int cx_parser_create_request(struct clt_ctx *cx)
{
    if (cx->clt_parser)
        return 0;

    return parser_create_request(&cx->clt_parser, cx, !!(cx->flags & CXF_GUEST_PROXY));
}

static void cx_reset_state(struct clt_ctx *cx, bool soft)
{
    if (!soft) {
        free(cx->h.sv_name);
        cx->h.sv_name = NULL;
        cx->schema = NULL;
        cx->h.daddr.sin_addr.s_addr = 0;
        cx->h.daddr.sin_port = 0;
        cx->flags &= ((~CXF_HOST_RESOLVED) & (~CXF_PRX_DECIDED) & (~CXF_RPC_PROXY_URL));
        cx->flags &= ((~CXF_LOCAL_WEBDAV) & (~CXF_LOCAL_WEBDAV_COMPLETE));
    }
    cx->flags &= ((~CXF_HEADERS_OK) & (~CXF_LONG_REQ) & (~CXF_HEAD_REQUEST) &
                 (~CXF_HEAD_REQUEST_SENT));
    if (cx->clt_parser)
        parser_reset(cx->clt_parser);
    if (cx->srv_parser) {
        CXL5("SRV_PARSER RESET");
        parser_reset(cx->srv_parser);
    }
}

static void cx_reset(struct clt_ctx *cx, bool soft)
{
    if (cx->in)
        BUFF_RESET(cx->in);
    if (cx->out)
        BUFF_RESET(cx->out);
    cx_reset_state(cx, soft);
}

static int cx_srv_fin(struct clt_ctx *cx)
{
    int ret = -1;

    if (!cx->ni_opaque)
        goto out;
    if ((cx->flags & CXF_CLOSED))
        goto out;

    ret = ni_send_fin(cx->ni_opaque);
    CXL4("ret %d", ret);
out:
    return ret;
}

static int cx_chr_can_write(void *opaque)
{
    struct clt_ctx *cx = opaque;

    return cx->in ? (BUFF_FREEDOM(cx->in) + cx->in->mx_size -
            cx->in->size) : 0;
}

static int cx_chr_can_read(void *opaque)
{
    struct clt_ctx *cx = opaque;

    return ni_can_recv(cx->ni_opaque);
}

static void cx_chr_read(void *opaque, const uint8_t *buf, int size)
{
    struct clt_ctx *cx = opaque;

    ni_recv(cx->ni_opaque, buf, size);
}

static void cx_chr_event(CharDriverState *chr, int event)
{
    struct clt_ctx *cx = (struct clt_ctx *) chr->handler_opaque;

    if (event == CHR_EVENT_BUFFER_CHANGE) {
        if (cx_guest_write(cx) < 0)
            goto out_close;

        if ((cx->flags & CXF_LOCAL_WEBDAV) && (!cx->out || !BUFF_BUFFERED(cx->out)))
            cx_webdav_ready(cx);
        goto out;
    }

    if (event == CHR_EVENT_NI_CLOSE || event == CHR_EVENT_NI_RST) {
        if (event == CHR_EVENT_NI_RST)
            CXL3("guest closing with RST, event %d", event);
        if (cx_closing(cx, event == CHR_EVENT_NI_RST) < 0)
            goto out_close;

        goto out;
    }

out:
    return;
out_close:
    cx_close(cx);
    goto out;
}

static void cx_chr_save(struct CharDriverState *chr,  QEMUFile *f)
{
    struct clt_ctx *cx = (struct clt_ctx *) chr->handler_opaque;
    unsigned int save_state = CXSV_RESET;

    if (!(cx->flags & CXF_CLOSED) && (cx->flags & CXF_GUEST_PROXY) && !cx->hp &&
            (cx->flags & CXF_HTTP)) {

        if ((cx->flags & CXF_GPROXY_REQUEST) && cx->clt_parser &&
             cx->clt_parser->parse_state == PS_MCOMPLETE) {

            save_state = CXSV_CONNFAILED;
        } else if (!(cx->flags & CXF_GPROXY_REQUEST) && (!cx->in || !BUFF_BUFFERED(cx->in))) {

            save_state = CXSV_CONTINUE;
        }
    }

    qemu_put_be32(f, 4); // 4 bytes
    qemu_put_be32(f, (uint32_t) save_state);
}

static void cx_chr_restore(struct CharDriverState *chr,  QEMUFile *f)
{
    struct clt_ctx *cx = (struct clt_ctx *) chr->handler_opaque;
    unsigned int len;
    unsigned int save_state = CXSV_RESET;

    len = qemu_get_be32(f);

    if (!len)
        goto out;

    if (len != 4) { // 4 bytes
        CXL("ERROR - expected length 4 bytes, got %u!", len);
        qemu_file_skip(f, len);
        goto consume;
    }

    save_state = qemu_get_be32(f);
    if (save_state >= CXSV_LAST_STATE) {
        CXL("ERROR - received invalid save-state %u", save_state);
        save_state = CXSV_RESET;
    }

consume:
    while ((len = qemu_get_be32(f)))
        qemu_file_skip(f, len);
out:
    cx->restart_state = save_state;
}

static ssize_t cx_write(struct clt_ctx *cx, uint8_t *p, size_t l)
{
    ssize_t ret = 0;

#if VERBSTATS
    if (l && cx->rq_ts) {
        uint32_t dt;

        dt = (uint32_t) (get_clock_ms(rt_clock) - cx->rq_ts);
        cx->rq_ts = 0;

        if (cx->lat_min == 0 || cx->lat_min > dt)
            cx->lat_min = dt;
        if (cx->lat_max < dt)
            cx->lat_max = dt;
        cx->lat_sum += dt;
    }
#endif

    assert(cx->chr);
    while (l) {
        int r;

        r = qemu_chr_can_read(cx->chr);
        if (r <= 0)
            break;
        if (r > l)
            r = l;
        qemu_chr_read(cx->chr, p, r);
        p += r;
        l -= r;
        ret += r;
    }

    return ret;
}

static int cx_guest_write(struct clt_ctx *cx)
{
    int ret = 0;
    ssize_t r;
    size_t l;
    bool buf_ready = false;

    if ((cx->flags & CXF_CLOSED))
        goto out;
    if ((cx->flags & CXF_FORCE_CLOSE))
        goto out_close;
    if (!(cx->flags & CXF_NI_ESTABLISHED) || !cx->out)
        goto out;

    l = BUFF_CONSUMED(cx->out);
    CXL5("available buf len %d", (int) l);
    if (l == 0)
        goto out;

    cx->flags &= ~CXF_GPROXY_REQUEST;
    if ((cx->flags & (CXF_SUSPENDED | CXF_PROXY_SUSPEND)))
        goto out;

    r = cx_write(cx, (uint8_t *) (BUFF_BEGINNING(cx->out)), l);
    if (NLOG_LEVEL > 5 && !hide_log_sensitive_data && r > 0) {
        CXL5("buffer:");
        netlog_print_esc("buffer", BUFF_BEGINNING(cx->out), r);
    }
    CXL5("wrote %d bytes to G", (int) r);

    if (r > 0) {
#if VERBSTATS
    if (cx->clt_lat_idx < LAT_STAT_NUMBER * 2) {
        int64_t now = get_clock_ms(rt_clock);

        cx->clt_lat[cx->clt_lat_idx] = (uint32_t) (now - cx->created_ts);
        cx->clt_lat[cx->clt_lat_idx + 1] = (uint32_t) r;
        cx->clt_lat_idx += 2;

        cx->created_ts = now;
    }
#endif
        buff_gc_consume(cx->out, r);
        if (cx->hp)
            buf_ready = true;

        if (!(cx->flags & CXF_TUNNEL_GUEST_SENT) && (cx->flags & CXF_TUNNEL_RESPONSE_OK))
            cx->flags |= CXF_TUNNEL_GUEST_SENT;
    }

    CXL5("BUFF_BUFFERED(cx->out) %d", (int) BUFF_BUFFERED(cx->out));
    if (BUFF_BUFFERED(cx->out) == 0) {
        if ((cx->flags & CXF_FLUSH_CLOSE)) {
            CXL5("CXF_FLUSH_CLOSE END");
            if (!(cx->flags & CXF_GUEST_PROXY) && cx_srv_fin(cx) == 0)
                goto out;

            goto out_close;
        }

        if (cx->hp && (cx->hp->flags & HF_RESTARTABLE)) {
            assert(cx->srv_parser);
            CXL5("parse_state %d", (int) cx->srv_parser->parse_state);
            if (cx->srv_parser->parse_state == PS_MCOMPLETE) {
                cx->hp->flags |= HF_RESTART_OK;
                if (cx->hp->flags & HF_REUSABLE)
                    cx->hp->flags |= HF_REUSE_READY;
                CXL5("PS_MCOMPLETE");
                cx->flags &= ~CXF_RESET_STATE;

                if ((cx->hp->flags & HF_HTTP_CLOSE))
                    cx->hp->flags &= ~HF_HTTP_CLOSE;

                if ((cx->flags & CXF_GUEST_PROXY) && !(cx->flags & CXF_TUNNEL_GUEST)) {

                     if (cx->proxy && !(cx->hp->flags & HF_PINNED) && cx_hp_disconnect(cx) < 0)
                        goto out_close;
                     if (!cx->proxy && cx->hp && !(cx->hp->flags & HF_PINNED) && cx->hp->hpd && cx_hp_disconnect(cx) < 0)
                        goto out_close;
                     cx_reset(cx, false);
                } else if (!(cx->flags & (CXF_GUEST_PROXY | CXF_TUNNEL_GUEST | CXF_TLS |
                             CXF_BINARY)) && cx->proxy) {

                    if (cx_hp_disconnect(cx) < 0)
                        goto out_close;
                    cx_reset(cx, true);
                }
                parser_reset(cx->srv_parser);
            } else if (cx->proxy || (cx->flags & CXF_GUEST_PROXY)) {
                cx->flags |= CXF_RESET_STATE;
            }
        }

        if ((cx->flags & CXF_TUNNEL_RESPONSE)) {
            cx->flags &= (~CXF_TUNNEL_DETECTED & ~CXF_TUNNEL_RESPONSE);
            cx->flags |= CXF_TUNNEL_RESPONSE_OK;
            if (cx->in)
                BUFF_RESET(cx->in);
            if (cx->clt_parser)
                parser_reset(cx->clt_parser);
            CXL5("CXF_TUNNEL_RESPONSE_OK cx->in RESET");
            if (cx_process(cx, NULL, 0) < 0)
                goto out_close;
        }
    }

out:
    if (buf_ready && cx->hp)
        hp_cx_buf_ready(cx->hp);

    return ret;
out_close:
    cx_close(cx);
    ret = -1;
    goto out;
}

static int cx_chr_write(CharDriverState *chr, const uint8_t *buf, int len_buf)
{
    int ret = -1;
    struct clt_ctx *cx = chr->handler_opaque;

    if (len_buf <= 0)
        return len_buf;

    if ((cx->flags & (CXF_SUSPENDED | CXF_NI_FIN | CXF_IGNORE | CXF_CLOSED))) {
        ret = 0;
        goto out;
    }

    ret = cx_process(cx, buf, len_buf);
    if (ret < 0)
        goto close;

out:
    CXL5("len_buf %d ret %d", len_buf, ret);
    return ret;
close:
    cx_close(cx);
    ret = -1;
    goto out;
}

static void cx_rpc_proxy_by_url_cb(void *opaque, dict d)
{
    struct clt_ctx *cx = opaque;
    const char *proxy_server;
    int is_direct, ct, cancelled, no_proxy;
    struct proxy_t *proxy = NULL;
    uint16_t port;
    const char *realm = NULL, *alternative_proxies = NULL, *tmp;
    int64_t last_refresh = 0;
    bool process = false;

    cx->flags &= ~CXF_RPC_PROXY_URL;
    cx_put(cx);
    if ((cx->flags & CXF_CLOSED))
        goto out;

    no_proxy = dict_get_integer_default(d, "no_proxy", -1);
    if (no_proxy > 0) {
        CXL("no more proxy posibilities, closing connection.");
        goto out_close;
    }

    is_direct = dict_get_integer_default(d, "is_direct", -1);
    if (is_direct < 0) {
        CXL("ERROR - 'is_direct' not defined");
        goto out_close;
    }

    if (is_direct) {
        proxy_cache_add(cx->ni, cx->schema, cx->h.sv_name, cx->h.daddr.sin_port, NULL);
        cx_proxy_set(cx, NULL);
        process = true;
        goto out;
    }

    proxy_server = dict_get_string(d, "proxy_server");
    if (!proxy_server) {
        CXL("ERROR - 'proxy_server' not defined");
        goto out_close;
    }

    port = dict_get_integer_default(d, "proxy_port", 0);
    if (!port) {
        CXL("ERROR - 'proxy_port' not defined");
        goto out_close;
    }
    port = htons(port);

    ct = dict_get_integer_default(d, "challenge_type", 0);
    realm = dict_get_string(d, "realm");

    CXL2(" proxy: %s:%hu ct: %d", proxy_server, ntohs(port), ct);
    proxy = proxy_save(proxy_server, port, ct, realm);
    if (!proxy) {
        CXL("ERROR - cannot create proxy struct");
        goto out_close;
    }

    proxy_cache_add(cx->ni, cx->schema, cx->h.sv_name, cx->h.daddr.sin_port, proxy);
    if ((tmp = dict_get_string(d, "last_refresh")))
        sscanf(tmp, "%" PRId64, &last_refresh);

    if (last_refresh > 0)
        prx_refresh_id = last_refresh;

    cancelled = dict_get_integer_default(d, "cancelled", 0);
    if (cancelled) {
        cx->flags |= CXF_407_MESSAGE;
        proxy_cache_reset();
    }

    if (cx->alternative_proxies)
        free(cx->alternative_proxies);
    cx->alternative_proxies = NULL;
    alternative_proxies = dict_get_string(d, "alternative_proxies");
    if (alternative_proxies && *alternative_proxies)
        cx->alternative_proxies = strdup(alternative_proxies);

    cx_proxy_set(cx, proxy);
    process = true;

out:
    if (process && cx_process(cx, NULL, 0) < 0)
        goto out_close;
    return;

out_close:
    process = false;
    cx_close(cx);
    cx = NULL;
    goto out;
}

static int cx_rpc_proxy_by_url(struct clt_ctx *cx, const char *sv_name, uint16_t port)
{
    int ret = -1;
    dict args = NULL;
    char buf[64];

    if ((cx->flags & (CXF_PRX_DECIDED | CXF_RPC_PROXY_URL)))
        goto out_ok;

    args = dict_new();
    if (!args)
        goto out;
    dict_put_string(args, "in_server", sv_name);

    // FIXME! ip address needs to be removed from the RPC call
    snprintf(buf, 64, "%lu", (unsigned long) 0);
    dict_put_string(args, "addr", buf);
    dict_put_integer(args, "port", ntohs(port));
    if (cx->schema)
        dict_put_string(args, "schema", cx->schema);

    CXL3("nc_GetServerPort");
    cx_get(cx);
    cx->flags |= CXF_RPC_PROXY_URL;
    if (ni_rpc_send(cx->ni, "nc_GetServerPort", args, cx_rpc_proxy_by_url_cb, cx)) {
        cx->flags &= ~CXF_RPC_PROXY_URL;
        cx_put(cx);
        goto out;
    }

out_ok:
    ret = 0;
out:
    if (args)
        dict_free(args);
    return ret;
}

static int cx_proxy_decide(struct clt_ctx *cx)
{
    int ret = -1;
    struct proxy_t *proxy = NULL;

    if ((cx->flags & CXF_PRX_DECIDED))
        return 0;

    if (!ac_proxy_set(cx->ni) || (!(cx->flags & CXF_GUEST_PROXY) && no_transparent_proxy)) {
        cx_proxy_set(cx, NULL);

        ret = 0;
        goto out;
    }

    assert(cx->h.sv_name && cx->h.daddr.sin_port);
    if (!cx->h.sv_name) {
        CXL("ERROR - bug!, sv_name NULL");
        goto out;
    }

    if (hc_prx_srv) {
        proxy = proxy_find(hc_prx_srv, hc_prx_port);
        if (!proxy)
            proxy = proxy_save(hc_prx_srv, hc_prx_port, 0, NULL);
        if (!proxy) {
            CXL("ERROR - proxy_save");
            goto out;
        }
    } else {
        proxy = proxy_cache_find(cx->schema, cx->h.sv_name, cx->h.daddr.sin_port);
    }

    if (proxy) {
        CXL4("proxy cache hit for %s:%hu", cx->h.sv_name, ntohs(cx->h.daddr.sin_port));
        cx_proxy_set(cx, PROXY_IS_DIRECT(proxy) ? NULL : proxy);

        ret = 0;
        goto out;
    }

    // slowpath
    ret = cx_rpc_proxy_by_url(cx, cx->h.sv_name, cx->h.daddr.sin_port);
out:
    return ret;
}

static void cx_proxy_set(struct clt_ctx *cx, struct proxy_t *proxy)
{
    cx->flags |= CXF_PRX_DECIDED;
    cx->proxy = proxy;

    /* if the website is to be proxied through itself, do not use the
     * proxy and rather go direct, that is what IE does */
    if (cx->proxy && cx->proxy->name && cx->h.sv_name &&
        cx->proxy->port == cx->h.daddr.sin_port &&
        strcasecmp(cx->proxy->name, cx->h.sv_name) == 0) {

        if (cx->hp && !(cx->hp->flags & HF_PINNED))
            cx_hp_disconnect_ex(cx, true);
        cx->proxy = NULL;
    }
}

static int cx_process(struct clt_ctx *cx, const uint8_t *buf, int len_buf)
{
    int ret = 0, r;
    size_t lparsed;
    bool need_parse = (buf != NULL && len_buf);
    bool maybe_binary = false;

    CXL5("len_buf %d", len_buf);
    if ((cx->flags & (CXF_CLOSED | CXF_CLOSING | CXF_IGNORE)))
        goto out;

    if ((cx->flags & CXF_TUNNEL_RESPONSE))
        goto out;

    if ((cx->flags & CXF_LOCAL_WEBDAV_COMPLETE)) {
        cx_webdav_close(cx);
        cx_reset(cx, false);
        cx->flags &= ~CXF_LOCAL_WEBDAV_COMPLETE;
    }

    if (buf && (cx->flags & CXF_RESET_STATE)) {
        CXL4("CXF_RESET_STATE");
        cx->flags &= ~CXF_RESET_STATE;
        cx_reset(cx, false);
        if (cx->hp) {
            cx->hp->flags &= (~HF_REUSABLE & ~HF_HTTP_CLOSE);
            if (!(cx->hp->flags & HF_PINNED) && cx_hp_disconnect(cx) < 0)
                goto out;
        }
    }

    assert(cx->in);

    if (buf && !(cx->flags & CXF_GUEST_PROXY) && !(cx->flags & CXF_TLS_DETECT_OK)) {
        maybe_binary = true;
        r = QUICK_HTTP_PARSE_LEN - cx->bf_tls_ck_len;
        if (r > len_buf)
            r = len_buf;

        memcpy(cx->bf_tls_ck + cx->bf_tls_ck_len, buf, r);
        cx->bf_tls_ck_len += r;
        if (cx->bf_tls_ck_len == QUICK_HTTP_PARSE_LEN) {
            cx->flags |= CXF_TLS_DETECT_OK;
            if (tls_is_ssl(cx->bf_tls_ck, cx->bf_tls_ck_len)) {
                cx->flags |= CXF_TLS;
                need_parse = false;
            }
        }
    }

    while (need_parse) {

        if (!(cx->flags & CXF_GUEST_PROXY) && (cx->flags & CXF_PRX_DECIDED) && !cx->proxy) {
            need_parse = false;
            break;
        }

        if ((cx->flags & CXF_GUEST_PROXY) && (cx->flags & CXF_TUNNEL_GUEST) && cx->hp) {
            need_parse = false;
            break;
        }
        if (cx->hp && (cx->hp->flags & HF_BINARY_STREAM)) {
            need_parse = false;
            break;
        }
        if ((cx->flags & (CXF_TLS | CXF_BINARY))) {
            need_parse = false;
            break;
        }

        break;
    }

    if (need_parse) {
        if (BUFF_BUFFERED(cx->in) > 2 * MAX_GUEST_BUF) {
            CXL("strange, BUFF_BUFFERED(cx->in) > 2 * MAX_GUEST_BUF, %u > %u",
                    (unsigned int) BUFF_BUFFERED(cx->in), (unsigned int) 2 * MAX_GUEST_BUF);
            goto out;
        }
        assert(len_buf >= ret);
        if (buff_append(cx->in, (const char*) buf + ret , len_buf - ret) < 0)
            goto err;
        if (NLOG_LEVEL > 5) {
            CXL6("cx->in :");
            netlog_print_esc("cx->in", BUFF_CSTR(cx->in), cx->in->len);
        }
        ret = len_buf;
        if (cx_parser_create_request(cx) < 0)
            goto err;
        lparsed = HTTP_PARSE_BUFF(cx->clt_parser, cx->in);
        if (lparsed != cx->in->len && maybe_binary) {
            cx->flags |= CXF_BINARY;
            parser_reset(cx->clt_parser);
        } else if (lparsed != cx->in->len) {
            CXL("HTTP parse error lparsed %u for %u, errno %d pl %d ml %d cl %lu",
                (unsigned int) lparsed, (unsigned int) cx->in->len,
                (int) cx->clt_parser->parser.http_errno,
                (int) cx->clt_parser->parsed_len,
                (int) cx->clt_parser->message_len,
                (unsigned long) cx->clt_parser->parser.content_length);
            goto err;
        }
        BUFF_CONSUME_ALL(cx->in);
        if (!(cx->flags & (CXF_TLS | CXF_BINARY)) && !(cx->flags & CXF_HEADERS_OK) &&
             (cx->clt_parser->parse_state == PS_HCOMPLETE ||
              cx->clt_parser->parse_state == PS_MCOMPLETE)) {

            cx->flags |= (CXF_HTTP | CXF_HEADERS_OK);
            CXL5("CXF_HEADERS_OK");
            if (cx->clt_parser->h.header_length + cx->clt_parser->h.content_length >=
                MAX_GUEST_BUF) {

                CXL4("long HTTP request (>= %u bytes)", (unsigned) MAX_GUEST_BUF);
                cx->flags |= CXF_LONG_REQ;
            }
        } else if (!(cx->flags & (CXF_HTTP | CXF_TLS | CXF_BINARY | CXF_GUEST_PROXY)) &&
                    (cx->flags & CXF_TLS_DETECT_OK)) {

                cx->flags |= CXF_HTTP;
        }
    }

    if (!(cx->flags & CXF_HOST_RESOLVED)) {
        struct http_parser_url h_url;
        int ssl = 0;
        char *domain = NULL;
        uint16_t port = 0;

        assert((cx->flags & CXF_GUEST_PROXY));
        if (!buf || !len_buf)
            goto out;

        if (!(cx->flags & CXF_HEADERS_OK))
            goto out;

        if (!(cx->flags & CXF_LONG_REQ) && cx->clt_parser->parse_state != PS_MCOMPLETE) {
            CXL5("waiting PS_MCOMPLETE GPROXY");
            goto out;
        }

#if VERBSTATS
        if (!cx->rq_ts)
            cx->rq_ts = get_clock_ms(rt_clock);
        cx->number_req++;
#endif
        cx->flags |= CXF_GPROXY_REQUEST;
        assert(cx->clt_parser);
        if (!cx->clt_parser->h.method || !cx->clt_parser->h.url ||
             cx->clt_parser->h.url->len == 0) {

            CXL(" null method or url !");
            if (cx_proxy_response(cx, HMSG_BAD_REQUEST, true) < 0)
                goto err;

            goto out;
        }

        if (strcasecmp(cx->clt_parser->h.method, S_HEAD) == 0) {
            cx->flags |= CXF_HEAD_REQUEST;
            cx->flags &= ~CXF_HEAD_REQUEST_SENT;
        }

        if (strcasecmp(cx->clt_parser->h.method, S_CONNECT) == 0)
            ssl = 1;

        memset(&h_url, 0, sizeof(h_url));
        if (http_parser_parse_url(BUFF_TO(cx->clt_parser->h.url, const char *),
                    cx->clt_parser->h.url->len, ssl, &h_url)) {

            CXL("malformed HTTP url '%s'", hide_log_sensitive_data ? "..." :
                    BUFF_TO(cx->clt_parser->h.url, const char *));
            if (cx_proxy_response(cx, HMSG_BAD_REQUEST, true) < 0)
                goto err;

            goto out;
        }

        if (!(h_url.field_set & (((uint16_t) 1) << UF_HOST)) ||
                !h_url.field_data[UF_HOST].len) {

            CXL("malformed HTTP url '%s' (no host)", hide_log_sensitive_data ? "..." :
                    BUFF_TO(cx->clt_parser->h.url, const char *));
            if (cx_proxy_response(cx, HMSG_BAD_REQUEST, true) < 0)
                goto err;

            goto out;
        }

        port = h_url.port;
        if (!port)
            port = ssl ? 443 : 80;

        domain = calloc(1, h_url.field_data[UF_HOST].len + 1);
        if (!domain)
            goto mem_err;

        assert(cx->clt_parser->h.url->len >= h_url.field_data[UF_HOST].off +
                    h_url.field_data[UF_HOST].len);
        memcpy(domain, BUFF_TO(cx->clt_parser->h.url, const char *) +
                 h_url.field_data[UF_HOST].off,
                 h_url.field_data[UF_HOST].len);

        free(cx->h.sv_name);
        cx->h.sv_name = domain;
        domain = NULL;
        cx->h.daddr.sin_port = ntohs(port);

        cx->schema = NULL;
        if (ssl) {
            cx->schema = "https";
            CXL5("schema %s port %hu", cx->schema, (uint16_t) port);
        } else {
            char schema[16];

            memset(schema, 0, sizeof(schema));
            if (h_url.field_data[UF_SCHEMA].len && h_url.field_data[UF_SCHEMA].len <
                sizeof(schema) - 1) {

                assert(cx->clt_parser->h.url->len >= h_url.field_data[UF_SCHEMA].off +
                        h_url.field_data[UF_SCHEMA].len);
                memcpy(schema, BUFF_TO(cx->clt_parser->h.url, const char *) +
                        h_url.field_data[UF_SCHEMA].off,
                        h_url.field_data[UF_SCHEMA].len);
                cx->schema = GET_CONST_SCHEMA(schema);
                CXL5("schema %s(%s)", cx->schema ? cx->schema : "(unkn)", schema);
            }
        }

        cx->flags |= CXF_HOST_RESOLVED;

        CXL4("%s URL %s", cx->h.sv_name,
           hide_log_sensitive_data ? "..." : BUFF_TO(cx->clt_parser->h.url, const char *));

        if (!ssl && port == 80 && cx->ni->webdav_svc_ok) {
            struct in_addr daddr = {.s_addr = 0};

            if (inet_aton(cx->h.sv_name, &daddr) != 0) {
                if (daddr.s_addr == cx->ni->host_addr.s_addr)
                    cx->flags |= (CXF_LOCAL_WEBDAV | CXF_PRX_DECIDED);
            } else if (dns_is_nickel_domain_name(cx->h.sv_name))
                cx->flags |= (CXF_LOCAL_WEBDAV | CXF_PRX_DECIDED);
        }

        {
            struct lava_event *lv;

            lv = tcpip_lava_get(cx->ni_opaque);
            if (lv) {
                lava_event_remote_disconnect(lv);
                lava_event_set_http(lv, cx->clt_parser->h.method,
                            cx->h.sv_name, BUFF_TO(cx->clt_parser->h.url, const char *), port);
                if ((cx->flags & CXF_LOCAL_WEBDAV))
                    lava_event_set_local(lv);
            }
        }

        if (ssl) {
            cx->flags |= (CXF_TUNNEL_GUEST | CXF_TLS);
            if (cx->hp) {
                CXL("ERROR - cannot reuse socket for HTTP CONNECT");
                goto err;
            }

            cx->flags |= CXF_TUNNEL_DETECTED;
        } else {
            cx->flags |= CXF_HTTP;
        }

        if (cx->hp && (cx->hp->flags & HF_PARSE_ERROR)) {
            CXL5("HF_PARSE_ERROR disconnect if not pinned.");
            if (!(cx->hp->flags & HF_PINNED) && cx_hp_disconnect(cx) < 0)
                goto out;
        }

        if (cx->hp && (cx->hp->h.daddr.sin_port != cx->h.daddr.sin_port ||
                      (strcasecmp(cx->hp->h.sv_name, cx->h.sv_name) != 0) ||
                      (cx->proxy && !(cx->hp->flags & HF_PINNED)))) {

            if (!cx->proxy) {
                CXL5("cx changed from %s:%hu -> %s:%hu, DISCONNECT",
                        cx->hp->h.sv_name, ntohs(cx->hp->h.daddr.sin_port),
                        cx->h.sv_name, ntohs(cx->h.daddr.sin_port));
            }
            if (cx_hp_disconnect(cx) < 0)
                goto out;
        } else if (cx->hp) {
            cx->flags |= CXF_PRX_DECIDED;
            if (hp_connect_reinit(cx->hp) < 0)
                goto err;
            cx_lava_connect(cx);
            CXL5("SAME HP REUSED");
        }

        if (ssl && BUFF_BUFFERED(cx->in) > STRLEN("\r\n\r\n")) {
            char *hend;
            size_t hlen;

            hlen = BUFF_BUFFERED(cx->in) - STRLEN("\r\n\r\n");
            hend = ((char *) BUFF_BEGINNING(cx->in)) + hlen;

            hlen += 2; /* just before the last \r\n */
            if (strcmp(hend, "\r\n\r\n") == 0 &&
                (cx->connect_header_lines = calloc(1, hlen + 1))) {

                memcpy(cx->connect_header_lines, BUFF_BEGINNING(cx->in), hlen);
            }
        }
    }

    assert((cx->flags & CXF_HOST_RESOLVED));
    if (!(cx->flags & CXF_PRX_DECIDED)) {
        if (cx_proxy_decide(cx) < 0) {
            CXL("cx_decide ERROR");
            goto err;
        }
        if (!(cx->flags & CXF_PRX_DECIDED))
            goto out_buffer;

        if (cx->proxy && !cx->srv_parser && parser_create_response(&cx->srv_parser, cx) < 0)
            goto err;

        if (cx->hp && cx->proxy)
            if (!(cx->hp->flags & HF_PINNED) && cx_hp_disconnect(cx) < 0)
                goto out;
    }

    assert((cx->flags & CXF_PRX_DECIDED));
    if (!(cx->flags & CXF_NI_ESTABLISHED) && cx->proxy) {
        cx->flags |= CXF_NI_ESTABLISHED;
        if (cx->ni_opaque)
            ni_event(cx->ni_opaque, CHR_EVENT_OPENED);
    }

    if (!(cx->flags & CXF_GUEST_PROXY) && cx->proxy) {
        if (!(cx->flags & (CXF_BINARY | CXF_TLS | CXF_HTTP)))
            goto out_buffer; /* wait for more bytes from the G */
        if ((cx->flags & CXF_HTTP) && !(cx->flags & CXF_HEADERS_OK))
            goto out_buffer; /* wait till headers complete */
        if ((cx->flags & CXF_HTTP) && !(cx->flags & CXF_LONG_REQ) &&
            cx->clt_parser && cx->clt_parser->parse_state != PS_MCOMPLETE) {

            CXL5("waiting PS_MCOMPLETE");
            goto out_buffer; /* wait till message complete */
        }

        if ((cx->flags & (CXF_HTTP | CXF_BINARY | CXF_TLS)) == CXF_HTTP &&
            !cx->hp && cx->clt_parser && cx->clt_parser->h.method &&
            strcasecmp(cx->clt_parser->h.method, S_HEAD) == 0) {

            cx->flags |= CXF_HEAD_REQUEST;
            cx->flags &= ~CXF_HEAD_REQUEST_SENT;
        }
    }

    if (!(cx->flags & CXF_LOCAL_WEBDAV) && !cx->hp) {
        bool connect_now = false;

        if ((!(cx->flags & CXF_GUEST_PROXY) || buf || BUFF_BUFFERED(cx->in)) &&
            cx_hp_connect(cx, &connect_now) < 0) {

            goto err;
        }
        if (connect_now && !(cx->flags & CXF_NI_ESTABLISHED)) {
            cx->flags |= CXF_NI_ESTABLISHED;
            ni_event(cx->ni_opaque, CHR_EVENT_OPENED);
        }
    }

    if ((cx->flags & CXF_TUNNEL_DETECTED))
        goto out_buffer;

    if (cx->hp) {
        assert(len_buf >= ret);
        r = hp_clt_process(cx->hp, buf + ret, len_buf - ret);
        CXL5("hp_clt_process ret %d for %d", r, len_buf - ret);
        if (r < 0)
            goto err;
        ret += r;
    } else if ((cx->flags & CXF_LOCAL_WEBDAV)) {
        assert(len_buf >= ret);
        r = cx_webdav_process(cx, buf + ret, len_buf - ret);
        CXL5("cx_webdav_process ret %d for %d", r, len_buf - ret);
        if (r < 0)
            goto err;
        ret += r;
    }

out_buffer:
    if (ret == len_buf)
        goto out;

    if ((cx->flags & CXF_CLOSED))
        goto out;

    assert(cx->in);
    assert(len_buf > ret);
    if (buff_append(cx->in, (const char*) (buf + ret), len_buf - ret) < 0)
        goto mem_err;
    ret = len_buf;

out:
    return ret;

mem_err:
    warnx("%s: cx %"PRIxPTR" malloc", __FUNCTION__, (uintptr_t) cx);
err:
    CXL("ERROR");
    cx_close(cx);
    ret = -1;
    goto out;
}

static CharDriverState *
cx_open(void *opaque, struct nickel *ni, struct sockaddr_in saddr, struct sockaddr_in daddr)
{
    CharDriverState *chr = NULL;
    const char *sv_name = NULL;
    struct clt_ctx *cx = NULL;

    NETLOG5("%s: to %s:%hu", __FUNCTION__, inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port));
    if (daddr.sin_addr.s_addr == 0 || daddr.sin_port == 0)
        goto cleanup;

    cx = cx_create(ni);
    chr = calloc(1, sizeof(*chr));
    if (!cx || !chr) {
        warnx("%s: memory error", __FUNCTION__);
        goto cleanup;
    }
    cx->chr = chr;
    cx->chr->refcnt = 1;

    cx->ni_opaque = opaque;
    cx->h.daddr = daddr;
    cx->h.daddr.sin_family = AF_INET; /* ipv4 only (in the guest) */
    cx->flags |= CXF_HOST_RESOLVED;

    if (fakedns_is_fake(&daddr.sin_addr)) {
        if (fakedns_is_denied(&daddr.sin_addr)) {
            CXL("fake-ip daddr %s denied", inet_ntoa(daddr.sin_addr));
            goto cleanup;
        }
        sv_name = fakedns_get_name(daddr.sin_addr);
        if (!sv_name)
            goto cleanup;
    }
    if (!sv_name) {
        sv_name = inet_ntoa(daddr.sin_addr);
        if (!sv_name)
            goto cleanup;
    }
    cx->h.sv_name = strdup(sv_name);
    if (!cx->h.sv_name)
        goto cleanup;

    qemu_chr_add_handlers(chr, cx_chr_can_read, cx_chr_read, NULL, cx);
    chr->chr_write = cx_chr_write;
    chr->chr_send_event = cx_chr_event;
    chr->chr_can_write = cx_chr_can_write;
    chr->chr_save = cx_chr_save;
    chr->chr_restore = cx_chr_restore;

    CXL5("created");
    cx_process(cx, NULL, 0);
    if ((cx->flags & CXF_NI_ESTABLISHED))
        ni_event(cx->ni_opaque, CHR_EVENT_OPENED);

    return chr;
cleanup:
    if (cx) {
        cx->ni_opaque = NULL;
        cx_close(cx);
    }
    return NULL;
}

static CharDriverState *
ns_cx_open(void *opaque, struct nickel *ni, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr, yajl_val config)
{
    CharDriverState *chr = NULL;
    struct clt_ctx *cx = NULL;

    cx = cx_create(ni);
    chr = calloc(1, sizeof(*chr));
    if (!cx || !chr)
        goto mem_err;

    cx->chr = chr;
    cx->chr->refcnt = 1;

    cx->ni_opaque = opaque;
    cx->flags |= (CXF_GUEST_PROXY | CXF_HTTP);
    if (cx_parser_create_request(cx) < 0)
        goto mem_err;

    qemu_chr_add_handlers(chr, cx_chr_can_read, cx_chr_read, NULL, cx);
    chr->chr_write = cx_chr_write;
    chr->chr_send_event = cx_chr_event;
    chr->chr_can_write = cx_chr_can_write;
    chr->chr_save = cx_chr_save;
    chr->chr_restore = cx_chr_restore;

    cx->flags |= CXF_NI_ESTABLISHED;

    CXL5("CXF_NI_ESTABLISHED");
    return chr;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    return NULL;
}

ni_prx_add_service(prx);
ns_add_service(ns_prx_desc);
