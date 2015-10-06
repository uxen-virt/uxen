/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef __PROXY_H__
#define __PROXY_H__

#ifndef _WIN32
#include <netinet/in.h>
#endif

#include <dm/queue2.h>
#include <dns/dns.h>


#define QUICK_HTTP_PARSE_LEN    4
#define VERBSTATS   1
#define LAT_STAT_NUMBER         10

struct nickel;

struct clt_ctx;
struct parser_ctx;
struct proxy_t;
struct hpd_t;
struct buff;
struct http_server {
    char *sv_name;
    struct sockaddr_in daddr;
};
RLIST_HEAD(clt_ctx_list, clt_ctx);
struct clt_ctx {
    struct CharDriverState *chr;

    LIST_ENTRY(clt_ctx) entry;
    RLIST_ENTRY(clt_ctx_list) w_list;
    RLIST_ENTRY(clt_ctx_list) direct_cx_list;
    struct nickel *ni;
    void *ni_opaque;
    struct http_ctx *hp;
    void *webdav_opaque;
    struct http_server h;
    const char *schema;
    uint64_t flags;
    struct buff *in;
    struct buff *out;
    char *connect_header_lines;
    uint8_t bf_tls_ck[QUICK_HTTP_PARSE_LEN + 1];
    int bf_tls_ck_len;
    struct proxy_t *proxy;
    struct hpd_t *hpd;
    struct parser_ctx *clt_parser;
    struct parser_ctx *srv_parser;
    char *alternative_proxies;
    unsigned int restart_state;

#if VERBSTATS
    int64_t created_ts;
    int64_t rq_ts;
    uint32_t number_req;
    uint32_t lat_max;
    uint32_t lat_min;
    uint32_t lat_sum;
    uint32_t clt_lat[LAT_STAT_NUMBER * 2];
    int clt_lat_idx;
#endif

    uint32_t refcnt;
};
struct proxy_t {
    LIST_ENTRY(proxy_t) entry;
    struct clt_ctx w_list;
    const char *name;
    char *canon_name;
    struct net_addr *a;
    int port;
    int resolved;
    int ct;
    int wakeup_list;
    char *realm;
};
extern struct proxy_t proxy_direct;

#define PROXY_IS_DIRECT(proxy)  ((proxy) == &proxy_direct)

#define PRXL0(ll, fmt, ...) NETLOG_LEVEL(ll, "(prx) px %"PRIxPTR" [%s] " fmt, \
                    (uintptr_t) proxy, __FUNCTION__,  ## __VA_ARGS__)

#define PRXL(fmt, ...)  PRXL0(1, fmt, ## __VA_ARGS__)
#define PRXL2(fmt, ...) PRXL0(2, fmt, ## __VA_ARGS__)
#define PRXL3(fmt, ...) PRXL0(3, fmt, ## __VA_ARGS__)
#define PRXL4(fmt, ...) PRXL0(4, fmt, ## __VA_ARGS__)
#define PRXL5(fmt, ...) PRXL0(5, fmt, ## __VA_ARGS__)
#define PRXL6(fmt, ...) PRXL0(6, fmt, ## __VA_ARGS__)
struct proxy_t * proxy_find(const char *name, uint16_t port);
void proxy_foreach(void (*cb)(struct proxy_t * proxy));
struct proxy_t * proxy_save(const char *name, uint16_t port, int ct, const char *realm);
void proxy_reset(struct proxy_t *proxy);
struct proxy_t * proxy_save(const char *name, uint16_t port, int ct, const char *realm);
void proxy_update(struct proxy_t *proxy, int ct, const char *realm);
void proxy_cache_add(struct nickel *ni, const char *schema, const char *domain, int port, struct proxy_t *proxy);
struct proxy_t * proxy_cache_find(const char *schema, const char *domain, int port);
void proxy_cache_reset(void);
int proxy_number_waiting(struct proxy_t *proxy);
#endif
