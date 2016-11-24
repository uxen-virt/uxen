/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HTTP_AUTH__H_
#define _HTTP_AUTH__H_

#define HTTP_AUTH_MAP(XX)                 \
  XX(0,  UNKNOWN,   "#")                  \
  XX(1,  NONE,      "")                   \
  XX(2,  NTLM,      "ntlm")               \
  XX(3,  NEGOTIATE, "negotiate")          \
  XX(4,  KERBEROS,  "kerberos")           \
  XX(5,  BASIC,     "basic")              \

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define IS_SSPI_AUTH(a) ((a) == AUTH_TYPE_NTLM || (a) == AUTH_TYPE_NEGOTIATE || \
        (a) == AUTH_TYPE_KERBEROS)

enum auth_enum {
#define XX(num, name, string) AUTH_TYPE_##name = num,
  HTTP_AUTH_MAP(XX)
#undef XX
};

struct nickel;
struct http_header;
struct http_ctx;
struct http_auth {
    struct nickel *ni;
    enum auth_enum type;
    char *prx_auth;
    int authorized;
    int was_authorized;
    int sessions;
    int last_step;
    int cred_tried;
    int logon_required;
    int needs_reconnect;
    int needs_restart;
    void *auth_opaque;
    struct proxy_t *proxy;
    struct http_ctx *hp;
    struct http_header *auth_header;
};

#define AUTH_PASS           0
#define AUTH_PROGRESS       1
#define AUTH_ERR            2
#define AUTH_RESTART        3


#define AUXL0(ll, fmt, ...) NETLOG_LEVEL(ll, "(auth) a:%"PRIxPTR" hp:%"PRIxPTR" [%s] " fmt, \
                    (uintptr_t) auth, (uintptr_t) auth->hp, __FUNCTION__,  ## __VA_ARGS__)

#define AUXL(fmt, ...)  AUXL0(1, fmt, ## __VA_ARGS__)
#define AUXL2(fmt, ...) AUXL0(2, fmt, ## __VA_ARGS__)
#define AUXL3(fmt, ...) AUXL0(3, fmt, ## __VA_ARGS__)
#define AUXL4(fmt, ...) AUXL0(4, fmt, ## __VA_ARGS__)
#define AUXL5(fmt, ...) AUXL0(5, fmt, ## __VA_ARGS__)
#define AUXL6(fmt, ...) AUXL0(6, fmt, ## __VA_ARGS__)
int http_auth_init(void);
void http_auth_exit(void);
struct http_auth * http_auth_create(struct nickel *ni, struct http_ctx *hp, struct proxy_t *proxy);
void http_auth_free(struct http_auth **pauth);
int http_auth_reset(struct http_auth *auth);
int http_auth_clt(struct http_auth *auth);
int http_auth_srv(struct http_auth *auth, struct http_header *h);
int http_auth_srv_closing(struct http_auth *auth);
#endif
