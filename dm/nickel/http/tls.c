/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/queue2.h>
#include <inttypes.h>
#include <dm/base64.h>
#include <dm/dict.h>
#include <dm/dict-rpc.h>
#include <dm/control.h>


#include <nickel.h>
#include <log.h>
#include <buff.h>
#include "tls.h"
#include "proxy.h"
#include "cert.h"

#define SSL_CHANGE_CIPHER_SPEC 0x14
#define SSL_ALERT 0x15
#define SSL_HANDSHAKE 0x16
#define SSL_APPLICATION_DATA 0x17
#define SSLV3_MAJOR 0x03
#define SSLHS_CLT_HELLO 0x01
#define SSLHS_CERTIFICATE 0x0b
#define SSLHS_SRV_HELLO_DONE 0x0e

#define HS_STATE_INIT     0
#define HS_STATE_LENGTH   1
#define HS_STATE_DATA     2

#define CST_INIT        0
#define CST_LENGTH      1
#define CST_CINIT       2
#define CST_CLENGTH     3
#define CST_CCERT       4
#define CST_VALIDATING  5
#define CST_DONE        6

#define CRSP_INIT       0
#define CRSP_OK         1
#define CRSP_REVOKED    2
#define CRSP_ERR        3

#define CLT_STATE_INIT  0
#define CLT_STATE_SID   1
#define CLT_STATE_DONE  2


/* RFC 5246 and RFC 4366, TLS 1.2 handshake types:
    hello_request(0), client_hello(1), server_hello(2),
    certificate(11), server_key_exchange (12),
    certificate_request(13), server_hello_done(14),
    certificate_verify(15), client_key_exchange(16),
    finished(20) certificate_url(21), certificate_status(22),
*/

#define IS_STANDARD_SSLHS(a)  (((a) >= 0 && (a) <= 2) ||        \
        ((a) >= 11 && (a) <= 16) || ((a) >= 20 && (a) <= 22))

#define TLSL0(ll, fmt, ...) NETLOG_LEVEL(ll, "(tls) tl:%"PRIxPTR" hp:%"PRIxPTR" [%s] " fmt, \
        (uintptr_t) tls, (uintptr_t) (tls ? tls->hp : 0), __FUNCTION__,  ## __VA_ARGS__)

#define TLSL(fmt, ...)  TLSL0(1, fmt, ## __VA_ARGS__)
#define TLSL2(fmt, ...) TLSL0(2, fmt, ## __VA_ARGS__)
#define TLSL3(fmt, ...) TLSL0(3, fmt, ## __VA_ARGS__)
#define TLSL4(fmt, ...) TLSL0(4, fmt, ## __VA_ARGS__)
#define TLSL5(fmt, ...) TLSL0(5, fmt, ## __VA_ARGS__)
#define TLSL6(fmt, ...) TLSL0(6, fmt, ## __VA_ARGS__)

struct tls_rec_header {
    uint8_t type;
    uint16_t version;
    uint16_t len;
} __attribute__((packed));

struct tls_hs_header {
    uint8_t type;
    uint8_t len[3];
} __attribute__((packed));

struct tls_clt_hello {
    uint16_t clt_version;
    uint32_t gmt_unix_time;
    uint8_t random[28];
    uint8_t sid_len;
} __attribute__((packed));

struct tls_rec {
    uint8_t hidx;
    size_t hlen;
    struct tls_rec_header header;
    struct tls_hs_header hs_header;

    int hs_type;
    uint8_t hs_idx;
    size_t hs_len;
};

struct cert_t;
RLIST_HEAD (cert_list, cert_t);
struct cert_t {
    RLIST_ENTRY(cert_list) entry;
    uint32_t len;
    uint32_t offset;
    uint8_t *data;
};

struct cert_ctx_t {
    RLIST_ENTRY(cert_list) entry;
    struct tls_state_t *tls;
    int state;
    uint32_t len;
    int response_state;
    uint32_t response_err;
};

enum sslv2_check_t {
    SSLv2_CK_INIT   = 0,
    SSLv2_CK_BUFF,
    SSLv2_CK_SSLv2,
    SSLv2_CK_OTHER
};

struct tls_state_t {
    struct nickel *ni;
    const struct http_ctx *hp;
    enum sslv2_check_t  sslv2;
    /* clt */
    struct tls_rec clr;
    struct tls_clt_hello clt_hello;
    uint32_t clt_idx;
    uint8_t *clt_sid;
    size_t clt_sid_idx;
    int clt_state;

    /* svr */
    struct tls_rec svr;
    int cert_parse_done;
    struct cert_ctx_t *cert_ctx;
    void (*cb) (void *opaque, int revoked, uint32_t err_code);
    void *cb_opaque;
    int64_t check_ts;
    int closing;
    uint32_t refcnt;
};

static void tls_get(struct tls_state_t *tls);
static int tls_put(struct tls_state_t *tls);
static size_t tls_rec_read(struct tls_state_t *tls, const uint8_t *buf, size_t len, bool is_client);
static size_t
tls_handshake_read(struct tls_state_t *tls, const uint8_t *buf, size_t len, bool is_client);
static struct cert_ctx_t * cert_init(void);
static int cert_parse(struct cert_ctx_t *cert_ctx, const uint8_t *buf, size_t len);
static int clt_hello_parse(struct tls_state_t *tls, const uint8_t *buf, size_t len);


static size_t tls_rec_read(struct tls_state_t *tls, const uint8_t *buf, size_t len, bool is_client)
{
    size_t ret = 0, cp;
    struct tls_rec *rec;

    if (!len)
        goto out;

    rec = is_client ? &tls->clr : &tls->svr;

    if (is_client && (tls->sslv2 == SSLv2_CK_BUFF || tls->sslv2 == SSLv2_CK_SSLv2)) {
        ret = len;
        goto out;
    }

    if (is_client && tls->sslv2 == SSLv2_CK_INIT) {
        if (len < 3) {
            tls->sslv2 = SSLv2_CK_BUFF;
            TLSL2("SSLv2_CK_BUFF");
            ret = len;
            goto out;
        }

        if (buf[0] == 0x80 && buf[2] == 0x01) {
            tls->sslv2 = SSLv2_CK_SSLv2;
            TLSL2("SSLv2 !");
            ret = len;
            goto out;
        }

        tls->sslv2 = SSLv2_CK_OTHER;
    }

    /* termination */
    if (rec->hidx == sizeof(struct tls_rec_header) && rec->hlen == 0) {
        memset(&rec->header, 0, sizeof(rec->header));
        rec->hidx = 0;
        rec->hlen = 0;
    }

    /* header */
    if (rec->hidx < sizeof(struct tls_rec_header)) {
        cp = sizeof(struct tls_rec_header) - rec->hidx;
        if (cp > len)
            cp = len;
        memcpy(((uint8_t *)(&rec->header)) + rec->hidx, buf, cp);

        rec->hidx += cp;
        ret += cp;

        if (rec->hidx < sizeof(struct tls_rec_header))
            goto out;

        rec->hs_type = -1;
        rec->hs_len = 0;
        rec->hs_idx = 0;
        rec->hlen = ntohs(rec->header.len);
        TLSL5("TLS rec len %lu, type %d", (unsigned long) rec->hlen, (int) rec->header.type);

        goto out;
    }

    /* tls data */
    assert(rec->hlen);
    cp = len > rec->hlen ? rec->hlen : len;
    if (rec->header.type == SSL_HANDSHAKE) {
        cp = tls_handshake_read(tls, buf, cp, is_client);
        if (cp == 0) {
            if (!tls->cert_parse_done) {
                TLSL("tls_handshake_read ERROR");
            }
            ret = 0;
            goto out;
        }
    } else if (!is_client && rec->header.type == SSL_CHANGE_CIPHER_SPEC) {
        TLSL5("server SSL_CHANGE_CIPHER_SPEC");
        tls->cert_parse_done = 1;
        ret = 0;
        goto out;
    }

    rec->hlen -= cp;
    ret += cp;
out:
    return ret;
}

#define ADV_BUF(l)    do { buf += (l); len -= (l); } while(1 == 0)
#define ADV_REC(l)    do { ADV_BUF(l); ret += (l); } while(1 == 0)
static size_t
tls_handshake_read(struct tls_state_t *tls, const uint8_t *buf, size_t len, bool is_client)
{
    size_t ret = 0, cp;
    struct tls_rec *rec;

    if (!len)
        goto out;

    rec = is_client ? &tls->clr : &tls->svr;

    while (len) {
        cp = len;
        /* peek type */
        if (rec->hs_type < 0) {
            rec->hs_type = (int) (*buf);
            TLSL5("hs_type (peek) %d", rec->hs_type);
            if (!is_client && rec->hs_type == SSLHS_SRV_HELLO_DONE) {
                tls->cert_parse_done = 1;
                break;
            }
        }

        if (!IS_STANDARD_SSLHS(rec->hs_type)) {
            ADV_REC(cp);
            continue;
        }

        if (rec->hs_idx < sizeof(struct tls_hs_header)) {
            cp = sizeof(struct tls_hs_header) - rec->hs_idx;
            if (cp > len)
                cp = len;
            memcpy(((uint8_t *)(&rec->hs_header)) + rec->hs_idx, buf, cp);
            rec->hs_idx += cp;
            ADV_REC(cp);

            if (rec->hs_idx == sizeof(struct tls_hs_header)) {
                uint32_t l;

                l = 0;
                memcpy(((uint8_t*)&l) + 1, &rec->hs_header.len, 3);
                rec->hs_len = ntohl(l);
                TLSL5("TLS hs %d len %lu", rec->hs_type, (unsigned long) rec->hs_len);
            }

            continue;
        }

        if (rec->hs_len == 0) {
            rec->hs_type = -1;
            rec->hs_idx = 0;

            continue;
        }

        /* hs data */
        cp = rec->hs_len > len ? len : rec->hs_len;
        if (is_client) {
            if (rec->hs_type == SSLHS_CLT_HELLO && clt_hello_parse(tls, buf, cp) < 0) {
                TLSL("ERROR - clt_hello_parse error");
                goto err;
            }
        } else {
            if (rec->hs_type == SSLHS_SRV_HELLO_DONE) {
                tls->cert_parse_done = 1;
                break;
            }
            if (rec->hs_type == SSLHS_CERTIFICATE) {
                if (!tls->cert_ctx && !(tls->cert_ctx = cert_init()))
                    goto mem_err;
                tls->cert_ctx->tls = tls;
                if (cert_parse(tls->cert_ctx, buf, cp) < 0) {
                    TLSL("ERROR - cert_parse error");
                    goto err;
                }
            }
        }

        ADV_REC(cp);
        rec->hs_len -= cp;
    }

out:
    return ret;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
err:
    ret = 0;
    goto out;
}

static struct cert_ctx_t * cert_init(void)
{
    struct cert_ctx_t *cert_ctx;

    cert_ctx = calloc(1, sizeof (*cert_ctx));
    if (!cert_ctx) {
        warnx("%s: malloc", __FUNCTION__);
        goto out;
    }
    RLIST_INIT(cert_ctx, entry);
out:
    return cert_ctx;
}

static void cert_free(struct cert_ctx_t *cert_ctx)
{
    if (cert_ctx) {
        struct cert_t *cert, *next;

        RLIST_FOREACH_SAFE(cert, (struct cert_t*)cert_ctx, entry, next) {
            RLIST_REMOVE(cert, entry);
            ni_priv_free(cert->data);
            free(cert);
        }
    }
    free(cert_ctx);
}

static int cert_parse(struct cert_ctx_t *cert_ctx, const uint8_t *buf, size_t len)
{
    int ret = 0;
    struct cert_t *cert = NULL;
    struct tls_state_t *tls = cert_ctx->tls;
    size_t cp;

    if (cert_ctx->state == CST_VALIDATING)
        goto out;

    while (len) {

        if (cert_ctx->state == CST_INIT) {
            cert_ctx->len = 0x1;
            cert_ctx->state = CST_LENGTH;
        }

        if (cert_ctx->state == CST_LENGTH) {
            cert_ctx->len <<= 8;
            cert_ctx->len |= (uint32_t) (*buf);
            if ((cert_ctx->len & 0xFF000000)) {
                cert_ctx->state = CST_CINIT;
                cert_ctx->len &= (~0xFF000000);
                TLSL5("cert LIST len %lu", (unsigned long) cert_ctx->len);
            }
            ADV_BUF(1);
            continue;
        }

        if (cert_ctx->len == 0) {
            cert_ctx->state = CST_VALIDATING;
            break;
        }

        if (cert_ctx->state == CST_CINIT) {
            cert = calloc(1, sizeof(*cert));
            if (!cert)
                goto mem_err;
            RLIST_INSERT_TAIL((struct cert_t *)cert_ctx, cert, entry);
            cert->len = 0x01;
            cert_ctx->state = CST_CLENGTH;
        }

        assert(!RLIST_EMPTY(cert_ctx, entry));
        if (!cert)
            cert = RLIST_LAST(cert_ctx, entry);

        if (cert_ctx->state == CST_CLENGTH) {
            cert->len <<= 8;
            cert->len |= (uint32_t) (*buf);
            if ((cert->len & 0xFF000000)) {
                cert_ctx->state = CST_CCERT;
                cert->len &= (~0xFF000000);
                TLSL5("cert CERT len %lu", cert->len);
            }
            ADV_BUF(1);
            cert_ctx->len -= 1;
            continue;
        }

        assert(cert_ctx->state == CST_CCERT);
        if (cert->offset == cert->len) {
            cert_ctx->state = CST_CINIT;
            continue;
        }
        if (!cert->data && !(cert->data = ni_priv_calloc(1, cert->len)))
            goto mem_err;
        cp = cert->len - cert->offset;
        if (cp > len)
            cp = len;
        if (cp > cert_ctx->len)
            cp = cert_ctx->len;
        memcpy(cert->data + cert->offset, buf, cp);
        cert->offset += cp;
        ADV_BUF(cp);
        cert_ctx->len -= cp;
        if (cert->offset == cert->len) {
            TLSL5("cert COPIED");
            cert_ctx->state = CST_CINIT;
        }
    }
out:
    return ret;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    ret = -1;
    goto out;
}

static void cert_check_sync(void *opaque)
{
    struct cert_ctx_t *cert_ctx = opaque;
    struct tls_state_t *tls = cert_ctx->tls;
    int cert_res;
    size_t ncerts;
    struct cert_t *cert, *cx;
    struct hcert_ctx *hcx = NULL;
    uint32_t err_code = 0;

    cert_ctx->response_state = CRSP_ERR;
    if (!tls || tls->closing)
        goto out;

    if (RLIST_EMPTY(cert_ctx, entry)) {
        TLSL5("no certificates");
        goto out;
    }
    cert = RLIST_FIRST(cert_ctx, entry);
    if (!cert->data || !cert->len) {
        TLSL5("empty certificate");
        goto out;
    }
    if (cert->offset != cert->len) {
        TLSL2("(err) cert incomplete");
        goto out;
    }

    ncerts = 0;
    RLIST_FOREACH(cx, (struct cert_t*)cert_ctx, entry)
        ncerts++;
    hcx = hcert_open_chain(ncerts);
    if (!hcx) {
        TLSL("ERROR - cannot create cert chain");
        goto out;
    }

    RLIST_FOREACH(cx, (struct cert_t*)cert_ctx, entry) {
        if (hcert_add_cert(hcx, cx->data, cx->len) < 0) {
            TLSL("ERROR on hcert_add_cert");
            goto out;
        }
    }

    cert_res = hcert_get_chain(hcx, NULL, &err_code, NULL, NULL, server, true); /* XXX no hostname for now */
    TLSL2("hcert_verify_chain %d err 0x%lx", cert_res, (unsigned long) err_code);

    cert_ctx->response_err = err_code;
    /* XXX only check for revoked certificates for now */
    if (cert_res == HCERT_OK)
        cert_ctx->response_state = CRSP_OK;
    else if (cert_res == HCRET_REVOKED)
        cert_ctx->response_state = CRSP_REVOKED;
out:
    if (hcx)
        hcert_free(hcx);
}

static void cert_check_finish(void *opaque)
{
    struct cert_ctx_t *cert = opaque;
    struct tls_state_t *tls = cert->tls;
    int revoked = 0;
    int64_t now;

    if (!tls)
        goto out;

    revoked = (cert->response_state == CRSP_REVOKED) ? 1 : 0;

    if (!tls->closing)
        TLSL5("revoked %d", revoked);
    now = get_clock_ms(rt_clock);
    if (now - tls->check_ts > 300) {
        TLSL("certificate check ret %d took %lu ms",
                cert->response_state, (unsigned long) (now - tls->check_ts));
    } else {
        TLSL4("certificate check ret %d in %lu ms",
                cert->response_state, (unsigned long) (now - tls->check_ts));
    }
    if (tls->cb)
        tls->cb(tls->cb_opaque, revoked, cert->response_err);

    tls_put(tls);
out:
    cert_free(cert);
}

int tls_async_cert_check(struct tls_state_t *tls, void (*cb)(void *opaque, int revoked,
            uint32_t err_code), void *opaque)
{
    int ret = -1;
    struct cert_ctx_t *cert = tls->cert_ctx;

    if (!cert)
        goto out;

    tls_get(tls);
    tls->check_ts = get_clock_ms(rt_clock);
    tls->cert_ctx = NULL;
    cert->tls = tls;
    tls->cb = cb;
    tls->cb_opaque = opaque;
    if (ni_schedule_bh(tls->ni, cert_check_sync, cert_check_finish, cert)) {
        tls->cb = NULL;
        tls->cert_ctx = cert;
        tls_put(tls);
        NETLOG("%s: unet_schedule_bh failure", __FUNCTION__);
        goto out;
    }
    ret = 0;
out:
    return ret;
}

int tls_cert_send_hostsvr(struct tls_state_t *tls, const char *hostname)
{
    int ret = -1;
    struct cert_t *cx;
    struct cert_ctx_t *cert_ctx = tls->cert_ctx;
    dict d = NULL;
    struct buff *bf = NULL;
    bool first = true;
    char *str = NULL;

    if (!cert_ctx)
        goto out;

    d = dict_new();
    bf = buff_new(NULL, 4096);
    if (!d || !bf)
        goto mem_err;

    dict_put_string(d, "hostname", hostname ? hostname : "");

    RLIST_FOREACH(cx, (struct cert_t*)cert_ctx, entry) {
        str = base64_encode((const unsigned char *)cx->data, cx->len);
        if (!str)
            goto mem_err;
        if (!first && BUFF_APPENDSTR(bf, ",") < 0)
            goto mem_err;
        first = false;
        if (BUFF_APPENDSTR(bf, str) < 0)
            goto mem_err;
        free(str);
        str = NULL;
    }

    dict_put_string(d, "certs", BUFF_TO(bf, const char *));
    NETLOG4("h:%lx sending nc_TLSCertificates blen %lu", tls->hp, (unsigned long) bf->len);
    if (control_send_command("nc_TLSCertificates", d, NULL, NULL))
        goto out;

    ret = 0;
out:
    free(str);
    if (d)
        dict_free(d);
    buff_free(&bf);
    return ret;

mem_err:
    warnx("%s: malloc", __FUNCTION__);
    ret = -1;
    goto out;
}

bool tls_is_ssl(const uint8_t *b, size_t len)
{
    uint16_t ssl_version;

    if (len < 3)
        return false;

    if (b[0] == 0x80 && b[2] == 0x01) // SSLv2 Client Hello
        return true;

    if (b[0] != SSL_HANDSHAKE)
        return false;

    ssl_version = ntohs(*((uint16_t *)(b + 1)));
    if ((ssl_version >> 8) != SSLV3_MAJOR)
        return false;

    return true;
}

bool tls_check_enabled(void)
{
    return hcert_enabled();
}

struct tls_state_t * tls_new(struct nickel *ni, const struct http_ctx *hp)
{
    struct tls_state_t *tls;

    tls = calloc(1, sizeof(*tls));
    if (!tls)
        warnx("%s: malloc", __FUNCTION__);
    tls->ni = ni;
    tls->hp = hp;
    tls->refcnt = 1;
    return tls;
}

static void tls_get(struct tls_state_t *tls)
{
    if (!tls)
        return;

    atomic_inc(&tls->refcnt);
}

static int tls_put(struct tls_state_t *tls)
{
    if (!tls)
        return 0;

    if (!atomic_dec_and_test(&tls->refcnt))
        return -1;

    cert_free(tls->cert_ctx);
    tls->cert_ctx = NULL;
    ni_priv_free(tls->clt_sid);
    free(tls);
    return 0;
}

void tls_free(struct tls_state_t **ptls)
{
    struct tls_state_t *tls = *ptls;

    if (!tls)
        return;
    tls->closing = 1;
    tls_put(tls);
    *ptls = NULL;
}

static int clt_hello_parse(struct tls_state_t *tls, const uint8_t *buf, size_t len)
{
    int ret = 0;
    size_t cp;

    if (!tls)
        goto out;

    if (tls->clt_state == CLT_STATE_DONE)
        goto out;

    while (len) {
        if (tls->clt_idx < sizeof(struct tls_clt_hello)) {
            cp = sizeof(struct tls_clt_hello) - tls->clt_idx;

            if (cp > len)
                cp = len;
            memcpy(((uint8_t *)(&tls->clt_hello)) + tls->clt_idx, buf, cp);
            tls->clt_idx += cp;
            ADV_BUF(cp);

            if (tls->clt_idx < sizeof(struct tls_clt_hello))
                break;
            tls->clt_state = CLT_STATE_DONE;
            if (tls->clt_hello.sid_len != 0) {
                tls->clt_sid = ni_priv_calloc(1, tls->clt_hello.sid_len);
                if (!tls->clt_sid) {
                    warnx("%s: malloc", __FUNCTION__);
                    ret = -1;
                    goto out;
                }
                tls->clt_state = CLT_STATE_SID;
            }

            continue;
        }

        /* data */
        if (tls->clt_state == CLT_STATE_SID) {
            cp = tls->clt_hello.sid_len;
            if (cp > len)
                cp = len;
            memcpy(tls->clt_sid + tls->clt_sid_idx, buf, cp);
            tls->clt_sid_idx += cp;
            tls->clt_hello.sid_len -= cp;
            ADV_BUF(cp);
            if (tls->clt_hello.sid_len == 0) {
                tls->clt_state = CLT_STATE_DONE;
                TLSL5("clt sid of %lu bytes", (unsigned long) tls->clt_sid_idx);
                break;
            }

            continue;
        }

        if (tls->clt_state == CLT_STATE_DONE)
            break;
    }

out:
    return ret;
}

int tls_read(struct tls_state_t *tls, const uint8_t *buf, size_t len, bool is_client)
{
    int ret = TLSR_ERROR;
    size_t cp;

    assert(tls);

    while (len) {
        cp = tls_rec_read(tls, buf, len, is_client);
        assert(cp <= len);

        if (tls->cert_parse_done) {
            ret = TLSR_DONE_CHECK;
            if (!tls->cert_ctx)
                ret = TLSR_DONE_SKIP;
            TLSL5("cert_parse_done %d", ret);
            goto out;
        }

        if (cp == 0) {
            TLSL("ERROR on parsing tls_rec_read");
            ret = TLSR_ERROR;
            goto out;
        }

        buf += cp;
        len -= cp;
    }

    ret = TLSR_CONTINUE;

out:
    return ret;
}
