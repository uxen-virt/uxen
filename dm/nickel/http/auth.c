/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/dict.h>
#include <dm/dict-rpc.h>
#include <log.h>
#include <nickel.h>
#include "proxy.h"
#include "strings.h"
#include "parser.h"
#include "rpc.h"
#include "auth.h"
#include <inttypes.h>

#if defined(_WIN32)
#include "auth-basic.h"
#include "auth-sspi.h"
#endif

#define MAX_AUTH_SESSIONS   3

static const char *auth_types[] = {
#define XX(num, name, string) string,
    HTTP_AUTH_MAP(XX)
#undef XX
};

static int change_auth(struct http_auth *auth, enum auth_enum new_type);

static int auth_reset_header(struct http_auth *auth)
{
    int ret = -1;

    if (!auth->auth_header)
        auth->auth_header = calloc(1, sizeof (*(auth->auth_header)));
    if (!auth->auth_header)
        goto mem_err;

    parser_reset_header(auth->auth_header);
    ret = 0;
out:
    return ret;
mem_err:
    warnx("%s: malloc error", __FUNCTION__);
    ret = -1;
    goto out;
}

static enum auth_enum get_auth_type(const char *str)
{
    enum auth_enum ret = AUTH_TYPE_UNKNOWN;
    char *p;
    int len, i;

    if (!str)
        goto out;
    p = strchr(str, ' ');
    len = p ? p - str : strlen(str);

    for (i = 2; i < ARRAY_SIZE(auth_types); i++)
        if (strncasecmp(str, auth_types[i], len) == 0)
            break;

    if (i < ARRAY_SIZE(auth_types))
        ret = i;
out:
    return ret;
}

static int http_auth_get_proxy_auth(struct http_auth *auth, struct http_header *h)
{
    int ret = -1, i, prx_header = -1, prx_saved_header = -1;
    int type;
    char *p;
    bool change = false;

    if (!auth || !h)
        goto out;

    type = auth->type;
    for (i = 0; i < h->crt_header; i++) {
        enum auth_enum t;

        if (strcasecmp(BUFF_CSTR(h->headers[i].name), S_PROXY_CHALLENGE_HEADER))
            continue;

        t = get_auth_type(BUFF_CSTR(h->headers[i].value));
        if (t == AUTH_TYPE_UNKNOWN)
            continue;
        if (t == type) {
            prx_header = i;
            break;
        }
        if (prx_saved_header < 0)
            prx_saved_header = i;
    }

    if (prx_header < 0 && prx_saved_header < 0)
        goto out;

    i = -1;
    if (prx_header < 0) {
        i = prx_saved_header;
        ret = get_auth_type(BUFF_CSTR(h->headers[i].value));
        change = true;
    } else {
        i = prx_header;
        ret = auth->type;
    }

    if (i < 0)
        goto out;

    p = strchr(BUFF_CSTR(h->headers[i].value), ' ');
    if (p && *++p) {
        AUXL4("prx_auth %s", p);
        auth->prx_auth = ni_priv_strdup(p);
        if (!auth->prx_auth)
            goto mem_err;
    }

    if (change) {
        change_auth(auth, ret);
        if (auth->proxy && auth->type != auth->proxy->ct) {
            dict d;

            proxy_update(auth->proxy, auth->type, NULL);
            d = dict_new();
            if (!d)
                goto mem_err;
            dict_put_string(d, "server", auth->proxy->name);
            dict_put_integer(d, "port", ntohs(auth->proxy->port));
            dict_put_string(d, "realm", auth->proxy->realm ? auth->proxy->realm : "");
            dict_put_integer(d, "type", auth->proxy->ct);
            ni_rpc_send(auth->ni, "nc_SetProxyAuthType", d, NULL, NULL);
            dict_free(d);
        }
    }
out:
    return ret;
mem_err:
    warnx("%s: malloc error", __FUNCTION__);
    ret = -1;
    goto out;
}

static int auth_init(struct http_auth *auth)
{
    int ret = 0;

    if (auth->type == AUTH_TYPE_UNKNOWN || auth->type == AUTH_TYPE_NONE)
        goto out;

#if defined(_WIN32)
    if (IS_SSPI_AUTH(auth->type)) {
        ret = sspi_init_auth(auth);
    } else if (auth->type == AUTH_TYPE_BASIC) {
        ret = basicauth_init_auth(auth);
    }
#endif

out:
    return ret;
}
static int change_auth(struct http_auth *auth, enum auth_enum new_type)
{

#if defined(_WIN32)
    if (IS_SSPI_AUTH(auth->type)) {
        sspi_free_auth(auth);
    } else if (auth->type == AUTH_TYPE_BASIC) {
        basicauth_free_auth(auth);
    }
#endif

    auth->type = new_type;
    return auth_init(auth);
}

struct http_auth *
http_auth_create(struct nickel *ni, struct http_ctx *hp, struct proxy_t *proxy)
{
    struct http_auth *auth = NULL;

    auth = calloc(1, sizeof(*auth));
    if (!auth) {
        warnx("%s: malloc error", __FUNCTION__);
        goto out;
    }
    auth->proxy = proxy;
    auth->ni = ni;
    auth->hp = hp;

out:
    return auth;
}

void http_auth_free(struct http_auth **pauth)
{
    struct http_auth *auth = *pauth;

    if (!auth)
        return;

    change_auth(auth, AUTH_TYPE_NONE);
    ni_priv_free(auth->prx_auth);
    auth_reset_header(auth);
    free(auth->auth_header);
    auth->auth_header = NULL;

    free(auth);
    *pauth = NULL;
}

int http_auth_reset(struct http_auth *auth)
{
    int ret = 0;

    if (!auth)
        goto out;

    auth->last_step = 0;
    ni_priv_free(auth->prx_auth);
    auth->prx_auth = NULL;
    if (auth_reset_header(auth) < 0) {
        ret = -1;
        goto out;
    }
#if defined(_WIN32)
    if (IS_SSPI_AUTH(auth->type))
        sspi_reset_auth(auth);
#endif

out:
    return ret;
}

int http_auth_clt(struct http_auth *auth)
{
    int ret = -1;

    auth->logon_required = 0;
    auth->last_step = 1;
    if (auth_reset_header(auth) < 0)
        goto out;

#if defined(_WIN32)
    if (IS_SSPI_AUTH(auth->type)) {
        if (sspi_clt(auth)) {
            AUXL("sspi_step ERROR");
            goto out;
        }
    } else if (auth->type == AUTH_TYPE_BASIC) {
        if (basicauth_clt(auth)) {
            AUXL("basicauth_step ERROR");
            goto out;
        }
    }
#endif

    ret = 0;
out:
    return ret;
}

int http_auth_srv(struct http_auth *auth, struct http_header *h)
{
    int ret = AUTH_ERR;
    int auth_type = 0;

    if (!h || !auth)
        return AUTH_ERR;

    if (auth->prx_auth) {
        ni_priv_free(auth->prx_auth);
        auth->prx_auth = NULL;
    }

    auth->authorized = h->status_code == HTTP_STATUS_PROXY_AUTH ? 0 : 1;

#if defined(_WIN32)
    if (IS_SSPI_AUTH(auth->type)) {
        if (sspi_srv(auth, auth->authorized)) {
            AUXL("sspi_srv ERROR");
            goto out;
        }
    } else if (auth->type == AUTH_TYPE_BASIC) {
        if (basicauth_srv(auth, auth->authorized)) {
            AUXL("basicauth_srv ERROR");
            goto out;
        }
    }
#endif

    if (auth->authorized) {
        ret = AUTH_PASS;
        goto out;
    }

    auth_type = http_auth_get_proxy_auth(auth, h);
    if (auth_type < 0) {
        AUXL("got HTTP 407 but no proxy auth");
        goto out;
    }
    if (auth_type == AUTH_TYPE_UNKNOWN) {
        AUXL("unknown auth type");
        goto out;
    }

    if (auth->cred_tried)
        auth->logon_required = 1;

    ret = AUTH_PROGRESS;
out:
    return ret;
}

int http_auth_srv_closing(struct http_auth *auth)
{
    int ret = -1;

    if (auth->sessions >= MAX_AUTH_SESSIONS)
        goto out;

    if (auth->type == AUTH_TYPE_UNKNOWN) {
        AUXL("AUTH_TYPE_UNKNOWN");
        goto out;
    }

#if defined(_WIN32)
    if (IS_SSPI_AUTH(auth->type))
        ret = sspi_srv_closing(auth);
    else if (auth->type == AUTH_TYPE_BASIC)
        ret = basicauth_srv_closing(auth);
#endif

out:
    return ret;
}

int http_auth_init(void)
{
    int ret = 0;

#if defined(_WIN32)
    ret = sspi_lib_init();
#endif

    return ret;
}

void http_auth_exit(void)
{

#if defined(_WIN32)
    sspi_lib_exit();
#endif

}
