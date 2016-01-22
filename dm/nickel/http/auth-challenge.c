/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/base64.h>
#include <log.h>
#include <buff.h>
#include "strings.h"
#include "proxy.h"
#include "parser.h"
#include "auth.h"
#include <inttypes.h>

#include "auth-challenge.h"
#include "ntlm.h"
#if defined(_WIN32)
#include "sspi.h"
#elif defined(__APPLE__)
#include "ntlm-osx.h"
#endif

#define NTLM_TOKEN_SIGNATURE   "NTLMSSP"
#define MAX_SSPI_STEPS 6

static const char *const auth_prefix[] = {
    "Kerberos ",
    "Negotiate ",
    "NTLM "
};

struct sspi_pkg pkg_ctx[_NUMBER_OF_PACKAGES_];
extern struct ntlm_ctx *custom_ntlm;

static bool is_ntlm_token(struct http_auth *auth, const char *token, size_t len)
{
    bool ret = false;

    if (len >= sizeof(NTLM_TOKEN_SIGNATURE) &&
        strncmp(NTLM_TOKEN_SIGNATURE, token, sizeof(NTLM_TOKEN_SIGNATURE) - 1) == 0) {
        ret = true;
        goto out;
    }

    if (NLOG_LEVEL > 3)
        netlog_print_esc("TOKEN", token, len);

out:
    AUXL4(" %s", ret ? "NTLM" : "Unknown (Negotiate)");
    return ret;
}

bool challenge_auth_islast_step(struct http_auth *auth)
{
    struct challenge_ctx_t *ctx;

    if (!auth)
        return false;
    ctx = auth->auth_opaque;
    if (!ctx)
        return false;

    return ctx->nr_steps == ctx->step;
}

int challenge_auth_init(void)
{
    int ret = 0;

#if defined(_WIN32)
    ret = sspi_init();
#endif

    return ret;
}

void challenge_auth_exit(void)
{
#if defined(_WIN32)
    sspi_exit();
#endif
}

int challenge_auth_init_auth(struct http_auth *auth)
{
    int ret = -1;
    struct challenge_ctx_t *ctx;

    assert(!auth->auth_opaque);
    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        goto out;
    ctx->auth = auth;
    if (auth->type == AUTH_TYPE_KERBEROS)
        ctx->nr_steps = 1;
    else if (auth->type == AUTH_TYPE_NTLM)
        ctx->nr_steps = 2;
    else
        ctx->nr_steps = MAX_SSPI_STEPS; // Negotiate

    ctx->custom_ntlm = custom_ntlm == NULL ? 0 : 1;
#if defined(_WIN32)
    ctx->priv = sspi_init_auth(ctx);
    if (!ctx->priv)
        goto out;
#elif defined(__APPLE__)
    ctx->priv = ntlm_osx_init_auth(ctx);
    if (!ctx->priv)
        goto out;
#endif

    auth->auth_opaque = ctx;
    ret = 0;
out:
    return ret;
}

void challenge_auth_free_auth(struct http_auth *auth)
{
    struct challenge_ctx_t *ctx = auth->auth_opaque;

    if (!ctx)
        return;

    AUXL4("");
    challenge_auth_reset_auth(auth);
    free(ctx->target_name);

#if defined(_WIN32)
    sspi_free_auth(ctx->priv);
#elif defined(__APPLE__)
    ntlm_osx_free_auth(ctx->priv);
#endif

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
    auth->auth_opaque = NULL;
}

void challenge_auth_reset_auth(struct http_auth *auth)
{
    struct challenge_ctx_t *ctx = auth->auth_opaque;

    if (!ctx)
        return;

    AUXL4("");
    ctx->step = 0;

#if defined(_WIN32)
    sspi_reset_auth(ctx->priv);
#elif defined(__APPLE__)
    ntlm_osx_reset_auth(ctx->priv);
#endif
}

int challenge_auth_clt(struct http_auth *auth)
{
    int ret = -1, rc;
    enum pkg_type pkg;
    int len_auth_prefix;
    struct challenge_ctx_t *ctx;

    const char *proxy_name;
    unsigned char *buf_in_data = NULL;
    size_t buf_in_data_len = 0;
    unsigned char *buf_out_data = NULL;
    size_t buf_out_data_len = 0;
    char *buf_encoded = NULL;
    size_t buf_encoded_len = 0;

    if (!auth)
        goto out;

    rc = get_package(auth->type);
    if (rc < 0) {
        NETLOG("%s: auth package not initialized", __FUNCTION__);
        goto out;
    }
    pkg = rc;
    len_auth_prefix = strlen(auth_prefix[pkg]);

    assert(auth->proxy);
    proxy_name = auth->proxy->name;

    ctx = auth->auth_opaque;
    assert(ctx);

    ctx->step++;
    auth->last_step = !!challenge_auth_islast_step(auth);
    AUXL5("step = %d, last_step = %d", ctx->step, auth->last_step);

    if (auth->authorized) {
        auth->last_step = 1;
        ret = 0;
        goto out;
    }

    if (ctx->step > MAX_SSPI_STEPS) {
        NETLOG("%s: failing, MAX_SSPI_STEPS exceeded", __FUNCTION__);
        if (!custom_ntlm)
            auth->logon_required = 1;
        ret = 0;
        goto out;
    }

    if (!ctx->target_name) {
        if (!proxy_name) {
            NETLOG("%s: bug, no proxy_name", __FUNCTION__);
            goto out;
        }

        if (auth->type == AUTH_TYPE_KERBEROS || auth->type == AUTH_TYPE_NEGOTIATE) {
#if defined(_WIN32)
            char *tmp;

            /* kerberos needs the canonical domain name of the proxy */
            if (asprintf(&tmp, "%s/%s", "HTTP", auth->proxy->canon_name ?
                        auth->proxy->canon_name : proxy_name) < 0)
                goto mem_err;
            NETLOG5("target name: %s", tmp);
            ctx->target_name = buff_unicode_encode(tmp);
            free(tmp);
#elif defined(__APPLE__)
            NETLOG5("target name: %s", proxy_name);
            ctx->target_name = strdup(proxy_name);
#endif
        } else {
            NETLOG5("proposed target name: %s", proxy_name);
#if defined(_WIN32)
            ctx->target_name = buff_unicode_encode(proxy_name);
#elif defined(__APPLE__)
            ctx->target_name = strdup(proxy_name);
#endif
        }
    }

    if (!ctx->target_name) {
        AUXL2("no target_name!");
        goto out;
    }

    if (auth->prx_auth) {
        buf_in_data = base64_decode(auth->prx_auth, &buf_in_data_len);
        if (!buf_in_data || !buf_in_data_len) {
            NETLOG("%s: base64_decode failed for buf_in_data", __FUNCTION__);
            goto out;
        }
        AUXL4("buf_in_data decoded from %u to %u", (unsigned) strlen(auth->prx_auth),
               (unsigned) buf_in_data_len);
    }

    auth->logon_required = 0;
    if (custom_ntlm) {
        if (ntlm_get_next_token(custom_ntlm, buf_in_data, buf_in_data_len,
                &buf_out_data, &buf_out_data_len) < 0) {

            NETLOG("%s: ERROR on ntlm_get_next_token", __FUNCTION__);
            goto out;
        }
    } else {
        int r;
        int logon_required = 0, needs_reconnect = 0;

#if defined(_WIN32)
        r = sspi_clt(ctx->priv, false, buf_in_data, buf_in_data_len,
                          &buf_out_data, &buf_out_data_len,
                          &logon_required, &needs_reconnect);
        if (r < 0 || logon_required) {
            logon_required = 0;
            r = sspi_clt(ctx->priv, true, buf_in_data, buf_in_data_len,
                          &buf_out_data, &buf_out_data_len,
                          &logon_required, &needs_reconnect);
        }
#elif defined(__APPLE__)
        if (!IS_NTLM_AUTH(auth->type)) {
            AUXL2("only NTLM auth supported on OSX at the moment");
            ret = -1;
            goto out;
        }
        r = ntlm_osx_clt(ctx->priv, false, buf_in_data, buf_in_data_len,
                &buf_out_data, &buf_out_data_len,
                &logon_required, &needs_reconnect);
#else
#error "challenge auth not supported"
#endif

        if (logon_required)
            auth->logon_required = 1;
        if (needs_reconnect)
            auth->needs_reconnect = 1;
        if (r < 0 || auth->logon_required || auth->needs_reconnect) {
            ret = r;
            goto out;
        }
    }

    AUXL4("(2) step = %d, last_step = %d", ctx->step, auth->last_step);
    if (!buf_out_data || !buf_out_data_len) {
        NETLOG("%s: ERROR! no buf_out_data", __FUNCTION__);
        goto out;
    }

    /* we need to find out the number of auth steps if Negotiate */
    if (!custom_ntlm && auth->type == AUTH_TYPE_NEGOTIATE && ctx->step == 1 &&
        is_ntlm_token(auth, (const char *) buf_out_data, buf_out_data_len)) {

        ctx->nr_steps = 2; /* NTLM */
        auth->last_step = 0;
    }

    buf_encoded = base64_encode(buf_out_data, buf_out_data_len);
    if (!buf_encoded) {
        NETLOG("%s: base64_encode FAILED, len = %d", __FUNCTION__, (int) buf_out_data_len);
        goto out;
    }
    buf_encoded_len = strlen(buf_encoded);

    assert(auth->auth_header && !auth->auth_header->crt_header);
    if (auth->auth_header->crt_header >= NUM_HEADERS) {
        NETLOG("%s: ERROR, max number of headers exceeded", __FUNCTION__);
        goto out;
    }

    auth->auth_header->headers[auth->auth_header->crt_header].name =
        BUFF_NEWSTR(S_PROXY_AUTH_HEADER);
    if (!auth->auth_header->headers[auth->auth_header->crt_header].name)
        goto mem_err;

    if (!buff_new_priv(&(auth->auth_header->headers[auth->auth_header->crt_header].value),
                len_auth_prefix + buf_encoded_len))
        goto mem_err;
    if (buff_append(auth->auth_header->headers[auth->auth_header->crt_header].value,
                auth_prefix[pkg], len_auth_prefix) < 0)
        goto mem_err;
    if (buff_append(auth->auth_header->headers[auth->auth_header->crt_header].value,
                buf_encoded, buf_encoded_len) < 0)
        goto mem_err;
    auth->auth_header->crt_header++;

    ret = 0;
out:
    free(buf_in_data);
    free(buf_out_data);
    free(buf_encoded);
    return ret;

mem_err:
    warnx("%s: malloc", __FUNCTION__);
    goto out;
}

int challenge_auth_srv(struct http_auth *auth, int authorized)
{
    struct challenge_ctx_t *ctx = auth->auth_opaque;

    if (authorized)
        goto out;

    AUXL4("last_step = %d", auth->last_step);
    if (auth->last_step) {
        bool prompt_u = ctx && !custom_ntlm;

        if (prompt_u && auth->was_authorized) {
            AUXL2("last auth step but was once authorized, retry the request.");
            auth->needs_restart = 1;
            goto out;
        }

        AUXL2("last auth step but not authorized. %s",
            prompt_u ?  "Prompt for username/pass" : "CUSTOM CREDENTIALS USED. Giving Up.");
        if (prompt_u)
            auth->logon_required = 1;
    }

out:
    return 0;
}

int challenge_auth_srv_closing(struct http_auth *auth)
{
    struct challenge_ctx_t *ctx = auth->auth_opaque;

    if (!ctx || ctx->step == 0 || auth->needs_reconnect || auth->logon_required)
        return 0;

    /* if closes in the middle of auth what can we do ? */
    NETLOG("%s: h:%"PRIxPTR" unexpected proxy conn close", __FUNCTION__, (uintptr_t) auth->hp);
    return -1;
}
