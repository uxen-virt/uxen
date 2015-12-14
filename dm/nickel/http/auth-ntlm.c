/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/base64.h>
#include <log.h>
#include <buff.h>
#include "ntlm.h"
#include "strings.h"
#include "proxy.h"
#include "parser.h"
#include "auth.h"
#include "auth-ntlm.h"
#include <inttypes.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

#define PREFIX "NTLM "

struct ntlm_ctx_t {
    int step;
    int nr_steps;
    char *target_name;
    struct ntlm_ctx *ntlm_ctx;
};

int get_ntlm_context(char* server, struct ntlm_ctx *ntlm_ctx)
{
    int ret = 0;
    UInt32 returnpasswordLength = 0;
    char *passwordBuffer = NULL;
    SecKeychainItemRef itemref = NULL;
    UInt32 attributeTags[1];
    UInt32 formatConstants[1];
    SecKeychainAttributeInfo attributeInfo;
    SecKeychainAttributeList *attributeList = NULL;
    OSStatus res = 0;
    char *account = NULL;
    char *password = NULL;
    char *passwordWide = NULL;

    NETLOG3("Attempting to get proxy creds for %s", server);

    if (!server)
        goto out;

    res = SecKeychainFindInternetPassword(NULL,
                                          strlen(server),
                                          server,
                                          0, NULL,
                                          0, NULL,
                                          0, NULL,
                                          0,
                                          kSecProtocolTypeAny,
                                          kSecAuthenticationTypeAny,
                                          &returnpasswordLength,
                                          (void**)&passwordBuffer,
                                          &itemref);
    if (res != noErr) {
        NETLOG3("%s: SecKeychainFindInternetPassword failed, error = %d", __FUNCTION__, (int)res);
        ret = 1;
        goto out;
    }

    *attributeTags = kSecAccountItemAttr;
    *formatConstants = CSSM_DB_ATTRIBUTE_FORMAT_STRING;
    attributeInfo.count = 1;
    attributeInfo.tag = attributeTags;
    attributeInfo.format = formatConstants;
    res = SecKeychainItemCopyAttributesAndData(itemref, &attributeInfo, NULL, &attributeList, 0, NULL);

    if (res != noErr) {
        NETLOG3("%s: SecKeychainItemCopyAttributesAndData failed, error = %d", __FUNCTION__, (int)res);
        ret = 1;
        goto out;
    }

    SecKeychainAttribute accountNameAttribute = attributeList->attr[0];
    account = calloc(accountNameAttribute.length + 1, 1);
    if (!account)
        goto mem_err;
    memcpy(account, accountNameAttribute.data, accountNameAttribute.length);

    // In the keychain, account is "DOMAIN\username", which we need to split
    int delimiterPosition = -1;
    for (int i = 0; i < accountNameAttribute.length; i++) {
        if (account[i] == '\\') {
            delimiterPosition = i;
            break;
        }
    }

    int usernameLength = accountNameAttribute.length - (1 + delimiterPosition);
    if (usernameLength <= 0) {
        NETLOG3("%s: credentials for %s had no domain specified", __FUNCTION__, server);
        res = 1;
        goto out;
    }

    if (delimiterPosition <= 0) {
        ntlm_ctx->domain = NULL;
        ntlm_ctx->w_domain = NULL;
        ntlm_ctx->w_domain_len = 0;
        NETLOG5("Domain for NTLM not provided");
    } else {
        ntlm_ctx->domain = calloc(delimiterPosition + 1, 1);
        if (!ntlm_ctx->domain)
            goto mem_err;
        memcpy(ntlm_ctx->domain, account, delimiterPosition);
        ntlm_ctx->w_domain = calloc((delimiterPosition + 1) * 2, 1);
        if (!ntlm_ctx->w_domain)
            goto mem_err;
        for (int i = 0; i < delimiterPosition; i++)
            ntlm_ctx->w_domain[i * 2] = ntlm_ctx->domain[i];
        ntlm_ctx->w_domain_len = delimiterPosition * 2;
        NETLOG5("Domain for NTLM: %s", ntlm_ctx->domain);
    }

    ntlm_ctx->username = calloc(usernameLength + 1, 1);
    if (!ntlm_ctx->username)
        goto mem_err;
    memcpy(ntlm_ctx->username, account + delimiterPosition + 1, usernameLength);
    ntlm_ctx->w_username = calloc((usernameLength + 1) * 2, 1);
    if (!ntlm_ctx->w_username)
        goto mem_err;
    for (int i = 0; i < usernameLength; i++)
        ntlm_ctx->w_username[i * 2] = ntlm_ctx->username[i];
    ntlm_ctx->w_username_len = usernameLength * 2;
    NETLOG5("username for NTLM: %s", ntlm_ctx->username);

    password = calloc(returnpasswordLength + 1, 1);
    if (!password)
        goto mem_err;
    memcpy(password, passwordBuffer, returnpasswordLength);

    passwordWide = calloc((returnpasswordLength + 1) * 2, 1);
    if (!passwordWide)
        goto mem_err;
    for (int i = 0; i < returnpasswordLength; i++)
        passwordWide[i * 2] = password[i];

    ntlm_ctx->ntlm_hash = calloc(1, 32 + 2);
    if (!ntlm_ctx->ntlm_hash)
        goto mem_err;
    CC_MD4(passwordWide, returnpasswordLength * 2, ntlm_ctx->ntlm_hash);

    if (0 != gethostname((char*)ntlm_ctx->hostname, 255)) {
        int e = errno;
        NETLOG("%s: Failed to get hostname %d %s", __FUNCTION__, e, strerror(e));
        ret = 1;
        goto out;
    }

out:
    if (passwordBuffer)
        SecKeychainItemFreeContent(NULL, passwordBuffer);
    if (itemref)
        CFRelease(itemref);
    if (attributeList)
        SecKeychainItemFreeAttributesAndData(attributeList, NULL);
    if (account)
        free(account);
    if (passwordWide) {
        bzero(passwordWide, returnpasswordLength * 2);
        free(passwordWide);
    }
    if (password) {
        bzero(password, returnpasswordLength);
        free(password);
    }

    return ret;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    ret = 1;
    goto out;
}

int ntlm_init_auth(struct http_auth *auth)
{
    int ret = -1;
    struct ntlm_ctx_t *ntlm;

    assert(!auth->auth_opaque);
    ntlm = calloc(1, sizeof(*ntlm));
    if (!ntlm)
        goto out;
    ntlm->nr_steps = 2;

    struct ntlm_ctx *context = calloc(1, sizeof(struct ntlm_ctx));
    if (!context) {
        free(ntlm);
        goto out;
    }
    ntlm->ntlm_ctx = context;

    auth->auth_opaque = ntlm;
    ret = 0;
out:
    return ret;
}

void ntlm_free_auth(struct http_auth *auth)
{
    struct ntlm_ctx_t *ntlm = auth->auth_opaque;

    if (!ntlm)
        return;

    AUXL4("");
    ntlm_reset_auth(auth);

    free(ntlm->ntlm_ctx->username);
    free(ntlm->ntlm_ctx->domain);
    free(ntlm->ntlm_ctx->w_username);
    free(ntlm->ntlm_ctx->w_domain);
    free(ntlm->ntlm_ctx->ntlm_hash);
    free(ntlm->ntlm_ctx);
    free(ntlm->target_name);
    free(ntlm);
    auth->auth_opaque = NULL;
}

void ntlm_reset_auth(struct http_auth *auth)
{
    struct ntlm_ctx_t *ntlm = auth->auth_opaque;

    if (!ntlm)
        return;

    AUXL4("");
    ntlm->step = 0;

    if (ntlm->ntlm_ctx) {
        free(ntlm->ntlm_ctx->ntlm_hash);
        free(ntlm->ntlm_ctx);
    }
    struct ntlm_ctx *context = calloc(1, sizeof(struct ntlm_ctx));
    ntlm->ntlm_ctx = context;
}

int ntlm_clt(struct http_auth *auth)
{
    int ret = -1;
    const char *proxy_name;
    struct ntlm_ctx_t *ntlm = NULL;
    unsigned char *buf_in_data = NULL;
    size_t buf_in_data_len = 0;
    unsigned char *buf_out_data = NULL;
    size_t buf_out_data_len = 0;
    char *buf_encoded = NULL;
    size_t buf_encoded_len = 0;

    if (!auth)
        goto out;

    assert(auth->proxy);
    proxy_name = auth->proxy->name;

    ntlm = auth->auth_opaque;
    assert(ntlm);

    ntlm->step++;
    auth->last_step = ntlm->step == ntlm->nr_steps;
    AUXL5("step = %d, last_step = %d", ntlm->step, auth->last_step);

    if (auth->authorized) {
        auth->last_step = 1;
        ret = 0;
        goto out;
    }

    if (ntlm->step > ntlm->nr_steps) {
        NETLOG("%s: failing, nr_steps exceeded", __FUNCTION__);
        auth->logon_required = 1;
        ret = 0;
        goto out;
    }

    if (!ntlm->target_name) {

        if (!proxy_name) {
            NETLOG("%s: bug, no proxy_name", __FUNCTION__);
            goto out;
        }
        if (ntlm->target_name) {
            free(ntlm->target_name);
            ntlm->target_name = NULL;
        }

        NETLOG5("target name: %s", proxy_name);
        ntlm->target_name = strdup(proxy_name);
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

    if (0 != get_ntlm_context(ntlm->target_name, ntlm->ntlm_ctx)) {
        NETLOG("%s: No credentials found for %s", __FUNCTION__, ntlm->target_name);
        auth->logon_required = 1;
        ret = 0;
        goto out;
    }

    auth->logon_required = 0;

    if (ntlm_get_next_token(ntlm->ntlm_ctx, buf_in_data, buf_in_data_len,
                &buf_out_data, &buf_out_data_len) < 0) {
        NETLOG("%s: ERROR on ntlm_get_next_token", __FUNCTION__);
        goto out;
    }

    AUXL4("(2) step = %d, last_step = %d", ntlm->step, auth->last_step);
    if (!buf_out_data || !buf_out_data_len) {
        NETLOG("%s: ERROR! no buf_out_data", __FUNCTION__);
        goto out;
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
                strlen(PREFIX) + buf_encoded_len))
        goto mem_err;
    if (buff_append(auth->auth_header->headers[auth->auth_header->crt_header].value,
                PREFIX, strlen(PREFIX)) < 0)
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

int ntlm_srv(struct http_auth *auth, int authorized)
{
    struct ntlm_ctx_t *ntlm = auth->auth_opaque;

    if (authorized)
        goto out;

    AUXL4("last_step = %d", auth->last_step);
    if (auth->last_step) {
        bool prompt_u = ntlm;

        if (prompt_u && auth->was_authorized) {
            AUXL2("last sspi step but was once authorized, retry the request.");
            auth->needs_restart = 1;
            goto out;
        }

        AUXL2("last sspi step but not authorized. %s",
            prompt_u ?  "Prompt for username/pass" : "CUSTOM CREDENTIALS USED. Giving Up.");
        if (prompt_u)
            auth->logon_required = 1;
    }

out:
    return 0;
}


int ntlm_srv_closing(struct http_auth *auth)
{
    struct ntlm_ctx_t *ntlm = auth->auth_opaque;

    if (!ntlm || ntlm->step == 0 || auth->needs_reconnect || auth->logon_required)
        return 0;

    /* if closes in the middle of auth what can we do ? */
    NETLOG("%s: h:%"PRIxPTR" unexpected proxy conn close", __FUNCTION__, (uintptr_t) auth->hp);
    return -1;
}
