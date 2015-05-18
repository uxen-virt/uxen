/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/base64.h>
#include <inttypes.h>

#include <buff.h>
#include <log.h>
#include <nickel.h>
#include "proxy.h"
#include "parser.h"
#include "auth.h"
#include "strings.h"
#include "auth-basic.h"

#include <windows.h>
#define SECURITY_WIN32 1
#include <security.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <wincrypt.h>

#define BASIC_PREFIX "Basic "
#define CRED_TMP_PREFIX "tmp_"
#define START_REALM "realm=\""

#define TARGET_TEMPLATE "Microsoft_WinInet_%s:%d/%s"

/* Get the realm of the proxy authentication from the received challenge */
static char * get_realm(const char *proxy_challenge)
{
    char *realm = NULL;
    size_t len;

    if (!proxy_challenge)
        goto out;

    len = strlen(proxy_challenge);
    if (len < STRLEN(START_REALM) + 1)
        goto out;
    if (strncasecmp(proxy_challenge, START_REALM, STRLEN(START_REALM)) != 0)
        goto out;
    if (proxy_challenge[len - 1] != '"')
        goto out;
    len -= (STRLEN(START_REALM) + 1);
    realm = ni_priv_calloc(1, len + 1);
    if (!realm)
        goto out;
    memcpy(realm, proxy_challenge + STRLEN(START_REALM), len);
out:
    return realm;
}

/* Get the basic auth credentials for the specified realm.
 * The return value is the base64 encoded payload. */
static char *get_user_credentials(const char *server, uint16_t port, const char *realm)
{
    char *encoded_credentials = NULL;
    char *target_name = NULL;
    PCREDENTIALA pcred = NULL;
    DATA_BLOB data_in = {0};
    DATA_BLOB data_out = {0};
    DATA_BLOB optional_entropy = {0};
    char key[ARRAYSIZE(IE7_cred_key)] = IE7_cred_key;
    uint16_t temp[ARRAYSIZE(key)] = {0};
    char *credentials = NULL;
    size_t len_ascii = 0;
    BOOL ok = FALSE;
    int i = 0;

    if (!server || !realm)
        goto out;

    /* Get the target name for the basic auth credentials */
    if (asprintf(&target_name, TARGET_TEMPLATE, server, port, realm ? realm : "") < 0)
        goto mem_err;

    ok = CredReadA(target_name, CRED_TYPE_GENERIC, 0, &pcred);
    if (ok != TRUE) {
        char *tmp = NULL;

        // try the session one
        if (asprintf(&tmp, "%s%s", CRED_TMP_PREFIX, target_name) < 0)
            goto mem_err;
        ok = CredReadA(tmp, CRED_TYPE_GENERIC, 0, &pcred);
        free(tmp);
    }
    if (ok != TRUE) {
        NETLOG3("%s: CredReadA failed, error = %d", __FUNCTION__, (int) GetLastError());
        goto out;
    }

    for (i = 0; i < ARRAYSIZE(key); ++i)
        temp[i] = (uint16_t)(key[i] * 4);

    optional_entropy.pbData = (BYTE*)(&temp);
    optional_entropy.cbData = sizeof(temp);

    data_in.pbData = (BYTE*)pcred->CredentialBlob;
    data_in.cbData = pcred->CredentialBlobSize;

    if (CryptUnprotectData(&data_in, NULL, &optional_entropy, NULL, NULL, 0, &data_out) != TRUE) {
        NETLOG("%s: CryptUnprotectData error %d", __FUNCTION__, (int) GetLastError());
        goto out;
    }

    /* Extract username & password from credentials (username;password) */
    credentials = NULL;
    if (!data_out.pbData)
        goto out;
    len_ascii = strlen((const char *)data_out.pbData);

    if (len_ascii == data_out.cbData - 1) {
        credentials = strdup((const char *)data_out.pbData);
        if (!credentials)
            goto mem_err;
    } else {
        credentials = buff_ascii_encode((wchar_t*)data_out.pbData);
    }

    encoded_credentials = base64_encode((const unsigned char *)credentials, strlen(credentials));
    if (!encoded_credentials)
        goto mem_err;

out:
    if (pcred) {
        SecureZeroMemory(pcred->CredentialBlob, pcred->CredentialBlobSize);
        CredFree(pcred);
    }
    /* must free memory allocated by CredRead()! */
    if (data_out.pbData) {
        SecureZeroMemory(data_out.pbData, data_out.cbData);
        LocalFree(data_out.pbData);
    }

    /* must free memory allocated by CredRead()! */
    if (credentials) {
        SecureZeroMemory(credentials, strlen(credentials));
        free(credentials);
    }
    free(target_name);
    return encoded_credentials;

mem_err:
    warnx("%s: malloc", __FUNCTION__);
    goto out;
}

int basicauth_init_auth(struct http_auth *auth)
{
    if (!auth->prx_auth)
        return 0;

    if (!auth->proxy || auth->proxy->realm)
        return 0;

    auth->proxy->realm = get_realm(auth->prx_auth);

    return 0;
}

void basicauth_free_auth(struct http_auth *auth)
{

}

bool basicauth_islast_step(struct http_auth *auth)
{
   return true;
}

void basicauth_reset_auth(struct http_auth *auth)
{
}

int basicauth_clt(struct http_auth *auth)
{
    int ret = -1;
    char *encoded_credentials = NULL;
    size_t cred_len = 0;

    auth->last_step = 1;
    auth->authorized = 0;
    assert(auth->proxy && auth->proxy->name);
    encoded_credentials = get_user_credentials(auth->proxy->name, ntohs(auth->proxy->port),
        auth->proxy->realm);
    if (!encoded_credentials) {
        AUXL4("no credentials found, logon_required");
        auth->logon_required = 1;
        ret = 0;
        goto out;
    }
    cred_len = strlen(encoded_credentials);

    assert(auth->auth_header && !auth->auth_header->crt_header);
    if (auth->auth_header->crt_header >= NUM_HEADERS) {
        NETLOG("%s: error, max number of headers exceeded", __FUNCTION__);
        goto out;
    }

    auth->auth_header->headers[auth->auth_header->crt_header].name =
        BUFF_NEWSTR(S_PROXY_AUTH_HEADER);
    if (!auth->auth_header->headers[auth->auth_header->crt_header].name)
        goto mem_err;

    if (!buff_new_priv(&(auth->auth_header->headers[auth->auth_header->crt_header].value),
                STRLEN(BASIC_PREFIX) + cred_len + 1))
        goto mem_err;
    if (buff_append(auth->auth_header->headers[auth->auth_header->crt_header].value,
                BASIC_PREFIX, STRLEN(BASIC_PREFIX)) < 0)
        goto mem_err;
    if (buff_append(auth->auth_header->headers[auth->auth_header->crt_header].value,
                encoded_credentials, cred_len) < 0)
        goto mem_err;
    ret = 0;
out:
    if (encoded_credentials)
        SecureZeroMemory(encoded_credentials, cred_len);
    free(encoded_credentials);
    return ret;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    ret = -1;
    goto out;
}

int basicauth_srv(struct http_auth *auth, int authorized)
{
    int ret = 0;

    if (!authorized)
        auth->cred_tried = 1;

    return ret;
}

int basicauth_srv_closing(struct http_auth *auth)
{
    return 0;
}
