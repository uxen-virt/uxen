/*
 * Copyright 2014-2016, Bromium, Inc.
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

#if defined(_WIN32)
#include <windows.h>
#define SECURITY_WIN32 1
#include <security.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>
#endif

#define BASIC_PREFIX "Basic "
#define CRED_TMP_PREFIX "tmp_"
#define START_REALM "realm=\""

#if defined(_WIN32)
#define TARGET_TEMPLATE "Microsoft_WinInet_%s:%d/%s"
#endif

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
#if defined(_WIN32)
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
#elif defined(__APPLE__)
    char *encoded_credentials = NULL;
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
    char *credentials = NULL;

    NETLOG3("Attempting to get proxy creds for %s:%d", server, port);

    if (!server)
        goto out;

    res = SecKeychainFindInternetPassword(NULL,
                                          strlen(server),
                                          server,
                                          0, NULL,
                                          0, NULL,
                                          0, NULL,
                                          port,
                                          kSecProtocolTypeAny,
                                          kSecAuthenticationTypeAny,
                                          &returnpasswordLength,
                                          (void**)&passwordBuffer,
                                          &itemref);
    if (res != noErr) {
        NETLOG3("%s: SecKeychainFindInternetPassword failed, error = %d", __FUNCTION__, (int)res);
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
        goto out;
    }

    SecKeychainAttribute accountNameAttribute = attributeList->attr[0];
    account = calloc(accountNameAttribute.length + 1, 1);
    if (!account)
        goto mem_err;
    memcpy(account, accountNameAttribute.data, accountNameAttribute.length);

    password = calloc(returnpasswordLength + 1, 1);
    if (!password)
        goto mem_err;
    memcpy(password, passwordBuffer, returnpasswordLength);

    if (asprintf(&credentials, "%s:%s", account, password) < 0) {
        goto mem_err;
    }

    encoded_credentials = base64_encode((const unsigned char *)credentials, strlen(credentials));
    if (!encoded_credentials)
        goto mem_err;

out:
    if (passwordBuffer)
        SecKeychainItemFreeContent(NULL, passwordBuffer);
    if (itemref)
        CFRelease(itemref);
    if (attributeList)
        SecKeychainItemFreeAttributesAndData(attributeList, NULL);
    if (credentials) {
        bzero(credentials, strlen(credentials));
        free(credentials);
    }
    if (account)
        free(account);
    if (password) {
        bzero(password, returnpasswordLength);
        free(password);
    }

    return encoded_credentials;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    goto out;
#endif
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
#if defined(_WIN32)
        SecureZeroMemory(encoded_credentials, cred_len);
#else
        bzero(encoded_credentials, cred_len);
#endif
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
