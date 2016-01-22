/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HTTP_CHALLENGE_AUTH_H_
#define _HTTP_CHALLENGE_AUTH_H_

#include "auth.h"

struct sspi_pkg
{
    bool initialized;
#if defined(_WIN32)
    ULONG max_token_length;
#endif
};

enum pkg_type {
    PACKAGE_TYPE_KERBEROS = 0,
    PACKAGE_TYPE_NEGOTIATE,
    PACKAGE_TYPE_NTLM,

    _NUMBER_OF_PACKAGES_
};

struct challenge_ctx_t {
    struct http_auth *auth;
    int step;
    int nr_steps;
    int custom_ntlm;
#if defined(_WIN32)
    wchar_t *target_name;
    struct sspi_ctx_t  *priv;
#elif defined(__APPLE__)
    char *target_name;
    struct ntlm_ctx_t *priv;
#endif
};

extern struct sspi_pkg pkg_ctx[_NUMBER_OF_PACKAGES_];

static inline int get_package(enum auth_enum auth_type)
{
    int rc = -1;

    switch (auth_type) {
        case AUTH_TYPE_KERBEROS:
            rc = PACKAGE_TYPE_KERBEROS;
            break;
        case AUTH_TYPE_NEGOTIATE:
            rc = PACKAGE_TYPE_NEGOTIATE;
            break;
        case AUTH_TYPE_NTLM:
            rc = PACKAGE_TYPE_NTLM;
            break;
        default:
            break;
    }

#if defined(_WIN32)
    if (rc >= 0 && !pkg_ctx[rc].initialized)
        return -1;
#endif

    return rc;
}

int challenge_auth_init(void);
int challenge_auth_init_auth(struct http_auth *auth);
void challenge_auth_exit(void);
void challenge_auth_free_auth(struct http_auth *auth);
int challenge_auth_clt(struct http_auth *auth);
void challenge_auth_reset_auth(struct http_auth *auth);
int challenge_auth_srv(struct http_auth *auth, int authorized);
int challenge_auth_srv_closing(struct http_auth *auth);
#endif
