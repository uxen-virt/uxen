/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HTTP_CERT__H_
#define _HTTP_CERT__H_

#if defined(_WIN32)
#define SECURITY_WIN32 1
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS 1
#include <windows.h>
#include <security.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <wincrypt.h>
#include <stdint.h>
typedef PCCERT_CHAIN_CONTEXT hcert_chain_ctx;
#else
typedef void *hcert_chain_ctx;
#endif

enum hcert_err_t {
    HCERT_OK = 0,
    HCERT_INVALID,
    HCRET_REVOKED,
    HCRET_OTHER_ERR,
};

enum cert_type {
    server,
    client
};

struct hcert_ctx;

bool hcert_enabled(void);
struct hcert_ctx * hcert_open_chain(size_t ncerts);
int hcert_add_cert(struct hcert_ctx *hcx, uint8_t *cert, size_t len);
int hcert_get_chain(struct hcert_ctx *hcx, const char *hostname, uint32_t *err_code, uint32_t *policy_code, hcert_chain_ctx *chain_context_out, enum cert_type type, bool verify);
void hcert_free(struct hcert_ctx *hcx);
#endif
