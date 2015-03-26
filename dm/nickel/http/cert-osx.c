/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include "cert.h"

/* OSX cert support not yet */
bool hcert_enabled(void)
{
    return false;
}

struct hcert_ctx *
hcert_open_chain(size_t ncerts)
{
    return NULL;
}

int hcert_add_cert(struct hcert_ctx *hcx, uint8_t *cert, size_t len)
{
    return -1;
}

int hcert_get_chain(struct hcert_ctx *hcx, const char *hostname, uint32_t *err_code,
        uint32_t *policy_code, hcert_chain_ctx *chain_context_out,
        enum cert_type type, bool verify)
{
    return -1;
}

void hcert_free(struct hcert_ctx *hcx)
{
}
