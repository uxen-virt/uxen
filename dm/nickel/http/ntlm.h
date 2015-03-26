/*
 * Copyright 2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HTTP_NTLM__H_
#define _HTTP_NTLM__H_

struct ntlm_ctx {
    uint8_t *ntlm_hash;
    size_t ntlm_hash_len;

    uint8_t *domain;
    uint8_t *username;

    uint8_t hostname[256];

    uint8_t *w_domain;
    size_t   w_domain_len;
    uint8_t *w_username;
    size_t   w_username_len;

    int ok;
};

int ntlm_get_next_token(struct ntlm_ctx *ntlm, uint8_t *in_token, size_t in_len,
        uint8_t **out_token, size_t *out_len);
#endif
