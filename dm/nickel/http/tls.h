/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NP_TLS__H_
#define _NP_TLS__H_

struct nickel;
struct buff;
struct tls_state_t;
struct http_ctx;

#define TLSR_ERROR      -1
#define TLSR_CONTINUE    0
#define TLSR_DONE_CHECK  1
#define TLSR_DONE_SKIP   2

int tls_async_cert_check(struct tls_state_t *tls, void (*cb)(void *opaque, int revoked,
            uint32_t err_code), void *opaque);
int tls_cert_send_hostsvr(struct tls_state_t *tls, const char *hostname);
bool tls_check_enabled(void);
bool tls_is_ssl(const uint8_t *b, size_t len);
struct tls_state_t * tls_new(struct nickel *ni, const struct http_ctx *hp);
void tls_free(struct tls_state_t **state);
int tls_read(struct tls_state_t *state, const uint8_t *buf, size_t len, bool is_client);
#endif
