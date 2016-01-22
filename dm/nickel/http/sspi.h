/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SSPI_H_
#define _SSPI_H_

struct challenge_ctx_t;

int sspi_init();
void sspi_exit();

void sspi_free_auth(struct sspi_ctx_t *sspi);
struct sspi_ctx_t * sspi_init_auth(struct challenge_ctx_t *cctx);
void sspi_reset_auth(struct sspi_ctx_t *sspi);
int sspi_clt(struct sspi_ctx_t *sspi, bool force_saved_auth,
        unsigned char *buf_in_data, size_t buf_in_data_len,
        unsigned char **buf_out_data, size_t *buf_out_data_len,
        int *logon_required, int *needs_reconnect);

#endif /*_SSPI_H_*/
