/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NTLM_H_
#define _NTLM_H_

struct challenge_ctx_t;
struct ntlm_ctx_t;

int ntlm_osx_init();
void ntlm_osx_exit();

void ntlm_osx_free_auth(struct ntlm_ctx_t *ntlm);
struct ntlm_ctx_t * ntlm_osx_init_auth(struct challenge_ctx_t *cctx);
void ntlm_osx_reset_auth(struct ntlm_ctx_t *ntlm);
int ntlm_osx_clt(struct ntlm_ctx_t *ntlm, bool force_saved_auth,
        unsigned char *buf_in_data, size_t buf_in_data_len,
        unsigned char **buf_out_data, size_t *buf_out_data_len,
        int *logon_required, int *needs_reconnect);

#endif /*_NTLM_H_*/
