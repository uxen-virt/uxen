/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NTLM_H_
#define _NTLM_H_

struct http_auth;
struct http_header;

int ntlm_lib_init();
void ntlm_lib_exit();

void ntlm_free_auth(struct http_auth *auth);
int ntlm_init_auth(struct http_auth *auth);
bool ntlm_islast_step(struct http_auth *auth);
void ntlm_reset_auth(struct http_auth *auth);
int ntlm_clt(struct http_auth *auth);
int ntlm_srv(struct http_auth *auth, int authorized);
int ntlm_srv_closing(struct http_auth *auth);

#endif /*_NTLM_H_*/
