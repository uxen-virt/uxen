/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SSPI_H_
#define _SSPI_H_

struct http_auth;
struct http_header;

int sspi_lib_init();
void sspi_lib_exit();

void sspi_free_auth(struct http_auth *auth);
int sspi_init_auth(struct http_auth *auth);
bool sspi_islast_step(struct http_auth *auth);
void sspi_reset_auth(struct http_auth *auth);
int sspi_clt(struct http_auth *auth);
int sspi_srv(struct http_auth *auth, int authorized);
int sspi_srv_closing(struct http_auth *auth);

#endif /*_SSPI_H_*/
