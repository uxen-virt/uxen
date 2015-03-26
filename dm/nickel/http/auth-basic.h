/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _BASIC_AUTH_H_
#define _BASIC_AUTH_H_

struct http_auth;
struct http_header;


void basicauth_free_auth(struct http_auth *auth);
int basicauth_init_auth(struct http_auth *auth);
bool basicauth_islast_step(struct http_auth *auth);
void basicauth_reset_auth(struct http_auth *auth);
int basicauth_clt(struct http_auth* auth);
int basicauth_srv(struct http_auth* auth, int authorized);
int basicauth_srv_closing(struct http_auth *auth);

#endif /*_BASIC_AUTH_H_*/
