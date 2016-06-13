/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SOCKETS_H_
#define _SOCKETS_H_

#include "os.h"

#ifdef _WIN32
# include <ws2tcpip.h>
#endif

int socket_init(void);
void socket_cleanup(void);

int unix_listen(const char *path, char *ostr, int olen);
int unix_connect(const char *path);

int inet_listen(const char *str, char *ostr, int olen,
                int socktype, int port_offset);
int inet_connect(const char *str, int socktype);

void socket_set_block(int fd);
void socket_set_nonblock(int fd);

#endif  /* _SOCKETS_H_ */
