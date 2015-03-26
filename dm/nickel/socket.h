/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NK_SOCKET_H_
#define _NK_SOCKET_H_

#include <dm/yajl.h>

struct socket;
struct buff;
struct net_addr;

#define SO_EVT_CONNECTING   0x1
#define SO_EVT_CONNECTED    0x2
#define SO_EVT_READ         0x4
#define SO_EVT_WRITE        0x8
#define SO_EVT_CLOSING      0x10

struct nickel;
typedef void (*so_event_t) (void *opaque, uint32_t evtb, int err);
typedef void (*so_accept_t) (void *opaque, struct socket *so);

void so_prepare(struct nickel *ni, int *timeout);
void so_fd_nonblock(int fd);
struct socket * so_create(struct nickel *ni, so_event_t cb, void *opaque);
void so_update_event(struct socket *so, so_event_t cb, void *opaque);
int so_init(struct nickel *ni);
int so_close(struct socket *so);
int so_closesocket(struct socket *so);
int so_connect(struct socket *so, const struct net_addr *addr, uint16_t port);
int so_connect_list(struct socket *so, const struct net_addr *a, uint16_t port);
int16_t so_getclport(struct socket *so);
struct net_addr so_get_remote_addr(struct socket *so);
uint16_t so_get_remote_port(struct socket *so);
int so_listen(struct socket *so, const struct net_addr *addr, uint16_t port, so_accept_t accept_cb,
        void *accept_opaque);
int so_reconnect(struct socket *so);
void so_buf_ready(struct socket *so);
int so_dbg(struct buff *bf, struct socket *so);
size_t so_read(struct socket *so, const uint8_t *buf, size_t len);
unsigned long so_read_available(struct socket *so);
int so_shutdown(struct socket *so);
size_t so_write(struct socket *so, const uint8_t *buf, size_t len);
#endif
