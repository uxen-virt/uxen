/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _H_NICKEL_TCPIP_H_
#define _H_NICKEL_TCPIP_H_
#define LITTLE_ENDIAN_BITFIELD  1

#include "buff.h"

struct nickel;
struct ni_socket;
struct lava_event;

void udp_send(struct nickel *ni, struct buff *bf, struct sockaddr_in saddr, struct sockaddr_in daddr);
struct lava_event * tcpip_lava_get(struct ni_socket *so);
int tcpip_lava_submit(struct ni_socket *so);
void tcpip_event(struct ni_socket *so, int event);
void tcpip_init(struct nickel *ni);
void tcpip_post_init(struct nickel *ni);
void tcpip_exit(struct nickel *ni);
void tcpip_flush(struct nickel *ni);
void tcpip_input(struct nickel *ni, const uint8_t *buf, size_t len);
void tcpip_prepare(struct nickel *ni, int *timeout);
int tcpip_send_fin(struct ni_socket *so);
size_t tcpip_can_output(struct ni_socket *so);
void tcpip_output(struct ni_socket *so, const uint8_t *data, int size);
void tcpip_win_update(struct ni_socket *so);
void tcpip_set_chr(struct ni_socket *so, CharDriverState *chr);
void tcpip_set_sock_type(struct ni_socket *so, uint32_t typef);
struct ni_socket * tcp_listen_create(struct nickel *ni, CharDriverState *chr,
        uint32_t faddr, uint16_t fport, uint32_t gaddr, uint16_t gport, uint32_t flags);
void tcpip_close(struct ni_socket *so);
void tcpip_save(QEMUFile *f, struct nickel *ni);
int tcpip_load(QEMUFile *f, struct nickel *ni, int version_id);
struct sockaddr_in tcpip_get_gaddr(void *so_opaque);
#endif
