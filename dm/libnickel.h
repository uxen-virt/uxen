/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _LIBNICKEL_H_
#define _LIBNICKEL_H_

#include "qemu_glue.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#include <in6addr.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

struct net_user;
struct nickel;

void ni_init(void);
void ni_exit(void);
void ni_start(void);
void ni_suspend_flush(void);
#if defined(NICKEL_THREADED)
void ni_thread_start(void);
#endif
void ni_prepare(struct nickel *ni, int *timieout);
int net_init_nickel(QemuOpts *opts,
                   Monitor *mon,
                   const char *name,
                   VLANState *vlan);

extern int pcap_user_enable;
void ni_pcap_usertrig(void);
int ni_pcap_global_dump(void *opaque, const char *id, const char *opt,
                      dict d, void *command_opaque);
void ni_stats(unsigned int *n_nav_sockets, unsigned int *n_conn_ever,
        unsigned int *ms_last_packet, unsigned int *bytes_rx, unsigned int *bytes_tx,
        unsigned int *bytes_nav_rx, unsigned int *bytes_nav_tx);

size_t ni_can_recv(void *opaque);
void ni_buf_change(void *opaque);
void ni_recv(void *opaque, const uint8_t *buf, int size);
void ni_send(void *opaque);
void ni_close(void *opaque);
int ni_schedule_bh(struct nickel *ni, void (*async_cb)(void *), void (*finish_cb)(void *),
        void *opaque);
int ni_schedule_bh_permanent(struct nickel *ni, void (*cb)(void *), void *opaque);
int ni_rpc_ac_event(void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque);
int ni_rpc_http_event(void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque);
void fd_nonblock(int fd);
#endif /* _NICKEL_H_ */
