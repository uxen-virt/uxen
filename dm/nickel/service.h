/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NICKEL_SERVICE_H_
#define _NICKEL_SERVICE_H_

struct net_user;
struct socket;
struct prx_fwd {
    const char *name;

    void (*init) (struct nickel *ni, yajl_val config);
    CharDriverState *(*open)(void *, struct nickel *ni, struct sockaddr_in saddr,
            struct sockaddr_in daddr);
    CharDriverState *(*accept)(void *, struct nickel *ni, struct socket *so);
    LIST_ENTRY(prx_fwd) entry;
};

#define ni_prx_add_service(prx)                                               \
    static void __attribute__((constructor)) prx_add_service_##prx(void) {    \
        _ni_prx_add_service(&(prx));                                          \
    }

yajl_val ni_get_service_config(struct nickel *ni, const char *service_name);
bool ni_is_udp_vmfwd(struct nickel *ni, const struct in_addr dst_ip,
        const uint16_t dst_port);
bool ni_is_tcp_vmfwd(struct nickel *ni, const struct in_addr dst_ip,
        const uint16_t dst_port);
void _ni_prx_add_service(struct prx_fwd *prx);
void *
ni_vmfwd_add(struct nickel *ni, int is_udp, void *chr,
                struct in_addr host_addr, int host_port,
                struct in_addr vm_addr, int vm_port, uint64_t byte_limit);
void *
ni_vmfwd_add_service(struct nickel *ni, int is_udp,
                      CharDriverState *(*service_open)(void *,
                                                       struct net_user *,
                                                       CharDriverState **,
                                                       struct sockaddr_in,
                                                       struct sockaddr_in,
                                                       yajl_val),
                      yajl_val service_config,
                      struct in_addr host_addr, int host_port,
                      struct in_addr vm_addr, int vm_port, uint64_t byte_limit);
int ni_add_hostfwd(struct nickel *ni, int is_udp, struct in_addr host_addr,
                      int host_port, struct in_addr guest_addr, int guest_port);
int
ni_add_hostfwd_pipe(struct nickel *ni, int is_udp, const char *host_pipe, struct in_addr host_addr,
     int host_port, struct in_addr guest_addr, int guest_port, int close_reconnect, int close_on_retry);
int ni_proxyfwd(struct nickel *ni, const yajl_val object);
int ni_proxyfwd_add(struct nickel *ni, const char *name);
CharDriverState *
ni_udp_vmfwd_open(struct nickel *ni, struct sockaddr_in saddr,
        struct sockaddr_in daddr, void *opaque);
CharDriverState *
ni_tcp_vmfwd_open(struct nickel *ni, struct sockaddr_in saddr, struct sockaddr_in daddr, void *opaque);
CharDriverState *
ni_prx_open(struct nickel *ni, struct sockaddr_in saddr, struct sockaddr_in daddr, void *opaque);

#endif
