/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NPR_DNS_H_
#define _NPR_DNS_H_

#ifdef _WIN32
#include <ws2tcpip.h>
#include <in6addr.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

struct nickel;
struct net_addr {
    uint16_t family;
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    };
    int64_t ts_hyb;
};

struct dns_response {
    const char *cname;
    char *canon_name;
    struct net_addr *a;
    int err;
    int denied;
    int64_t cost_ms;
};

bool dns_is_nickel_domain_name(const char *domain);
void dns_http_proxy_enabled(void);
struct dns_response dns_lookup(const char *dname);
struct dns_response dns_lookup_containment(struct nickel *ni, const char *name, int proxy_on);
void dns_hyb_update(struct net_addr *a, struct net_addr cn_addr);
const struct net_addr * dns_hyb_addr(struct net_addr *a);
struct net_addr * dns_ips_dup(const struct net_addr *a);
void dns_response_free(struct dns_response *resp);

#endif
