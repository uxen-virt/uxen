/*
 * Copyright 2014-2017, Bromium, Inc.
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

#if defined(_WIN32)
PCSTR WSAAPI inet_ntop (INT Family, PVOID pAddr, PSTR pStringBuf, size_t StringBufSize);
#ifndef errno
#define errno ((int) WSAGetLastError())
#endif
#endif

struct nickel;
struct net_addr {
    uint16_t family;
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    };
    union {
        int64_t ts_hyb;
        uint8_t prefix_len;
    };
};


#define NETADDR_MAXSTRLEN  (16 + MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN))
#define NETADDR_CMP(n1,n2,prefix) (({                           \
            int ret = 0;                                        \
            uint32_t pm = (uint32_t) ((1ULL << (prefix)) - 1);  \
                                                                \
            if ((n1)->family != (n2)->family) {                 \
                ret = (n1)->family == AF_INET ? -1 : 1;         \
            } else if ((n1)->family == AF_INET) {               \
                if (((n1)->ipv4.s_addr & pm) ==                 \
                   ((n2)->ipv4.s_addr & pm)) {                  \
                                                                \
                    ret = 0;                                    \
                } else  {                                       \
                    ret = ((n1)->ipv4.s_addr & pm) <            \
                          ((n2)->ipv4.s_addr & pm) ? -1 : 1;    \
                }                                               \
            } else {                                            \
                ret = memcmp(&(n1)->ipv6, &(n2)->ipv6,          \
                             sizeof((n1)->ipv6));               \
            }                                                   \
            ret;                                                \
        }))

#define NETADDR_STR(_paddr, _buf, _maxlen) (({                  \
    const struct net_addr *paddr = _paddr;                      \
    char *buf = _buf;                                           \
    size_t maxlen = _maxlen;                                    \
                                                                \
    do {                                                        \
        *buf = 0;                                               \
        if (maxlen < NETADDR_MAXSTRLEN) {                       \
            warn("%s: NETADDR_STR fails as too short buffer\n", \
                 __FUNCTION__);                                 \
            break;                                              \
        }                                                       \
        buf[NETADDR_MAXSTRLEN - 1] = 0;                         \
        if (paddr->family == AF_INET) {                         \
            if (inet_ntop(AF_INET, (void *) &paddr->ipv4,       \
                          buf, NETADDR_MAXSTRLEN) == NULL) {    \
                warn("%s: inet_ntop failed %d\n",               \
                     __FUNCTION__, errno);                      \
            }                                                   \
            break;                                              \
        }                                                       \
        if (paddr->family == AF_INET6) {                        \
            if (inet_ntop(AF_INET6, (void *) &paddr->ipv6,      \
                          buf, NETADDR_MAXSTRLEN) == NULL) {    \
                warn("%s: inet_ntop failed %d\n",               \
                     __FUNCTION__, errno);                      \
            }                                                   \
            break;                                              \
        }                                                       \
        warn("%s: NETADDR_STR unknown family %d\n",             \
             __FUNCTION__, (int) paddr->family);                \
        break;                                                  \
    } while (0);                                                \
    buf;                                                        \
}))

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
