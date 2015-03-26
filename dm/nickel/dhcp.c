/*
 * QEMU BOOTP/DHCP server
 *
 * Copyright (c) 2004 Fabrice Bellard
 *  modified paulian.marinca@bromium.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/*
 * uXen changes:
 *
 * Copyright 2014-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* XXX: only DHCP is supported */

#include <dm/config.h>
#include "proto.h"
#include "buff.h"
#include "nickel.h"
#include "tcpip.h"
#include "dhcp.h"
#include "log.h"

#define BOOTP_SERVER    67
#define BOOTP_CLIENT    68

#define BOOTP_REQUEST   1
#define BOOTP_REPLY     2
#define DHCPDISCOVER            1
#define DHCPREQUEST             3
#define RFC1533_GATEWAY         3
#define RFC2132_LEASE_TIME      51
#define RFC1533_COOKIE          99, 130, 83, 99
#define RFC1533_PAD             0
#define RFC1533_END             255
#define RFC2132_MSG_TYPE        53
#define RFC2132_REQ_ADDR        50
#define RFC2132_SRV_ID          54
#define RFC1533_NETMASK         1
#define RFC1533_DNS             6

#define DHCPOFFER               2
#define DHCPACK                 5
#define LEASE_TIME (24 * 3600)

#define DHCP_OPT_LEN            312
struct bootp_t {
    uint8_t bp_op;
    uint8_t bp_htype;
    uint8_t bp_hlen;
    uint8_t bp_hops;
    uint32_t bp_xid;
    uint16_t bp_secs;
    uint16_t unused;
    struct in_addr bp_ciaddr;
    struct in_addr bp_yiaddr;
    struct in_addr bp_siaddr;
    struct in_addr bp_giaddr;
    uint8_t bp_hwaddr[16];
    uint8_t bp_sname[64];
    uint8_t bp_file[128];
    uint8_t bp_vend[DHCP_OPT_LEN];
} __attribute__((packed));

static const uint8_t rfc1533_cookie[] = { RFC1533_COOKIE };

static void
dhcp_decode(const struct bootp_t *bp, int *pmsg_type, struct in_addr *preq_addr,
        int plen)
{
    const uint8_t *p, *p_end;
    int len, tag;

    *pmsg_type = 0;
    preq_addr->s_addr = htonl(0L);

    p = bp->bp_vend;
    p_end = ((const uint8_t * )bp) + plen;
    if (memcmp(p, rfc1533_cookie, 4) != 0)
        return;
    p += 4;
    while (p < p_end) {
        tag = p[0];
        if (tag == RFC1533_PAD)
            p++;
        else if (tag == RFC1533_END)
            break;
        else {
            p++;
            if (p >= p_end)
                break;
            len = *p++;

            switch(tag) {
            case RFC2132_MSG_TYPE:
                if (len >= 1)
                    *pmsg_type = p[0];
                break;
            case RFC2132_REQ_ADDR:
                if (len >= 4)
                    memcpy(&(preq_addr->s_addr), p, 4);
                break;
            default:
                break;
            }
            p += len;
        }
    }
    if (*pmsg_type == DHCPREQUEST && preq_addr->s_addr == htonl(0L) &&
        bp->bp_ciaddr.s_addr)
        memcpy(&(preq_addr->s_addr), &bp->bp_ciaddr, 4);
}

void dhcp_input(struct nickel *ni, const uint8_t *pkt, size_t len,
        uint32_t _saddr, uint32_t _daddr)
{
    struct buff *bf = NULL;
    struct bootp_t *bp;
    struct bootp_t *rbp;
    struct sockaddr_in saddr, daddr;
    struct in_addr preq_addr;
    int dhcp_msg_type, val;
    uint8_t *q;
    uint8_t client_ethaddr[ETH_ALEN];
    size_t l;

    pkt += sizeof(struct udp);
    len -= sizeof(struct udp);

    bp = (struct bootp_t *) pkt;
    NETLOG("%s: len %d sizeof(*bp) %d", __FUNCTION__, (int) len, (int) sizeof(*bp));
    if (len < (((uint8_t *)bp->bp_vend) - (uint8_t *)bp) + 4)
        return;
    NETLOG("%s: BOOTP_REQUEST %d bp->bp_op %d", __FUNCTION__, (int) BOOTP_REQUEST,
            (int) bp->bp_op);
    if (bp->bp_op != BOOTP_REQUEST)
        return;

    /* extract exact DHCP msg type */
    dhcp_decode(bp, &dhcp_msg_type, &preq_addr, len);

    if (dhcp_msg_type == 0)
        dhcp_msg_type = DHCPREQUEST; /* Force reply for old BOOTP clients */

    NETLOG("%s: dhcp_msg_type %d", __FUNCTION__, (int) dhcp_msg_type);
    if (dhcp_msg_type != DHCPDISCOVER && dhcp_msg_type != DHCPREQUEST)
        return;

    /* Get client's hardware address from bootp request */
    memcpy(client_ethaddr, bp->bp_hwaddr, ETH_ALEN);
    l = ETH_HLEN + sizeof(struct ip) + sizeof(struct udp) +
        sizeof(struct bootp_t);
    bf = ni_netbuff(ni, l);
    if (!bf)
        return;
    bf->opaque = ni;
    bf->len = l;
    rbp = (struct bootp_t *) (bf->m + ETH_HLEN + sizeof(struct ip) +
            sizeof(struct udp));

    saddr.sin_addr = ni->host_addr;
    daddr.sin_addr = ni->dhcp_startaddr;
    saddr.sin_port = htons(BOOTP_SERVER);
    daddr.sin_port = htons(BOOTP_CLIENT);

    rbp->bp_op = BOOTP_REPLY;
    rbp->bp_xid = bp->bp_xid;
    rbp->bp_htype = 1;
    rbp->bp_hlen = 6;
    memcpy(rbp->bp_hwaddr, bp->bp_hwaddr, ETH_ALEN);

    rbp->bp_yiaddr = daddr.sin_addr; /* Client IP address */
    rbp->bp_siaddr = saddr.sin_addr; /* Server IP address */

    q = rbp->bp_vend;
    memcpy(q, rfc1533_cookie, 4);
    q += 4;

    if (dhcp_msg_type == DHCPDISCOVER) {
        *q++ = RFC2132_MSG_TYPE;
        *q++ = 1;
        *q++ = DHCPOFFER;
    } else /* DHCPREQUEST */ {
        *q++ = RFC2132_MSG_TYPE;
        *q++ = 1;
        *q++ = DHCPACK;
    }

    *q++ = RFC2132_SRV_ID;
    *q++ = 4;
    memcpy(q, &saddr.sin_addr, 4);
    q += 4;

    *q++ = RFC1533_NETMASK;
    *q++ = 4;
    memcpy(q, &ni->network_mask, 4);
    q += 4;

    *q++ = RFC1533_GATEWAY;
    *q++ = 4;
    memcpy(q, &saddr.sin_addr, 4);
    q += 4;

    *q++ = RFC1533_DNS;
    *q++ = 4;
    memcpy(q, &ni->host_addr, 4);
    q += 4;

    *q++ = RFC2132_LEASE_TIME;
    *q++ = 4;
    val = htonl(LEASE_TIME);
    memcpy(q, &val, 4);
    q += 4;

    *q = RFC1533_END;

    daddr.sin_addr.s_addr = 0xffffffffu;

    udp_send(ni, bf, saddr, daddr);
}

