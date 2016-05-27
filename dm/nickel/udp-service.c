/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#if defined(_WIN32)
#define _POSIX
#endif
#include <time.h>
#include <sys/time.h>

#include <dm/queue2.h>
#include <dm/dict.h>
#include <dm/dict-rpc.h>
#include <dm/qemu_glue.h>

#include <dns/dns.h>
#include <socket.h>
#include <nickel.h>
#include <buff.h>
#include <log.h>
#include <service.h>

struct udps_ctx {
    CharDriverState chr;

    int closed;
    struct nickel *ni;
    struct socket *so;
    struct ni_socket *ni_opaque;
};

static void udps_init(struct nickel *ni, yajl_val config)
{
}

static void udps_close(struct udps_ctx *cx)
{
    if (cx->closed)
        return;
    if (cx->ni_opaque)
        ni_close(cx->ni_opaque);
    cx->ni_opaque = NULL;
    if (cx->so)
        so_close(cx->so);
    cx->so = NULL;
    cx->closed = 1;
}

static void udps_free(struct udps_ctx *cx)
{
    udps_close(cx);
    memset(cx, 0, sizeof(*cx));
    free(cx);
}

static int udps_chr_can_read(void *opaque)
{
    struct udps_ctx *cx = opaque;

    return ni_can_recv(cx->ni_opaque);
}

static void udps_chr_read(void *opaque, const uint8_t *buf, int size)
{
    struct udps_ctx *cx = opaque;

    ni_recv(cx->ni_opaque, buf, size);
}

static void udps_read(struct udps_ctx *cx)
{
    int len;
    size_t  r;
    bool rd = false;

    if (!cx->ni->udps_buf) {
        cx->ni->udps_buf = ni_priv_malloc(cx->ni->mtu);
        if (!cx->ni->udps_buf) {
            warnx("%s: malloc failure", __FUNCTION__);
            return;
        }
        cx->ni->udps_maxlen = cx->ni->mtu;
    }

    for (;;) {
        len = qemu_chr_can_read(&cx->chr);
        if (len < 0)
            len = 0;
        if (len > cx->ni->udps_maxlen)
            len = cx->ni->udps_maxlen;
        r = so_read(cx->so, cx->ni->udps_buf, len);
        if (r == 0 && rd)
            break;
        rd = true;
        qemu_chr_read(&cx->chr, cx->ni->udps_buf, r);
        if (len <= 0)
            break;
    }
}

static int udps_chr_write(CharDriverState *chr, const uint8_t *buf, int len_buf)
{
    struct udps_ctx *cx = chr->handler_opaque;

    so_write(cx->so, buf, len_buf);
    return 0;
}

static int udps_chr_can_write(void *opaque)
{
    struct udps_ctx *cx = opaque;

    return cx->ni->mtu;
}

static void udps_chr_event(CharDriverState *chr, int event)
{
    struct udps_ctx *cx = (struct udps_ctx *) chr->handler_opaque;

    if (event == CHR_EVENT_NI_CLOSE || event == CHR_EVENT_NI_RST) {
        udps_free(cx);
        return;
    }
}

static void udps_chr_close(CharDriverState *chr)
{
    struct udps_ctx *cx = chr->handler_opaque;

    udps_close(cx);
}

static void udps_so_event(void *opaque, uint32_t evt, int err)
{
    struct udps_ctx *cx = (struct udps_ctx *) opaque;

    if ((evt & SO_EVT_READ))
        udps_read(cx);
}

static CharDriverState *
udps_open(void *opaque, struct nickel *ni, struct sockaddr_in saddr, struct sockaddr_in daddr)
{
    CharDriverState *chr = NULL;
    struct udps_ctx *cx = NULL;
    struct net_addr a;

    NETLOG5("%s: to %s:%hu", __FUNCTION__, inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port));
    if (daddr.sin_addr.s_addr == 0 || daddr.sin_port == 0)
        goto cleanup;
    cx = calloc(1, sizeof(*cx));
    if (!cx) {
        warnx("%s: malloc failure", __FUNCTION__);
        goto cleanup;
    }
    cx->ni = ni;
    chr = &cx->chr;
    chr->refcnt = 1;
    cx->ni_opaque = opaque;

    qemu_chr_add_handlers(chr, udps_chr_can_read, udps_chr_read, NULL, cx);
    chr->chr_write = udps_chr_write;
    chr->chr_send_event = udps_chr_event;
    chr->chr_can_write = udps_chr_can_write;
    chr->chr_close = udps_chr_close;

    cx->so = so_create(ni, true, udps_so_event, cx);
    if (!cx->so)
        goto cleanup;

    memset(&a, 0, sizeof(a));
    a.family = AF_INET;
    a.ipv4 = daddr.sin_addr;
    if (so_connect(cx->so, &a, daddr.sin_port) < 0)
        goto cleanup;

    return chr;
cleanup:
    if (cx) {
        if (cx->so) {
            so_close(cx->so);
            cx->so = NULL;
        }
        free(cx);
    }
    return NULL;
}

static struct prx_fwd prx = {
    .is_udp = 1,
    .name = "udp-service",
    .init = udps_init,
    .open = udps_open,
    .accept = NULL,
};

void early_init_nickel_udp(void)
{
    _ni_prx_add_service(&prx);
}
