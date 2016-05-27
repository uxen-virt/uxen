/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include "qemu_glue.h"
#include "dict.h"
#include "char.h"
#include "ns.h"

#include "libnickel.h"
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#endif

struct ns_fwd_data {
    CharDriverState chr; /* needs to be the first */
    struct nickel *ni;
    void *net_opaque;
    void *opaque;
    int s;
    int closing;
};

static void ns_fwd_event(CharDriverState *chr, int event);

static int
ns_fwd_chr_write(CharDriverState *chr, const uint8_t *buf, int blen)
{
    struct ns_fwd_data *d = chr->opaque;
    int ret;

    ret = send(d->s, (char *)buf, blen, 0);

    return ret > 0 ? 0 : ret;
}

static int
ns_fwd_chr_can_read(void *opaque)
{
    struct ns_fwd_data *d = opaque;

    return ni_can_recv(d->net_opaque);
}

static void
ns_fwd_chr_read(void *opaque, const uint8_t *buf, int size)
{
    struct ns_fwd_data *d = opaque;

    ni_recv(d->net_opaque, buf, size);
}

static void
ns_fwd_chr_close(CharDriverState *chr)
{
    struct ns_fwd_data *d = (struct ns_fwd_data *)chr->opaque;

    if (d->s != -1)
        closesocket(d->s);
    d->s = -1;
    if (!d->closing) {
        ni_close(d->net_opaque);
        d->net_opaque = NULL;
    }
    d->closing = 1;
}

static CharDriverState *
ns_fwd_open(void *opaque, struct nickel *ni, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr,
        yajl_val config)
{
    struct ns_fwd_data *d = NULL;
    struct sockaddr_in addr;
    const char *remote_addr;
    int remote_port;

    d = calloc(1, sizeof(*d));
    if (!d)
        return NULL;

    d->s = -1;
    remote_addr = yajl_object_get_string(config, "remote_addr");
    if (!remote_addr) {
        debug_printf("%s: invalid 'remote_addr' param\n", __FUNCTION__);

        goto cleanup;
    }
    remote_port = yajl_object_get_integer_default(config, "remote_port", 0);
    if (!remote_port) {
        debug_printf("%s: invalid 'remote_port' param\n", __FUNCTION__);
        goto cleanup;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(remote_port);
    if (!inet_aton(remote_addr, &addr.sin_addr)) {
        debug_printf("%s: 'remote_addr' needs to be a valid IPv4 address\n", __FUNCTION__);
        goto cleanup;
    }

    d->s = qemu_socket(addr.sin_family, SOCK_DGRAM, 0);
    if (d->s == -1) {
        debug_printf("%s: socket error %d\n", __FUNCTION__, (int) errno);
        goto cleanup;
    }

    {
#ifdef FIONBIO
#ifdef _WIN32
        unsigned long opt = 1;
#else
        int opt = 1;
#endif

        ioctlsocket(d->s, FIONBIO, &opt);
#else
        int opt;

        opt = fcntl(d->s, F_GETFL, 0);
        opt |= O_NONBLOCK;
        fcntl(d->s, F_SETFL, opt);
#endif
    }

    if (connect(d->s, (const struct sockaddr *) &addr, sizeof(addr)) != 0) {
        debug_printf("%s: connect error %d\n", __FUNCTION__, (int) errno);
        goto cleanup;
    }

    d->ni = ni;
    d->net_opaque = opaque;
    d->chr.opaque = d;
    d->chr.refcnt = 1;
    qemu_chr_add_handlers(&d->chr, ns_fwd_chr_can_read, ns_fwd_chr_read, NULL, d);
    d->chr.chr_write = ns_fwd_chr_write;
    d->chr.chr_close = ns_fwd_chr_close;
    d->chr.chr_send_event = ns_fwd_event;

    return &d->chr;
cleanup:
    if (d) {
        if (d->s != -1)
            closesocket(d->s);
        free(d);
    }
    return NULL;
}

static void
ns_fwd_event(CharDriverState *chr, int event)
{

    if (event == CHR_EVENT_NI_CLOSE || event == CHR_EVENT_NI_RST) {
        qemu_chr_close(chr);
        return;
    }
}

static struct ns_desc ns_fwd_desc = {
    .service_type = NS_SERVICE_TYPE_UDP,
    .service_name = "udp-forward",
    .service_open = ns_fwd_open,
};

void early_init_ns_fwd(void)
{
    _ns_add_service(&ns_fwd_desc);
}
