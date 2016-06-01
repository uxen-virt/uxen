/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Michael Dales <michael@digitalflapjack.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "char.h"
#include "ns.h"
#include "timer.h"
#include "bh.h"

#include "libnickel.h"
#include "webdav.h"

struct ns_webdav_data {
    struct ns_data ns_data;
    DavClient dc;
    yajl_val config;
};

static void ns_webdav_close(CharDriverState *chr);
static void ns_webdav_chr_send_event(CharDriverState *chr, int event)
{
    ns_chr_send_event(chr, event);

    if (event != CHR_EVENT_BUFFER_CHANGE)
        return;

    /* if there's no more data, call the webdav code to fetch more data */
    struct ns_webdav_data *d = chr->opaque;
    if ((d->ns_data.send_buffer == NULL) || (d->ns_data.send_len == 0)) {
        /* no outstanding data, so give webdav a chance to send more */
        dav_write_ready(&(d->dc));
    }
}

static int
ns_webdav_chr_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    int r;
    struct ns_webdav_data *d = chr->opaque;
    r = dav_input(&d->dc, (char*)buf, len);
    if (r < 0) {
        debug_printf("%s close %p\n", __FUNCTION__, chr);
        ns_webdav_close(chr);
    }
    return len;
}

static void ns_webdav_do_write(void *opaque, const char *buf, size_t len)
{
    struct ns_webdav_data *d = opaque;
    ns_append_send_buffer(&d->ns_data, (uint8_t*)buf, len);
}

static CharDriverState *
ns_webdav_open(void *opaque, struct nickel *ni, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr,
        yajl_val config)
{
    debug_printf("%s\n", __FUNCTION__);
    struct ns_webdav_data *d;
    int ret;
    const char *host_dir;
    DavFSCallbacks callbacks = {
            ns_webdav_do_write, 
    };

    debug_printf("%s service %s\n", __FUNCTION__,
            yajl_object_get_string(config, "service"));

    host_dir = yajl_object_get_string(config, "host_dir");
    if (!host_dir) {
        return NULL;
    }

    d = calloc(1, sizeof(*d));
    if (d == NULL) {
        return NULL;
    }

    d->ns_data.net_opaque = opaque;

    ret = ns_open(&d->ns_data, ni);
    if (ret) {
        free(d);
        return NULL;
    }

    d->ns_data.service_close = ns_webdav_close;
    d->ns_data.chr->chr_write = ns_webdav_chr_write;
    d->ns_data.chr->chr_send_event = ns_webdav_chr_send_event;
    d->config = config;
    if (dav_init(&d->dc, &callbacks, host_dir, d) != 0) {
        ns_close(&d->ns_data);
        free(d);
        return NULL;
    }

    debug_printf("%s: opened %p\n", __FUNCTION__, d->ns_data.chr);
    return d->ns_data.chr;
}

static void
ns_webdav_close(CharDriverState *chr)
{
    debug_printf("%s\n", __FUNCTION__);
    struct ns_webdav_data *d = chr->opaque;

    dav_close(&(d->dc));

    ns_close(&d->ns_data);
}

static struct ns_desc ns_webdav_desc = {
    .service_name = "webdav",
    .service_open = ns_webdav_open,
    .service_close = ns_webdav_close,
};

ns_add_service(ns_webdav_desc);
