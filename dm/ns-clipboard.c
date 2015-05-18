/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include "char.h"
#include "ns.h"

#include "libnickel.h"
#include <hgcm-limits.h>
#include "vbox-drivers/shared-clipboard/clipboard-interface.h"

struct ns_uclip_data {
    /* ns_data must be first in the struct */
    struct ns_data ns_data;
    yajl_val config;
};

static void ns_uclip_close(CharDriverState *chr);

static int uclip_parse_config(yajl_val config)
{
    const char *policy = yajl_object_get_string(config, "policy");
    if (policy)
        uxen_clipboard_set_policy(policy);
    return 0;
}

extern bool ns_uclip_hostmsg_connection_already_opened;
static bool ns_uclip_connection_already_opened;
void ns_uclip_try_init()
{
    if (ns_uclip_hostmsg_connection_already_opened &&
        ns_uclip_connection_already_opened) {
        uxen_clipboard_init();
        uxen_clipboard_connect();
    }
}

static CharDriverState *
ns_uclip_open(void *opaque, struct nickel *ni, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr,
        yajl_val config)
{
    struct ns_uclip_data *d;
    int ret;

    if (!ns_uclip_connection_already_opened) {
        ns_uclip_connection_already_opened = true;
    } else
        /* Do not allow multiple connections */
        return NULL;

    if (uclip_parse_config(config))
        return NULL;
    debug_printf("%s service %s\n", __FUNCTION__,
                 yajl_object_get_string(config, "service"));

    d = calloc(1, sizeof(*d));
    if (d == NULL)
        return NULL;

    d->ns_data.service_close = ns_uclip_close;
    d->ns_data.net_opaque = opaque;

    ret = ns_open(&d->ns_data, ni);
    if (ret) {
        free(d);
	    return NULL;
    }
    d->ns_data.recv_len = MAX_HGCM_PACKET_SIZE;
    d->ns_data.ns_processor_func = uxen_clipboard_process_request;
    ret = ns_set_threaded_mode(&d->ns_data);
    ns_uclip_try_init();
    return d->ns_data.chr;
}

static void
ns_uclip_close(CharDriverState *chr)
{
    struct ns_uclip_data *d = chr->opaque;

    debug_printf("%s\n", __FUNCTION__);
    ns_close(&d->ns_data);
}

static struct ns_desc ns_uclip_desc = {
    .service_type = NS_SERVICE_TYPE_TCP,
    .service_name = "shared-clipboard",
    .service_open = ns_uclip_open,
    .service_close = ns_uclip_close,
};

ns_add_service(ns_uclip_desc);
