/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include "char.h"
#include "console.h"
#include "ns.h"

#include "net-user.h"

/*
 * Be careful to choose source port numbers that are outside of an ephemeral
 * port range. Typically: [5001-49151]
 */
static const struct {
    const char *log_prefix;
    int source_port;
} logging_ports[] = {
    { "uxenevent",  5001 },
};

struct ns_logging_data {
    struct ns_data ns_data;
    const char *log_prefix;
    yajl_val config;
};

static void ns_logging_close(CharDriverState *chr);

static int
ns_logging_chr_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    struct ns_logging_data *d = chr->opaque;
    char *str;

    str = malloc(len + 1);
    if (!str)
        return len;

    memcpy(str, buf, len);
    str[len] = 0;
    debug_printf("%s: %s\n", d->log_prefix, str);
    free(str);

    return len;
}

static CharDriverState *
ns_logging_open(void *opaque, struct net_user *nu, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr,
        yajl_val config)
{
    struct ns_logging_data *d;
    int ret;
    int i;

    for (i = 0; i < ARRAY_SIZE(logging_ports); i++) {
        if (logging_ports[i].source_port == ntohs(saddr.sin_port))
            break;
    }
    if (i == ARRAY_SIZE(logging_ports)) {
        debug_printf("%s: bad source port %d\n", __FUNCTION__,
                     ntohs(saddr.sin_port));
        return NULL;
    }

    d = calloc(1, sizeof(*d));
    if (d == NULL)
        return NULL;

    d->ns_data.service_close = ns_logging_close;
    d->ns_data.net_opaque = opaque;

    ret = ns_open(&d->ns_data, nu);
    if (ret) {
        free(d);
	return NULL;
    }

    d->ns_data.chr->chr_write = ns_logging_chr_write;
    d->config = config;
    d->log_prefix = logging_ports[i].log_prefix;

    return d->ns_data.chr;
}

static void
ns_logging_close(CharDriverState *chr)
{
    struct ns_logging_data *d = chr->opaque;

    ns_close(&d->ns_data);
}

static struct ns_desc ns_logging_desc = {
    .service_type = NS_SERVICE_TYPE_UDP,
    .service_name = "logging",
    .service_open = ns_logging_open,
    .service_close = ns_logging_close,
};

ns_add_service(ns_logging_desc);
