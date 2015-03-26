/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include "char.h"
#include "net-user.h"
#include "ns.h"
#include "ioh.h"
#include "vbox-drivers/shared-clipboard/clipboard-interface.h"

struct ns_uclip_hostmsg_data {
    struct ns_data ns_data;
    HANDLE data_ready_event;
    int busy; /* if set: no response from the guest yet, potentially paused */
    char *message; /* queued message to the guest */
    int message_len;
    yajl_val config;
};

static void ns_uclip_hostmsg_close(CharDriverState *chr);
/* We have only a single instance of ns_uclip_hostmsg_data ever. Thus,
   instaead of passing it via 15 levels of vbox clipboard init functions,
   just store it in a global. */
static struct ns_uclip_hostmsg_data *g_ns_uclip_hostmsg_data;

static int
ns_uclip_hostmsg_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    struct ns_uclip_hostmsg_data *d = g_ns_uclip_hostmsg_data;
    debug_printf("ns_uclip_hostmsg_write, g_ns_uclip_hostmsg_data=%p, busy=%d\n", d,
        d?d->busy:0);
    if (d) {
        /* the peer has acknowledged the previous message... */
        critical_section_enter(&d->ns_data.lock);
        if (d->message) {
            /* ... we have a queued message, ask to send it */
            d->busy = 1;
            SetEvent(d->data_ready_event);
        }
        else
            d->busy = 0;
        critical_section_leave(&d->ns_data.lock);
    }

    return len;
}

/* uxen_clipboard_notify_guest is called from the message loop for the
   clipboard window, so asynchronously with all the rest, therefore
   the need for d->ns_data.lock */
void uxen_clipboard_notify_guest(int type, char *data, int len)
{
    char *msg;
    int *msg_int;
    int message_len = len + 2 * sizeof(int);
    struct ns_uclip_hostmsg_data *d = g_ns_uclip_hostmsg_data;
    if (!d)
        return;
    if (len < 0 || len > 65535) {
        debug_printf("impossible: uxen_clipboard_notify_guest len 0x%x, uxendm hacking itself?\n", len);
        return;
    }
    msg = malloc(message_len);
    if (!msg) {
        debug_printf("uxen_clipboard_notify_guest malloc fail len 0x%x\n", len);
        return;
    }
    msg_int = (int*)msg;
    msg_int[0] = len;
    msg_int[1] = type;
    memcpy(msg_int + 2, data, len);
    critical_section_enter(&d->ns_data.lock);
    if (d->message)
        free(d->message);
    d->message = msg;
    d->message_len = message_len;
    if (d->busy)
        /* just replace the queued message */
        debug_printf("uxen_clipboard_notify_guest busy\n");
    else {
        /* the guest confirmed the last message, so we can send the new one */
        d->busy = 1;
        SetEvent(d->data_ready_event);
    }
    critical_section_leave(&d->ns_data.lock);
}

static void
ns_uclip_hostmsg_data_ready(void *opaque)
{
    struct ns_uclip_hostmsg_data *d = opaque;
    CharDriverState *chr = d->ns_data.chr;
    int sent = 0, available;

    critical_section_enter(&d->ns_data.lock);
    if (!d->message) {
        debug_printf("ns_uclip_hostmsg_data_ready: NULL message ?\n");
        critical_section_leave(&d->ns_data.lock);
        return;
    }

    /* qemu_chr_can_read is always <= tcp mss, must loop therefore */
    do {
        available = qemu_chr_can_read(chr);
        if (!available) {
            debug_printf("ns_uclip_hostmsg_data_ready: available = 0, sent=0x%x, requested 0x%x\n", sent, d->message_len);
            break;
        }
        if (available > d->message_len - sent)
            available = d->message_len - sent;
        qemu_chr_read(chr, (uint8_t*)(d->message + sent), available);
        sent += available;
    }
    while (sent < d->message_len);

    free(d->message);
    d->message = NULL;
    d->message_len = 0;
    if (!sent)
        d->busy = 0;
    critical_section_leave(&d->ns_data.lock);
}

bool ns_uclip_hostmsg_connection_already_opened;
static CharDriverState *
ns_uclip_hostmsg_open(void *opaque, struct net_user *nu, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr,
        yajl_val config)
{
    struct ns_uclip_hostmsg_data *d;
    int ret;

    if (ns_uclip_hostmsg_connection_already_opened)
        return NULL;
    debug_printf("%s service %s\n", __FUNCTION__,
                 yajl_object_get_string(config, "service"));

    d = calloc(1, sizeof(*d));
    if (d == NULL)
        return NULL;

    d->ns_data.net_opaque = opaque;

    ret = ns_open(&d->ns_data, nu);
    if (ret) {
        free(d);
    	return NULL;
    }

    d->ns_data.service_close = ns_uclip_hostmsg_close;
    d->ns_data.chr->chr_write = ns_uclip_hostmsg_write;

    d->config = config;

    if (!(d->data_ready_event = CreateEvent(NULL, FALSE, FALSE, NULL))) {
        free(d);
        return NULL;
    }
    netuser_add_wait_object(nu, &d->data_ready_event, ns_uclip_hostmsg_data_ready, d);
    g_ns_uclip_hostmsg_data = d;
    ns_uclip_hostmsg_connection_already_opened = true;
    ns_uclip_try_init();
    return d->ns_data.chr;
}

static void
ns_uclip_hostmsg_close(CharDriverState *chr)
{
    struct ns_uclip_hostmsg_data *d = chr->opaque;

    debug_printf("%s\n", __FUNCTION__);
    g_ns_uclip_hostmsg_data = NULL;
    netuser_del_wait_object(d->ns_data.nu, &d->data_ready_event);
    ns_close(&d->ns_data);
}

static struct ns_desc ns_uclip_hostmsg_desc = {
    .service_type = NS_SERVICE_TYPE_TCP,
    .service_name = "shared-clipboard-hostmsg",
    .service_open = ns_uclip_hostmsg_open,
    .service_close = ns_uclip_hostmsg_close,
};

ns_add_service(ns_uclip_hostmsg_desc);
