/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include "char.h"
#include "ns.h"
#include "timer.h"

#include "libnickel.h"

struct ns_echo_data {
    struct ns_data ns_data;
    yajl_val config;
    Timer *timer;
    int period;
};

#define CHARGEN_COMMAND "chargen"
#define MAX_CHARGEN_LENGTH (4*1024*1024)

static void ns_echo_close(CharDriverState *chr);
static int
ns_echo_chr_write_chargen(CharDriverState *chr, const uint8_t *buf, int len1)
{
    struct ns_echo_data *d = chr->opaque;
    char tmp[16] = {0,};
    uint8_t *buffer;
    unsigned int i, len;

    memcpy(tmp, buf, len1 < sizeof(tmp) - 1 ? len1 : sizeof(tmp) - 1);

    len = atoi(&tmp[strlen(CHARGEN_COMMAND)]);
    if (len > MAX_CHARGEN_LENGTH)
        return len1;

    /* Ensure enough space for length */
    if (len < 7)
        len = 7;

    /* Clear any pending output, frees associated buffer */
    ns_reset_send_buffer(&d->ns_data);

    /* Allocate len bytes for d->buffer, fill with data */
    buffer = malloc(len + 1);
    if (!buffer)
        return len1;

    for (i = 0; i < len - 7; i++)
        buffer[i] = 'A' + (i % 26);
    sprintf((char *)&buffer[len - 7], "%07d", len);

    debug_printf("%s: sending %d byte chargen\n", __FUNCTION__, len);

    ns_send_buffer(&d->ns_data, buffer, len);

    return len1;
}

static int
ns_echo_chr_write(CharDriverState *chr, const uint8_t *buf, int len1)
{
    struct ns_echo_data *d = chr->opaque;
    char *r;
    int len;

    if (len1 > strlen(CHARGEN_COMMAND) &&
        !strncasecmp((char *)buf, CHARGEN_COMMAND, strlen(CHARGEN_COMMAND)))
        return ns_echo_chr_write_chargen(chr, buf, len1);

    /* limit the length of message that we process, to exercise the
     * ns_await_write/ns_signal_write code path */
    len = yajl_object_get_integer_default(d->config, "max", len1);
    if (len > len1)
        len = len1;

    asprintf(&r, "%s: %.*s%s", yajl_object_get_string(d->config, "prefix"),
             len, buf, buf[len - 1] != '\n' ? "\n" : "");
    if (r == NULL)
        return 0;

    debug_printf("%s", r);

    /* show send space before sending */
    debug_printf("%s: space for %d bytes\n", __FUNCTION__,
                 qemu_chr_can_read(chr));

    qemu_chr_read(chr, (uint8_t *)r, strlen(r));

    /* show send space after sending */
    debug_printf("%s: space for %d bytes\n", __FUNCTION__,
                 qemu_chr_can_read(chr));

    free(r);

    if (len != len1) {
        /* add wait object to wait for signal that we can process more data */
        ns_await_write(&d->ns_data);
        /* signal that we can process more data -- a real server would
         * do this when it can actually process more data */
        ns_signal_write(&d->ns_data);
    }

    return len;
}

static void
ns_echo_timer(void *opaque)
{
    struct ns_echo_data *d = (struct ns_echo_data *)opaque;
    static int nr = 0;
    char *s;
    int ret;

    debug_printf("%s %d\n", __FUNCTION__, nr);
    asprintf(&s, "%d\n", nr++);
    if (s) {
        ret = ns_append_send_buffer(&d->ns_data, (const uint8_t *)s, strlen(s));
        if (!ret)
            mod_timer(d->timer, get_clock_ms(vm_clock) + d->period);
        free(s);
    }
}

static CharDriverState *
ns_echo_open(void *opaque, struct nickel *ni, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr,
        yajl_val config)
{
    struct ns_echo_data *d;
    int ret;

    debug_printf("%s service %s prefix >%s<\n", __FUNCTION__,
                 yajl_object_get_string(config, "service"),
                 yajl_object_get_string(config, "prefix"));

    d = calloc(1, sizeof(*d));
    if (d == NULL)
        return NULL;

    d->ns_data.net_opaque = opaque;

    ret = ns_open(&d->ns_data, ni);
    if (ret) {
        free(d);
	return NULL;
    }

    d->ns_data.service_close = ns_echo_close;
    d->ns_data.chr->chr_write = ns_echo_chr_write;

    d->config = config;

    d->period = yajl_object_get_integer_default(config, "timer", 0);
    if (d->period) {
        debug_printf("%s: period %d\n", __FUNCTION__, d->period);
        d->timer = new_timer_ms(vm_clock, ns_echo_timer, d);
        if (d->timer)
            mod_timer(d->timer, get_clock_ms(vm_clock) + d->period);
    }

    return d->ns_data.chr;
}

static void
ns_echo_close(CharDriverState *chr)
{
    struct ns_echo_data *d = chr->opaque;

    debug_printf("%s\n", __FUNCTION__);
    ns_close(&d->ns_data);
}

static struct ns_desc ns_echo_desc = {
    .service_type = NS_SERVICE_TYPE_TCP,
    .service_name = "echo",
    .service_open = ns_echo_open,
    .service_close = ns_echo_close,
};

ns_add_service(ns_echo_desc);
