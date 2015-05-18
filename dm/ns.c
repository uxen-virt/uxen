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
#include "ioh.h"
#include "ns.h"

#include <dm/file.h>
#include <dm/async-op.h>
#include <dm/libnickel.h>

#define SEND_BUFFER_TRIM_THRESHHOLD 16384

LIST_HEAD(, ns_desc) nsd_list = LIST_HEAD_INITIALIZER(&nsd_list);

static void ns_try_send_buffer(void *opaque);

static int
ns_chr_can_read(void *opaque)
{
    struct ns_data *d = opaque;

    return ni_can_recv(d->net_opaque);
}

static void
ns_chr_read(void *opaque, const uint8_t *buf, int size)
{
    struct ns_data *d = opaque;

    ni_recv(d->net_opaque, buf, size);
}

/* This is called from tcp_input(), when ACK segment has been processed, so
   there is a chance we can send more data. */
void
ns_chr_send_event(CharDriverState *chr, int event)
{
    if (event == CHR_EVENT_BUFFER_CHANGE) {
        ns_try_send_buffer(chr->opaque);
        return;
    }

    if (event == CHR_EVENT_NI_CLOSE || event == CHR_EVENT_NI_RST) {
        struct ns_data *d = chr->opaque;

        if (d->service_close)
            d->service_close(chr);

        return;
    }
}

static void ns_chr_save(struct CharDriverState *chr, QEMUFile *f)
{
    struct ns_data *d = chr->opaque;
    int savelen;
    int recv_offset;

    if (d->ns_processor_func) {
        d->is_close_request = 1;
        ioh_event_set(&d->request_ready_event);
        wait_thread(d->server_thread);
    }

    /* sanitize buffer lengths, just in case */
    if (!d->send_buffer) {
        d->send_len = 0;
        d->send_offset = 0;
    }

    if (!d->recv_buffer)
        d->recv_offset = 0;

    if (d->send_buffer)
        /* we are still sending response. So, no buffered request is valid.
        d->recv_buffer can be still nonNULL, if ns_response_ready has not
        been run yet. */
        recv_offset = 0;
    else
        recv_offset = d->recv_offset;

    savelen =       4 /* sizeof(d->recv_offset) */
                    + recv_offset
                    + 4 /* sizeof(d->send_len) */
                    + d->send_len - d->send_offset;
    qemu_put_be32(f, savelen);
    qemu_put_be32(f, recv_offset);
    if (d->recv_buffer && recv_offset > 0)
        qemu_put_buffer(f, d->recv_buffer, d->recv_offset);
    qemu_put_be32(f, d->send_len - d->send_offset);
    if (d->send_buffer)
        qemu_put_buffer(f, d->send_buffer, d->send_len - d->send_offset);
}

static void ns_chr_restore(struct CharDriverState *chr, QEMUFile *f)
{
    struct ns_data *d = chr->opaque;
    int len = qemu_get_be32(f);
    int recv_len, send_len, terminator;

    if (len < 8) {
        warnx("error in ns_chr_restore: len=0x%x, we are doomed", len);
        return;
    }

    recv_len = qemu_get_be32(f);
    if (recv_len) {
        d->recv_offset = recv_len;
        d->recv_buffer = malloc(d->recv_len);
        if (d->recv_buffer)
            qemu_get_buffer(f, d->recv_buffer, recv_len);
        else {
            warnx("ns_chr_restore: out of memory for alloc of 0x%x bytes",
                d->recv_len);
            qemu_file_skip(f, recv_len);
        }
    }

    send_len = qemu_get_be32(f);
    if (send_len) {
        d->send_offset = 0;
        d->send_len = send_len;
        d->send_buffer = malloc(d->send_len);
        if (d->send_buffer)
            qemu_get_buffer(f, d->send_buffer, send_len);
        else {
            warnx("ns_chr_restore: out of memory for alloc of 0x%x bytes",
                d->send_len);
            qemu_file_skip(f, send_len);
        }
        /* if we did save immediately after response was prepared,
           we need to start sending */
        ns_try_send_buffer(d);
    }

    terminator = qemu_get_be32(f);
    if (terminator)
        warnx("ns_chr_restore: expected terminating 0, got 0x%x",
              terminator);
}

static void
ns_chr_close(CharDriverState *chr)
{
    struct ns_data *d = chr->opaque;

    debug_printf("%s: close\n", __FUNCTION__);
    ni_close(d->net_opaque);
}

int
ns_open(struct ns_data *d, struct nickel *ni)
{

    critical_section_init(&d->lock);

    d->ni = ni;
    d->chr = calloc(1, sizeof(CharDriverState));

    if (!d->chr)
        return -1;

    d->chr->refcnt = 1;

    ioh_event_init(&d->write_event);
    if (!ioh_event_valid(&d->write_event)) {
        free(d->chr);
        d->chr = NULL;
        return -1;
    }

    qemu_chr_add_handlers(d->chr, ns_chr_can_read, ns_chr_read, NULL, d);

    d->chr->chr_close = ns_chr_close;
    d->chr->chr_send_event = ns_chr_send_event;
    d->chr->chr_restore = ns_chr_restore;
    d->chr->chr_save = ns_chr_save;

    d->chr->opaque = d;

    return 0;
}

void
ns_close(struct ns_data *d)
{
    CharDriverState *chr = d->chr;

    ns_reset_send_buffer(d);
    if (d->ns_processor_func) {
        d->is_close_request = 1;
        ioh_event_set(&d->request_ready_event);
        wait_thread(d->server_thread);
        if (d->recv_buffer) {
            free(d->recv_buffer);
            d->recv_buffer = NULL;
        }
        close_thread_handle(d->server_thread);
        ni_del_wait_object(d->ni, &d->response_ready_event);
        ioh_event_close(&d->response_ready_event);
        ioh_event_close(&d->request_ready_event);
    }

    critical_section_enter(&d->lock);
    qemu_chr_close(chr);
    d->chr = NULL;
    critical_section_leave(&d->lock);
}

static void
ns_ready_write(void *opaque)
{
    struct ns_data *d = opaque;

    assert(d->awaiting_write);

    ni_del_wait_object(d->ni, &d->write_event);
    d->awaiting_write = 0;

    ni_send(d->net_opaque);
}

void
ns_await_write(struct ns_data *d)
{

    if (d->awaiting_write)
        return;

    ni_add_wait_object(d->ni, &d->write_event, ns_ready_write, d);
    d->awaiting_write = 1;
}

void
ns_signal_write(struct ns_data *d)
{

    /* XXX maybe, could also always allow signal */
    assert(d->awaiting_write);

    ioh_event_set(&d->write_event);
}

static void
ns_try_send_buffer(void *opaque)
{
    struct ns_data *d = opaque;
    CharDriverState *chr = d->chr;
    int len, available;

    if (d->processing_request)
        /* We can get here from ns_chr_send_event when the response is ready,
        but d->processing_request has not yet been cleared. In such case,
        do nothing, wait for ns_response_ready to call us. */
        return;

    critical_section_enter(&d->lock);

    /* Apparently, qemu_chr_read never returns more than tcp MSS, even if the
     * tcp window is larger. Therefore, we must loop.
     */
    for(;;) {
        if (!d->send_buffer)
            goto out;

        len = qemu_chr_can_read(chr);
        if (len <= 0)
            goto out;

        available = d->send_len - d->send_offset;
        if (available < len)
            len = available;

        qemu_chr_read(chr, &d->send_buffer[d->send_offset], len);
        d->send_offset += len;

        if (d->send_offset == d->send_len) {
            free(d->send_buffer);
            d->send_buffer = NULL;
            d->send_offset = d->send_len = 0;
        }
    }

  out:
    critical_section_leave(&d->lock);
}

void
ns_send_buffer(struct ns_data *d, uint8_t *buffer, int len)
{

    critical_section_enter(&d->lock);

    if (d->send_buffer)
        free(d->send_buffer);

    d->send_buffer = buffer;
    d->send_len = len;
    d->send_offset = 0;

    ns_try_send_buffer(d);

    critical_section_leave(&d->lock);
}

static void ns_try_send_buffer_cb(void *opaque)
{
    CharDriverState *chr = opaque;

    if (qemu_chr_put(chr) == 0 || chr->closing)
        return;

    ns_try_send_buffer(chr->opaque);
}

int
ns_append_send_buffer(struct ns_data *d, const uint8_t *buffer, int len)
{
    uint8_t *new_buffer;
    int ret = 0;

    critical_section_enter(&d->lock);
    if (!d->chr) {
        ret = -1;
        goto out;
    }

    if (!d->send_buffer) {
        d->send_len = 0;
        d->send_offset = 0;
    }

    if (d->send_offset > SEND_BUFFER_TRIM_THRESHHOLD) {
        new_buffer = malloc(d->send_len - d->send_offset + len);
        if (!new_buffer) {
            ret = -1;
            goto out;
        }
        memcpy(new_buffer, &d->send_buffer[d->send_offset],
               d->send_len - d->send_offset);
        d->send_len -= d->send_offset;
        d->send_offset = 0;
        free(d->send_buffer);
    } else
        new_buffer = realloc(d->send_buffer, d->send_len + len);

    memcpy(&new_buffer[d->send_len], buffer, len);
    d->send_len += len;

    d->send_buffer = new_buffer;

    qemu_chr_get(d->chr);
    if (ni_schedule_bh(d->ni, NULL, ns_try_send_buffer_cb, d->chr) < 0) {
        qemu_chr_put(d->chr);
        warnx("%s: error on netuser_schedule_bh !", __FUNCTION__);
    }

  out:
    critical_section_leave(&d->lock);

    return ret;
}

void
ns_reset_send_buffer(struct ns_data *d)
{

    critical_section_enter(&d->lock);

    if (d->send_buffer) {
        free(d->send_buffer);
        d->send_buffer = NULL;
    }

    critical_section_leave(&d->lock);
}

static int
ns_buffered_can_write(void *opaque)
{
    return (64 * 1024 - 2);
}

static int
ns_buffered_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    struct ns_data *d = chr->opaque;
    int ret;

    if (!len || d->processing_request || d->send_buffer) {
        warnx("unexpected ns_buffered_write, len=0x%x, processing_request=%d, send_buffer=%p",
            len, d->processing_request, d->send_buffer);
        return len;
    }
    if (!d->recv_buffer) {
        d->recv_buffer = malloc(d->recv_len);
        if (!d->recv_buffer) {
            warnx("ns_buffered_write alloc 0x%x failed", d->recv_len);
            return -1;
        }
        d->recv_offset = 0;
    }

    if (d->recv_offset + len > d->recv_len) {
        warnx("ns_buffered_write recv_offset 0x%x len 0x%x recv_len 0x%x",
            d->recv_offset, len, d->recv_len);
        return -1;
    }

    memcpy(d->recv_buffer + d->recv_offset, buf, len);
    d->recv_offset += len;

    /* just ask if we have enough data already */
    ret = d->ns_processor_func(d->recv_buffer, d->recv_offset, NULL, NULL);
    if (ret < 0) {
        /* possibly forcibly close connection ? Log more ? */
        return -1;
    }
    if (ret > 0) {
        d->processing_request = 1;
        ioh_event_set(&d->request_ready_event);
    }
    return len;
}

#ifdef _WIN32
static DWORD WINAPI ns_thread_func(LPVOID arg)
#else
static void *ns_thread_func(void *arg)
#endif
{
    struct ns_data *d = arg;

    for (;;) {
        ioh_event_wait(&d->request_ready_event);
        ioh_event_reset(&d->request_ready_event);
        if (d->is_close_request)
            return 0;

        critical_section_enter(&d->lock);
        d->send_offset = 0;
        critical_section_leave(&d->lock);

        d->ns_processor_func(d->recv_buffer, d->recv_offset,
            &d->send_buffer, &d->send_len);
        ioh_event_set(&d->response_ready_event);
    }
}

static void
ns_response_ready(void *opaque)
{
    struct ns_data *d = opaque;

    d->processing_request = 0;
    if (d->recv_buffer) {
        free(d->recv_buffer);
        d->recv_buffer = NULL;
        d->recv_offset = 0;
    }
    ns_try_send_buffer(d);
}

int
ns_set_threaded_mode(struct ns_data *d)
{

    /* both events are manual-reset */
    ioh_event_init(&d->request_ready_event);
    if (!ioh_event_valid(&d->request_ready_event)) {
        return -1;
    }

    ioh_event_init(&d->response_ready_event);
    if (!ioh_event_valid(&d->response_ready_event)) {
        ioh_event_close(&d->request_ready_event);
        return -1;
    }

    if (create_thread(&d->server_thread, ns_thread_func, d) < 0) {
        ioh_event_close(&d->request_ready_event);
        ioh_event_close(&d->response_ready_event);
        return -1;
    }
    elevate_thread(&d->server_thread);

    ni_add_wait_object(d->ni, &d->response_ready_event, ns_response_ready, d);
    d->chr->chr_write = ns_buffered_write;
    d->chr->chr_can_write = ns_buffered_can_write;

    return 0;
}

struct ns_desc *
ns_find_service(const char *service, int is_udp)
{
    struct ns_desc *nsd;
    int type = is_udp ? NS_SERVICE_TYPE_UDP : NS_SERVICE_TYPE_TCP;

    LIST_FOREACH(nsd, &nsd_list, entry)
        if (!strcmp(nsd->service_name, service) && nsd->service_type == type)
            break;

    return nsd;
}

void
_ns_add_service(struct ns_desc *nsd)
{

    LIST_INSERT_HEAD(&nsd_list, nsd, entry);
}
