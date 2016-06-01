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
#include <dm/qemu_glue.h>

#include <dns/dns.h>
#include <socket.h>
#include <nickel.h>
#include <buff.h>
#include <log.h>
#include <service.h>

#define U32BF(a)            (((uint32_t) 1) << (a))

#define CXF_SO_READ_PENDING U32BF(0)
#define CXF_SO_CONNECTED    U32BF(1)
#define CXF_CLOSED          U32BF(2)
#define CXF_FLUSH_CLOSE     U32BF(3)
#define CXF_VM_FIN          U32BF(4)

#define SO_READBUFLEN   (16 * 1024)
#define MAX_SRV_BUFLEN  (128 * 1024)
#define MX_GUEST_IN_LEN (64 * 1024)
#define BUF_CHUNK   (2 * 1024)

#define CXL0(ll, fmt, ...) do {                                                    \
            if (NLOG_LEVEL < ll) break;                                            \
            NETLOG("(tcp) cx:%"PRIxPTR " tcp:%"PRIxPTR " so:%"PRIxPTR" [%s] " fmt, \
                   (uintptr_t) cx, (uintptr_t) (cx ? cx->ni_opaque : 0),           \
                   (uintptr_t) (cx ? cx->so : 0),                                  \
                    __FUNCTION__,  ## __VA_ARGS__);                                \
        } while (1 == 0)

#define CXL(fmt, ...)  CXL0(1, fmt, ## __VA_ARGS__)
#define CXL2(fmt, ...) CXL0(2, fmt, ## __VA_ARGS__)
#define CXL3(fmt, ...) CXL0(3, fmt, ## __VA_ARGS__)
#define CXL4(fmt, ...) CXL0(4, fmt, ## __VA_ARGS__)
#define CXL5(fmt, ...) CXL0(5, fmt, ## __VA_ARGS__)
#define CXL6(fmt, ...) CXL0(6, fmt, ## __VA_ARGS__)

struct cx_ctx {
    CharDriverState chr;
    LIST_ENTRY(cx_ctx) entry;

    struct nickel *ni;
    struct socket *so;
    struct ni_socket *ni_opaque;
    struct buff *b_vm, *b_so;
    uint32_t flags;
};

static LIST_HEAD(, cx_ctx) cx_gc_list = LIST_HEAD_INITIALIZER(&cx_gc_list);

static void cx_close(struct cx_ctx *cx)
{
    if (cx->flags & CXF_CLOSED)
        return;

    CXL5("CLOSE");
    if (cx->ni_opaque)
        ni_close(cx->ni_opaque);
    cx->ni_opaque = NULL;
    if (cx->so)
        so_close(cx->so);
    cx->so = NULL;
    buff_free(&cx->b_vm);
    buff_free(&cx->b_so);
    cx->flags |= CXF_CLOSED;
    LIST_INSERT_HEAD(&cx_gc_list, cx, entry);
}

static void cx_bh(void *unused)
{
    struct cx_ctx *cx, *cx_next;

    LIST_FOREACH_SAFE(cx, &cx_gc_list, entry, cx_next) {
        LIST_REMOVE(cx, entry);
        CXL5("FREE");
        free(cx);
    }
}

static void cx_init(struct nickel *ni, yajl_val config)
{
    ni_schedule_bh_permanent(ni, cx_bh, NULL);
}

static void wakeup_vm(struct cx_ctx *cx)
{
    if (cx->ni_opaque)
        ni_buf_change(cx->ni_opaque);
}

static int cx_vm_can_read(void *opaque)
{
    struct cx_ctx *cx = opaque;

    return ni_can_recv(cx->ni_opaque);
}

static void cx_vm_read(void *opaque, const uint8_t *buf, int size)
{
    struct cx_ctx *cx = opaque;

    ni_recv(cx->ni_opaque, buf, size);
}

static int cx_vm_try_write(struct cx_ctx *cx)
{
    int ret = 0;
    size_t l;
    uint8_t *p;

    if (!cx->ni_opaque || !cx->b_so)
        goto out;

    l = BUFF_CONSUMED(cx->b_so);
    if (l == 0)
        goto out;

    ret = 0;
    p = (uint8_t *) BUFF_BEGINNING(cx->b_so);
    while (l) {
        int r;

        r = qemu_chr_can_read(&cx->chr);
        if (r <= 0)
            break;
        if (r > l)
            r = l;
        qemu_chr_read(&cx->chr, p, r);
        p += r;
        l -= r;
        ret += r;
    }
    if (ret > 0) {
        buff_gc_consume(cx->b_so, ret);
        if ((cx->flags & CXF_SO_READ_PENDING) && cx->so) {
            cx->flags &= ~(CXF_SO_READ_PENDING);
            so_buf_ready(cx->so);
        }
    }

    if ((cx->flags & CXF_FLUSH_CLOSE) && (!cx->b_so || !BUFF_BUFFERED(cx->b_so)))
        cx_close(cx);
out:
    return ret;
}


static void cx_so_try_read(struct cx_ctx *cx)
{
    size_t len = 0;
    ssize_t max_allowed = 0;

    if (!cx->so)
        goto out;

    if (!cx->b_so && !buff_new_priv(&cx->b_so, SO_READBUFLEN))
        goto out;

    len = BUFF_FREEDOM(cx->b_so);
    max_allowed = (ssize_t) MAX_SRV_BUFLEN - (ssize_t) BUFF_BUFFERED(cx->b_so);
    if (max_allowed < 0)
        max_allowed = 0;
    if (!len && max_allowed <= 0) {
        CXL5("MAX_SRV_BUFLEN %d reached", MAX_SRV_BUFLEN);
        goto out_pending;
    }

    if (max_allowed > 0 && max_allowed > len) {
        size_t avail;

        avail = so_read_available(cx->so);
        if (avail > len)
            len = avail;
        if (len > max_allowed)
            len = max_allowed;
    }

    if (len == 0)
        goto out_pending;

    if (len > BUFF_FREEDOM(cx->b_so) && BUFF_ENLARGE(cx->b_so, len + BUF_CHUNK) < 0)
        goto out_pending;

    cx->flags &= ~CXF_SO_READ_PENDING;
    len = so_read(cx->so, cx->b_so->m + cx->b_so->len, len);
    if (len == 0)
        goto out;
    BUFF_ADVANCE(cx->b_so, len);
    BUFF_CONSUME_ALL(cx->b_so);
out:
    cx_vm_try_write(cx);
    return;
out_pending:
    cx->flags |= CXF_SO_READ_PENDING;
    goto out;
}

static int cx_so_try_write(struct cx_ctx *cx, const uint8_t *buf, int len_buf)
{
    int r, written = 0;
    bool signal_vm = false;

    if (cx->b_vm && cx->b_vm->len > 0) {
        r = so_write(cx->so, BUFF_TO(cx->b_vm, const uint8_t *), cx->b_vm->len);
        if (r <= 0)
            goto out;
        if (r == cx->b_vm->len)
            signal_vm = true;
        BUFF_CONSUME(cx->b_vm, r);
        BUFF_GC(cx->b_vm);
        if (cx->b_vm->len > 0)
            goto out;
    }

    if (!buf || !len_buf)
        goto out;

    r = so_write(cx->so, buf, len_buf);
    if (r < 0)
        r = 0;
    if (r == len_buf)
        signal_vm = true;
    buf += r;
    len_buf -= r;
    written += r;
out:
    if (len_buf > 0 && buf) {
        if (!cx->b_vm && !BUFF_NEW_MX_PRIV(&cx->b_vm, len_buf, MX_GUEST_IN_LEN))
            goto mem_error;
        if (buff_append(cx->b_vm, (const char *) buf, len_buf) < 0)
            goto mem_error;
        written += len_buf;
    }

    if (signal_vm)
        wakeup_vm(cx);

    return written;
mem_error:
    warnx("%s: malloc FAILURE", __FUNCTION__);
    return written;
}

static int cx_chr_write(CharDriverState *chr, const uint8_t *buf, int len_buf)
{
    struct cx_ctx *cx = chr->handler_opaque;

    return cx_so_try_write(cx, buf, len_buf);
}

#if 0
static int cx_vm_send_fin(struct cx_ctx *cx)
{
    int ret = -1;

    if (!cx->ni_opaque)
        goto out;
    if ((cx->flags & CXF_CLOSED))
        goto out;

    ret = ni_send_fin(cx->ni_opaque);
out:
    return ret;
}
#endif

static int cx_chr_can_write(void *opaque)
{
    struct cx_ctx *cx = opaque;

    return cx->b_vm ? (BUFF_FREEDOM(cx->b_vm) + cx->b_vm->mx_size -
            cx->b_vm->size) : MX_GUEST_IN_LEN;
}

static void cx_vm_on_event(CharDriverState *chr, int event)
{
    struct cx_ctx *cx = (struct cx_ctx *) chr->handler_opaque;

    if (cx->flags & CXF_CLOSED)
        goto out;

    if (event == CHR_EVENT_BUFFER_CHANGE) {
        if (cx_vm_try_write(cx) < 0)
            goto out_close;
        goto out;
    }

    if (event == CHR_EVENT_NI_CLOSE || event == CHR_EVENT_NI_RST) {
        CXL5("VM CLOSING");
        cx->flags |= CXF_VM_FIN;
        if (event == CHR_EVENT_NI_RST) {
            CXL5("RST");
            goto out_close;
        }

        if (!cx->so || !(cx->flags & CXF_SO_CONNECTED))
            goto out_close;

        so_shutdown(cx->so);
        CXL5("so_shutdown");
        goto out;
    }

out:
    return;
out_close:
    cx_close(cx);
    goto out;
}

static void cx_vm_chr_close(CharDriverState *chr)
{
    struct cx_ctx *cx = chr->handler_opaque;

    CXL5("");
    cx_close(cx);
}

static int cx_so_connecting(struct cx_ctx *cx)
{
    return 0;
}


static int cx_so_connected(struct cx_ctx *cx)
{
    CXL5("CONNECTED");
    cx->flags |= CXF_SO_CONNECTED;
    if (cx->ni_opaque)
        ni_event(cx->ni_opaque, CHR_EVENT_OPENED);
    return 0;
}

static int cx_so_write_available(struct cx_ctx *cx)
{
    assert(cx->so);
    wakeup_vm(cx);
    cx_so_try_write(cx, NULL, 0);
    return 0;
}

static int cx_so_closing(struct cx_ctx *cx, int err)
{
    CXL5("SO CLOSING");
    if (cx->b_vm && BUFF_BUFFERED(cx->b_vm)) {
        cx->flags |= CXF_FLUSH_CLOSE;
        cx_vm_try_write(cx);

        return 0;
    }

    cx_close(cx);
    return 0;
}

static void cx_so_on_event(void *opaque, uint32_t evt, int err)
{
    struct cx_ctx *cx = (struct cx_ctx *) opaque;

    if (cx->flags & CXF_CLOSED)
        goto out;

    if ((evt & SO_EVT_CONNECTING) && cx_so_connecting(cx) < 0)
        goto out_close;
    if ((evt & SO_EVT_CONNECTED) && cx_so_connected(cx) < 0)
        goto out_close;
    if ((evt & SO_EVT_READ))
        cx_so_try_read(cx);
    if ((evt & SO_EVT_WRITE) && cx_so_write_available(cx) < 0)
        goto out_close;
    if ((evt & SO_EVT_CLOSING) && cx_so_closing(cx, err) < 0)
        goto out_close;

out:
    return;

out_close:
    cx_close(cx);
    goto out;
}

static CharDriverState *
cx_open(void *opaque, struct nickel *ni, struct sockaddr_in saddr, struct sockaddr_in daddr)
{
    CharDriverState *chr = NULL;
    struct cx_ctx *cx = NULL;
    struct net_addr a;

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

    qemu_chr_add_handlers(chr, cx_vm_can_read, cx_vm_read, NULL, cx);
    chr->chr_write = cx_chr_write;
    chr->chr_send_event = cx_vm_on_event;
    chr->chr_can_write = cx_chr_can_write;
    chr->chr_close = cx_vm_chr_close;

    CXL5("CONNECTING to %s:%hu", inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port));
    cx->so = so_create(ni, false, cx_so_on_event, cx);
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

static CharDriverState *
cx_accept(void *opaque, struct nickel *ni, struct socket *so)
{
    struct cx_ctx *cx = NULL;
    CharDriverState *chr = NULL;

    CXL5("ACCEPT");
    cx = calloc(1, sizeof(*cx));
    if (!cx) {
        warnx("%s: memory error", __FUNCTION__);
        goto cleanup;
    }
    chr = &cx->chr;
    chr->refcnt = 1;
    cx->ni_opaque = opaque;

    cx->so = so;
    so_update_event(so, cx_so_on_event, cx);

    qemu_chr_add_handlers(chr, cx_vm_can_read, cx_vm_read, NULL, cx);
    chr->chr_write = cx_chr_write;
    chr->chr_send_event = cx_vm_on_event;
    chr->chr_can_write = cx_chr_can_write;
    chr->chr_close = cx_vm_chr_close;

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
    .is_udp = 0,
    .name = "tcp-service",
    .init = cx_init,
    .open = cx_open,
    .accept = cx_accept,
};
ni_prx_add_service(prx);
