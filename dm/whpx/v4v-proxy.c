/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#define UNICODE
#include <dm/qemu_glue.h>
#include <dm/hw/uxen_v4v.h>
#include <dm/whpx/whpx.h>
#include <dm/whpx/v4v-whpx.h>
#include "../../windows/uxenv4vproxy/proxy_api.h"

// this is just for testing
//#define DEBUG_FORCE_DOM0_PARTNER

#define PROXY_MAX_PACKET_LEN 262144
#define PROXY_READ_BUFFER_LEN (PROXY_MAX_PACKET_LEN + sizeof(v4v_proxy_complete_read_t))
#define PROXY_MAX_REQ_LEN (PROXY_MAX_PACKET_LEN + 256)
#define PROXY_RING_LEN (262144*4)
#define PROXY_DRIVER_NAME L"uxenv4vproxy"

/* why no define in windows hdrs? */
#define ERROR_OPERATION_IN_PROGRESS 329

struct v4v_proxy_context;

typedef struct v4v_proxy_pending_write {
    struct v4v_proxy_context *proxy;
    uint64_t reqid;
    v4v_async_t async;
    TAILQ_ENTRY(v4v_proxy_pending_write) entry;
} v4v_proxy_pending_write_t;

typedef struct v4v_proxy_context {
    critical_section read_lock;
    critical_section write_lock;
    v4v_context_t context;
    v4v_async_t recv_async;

    /* bound address of the proxied ring */
    v4v_addr_t bind_addr;

    /* v4v read has been started */
    bool read_pending;

    /* id of pending read request */
    uint64_t read_reqid;

    /* buffer for v4v recv data */
    uint8_t read_buffer[PROXY_READ_BUFFER_LEN];

    /* pending writes */
    TAILQ_HEAD(, v4v_proxy_pending_write) writes;

    TAILQ_ENTRY(v4v_proxy_context) entry;
} v4v_proxy_context_t;

static v4v_channel_t proxy_channel;
static TAILQ_HEAD(, v4v_proxy_context) proxies;
static critical_section proxies_lock;

static BOOLEAN
_v4v_proxy_register_backend(v4v_channel_t *channel, v4v_proxy_register_backend_t *reg, OVERLAPPED *ov)
{
    OVERLAPPED o = { };
    DWORD br;
    BOOLEAN rc;

    if ((channel == NULL) || (reg == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(channel->v4v_handle, V4V_PROXY_IOCTL_REGISTER_BACKEND,
        reg, sizeof(v4v_proxy_register_backend_t),
        reg, sizeof(v4v_proxy_register_backend_t), &br,
        v4v_is_overlapped(channel) ? (ov ? ov : &o) : NULL);
    if (v4v_is_overlapped(channel)) {
        if ((GetLastError() != ERROR_SUCCESS) &&
            (GetLastError() != ERROR_IO_PENDING))
            return FALSE;
        if (GetLastError() == ERROR_IO_PENDING && !ov) {
            DWORD t;
            if (!GetOverlappedResult(channel->v4v_handle, &o, &t, TRUE))
                return FALSE;
        }
    } else if (!rc)
        return FALSE;
    return TRUE;
}

static BOOLEAN
_v4v_proxy_get_req(v4v_channel_t *channel, void *buf, size_t buf_size, size_t *out_received)
{
    OVERLAPPED o = { };
    DWORD br = 0;
    BOOLEAN rc;

    if (channel == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(channel->v4v_handle, V4V_PROXY_IOCTL_GET_REQ,
        NULL, 0,
        buf, buf_size, &br,
        v4v_is_overlapped(channel) ? &o : NULL);
    *out_received = br;
    if (v4v_is_overlapped(channel)) {
        if ((GetLastError() != ERROR_SUCCESS) &&
            (GetLastError() != ERROR_IO_PENDING))
            return FALSE;
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD t;
            if (!GetOverlappedResult(channel->v4v_handle, &o, &t, TRUE))
                return FALSE;
        }
    }

    return rc;
}

static BOOLEAN
_v4v_proxy_complete_read(v4v_channel_t *channel, v4v_proxy_complete_read_t *read)
{
    OVERLAPPED o = { };
    DWORD br;
    BOOLEAN rc;

    if ((channel == NULL) || (read == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(channel->v4v_handle, V4V_PROXY_IOCTL_COMPLETE_READ,
        read, sizeof(v4v_proxy_complete_read_t),
        NULL, 0, &br,
        v4v_is_overlapped(channel) ? &o : NULL);
    if (v4v_is_overlapped(channel)) {
        if ((GetLastError() != ERROR_SUCCESS) &&
            (GetLastError() != ERROR_IO_PENDING))
            return FALSE;
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD t;
            if (!GetOverlappedResult(channel->v4v_handle, &o, &t, TRUE))
                return FALSE;
        }
    } else if (!rc)
        return FALSE;
    return TRUE;
}

static BOOLEAN
_v4v_proxy_complete_write(v4v_channel_t *channel, v4v_proxy_complete_write_t *write)
{
    OVERLAPPED o = { };
    DWORD br;
    BOOLEAN rc;

    if ((channel == NULL) || (write == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(channel->v4v_handle, V4V_PROXY_IOCTL_COMPLETE_WRITE,
        write, sizeof(v4v_proxy_complete_write_t),
        NULL, 0, &br,
        v4v_is_overlapped(channel) ? &o : NULL);
    if (v4v_is_overlapped(channel)) {
        if ((GetLastError() != ERROR_SUCCESS) &&
            (GetLastError() != ERROR_IO_PENDING))
            return FALSE;
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD t;
            if (!GetOverlappedResult(channel->v4v_handle, &o, &t, TRUE))
                return FALSE;
        }
    } else if (!rc)
        return FALSE;
    return TRUE;
}

static BOOLEAN
_v4v_proxy_complete_bind(v4v_channel_t *channel, v4v_proxy_complete_bind_t *bind)
{
    OVERLAPPED o = { };
    DWORD br;
    BOOLEAN rc;

    if ((channel == NULL) || (bind == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(channel->v4v_handle, V4V_PROXY_IOCTL_COMPLETE_BIND,
        bind, sizeof(v4v_proxy_complete_bind_t),
        NULL, 0, &br,
        v4v_is_overlapped(channel) ? &o : NULL);
    if (v4v_is_overlapped(channel)) {
        if ((GetLastError() != ERROR_SUCCESS) &&
            (GetLastError() != ERROR_IO_PENDING))
            return FALSE;
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD t;
            if (!GetOverlappedResult(channel->v4v_handle, &o, &t, TRUE))
                return FALSE;
        }
    } else if (!rc)
        return FALSE;
    return TRUE;
}

static BOOLEAN
_v4v_proxy_is_bound(v4v_channel_t *channel, v4v_proxy_is_bound_t *isbound)
{
    OVERLAPPED o = { };
    DWORD br;
    BOOLEAN rc;

    if ((channel == NULL) || (isbound == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(channel->v4v_handle, V4V_PROXY_IOCTL_IS_BOUND,
        isbound, sizeof(v4v_proxy_is_bound_t),
        NULL, 0, &br,
        v4v_is_overlapped(channel) ? &o : NULL);
    if (v4v_is_overlapped(channel)) {
        if ((GetLastError() != ERROR_SUCCESS) &&
            (GetLastError() != ERROR_IO_PENDING))
            return FALSE;
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD t;
            if (!GetOverlappedResult(channel->v4v_handle, &o, &t, TRUE))
                return FALSE;
        }
    } else if (!rc)
        return FALSE;
    return TRUE;
}

static void
proxy_complete_read_with_error(v4v_proxy_context_t *ctx, int error)
{
    v4v_proxy_complete_read_t read = { };

    read.reqid = ctx->read_reqid;
    read.status = error;
    read.datagram_len = 0;

    if (!_v4v_proxy_complete_read(&proxy_channel, &read)) {
        /* FNF is ok since it means most likely request was cancelled */
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            whpx_panic("error completing proxy read: %d", (int)GetLastError());
    }
}

static void
proxy_complete_read(v4v_proxy_context_t *ctx)
{
    critical_section_enter(&ctx->read_lock);

    if (ctx->read_pending) {
        v4v_proxy_complete_read_t *read =
            (v4v_proxy_complete_read_t*) ctx->read_buffer;
        size_t bytes = 0;
        int ret;

        /* completed read data should now be placed in ctx->read_buffer; get data
         * length and send it to the proxy */
        ret = whpx_v4v_async_get_result(&ctx->recv_async, &bytes, false);
        if (ret)
            whpx_panic("error getting async result: %d", ret);
        assert(bytes >= sizeof(v4v_datagram_t));

        read->reqid = ctx->read_reqid;
        read->status = 0;
        read->datagram_len = bytes;

        __sync_synchronize();

        ctx->read_pending = false;

        critical_section_leave(&ctx->read_lock);

        if (!_v4v_proxy_complete_read(&proxy_channel, read)) {
            /* FNF is ok since it means most likely request was cancelled */
            if (GetLastError() != ERROR_FILE_NOT_FOUND)
                whpx_panic("error completing proxy read: %d", (int)GetLastError());
        }
    } else
        critical_section_leave(&ctx->read_lock);
}

static void
proxy_complete_write_with_error(v4v_proxy_pending_write_t *write, int error)
{
    v4v_proxy_context_t *ctx = write->proxy;

    v4v_proxy_complete_write_t comp_write = { };

    critical_section_enter(&ctx->write_lock);
    TAILQ_REMOVE(&ctx->writes, write, entry);
    critical_section_leave(&ctx->write_lock);

    comp_write.reqid = write->reqid;
    comp_write.status = error;
    comp_write.written = 0;

    if (!_v4v_proxy_complete_write(&proxy_channel, &comp_write)) {
        /* FNF is ok since it means most likely request was cancelled */
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            whpx_panic("error completing proxy write: %d", (int)GetLastError());
    }

    free(write);
}

static void
proxy_complete_write(v4v_proxy_pending_write_t *write)
{
    v4v_proxy_context_t *ctx = write->proxy;
    int ret;
    size_t bytes = 0;
    v4v_proxy_complete_write_t comp_write = { };

    critical_section_enter(&ctx->write_lock);
    TAILQ_REMOVE(&ctx->writes, write, entry);
    critical_section_leave(&ctx->write_lock);

    ret = whpx_v4v_async_get_result(&write->async, &bytes, false);
    if (ret)
        whpx_panic("error getting async result: %d", ret);

    comp_write.reqid = write->reqid;
    comp_write.status = 0;
    comp_write.written = bytes;

    if (!_v4v_proxy_complete_write(&proxy_channel, &comp_write)) {
        /* FNF is ok since it means most likely request was cancelled */
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            whpx_panic("error completing proxy write: %d", (int)GetLastError());
    }

    free(write);
}

static void
proxy_read_async_done(void *opaque)
{
    proxy_complete_read((v4v_proxy_context_t*)opaque);
}

static void
proxy_write_async_done(void *opaque)
{
    proxy_complete_write((v4v_proxy_pending_write_t*)opaque);
}

static v4v_proxy_context_t *
get_proxy_context_for(v4v_addr_t addr)
{
    v4v_proxy_context_t *p;
    v4v_proxy_context_t *found = NULL;

    critical_section_enter(&proxies_lock);
    TAILQ_FOREACH(p, &proxies, entry) {
        v4v_addr_t *pa = &p->bind_addr;
        if (addr.port == pa->port) {
            found = p;
            break;
        }
    }
    critical_section_leave(&proxies_lock);

    return found;
}

/* caller must hold proxies lock */
static void
proxy_close(v4v_proxy_context_t *p)
{
    v4v_proxy_pending_write_t *w;

    whpx_v4v_close(&p->context);

    /* cancel & free pending writes */
    TAILQ_FOREACH(w, &p->writes, entry) {
        whpx_v4v_async_cancel(&w->async);
        free(w);
    }

    critical_section_free(&p->read_lock);
    critical_section_free(&p->write_lock);

    /* free proxy */
    TAILQ_REMOVE(&proxies, p, entry);

    debug_printf("closed v4v-proxy domain %d port %d\n",
        p->bind_addr.domain, p->bind_addr.port);
    free(p);
}

static void
close_dead_proxies(void)
{
    v4v_proxy_context_t *p, *next;

    critical_section_enter(&proxies_lock);
    TAILQ_FOREACH_SAFE(p, &proxies, entry, next) {
        v4v_proxy_is_bound_t isbound = { };
        isbound.addr = p->bind_addr;

        if (!_v4v_proxy_is_bound(&proxy_channel, &isbound))
            proxy_close(p);
    }
    critical_section_leave(&proxies_lock);
}

static void
proxy_request_bind(v4v_proxy_req_bind_t *req_bind)
{
    v4v_proxy_context_t *p;
    v4v_proxy_complete_bind_t complete = { };
    int err;

    /* cleanup any previously dead proxies */
    close_dead_proxies();

    p = calloc(1, sizeof(v4v_proxy_context_t));

    /* open connection representing the proxy */
    if ((err = whpx_v4v_open(&p->context, PROXY_RING_LEN, V4V_FLAG_ASYNC|V4V_FLAG_PROXY)))
        whpx_panic("failed to open proxy v4v context: %d", err);
    /* bind */
    v4v_bind_values_t bind = req_bind->bind;
    /* ensure partner UUID is our vm uuid */
    bind.ring_id.partner = V4V_DOMID_UUID;
    memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));

#ifdef DEBUG_FORCE_DOM0_PARTNER
    bind.ring_id.partner = 0;
#endif

    complete.reqid = req_bind->req.id;
    complete.bind = bind;

    if ((err = whpx_v4v_bind(&p->context, &bind))) {
        debug_printf("failed to bind proxy v4v context: %d", err);
        complete.status = err;
        free(p);
        goto complete_bind;
    }

    /* initialize proxy context fields */
    p->bind_addr = bind.ring_id.addr;
    critical_section_init(&p->read_lock);
    critical_section_init(&p->write_lock);
    TAILQ_INIT(&p->writes);

    TAILQ_INSERT_TAIL(&proxies, p, entry);

    debug_printf("bound new v4v-proxy domain %d port %d\n",
        p->bind_addr.domain, p->bind_addr.port);

    critical_section_leave(&proxies_lock);

complete_bind:
    if (!_v4v_proxy_complete_bind(&proxy_channel, &complete)) {
        /* FNF is ok since it means most likely request was cancelled */
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            whpx_panic("error completing proxy bind: %d", (int)GetLastError());
    }
}

// request incoming from proxy driver
static void
proxy_request_received(void *opaque)
{
    uint8_t buffer[PROXY_MAX_REQ_LEN];
    v4v_proxy_req_t *req = (v4v_proxy_req_t*) buffer;
    size_t req_size = 0;
    int ret = 0;

    /* handle pending proxy requests */
    while (_v4v_proxy_get_req(&proxy_channel, buffer, sizeof(buffer), &req_size)) {
        switch (req->op) {
        case V4VPROXY_REQ_BIND: {
            /* incoming bind from external app */
            proxy_request_bind((v4v_proxy_req_bind_t*)req);
            break;
        }
        case V4VPROXY_REQ_RECV: {
            /* incoming recv from external app */
            v4v_proxy_req_recv_t *recv_req = (v4v_proxy_req_recv_t*) req;
            v4v_proxy_context_t *proxy = get_proxy_context_for(recv_req->from);

            assert(proxy);
            assert(recv_req->buffer_len <= PROXY_MAX_PACKET_LEN);

            critical_section_enter(&proxy->read_lock);

            if (proxy->read_pending) {
                proxy_complete_read_with_error(proxy, ERROR_OPERATION_IN_PROGRESS);
                critical_section_leave(&proxy->read_lock);
            } else {
                proxy->read_pending = true;
                critical_section_leave(&proxy->read_lock);

                proxy->read_reqid = recv_req->req.id; /* store pending request ID */
                whpx_v4v_async_init_cb(&proxy->context, &proxy->recv_async, proxy, proxy_read_async_done);
                ret = whpx_v4v_recv(
                    &proxy->context,
                    &((v4v_proxy_complete_read_t*) proxy->read_buffer)->datagram,
                    recv_req->buffer_len,
                    &proxy->recv_async);
                if (ret && ret != ERROR_IO_PENDING)
                    proxy_complete_read_with_error(proxy, ret); /* report error */
            }
            break;
        }
        case V4VPROXY_REQ_SEND: {
            /* incoming send from external app */
            v4v_proxy_req_send_t *send_req = (v4v_proxy_req_send_t*) req;
            v4v_proxy_context_t *proxy = get_proxy_context_for(send_req->from);
            v4v_proxy_pending_write_t *write;
            uint32_t datagram_len = send_req->datagram_len;

            assert(proxy);

#ifndef DEBUG_FORCE_DOM0_PARTNER
            send_req->datagram.addr.domain = WHPX_DOMAIN_ID_SELF;
#else
            send_req->datagram.addr.domain = 0;
#endif
            write = calloc(1, sizeof(v4v_proxy_pending_write_t));
            write->proxy = proxy;
            write->reqid = send_req->req.id;
            /* bookeep pending write */
            critical_section_enter(&proxy->write_lock);
            TAILQ_INSERT_TAIL(&proxy->writes, write, entry);
            critical_section_leave(&proxy->write_lock);
            whpx_v4v_async_init_cb(&proxy->context, &write->async, write,
                proxy_write_async_done);
            ret = whpx_v4v_send(&proxy->context, &send_req->datagram,
                datagram_len, &write->async);
            if (ret && ret != ERROR_IO_PENDING)
                proxy_complete_write_with_error(write, ret);
            break;
        }
        default:
            whpx_panic("unexpected req code: %d\n", req->op);
            break;
        }
        if (ret && ret != ERROR_IO_PENDING)
            debug_printf("error handling proxy req %d = %d\n", req->op, ret);
    }
}

extern WaitObjects v4v_virq_wait_objects;

void
whpx_v4v_proxy_init(void)
{
    v4v_proxy_register_backend_t reg;

    TAILQ_INIT(&proxies);
    critical_section_init(&proxies_lock);

    /* open connection to proxy driver */
    if (!_v4v_open(&proxy_channel, 0, V4V_FLAG_ASYNC, NULL))
      whpx_panic("failed to open proxy v4v channel: %d", (int)GetLastError());

    memcpy(&reg.partner, &v4v_idtoken, sizeof(reg.partner));
    if (!_v4v_proxy_register_backend(&proxy_channel, &reg, NULL))
        whpx_panic("failed to register backend: %d", (int)GetLastError());
    /* we'll run proxy request handler on v4v virq thread */
    ioh_add_wait_object (&proxy_channel.recv_event, proxy_request_received, NULL, &v4v_virq_wait_objects);

}
