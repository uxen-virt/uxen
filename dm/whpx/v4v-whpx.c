/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/hw/uxen_v4v.h>
#include <dm/whpx/whpx.h>
#include <dm/whpx/v4v-whpx.h>
#include <dm/whpx/v4v_err.h>

/* why no define in windows hdrs? */
#define ERROR_OPERATION_IN_PROGRESS 329

struct domain;

typedef struct v4v_pending_recv {
    bool pending;
    size_t buffer_size;
    v4v_datagram_t *datagram;
    v4v_async_t *async;
} v4v_pending_recv_t;

typedef struct v4v_pending_send {
    size_t size;
    v4v_datagram_t *datagram;
    v4v_async_t *async;

    TAILQ_ENTRY(v4v_pending_send) entry;
} v4v_pending_send_t;

/* list of open backend rings/connections */
typedef struct v4v_connection {
    critical_section pending_send_lock;
    critical_section pending_recv_lock;
    void *cb_opaque;
    void (*cb)(void*);
    v4v_ring_t *ring;
    v4v_context_t *context;
    v4v_pending_recv_t pending_recv;
    TAILQ_HEAD(, v4v_pending_send) pending_send;
    int num_pending;
    bool opened;
    uint32_t flags;
    TAILQ_ENTRY(v4v_connection) entry;
} v4v_connection_t;

static TAILQ_HEAD(, v4v_connection) connections;
static critical_section connections_lock;

static bool virq_thread_quit;
static bool virq_thread_running;
static struct io_handler_queue virq_io_handlers;
WaitObjects v4v_virq_wait_objects;
static uxen_thread virq_thread;
static ioh_event virq_ev;

extern int do_v4v_op_dom0(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10,
    uint64_t r9, uint64_t r8);

static inline v4v_connection_t *
context_conn(v4v_context_t *v4v)
{
    return (v4v_connection_t*)v4v->v4v_channel.v4v_handle;
}

static inline v4v_ring_t *
context_ring(v4v_context_t *v4v)
{
    return context_conn(v4v)->ring;
}

static void
pending_send_lock(v4v_context_t *v4v)
{
    critical_section_enter(&context_conn(v4v)->pending_send_lock);
}

static void
pending_send_unlock(v4v_context_t *v4v)
{
    critical_section_leave(&context_conn(v4v)->pending_send_lock);
}

static void
pending_recv_lock(v4v_context_t *v4v)
{
    critical_section_enter(&context_conn(v4v)->pending_recv_lock);
}

static void
pending_recv_unlock(v4v_context_t *v4v)
{
    critical_section_leave(&context_conn(v4v)->pending_recv_lock);
}

static void
connections_add(v4v_connection_t *c)
{
    critical_section_enter(&connections_lock);
    TAILQ_INSERT_TAIL(&connections, c, entry);
    critical_section_leave(&connections_lock);
}

static void
connections_del(v4v_connection_t *c)
{
    critical_section_enter(&connections_lock);
    TAILQ_REMOVE(&connections, c, entry);
    critical_section_leave(&connections_lock);
}

static uint32_t
get_send_values(v4v_datagram_t *dg,
    size_t write_size,
    v4v_addr_t *out_dst,
    uint8_t **out_msg,
    uint32_t *out_len,
    uint32_t *out_flags)
{
    assert(write_size >= sizeof(v4v_datagram_t));

    *out_dst = dg->addr;
    *out_flags = dg->flags;
    *out_msg = (uint8_t*)(dg+1);
    *out_len = write_size - sizeof(v4v_datagram_t);

    return V4V_PROTO_DGRAM;
}

void whpx_v4v_set_recv_callback(v4v_context_t *v4v, void *opaque, void (*cb)(void*))
{
    v4v_connection_t *conn = context_conn(v4v);
    conn->cb_opaque = opaque;
    conn->cb = cb;
}

static int
do_v4v_send(v4v_context_t *v4v, v4v_datagram_t *dgram, size_t size)
{
    uint32_t protocol, len, flags;
    v4v_addr_t dst;
    uint8_t *msg;
    int ret;

    protocol = get_send_values(dgram, size, &dst, &msg, &len, &flags);

    ret = do_v4v_op_dom0(V4VOP_send,
        (uint64_t) (uintptr_t) &context_ring(v4v)->id.addr,
        (uint64_t) (uintptr_t) &dst,
        (uint64_t) (uintptr_t) msg,
        len,
        protocol);
    if (ret == -ECONNREFUSED && !(flags & V4V_DATAGRAM_FLAG_IGNORE_DLO)) {
        /* try to create ring */
        v4v_ring_id_t id;

        id.addr.port = dst.port;
        id.addr.domain = dst.domain;
        id.partner = context_conn(v4v)->ring->id.partner;

        debug_printf("create DLO ring domain=%d port=%x\n",
            id.addr.domain, id.addr.port);
        ret = do_v4v_op_dom0(V4VOP_create_ring,
          (uint64_t) (uintptr_t) &id, 0, 0, 0, 0);
        if (ret) {
            debug_printf("failed to create DLO ring domain=%d port=%x, err=%d\n",
                id.addr.domain, id.addr.port, ret);
            ret = -ECONNREFUSED;
            return ret;
        }

        /* retry send */
        ret = do_v4v_op_dom0(V4VOP_send,
            (uint64_t) (uintptr_t) &context_ring(v4v)->id.addr,
            (uint64_t) (uintptr_t) &dst,
            (uint64_t) (uintptr_t) msg,
            len,
            protocol);
    }
    if (ret >= 0)
        ret += sizeof(v4v_datagram_t);

    return ret;
}

static v4v_connection_t *
connection_alloc(v4v_context_t *v4v, uint32_t ring_size, uint32_t flags)
{
    v4v_connection_t *conn;
    v4v_ring_t *r;

    /* ring needs to be aligned */
    r = VirtualAlloc(NULL, sizeof(v4v_ring_t) + ring_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!r)
        whpx_panic("out of memory");
    memset(r, 0, sizeof(*r));
    r->magic = V4V_RING_MAGIC;
    r->len = ring_size;

    conn = calloc(1, sizeof(v4v_connection_t));
    if (!conn)
        whpx_panic("out of memory");
    conn->context = v4v;
    conn->ring = r;
    conn->flags = flags;
    critical_section_init(&conn->pending_send_lock);
    critical_section_init(&conn->pending_recv_lock);
    TAILQ_INIT(&conn->pending_send);

    return conn;
}

static void
async_complete(v4v_async_t *async, int bytes)
{
    async->whpx.completed = 1;
    async->whpx.bytes = bytes;
    if (async->whpx.cb)
        async->whpx.cb(async->whpx.cb_opaque);
    if (async->whpx.ev)
        ioh_event_set(&async->whpx.ev);
}

static void
free_pending_send(v4v_pending_send_t *send)
{
    free(send->datagram);
    free(send);
}

static bool
try_complete_pending_recv(v4v_context_t *v4v, size_t *out_bytes)
{
    v4v_connection_t *conn = context_conn(v4v);
    v4v_pending_recv_t *recv = &conn->pending_recv;
    v4v_datagram_t *dg = recv->datagram;
    uint32_t protocol;
    bool completed = false;

    pending_recv_lock(v4v);

    if (!recv->pending)
        goto out;

    assert(recv->buffer_size >= sizeof(v4v_datagram_t));

    ssize_t len = v4v_copy_out (
        conn->ring, NULL,
        &protocol,
        NULL,
        0,
        0);

    if (len > 0) {
        size_t received;

        assert(len <= recv->buffer_size - sizeof(v4v_datagram_t));
        len = v4v_copy_out (conn->ring, &dg->addr,
            &protocol,
            dg + 1, /* copy past datagram struct */
            recv->buffer_size - sizeof(v4v_datagram_t),
            1);
        if (len > 0) {
            received = len + sizeof(v4v_datagram_t);
            if (out_bytes)
                *out_bytes = received;
            dg->flags = 0;
            /* async notification */
            if (recv->async)
                async_complete(recv->async, received);
            /* reset pending entry */
            memset(recv, 0, sizeof(*recv));

            completed = true;
        }
    }

out:
    pending_recv_unlock(v4v);

    return completed;
}

int
whpx_v4v_open(v4v_context_t *v4v, uint32_t ring_size, uint32_t flags)
{
    v4v_connection_t *conn;

    conn = connection_alloc(v4v, ring_size, flags);
    assert(conn);

    v4v->v4v_channel.v4v_handle = conn;

    v4v->v4v_channel.recv_event = CreateEvent(NULL, FALSE, FALSE, 0);
    assert(v4v->v4v_channel.recv_event);

    connections_add(conn);
    conn->opened = true;

    return 0;
}

void
whpx_v4v_close(v4v_context_t *v4v)
{
    v4v_connection_t *conn = context_conn(v4v);
    v4v_pending_send_t *send;
    int ret;

    if (conn) {
        connections_del(conn);

        v4v->v4v_channel.v4v_handle = NULL;

        CloseHandle(v4v->v4v_channel.recv_event);
        v4v->v4v_channel.recv_event = NULL;

        /* unregister ring */
        ret = do_v4v_op_dom0(V4VOP_unregister_ring, (uint64_t) (uintptr_t) conn->ring, 0,
            0, 0, 0);
        if (ret)
            debug_printf("unregister ring FAILED, error %d\n", ret);

        /* free pending sends */
        critical_section_enter(&conn->pending_send_lock);
        TAILQ_FOREACH(send, &conn->pending_send, entry)
            free_pending_send(send);
        critical_section_leave(&conn->pending_send_lock);

        critical_section_free(&conn->pending_send_lock);
        critical_section_free(&conn->pending_recv_lock);

        VirtualFree(conn->ring, 0, MEM_RELEASE);
        free(conn);
    }
}

#define MAX_NOTIFY_COUNT 64

/* host is notified about pending v4v data */
static void
whpx_v4v_handle_signal_work(void *opaque)
{
    v4v_connection_t *c;
    v4v_context_t *notify[MAX_NOTIFY_COUNT];
    int notify_count = 0;
    int i;

    if (virq_thread_quit)
        return;

    ioh_event_reset(&virq_ev);

    critical_section_enter(&connections_lock);
    TAILQ_FOREACH(c, &connections, entry) {
        if (c->ring->tx_ptr != c->ring->rx_ptr) {
            /* callback variant is usually faster than event signalling variant */
            if (c->cb) {
                c->cb(c->cb_opaque);
            } else {
                if (c->pending_recv.pending)
                    try_complete_pending_recv(c->context, NULL);
                else
                    ioh_event_set(&c->context->v4v_channel.recv_event);
            }
        }
        assert(notify_count < MAX_NOTIFY_COUNT);
        notify[notify_count++] = c->context;
    }

    for (i = 0; i < notify_count; i++)
        whpx_v4v_notify(notify[i]);

    critical_section_leave(&connections_lock);
}

static DWORD WINAPI
virq_thread_run(void *opaque)
{
    while (!virq_thread_quit) {
        int timeout = 1000;
        ioh_wait_for_objects(&virq_io_handlers, &v4v_virq_wait_objects, NULL, &timeout, NULL);
    }

    return 0;
}

void
whpx_v4v_handle_signal(void)
{
    whpx_v4v_handle_signal_work(NULL);
}

int
whpx_v4v_bind(v4v_context_t *v4v, v4v_bind_values_t *bind)
{
    v4v_ring_t *r = context_ring(v4v);

    r->id = bind->ring_id;
    assert(r->id.addr.port != V4V_PORT_NONE);
    int ret = do_v4v_op_dom0(V4VOP_register_ring, (uint64_t) (uintptr_t) r, 0,
        (uint64_t) (uintptr_t) &bind->partner, 1, 0);

    if (ret)
        return ret;

    /* return updated partner id to caller */
    bind->ring_id.partner = r->id.partner;

    return 0;
}

int
whpx_v4v_ring_map(v4v_context_t *v4v, v4v_ring_t **out_ring)
{
    *out_ring = context_ring(v4v);

    return 0;
}

static int
whpx_v4v_queue_send(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t size, v4v_async_t *async)
{
    v4v_connection_t *conn = context_conn(v4v);
    v4v_pending_send_t *pending = calloc(1, sizeof(v4v_pending_send_t));

    if (!pending)
        whpx_panic("out of memory");

    pending->datagram = malloc(size);
    if (!pending->datagram)
        whpx_panic("out of memory");
    memcpy(pending->datagram, dgram, size);
    pending->size = size;
    pending->async = async;

    pending_send_lock(v4v);
    TAILQ_INSERT_TAIL(&conn->pending_send, pending, entry);
    conn->num_pending++;
    pending_send_unlock(v4v);

    return 0;
}

static v4v_ring_data_t *
copy_destination_ring_data(v4v_context_t *v4v)
{
    v4v_connection_t *conn = context_conn(v4v);
    v4v_ring_data_t *data;
    v4v_pending_send_t *p;
    int n, i;

    pending_send_lock(v4v);
    n = conn->num_pending;
    if (!n) {
        pending_send_unlock(v4v);
        return NULL;
    }

    data = calloc(1, sizeof(v4v_ring_data_t) + n * sizeof(v4v_ring_data_ent_t));
    if (!data)
        whpx_panic("out of memory");
    data->magic = V4V_RING_DATA_MAGIC;

    i = 0;
    TAILQ_FOREACH(p, &conn->pending_send, entry) {
        if (i >= n)
            break;
        data->data[i].ring = p->datagram->addr;
        data->data[i].space_required = p->size;
    }
    data->nent = n;

    pending_send_unlock(v4v);

    return data;
}

static v4v_pending_send_t *
remove_next_pending(v4v_context_t *v4v, v4v_addr_t dst)
{
    v4v_connection_t *conn = context_conn(v4v);
    v4v_pending_send_t *p, *next;

    TAILQ_FOREACH_SAFE(p, &conn->pending_send, entry, next) {
        if (!memcmp(&dst, &p->datagram->addr, sizeof(dst))) {
            TAILQ_REMOVE(&conn->pending_send, p, entry);

            return p;
        }
    }

    return NULL;
}

static void
resend_to(v4v_context_t *v4v, v4v_ring_data_ent_t *entry)
{
    v4v_connection_t *conn = context_conn(v4v);
    v4v_pending_send_t *next;
    int counter = 0;

    pending_send_lock(v4v);

    do {
        next = remove_next_pending(v4v, entry->ring);
        if (!next)
            break;
        // In the case of the first write, check the flag to see if the next size we reported will
        // fit at this point, if not then end here. If we get the first item in then we can just try
        // subsequent writes. If any fail with retry, we will get an interrupt later.
        if (((entry->flags & V4V_RING_DATA_F_EXISTS) != 0) && (counter == 0) &&
            ((entry->flags & V4V_RING_DATA_F_SUFFICIENT) == 0)) {
            // requeue
            TAILQ_INSERT_TAIL(&conn->pending_send, next, entry);
            break;
        }

        pending_send_unlock(v4v);
        int ret = do_v4v_send(v4v, next->datagram, next->size);
        pending_send_lock(v4v);

        if (ret == -EAGAIN) {
            // requeue
            TAILQ_INSERT_TAIL(&conn->pending_send, next, entry);
            break;
        } else if (ret >= 0) {
            /* success */
            if (next->async)
                async_complete(next->async, ret);
            conn->num_pending--;
            free_pending_send(next);
        } else {
            /* fail */
            if (next->async)
                async_complete(next->async, ret);
            conn->num_pending--;
            free_pending_send(next);
        }

        counter++;
    } while (true);

    pending_send_unlock(v4v);
}

bool
whpx_v4v_notify(v4v_context_t *v4v)
{
    v4v_ring_data_t *ring_data;
    int count;
    int i;

    ring_data = copy_destination_ring_data(v4v);

    if (!ring_data)
        return false;

    count = ring_data->nent;

    // Now do the actual notify
    int ret =  do_v4v_op_dom0(V4VOP_notify,
        (uint64_t) (uintptr_t) ring_data, 0, 0, 0, 0);
    if (ret) {
        free(ring_data);
        return false;
    }

    for (i = 0; i < count; i++)
        resend_to(v4v, &ring_data->data[i]);

    free(ring_data);

    return true;
}

int
whpx_v4v_async_init(v4v_context_t *ctx, v4v_async_t *async, ioh_event ev)
{
    memset(async, 0, sizeof(v4v_async_t));
    async->context = ctx;
    async->whpx.ev = ev;

    return 0;
}

int
whpx_v4v_async_init_cb(v4v_context_t *ctx, v4v_async_t *async,
    void *opaque, void (*cb)(void *))
{
    memset(async, 0, sizeof(v4v_async_t));
    async->context = ctx;
    async->whpx.cb = cb;
    async->whpx.cb_opaque = opaque;

    return 0;
}

bool
whpx_v4v_async_is_completed(v4v_async_t *async)
{
    return async->whpx.completed || async->whpx.cancelled;
}

int
whpx_v4v_async_get_result(v4v_async_t *async, size_t *bytes, bool wait)
{
    int ret;
    v4v_context_t *v4v = async->context;
    v4v_connection_t *conn = context_conn(v4v);

    if (!v4v->v4v_channel.v4v_handle || !conn->opened)
        return ERROR_VC_DISCONNECTED;

    while (!whpx_v4v_async_is_completed(async)) {
        if (!wait)
            return ERROR_IO_INCOMPLETE;

        if (!v4v->v4v_channel.v4v_handle || !conn->opened)
            return ERROR_VC_DISCONNECTED;

        ret = (int) WaitForSingleObject(async->whpx.ev, INFINITE);
        if (ret != WAIT_OBJECT_0)
            whpx_panic("unexpected wait result: %d\n", ret);
    }

    if (async->whpx.cancelled)
        return ERROR_OPERATION_ABORTED;

    if (bytes)
        *bytes = async->whpx.bytes;

    return 0;
}

int
whpx_v4v_async_cancel(v4v_async_t *async)
{
    async->whpx.cancelled = 1;
    if (async->whpx.ev)
        ioh_event_set(&async->whpx.ev);

    return 0;
}

int
whpx_v4v_send(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t size, v4v_async_t *async)
{
    if (!v4v->v4v_channel.v4v_handle || !context_conn(v4v)->opened)
        return ERROR_VC_DISCONNECTED;

    int ret = do_v4v_send(v4v, dgram, size);

    if (ret == -EAGAIN) {
        whpx_v4v_queue_send(v4v, dgram, size, async);
        return ERROR_IO_PENDING;
    }
    if (ret < 0) {
        debug_printf("whpx_v4v_send failed: %d\n", ret);
        switch (ret) {
        case -ECONNREFUSED:
            return ERROR_VC_DISCONNECTED;
        default:
            return ERROR_GEN_FAILURE;
        }
    }
    if (async)
        async_complete(async, ret);

    return 0;
}

int
whpx_v4v_recv(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t buffer_size, v4v_async_t *async)
{
    v4v_connection_t *conn = context_conn(v4v);
    size_t received = 0;
    int err = 0;

    if (!v4v->v4v_channel.v4v_handle || !conn->opened)
        return ERROR_VC_DISCONNECTED;

    assert(buffer_size >= sizeof(v4v_datagram_t));

    pending_recv_lock(v4v);

    if (conn->pending_recv.pending) {
        err = ERROR_OPERATION_IN_PROGRESS;
        goto out;
    }

    conn->pending_recv.pending = true;
    conn->pending_recv.datagram = dgram;
    conn->pending_recv.buffer_size = buffer_size;
    conn->pending_recv.async = async;

    if (!try_complete_pending_recv(v4v, &received))
        err = ERROR_IO_PENDING;

out:
    pending_recv_unlock(v4v);

    return err;
}

void v4v_early_init(void);

void
whpx_v4v_virq_start(void)
{
    if (!virq_thread_running) {
        virq_thread_quit = false;
        create_thread(&virq_thread, virq_thread_run, NULL);
        virq_thread_running = true;
        debug_printf("v4v virq running\n");
    }
}

void
whpx_v4v_virq_stop(void)
{
    if (virq_thread_running) {
        virq_thread_quit = true;
        ioh_event_set(&virq_ev);
        debug_printf("v4v virq stop\n");
        wait_thread(virq_thread);
        virq_thread_running = false;
        debug_printf("v4v virq stopped\n");
    }
}

void
whpx_v4v_init(void)
{
    v4v_early_init();

    TAILQ_INIT(&connections);

    critical_section_init(&connections_lock);

    ioh_event_init(&virq_ev);
    ioh_queue_init(&virq_io_handlers);
    ioh_init_wait_objects(&v4v_virq_wait_objects);
    ioh_add_wait_object(&virq_ev, whpx_v4v_handle_signal_work, NULL, &v4v_virq_wait_objects);
    whpx_v4v_virq_start();
}

void
whpx_v4v_shutdown(void)
{
    whpx_v4v_virq_stop();
    ioh_cleanup_wait_objects(&v4v_virq_wait_objects);
    ioh_event_close(&virq_ev);
}
