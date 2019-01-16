/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/dm.h>
#include <dm/hw/uxen_v4v.h>
#include <echo-common.h>

struct echo_msg {
    v4v_datagram_t dg;
    struct uxenecho_msg msg;
};

struct conn {
    v4v_context_t v4v;
    int port;
    uint32_t partner_id;
    HANDLE tx_event;
    v4v_async_t async;
    v4v_ring_t *ring;
    Timer *timeout_timer;
    uint64_t last_id;
    struct echo_msg msg;
    int open;
};

static struct conn conns[2];

static Timer *hb_timer;
static uint64_t hb_message_id;

static void
hb_timer_run(void *opaque)
{
    int i, err;

    /* ping kernel & userspace */
    for (i = 0; i < 2; i++) {
        struct conn *c = &conns[i];

        dm_v4v_async_init(&c->v4v, &c->async, c->tx_event);

        memset(&c->msg, 0, sizeof(c->msg));
        c->msg.dg.addr.port = c->port;
        c->msg.dg.addr.domain = c->partner_id;
        c->msg.dg.flags = 0; //V4V_DATAGRAM_FLAG_IGNORE_DLO;
        c->msg.msg.id = hb_message_id;
        c->last_id = hb_message_id;
        err = dm_v4v_send(&c->v4v, (v4v_datagram_t*)&c->msg, sizeof(c->msg), &c->async);
        if (err && err != ERROR_IO_PENDING)
            debug_printf("hbmon: error sending echo ping%d: %d\n", i, err);
        else
            mod_timer(c->timeout_timer, get_clock_ms(vm_clock) + hbmon_timeout_period);
    }

    hb_message_id++;
    mod_timer(hb_timer, get_clock_ms(vm_clock) + hbmon_period);
}

static void
timeout_timer_run(void *opaque)
{
    struct conn *c = opaque;

    debug_printf("hbmon: TIMEOUT on port %d, last id=%"PRId64"\n",
        c->port, c->last_id);
}

static void
handle_recv_event(void *opaque)
{
    struct conn *c = opaque;
    uint32_t proto;
    struct echo_msg msg;
    int len;

    len = v4v_copy_out(c->ring, &msg.dg.addr, &proto,
        ((char*)&msg) + sizeof(v4v_datagram_t),
        sizeof(msg) - sizeof(v4v_datagram_t),
        1);
    if (len) {
        /* ack it */
        del_timer(c->timeout_timer);

        if (hbmon_verbose)
            debug_printf("hbmon: reponse on port %d, id=%"PRId64"\n",
                c->port, msg.msg.id);
    }
}

static int
hbmon_open_conn(struct conn *c, int port)
{
    v4v_bind_values_t bind = { };
    int err;

    err = dm_v4v_open(&c->v4v, UXEN_ECHO_RING_SIZE);
    if (err) {
        debug_printf("%s: failed to open v4v (%x)\n",
            __FUNCTION__, err);
        return -1;
    }

    bind.ring_id.addr.port = port;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_UUID;
    memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));

    err = dm_v4v_bind(&c->v4v, &bind);
    if (err) {
        debug_printf("%s: failed to bind v4v (%x)\n",
            __FUNCTION__, err);
        dm_v4v_close(&c->v4v);
        return -1;
    }

    err = dm_v4v_ring_map(&c->v4v, &c->ring);
    if (!c->ring) {
        debug_printf("%s: failed to map v4v ring (%x)\n",
            __FUNCTION__, err);
        dm_v4v_close(&c->v4v);
        return -1;
    }
    c->port = port;
    c->partner_id = bind.ring_id.partner;

    c->timeout_timer = new_timer_ms(vm_clock, timeout_timer_run, c);
    if (!c->timeout_timer) {
        debug_printf("%s: failed to create timeout timer\n",
            __FUNCTION__);
        dm_v4v_close(&c->v4v);
        return -1;
    }
    c->tx_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!c->tx_event) {
        debug_printf("%s: failed to create event\n",
            __FUNCTION__);
        free_timer(c->timeout_timer);
        dm_v4v_close(&c->v4v);
        return -1;
    }

    ioh_add_wait_object (&c->v4v.recv_event, handle_recv_event, c, NULL);

    c->open = 1;

    return 0;
}

static void
hbmon_cleanup_conn(struct conn *c)
{
    if (c->open) {
        free_timer(c->timeout_timer);
        ioh_del_wait_object(&c->v4v.recv_event, NULL);
        dm_v4v_close(&c->v4v);
        CloseHandle(c->tx_event);
        c->open = 0;
    }
}

void
hbmon_ping(void)
{
    hb_timer_run(NULL);
}

int
hbmon_init(void)
{
    int err;

    if (!hbmon_period || vm_restore_mode == VM_RESTORE_TEMPLATE)
        return 0;

    debug_printf("initializing heartbeat monitor\n");

    memset(conns, 0, sizeof(conns));
    err = hbmon_open_conn(&conns[0], UXEN_ECHO_PORT);
    if (err)
        goto error;
    err = hbmon_open_conn(&conns[1], UXEN_ECHO_US_PORT);
    if (err)
        goto error;
    hb_timer = new_timer_ms(vm_clock, hb_timer_run, NULL);
    if (!hb_timer) {
        debug_printf("%s: failed to create hb_timer\n",
            __FUNCTION__);
        goto error;
    }

    mod_timer(hb_timer, get_clock_ms(vm_clock) + hbmon_period);

    return 0;

error:
    hbmon_cleanup_conn(&conns[0]);
    hbmon_cleanup_conn(&conns[1]);

    return -1;
}

void
hbmon_cleanup(void)
{
    if (hb_timer)
        free_timer(hb_timer);
    hbmon_cleanup_conn(&conns[0]);
    hbmon_cleanup_conn(&conns[1]);
}
