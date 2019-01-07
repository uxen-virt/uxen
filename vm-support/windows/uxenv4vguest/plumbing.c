/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vguest_private.h"
#include <whpx-shared.h>
#include <echo-common.h>

//#define ECHO_DEBUG

static void
guest_logger(int lvl, const char *str)
{
    (lvl);
    _printk(str);
}

static uintptr_t
v4v_hypercall(uintptr_t privileged,
              uintptr_t a1, uintptr_t a2, uintptr_t a3,
              uintptr_t a4, uintptr_t a5, uintptr_t a6)
{
    (void)privileged;
    return uxen_hypercall6(__HYPERVISOR_v4v_op, a1, a2, a3, a4, a5, a6);
}

static uintptr_t
whpx_v4v_hypercall(uintptr_t privileged,
              uintptr_t a1, uintptr_t a2, uintptr_t a3,
              uintptr_t a4, uintptr_t a5, uintptr_t a6)
{
    (void)privileged;
    return uxen_hypercall6(__WHPX_HYPERVISOR_v4v_op, a1, a2, a3, a4, a5, a6);
}

static void
echo_response_dpc(uxen_v4v_ring_handle_t *ring, void *ctx1, void *ctx2)
{
    v4v_addr_t from;
    uint32_t proto;
    struct uxenecho_msg msg;
    int len, err;

    UNREFERENCED_PARAMETER(ctx1);
    UNREFERENCED_PARAMETER(ctx2);

    for (;;) {
        len = uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 0);
        if (len <= 0 || len < sizeof(msg))
            break;
        uxen_v4v_copy_out(ring, &from, &proto, &msg, sizeof(msg), 1);
        uxen_v4v_notify();
#ifdef ECHO_DEBUG
        uxen_msg("echo: request id=%"PRId64" received", msg.id);
#endif
        /* send resp */
        err = uxen_v4v_send_from_ring(ring, &from, &msg, sizeof(msg),
            V4V_PROTO_DGRAM);
        if (err != len) {
            uxen_err("%s: failed to send echo response: %d\n", __FUNCTION__, err);
            break;
        }
    }
}

static void
echo_init(PDEVICE_EXTENSION ext)
{
    ext->EchoRing = uxen_v4v_ring_bind(UXEN_ECHO_PORT, V4V_DOMID_DM,
        UXEN_ECHO_RING_SIZE,
        echo_response_dpc, NULL, NULL);
    if (!ext->EchoRing) {
        uxen_err("%s: failed to bind v4v ring", __FUNCTION__);
        return;
    }
}

static void
echo_cleanup(PDEVICE_EXTENSION ext)
{
    uxen_v4v_ring_free(ext->EchoRing);
}

void uxen_v4v_guest_do_plumbing(PDRIVER_OBJECT pdo)
{
    uxen_v4vlib_set_logger(guest_logger);
    uxen_v4vlib_set_state_bar_ptr(uxen_get_state_bar_ptr());
    uxen_hypercall_init();
    if (!uxen_is_whp_present())
        uxen_v4vlib_set_hypercall_func(v4v_hypercall); /*This will trigger things is the above is correct*/
    else
        uxen_v4vlib_set_hypercall_func(whpx_v4v_hypercall);
    uxen_v4v_test();
    uxen_v4vlib_init_driver(pdo);
    uxen_v4vlib_start_device();
    echo_init(pdo->DeviceObject->DeviceExtension);
}


void uxen_v4v_guest_undo_plumbing(PDRIVER_OBJECT pdo)
{
    echo_cleanup(pdo->DeviceObject->DeviceExtension);
    uxen_v4vlib_free_driver();
    uxen_v4vlib_set_state_bar_ptr(NULL);
    uxen_v4vlib_set_hypercall_func(NULL);
}

