/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __UXENV4VLIB_H__
#define __UXENV4VLIB_H__

#ifndef XENV4V_DRIVER
typedef __int8 int8_t;
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef __int64 int64_t;

typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#endif


#include <xen/xen.h>
#include <xen/v4v.h>

typedef uintptr_t (uxen_v4vlib_hypercall_func_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
typedef uintptr_t (uxen_v4vlib_page_notify_func_t)(uint64_t *, uint32_t, int);
struct v4v_ring;

typedef struct uxen_v4v_ring_handle_struct {
    struct v4v_ring *ring;
    struct xenv4v_ring_struct *ring_object;
}  uxen_v4v_ring_handle_t;

typedef void (uxen_v4v_callback_t)(uxen_v4v_ring_handle_t *, void *private_data1, void *private_data2);

#ifndef XENV4V_DRIVER

struct uxp_state_bar;

DECLSPEC_IMPORT LONG uxen_v4vlib_ring_refs;

/* Calls from upper drivers */
DECLSPEC_IMPORT void uxen_v4vlib_set_hypercall_func(uxen_v4vlib_hypercall_func_t *);
DECLSPEC_IMPORT void uxen_v4vlib_set_page_notify_func(uxen_v4vlib_page_notify_func_t *func);
DECLSPEC_IMPORT void uxen_v4vlib_set_state_bar_ptr(struct uxp_state_bar **a);
DECLSPEC_IMPORT void uxen_v4vlib_we_are_dom0(void);
DECLSPEC_IMPORT void uxen_v4vlib_deliver_signal (void);
DECLSPEC_IMPORT void uxen_v4vlib_init_driver(PDRIVER_OBJECT pdo);
DECLSPEC_IMPORT void uxen_v4vlib_free_driver(void );

DECLSPEC_IMPORT void uxen_v4vlib_init_driver_hook(PDRIVER_OBJECT pdo);
DECLSPEC_IMPORT void uxen_v4vlib_free_driver_unhook(void );

/*Calls from clients*/
DECLSPEC_IMPORT int uxen_v4v_ring_create(v4v_addr_t *dst, domid_t partner);
DECLSPEC_IMPORT uxen_v4v_ring_handle_t *uxen_v4v_ring_bind(uint32_t local_port, domid_t partner_domain, uint32_t ring_size, uxen_v4v_callback_t *callback, void *private_data1, void *private_data2);
DECLSPEC_IMPORT void uxen_v4v_ring_free(uxen_v4v_ring_handle_t *ring);

DECLSPEC_IMPORT ssize_t uxen_v4v_recv (uxen_v4v_ring_handle_t *ring, v4v_addr_t *from, void *buf, int buflen, uint32_t *protocol);
DECLSPEC_IMPORT ssize_t uxen_v4v_send_async(v4v_addr_t *src, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
DECLSPEC_IMPORT ssize_t uxen_v4v_sendv_async(v4v_addr_t *src, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
DECLSPEC_IMPORT ssize_t uxen_v4v_send_from_ring_async(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
DECLSPEC_IMPORT ssize_t uxen_v4v_sendv_from_ring_async(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
DECLSPEC_IMPORT BOOLEAN uxen_v4v_cancel_async(v4v_addr_t *dst, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
DECLSPEC_IMPORT ssize_t uxen_v4v_send(v4v_addr_t *src, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol);
DECLSPEC_IMPORT ssize_t uxen_v4v_sendv(v4v_addr_t *src, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol);
DECLSPEC_IMPORT ssize_t uxen_v4v_send_from_ring(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol);
DECLSPEC_IMPORT ssize_t uxen_v4v_sendv_from_ring(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol);
DECLSPEC_IMPORT void uxen_v4v_notify(void);
DECLSPEC_IMPORT void uxen_v4v_test(void);
DECLSPEC_IMPORT void uxen_v4v_poke(v4v_addr_t *dst);

DECLSPEC_IMPORT void uxen_v4vlib_unset_resume_dpc(KDPC *dpc, void *arg1);
DECLSPEC_IMPORT void uxen_v4vlib_set_resume_dpc(KDPC *dpc, void *arg1);


static V4V_INLINE ssize_t
uxen_v4v_copy_out (struct uxen_v4v_ring_handle_struct *r, struct v4v_addr *from, uint32_t *protocol,
                   void *_buf, size_t t, int consume)
{
    return v4v_copy_out(r->ring, from, protocol, _buf, t, consume);
}
#endif
#endif
