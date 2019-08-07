/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __UXENV4VLIB_H__
#define __UXENV4VLIB_H__

#if defined(XENV4V_DRIVER) || defined(__UXEN__)
#include <public/xen.h>
#include <public/v4v.h>
#else
#include <xen/xen.h>
#include <xen/v4v.h>
#endif

typedef uintptr_t (uxen_v4vlib_hypercall_func_t)(
    uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
typedef uintptr_t (uxen_v4vlib_page_notify_func_t)(uint64_t *, uint32_t, int);

struct v4v_ring;
typedef struct uxen_v4v_ring_struct {
    struct v4v_ring *ring;
    uint32_t ring_length;
}  uxen_v4v_ring_t;

typedef struct uxen_v4v_ring_handle_struct {
    struct uxen_v4v_ring_struct *ring_object;
}  uxen_v4v_ring_handle_t;

typedef void (uxen_v4v_callback_t)(
    uxen_v4v_ring_handle_t *, void *private_data1, void *private_data2);

#define V4VLOG_ERROR 0
#define V4VLOG_WARNING 1
#define V4VLOG_INFO 2
#define V4VLOG_NOTICE 3
#define V4VLOG_VERBOSE 4

typedef void (*uxen_v4v_logger_t)(int lvl, const char *);

#ifdef XENV4V_DRIVER
#define V4V_DLL_DECL V4V_DLL_EXPORT
#else
#define V4V_DLL_DECL DECLSPEC_IMPORT
#endif

struct uxp_state_bar;

/* Calls from upper drivers */
V4V_DLL_DECL void uxen_v4vlib_set_hypercall_func(uxen_v4vlib_hypercall_func_t *);
V4V_DLL_DECL void uxen_v4vlib_set_page_notify_func(uxen_v4vlib_page_notify_func_t *func);
V4V_DLL_DECL void uxen_v4vlib_set_state_bar_ptr(struct uxp_state_bar **a);
V4V_DLL_DECL void uxen_v4vlib_we_are_dom0(void);
V4V_DLL_DECL void uxen_v4vlib_deliver_signal (void);
V4V_DLL_DECL void uxen_v4vlib_set_logger(uxen_v4v_logger_t logger);
V4V_DLL_DECL void uxen_v4vlib_init_driver(PDRIVER_OBJECT pdo);
V4V_DLL_DECL void uxen_v4vlib_free_driver(void );
V4V_DLL_DECL void uxen_v4vlib_set_thread_priority(LONG priority);

V4V_DLL_DECL void uxen_v4vlib_init_driver_hook(PDRIVER_OBJECT pdo);
V4V_DLL_DECL void uxen_v4vlib_free_driver_unhook(void );
V4V_DLL_DECL void uxen_v4vlib_start_device(void);

/*Calls from clients*/
V4V_DLL_DECL int uxen_v4v_ring_create(v4v_addr_t *dst, domid_t partner);
V4V_DLL_DECL uxen_v4v_ring_handle_t *uxen_v4v_ring_bind(uint32_t local_port, domid_t partner_domain, uint32_t ring_size, uxen_v4v_callback_t *callback, void *private_data1, void *private_data2);
V4V_DLL_DECL void uxen_v4v_ring_free(uxen_v4v_ring_handle_t *ring);

V4V_DLL_DECL ssize_t uxen_v4v_recv (uxen_v4v_ring_handle_t *ring, v4v_addr_t *from, void *buf, int buflen, uint32_t *protocol);
V4V_DLL_DECL ssize_t uxen_v4v_send_async(v4v_addr_t *src, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_DECL ssize_t uxen_v4v_sendv_async(v4v_addr_t *src, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_DECL ssize_t uxen_v4v_send_from_ring_async(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_DECL ssize_t uxen_v4v_sendv_from_ring_async(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_DECL BOOLEAN uxen_v4v_cancel_async(v4v_addr_t *dst, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_DECL ssize_t uxen_v4v_send(v4v_addr_t *src, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol);
V4V_DLL_DECL ssize_t uxen_v4v_sendv(v4v_addr_t *src, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol);
V4V_DLL_DECL ssize_t uxen_v4v_send_from_ring(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol);
V4V_DLL_DECL ssize_t uxen_v4v_sendv_from_ring(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol);
V4V_DLL_DECL void uxen_v4v_notify(void);
V4V_DLL_DECL void uxen_v4v_test(void);
V4V_DLL_DECL ssize_t uxen_v4v_poke(v4v_addr_t *dst);

V4V_DLL_DECL void uxen_v4vlib_unset_resume_dpc(KDPC *dpc, void *arg1);
V4V_DLL_DECL void uxen_v4vlib_set_resume_dpc(KDPC *dpc, void *arg1);

static V4V_INLINE struct v4v_ring *
uxen_v4v_ring(struct uxen_v4v_ring_handle_struct *r)
{
    return r->ring_object->ring;
}

static V4V_INLINE uint32_t
uxen_v4v_ring_length(struct uxen_v4v_ring_handle_struct *r)
{
    return r->ring_object->ring_length;
}

static V4V_INLINE ssize_t
uxen_v4v_copy_out (struct uxen_v4v_ring_handle_struct *r,
                   struct v4v_addr *from, uint32_t *protocol,
                   void *_buf, size_t t, int consume)
{
    return v4v_copy_out_safe(uxen_v4v_ring(r), uxen_v4v_ring_length(r),
                             from, protocol, _buf, t, consume);
}

static V4V_INLINE ssize_t
uxen_v4v_copy_out_offset (struct uxen_v4v_ring_handle_struct *r,
                          struct v4v_addr *from, uint32_t *protocol,
                          void *_buf, size_t t, int consume, size_t skip)
{
    return v4v_copy_out_offset(uxen_v4v_ring(r), uxen_v4v_ring_length(r),
                               from, protocol, _buf, t, consume, skip);
}

#endif  /* __UXENV4VLIB_H__ */
