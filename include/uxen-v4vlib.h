/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_V4VLIB_H_
#define _UXEN_V4VLIB_H_

#include <xen/xen.h>
#include <xen/v4v.h>

#include <linux/socket.h>
#define AF_VSOCK    40

struct sockaddr_vm {
    unsigned short family;
    domid_t partner;
    v4v_addr_t v4v;
    unsigned char zero[sizeof(struct sockaddr) -
    sizeof(unsigned short) - sizeof(unsigned short) -
    - sizeof(v4v_addr_t)];
};


//struct uxen_v4v_ring;
typedef struct uxen_v4v_ring uxen_v4v_ring_t;

typedef void (uxen_v4v_callback_t)(void *opaque);

static V4V_INLINE ssize_t
uxen_v4v_copy_out (struct uxen_v4v_ring *r, struct v4v_addr *from, u32 *protocol,
                   void *_buf, size_t t, int consume)
{
    return v4v_copy_out(*(v4v_ring_t **)r, from, protocol, _buf, t, consume);
}

static V4V_INLINE ssize_t
uxen_v4v_copy_out_offset (struct uxen_v4v_ring *r, struct v4v_addr *from,
                          u32 *protocol, void *_buf, size_t t, int consume,
                          size_t skip)
{
    return v4v_copy_out_offset(*(v4v_ring_t **)r, from, protocol, _buf, t,
							   consume, skip);
}

void uxen_v4v_ring_free (uxen_v4v_ring_t *ring);
uxen_v4v_ring_t *uxen_v4v_ring_bind(u32 local_port, domid_t partner_domain,
                                            u32 ring_size, uxen_v4v_callback_t *callback,
                                            void *callback_opaque);
ssize_t uxen_v4v_send_from_ring(uxen_v4v_ring_t *ring, v4v_addr_t *dst, void *buf,
                                u32 len, u32 protocol);
ssize_t uxen_v4v_sendv_from_ring(uxen_v4v_ring_t *ring, v4v_addr_t *dst, v4v_iov_t *iov,
                                 u32 niov, u32 protocol);
int uxen_v4v_notify(void);
int uxen_v4v_notify_space(domid_t dst_domain, u32 dst_port, u32 space_required, int *ok);

#endif
