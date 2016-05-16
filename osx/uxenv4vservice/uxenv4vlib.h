/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENV4VLIB_H_
#define _UXENV4VLIB_H_

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <dispatch/dispatch.h>
#include <IOKit/IOKitLib.h>
#include <xen/v4v.h>

/* Quick usage guide:
 * - Link against the userlib, or compile uxenv4vlib.c into your application.
 *   Don't forget to link against IOKit.framework.
 *
 * - v4v_open_service() will connect to the kernel service (When done, to be
 *   closed with v4v_close())
 *
 * - v4v_bind() will create a ring of a specific size and on a specific port.
 *   One ring per kernel connection. If you need more, call v4v_open_service()
 *   again and v4v_bind() each one individually. If partner is V4V_DOMID_ANY,
 *   messages from anywhere will be accepted.
 *
 * - v4v_dispatch_source_create_receive() and v4v_dispatch_source_create_send()
 *   produce GCD dispatch sources on a specific queue which will fire when
 *   messages are received and when it might be a good time to retry a v4v send
 *   that previously failed with EAGAIN. Note that the kernel side can't tell
 *   what kind of notification it's getting via the V4V interrupt, so a send may
 *   fail with EAGAIN in the send event handler. You'll need to set handlers
 *   etc. on the sources and resume them, as with any dispatch source.
 *
 * - Alternatively, if not using GCD or runloops, v4v_get_send_port() and
 *   v4v_get_receive_port() will yield equivalent Mach ports which can be used
 *   with kqueue/kevent. (this is what uxendm uses)
 *
 * - v4v_sendto() is similar to socket send.
 *
 * - v4v_recvmsg() is a handy wrapper similar to socket recv, for reading a
 *   message from a bound ring. Keep reading messages until there are none
 *   left. (return value < 0)
 *
 * - v4v_recv is an even more basic wrapper for v4v_recvmsg().
 *
 * - Alternatively, you can also get direct access to ring memory using
 *   v4v_get_mapped_ring() (this is mapped right into user address space). The
 *   v4v_ring_t pointer returned from the latter can be used with the generic
 *   xen v4v ring functions. You'll need this if you want to read out parts of
 *   messages, etc. If using the v4v_ring_t directly, call v4v_notify() when
 *   you're done reading messages to notify the sender in case it's waiting to
 *   send more. The more high level v4v_recvmsg() will already do this for you.
 */

typedef struct v4v_channel {
    struct _v4v_channel *_c;
} v4v_channel_t;

static const unsigned V4V_DATAGRAM_FLAG_IGNORE_DLO = (1u << 0);

#ifdef __cplusplus
extern "C" {
#endif

errno_t _v4v_open_service(v4v_channel_t *channel);
bool _v4v_open(v4v_channel_t *channel);
#define _v4v_opened(c) ((c)->_c != NULL)
dispatch_source_t _v4v_dispatch_source_create_receive(v4v_channel_t *channel,
                                                      dispatch_queue_t queue);
dispatch_source_t _v4v_dispatch_source_create_send(v4v_channel_t *channel,
                                                   dispatch_queue_t queue);
void _v4v_close(v4v_channel_t *channel);

errno_t _v4v_bind(v4v_channel_t *channel, uint32_t ring_len,
                  uint32_t local_port, domid_t partner);
v4v_ring_t *_v4v_get_mapped_ring(v4v_channel_t *channel);

ssize_t _v4v_recv(v4v_channel_t *channel, void *buf, size_t len);
ssize_t _v4v_recvmsg(v4v_channel_t *channel, v4v_addr_t *out_from_addr,
                     uint32_t *protocol, void *buf, size_t len, bool consume);

ssize_t _v4v_sendto(v4v_channel_t *channel, v4v_addr_t dest,
                    const void *buf, size_t len, unsigned flags);

errno_t _v4v_notify(v4v_channel_t *channel);

mach_port_t _v4v_get_receive_port(v4v_channel_t *channel);
mach_port_t _v4v_get_send_port(v4v_channel_t *channel);

#define v4v_open_service(channel) _v4v_open_service(channel)
#define v4v_open(channel) _v4v_open(channel)
#define v4v_opened(channel) _v4v_opened(channel)
#define v4v_dispatch_source_create_receive(channel, queue)      \
    _v4v_dispatch_source_create_receive(channel, queue)
#define v4v_dispatch_source_create_send(channel, queue) \
    _v4v_dispatch_source_create_send(channel, queue)
#define v4v_close(channel) _v4v_close(channel)
#define v4v_bind(channel, ring_len, local_port, partner)        \
    _v4v_bind(channel, ring_len, local_port, partner)
#define v4v_get_mapped_ring(channel) _v4v_get_mapped_ring(channel)
#define v4v_recv(channel, buf, len) _v4v_recv(channel, buf, len)
#define v4v_recvmsg(channel, out_from_addr, protocol, buf, len, consume) \
    _v4v_recvmsg(channel, out_from_addr, protocol, buf, len, consume)
#define v4v_sendto(channel, dest, buf, len, flags)      \
    _v4v_sendto(channel, dest, buf, len, flags)
#define v4v_notify(channel) _v4v_notify(channel)
#define v4v_get_receive_port(channel) _v4v_get_receive_port(channel)
#define v4v_get_send_port(channel) _v4v_get_send_port(channel)

#ifdef __cplusplus
}
#endif

#endif /* _UXENV4VLIB_H_ */
