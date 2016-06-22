/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include <stdint.h>
#include <string.h>
#include "uxenv4vlib.h"
#include "v4v_service_shared.h"
#include <mach/mach_port.h>
#include <IOKit/IOKitLib.h>
#include <sys/errno.h>
#include <stdio.h>

#define V4V_SERVICE_CLASSNAME "org_uxen_driver_v4v_service"

struct _v4v_channel {
    io_connect_t ring_connection;
    mach_port_t send_notification_port;
    mach_port_t receive_notification_port;
    v4v_ring_t *ring;
    size_t ring_size;
    domid_t partner_domain;
};

static mach_port_t
v4v_notification_port_create(void)
{
    mach_port_t port = MACH_PORT_NULL;
    mach_port_limits_t limits = {};
    mach_msg_type_number_t info_count = MACH_PORT_LIMITS_INFO_COUNT;

    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_get_attributes(
        mach_task_self(),
        port,
        MACH_PORT_LIMITS_INFO,
        (mach_port_info_t)&limits,
        &info_count);

    // only one entry in queue needed
    limits.mpl_qlimit = 1;

    mach_port_set_attributes(
        mach_task_self(),
        port,
        MACH_PORT_LIMITS_INFO,
        (mach_port_info_t)&limits,
        MACH_PORT_LIMITS_INFO_COUNT);

    return port;
}

static errno_t
v4v_notification_port_create_and_set(
    io_connect_t v4v_ring_conn, enum uxen_v4v_user_notification_port_type type,
    mach_port_t* out_port)
{
    mach_port_t port;
    kern_return_t ret;

    port = v4v_notification_port_create();
    if (port == MACH_PORT_NULL)
        return ENOMEM;

    ret = IOConnectSetNotificationPort(v4v_ring_conn, type, port, 0 /* ref */);
    if (ret != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), port);
        return ENODEV;
    }

    *out_port = port;
    return 0;
}

bool
_v4v_open(v4v_channel_t *_channel, uint32_t ring_size)
{
    io_service_t v4v_service;
    io_connect_t v4v_ring_conn = IO_OBJECT_NULL;
    kern_return_t ret;
    mach_port_t recv_port = MACH_PORT_NULL;
    mach_port_t send_port = MACH_PORT_NULL;
    errno_t err;
    struct _v4v_channel *channel;

    if (_channel == NULL) {
        errno = EINVAL;
        return false;
    }

    memset(_channel, 0, sizeof(*_channel));

    v4v_service = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching(V4V_SERVICE_CLASSNAME));
    if (v4v_service == IO_OBJECT_NULL) {
        errno = ENOENT;
        return false;
    }

    ret = IOServiceOpen(
        v4v_service, mach_task_self(), 0 /* type */, &v4v_ring_conn);
    IOObjectRelease(v4v_service);
    if (ret != KERN_SUCCESS) {
        errno = ENODEV;
        return false;
    }

    err = v4v_notification_port_create_and_set(
        v4v_ring_conn, kUxenV4VPort_ReceiveEvent, &recv_port);
    if (err == 0) {
        err = v4v_notification_port_create_and_set(
            v4v_ring_conn, kUxenV4VPort_SendEvent, &send_port);
        if (err != 0)
            mach_port_destroy(mach_task_self(), recv_port);
    }

    if (!err) {
        channel = _channel->_c = calloc(sizeof(*channel), 1);
        if (!channel)
            err = ENOMEM;
    }

    if (err != 0) {
        IOServiceClose(v4v_ring_conn);
        IOObjectRelease(v4v_service);
        errno = err;
        return false;
    }

    channel->ring_connection = v4v_ring_conn;
    channel->receive_notification_port = recv_port;
    channel->send_notification_port = send_port;
    channel->ring_size = ring_size;
    errno = 0;
    return true;
}

dispatch_source_t
_v4v_dispatch_source_create_receive(
    v4v_channel_t *_channel, dispatch_queue_t queue)
{
    struct _v4v_channel *channel = _channel->_c;
    dispatch_source_t port_source;

    if (channel->receive_notification_port == MACH_PORT_NULL)
        return NULL;

    port_source = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_MACH_RECV, channel->receive_notification_port,
        0, queue);
    return port_source;
}

dispatch_source_t
_v4v_dispatch_source_create_send(
    v4v_channel_t *_channel, dispatch_queue_t queue)
{
    struct _v4v_channel *channel = _channel->_c;
    dispatch_source_t port_source;

    if (channel->send_notification_port == MACH_PORT_NULL)
        return NULL;

    port_source = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_MACH_RECV, channel->send_notification_port,
        0, queue);
    return port_source;
}

void
_v4v_close(v4v_channel_t *_channel)
{
    struct _v4v_channel *channel = _channel->_c;

    if (channel->ring != NULL)
        IOConnectUnmapMemory64(
            channel->ring_connection, 0 /* type */, mach_task_self(),
            (uintptr_t)channel->ring);
    IOServiceClose(channel->ring_connection);
    mach_port_destroy(mach_task_self(), channel->receive_notification_port);
    mach_port_destroy(mach_task_self(), channel->receive_notification_port);
    free(channel);
}

ssize_t
_v4v_sendto(
    v4v_channel_t *_channel, v4v_addr_t dest,
    const void *buf, size_t len, unsigned flags)
{
    struct _v4v_channel *channel = _channel->_c;
    struct {
        mach_msg_header_t msgHdr;
        mach_msg_trailer_t trailer;
    } msg;
    uint64_t outputs[] = { 0 };
    uint32_t num_outputs = 1;
    uint64_t inputs[] = { dest.domain, dest.port, flags };
    kern_return_t ret;

    // clear any pending notification
    mach_msg(
        &msg.msgHdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg),
        channel->send_notification_port, 0 /* timeout */, MACH_PORT_NULL);

    ret = IOConnectCallMethod(
        channel->ring_connection, kUxenV4V_SendTo, inputs,
        sizeof(inputs)/sizeof(inputs[0]),
        buf, len, outputs, &num_outputs, NULL, NULL);
    if (ret != kIOReturnSuccess)
        outputs[0] = (int64_t)-EIO;
    return (ssize_t)outputs[0];
}

bool
_v4v_bind(
    v4v_channel_t *_channel, uint32_t local_port, domid_t partner)
{
    struct _v4v_channel *channel = _channel->_c;
    uint64_t result = 0;
    kern_return_t ret;
    const uint64_t inputs[] = { channel->ring_size, partner, local_port };
    uint32_t outputs = 1;
    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;

    if (channel->ring != NULL) {
        errno = EINVAL;
        return false;
    }

    ret = IOConnectCallScalarMethod(
        channel->ring_connection, kUxenV4V_BindRing, inputs,
        sizeof(inputs)/sizeof(inputs[0]), &result, &outputs);

    if (ret != KERN_SUCCESS) {
        errno = (errno_t)result;
        return false;
    }

    ret = IOConnectMapMemory64(channel->ring_connection, 0 /* type */,
        mach_task_self(), &address, &size, kIOMapAnywhere /* options*/);

    if (ret != KERN_SUCCESS || address == 0) {
        errno = ENOMEM;
        return false;
    }

    channel->ring = (void*)address;
    channel->partner_domain = partner;
    return true;
}

ssize_t
_v4v_recv(v4v_channel_t *_channel, void *buf, size_t len)
{
    struct _v4v_channel *channel = _channel->_c;
    v4v_addr_t addr = {};
    uint32_t protocol = 0;

    while (1) {
        ssize_t result = _v4v_recvmsg(
            _channel, &addr, &protocol, buf, len, true /*consume*/);
        if (result < 0)
            return result;
        if ((addr.domain == channel->partner_domain ||
             channel->partner_domain == V4V_DOMID_ANY) &&
            protocol == V4V_PROTO_DGRAM)
            return result;
    }
}

ssize_t
_v4v_recvmsg(
    v4v_channel_t *_channel,
    v4v_addr_t *out_from_addr, uint32_t *out_protocol,
    void *buf, size_t len, bool consume)
{
    struct _v4v_channel *channel = _channel->_c;
    struct {
        mach_msg_header_t msgHdr;
        mach_msg_trailer_t trailer;
    } msg;
    v4v_addr_t from = {};
    uint32_t protocol = 0;
    ssize_t bytes_read;

    // clear any pending notification
    mach_msg(
        &msg.msgHdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg),
        channel->receive_notification_port, 0 /* timeout */, MACH_PORT_NULL);

    if (channel->ring == NULL)
        return -EIO;

    bytes_read = v4v_copy_out(
        channel->ring, &from, &protocol, buf, len, consume);
    if (bytes_read > 0 && v4v_ring_bytes_to_read(channel->ring) == 0)
        /* the last message has been removed from the ring, notify the
         * sender in case it's waiting */
        _v4v_notify(_channel);
    return bytes_read;
}

v4v_ring_t *
_v4v_get_mapped_ring(v4v_channel_t *_channel)
{
    struct _v4v_channel *channel = _channel->_c;

    return channel->ring;
}

bool
_v4v_notify(v4v_channel_t *_channel)
{
    struct _v4v_channel *channel = _channel->_c;
    uint64_t result = 0;
    uint32_t outputs = 1;
    kern_return_t ret;

    ret = IOConnectCallMethod(
        channel->ring_connection, kUxenV4V_Notify, NULL, 0, NULL, 0,
        &result, &outputs, NULL, NULL);
    if (ret != kIOReturnSuccess)
        errno = EIO;
    else
        errno = (errno_t)result;
    return !errno;
}

mach_port_t
_v4v_get_receive_port(v4v_channel_t *_channel)
{
    struct _v4v_channel *channel = _channel->_c;

    return channel->receive_notification_port;
}

mach_port_t
_v4v_get_send_port(v4v_channel_t *_channel)
{
    struct _v4v_channel *channel = _channel->_c;

    return channel->send_notification_port;
}

