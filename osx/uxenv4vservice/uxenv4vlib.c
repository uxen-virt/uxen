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

struct v4v_connection
{
    io_connect_t ring_connection;
    mach_port_t send_notification_port;
    mach_port_t receive_notification_port;
    v4v_ring_t* ring;
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
    mach_port_t port = v4v_notification_port_create();
    if (port == MACH_PORT_NULL) {
        return ENOMEM;
    }
    kern_return_t ret = IOConnectSetNotificationPort(
        v4v_ring_conn, type, port, 0 /* ref */);
    if (ret != KERN_SUCCESS)
    {
        mach_port_destroy(mach_task_self(), port);
        return ENODEV;
    }

    *out_port = port;
    return 0;
}

errno_t
v4v_open_service(v4v_connection_t *out_connection)
{
    io_service_t v4v_service;
    io_connect_t v4v_ring_conn = IO_OBJECT_NULL;
    kern_return_t ret;
    mach_port_t recv_port = MACH_PORT_NULL;
    mach_port_t send_port = MACH_PORT_NULL;
    errno_t err;
    v4v_connection_t conn;

    v4v_service = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching(V4V_SERVICE_CLASSNAME));
    if (v4v_service == IO_OBJECT_NULL) {
        return ENOENT;
    }

    ret = IOServiceOpen(
        v4v_service, mach_task_self(), 0 /* type */, &v4v_ring_conn);
    IOObjectRelease(v4v_service);
    if (ret != KERN_SUCCESS) {
        return ENODEV;
    } else {
        err = v4v_notification_port_create_and_set(
            v4v_ring_conn, kUxenV4VPort_ReceiveEvent, &recv_port);
        if (err == 0) {
            err = v4v_notification_port_create_and_set(
                v4v_ring_conn, kUxenV4VPort_SendEvent, &send_port);
            if (err != 0)
                mach_port_destroy(mach_task_self(), recv_port);
        }
        
        if (err != 0) {
            IOServiceClose(v4v_ring_conn);
            IOObjectRelease(v4v_service);
            return err;
        }
        
        conn = *out_connection = calloc(sizeof(*conn), 1);
        conn->ring_connection = v4v_ring_conn;
        conn->receive_notification_port = recv_port;
        conn->send_notification_port = send_port;
        return 0;
    }
}

bool
v4v_open(v4v_connection_t *out_context)
{

    return 0 == v4v_open_service(out_context);
}

dispatch_source_t
v4v_dispatch_source_create_receive(
    v4v_connection_t v4v_conn, dispatch_queue_t queue)
{

    if (v4v_conn->receive_notification_port == MACH_PORT_NULL)
        return NULL;
    dispatch_source_t port_source = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_MACH_RECV, v4v_conn->receive_notification_port,
        0, queue);
    return port_source;
}

dispatch_source_t
v4v_dispatch_source_create_send(
    v4v_connection_t v4v_conn, dispatch_queue_t queue)
{

    if (v4v_conn->send_notification_port == MACH_PORT_NULL)
        return NULL;
    dispatch_source_t port_source = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_MACH_RECV, v4v_conn->send_notification_port,
        0, queue);
    return port_source;
}

void
v4v_close(v4v_connection_t v4v_conn)
{

    if (v4v_conn->ring != NULL)
        IOConnectUnmapMemory64(
            v4v_conn->ring_connection, 0 /* type */, mach_task_self(),
            (uintptr_t)v4v_conn->ring);
    IOServiceClose(v4v_conn->ring_connection);
    mach_port_destroy(mach_task_self(), v4v_conn->receive_notification_port);
    mach_port_destroy(mach_task_self(), v4v_conn->receive_notification_port);
    free(v4v_conn);
}

ssize_t
v4v_sendto(
    v4v_connection_t v4v_conn, v4v_addr_t dest,
    const void *buf, size_t len, unsigned flags)
{
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
        v4v_conn->send_notification_port, 0 /* timeout */, MACH_PORT_NULL);
    
    ret = IOConnectCallMethod(
        v4v_conn->ring_connection, kUxenV4V_SendTo, inputs,
        sizeof(inputs)/sizeof(inputs[0]),
        buf, len, outputs, &num_outputs, NULL, NULL);
    if (ret != kIOReturnSuccess)
        outputs[0] = (int64_t)-EIO;
    return (ssize_t)outputs[0];
}

errno_t
v4v_bind(
    v4v_connection_t v4v_conn, uint32_t ring_len,
    uint32_t local_port, domid_t partner)
{
    uint64_t result = 0;
    kern_return_t ret;
    const uint64_t inputs[] = { ring_len, partner, local_port };
    uint32_t outputs = 1;

    if (v4v_conn->ring != NULL)
        return EINVAL;
    
    ret = IOConnectCallScalarMethod(
        v4v_conn->ring_connection, kUxenV4V_BindRing, inputs,
        sizeof(inputs)/sizeof(inputs[0]), &result, &outputs);

    if (ret != KERN_SUCCESS)
        return (errno_t)result;

    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    ret = IOConnectMapMemory64(v4v_conn->ring_connection, 0 /* type */,
        mach_task_self(), &address, &size, kIOMapAnywhere /* options*/);
    
    if (ret != KERN_SUCCESS || address == 0) {
        return ENOMEM;
    } else {
        v4v_conn->ring = (void*)address;
        v4v_conn->ring_size = size;
        v4v_conn->partner_domain = partner;
        return 0;
    }
}

ssize_t
v4v_recv(v4v_connection_t v4v_conn, void *buf, size_t len)
{
    v4v_addr_t addr = {};
    uint32_t protocol = 0;

    while (1) {
        ssize_t result = v4v_recvmsg(
            v4v_conn, &addr, &protocol, buf, len, true /*consume*/);
        if (result < 0)
            return result;
        if ((addr.domain == v4v_conn->partner_domain
             || v4v_conn->partner_domain == V4V_DOMID_ANY)
            && protocol == V4V_PROTO_DGRAM)
            return result;
    }
}

ssize_t
v4v_recvmsg(
    v4v_connection_t v4v_conn,
    v4v_addr_t *out_from_addr, uint32_t *out_protocol,
    void *buf, size_t len, bool consume)
{
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
        v4v_conn->receive_notification_port, 0 /* timeout */, MACH_PORT_NULL);
    
    if (v4v_conn->ring != NULL) {
        bytes_read = v4v_copy_out(
            v4v_conn->ring, &from, &protocol, buf, len, consume);
        if (bytes_read > 0 && v4v_ring_bytes_to_read(v4v_conn->ring) == 0) {
            /* the last message has been removed from the ring, notify the
             * sender in case it's waiting */
            v4v_notify(v4v_conn);
        }
        return bytes_read;
    } else {
        return -EIO;
    }
}

v4v_ring_t *
v4v_get_mapped_ring(v4v_connection_t v4v_conn)
{

    return v4v_conn->ring;
}

errno_t
v4v_notify(v4v_connection_t v4v_conn)
{
    uint64_t result = 0;
    uint32_t outputs = 1;

    (void)IOConnectCallMethod(
        v4v_conn->ring_connection, kUxenV4V_Notify, NULL, 0, NULL, 0, &result, &outputs, NULL, NULL);
    return (errno_t)result;
}

mach_port_t
v4v_get_receive_port(v4v_connection_t v4v_conn)
{

    return v4v_conn->receive_notification_port;
}

mach_port_t
v4v_get_send_port(v4v_connection_t v4v_conn)
{

    return v4v_conn->send_notification_port;
}

