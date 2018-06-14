/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef V4V_PROXY_API_H_
#define V4V_PROXY_API_H_

#if defined(_MSC_VER)
#define PROXY_PACKED
#else
#define PROXY_PACKED __attribute__((packed))
#endif

/**
 * request codes for requests made from driver into v4v backend hosting process
 */
#define V4VPROXY_REQ_BIND 1
#define V4VPROXY_REQ_IS_BOUND 2
#define V4VPROXY_REQ_SEND 3
#define V4VPROXY_REQ_RECV 4

//// packed structs
#pragma pack(push, 1)

////////////////////////////////
//// DRIVER -> BACKEND requests
typedef struct v4v_proxy_req {
    uint32_t op;
    uint64_t id;
} PROXY_PACKED v4v_proxy_req_t;

typedef struct v4v_proxy_req_bind {
    v4v_proxy_req_t req;
    v4v_bind_values_t bind;
} PROXY_PACKED v4v_proxy_req_bind_t;

typedef struct v4v_proxy_req_send {
    v4v_proxy_req_t req;
    v4v_addr_t from; /* send from address */
    uint32_t datagram_len;
    v4v_datagram_t datagram;
} PROXY_PACKED v4v_proxy_req_send_t;

typedef struct v4v_proxy_req_recv {
    v4v_proxy_req_t req;
    v4v_addr_t from; /* receive from address */
    uint32_t buffer_len;
} PROXY_PACKED v4v_proxy_req_recv_t;

////////////////////////////////
///// BACKEND -> DRIVER requests
typedef struct v4v_proxy_register_backend {
    v4v_idtoken_t partner;
} PROXY_PACKED v4v_proxy_register_backend_t;

typedef struct v4v_proxy_is_bound {
    v4v_addr_t addr;
} PROXY_PACKED v4v_proxy_is_bound_t;

typedef struct v4v_proxy_complete_read {
    uint64_t reqid; /* request id being completed */
    uint32_t status;
    uint32_t datagram_len;
    v4v_datagram_t datagram;
} PROXY_PACKED v4v_proxy_complete_read_t;

typedef struct v4v_proxy_complete_write {
    uint64_t reqid; /* request id being completed */
    uint32_t status;
    uint32_t written;
} PROXY_PACKED v4v_proxy_complete_write_t;

typedef struct v4v_proxy_complete_bind {
    uint64_t reqid; /* request id being completed */
    uint32_t status;
    v4v_bind_values_t bind;
} PROXY_PACKED v4v_proxy_complete_bind_t;

#pragma pack(pop)
//// packed structs END

/**
 * proxy driver exposes same IOCTLs as regular v4v host driver; and additionaly
 * IOCTLs to register v4v backends and to query proxy requests, complete proxy requests etc */

/* start at 0x40 to not clash with regular v4v functions */
#define V4V_PROXY_FUNC_REGISTER_BACKEND 0x40
#define V4V_PROXY_FUNC_IS_BOUND 0x41
#define V4V_PROXY_FUNC_GET_REQ 0x42
#define V4V_PROXY_FUNC_COMPLETE_READ 0x43
#define V4V_PROXY_FUNC_COMPLETE_WRITE 0x44
#define V4V_PROXY_FUNC_COMPLETE_BIND 0x45

#define V4V_PROXY_IOCTL_REGISTER_BACKEND    CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_PROXY_FUNC_REGISTER_BACKEND, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define V4V_PROXY_IOCTL_IS_BOUND            CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_PROXY_FUNC_IS_BOUND, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define V4V_PROXY_IOCTL_GET_REQ             CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_PROXY_FUNC_GET_REQ, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define V4V_PROXY_IOCTL_COMPLETE_READ       CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_PROXY_FUNC_COMPLETE_READ, METHOD_NEITHER, FILE_ANY_ACCESS)
#define V4V_PROXY_IOCTL_COMPLETE_WRITE      CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_PROXY_FUNC_COMPLETE_WRITE, METHOD_NEITHER, FILE_ANY_ACCESS)
#define V4V_PROXY_IOCTL_COMPLETE_BIND       CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_PROXY_FUNC_COMPLETE_BIND, METHOD_NEITHER, FILE_ANY_ACCESS)

#endif
