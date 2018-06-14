/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENV4VPROXY_H_
#define _UXENV4VPROXY_H_

//#include <ntddk.h>
#define UNICODE

#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <sddl.h>
#include <stdarg.h>

#define XENV4V_DRIVER

#include <xen/types.h>

#include <public/xen.h>
#include <public/v4v.h>
#include "../uxenv4vlib/gh_v4vapi.h"

#define PROXY_POOL_TAG 'vprx'
#define V4V_DEVICE_NAME    L"\\Device\\xenv4v"
#define V4V_SYMBOLIC_NAME  L"\\DosDevices\\Global\\v4vdev"
#define V4V_USER_FILE_NAME L"\\\\.\\Global\\v4vdev"
#define V4V_BASE_FILE_NAME L"v4vdev"

#define XENV4V_MAGIC          0x228e471d
#define XENV4V_SYM_NAME_LEN   64
#define XENV4V_MAX_RING_LENGTH (4*1024*1024UL)

#define MAX_IRP_COUNT  65536

typedef struct proxy_extension {
    ULONG magic;
    ULONG32 refc;

    DEVICE_OBJECT *fdo;
    UNICODE_STRING symbolic_link;
    wchar_t symbolic_linkText[XENV4V_SYM_NAME_LEN];

    IO_REMOVE_LOCK remove_lock;

    LONG context_count;
    KSPIN_LOCK context_lock;
    LIST_ENTRY context_list;

    ULONG64 reqid;

    ULONG seed;

    LIST_ENTRY pending_irp_queue;
    LONG       pending_irp_count;
    KSPIN_LOCK queue_lock;
    IO_CSQ     csq_object;
} proxy_extension_t;

#define CTX_STATE_UNINITIALIZED 0
#define CTX_STATE_UNBOUND 1
#define CTX_STATE_BOUND 2
#define CTX_STATE_BOUND_BACKEND 3
#define CTX_STATE_CLOSED 4

typedef struct proxy_context {
    LIST_ENTRY le;
    ULONG32 refc;
    ULONG32 state;

    BOOLEAN admin_access;
    BOOLEAN backend;

    FILE_OBJECT *pfo_parent;
    KEVENT *rx_event;

    struct v4v_ring_id ring_id;
    v4v_idtoken_t token;
} proxy_context_t;

#define FDO_TO_EXT(devobj) ((proxy_extension_t*)((devobj)->DeviceExtension))
#define CSQ_TO_EXT(csq) ((CONTAINING_RECORD(csq, proxy_extension_t, csq_object)))

/* it's a read irp */
#define PROXY_IRP_FLAG_READ 1
/* it's a write irp */
#define PROXY_IRP_FLAG_WRITE 2
/* it's a bind irp */
#define PROXY_IRP_FLAG_BIND 4
/* irp has been queued for processing by backend uxendm */
#define PROXY_IRP_FLAG_WAIT_BACKEND 8

typedef struct proxy_qpeek {
    /* match by irp flags */
    uint32_t flags_on, flags_off;
    /* match by request id */
    uint64_t reqid;
    /* match by file context which owns the IRP */
    proxy_context_t *context;
    /* match by file context which has the backend currently processing pending IRP */
    proxy_context_t *backend_context;
} proxy_qpeek_t;

// 32-bit thunk IOCTLs
#if defined(_WIN64)
typedef struct v4v_init_values_32_struct {
    VOID *POINTER_32 rx_event;
    ULONG32 ring_length;
} v4v_init_values_32_t;
#endif

#define V4V_IOCTL_INITIALIZE_32 CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_INITIALIZE, METHOD_BUFFERED, FILE_ANY_ACCESS)

static __inline uint32_t
irp_get_flags(PIRP irp)
{
    return (uint32_t) (ULONG_PTR) irp->Tail.Overlay.DriverContext[0];
}

static __inline void
irp_add_flag(PIRP irp, uint32_t f)
{
    (uint32_t) (ULONG_PTR) irp->Tail.Overlay.DriverContext[0] |= f;
}

static __inline proxy_context_t *
irp_get_destination(PIRP irp)
{
    return (proxy_context_t*) irp->Tail.Overlay.DriverContext[1];
}

static __inline uint64_t
irp_get_reqid(PIRP irp)
{
    return (uint64_t) irp->Tail.Overlay.DriverContext[2];
}

static __inline void
irp_set_reqid(PIRP irp, uint64_t reqid)
{
    irp->Tail.Overlay.DriverContext[2] = (PVOID) (ULONG_PTR) reqid;
}

NTSTATUS simple_complete_irp(PIRP irp, NTSTATUS status);

NTSTATUS NTAPI csq_insert_irp_ex(PIO_CSQ csq, PIRP irp, PVOID unused);
VOID NTAPI csq_remove_irp(PIO_CSQ csq, PIRP irp);
PIRP NTAPI csq_peek_next_irp(PIO_CSQ csq, PIRP irp, PVOID peekContext);
VOID NTAPI csq_acquire_lock(PIO_CSQ csq, PKIRQL irqlOut);
VOID NTAPI csq_release_lock(PIO_CSQ csq, KIRQL irql);
VOID NTAPI csq_complete_canceled_irp(PIO_CSQ csq, PIRP irp);

#endif
