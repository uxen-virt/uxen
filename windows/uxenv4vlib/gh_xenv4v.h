/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * uXen changes:
 *
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if !defined(_XENV4V_H_)
#define _XENV4V_H_

#pragma warning(disable: 4127) // conditional expression is constant
#pragma warning(disable: 4201)

#include "gh_v4vapi.h"

// define hypercall hooks
#define XENV4V_TAG 'v4vx'

// Allow for clients using the older DOMID_INVALID value
#define DOMID_INVALID_COMPAT (0x7FFFU)

#define XENV4V_ADDR_COMPARE(a, b) ((a.port == b.port)&&(a.domain == b.domain))
#define XENV4V_LARGEINT_DELAY(ms) (ULONG64) -(10000 * ((LONG32) (ms)))
#define XENV4V_SET_BOOL_PTR(b) if (b != NULL) {*b = TRUE;}
#define XENV4V_CLEAR_BOOL_PTR(b) if (b != NULL) {*b = FALSE;}

//#define XENV4V_NO_PROTOCOL_CHECK
#if defined(XENV4V_NO_PROTOCOL_CHECK) && defined(DBG)
#define XENV4V_PROTOCOL_TEST(p, v) (TRUE)
#else
#define XENV4V_PROTOCOL_TEST(p, v) (p == v)
#endif

//#define XENV4V_ENABLE_RWTRACE
#if defined(XENV4V_ENABLE_RWTRACE) && defined(DBG)
#define TraceReadWrite(_X_) __XenTraceVerbose _X_
#else
#define TraceReadWrite(_X_)
#endif

//#define TraceReadWrite(a) do { DbgPrint a; } while (0)


#define XENV4V_WRITE_RO_PROTECT

// Structure used both to form a list of IRPs for the same destination and
// to store a destination record for each IRP. The same struc is used so
// that it can be pulled for both purposes from the same lookaside list.
typedef struct xenv4v_destination_struct {
    LIST_ENTRY le;
    ULONG32    refc;
    ULONG      nextLength;
    PIRP       nextIrp;
    BOOLEAN    dst_ax;
    v4v_addr_t dst;
} xenv4v_destination_t;

#define XENV4V_MAGIC          0x228e471d
#define XENV4V_SYM_NAME_LEN   64
#define XENV4V_MAX_IRP_COUNT  65536
#define XENV4V_TIMER_INTERVAL 1000 // ms

#define XENV4V_DEV_STOPPED   0x00000000
#define XENV4V_DEV_STARTED   0x00000001

struct xenv4v_prealloc_block;

typedef struct xenv4v_extension_struct {
    ULONG magic;
    ULONG refc;

    // Our fdo
    PDEVICE_OBJECT fdo;

    UNICODE_STRING symbolic_link;
    wchar_t symbolic_linkText[XENV4V_SYM_NAME_LEN];

    IO_REMOVE_LOCK remove_lock;

    // The device state flag
    LONG  state;

    // The last power state seen
    SYSTEM_POWER_STATE last_po_state;

    // Pooled allocations
    KSPIN_LOCK  alloc_lock;
    struct xenv4v_prealloc_block *prealloc_blocks;
    void *prealloc_area;

    // V4V interrupt
    PETHREAD    virq_thread;
    KEVENT      virq_event;
    LONG volatile virq_thread_running;
    KSPIN_LOCK  virq_lock;

    // Active file context list
    LIST_ENTRY context_list;
    KSPIN_LOCK context_lock;
    LONG       context_count;

    // Active ring object list
    LIST_ENTRY ring_list;
    KSPIN_LOCK ring_lock;
    LONG volatile ring_gen;

    // IRP queuing and cancel safe queues
    LIST_ENTRY pending_irp_queue;
    LONG       pending_irp_count;
    KSPIN_LOCK queue_lock;
    IO_CSQ     csq_object;
    LIST_ENTRY dest_list;
    LONG       dest_count;
    NPAGED_LOOKASIDE_LIST dest_lookaside_list;

    LIST_ENTRY notify_list;
    PETHREAD   notify_thread;
    KEVENT     notify_event;
    LONG volatile notify_thread_running;

    // Seed for generating random-ish numbers for ports and conids
    ULONG seed;

} xenv4v_extension_t;

#define xenv4v_ring_t_MULT 16

typedef struct xenv4v_ring_struct {
    // uxenv4vlib exposed Ring bits
    uxen_v4v_ring_t;

    // List and ref
    LIST_ENTRY le;
    ULONG32    refc:31;
    ULONG32    reflist:1;

    PMDL       mdl;
    void       *user_map;

    v4v_idtoken_t   partner;
    v4v_ring_id_t   id;

    // Access control
    BOOLEAN admin_access;

    // ax-based ring
    BOOLEAN ax;

    // Ring bits
    v4v_pfn_list_t *pfn_list;
    KSPIN_LOCK      lock;

    BOOLEAN registered;

    ULONG32 queue_length;

    BOOLEAN direct_access;  //If true ring is accessed using the methods in export.c  no context
    uxen_v4v_callback_t *callback;
    struct uxen_v4v_ring_handle_struct *uxen_ring_handle;
    PVOID   callback_data1;
    PVOID   callback_data2;

    //Set if the client is responsible for removing things
    //from the ring
    volatile BOOLEAN ring_is_mapped;
} xenv4v_ring_t;

#define XENV4V_INVALID_CONNID      0xffffffffffffffff

#define XENV4V_STATE_UNINITIALIZED 0x00000000
#define XENV4V_STATE_IDLE          0x00000001
#define XENV4V_STATE_BOUND         0x00000002
#define XENV4V_STATE_CLOSED        0x00001000

#define XENV4V_TYPE_UNSPECIFIED  0x00000000
#define XENV4V_TYPE_DATAGRAM     0x00000001


typedef struct xenv4v_data_struct {
    struct xenv4v_data_struct *next;
    UCHAR               *data;
    uint32_t             length;
} xenv4v_data_t;

typedef struct xenv4v_context_struct {
    // List and ref
    LIST_ENTRY le;
    ULONG32    refc;

    // State and type
    LONG state;

    // Access control
    BOOLEAN admin_access;

    // Ring pieces
    xenv4v_ring_t *ring_object;
    ULONG32      ring_length;

    // Event for user land receive notification
    KEVENT *receive_event;

    // A backpointer to the owning file object
    FILE_OBJECT *pfo_parent;

    // file flags
    ULONG32 flags;

    // Safe place to point 0 length write buffer pointers w/ NULL MDLs
    UCHAR safe[4];

} xenv4v_context_t;

// The queue peek values are used to provide peek information for finding IRPs.
#define XENV4V_PEEK_READ           0x01000000 // op
#define XENV4V_PEEK_WRITE          0x02000000 // op
#define XENV4V_PEEK_IOCTL          0x04000000 // op
#define XENV4V_PEEK_ANY_OP         0xffff0000 // op

typedef struct xenv4v_qpeek_struct {
    FILE_OBJECT *pfo;
    ULONG_PTR    ops;
    v4v_addr_t   dst;
} xenv4v_qpeek_t;

// 32-bit thunk IOCTLs
#if defined(_WIN64)
typedef struct v4v_init_values_32_struct {
    VOID *POINTER_32 rx_event;
    ULONG32 ring_length;
} v4v_init_values_32_t;
#endif

#define V4V_IOCTL_INITIALIZE_32 CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_INITIALIZE, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Dispatch Routines
DRIVER_DISPATCH gh_v4v_dispatch_create;
NTSTATUS NTAPI
gh_v4v_dispatch_create(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH gh_v4v_dispatch_cleanup;
NTSTATUS NTAPI
gh_v4v_dispatch_cleanup(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH gh_v4v_dispatch_close;
NTSTATUS NTAPI
gh_v4v_dispatch_close(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH gh_v4v_dispatch_device_control;
NTSTATUS NTAPI
gh_v4v_dispatch_device_control(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH gh_v4v_dispatch_read;
NTSTATUS NTAPI
gh_v4v_dispatch_read(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH gh_v4v_dispatch_write;
NTSTATUS NTAPI
gh_v4v_dispatch_write(PDEVICE_OBJECT fdo, PIRP irp);

// Cancel Safe Queue Routines
NTSTATUS NTAPI
gh_v4v_csq_insert_irp_ex(PIO_CSQ csq, PIRP irp, PVOID insertContext);

VOID NTAPI
gh_v4v_csq_remove_irp(PIO_CSQ csq, PIRP irp);

PIRP NTAPI
gh_v4v_csq_peek_next_irp(PIO_CSQ csq, PIRP irp, PVOID peekContext);

VOID NTAPI
gh_v4v_csq_acquire_lock(PIO_CSQ csq, PKIRQL irqlOut);

VOID NTAPI
gh_v4v_csq_release_lock(PIO_CSQ csq, KIRQL irql);

VOID NTAPI
gh_v4v_csq_complete_canceled_irp(PIO_CSQ csq, PIRP irp);

v4v_ring_data_t *
gh_v4v_copy_destination_ring_data(xenv4v_extension_t *pde, BOOLEAN ax, ULONG *gh_count);

VOID
gh_v4v_cancel_all_file_irps(xenv4v_extension_t *pde, FILE_OBJECT *pfo);

NTSTATUS
gh_v4v_process_notify(xenv4v_extension_t *pde);

VOID
gh_v4v_process_context_writes(xenv4v_extension_t *pde, xenv4v_context_t *ctx);

VOID
gh_v4v_process_context_reads_quick(xenv4v_extension_t *pde, xenv4v_context_t *ctx);

VOID
gh_v4v_process_context_reads(xenv4v_extension_t *pde, xenv4v_context_t *ctx);

VOID
gh_v4v_process_context_reads_quick(xenv4v_extension_t *pde, xenv4v_context_t *ctx);

// Hypercall Interface
NTSTATUS
gh_v4v_register_ring(xenv4v_extension_t *pde, xenv4v_ring_t *robj);

NTSTATUS
gh_v4v_unregister_ring(xenv4v_ring_t *robj);

NTSTATUS
gh_v4v_notify(v4v_ring_data_t *ringData, int ax);

NTSTATUS
gh_v4v_send(v4v_addr_t *src, v4v_addr_t *dest, int ax, ULONG32 protocol, VOID *buf, ULONG32 length, ULONG32 *writtenOut);

NTSTATUS
gh_v4v_send_vec(v4v_addr_t *src, v4v_addr_t *dest, int ax, v4v_iov_t *iovec, ULONG32 nent, ULONG32 protocol, ULONG32 *writtenOut);

// Ring Routines
xenv4v_ring_t *
gh_v4v_allocate_ring(uint32_t ring_length);

VOID
gh_v4v_link_to_ring_list(xenv4v_extension_t *pde, xenv4v_ring_t *robj);

ULONG32
gh_v4v_add_ref_ring(xenv4v_extension_t *pde, xenv4v_ring_t *robj);

ULONG32
gh_v4v_release_ring(xenv4v_extension_t *pde, xenv4v_ring_t *robj);

uint32_t
gh_v4v_random_port(xenv4v_extension_t *pde);

uint32_t
gh_v4v_spare_port_number(xenv4v_extension_t *pde, uint32_t port);

BOOLEAN
gh_v4v_ring_id_in_use(xenv4v_extension_t *pde, struct v4v_ring_id *id);

VOID
gh_v4v_recover_ring(xenv4v_context_t *ctx);

VOID
gh_v4v_dump_ring(v4v_ring_t *r);

// Context Routines
ULONG32
gh_v4v_add_ref_context(xenv4v_extension_t *pde, xenv4v_context_t *ctx);

ULONG32
gh_v4v_release_context(xenv4v_extension_t *pde, xenv4v_context_t *ctx);

xenv4v_context_t **
gh_v4v_get_all_contexts(xenv4v_extension_t *pde, ULONG *count_out);

VOID
gh_v4v_put_all_contexts(xenv4v_extension_t *pde, xenv4v_context_t **ctx_list, ULONG count);

// Inlines
static __inline size_t xenv4v_payload_data_len(IRP *i)
{
    size_t l;

    l = IoGetCurrentIrpStackLocation(i)->Parameters.Write.Length - sizeof(v4v_datagram_t);

    return l;
}

static __inline xenv4v_extension_t *
v4v_get_device_extension(PDEVICE_OBJECT fdo)
{
    xenv4v_extension_t *pde = (xenv4v_extension_t *)fdo->DeviceExtension;
    ASSERT(pde->magic == XENV4V_MAGIC);
    return pde;
}

static __inline xenv4v_extension_t *
v4v_csq_get_device_extension(PIO_CSQ csq)
{
    xenv4v_extension_t *pde = CONTAINING_RECORD(csq, xenv4v_extension_t, csq_object);
    ASSERT(pde->magic == XENV4V_MAGIC);
    return pde;
}

static __inline VOID
v4v_initialize_irp(PIRP irp)
{
    // Initialize the bits of the IRP we will use
    irp->Tail.Overlay.DriverContext[0] = NULL;
    irp->Tail.Overlay.DriverContext[1] = NULL;
    InitializeListHead(&irp->Tail.Overlay.ListEntry);
}

static __inline NTSTATUS
v4v_simple_complete_irp(PIRP irp, NTSTATUS status)
{
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}


#endif /*_XENV4V_H_*/
