/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */
#include "proxy.h"
#include "version.h"
#include "log.h"
#include "proxy_lib.h"
#include "proxy_api.h"

#define ERROR_IO_PENDING 997
#define ERROR_VC_DISCONNECTED 240


NTSTATUS
DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING regpath);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif


//
// Initialize a security descriptor string. Refer to SDDL docs in the SDK
// for more info.
//
// System:          All access
// LocalService:    All access
// Administrators:  All access
// Interactive:     All access
//
static WCHAR g_win5Sddl[] = {
    SDDL_DACL SDDL_DELIMINATOR SDDL_PROTECTED

    SDDL_ACE_BEGIN
    SDDL_ACCESS_ALLOWED
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_GENERIC_ALL
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_LOCAL_SYSTEM
    SDDL_ACE_END

    SDDL_ACE_BEGIN
    SDDL_ACCESS_ALLOWED
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_GENERIC_ALL
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_LOCAL_SERVICE
    SDDL_ACE_END

    SDDL_ACE_BEGIN
    SDDL_ACCESS_ALLOWED
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_GENERIC_ALL
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_BUILTIN_ADMINISTRATORS
    SDDL_ACE_END

    SDDL_ACE_BEGIN
    SDDL_ACCESS_ALLOWED
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_GENERIC_ALL
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_INTERACTIVE
    SDDL_ACE_END
};

uxen_v4vproxy_logger_t proxy_logger = NULL;

// FIXME: should this be modified?
// {3a523e0a-9b28-46c9-9046-5aaaaf20e51d}
static const GUID GUID_SD_XENV4V_CONTROL_OBJECT =
{ 0x3a523e0a, 0x9b28, 0x46c9, { 0x90, 0x46, 0x5a, 0xaa, 0xaf, 0x20, 0xe5, 0x1d } };

static PDEVICE_OBJECT g_fdo;
static PDRIVER_OBJECT g_drvobj;

NTSTATUS
simple_complete_irp(PIRP irp, NTSTATUS status)
{
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

static void
initialize_irp(PIRP irp)
{
    // Initialize the bits of the IRP we will use
    irp->Tail.Overlay.DriverContext[0] = NULL;
    irp->Tail.Overlay.DriverContext[1] = NULL;
    irp->Tail.Overlay.DriverContext[2] = NULL;
    InitializeListHead(&irp->Tail.Overlay.ListEntry);
}

static void
cancel_all_file_irps(proxy_extension_t *pde, proxy_context_t *ctx)
{
    proxy_qpeek_t peek;
    IRP *pendingIrp;

    RtlZeroMemory(&peek, sizeof(peek));
    peek.context = ctx;

    pendingIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
    while (pendingIrp != NULL) {
        simple_complete_irp(pendingIrp, STATUS_CANCELLED);
        pendingIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
    }
}

static ULONG32
release_context(proxy_extension_t *pde, proxy_context_t *ctx, BOOLEAN lock)
{
    KLOCK_QUEUE_HANDLE  lqh = {0};
    ULONG32             count;
    FILE_OBJECT        *pfo;


    if (lock)
        KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);

    ASSERT(ctx->refc != 0); // SNO, really bad
    count = --ctx->refc;

    if (lock)
        KeReleaseInStackQueuedSpinLock(&lqh);

    // When the count goes to zero, clean it all up. We are out of the list so a lock is not needed.
    // N.B. if we end up doing any cleanup that cannot happen at DISPATCH, we will need a work item.
    if (count == 0) {
        pfo = ctx->pfo_parent;

        // Release the event
        if (ctx->rx_event != NULL)
            ObDereferenceObject(ctx->rx_event);
        // Free any that were requeued by the VIRQ handler at the last minute
        if (pfo)
            cancel_all_file_irps(pde, ctx);

        // Free context itself...
        ExFreePoolWithTag(ctx, PROXY_POOL_TAG);

        // Drop the reference the context held that prevents the final close
        if (pfo)
            ObDereferenceObject(pfo);
    }

    return count;
}

static void
link_to_context_list(proxy_extension_t *pde, proxy_context_t *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);

    // Add a reference for the list and up the counter
    ctx->refc++;
    pde->context_count++;

    // Link this context into the adapter list
    InsertHeadList(&pde->context_list, &(ctx->le));

    KeReleaseInStackQueuedSpinLock(&lqh);
}

static void
unlink_from_context_list(proxy_extension_t *pde, proxy_context_t *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
    RemoveEntryList(&ctx->le);
    release_context(pde, ctx, FALSE);
    // Drop the count when it gets removed from the list
    pde->context_count--;
    ASSERT(pde->context_count >= 0); // SNO, really bad
    KeReleaseInStackQueuedSpinLock(&lqh);
}


NTSTATUS
proxy_cleanup(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    proxy_extension_t *pde = FDO_TO_EXT(fdo);
    proxy_context_t *ctx;
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    FILE_OBJECT *pfo;

    pfo = isl->FileObject;

    ctx = (proxy_context_t *)pfo->FsContext;
    if (ctx != NULL) {
        InterlockedExchange(&ctx->state, CTX_STATE_CLOSED);

        // Drop it out of the list
        unlink_from_context_list(pde, ctx);

        // Release our ref count - if zero then the release routine will do the final cleanup
        release_context(pde, ctx, TRUE);
    } else {
        ERROR("cleanup file - no context associated with the file?!?");
        status = STATUS_UNSUCCESSFUL;
    }

    simple_complete_irp(irp, status);

    return status;

}


static NTSTATUS
add_device(PDRIVER_OBJECT drv)
{
    NTSTATUS          status = STATUS_SUCCESS;
    UNICODE_STRING    device_name;
    PDEVICE_OBJECT    fdo = NULL;
    proxy_extension_t *pde = NULL;
    BOOLEAN           symlink = FALSE;
    WCHAR            *szSddl = NULL;
    UNICODE_STRING    sddlString;
    HANDLE handle;

    VERBOSE("----->");

    do {
        // Create our device
        RtlInitUnicodeString(&device_name, V4V_DEVICE_NAME);
        szSddl = g_win5Sddl;
        RtlInitUnicodeString(&sddlString, szSddl);

        status =
            IoCreateDeviceSecure(drv,
                                 sizeof(proxy_extension_t),
                                 &device_name,
                                 FILE_DEVICE_UNKNOWN,
                                 FILE_DEVICE_SECURE_OPEN,
                                 FALSE,
                                 &sddlString,
                                 (LPCGUID)&GUID_SD_XENV4V_CONTROL_OBJECT,
                                 &fdo);
        if (!NT_SUCCESS(status)) {
            ERROR("IoCreateDeviceSecure failed error 0x%x", status);
            fdo = NULL;
            break;
        }


        pde = (proxy_extension_t *)fdo->DeviceExtension;
        RtlZeroMemory(pde, sizeof(proxy_extension_t));
        RtlStringCchCopyW(pde->symbolic_linkText, XENV4V_SYM_NAME_LEN, V4V_SYMBOLIC_NAME);
        RtlInitUnicodeString(&pde->symbolic_link, pde->symbolic_linkText);

        // Create our symbolic link
        status = IoCreateSymbolicLink(&pde->symbolic_link, &device_name);
        if (!NT_SUCCESS(status)) {
            ERROR("IoCreateSymbolicLink failed error 0x%x", status);
            break;
        }
        symlink = TRUE;

        // Setup the extension
        pde->magic = XENV4V_MAGIC;
        pde->fdo = fdo;
        IoInitializeRemoveLock(&pde->remove_lock, PROXY_POOL_TAG, 0, 0);
        KeInitializeSpinLock(&pde->context_lock);
        KeInitializeSpinLock(&pde->queue_lock);
        InitializeListHead(&pde->context_list);
        InitializeListHead(&pde->pending_irp_queue);
        IoCsqInitializeEx(&pde->csq_object,
            csq_insert_irp_ex,
            csq_remove_irp,
            csq_peek_next_irp,
            csq_acquire_lock,
            csq_release_lock,
            csq_complete_canceled_irp);

        LARGE_INTEGER seed;
        KeQueryTickCount(&seed);
        pde->seed = seed.u.LowPart;

        // Use direct IO and let the IO manager directly map user buffers; clear the init flag
        fdo->Flags |= DO_DIRECT_IO;
        fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        if (fdo != NULL) {
            if (symlink) {
                IoDeleteSymbolicLink(&pde->symbolic_link);
            }
            IoDeleteDevice(fdo);
        }
    } else {
        g_fdo = fdo;
        proxy_set_notify_fdo(fdo);
        INFO("proxy device created");
    }

    VERBOSE("<-----");

    return status;
}

static void
stop_device(PDEVICE_OBJECT fdo, proxy_extension_t *pde)
{
    // FIXME
}

static NTSTATUS
delete_device(PDRIVER_OBJECT drv)
{
    DEVICE_OBJECT *fdo;
    proxy_extension_t *pde;
    NTSTATUS status = STATUS_SUCCESS;

    VERBOSE("----->");
    if (!g_fdo)
        return STATUS_UNSUCCESSFUL;
    fdo = g_fdo;

    pde = FDO_TO_EXT(fdo);

    // Stop our device's IO processing
    stop_device(fdo, pde);

    // Then detach and cleanup our device
    IoDeleteSymbolicLink(&pde->symbolic_link);
    IoDeleteDevice(fdo);
    proxy_set_notify_fdo(NULL);
    INFO("proxy device deleted");

    VERBOSE("<-----");

    return status;
}

proxy_context_t *
find_bound_backend_by_token(proxy_extension_t *pde, v4v_idtoken_t *token)
{
    proxy_context_t *ctx, *found = NULL;
    KLOCK_QUEUE_HANDLE  lqh = {0};

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
    ctx = (proxy_context_t *)pde->context_list.Flink;
    while (ctx != (proxy_context_t *)&pde->context_list) {
        if (ctx->state == CTX_STATE_BOUND_BACKEND) {
            if (RtlCompareMemory(token, &ctx->token, sizeof(v4v_idtoken_t)) ==
                sizeof(v4v_idtoken_t)) {
                found = ctx;
                break;
            }
        }
        ctx = (proxy_context_t *)ctx->le.Flink;
    }
    KeReleaseInStackQueuedSpinLock(&lqh);

    return found;
}

proxy_context_t *
find_bound_context_by_addr(proxy_extension_t *pde, v4v_addr_t addr)
{
    proxy_context_t *ctx, *found = NULL;
    KLOCK_QUEUE_HANDLE  lqh = {0};

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
    ctx = (proxy_context_t *)pde->context_list.Flink;
    while (ctx != (proxy_context_t *)&pde->context_list) {
        if (ctx->state == CTX_STATE_BOUND) {
            VERBOSE("bound %d %d", ctx->ring_id.addr.domain, ctx->ring_id.addr.port);
            if (addr.domain == ctx->ring_id.addr.domain &&
                addr.port == ctx->ring_id.addr.port) {
                found = ctx;
                break;
            }
        }
        ctx = (proxy_context_t *)ctx->le.Flink;
    }
    KeReleaseInStackQueuedSpinLock(&lqh);

    return found;
}

void
notify_rx(proxy_extension_t *pde, proxy_context_t *ctx)
{
    if (ctx->rx_event)
        KeSetEvent(ctx->rx_event, 0, FALSE);
}

NTSTATUS
proxy_create(PDEVICE_OBJECT fdo, PIRP irp)
{
    proxy_extension_t *pde = FDO_TO_EXT(fdo);
    PIO_STACK_LOCATION isl;
    FILE_OBJECT *pfo;
    PEPROCESS process;
    PACCESS_TOKEN token;
    proxy_context_t *ctx;

    VERBOSE("----->");
    isl = IoGetCurrentIrpStackLocation(irp);
    isl->FileObject->FsContext = NULL;
    isl->FileObject->FsContext2 = NULL;
    pfo = isl->FileObject;

    if (pfo->FsContext != NULL) {
        ERROR("FsContext %p already associated with the file!",
            pfo->FsContext);
        return simple_complete_irp(irp, STATUS_INVALID_HANDLE);
    }

    ctx = (proxy_context_t *)ExAllocatePoolWithTag(NonPagedPool,
                                                    sizeof(proxy_context_t),
                                                    PROXY_POOL_TAG);
    if (ctx == NULL) {
        ERROR("allocation of proxy context failed");
        return simple_complete_irp(irp, STATUS_NO_MEMORY);
    }
    RtlZeroMemory(ctx, sizeof(proxy_context_t));

    InterlockedExchange(&ctx->state, CTX_STATE_UNINITIALIZED);

    process = IoGetRequestorProcess(irp);
    if (!process)
        process = IoGetCurrentProcess();

    token = PsReferencePrimaryToken(process);
    if (token) {
        if (SeTokenIsAdmin(token) == TRUE)
            ctx->admin_access = TRUE;
        PsDereferencePrimaryToken(token);
    }

    // Add one ref count for the handle file object/handle reference
    ctx->refc++;
    link_to_context_list(pde, ctx);

    // Now it is ready for prime time, set it as the file contex
    // and set a back pointer. The reference on the file object by
    // the context prevents the final close until the ref count goes
    // to zero. Note, this can occur after the cleanup when all the
    // user mode handles are closed.
    isl->FileObject->FsContext = ctx;
    ctx->pfo_parent = isl->FileObject;
    ObReferenceObject(ctx->pfo_parent);

    VERBOSE("<-----");
    return simple_complete_irp(irp, STATUS_SUCCESS);
}

NTSTATUS
proxy_close(PDEVICE_OBJECT fdo, PIRP irp)
{
    PIO_STACK_LOCATION isl;

    UNREFERENCED_PARAMETER(fdo);

    VERBOSE("----->");
    isl = IoGetCurrentIrpStackLocation(irp);

    // By the time we reach close, the final release has been called and
    // dropped its ref count in the file object. All that is left is to
    // NULL the context for consistency.
    isl->FileObject->FsContext = NULL;

    simple_complete_irp(irp, STATUS_SUCCESS);

    VERBOSE("<-----");

    return STATUS_SUCCESS;
}

NTSTATUS
proxy_read(PDEVICE_OBJECT fdo, PIRP irp)
{
    proxy_extension_t *pde = FDO_TO_EXT(fdo);
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    FILE_OBJECT *pfo;
    proxy_context_t *ctx;
    proxy_context_t *backend_ctx;

    UNREFERENCED_PARAMETER(fdo);

    VERBOSE("----->");

    if (isl->Parameters.Read.Length > XENV4V_MAX_RING_LENGTH)
        return simple_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST);

    pfo = isl->FileObject;
    ctx = (proxy_context_t *)pfo->FsContext;

    initialize_irp(irp);

    // Map in the DIRECT IO locked MDL - do it once up front since we will access it
    // from the Q. If the length is zero, don't touch the MDL, it is NULL.
    if (isl->Parameters.Read.Length > 0) {
        if (MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL) {
            return simple_complete_irp(irp, STATUS_NO_MEMORY);
        }
    }

    switch (ctx->state) {
    case CTX_STATE_BOUND:
        // Input check for datagram header
        if (isl->Parameters.Read.Length < sizeof(v4v_datagram_t)) {
            return simple_complete_irp(irp, STATUS_BUFFER_TOO_SMALL);
        }
        break;
    default:
        return simple_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    backend_ctx = find_bound_backend_by_token(pde, &ctx->token);
    if (backend_ctx == NULL)
        return simple_complete_irp(irp, STATUS_VIRTUAL_CIRCUIT_CLOSED);

    // Store backend context in the IRP
    irp->Tail.Overlay.DriverContext[0] = (void*)(ULONG_PTR)PROXY_IRP_FLAG_READ;
    irp->Tail.Overlay.DriverContext[1] = backend_ctx;

    // Always queue it to the back and marks it pending
    status = IoCsqInsertIrpEx(&pde->csq_object, irp, NULL, NULL);
    if (NT_SUCCESS(status)) {
        status = STATUS_PENDING;

        /* notify backend that packet is pending */
        notify_rx(pde, backend_ctx);
    } else {
        // Fail it
        simple_complete_irp(irp, status);
    }

    return status;
}

NTSTATUS
proxy_write(PDEVICE_OBJECT fdo, PIRP irp)
{
    proxy_extension_t *pde = FDO_TO_EXT(fdo);
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    FILE_OBJECT *pfo;
    proxy_context_t *ctx;
    proxy_context_t *backend_ctx;

    UNREFERENCED_PARAMETER(fdo);

    VERBOSE("----->");

    pfo = isl->FileObject;
    ctx = (proxy_context_t *)pfo->FsContext;

    initialize_irp(irp);

    switch (ctx->state) {
    case CTX_STATE_BOUND:
        // Input check for datagram header
        if (isl->Parameters.Write.Length < sizeof(v4v_datagram_t)) {
            return simple_complete_irp(irp, STATUS_BUFFER_TOO_SMALL);
        }
        break;
    default:
        return simple_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    backend_ctx = find_bound_backend_by_token(pde, &ctx->token);
    if (backend_ctx == NULL)
        return simple_complete_irp(irp, STATUS_VIRTUAL_CIRCUIT_CLOSED);

    // Map in the DIRECT IO locked MDL - do it once up front since we will access it
    // from the Q. If the length is zero, don't touch the MDL, it is NULL.
    if (isl->Parameters.Write.Length > 0) {
        if (MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL) {
            return simple_complete_irp(irp, STATUS_NO_MEMORY);
        }
    }

    // Store destination backend context in the IRP
    irp->Tail.Overlay.DriverContext[0] = (void*)(ULONG_PTR)PROXY_IRP_FLAG_WRITE;
    irp->Tail.Overlay.DriverContext[1] = backend_ctx;

    // Always queue it to the back and marks it pending
    status = IoCsqInsertIrpEx(&pde->csq_object, irp, NULL, NULL);
    if (NT_SUCCESS(status)) {
        status = STATUS_PENDING;

        VERBOSE("new pending write backend=%p", backend_ctx);
        /* notify backend that packet is pending */
        notify_rx(pde, backend_ctx);
    } else {
        // Fail it
        simple_complete_irp(irp, status);
    }

    return status;
}

NTSTATUS
proxy_initialize_file(
    proxy_context_t *ctx,
    void *event,
    PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    VERBOSE("----->");
    if (ctx->state != CTX_STATE_UNINITIALIZED)
        return STATUS_INVALID_HANDLE;

    if (!event)
        return STATUS_INVALID_PARAMETER;

    status = ObReferenceObjectByHandle(event,
        EVENT_MODIFY_STATE,
        *ExEventObjectType,
        irp->RequestorMode,
        (void **)&ctx->rx_event,
        NULL);

    if (NT_SUCCESS(status))
        InterlockedExchange(&ctx->state, CTX_STATE_UNBOUND);

    VERBOSE("<-----");

    return status;
}

static BOOLEAN
proxy_addr_bound(proxy_extension_t *pde, v4v_addr_t addr)
{
    proxy_context_t *ctx;
    KLOCK_QUEUE_HANDLE  lqh = {0};

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
    ctx = (proxy_context_t *)pde->context_list.Flink;
    while (ctx != (proxy_context_t *)&pde->context_list) {
        if (ctx->state == CTX_STATE_BOUND) {
            if (ctx->ring_id.addr.domain == addr.domain &&
                ctx->ring_id.addr.port == addr.port)
            {
                KeReleaseInStackQueuedSpinLock(&lqh);
                return TRUE;
            }
        }
        ctx = (proxy_context_t *)ctx->le.Flink;
    }
    KeReleaseInStackQueuedSpinLock(&lqh);

    return FALSE;
}

/* must be called with context lock */
static BOOLEAN
proxy_port_in_use(proxy_extension_t *pde, uint32_t port, uint32_t *max)
{
    BOOLEAN used = FALSE;
    proxy_context_t *ctx;

    ctx = (proxy_context_t *)pde->context_list.Flink;
    while (ctx != (proxy_context_t *)&pde->context_list) {
        if (ctx->ring_id.addr.port > *max)
            *max = ctx->ring_id.addr.port;
        if (ctx->ring_id.addr.port == port)
            used = TRUE;
        ctx = (proxy_context_t *)ctx->le.Flink;
    }

    return used;
}

// Must be called at PASSIVE level
static uint32_t
proxy_random_port(proxy_extension_t *pde)
{
    uint32_t port;

    port = RtlRandomEx(&pde->seed);
    port |= 0x80000000U;
    return ((port > 0xf0000000U) ? (port - 0x10000000) : port);
}

// Must be called holding the lock
static uint32_t
proxy_spare_port_number(proxy_extension_t *pde, uint32_t port)
{
    uint32_t max = 0x80000000U;

    if (proxy_port_in_use(pde, port, &max)) {
        port = max + 1;
    }

    return port;
}


NTSTATUS
proxy_register_backend(
    proxy_extension_t *pde,
    proxy_context_t *ctx,
    v4v_proxy_register_backend_t *v)
{
    proxy_context_t *exists;

    VERBOSE("----->");
    if (ctx->state != CTX_STATE_UNBOUND)
        return STATUS_INVALID_HANDLE;

    if (find_bound_backend_by_token(pde, &v->partner)) {
        ERROR("duplicate register backend detected");
        return STATUS_INVALID_PARAMETER;
    }

    ctx->token = v->partner;
    ctx->backend = TRUE;

    InterlockedExchange(&ctx->state, CTX_STATE_BOUND_BACKEND);

    return STATUS_SUCCESS;
}

static NTSTATUS
winerror_to_ntstatus(int error)
{
    switch (error) {
    case 0:
        return STATUS_SUCCESS;
    case ERROR_IO_PENDING:
        return STATUS_PENDING;
    case ERROR_VC_DISCONNECTED:
        return STATUS_VIRTUAL_CIRCUIT_CLOSED;
    default:
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS
proxy_complete_read(proxy_extension_t *pde, proxy_context_t *ctx,
    v4v_proxy_complete_read_t *read)
{
    proxy_qpeek_t peek;
    IRP *pendingIrp;

    VERBOSE("complete read: domain %d port %d",
        read->datagram.addr.domain,
        read->datagram.addr.port);

    /* find pending IRP which we're completing */
    RtlZeroMemory(&peek, sizeof(peek));
    peek.flags_on = PROXY_IRP_FLAG_READ | PROXY_IRP_FLAG_WAIT_BACKEND;
    peek.backend_context = ctx;
    peek.reqid = read->reqid;

    pendingIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
    if (!pendingIrp) {
        //ERROR("could not find pending irp ctx=%p id=%lld\n", ctx, peek.reqid);

        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(pendingIrp);
    int datagram_len = read->datagram_len;
    int status = read->status;

    VERBOSE("read complete, datagram len %d target buffer len %d st %d",
        datagram_len, isl->Parameters.Read.Length, read->status);

    if (datagram_len > isl->Parameters.Read.Length) {
        /* shouldn't happen */
        ERROR("unexpectedly, read size is %d, target buffer is %d\n",
            datagram_len, isl->Parameters.Read.Length);
        /* fail pending irp */
        pendingIrp->IoStatus.Information = 0;
        pendingIrp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);

        /* fail read complete */
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (read->status == 0) {
        /* copy completed read data */
        RtlCopyMemory(pendingIrp->MdlAddress->MappedSystemVa, &read->datagram,
            datagram_len);

        /* complete pending irp */
        pendingIrp->IoStatus.Information = datagram_len;
        pendingIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
    } else {
        /* there was an error */
        pendingIrp->IoStatus.Information = 0;
        pendingIrp->IoStatus.Status = winerror_to_ntstatus(read->status);
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
    }
    return STATUS_SUCCESS;
}

NTSTATUS
proxy_complete_write(proxy_extension_t *pde, proxy_context_t *ctx,
    v4v_proxy_complete_write_t *write)
{
    proxy_qpeek_t peek;
    IRP *pendingIrp;

    VERBOSE("complete write: req id %lld", write->reqid);

    /* find pending IRP which we're completing */
    RtlZeroMemory(&peek, sizeof(peek));
    peek.flags_on = PROXY_IRP_FLAG_WRITE | PROXY_IRP_FLAG_WAIT_BACKEND;
    peek.backend_context = ctx;
    peek.reqid = write->reqid;

    pendingIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
    if (!pendingIrp) {
        //ERROR("could not find pending irp ctx=%p id=%lld\n", ctx, peek.reqid);

        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(pendingIrp);
    int status = write->status;

    VERBOSE("write complete, st %d", write->status);

    if (write->status == 0) {
        /* complete pending irp */
        pendingIrp->IoStatus.Information = write->written;
        pendingIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
    } else {
        /* there was an error */
        pendingIrp->IoStatus.Information = write->written;
        pendingIrp->IoStatus.Status = winerror_to_ntstatus(write->status);
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
    }
    return STATUS_SUCCESS;
}

NTSTATUS
proxy_complete_bind(proxy_extension_t *pde, proxy_context_t *ctx,
    v4v_proxy_complete_bind_t *bind)
{
    proxy_qpeek_t peek;
    IRP *pendingIrp;
    KLOCK_QUEUE_HANDLE lqh = { 0 };

    VERBOSE("complete bind");

    /* find pending IRP which we're completing */
    RtlZeroMemory(&peek, sizeof(peek));
    peek.flags_on = PROXY_IRP_FLAG_BIND | PROXY_IRP_FLAG_WAIT_BACKEND;
    peek.backend_context = ctx;
    peek.reqid = bind->reqid;

    pendingIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
    if (!pendingIrp)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(pendingIrp);
    int status = bind->status;

    if (status == 0) {
        proxy_context_t *irp_ctx = (proxy_context_t*) isl->FileObject->FsContext;

        /* fill in bound context address data */
        KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
        irp_ctx->ring_id = bind->bind.ring_id;
        irp_ctx->token = bind->bind.partner;

        /* context state change to bound */
        InterlockedExchange(&irp_ctx->state, CTX_STATE_BOUND);

        KeReleaseInStackQueuedSpinLock(&lqh);

        /* return updated bind values to caller */
        RtlCopyMemory(pendingIrp->AssociatedIrp.SystemBuffer,
            &bind->bind, sizeof(v4v_bind_values_t));

        pendingIrp->IoStatus.Information = sizeof(v4v_bind_values_t);
        pendingIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
    } else
        return winerror_to_ntstatus(status);

    return STATUS_SUCCESS;
}

NTSTATUS
proxy_get_req(proxy_extension_t *pde, proxy_context_t *ctx,
    void *buffer, ULONG buffer_size, ULONG_PTR *written)
{
    proxy_qpeek_t peek;
    IRP *pendingIrp;
    NTSTATUS status;

    VERBOSE("----->");

    if (ctx->state != CTX_STATE_BOUND_BACKEND)
        return STATUS_INVALID_DEVICE_REQUEST;

    /* Find 1st pending read/write irp with destination 'ctx';
     * only consider irps which haven't been yet queued for backend processing (WAIT_BACKEND state) */
    RtlZeroMemory(&peek, sizeof(peek));
    peek.flags_on  = PROXY_IRP_FLAG_WRITE | PROXY_IRP_FLAG_READ | PROXY_IRP_FLAG_BIND;
    peek.flags_off = PROXY_IRP_FLAG_WAIT_BACKEND;
    peek.backend_context = ctx;
    pendingIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
    VERBOSE("looked for pending irp, context %p, irp=%p", ctx, pendingIrp);
    if (pendingIrp) {
        uint32_t flags = irp_get_flags(pendingIrp);

        if (flags & PROXY_IRP_FLAG_WRITE) {
            /* pending write irp found, copy request data to the requestor */
            PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(pendingIrp);
            proxy_context_t *irp_ctx = (proxy_context_t*) isl->FileObject->FsContext;
            ULONG datagram_len = isl->Parameters.Write.Length;
            ULONG req_len = sizeof(v4v_proxy_req_send_t) + datagram_len - sizeof(v4v_datagram_t);
            v4v_proxy_req_send_t *req;

            if (buffer_size < req_len)
                return STATUS_BUFFER_TOO_SMALL;

            /* mark as being processed by backend */
            irp_add_flag(pendingIrp, PROXY_IRP_FLAG_WAIT_BACKEND);

            // request header
            req = (v4v_proxy_req_send_t*) buffer;
            req->req.op = V4VPROXY_REQ_SEND;
            req->req.id = InterlockedIncrement64(&pde->reqid);
            req->from.domain = 0; // all proxy sends have dom0 as source
            req->from.port = irp_ctx->ring_id.addr.port;
            req->datagram_len = datagram_len;
            // datagram body
            RtlCopyMemory(&req->datagram, pendingIrp->MdlAddress->MappedSystemVa, datagram_len);

            irp_set_reqid(pendingIrp, req->req.id);

            /* requeue IRP with WAIT_BACKEND flag */
            status = IoCsqInsertIrpEx(&pde->csq_object, pendingIrp, NULL, NULL);

            if (!NT_SUCCESS(status)) {
                ERROR("requeue of IRP failed\n");
                simple_complete_irp(pendingIrp, status);
                goto out;
            }

            /* complete get_req IRP with buffered request data */
            *written = req_len;

            VERBOSE("created write request id %lld domain %d port %d",
                req->req.id, req->from.domain, req->from.port);

            return STATUS_SUCCESS;
        } else if (flags & PROXY_IRP_FLAG_READ) {
            /* pending read irp found, queue it for backend processing */
            PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(pendingIrp);
            proxy_context_t *irp_ctx = (proxy_context_t*) isl->FileObject->FsContext;
            v4v_proxy_req_recv_t *req;
            ULONG req_len = sizeof(v4v_proxy_req_recv_t);

            if (buffer_size < req_len)
                return STATUS_BUFFER_TOO_SMALL;

            /* mark as being processed by backend */
            irp_add_flag(pendingIrp, PROXY_IRP_FLAG_WAIT_BACKEND);

            // request header
            req = (v4v_proxy_req_recv_t*) buffer;
            req->req.op = V4VPROXY_REQ_RECV;
            req->req.id = InterlockedIncrement64(&pde->reqid);
            req->buffer_len = isl->Parameters.Read.Length;
            req->from.domain = 0; // all proxy recvs have dom0 as source
            req->from.port = irp_ctx->ring_id.addr.port;

            irp_set_reqid(pendingIrp, req->req.id);

            /* requeue IRP with WAIT_BACKEND flag */
            status = IoCsqInsertIrpEx(&pde->csq_object, pendingIrp, NULL, NULL);

            if (!NT_SUCCESS(status)) {
                ERROR("requeue of IRP failed\n");
                simple_complete_irp(pendingIrp, status);
                goto out;
            }

            /* complete get_req IRP with buffered request data */
            *written = req_len;

            VERBOSE("created read request id %lld domain %d port %d\n",
                req->req.id, req->from.domain, req->from.port);

            return STATUS_SUCCESS;
        } else if (flags & PROXY_IRP_FLAG_BIND) {
            /* pending read irp found, queue it for backend processing */
            PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(pendingIrp);
            proxy_context_t *irp_ctx = (proxy_context_t*) isl->FileObject->FsContext;
            v4v_proxy_req_bind_t *req;
            ULONG req_len = sizeof(v4v_proxy_req_bind_t);

            if (buffer_size < req_len)
                return STATUS_BUFFER_TOO_SMALL;

            /* mark as being processed by backend */
            irp_add_flag(pendingIrp, PROXY_IRP_FLAG_WAIT_BACKEND);

            // request header
            req = (v4v_proxy_req_bind_t*) buffer;
            req->req.op = V4VPROXY_REQ_BIND;
            req->req.id = InterlockedIncrement64(&pde->reqid);
            RtlCopyMemory(&req->bind, pendingIrp->AssociatedIrp.SystemBuffer,
                sizeof(v4v_bind_values_t));

            irp_set_reqid(pendingIrp, req->req.id);

            /* requeue IRP with WAIT_BACKEND flag */
            status = IoCsqInsertIrpEx(&pde->csq_object, pendingIrp, NULL, NULL);

            if (!NT_SUCCESS(status)) {
                ERROR("requeue of IRP failed\n");
                simple_complete_irp(pendingIrp, status);
                goto out;
            }

            /* complete get_req IRP with buffered request data */
            *written = req_len;

            VERBOSE("created bind request id %lld domain %d port %d\n",
                req->req.id,
                req->bind.ring_id.addr.domain, req->bind.ring_id.addr.port);

            return STATUS_SUCCESS;
        } else {
            ASSERT(0);
        }
    }

out:
    /* no pending datagrams for this destination */
    return STATUS_END_OF_FILE;
}

NTSTATUS
proxy_bind(proxy_extension_t *pde, proxy_context_t *ctx, v4v_bind_values_t *bind, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    proxy_context_t *backend_ctx;
    KLOCK_QUEUE_HANDLE lqh = { 0 };

    VERBOSE("----->");
    if (ctx->state != CTX_STATE_UNBOUND)
        return STATUS_INVALID_HANDLE;

    initialize_irp(irp);

    backend_ctx = find_bound_backend_by_token(pde, &bind->partner);
    if (backend_ctx == NULL)
        return STATUS_VIRTUAL_CIRCUIT_CLOSED; /* no backend registered for that partner */


    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);

    /* figure out random port if not specified */
    ctx->ring_id = bind->ring_id;
    ctx->ring_id.addr.domain = 0; /* all proxy binds are in domain 0 */
    if (ctx->ring_id.addr.port == 0) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        /* must be called on passive level */
        uint32_t p = proxy_random_port(pde);
        KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
        p = proxy_spare_port_number(pde, p);
        ctx->ring_id.addr.port = p;
    }
    ctx->token = bind->partner;

    /* also update bind struct in the irp */
    bind->ring_id = ctx->ring_id;

    KeReleaseInStackQueuedSpinLock(&lqh);

    // Store destination backend context in the IRP
    irp->Tail.Overlay.DriverContext[0] = (void*)(ULONG_PTR)PROXY_IRP_FLAG_BIND;
    irp->Tail.Overlay.DriverContext[1] = backend_ctx;

    // Always queue it to the back and marks it pending
    status = IoCsqInsertIrpEx(&pde->csq_object, irp, NULL, NULL);
    if (NT_SUCCESS(status)) {
        status = STATUS_PENDING;

        VERBOSE("new pending bind backend=%p", backend_ctx);
        /* notify backend that packet is pending */
        notify_rx(pde, backend_ctx);
    } else {
        // Fail it
        simple_complete_irp(irp, status);
    }

    return status;
}

NTSTATUS
proxy_device_ioctl(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  isl;
    ULONG io_control_code;
    PVOID io_buffer;
    ULONG io_in_len;
    ULONG io_out_len;
    proxy_extension_t *pde = FDO_TO_EXT(fdo);
    proxy_context_t *ctx;

    VERBOSE("----->");
    isl = IoGetCurrentIrpStackLocation(irp);
    io_control_code = isl->Parameters.DeviceIoControl.IoControlCode;
    io_buffer = irp->AssociatedIrp.SystemBuffer;
    io_in_len = isl->Parameters.DeviceIoControl.InputBufferLength;
    io_out_len = isl->Parameters.DeviceIoControl.OutputBufferLength;
    ctx = (proxy_context_t *)isl->FileObject->FsContext;

    irp->IoStatus.Information = 0;

    switch (io_control_code) {
#if defined(_WIN64)
    case V4V_IOCTL_INITIALIZE_32: {
        v4v_init_values_32_t *invs32 = (v4v_init_values_32_t *)io_buffer;
        if (io_in_len == sizeof(v4v_init_values_32_t)) {
            v4v_init_values_t init;
            init.rx_event = invs32->rx_event;
            init.ring_length = invs32->ring_length;
            status = proxy_initialize_file(ctx, init.rx_event, irp);
        } else {
            ERROR("ctx %p invalid initialization values", ctx);
            status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
#endif
    case V4V_IOCTL_INITIALIZE: {
        v4v_init_values_t *invs = (v4v_init_values_t *)io_buffer;
        if (io_in_len == sizeof(v4v_init_values_t)) {
            status = proxy_initialize_file(ctx, invs->rx_event, irp);
        } else {
            ERROR("ctx %p invalid initialization values", ctx);
            status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
    case V4V_IOCTL_BIND: {
        v4v_bind_values_t *bvs = (v4v_bind_values_t *)io_buffer;
        if (io_in_len == sizeof(v4v_bind_values_t)) {
            status = proxy_bind(pde, ctx, bvs, irp);
        } else {
            ERROR("ctx %p invalid bind values", ctx);
            status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
    case V4V_IOCTL_GETINFO: {
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    case V4V_IOCTL_DUMPRING: {
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    case V4V_IOCTL_NOTIFY: {
        status = STATUS_SUCCESS;
        break;
    }
    case V4V_IOCTL_MAPRING: {
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    case V4V_PROXY_IOCTL_REGISTER_BACKEND: {
        v4v_proxy_register_backend_t *v = (v4v_proxy_register_backend_t*) io_buffer;
        if (io_in_len == sizeof(v4v_proxy_register_backend_t)) {
            status = proxy_register_backend(pde, ctx, v);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        if (NT_SUCCESS(status))
            irp->IoStatus.Information = sizeof(v4v_proxy_register_backend_t);
        break;
    }
    case V4V_PROXY_IOCTL_IS_BOUND: {
        v4v_proxy_is_bound_t *v = (v4v_proxy_is_bound_t*) io_buffer;
        if (io_in_len == sizeof(v4v_proxy_is_bound_t))
            status = proxy_addr_bound(pde, v->addr)
                ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
        else
            status = STATUS_INVALID_PARAMETER;
        break;
    }
    case V4V_PROXY_IOCTL_GET_REQ: {
        ULONG_PTR written = 0;
        void *out_buffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
        if (!out_buffer)
            status = STATUS_NO_MEMORY;
        else {
            status = proxy_get_req(pde, ctx, out_buffer, io_out_len, &written);
            irp->IoStatus.Information = written;
        }
        break;
    }
    case V4V_PROXY_IOCTL_COMPLETE_READ:
    case V4V_PROXY_IOCTL_COMPLETE_WRITE:
    case V4V_PROXY_IOCTL_COMPLETE_BIND: {
        void *in_buffer = isl->Parameters.DeviceIoControl.Type3InputBuffer;
        try {
            if (!in_buffer)
                status = STATUS_NO_MEMORY;
            else {
                ProbeForRead(in_buffer, io_in_len, sizeof(UCHAR));
                status = STATUS_INVALID_PARAMETER;
                switch (io_control_code) {
                case V4V_PROXY_IOCTL_COMPLETE_READ:
                    if (io_in_len == sizeof(v4v_proxy_complete_read_t))
                        status = proxy_complete_read(pde, ctx, (v4v_proxy_complete_read_t*) in_buffer);
                    break;
                case V4V_PROXY_IOCTL_COMPLETE_WRITE:
                    if (io_in_len == sizeof(v4v_proxy_complete_write_t))
                        status = proxy_complete_write(pde, ctx, (v4v_proxy_complete_write_t*) in_buffer);
                    break;
                case V4V_PROXY_IOCTL_COMPLETE_BIND:
                    if (io_in_len == sizeof(v4v_proxy_complete_bind_t))
                        status = proxy_complete_bind(pde, ctx, (v4v_proxy_complete_bind_t*) in_buffer);
                    break;
                }
            }
        } except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    }
    default:
        status = STATUS_INVALID_PARAMETER;
    }

    if (status != STATUS_PENDING) {
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    VERBOSE("<-----");

    return status;
}

PROXY_DLL_EXPORT void uxen_v4vproxy_set_logger(uxen_v4vproxy_logger_t logger)
{
    proxy_logger = logger;
    INFO("logging initialized");
}

void
proxy_unload(void)
{
    if (!g_drvobj)
        return;
    delete_device(g_drvobj);
    g_drvobj = NULL;
}

NTSTATUS
proxy_load(PDRIVER_OBJECT drvobj)
{
    if (g_drvobj)
        return STATUS_SUCCESS;
    g_drvobj = drvobj;

    drvobj->MajorFunction[IRP_MJ_CREATE] = proxy_create;
    drvobj->MajorFunction[IRP_MJ_CLEANUP] = proxy_cleanup;
    drvobj->MajorFunction[IRP_MJ_CLOSE] = proxy_close;
    drvobj->MajorFunction[IRP_MJ_READ] = proxy_read;
    drvobj->MajorFunction[IRP_MJ_WRITE] = proxy_write;
    drvobj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = proxy_device_ioctl;

    return STATUS_SUCCESS;
}

PROXY_DLL_EXPORT void
uxen_v4vproxy_start_device(void)
{
    if (g_drvobj)
        add_device(g_drvobj);
}

/*
    DriverEntry()

    This is never called.  It has to exist, however, in order to
    satisfy the build environment (WDK Build).
*/

NTSTATUS
DriverEntry (DRIVER_OBJECT *Driver, UNICODE_STRING *ServicesKey)
{
    Driver;
    ServicesKey;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    return STATUS_SUCCESS;
}

NTSTATUS
DllInitialize (PUNICODE_STRING RegistryPath)
{
    return STATUS_SUCCESS;
}

NTSTATUS
DllUnload (void)
{
    return STATUS_SUCCESS;
}

