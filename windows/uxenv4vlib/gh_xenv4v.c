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
 * Copyright 2015-2018, Bromium, Inc.
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

#include "uxenv4vlib_private.h"

typedef struct xenv4v_marker_struct {
    ULONG marker;
    ULONG winver;
    const char *date;
    const char *time;
    ULONG build;
    ULONG hw;
} xenv4v_marker_t;

#if defined(DBG)||defined(_DEBUG)
#define XENV4V_BUILD_TYPE ' GBD'
#else
#define XENV4V_BUILD_TYPE ' LER'
#endif

#if defined(_WIN64)
#define XENV4V_HW_TYPE ' 46x'
#else
#define XENV4V_HW_TYPE ' 68x'
#endif

/* This controls how read callbacks in the _host_ are handled
 * the uxen->here notification in the guest comes via an ISR
 * which runs a DPC, which can then do everything a DPC can
 * but in the host the notification comes via and upcall
 * and we will be holding many locks at this point.
 *
 * By default the upcall will schedule a DPC to do the same
 * work.
 */

__declspec(dllexport) xenv4v_marker_t __xenv4v = {
    0x800000B9, WINVER, __DATE__, __TIME__, XENV4V_BUILD_TYPE, XENV4V_HW_TYPE
};

static ULONG g_osMajorVersion = 0;
static ULONG g_osMinorVersion = 0;
static LONG g_deviceCreated = 0;

static PDEVICE_OBJECT static_fdo;

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

// {3a523e0a-9b28-46c9-9046-5aaaaf20e51d}
static const GUID GUID_SD_XENV4V_CONTROL_OBJECT =
{ 0x3a523e0a, 0x9b28, 0x46c9, { 0x90, 0x46, 0x5a, 0xaa, 0xaf, 0x20, 0xe5, 0x1d } };

// ---- EVENT CHANNEL ROUTINES ----


static VOID
gh_v4v_virq_work(xenv4v_extension_t *pde)
{
    xenv4v_context_t   **ctx_list;
    ULONG              count = 0, i;
    KLOCK_QUEUE_HANDLE lqh;
    NTSTATUS status;
    BOOLEAN notify = FALSE;

    check_resume();

    // Get a list of active contexts and their rings
    ctx_list = gh_v4v_get_all_contexts(pde, &count);

    // Loop over the contexts and process read IO for each.
    for (i = 0; ((ctx_list != NULL) && (i < count)); i++) {
        gh_v4v_process_context_reads(pde, ctx_list[i], &notify);
    }

    // Return the context list and drop the ref count
    gh_v4v_put_all_contexts(pde, ctx_list, count);

    // Now process the notify and satisfy writes that are queued
    // gh_v4v_process_notify invokes hypercalls and therefore can allocate - low irql needed
    // to benefit from automatic allocation retries
    ASSERT(KeGetCurrentIrql() <= PASSIVE_LEVEL);
    gh_v4v_process_notify(pde, notify);

    uxen_v4v_send_read_callbacks(pde);

    check_resume();
}

static void
gh_v4v_virq_thread(void *context)
{
    xenv4v_extension_t *pde =
        v4v_get_device_extension((DEVICE_OBJECT *)context);

    while (InterlockedExchangeAdd(&pde->virq_thread_running, 0)) {
        KeWaitForSingleObject(&pde->virq_event, Executive, KernelMode, TRUE,
                              NULL);
        KeClearEvent(&pde->virq_event);
        if (!InterlockedExchangeAdd(&pde->virq_thread_running, 0))
            break;

        gh_v4v_virq_work(pde);
    }
}

VOID gh_signaled(void)
{
    xenv4v_extension_t *pde = uxen_v4v_get_pde();
    if (!pde) return;

    /* Leave the rest of the work to the thread */
    KeSetEvent(&pde->virq_event, IO_NO_INCREMENT, FALSE);

    uxen_v4v_put_pde(pde);
}

VOID gh_set_thread_priority(LONG priority)
{
    xenv4v_extension_t *pde = uxen_v4v_get_pde();
    if (!pde) return;

    if (pde->virq_thread)
        KeSetPriorityThread(pde->virq_thread, priority);
    if (pde->notify_thread)
        KeSetPriorityThread(pde->notify_thread, priority);

    uxen_v4v_put_pde(pde);
}


static VOID
gh_v4v_stop_device(PDEVICE_OBJECT fdo, xenv4v_extension_t *pde)
{
    PIRP pendingIrp;
    xenv4v_qpeek_t peek;

    // Go to the stopped state to prevent IO, stop the
    // interrupt (ec).
    InterlockedExchange(&pde->state, XENV4V_DEV_STOPPED);

}

static IO_COMPLETION_ROUTINE gh_v4v_start_device_io_completion;
static NTSTATUS
gh_v4v_start_device_io_completion(PDEVICE_OBJECT fdo, PIRP irp, PVOID context)
{
    UNREFERENCED_PARAMETER(fdo);
    UNREFERENCED_PARAMETER(irp);

    uxen_v4v_verbose("====>");
    KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);
    uxen_v4v_verbose("<====");
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS gh_remove_device(PDEVICE_OBJECT fdo)
{
    NTSTATUS          status = STATUS_SUCCESS;
    xenv4v_extension_t *pde =  (xenv4v_extension_t *)fdo->DeviceExtension;

    // Stop our device's IO processing
    gh_v4v_stop_device(fdo, pde);

    InterlockedAnd(&pde->notify_thread_running, 0);
    KeSetEvent(&pde->notify_event, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(pde->notify_thread, Executive, KernelMode, FALSE,
                          NULL);
    ObDereferenceObject(pde->notify_thread);

    InterlockedAnd(&pde->virq_thread_running, 0);
    KeSetEvent(&pde->virq_event, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(pde->virq_thread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(pde->virq_thread);

    // Then detach and cleanup our device
    ExDeleteNPagedLookasideList(&pde->dest_lookaside_list);
    IoDeleteSymbolicLink(&pde->symbolic_link);
    IoDeleteDevice(fdo);
    uxen_v4v_set_notify_fdo(fdo);
    uxen_v4v_free_preallocation(pde);
    InterlockedAnd(&g_deviceCreated, 0);
    return status;
}

static NTSTATUS gh_add_device(PDRIVER_OBJECT driver_object)
{
    NTSTATUS          status = STATUS_SUCCESS;
    UNICODE_STRING    device_name;
    PDEVICE_OBJECT    fdo = NULL;
    xenv4v_extension_t *pde = NULL;
    LONG              val;
    BOOLEAN           symlink = FALSE;
    LARGE_INTEGER     seed;
    WCHAR            *szSddl = NULL;
    UNICODE_STRING    sddlString;
    HANDLE handle;

    uxen_v4v_verbose("====>");

    // We only allow one instance of this device type. If more than on pdo is created we need
    val = InterlockedCompareExchange(&g_deviceCreated, 1, 0);
    if (val != 0) {
        uxen_v4v_warn("cannot instantiate more that one v4v device node");
        return STATUS_UNSUCCESSFUL;
    }

    do {
        // Create our device
        RtlInitUnicodeString(&device_name, V4V_DEVICE_NAME);
        szSddl = g_win5Sddl;
        RtlInitUnicodeString(&sddlString, szSddl);

        status =
            IoCreateDeviceSecure(driver_object,
                                 sizeof(xenv4v_extension_t),
                                 &device_name,
                                 FILE_DEVICE_UNKNOWN,
                                 FILE_DEVICE_SECURE_OPEN,
                                 FALSE,
                                 &sddlString,
                                 (LPCGUID)&GUID_SD_XENV4V_CONTROL_OBJECT,
                                 &fdo);
        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("IoCreateDeviceSecure failed error 0x%x", status);
            fdo = NULL;
            break;
        }


        uxen_v4v_set_notify_fdo(fdo);

        pde = (xenv4v_extension_t *)fdo->DeviceExtension;
        RtlZeroMemory(pde, sizeof(xenv4v_extension_t));
        RtlStringCchCopyW(pde->symbolic_linkText, XENV4V_SYM_NAME_LEN, V4V_SYMBOLIC_NAME);
        RtlInitUnicodeString(&pde->symbolic_link, pde->symbolic_linkText);

        // Create our symbolic link
        status = IoCreateSymbolicLink(&pde->symbolic_link, &device_name);
        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("IoCreateSymbolicLink failed error 0x%x", status);
            break;
        }
        symlink = TRUE;

        KeInitializeSpinLock(&pde->alloc_lock);
        pde->prealloc_blocks = NULL;

        // Setup the extension
        pde->magic = XENV4V_MAGIC;
        pde->fdo = fdo;
        IoInitializeRemoveLock(&pde->remove_lock, 'v4vx', 0, 0);
        pde->state = XENV4V_DEV_STOPPED; // wait for start
        pde->last_po_state = PowerSystemWorking;

        pde->virq_thread_running = 1;
        KeInitializeEvent(&pde->virq_event, NotificationEvent, FALSE);
        status = PsCreateSystemThread(&handle, 0, NULL, NULL, NULL,
                                      gh_v4v_virq_thread, fdo);
        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("PsCreateSystemThread(virq) failed: 0x%08X",
                         status);
            break;
        }
        status = ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, NULL,
                                           KernelMode, &pde->virq_thread, NULL);
        ZwClose(handle);
        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("get reference to virq thread failed: 0x%08X",
                         status);
            break;
        }
        KeSetPriorityThread(pde->virq_thread, LOW_REALTIME_PRIORITY);
        KeInitializeSpinLock(&pde->virq_lock);

        InitializeListHead(&pde->context_list);
        KeInitializeSpinLock(&pde->context_lock);
        pde->context_count = 0;
        InitializeListHead(&pde->ring_list);
        KeInitializeSpinLock(&pde->ring_lock);
        pde->ring_gen = 0;
        InitializeListHead(&pde->pending_irp_queue);
        pde->pending_irp_count = 0;
        KeInitializeSpinLock(&pde->queue_lock);
        IoCsqInitializeEx(&pde->csq_object,
                          gh_v4v_csq_insert_irp_ex,
                          gh_v4v_csq_remove_irp,
                          gh_v4v_csq_peek_next_irp,
                          gh_v4v_csq_acquire_lock,
                          gh_v4v_csq_release_lock,
                          gh_v4v_csq_complete_canceled_irp);
        InitializeListHead(&pde->dest_list);
        pde->dest_count = 0;
        InitializeListHead(&pde->notify_list);

        pde->notify_thread_running = 1;
        KeInitializeEvent(&pde->notify_event, NotificationEvent, FALSE);
        status = PsCreateSystemThread(&handle, 0, NULL, NULL, NULL,
                                      uxen_v4v_notify_thread, fdo);
        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("PsCreateSystemThread(notify) failed: 0x%08X",
                         status);
            break;
        }
        status = ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, NULL,
                                           KernelMode, &pde->notify_thread,
                                           NULL);
        ZwClose(handle);
        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("get reference to notify thread failed: 0x%08X",
                         status);
            break;
        }
        KeSetPriorityThread(pde->notify_thread, LOW_REALTIME_PRIORITY);

        ExInitializeNPagedLookasideList(&pde->dest_lookaside_list,
                                        NULL,
                                        NULL,
                                        0,
                                        sizeof(xenv4v_destination_t),
                                        XENV4V_TAG,
                                        0);
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
    } else  {
        uxen_v4v_install_pde(pde);
    }

    uxen_v4v_verbose("<====");

    return status;
}


NTSTATUS gh_destroy_device(PDRIVER_OBJECT driver_object)
{
    xenv4v_extension_t *pde = uxen_v4v_remove_pde();
    DEVICE_OBJECT *fdo;

    if (!pde) return STATUS_UNSUCCESSFUL;


    fdo = pde->fdo;

    if (!fdo) return STATUS_UNSUCCESSFUL;

    driver_object->MajorFunction[IRP_MJ_CREATE]         = NULL;
    driver_object->MajorFunction[IRP_MJ_CLEANUP]        = NULL;
    driver_object->MajorFunction[IRP_MJ_CLOSE]          = NULL;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NULL;
    driver_object->MajorFunction[IRP_MJ_READ]           = NULL;
    driver_object->MajorFunction[IRP_MJ_WRITE]          = NULL;

    return gh_remove_device(fdo);
}


NTSTATUS gh_create_device(PDRIVER_OBJECT driver_object)
{
    NTSTATUS status;

    uxen_v4v_verbose("====>");

    PsGetVersion(&g_osMajorVersion, &g_osMinorVersion, NULL, NULL);

    if ((g_osMajorVersion < 5) || ((g_osMajorVersion == 5) && (g_osMinorVersion < 1))) {
        uxen_v4v_warn("Windows XP or later operating systems supported!");
        return STATUS_UNSUCCESSFUL;
    }

    uxen_v4v_info("Starting driver...");

    status = gh_add_device(driver_object);

    uxen_v4v_verbose("DriverEntry returning 0x%x", status);

    uxen_v4v_verbose("<====");

    return status;
}

NTSTATUS gh_dispatch_init(PDRIVER_OBJECT driver_object)
{
    uxen_v4v_verbose("====>");

    PsGetVersion(&g_osMajorVersion, &g_osMinorVersion, NULL, NULL);

    if ((g_osMajorVersion < 5) || ((g_osMajorVersion == 5) && (g_osMinorVersion < 1))) {
        uxen_v4v_warn("Windows XP or later operating systems supported!");
        return STATUS_UNSUCCESSFUL;
    }

    driver_object->MajorFunction[IRP_MJ_CREATE]         = gh_v4v_dispatch_create;
    driver_object->MajorFunction[IRP_MJ_CLEANUP]        = gh_v4v_dispatch_cleanup;
    driver_object->MajorFunction[IRP_MJ_CLOSE]          = gh_v4v_dispatch_close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = gh_v4v_dispatch_device_control;
    driver_object->MajorFunction[IRP_MJ_READ]           = gh_v4v_dispatch_read;
    driver_object->MajorFunction[IRP_MJ_WRITE]          = gh_v4v_dispatch_write;

    uxen_v4v_verbose("<====");

    return STATUS_SUCCESS;
}



