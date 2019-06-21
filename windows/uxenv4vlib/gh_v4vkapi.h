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

/*
 *  This the kernel version of v4vapi. See the documentation in gh_v4vapi.h for usage.
*/
#pragma  once
#define V4V_EXCLUDE_INTERNAL
#define XENV4V_DRIVER
#include <ntddk.h>
#include <windef.h>
#include <xen/v4v.h>
#include "gh_v4vapi.h"

// A pool tag
#define XENV4V_TAG              'V4VX'
#define V4V_EVENT_NAME          L"\\KernelObjects\\uxenv4vevent"

/* Typedef for internal stream header structure */
typedef struct v4v_stream_header v4v_stream_t, *Pv4v_stream_t;

typedef struct v4v_channel {
    HANDLE v4v_handle; /* handle for open V4V file */
    PKEVENT recv_event; /* data arrival, new connection for accept */
    HANDLE recv_event_handle; /* data arrival, new connection for accept */
    ULONG  flags;     /* configuration flags set by caller */
} v4v_channel_t;

typedef enum v4v_status_type_struct {
    V4V_UNINTIALIZED = 1,
    V4V_OPEN,
    V4V_CLOSED,
    V4V_BOUND,
    V4V_CONNECTED,
    V4V_DISCONNECTED,
    V4V_ERROR
} v4v_status_type_t;

typedef struct  uxen_v4v_struct {
    v4v_channel_t             channel;
    PFILE_OBJECT            file_object;
    PDEVICE_OBJECT          dev_object;
    v4v_status_type_t         state;
} uxen_v4v_t;

HANDLE  __inline NTAPI v4v_handle(uxen_v4v_t *v4v)
{
    return v4v->channel.v4v_handle;
}
void    __inline NTAPI v4v_set_flag (uxen_v4v_t *v4v, ULONG flags)
{
    v4v->channel.flags = flags;
}
ULONG   __inline NTAPI v4v_flag (uxen_v4v_t *v4v)
{
    return v4v->channel.flags;
}
void    __inline NTAPI V4VSetState (uxen_v4v_t *v4v, v4v_status_type_t state)
{
    v4v->state = state;
}
v4v_status_type_t __inline NTAPI  v4v_state(uxen_v4v_t *v4v)
{
    return v4v->state;
}

static __inline  NTSTATUS
uxen_v4v_dev_object(uxen_v4v_t *v4v)
{
    NTSTATUS        status;
    UNICODE_STRING  dev_name;

    RtlInitUnicodeString(&dev_name, V4V_DEVICE_NAME);
    status = IoGetDeviceObjectPointer (&dev_name,
                                       FILE_READ_DATA,
                                       &v4v->file_object,
                                       &v4v->dev_object);
    if (status != STATUS_SUCCESS) {
        uxen_v4v_err("IoGetDeviceObjectPointer failed error 0x%x", status);
    }
    return status;
};

static __inline  PIO_STACK_LOCATION
uxen_v4v_irpstack(uxen_v4v_t *v4v, PIRP irp)
{
    PIO_STACK_LOCATION  stack;

    stack = IoGetNextIrpStackLocation(irp);
    stack->MajorFunction = IRP_MJ_DEVICE_CONTROL;
    stack->DeviceObject = v4v->dev_object;
    stack->FileObject = v4v->file_object;
    return stack;
}

extern  NTSTATUS ZwCreateEvent( PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);

static __inline  HANDLE
uxen_v4v_create_event(uxen_v4v_t *v4v, PUNICODE_STRING drv_name)
{
    NTSTATUS        status;
    ULONG           attributes;
    HANDLE          ioctl_handle = 0;
    OBJECT_ATTRIBUTES   oa;
    BOOLEAN state = FALSE;

    UNREFERENCED_PARAMETER (v4v);

    attributes = OBJ_OPENIF;
    InitializeObjectAttributes(&oa, drv_name, attributes, NULL, NULL);
    status = ZwCreateEvent (&ioctl_handle, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, state );
    if (!NT_SUCCESS(status))
        ioctl_handle = (HANDLE)0;
    return ioctl_handle;
}

static __inline  PKEVENT
uxen_v4v_create_kevent(PHANDLE ioctl_handle)
{
    UNICODE_STRING  event_name;
    ULONG           attributes;
    PKEVENT         kevent;
    OBJECT_ATTRIBUTES   oa;

    RtlInitUnicodeString(&event_name, L"");
    attributes = OBJ_OPENIF | OBJ_KERNEL_HANDLE;
    InitializeObjectAttributes(&oa, &event_name, attributes, NULL, NULL);
    kevent = IoCreateSynchronizationEvent(&event_name, ioctl_handle);
    if (!kevent) {
        uxen_v4v_err("IoCreateSynchronizationEvent failed");
        kevent =  NULL;
    }
    else {
        KeResetEvent(kevent);
    }
    return kevent;
}

static __inline  NTSTATUS
uxen_v4v_init_dev(uxen_v4v_t *v4v, size_t ring_size)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    v4v_init_values_t     init = {0};
    HANDLE              ioctl_handle = 0;
    HANDLE              event_handle = 0;
    PIO_STACK_LOCATION  stack;
    UNICODE_STRING      drv_name;
    PKEVENT             kioctl;
    PIRP                irp;
    IO_STATUS_BLOCK     io_status;

    do {

        //Event for V4v
        RtlInitUnicodeString(&drv_name, V4V_EVENT_NAME);
        event_handle = uxen_v4v_create_event(v4v, &drv_name); //IoCreateSynchronizationEvent(&drv_name, &ioctl_handle);
        init.ring_length = (ULONG32)ring_size;
        init.rx_event = event_handle;
        if (init.rx_event == NULL) {
            uxen_v4v_err("uxen_v4v_create_event failed");
            break;
        }
        //KEvent for ioctl call
        kioctl = uxen_v4v_create_kevent(&ioctl_handle);
        if (!kioctl)
            break;

        irp = IoBuildDeviceIoControlRequest(V4V_IOCTL_INITIALIZE, v4v->dev_object, &init, sizeof(init), NULL, 0, FALSE, kioctl, &io_status);
        if (!irp) break;

        stack = uxen_v4v_irpstack(v4v, irp);
        status = IoCallDriver(v4v->dev_object, irp);

        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(kioctl, Executive, KernelMode, FALSE, NULL);
        }

        if (status != STATUS_SUCCESS && status != STATUS_PENDING) {
            uxen_v4v_err("IoCallDriver failed error 0x%x", status);
            status = STATUS_UNSUCCESSFUL;
            break;
        } else {
            status = ObReferenceObjectByHandle(
                init.rx_event,
                EVENT_MODIFY_STATE,
                *ExEventObjectType,
                KernelMode,
                (void **)&v4v->channel.recv_event,
                NULL);
            v4v->channel.recv_event_handle = init.rx_event;
        }
    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        if (init.rx_event) ZwClose(init.rx_event);
    } else
        v4v->state = V4V_OPEN;

    if (ioctl_handle)
        ZwClose(ioctl_handle);
    return status;
}

static __inline  NTSTATUS
uxen_v4v_connect_wait(uxen_v4v_t *v4v)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    v4v_wait_values_t     connect;
    PIRP                irp;
    HANDLE              ioctl_handle = 0;
    PKEVENT             kevent;
    PIO_STACK_LOCATION  pStack;
    IO_STATUS_BLOCK     io_status;

    do {
        RtlZeroMemory(&connect, sizeof(v4v_wait_values_t));

        kevent = uxen_v4v_create_kevent(&ioctl_handle);
        irp = IoBuildDeviceIoControlRequest(V4V_IOCTL_WAIT, v4v->dev_object,
            &connect, sizeof(v4v_wait_values_t), &connect, sizeof(v4v_wait_values_t),
            FALSE, kevent, &io_status);

        pStack = uxen_v4v_irpstack(v4v, irp);
        status = IoCallDriver(v4v->dev_object, irp);

        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(kevent, Executive, KernelMode, FALSE, NULL);
        }

        if (status != STATUS_SUCCESS) {
            uxen_v4v_err("IoCallDriver failed error 0x%x", status);
            break;
        }
    } while (FALSE);

    ZwClose(ioctl_handle);
    return status;
}

__inline  NTSTATUS
uxen_v4v_connect(uxen_v4v_t *v4v, domid_t to_domain, uint32_t port)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    v4v_connect_values_t  connect;
    PIRP                irp;
    HANDLE              ioctl_handle = 0;
    PKEVENT             kevent;
    PIO_STACK_LOCATION  pStack;
    IO_STATUS_BLOCK     io_status;

    do {
        RtlZeroMemory(&connect, sizeof(v4v_connect_values_t));
        connect.ringAddr.domain = to_domain;
        connect.ringAddr.port = port;
        kevent = uxen_v4v_create_kevent(&ioctl_handle);
        irp = IoBuildDeviceIoControlRequest(V4V_IOCTL_CONNECT, v4v->dev_object,
            &connect, sizeof(v4v_wait_values_t), &connect, sizeof(v4v_wait_values_t),
            FALSE, kevent, &io_status);

        pStack = uxen_v4v_irpstack(v4v, irp);
        status = IoCallDriver(v4v->dev_object, irp);
        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(kevent, Executive, KernelMode, FALSE, NULL);
        }
        if (status != STATUS_SUCCESS) {
            uxen_v4v_err("IoCallDriver failed error 0x%x", status);
            break;
        }
    } while (FALSE);

    v4v->state = V4V_CONNECTED;
    ZwClose(ioctl_handle);
    return status;
}

__inline  NTSTATUS
uxen_v4v_disconnect(uxen_v4v_t   *v4v)
{
    PIO_STACK_LOCATION  pStack;
    PKEVENT             kevent;
    PIRP                irp;
    HANDLE              ioctl_handle = 0;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    IO_STATUS_BLOCK     io_status;

    do {
        kevent = uxen_v4v_create_kevent(&ioctl_handle);
        irp = IoBuildDeviceIoControlRequest(V4V_IOCTL_DISCONNECT, v4v->dev_object, NULL, 0, NULL, 0, FALSE, kevent, &io_status);
        pStack = uxen_v4v_irpstack(v4v, irp);
        status = IoCallDriver(v4v->dev_object, irp);
        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(kevent, Executive, KernelMode, FALSE, NULL);
        }
        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("IoCallDriver failed error 0x%x", status);
            break;
        }
    } while (FALSE);

    if (NT_SUCCESS(status))
        v4v->state = V4V_DISCONNECTED;
    else
        v4v->state = V4V_ERROR;
    ZwClose(ioctl_handle);
    return status;
}

__inline  NTSTATUS
uxen_v4v_close(uxen_v4v_t *v4v)
{
    NTSTATUS status;

    ObDereferenceObject(v4v->file_object);
    ObDereferenceObject(v4v->channel.recv_event);

    do {
        status = ZwClose(v4v->channel.recv_event_handle);
        if (!NT_SUCCESS(status)) break;

        status = ZwClose(v4v->channel.v4v_handle);
        if (!NT_SUCCESS(status)) break;
    } while (FALSE);

    if (!NT_SUCCESS(status))
        v4v->state = V4V_ERROR;
    else
        v4v->state = V4V_CLOSED;

    return status;
}

__inline  NTSTATUS
uxen_v4v_write(uxen_v4v_t *v4v, PVOID buf, UINT len, PIO_STATUS_BLOCK iosb)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    PIRP                irp;
    HANDLE              ioctl_handle = 0;
    PKEVENT             kevent;
    PIO_STACK_LOCATION  stack;

    do {
        kevent = uxen_v4v_create_kevent(&ioctl_handle);
        irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE,
                                           v4v->dev_object, buf, len,
                                           NULL, kevent,
                                           iosb);
        if (!irp ) {
            uxen_v4v_err("IoBuildSynchronousFsdRequest failed");
            break;
        }

        stack = IoGetNextIrpStackLocation(irp);
        stack->DeviceObject = v4v->dev_object;
        stack->FileObject = v4v->file_object;
        status = IoCallDriver(v4v->dev_object, irp);

        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(kevent, Executive, KernelMode, FALSE, NULL);
        }

        if (status != STATUS_SUCCESS) {
            uxen_v4v_err("IoCallDriver failed error 0x%x", status);
            break;
        }
    } while (FALSE);

    ZwClose(ioctl_handle);
    return status;
}

__inline  NTSTATUS
uxen_v4v_read(uxen_v4v_t *v4v, PVOID buf, UINT len, PIO_STATUS_BLOCK iosb)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    PIRP                irp;
    HANDLE              ioctl_handle = 0;
    PKEVENT             kevent;
    PIO_STACK_LOCATION  stack;

    do {
        kevent = uxen_v4v_create_kevent(&ioctl_handle);
        irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                           v4v->dev_object, buf, len,
                                           NULL, kevent,
                                           iosb);
        if (!irp ) {
            uxen_v4v_err("IoBuildSynchronousFsdRequest failed");
            break;
        }

        stack = IoGetNextIrpStackLocation(irp);
        stack->DeviceObject = v4v->dev_object;
        stack->FileObject = v4v->file_object;
        status = IoCallDriver(v4v->dev_object, irp);

        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(kevent, Executive, KernelMode, FALSE, NULL);
        }

        if (status != STATUS_SUCCESS) {
            uxen_v4v_err("IoCallDriver failed error 0x%x", status);
            break;
        }
    } while (FALSE);

    ZwClose(ioctl_handle);
    return status;
}

__inline  NTSTATUS
uxen_v4v_bind(uxen_v4v_t *v4v, const uint8_t* partner_uuid, domid_t to_domain, uint32_t port)
{
    NTSTATUS            status = STATUS_SUCCESS;
    v4v_ring_id_t       v4vid;
    v4v_bind_values_t   bind = {0};
    PIRP                irp;
    HANDLE              ioctl_handle = 0;
    PKEVENT             kioctl;
    PIO_STACK_LOCATION  pStack;
    IO_STATUS_BLOCK     io_status;

    do {


        //Format Bind IOCTL
        v4vid.addr.domain = V4V_DOMID_NONE;
        v4vid.addr.port = port;
        v4vid.partner = to_domain;
        if (partner_uuid) {
            v4vid.partner = V4V_DOMID_UUID;
            RtlCopyMemory(&bind.partner, partner_uuid, sizeof(bind.partner));
        }
        RtlCopyMemory(&bind.ring_id, &v4vid, sizeof(v4v_ring_id_t));

        kioctl = uxen_v4v_create_kevent(&ioctl_handle);
        irp = IoBuildDeviceIoControlRequest(V4V_IOCTL_BIND, v4v->dev_object,
            &bind, sizeof(v4v_bind_values_t), &bind, sizeof(v4v_bind_values_t), FALSE, kioctl, &io_status);
        if (!irp)break;

        //Call Bind IOCTL
        pStack = uxen_v4v_irpstack(v4v, irp);
        status = IoCallDriver(v4v->dev_object, irp);

        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(kioctl, Executive, KernelMode, FALSE, NULL);
        }

        if (status != STATUS_SUCCESS && status != STATUS_PENDING ) {
            uxen_v4v_err("IoCallDriver failed error 0x%x", status);
            status = STATUS_UNSUCCESSFUL;
            break;
        }
    } while (FALSE);

    if (ioctl_handle) ZwClose(ioctl_handle);
    return status;
}

__inline  NTSTATUS
uxen_v4v_open_dgram_port (uxen_v4v_t *v4v, size_t ring_size, const uint8_t* partner_uuid, domid_t domain, uint32_t port)
{
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   oa;
    HANDLE              hd = 0;
    ULONG               attributes;
    IO_STATUS_BLOCK     io_status;
    UNICODE_STRING      dev_name;

    RtlInitUnicodeString(&dev_name, V4V_DEVICE_NAME);
    attributes = OBJ_OPENIF | OBJ_KERNEL_HANDLE;
    InitializeObjectAttributes( &oa,
                                &dev_name,
                                attributes,
                                NULL, NULL);

    do {

        status = ZwCreateFile(&hd,  GENERIC_READ | GENERIC_WRITE, &oa, &io_status, NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                              FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_ALERT,
                              NULL, 0);

        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("ZwCreateFile failed error 0x%x", status);
            break;

        } else {
            OBJECT_HANDLE_INFORMATION hdInfo;
            status = ObReferenceObjectByHandle(hd, EVENT_ALL_ACCESS, *IoFileObjectType, KernelMode,
                                               (PVOID *)&v4v->file_object, &hdInfo);
            v4v->dev_object = v4v->file_object->DeviceObject;
        }

        status = uxen_v4v_init_dev(v4v, ring_size);
        if (status != STATUS_SUCCESS)
            break;

        status = uxen_v4v_bind(v4v, partner_uuid, domain, port);
        if (status != STATUS_SUCCESS)
            break;

    } while (FALSE);

    if (status != STATUS_SUCCESS) {
        if (hd) ZwClose(hd);
        if (v4v->channel.recv_event_handle)
            ZwClose(v4v->channel.recv_event_handle);
    } else {
        v4v->channel.v4v_handle = hd;
    }
    return status;
}

__inline  NTSTATUS
uxen_v4v_open_device(uxen_v4v_t *v4v, size_t ring_size, domid_t domain, uint32_t port)
{
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   oa;
    HANDLE              hd = 0;
    ULONG               attributes;
    IO_STATUS_BLOCK     io_status;
    UNICODE_STRING      dev_name;

    RtlInitUnicodeString(&dev_name, V4V_DEVICE_NAME);
    attributes = OBJ_OPENIF | OBJ_KERNEL_HANDLE;
    InitializeObjectAttributes( &oa,
                                &dev_name,
                                attributes,
                                NULL, NULL);

    do {

        status = ZwCreateFile(&hd,  GENERIC_READ | GENERIC_WRITE, &oa, &io_status, NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                              FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_ALERT,
                              NULL, 0);

        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("ZwCreateFile failed error 0x%x", status);
            break;

        } else {
            OBJECT_HANDLE_INFORMATION hdInfo;
            status = ObReferenceObjectByHandle(hd, EVENT_ALL_ACCESS, *IoFileObjectType, KernelMode,
                                               (PVOID *)&v4v->file_object, &hdInfo);
            v4v->dev_object = v4v->file_object->DeviceObject;
        }

        status = uxen_v4v_init_dev(v4v, ring_size);
        if (status != STATUS_SUCCESS)
            break;

        status = uxen_v4v_bind(v4v, NULL, domain, port);
        if (status != STATUS_SUCCESS)
            break;

        status = uxen_v4v_connect(v4v, domain, port);
        if (status != STATUS_SUCCESS)
            break;

    } while (FALSE);

    if (status != STATUS_SUCCESS) {
        if (hd) ZwClose(hd);
        if (v4v->channel.recv_event_handle)
            ZwClose(v4v->channel.recv_event_handle);
    } else {
        v4v->channel.v4v_handle = hd;
    }
    return status;
}

__inline  void
uxen_v4v_destroy(uxen_v4v_t *v4v)
{
    if (v4v) {
        ExFreePoolWithTag(v4v, XENV4V_TAG );
    }
}

