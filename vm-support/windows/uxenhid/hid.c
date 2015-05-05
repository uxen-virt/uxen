/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>
#include <hidport.h>

#include "uxenhid.h"

static const wchar_t manufacturer_str[] = L"uXen";
static const wchar_t product_str[] = L"v4v HID device";
static const wchar_t serial_number[] = L"0.001";

#if 0
static void
hexdump(PVOID buf, ULONG start, ULONG stop, BOOLEAN ascii)
{
    UCHAR *p = buf;
    UCHAR c;
    ULONG diff, i;

     if (!(uxen_kd_mask & (UXEN_KD_DBG | UXEN_KD_USE_OSPRINTK)) ||
         !(*KdDebuggerEnabled))
        return;

    while (start < stop ) {
        diff = stop - start;
        if (diff > 16)
            diff = 16;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, ":%05X  ",
                   start);

        for (i = 0; i < diff; i++)
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%02X ",
                       *(p + start + i));

        if (ascii) {
            for (i = diff; i < 16; i++)
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "   ");
            for (i = 0; i < diff; i++) {
                c = *(p + start + i);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%c",
                           isprint(c) ? c : '.');
            }
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");
        start += 16;
    }
}
#endif

static void
hid_v4v_cb(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2)
{
    DEVICE_EXTENSION *devext = ctx;
    SSIZE_T len;
    UXENHID_MSG_HEADER hdr;

    UNREFERENCED_PARAMETER(ctx2);
    UNREFERENCED_PARAMETER(ring);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&devext->v4v_lock);

    len = uxen_v4v_copy_out(ring, NULL, NULL, &hdr, sizeof (hdr), 0);
    while (len >= 0) {
        IRP *irp;

        if (len < sizeof (hdr)) {
            uxen_err("uxen_v4v_copy_out(): %d", len);
            uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 1);

            len = uxen_v4v_copy_out(ring, NULL, NULL, &hdr, sizeof (hdr), 0);
            continue;
        }

        if (hdr.type == UXENHID_REQUEST_REPORT_DESCRIPTOR &&
            hdr.msglen < (65536 + sizeof (hdr))) {

            devext->rpt_desc_len = (USHORT)(hdr.msglen - sizeof (hdr));
            devext->rpt_desc = ExAllocatePoolWithTag(NonPagedPool,
                                                     devext->rpt_desc_len,
                                                     UXENHID_POOL_TAG);

            if (devext->rpt_desc)
                v4v_copy_out_offset(ring->ring, NULL, NULL, devext->rpt_desc,
                                    sizeof (hdr) + hdr.msglen, 1, sizeof (hdr));
        }

        if (hdr.type == UXENHID_FEATURE_REPORT &&
            hdr.msglen >= (sizeof (UCHAR) + sizeof (hdr))) {
            UCHAR report_id;

            /* Read report id without consuming */
            v4v_copy_out_offset(ring->ring, NULL, NULL, &report_id,
                                sizeof (hdr) + sizeof (report_id), 0, sizeof (hdr));


            irp = IoCsqRemoveNextIrp(&devext->pending_feature_query_csq,
                                     &report_id);
            if (irp) {
                HID_XFER_PACKET *pkt = irp->UserBuffer;

                if (pkt->reportBufferLen < hdr.msglen - sizeof (hdr)) {
                    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
                    irp->IoStatus.Information = 0;
                    uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 1);
                } else {
                    v4v_copy_out_offset(ring->ring, NULL, NULL, pkt->reportBuffer,
                                        sizeof (hdr) + hdr.msglen, 1, sizeof (hdr));
                    irp->IoStatus.Status = STATUS_SUCCESS;
                    irp->IoStatus.Information = hdr.msglen - sizeof (hdr);
                }

                KeReleaseSpinLockFromDpcLevel(&devext->v4v_lock);
                IoCompleteRequest(irp, IO_NO_INCREMENT);
                IoReleaseRemoveLock(&devext->remove_lock, irp);
                KeAcquireSpinLockAtDpcLevel(&devext->v4v_lock);

                len = uxen_v4v_copy_out(ring, NULL, NULL, &hdr, sizeof (hdr), 0);
                continue;
            }

            /*
             * This feature report was not queried, treat it as a normal
             * report.
             */
            hdr.type = UXENHID_REPORT;
        }

        irp = IoCsqRemoveNextIrp(&devext->pending_request_csq, &hdr.type);
        if (irp) {
            IO_STACK_LOCATION *loc = IoGetCurrentIrpStackLocation(irp);

            switch (loc->Parameters.DeviceIoControl.IoControlCode) {
            case IOCTL_HID_GET_DEVICE_DESCRIPTOR:
                {
                    HID_DESCRIPTOR *desc = irp->UserBuffer;

                    if (loc->Parameters.DeviceIoControl.OutputBufferLength <
                        sizeof (*desc)) {
                        irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
                        break;
                    }

                    desc->bLength = sizeof (HID_DESCRIPTOR);
                    desc->bDescriptorType = HID_HID_DESCRIPTOR_TYPE;
                    desc->bcdHID = HID_REVISION;
                    desc->bCountry = 0;
                    desc->bNumDescriptors = 1;
                    desc->DescriptorList[0].bReportType = HID_REPORT_DESCRIPTOR_TYPE;
                    desc->DescriptorList[0].wReportLength = devext->rpt_desc_len;

                    irp->IoStatus.Information = sizeof (*desc);
                    irp->IoStatus.Status = STATUS_SUCCESS;
                }
                break;
            case IOCTL_HID_GET_REPORT_DESCRIPTOR:
                if (loc->Parameters.DeviceIoControl.OutputBufferLength <
                    devext->rpt_desc_len) {
                    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }

                RtlCopyMemory(irp->UserBuffer, devext->rpt_desc,
                              devext->rpt_desc_len);
                irp->IoStatus.Information = devext->rpt_desc_len;
                irp->IoStatus.Status = STATUS_SUCCESS;
                break;
            case IOCTL_HID_READ_REPORT:
                if (loc->Parameters.DeviceIoControl.OutputBufferLength <
                    hdr.msglen - sizeof (hdr)) {
                    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
                    irp->IoStatus.Information = 0;
                    uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 1);
                    break;
                }

                v4v_copy_out_offset(ring->ring, NULL, NULL, irp->UserBuffer,
                                    sizeof (hdr) + hdr.msglen, 1, sizeof (hdr));
                irp->IoStatus.Status = STATUS_SUCCESS;
                irp->IoStatus.Information = hdr.msglen - sizeof (hdr);

                break;
            default:
                uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 1);
                irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
                uxen_err("unrecognized IRP ioctl type: %x",
                         loc->Parameters.DeviceIoControl.IoControlCode);

            }

            KeReleaseSpinLockFromDpcLevel(&devext->v4v_lock);
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            IoReleaseRemoveLock(&devext->remove_lock, irp);
            KeAcquireSpinLockAtDpcLevel(&devext->v4v_lock);
        } else
            uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 1);

        len = uxen_v4v_copy_out(ring, NULL, NULL, &hdr, sizeof (hdr), 0);
    }

    KeReleaseSpinLockFromDpcLevel(&devext->v4v_lock);
    uxen_v4v_notify();
}

static void
pending_request_lock(IO_CSQ *csq, KIRQL *irql)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_request_csq);
    KeAcquireSpinLock(&devext->pending_request_lock, irql);
}

static void
pending_request_unlock(IO_CSQ *csq, KIRQL irql)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_request_csq);
    KeReleaseSpinLock(&devext->pending_request_lock, irql);
}

static void
pending_request_insert(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_request_csq);
    InsertTailList(&devext->pending_request_list,
                   &irp->Tail.Overlay.ListEntry);
}

static void
pending_request_remove(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_request_csq);

    (void)devext;
    RemoveEntryList(&irp->Tail.Overlay.ListEntry);
}

static IRP *
pending_request_peek(IO_CSQ *csq, IRP *irp, void *ctx)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_request_csq);
    LIST_ENTRY *entry;

    if (irp)
        entry = irp->Tail.Overlay.ListEntry.Flink;
    else
        entry = devext->pending_request_list.Flink;

    while (entry != &devext->pending_request_list) {
        UXENHID_MSG_TYPE request_type;

        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);

        if (!ctx)
            return irp;

        request_type = *(UXENHID_MSG_TYPE *)ctx;

        if (irp->Tail.Overlay.DriverContext[0] == (PVOID)request_type)
            return irp;

        entry = entry->Flink;
    }

    return NULL;
}

static void
request_send_again(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2);

static void
pending_request_cancel(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_request_csq);

    uxen_v4v_cancel_async(&devext->peer, request_send_again, devext, irp);

    irp->IoStatus.Status = STATUS_CANCELLED;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    IoReleaseRemoveLock(&devext->remove_lock, irp);
}

static void
pending_report_lock(IO_CSQ *csq, KIRQL *irql)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_report_csq);
    KeAcquireSpinLock(&devext->pending_report_lock, irql);
}

static void
pending_report_unlock(IO_CSQ *csq, KIRQL irql)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_report_csq);
    KeReleaseSpinLock(&devext->pending_report_lock, irql);
}

static void
pending_report_insert(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_report_csq);
    InsertTailList(&devext->pending_report_list,
                   &irp->Tail.Overlay.ListEntry);
}

static void
pending_report_remove(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_report_csq);

    (void)devext;
    RemoveEntryList(&irp->Tail.Overlay.ListEntry);
}

static IRP *
pending_report_peek(IO_CSQ *csq, IRP *irp, void *ctx)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_report_csq);
    LIST_ENTRY *entry;

    if (irp)
        entry = irp->Tail.Overlay.ListEntry.Flink;
    else
        entry = devext->pending_request_list.Flink;

    while (entry != &devext->pending_request_list) {
        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);

        if (!ctx)
            return irp;

        if (ctx == irp)
            return irp;

        entry = entry->Flink;
    }

    return NULL;
}

static void
report_send_again(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2);

static void
pending_report_cancel(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_report_csq);

    uxen_v4v_cancel_async(&devext->peer, report_send_again, devext, irp);

    irp->IoStatus.Status = STATUS_CANCELLED;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    IoReleaseRemoveLock(&devext->remove_lock, irp);
}

static void
pending_feature_query_lock(IO_CSQ *csq, KIRQL *irql)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_feature_query_csq);
    KeAcquireSpinLock(&devext->pending_feature_query_lock, irql);
}

static void
pending_feature_query_unlock(IO_CSQ *csq, KIRQL irql)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_feature_query_csq);
    KeReleaseSpinLock(&devext->pending_feature_query_lock, irql);
}

static void
pending_feature_query_insert(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_feature_query_csq);
    InsertTailList(&devext->pending_feature_query_list,
                   &irp->Tail.Overlay.ListEntry);
}

static void
pending_feature_query_remove(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_feature_query_csq);

    (void)devext;
    RemoveEntryList(&irp->Tail.Overlay.ListEntry);
}

static IRP *
pending_feature_query_peek(IO_CSQ *csq, IRP *irp, void *ctx)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_feature_query_csq);
    LIST_ENTRY *entry;

    if (irp)
        entry = irp->Tail.Overlay.ListEntry.Flink;
    else
        entry = devext->pending_feature_query_list.Flink;

    while (entry != &devext->pending_feature_query_list) {
        HID_XFER_PACKET *pkt;

        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);

        if (!ctx)
            return irp;

        pkt = irp->UserBuffer;

        if (*(UCHAR *)ctx == pkt->reportId)
            return irp;

        entry = entry->Flink;
    }

    return NULL;
}

static void
feature_query_send_again(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2);

static void
pending_feature_query_cancel(IO_CSQ *csq, IRP *irp)
{
    DEVICE_EXTENSION *devext = CONTAINING_RECORD(csq, DEVICE_EXTENSION,
                                                 pending_feature_query_csq);

    uxen_v4v_cancel_async(&devext->peer, feature_query_send_again, devext, irp);

    irp->IoStatus.Status = STATUS_CANCELLED;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    IoReleaseRemoveLock(&devext->remove_lock, irp);
}

static void
uxenhid_resume(PKDPC dpc, PVOID deferred_context, PVOID arg1, PVOID arg2)
{
    DEVICE_EXTENSION *devext = deferred_context;
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[1];

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    msg.type = UXENHID_DEVICE_START;
    msg.msglen = sizeof (msg);
    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);

    ret = uxen_v4v_sendv_from_ring(devext->ring, &devext->peer,
                                   iov, 1, V4V_PROTO_DGRAM);
    if (ret != sizeof (msg))
        uxen_err("uxen_v4v_sendv_from_ring() failed: %d", ret);
}

NTSTATUS
hid_init(DEVICE_EXTENSION *devext)
{
    NTSTATUS status;
    UINT32 idx = 0; /* XXX */

    KeInitializeSpinLock(&devext->v4v_lock);

    devext->peer.port = UXENHID_V4V_PORT_BASE + idx;
    devext->peer.domain = 0;
    devext->ring = uxen_v4v_ring_bind(UXENHID_V4V_PORT_BASE + idx, 0,
                                      UXENHID_V4V_RING_LEN,
                                      hid_v4v_cb, devext, NULL);
    if (!devext->ring)
        return STATUS_NO_MEMORY;

    KeInitializeDpc(&devext->resume_dpc, uxenhid_resume, devext);
    uxen_v4vlib_set_resume_dpc(&devext->resume_dpc, NULL);

    InitializeListHead(&devext->pending_request_list);
    KeInitializeSpinLock(&devext->pending_request_lock);
    status = IoCsqInitialize(&devext->pending_request_csq,
                             pending_request_insert,
                             pending_request_remove,
                             pending_request_peek,
                             pending_request_lock,
                             pending_request_unlock,
                             pending_request_cancel);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoCsqInitialize() failed: 0x%08x", status);
        uxen_v4v_ring_free(devext->ring);
        return status;
    }

    InitializeListHead(&devext->pending_report_list);
    KeInitializeSpinLock(&devext->pending_report_lock);
    status = IoCsqInitialize(&devext->pending_report_csq,
                             pending_report_insert,
                             pending_report_remove,
                             pending_report_peek,
                             pending_report_lock,
                             pending_report_unlock,
                             pending_report_cancel);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoCsqInitialize() failed: 0x%08x", status);
        uxen_v4v_ring_free(devext->ring);
        return status;
    }

    InitializeListHead(&devext->pending_feature_query_list);
    KeInitializeSpinLock(&devext->pending_feature_query_lock);
    status = IoCsqInitialize(&devext->pending_feature_query_csq,
                             pending_feature_query_insert,
                             pending_feature_query_remove,
                             pending_feature_query_peek,
                             pending_feature_query_lock,
                             pending_feature_query_unlock,
                             pending_feature_query_cancel);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoCsqInitialize() failed: 0x%08x", status);
        uxen_v4v_ring_free(devext->ring);
        return status;
    }

    devext->rpt_desc = NULL;
    devext->rpt_desc_len = 0;

    return STATUS_SUCCESS;
}

void
hid_cleanup(DEVICE_EXTENSION *devext)
{
    uxen_v4v_ring_free(devext->ring);
    if (devext->rpt_desc)
        ExFreePoolWithTag(devext->rpt_desc, UXENHID_POOL_TAG);
}


#define uxenhid_v4v_sendv(devext, iov, niov, cb, ctx)   \
    uxen_v4v_sendv_from_ring_async((devext)->ring,      \
                                   &(devext)->peer,     \
                                   (iov), (niov),       \
                                   V4V_PROTO_DGRAM,     \
                                   (cb), (devext), (ctx))

static void
request_send_again(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2)
{
    DEVICE_EXTENSION *devext = ctx;
    IRP *irp = ctx2;
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[1];

    UNREFERENCED_PARAMETER(ring);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    msg.type = (UXENHID_MSG_TYPE)(SIZE_T)irp->Tail.Overlay.DriverContext[0];
    msg.msglen = sizeof (msg);
    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);

    ret = uxenhid_v4v_sendv(devext, iov, 1, request_send_again, irp);
    if ((ret != sizeof (msg)) && (ret != -EAGAIN)) {
        uxen_err("uxen_v4v_send_from_ring_async() failed: %d", ret);

        IoCsqRemoveNextIrp(&devext->pending_request_csq, &msg.type);

        irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&devext->remove_lock, irp);
    }
}

static NTSTATUS
uxenhid_send_request(DEVICE_EXTENSION *devext, IRP *irp,
                     UXENHID_MSG_TYPE request_type)
{
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[1];

    irp->Tail.Overlay.DriverContext[0] = (PVOID)request_type;
    IoCsqInsertIrp(&devext->pending_request_csq, irp, NULL);

    msg.type = request_type;
    msg.msglen = sizeof (msg);
    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);

    ret = uxenhid_v4v_sendv(devext, iov, 1, request_send_again, irp);
    if (ret != sizeof (msg)) {
        if (ret != -EAGAIN) {
            uxen_err("uxen_v4v_send_from_ring_async() failed: %d", ret);
            IoCsqRemoveNextIrp(&devext->pending_request_csq, &msg.type);

            return STATUS_INSUFFICIENT_RESOURCES;
        }
        return STATUS_PENDING;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
uxenhid_recv_report(DEVICE_EXTENSION *devext, IRP *irp)
{
    irp->Tail.Overlay.DriverContext[0] = (PVOID)UXENHID_REPORT;
    IoCsqInsertIrp(&devext->pending_request_csq, irp, NULL);

    return STATUS_PENDING;
}

static void
report_send_again(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2)
{
    DEVICE_EXTENSION *devext = ctx;
    IRP *irp = ctx2;
    HID_XFER_PACKET *pkt = irp->UserBuffer;
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[2];

    UNREFERENCED_PARAMETER(ring);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    msg.type = UXENHID_REPORT;
    msg.msglen = sizeof (msg) + pkt->reportBufferLen;

    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);
    iov[1].iov_base = (uint64_t)pkt->reportBuffer;
    iov[1].iov_len = pkt->reportBufferLen;

    ret = uxenhid_v4v_sendv(devext, iov, 2, report_send_again, irp);
    if (ret != -EAGAIN) {
        if (ret != (SSIZE_T)(sizeof (msg) + pkt->reportBufferLen)) {
            uxen_err("uxen_v4v_send_from_ring_async() failed: %d", ret);
            irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = ret;
        }

        IoCsqRemoveNextIrp(&devext->pending_report_csq, irp);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&devext->remove_lock, irp);
    }
}

static NTSTATUS
uxenhid_send_report(DEVICE_EXTENSION *devext, IRP *irp)
{
    HID_XFER_PACKET *pkt = irp->UserBuffer;
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[2];

    msg.type = UXENHID_REPORT;
    msg.msglen = sizeof (msg) + pkt->reportBufferLen;

    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);
    iov[1].iov_base = (uint64_t)pkt->reportBuffer;
    iov[1].iov_len = pkt->reportBufferLen;

    IoCsqInsertIrp(&devext->pending_report_csq, irp, NULL);

    ret = uxenhid_v4v_sendv(devext, iov, 2, report_send_again, irp);
    if (ret != (SSIZE_T)(sizeof (msg) + pkt->reportBufferLen)) {
        if (ret != -EAGAIN) {
            uxen_err("uxen_v4v_send_from_ring_async() failed: %d", ret);
            IoCsqRemoveNextIrp(&devext->pending_report_csq, irp);

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        return STATUS_PENDING;
    }

    IoCsqRemoveNextIrp(&devext->pending_report_csq, irp);
    irp->IoStatus.Information = ret;

    return STATUS_SUCCESS;
}

static void
feature_query_send_again(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2)
{
    DEVICE_EXTENSION *devext = ctx;
    IRP *irp = ctx2;
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[2];
    HID_XFER_PACKET *pkt;

    UNREFERENCED_PARAMETER(ring);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    pkt = irp->UserBuffer;

    msg.type = UXENHID_FEATURE_QUERY;
    msg.msglen = sizeof (msg) + sizeof (UCHAR);

    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);
    iov[1].iov_base = (uint64_t)&pkt->reportId;
    iov[1].iov_len = sizeof (UCHAR);

    ret = uxenhid_v4v_sendv(devext, iov, 2, feature_query_send_again, irp);
    if ((ret != (sizeof (msg) + sizeof (UCHAR))) && (ret != -EAGAIN)) {
        uxen_err("uxen_v4v_send_from_ring_async() failed: %d", ret);

        IoCsqRemoveNextIrp(&devext->pending_request_csq, &pkt->reportId);

        irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&devext->remove_lock, irp);
    }
}

static NTSTATUS
uxenhid_send_feature_query(DEVICE_EXTENSION *devext, IRP *irp)
{
    HID_XFER_PACKET *pkt = irp->UserBuffer;
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[2];

    IoCsqInsertIrp(&devext->pending_feature_query_csq, irp, NULL);

    msg.type = UXENHID_FEATURE_QUERY;
    msg.msglen = sizeof (msg) + sizeof (UCHAR);

    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);
    iov[1].iov_base = (uint64_t)&pkt->reportId;
    iov[1].iov_len = sizeof (UCHAR);

    ret = uxenhid_v4v_sendv(devext, iov, 2, feature_query_send_again, irp);
    if (ret != (sizeof (msg) + sizeof (UCHAR))) {
        if (ret != -EAGAIN) {
            uxen_err("uxen_v4v_send_from_ring_async() failed: %d", ret);
            IoCsqRemoveNextIrp(&devext->pending_feature_query_csq, &pkt->reportId);

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        return STATUS_PENDING;
    }

    return STATUS_SUCCESS;
}

#define CHECK_OUTPUT_BUFFER(reqlen)                                     \
    {                                                                   \
        IO_STACK_LOCATION *loc = IoGetCurrentIrpStackLocation(irp);     \
        ULONG len = loc->Parameters.DeviceIoControl.OutputBufferLength; \
        if (len < (reqlen)) {                                           \
            uxen_err("Output buffer too small %d/%d", len, (reqlen));   \
            return STATUS_BUFFER_TOO_SMALL;                             \
        }                                                               \
    }

NTSTATUS
hid_device_descriptor(DEVICE_EXTENSION *devext, IRP *irp, BOOLEAN *pending)
{
    NTSTATUS status;
    HID_DESCRIPTOR *desc = irp->UserBuffer;

    uxen_msg("");

    CHECK_OUTPUT_BUFFER(sizeof (*desc));

    if (!devext->rpt_desc) {
        status = uxenhid_send_request(devext, irp,
                                      UXENHID_REQUEST_REPORT_DESCRIPTOR);
        if ((status != STATUS_SUCCESS && status != STATUS_PENDING))
            return status;

        *pending = TRUE;
        return STATUS_PENDING;
    };

    desc->bLength = sizeof (HID_DESCRIPTOR);
    desc->bDescriptorType = HID_HID_DESCRIPTOR_TYPE;
    desc->bcdHID = HID_REVISION;
    desc->bCountry = 0;
    desc->bNumDescriptors = 1;
    desc->DescriptorList[0].bReportType = HID_REPORT_DESCRIPTOR_TYPE;
    desc->DescriptorList[0].wReportLength = devext->rpt_desc_len;

    irp->IoStatus.Information = sizeof (*desc);

    return STATUS_SUCCESS;
}

NTSTATUS
hid_report_descriptor(DEVICE_EXTENSION *devext, IRP *irp, BOOLEAN *pending)
{
    NTSTATUS status;
    UCHAR *desc = irp->UserBuffer;

    uxen_msg("");

    if (!devext->rpt_desc) {
        status = uxenhid_send_request(devext, irp,
                                      UXENHID_REQUEST_REPORT_DESCRIPTOR);
        if ((status != STATUS_SUCCESS) && (status != STATUS_PENDING))
            return status;

        *pending = TRUE;
        return STATUS_PENDING;
    };

    CHECK_OUTPUT_BUFFER(devext->rpt_desc_len);

    RtlCopyMemory(desc, devext->rpt_desc, devext->rpt_desc_len);
    irp->IoStatus.Information = devext->rpt_desc_len;

    return STATUS_SUCCESS;
}

NTSTATUS
hid_read_report(DEVICE_EXTENSION *devext, IRP *irp, BOOLEAN *pending)
{
    NTSTATUS status;

    status = uxenhid_recv_report(devext, irp);
    if (status == STATUS_PENDING)
        *pending = TRUE;

    return status;
}

NTSTATUS
hid_write_report(DEVICE_EXTENSION *devext, IRP *irp, BOOLEAN *pending)
{
    NTSTATUS status;

    uxen_msg("");

    status = uxenhid_send_report(devext, irp);
    if (status == STATUS_PENDING)
        *pending = TRUE;

    return status;
}

NTSTATUS
hid_set_feature(DEVICE_EXTENSION *devext, IRP *irp, BOOLEAN *pending)
{
    NTSTATUS status;

    uxen_msg("");

    status = uxenhid_send_report(devext, irp);
    if (status == STATUS_PENDING)
        *pending = TRUE;

    return status;
}

NTSTATUS
hid_get_feature(DEVICE_EXTENSION *devext, IRP *irp, BOOLEAN *pending)
{
    NTSTATUS status;

    uxen_msg("");

    status = uxenhid_send_feature_query(devext, irp);
    if ((status != STATUS_SUCCESS) && (status != STATUS_PENDING))
        return status;

    *pending = TRUE;

    return STATUS_PENDING;
}

NTSTATUS
hid_device_string(DEVICE_EXTENSION *devext, IRP *irp, BOOLEAN *pending)
{
    NTSTATUS status;
    PIO_STACK_LOCATION loc = IoGetCurrentIrpStackLocation(irp);
    UINT32 req;

    UNREFERENCED_PARAMETER(devext);

    *pending = FALSE;

    req = PtrToUlong(loc->Parameters.DeviceIoControl.Type3InputBuffer);

    uxen_msg("request=%x", req);

    switch (req & 0xFFFF) {
    case HID_STRING_ID_IMANUFACTURER:
        if (loc->Parameters.DeviceIoControl.OutputBufferLength <
            sizeof (manufacturer_str)) {
            irp->IoStatus.Information = 0;
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(irp->UserBuffer, manufacturer_str, sizeof (manufacturer_str));
        irp->IoStatus.Information = sizeof (manufacturer_str);
        status = STATUS_SUCCESS;
        break;
    case HID_STRING_ID_IPRODUCT:
        if (loc->Parameters.DeviceIoControl.OutputBufferLength <
            sizeof (product_str)) {
            irp->IoStatus.Information = 0;
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(irp->UserBuffer, product_str, sizeof (product_str));
        irp->IoStatus.Information = sizeof (product_str);
        status = STATUS_SUCCESS;
        break;
    case HID_STRING_ID_ISERIALNUMBER:
        if (loc->Parameters.DeviceIoControl.OutputBufferLength <
            sizeof (serial_number)) {
            irp->IoStatus.Information = 0;
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(irp->UserBuffer, serial_number, sizeof (serial_number));
        irp->IoStatus.Information = sizeof (serial_number);
        status = STATUS_SUCCESS;
        break;
    default:
        irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    return status;
}

NTSTATUS
hid_device_attributes(DEVICE_EXTENSION *devext, IRP *irp)
{
    HID_DEVICE_ATTRIBUTES *attrib = irp->UserBuffer;

    UNREFERENCED_PARAMETER(devext);

    uxen_msg("");

    CHECK_OUTPUT_BUFFER(sizeof (*attrib));

    /*
     * XXX: Get this from bus driver
     */
    attrib->Size = sizeof (*attrib);
    attrib->VendorID = 0x2345;
    attrib->ProductID = 0x4564;
    attrib->VersionNumber = 0x0001;

    irp->IoStatus.Information = sizeof (*attrib);

    return STATUS_SUCCESS;
}

struct start_stop_context {
    UXENHID_MSG_TYPE type;
    KEVENT event;
    NTSTATUS status;
};

static void
start_stop_send_again(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2)
{
    DEVICE_EXTENSION *devext = ctx;
    struct start_stop_context *context = ctx2;
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[1];

    UNREFERENCED_PARAMETER(ring);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    msg.type = context->type;
    msg.msglen = sizeof (msg);
    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);

    ret = uxenhid_v4v_sendv(devext, iov, 1, start_stop_send_again, context);
    if (ret == sizeof (msg)) {
        context->status = STATUS_SUCCESS;
        KeSetEvent(&context->event, IO_NO_INCREMENT, FALSE);
    } else if (ret != -EAGAIN) {
        uxen_err("uxen_v4v_send_from_ring_async() failed: %d", ret);
        context->status = STATUS_INSUFFICIENT_RESOURCES;
        KeSetEvent(&context->event, IO_NO_INCREMENT, FALSE);
    }
}

static NTSTATUS
uxenhid_send_start_stop(DEVICE_EXTENSION *devext, UXENHID_MSG_TYPE type)
{
    UXENHID_MSG_HEADER msg;
    SSIZE_T ret;
    v4v_iov_t iov[1];
    struct start_stop_context ctx;
    NTSTATUS status;

    ctx.type = type;
    KeInitializeEvent(&ctx.event, NotificationEvent, FALSE);

    msg.type = type;
    msg.msglen = sizeof (msg);
    iov[0].iov_base = (uint64_t)&msg;
    iov[0].iov_len = sizeof (msg);

    ret = uxenhid_v4v_sendv(devext, iov, 1, start_stop_send_again, &ctx);
    if (ret != sizeof (msg)) {
        if (ret == -EAGAIN) {
            status = KeWaitForSingleObject(&ctx.event, Executive, KernelMode,
                                           FALSE, NULL);
            if (!NT_SUCCESS(status))
                uxen_v4v_cancel_async(&devext->peer, start_stop_send_again,
                                      devext, &ctx);
            else
                status = ctx.status;

            return status;
        }

        uxen_err("uxen_v4v_send_from_ring_async() failed: %d", ret);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
hid_start(DEVICE_EXTENSION *devext)
{
    return uxenhid_send_start_stop(devext, UXENHID_DEVICE_START);
}

NTSTATUS
hid_stop(DEVICE_EXTENSION *devext)
{
    return uxenhid_send_start_stop(devext, UXENHID_DEVICE_STOP);
}
