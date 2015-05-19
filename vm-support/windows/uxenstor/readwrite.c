/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenstor.h"

/* FIXME: all perfcnts are currently global */

#define scsi_cmd_cls(cmd)                                                     \
    (IS_SCSIOP_READ(cmd) ? 0 : (IS_SCSIOP_WRITE(cmd) ? 1 : 2))

static 
LONG_PTR req_id = 0;

ULONG ahci_state = 1;

static
void stor_v4v_e_again_callback(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2);

void csq_acquire_lock(PIO_CSQ csq, PKIRQL irql)
{
    PUXENSTOR_DEV_EXT dev_ext;

    dev_ext = GET_DEV_EXT(csq);
    KeAcquireSpinLock(&dev_ext->io_queue_lock, irql);
}

void csq_release_lock(PIO_CSQ csq, KIRQL irql)
{
    PUXENSTOR_DEV_EXT dev_ext;

    dev_ext = GET_DEV_EXT(csq);
    KeReleaseSpinLock(&dev_ext->io_queue_lock, irql);
}

void csq_insert_irp(PIO_CSQ csq, PIRP irp)
{
    PUXENSTOR_DEV_EXT dev_ext;
    PSCSI_REQUEST_BLOCK srb;
    int cls;

    ASSERT(!irp->Tail.Overlay.ListEntry.Blink &&
           !irp->Tail.Overlay.ListEntry.Flink);

    srb = IoGetCurrentIrpStackLocation(irp)->Parameters.Scsi.Srb;
    cls = scsi_cmd_cls(srb->Cdb[0]);
    perfcnt_arr_inc(v4v_scsi_queued_delta, cls);
    perfcnt_arr_set_max(v4v_scsi_queued_delta_peek, cls,
                        perfcnt_arr_get(v4v_scsi_queued_delta, cls));
#if LOG_HIGH_QUEUED_DELTA
    if (perfcnt_arr_get(v4v_scsi_queued_delta, cls) > 64)
        uxen_msg("high v4v_scsi_queued_delta: %I64d",
                 perfcnt_arr_get(v4v_scsi_queued_delta, cls));
#endif /* LOG_HIGH_QUEUED_DELTA */

    dev_ext = GET_DEV_EXT(csq);
    InsertTailList(&dev_ext->pending_irp_list, &irp->Tail.Overlay.ListEntry);
}

PIRP csq_peek_next_irp(PIO_CSQ csq, PIRP irp, PVOID ctx)
{
    PUXENSTOR_DEV_EXT dev_ext;
    PIRP next_irp = NULL;
    PLIST_ENTRY next_entry;
    PLIST_ENTRY list_head;

    dev_ext = GET_DEV_EXT(csq);
   
    list_head = &dev_ext->pending_irp_list;
        
    if (irp)
        next_entry = irp->Tail.Overlay.ListEntry.Flink;
    else
        next_entry = list_head->Flink;
    
    while (next_entry != list_head) {
        next_irp = CONTAINING_RECORD(next_entry, IRP, Tail.Overlay.ListEntry);

        if (!ctx || next_irp->Tail.Overlay.DriverContext[0] == ctx)
            break;

        next_irp = NULL;
        next_entry = next_entry->Flink;
    }

    return next_irp;
}

void csq_remove_irp(PIO_CSQ csq, PIRP irp)
{
    PSCSI_REQUEST_BLOCK srb;

    UNREFERENCED_PARAMETER(csq);

    srb = IoGetCurrentIrpStackLocation(irp)->Parameters.Scsi.Srb;
    perfcnt_arr_dec(v4v_scsi_queued_delta, scsi_cmd_cls(srb->Cdb[0]));

    RemoveEntryList(&irp->Tail.Overlay.ListEntry);

    irp->Tail.Overlay.ListEntry.Blink = NULL;
    irp->Tail.Overlay.ListEntry.Flink = NULL;
}

void csq_complete_cancelled_irp(PIO_CSQ csq, PIRP irp)
{
    PUXENSTOR_DEV_EXT dev_ext;

    perfcnt_inc(v4v_scsi_cancelled);

    uxen_msg("IRP 0x%p has been cancelled", irp);

    dev_ext = GET_DEV_EXT(csq);

    /* this is synchronous call */
    uxen_v4v_cancel_async(&dev_ext->v4v_addr,
                          stor_v4v_e_again_callback, dev_ext, irp);

    irp->IoStatus.Status = STATUS_CANCELLED;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

void stor_v4v_callback(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2)
{
    PUXENSTOR_DEV_EXT dev_ext;
    ssize_t len;
    XFER_HEADER hdr;
    PIRP irp;
    PCHAR buf;
    PSCSI_REQUEST_BLOCK srb;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(ctx2);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    perfcnt_inc(stor_v4v_callback);

    dev_ext = (PUXENSTOR_DEV_EXT)ctx;
    
    KeAcquireSpinLockAtDpcLevel(&dev_ext->v4v_lock);
    do {
        len = uxen_v4v_copy_out(ring, NULL, NULL,
                                &hdr, sizeof(hdr), 0);
        if (len < (int)sizeof(hdr)) {
            if (len < 0) 
                break; /* ring empty - leave */
            uxen_err("datagram smaller than header size (%d < %d)", 
                     len, (int)sizeof(hdr));
            uxen_v4v_copy_out(dev_ext->v4v_ring, NULL, NULL, NULL, 0, 1);
            continue;
        }

        perfcnt_inc(recv_v4v_msgs);

        irp = IoCsqRemoveNextIrp(&dev_ext->io_queue, (PVOID)(ULONG_PTR)hdr.seq);
        if (irp) {
            srb = IoGetCurrentIrpStackLocation(irp)->Parameters.Scsi.Srb;

            if (hdr.sense_size > 0) {
                perfcnt_inc(v4v_scsi_completed_error);

                if (srb->SenseInfoBufferLength >= hdr.sense_size &&
                    srb->SenseInfoBuffer)
                {
                    ASSERT(hdr.write_size == 0 &&
                           hdr.pagelist_size == 0 &&
                           hdr.read_size == 0 &&
                           hdr.cdb_size == 0);
                    v4v_copy_out_offset(ring->ring, NULL, NULL,
                                        (PUCHAR)srb->SenseInfoBuffer,
                                        hdr.sense_size + sizeof(hdr),
                                        1,
                                        sizeof(hdr));
                    srb->SenseInfoBufferLength = (UCHAR)hdr.sense_size;
#if DUMP_SENSE_DATA
                    uxen_debug("dumping %d bytes of sense data", 
                               srb->SenseInfoBufferLength);
                    buffer_dump_ex(UXEN_KD_DBG, " ", 
                                   srb->SenseInfoBuffer,
                                   srb->SenseInfoBufferLength,
                                   (ULONG)-1, 0);
#endif /* DUMP_SENSE_DATA */
                } else {
                    uxen_err("target sense data buffer NULL");
                    uxen_v4v_copy_out(dev_ext->v4v_ring, NULL, NULL, NULL, 0, 1);
                }

                srb->SrbStatus = SRB_STATUS_ERROR; /* FIXME: be more specific */
                status = STATUS_UNSUCCESSFUL;

                uxen_msg("request 0x%p:0x%p failed: 0x%08x", 
                         irp, irp->Tail.Overlay.DriverContext[0], status);
                trace_scsi(irp, srb, status,
                           (LONG_PTR)irp->Tail.Overlay.DriverContext[0]);
                irp->Tail.Overlay.DriverContext[0] = NULL;

                KeReleaseSpinLockFromDpcLevel(&dev_ext->v4v_lock);

                irp->IoStatus.Status = status;
                IoCompleteRequest(irp, IO_DISK_INCREMENT);

                KeAcquireSpinLockAtDpcLevel(&dev_ext->v4v_lock);

                continue;
            }

            perfcnt_inc(v4v_scsi_completed_sucess);

            if (srb->DataTransferLength > 0 &&
                TEST_FLAG(srb->SrbFlags, SRB_FLAGS_DATA_IN))
            {
                buf = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                   NormalPagePriority);
                ASSERT(buf);

                srb->DataTransferLength = min(srb->DataTransferLength,
                                              len - sizeof(hdr));
                ASSERT(!IS_SCSIOP_READWRITE(srb->Cdb[0]) ||
                       IS_16_ALIGNED(srb->DataTransferLength));
                v4v_copy_out_offset(ring->ring, NULL, NULL,
                                    (PUCHAR)buf,
                                    srb->DataTransferLength + sizeof(hdr),
                                    1,
                                    sizeof(hdr));

                perfcnt_arr_add(in_bytes, IS_PAGING_IO(srb),
                                srb->DataTransferLength);

#if (DUMP_IN_DATA_BEGIN_BYTES > 0) || (DUMP_IN_DATA_END_BYTES > 0)
                uxen_debug("dumping read data");
                buffer_dump_ex(UXEN_KD_DBG, "  ", buf, srb->DataTransferLength, 
                               DUMP_IN_DATA_BEGIN_BYTES, DUMP_IN_DATA_END_BYTES);
#endif
            } else {
                uxen_v4v_copy_out(dev_ext->v4v_ring, NULL, NULL, NULL, 0, 1);
                perfcnt_arr_add_if(out_bytes, IS_PAGING_IO(srb),
                                   srb->DataTransferLength,
                                   TEST_FLAG(srb->SrbFlags, SRB_FLAGS_DATA_OUT));
            }

            trace_scsi(irp, srb, STATUS_SUCCESS,
                       (LONG_PTR)irp->Tail.Overlay.DriverContext[0]);
            irp->Tail.Overlay.DriverContext[0] = NULL;

            KeReleaseSpinLockFromDpcLevel(&dev_ext->v4v_lock);

            srb->SrbStatus = SRB_STATUS_SUCCESS;
            irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(irp, IO_DISK_INCREMENT);

            KeAcquireSpinLockAtDpcLevel(&dev_ext->v4v_lock);

        } else {
            /* IRP was cancelled - discard message */
            uxen_msg("request 0x%p not in the queue", hdr.seq);
            uxen_v4v_copy_out(dev_ext->v4v_ring, NULL, NULL, NULL, 0, 1);
            perfcnt_inc(zombie_requests);
        }
    } while (1, 1);
    KeReleaseSpinLockFromDpcLevel(&dev_ext->v4v_lock);
    
    uxen_v4v_notify();
}

static
NTSTATUS stor_v4v_scsi(PUXENSTOR_DEV_EXT dev_ext, PIRP irp,
                       PSCSI_REQUEST_BLOCK srb, BOOLEAN retry_path)
{
    XFER_HEADER *hdr;
    UCHAR hdr_data[ROUNDUP_16(sizeof(*hdr) + 16)];
    v4v_iov_t iov[2];
    ssize_t ret, req_size;
    NTSTATUS status;
    KIRQL irql;
    ULONG_PTR new_req_id;

    /* FIXME: we should probably do something about request tagging, etc. */
    /* ASSERT(!TEST_FLAG(srb->SrbFlags, SRB_FLAGS_QUEUE_ACTION_ENABLE)); */

    ASSERT(!irp->Tail.Overlay.ListEntry.Blink &&
           !irp->Tail.Overlay.ListEntry.Flink);
    ASSERT(!irp->Tail.Overlay.DriverContext[0]);

#ifdef _M_AMD64
    new_req_id = (ULONG_PTR)InterlockedIncrement64(&req_id);
#else
    new_req_id = (ULONG_PTR)InterlockedIncrement(&req_id);
#endif /* _M_AMD64 */
    irp->Tail.Overlay.DriverContext[0] = (PVOID)new_req_id;

    hdr = (XFER_HEADER *)&hdr_data[0];
    hdr->seq = (uint64_t)new_req_id;
    hdr->cdb_size = srb->CdbLength;
    hdr->write_size = TEST_FLAG(srb->SrbFlags, SRB_FLAGS_DATA_OUT) ?
                                srb->DataTransferLength : 0;
    hdr->pagelist_size = 0;
    hdr->read_size = TEST_FLAG(srb->SrbFlags, SRB_FLAGS_DATA_IN) ?
                               srb->DataTransferLength : 0;
    hdr->sense_size = srb->SenseInfoBufferLength;
    RtlCopyMemory(&hdr->data[0], srb->Cdb, srb->CdbLength);
    req_size = ROUNDUP_16(sizeof(*hdr) + srb->CdbLength);

    ASSERT(!IS_SCSIOP_READ(srb->Cdb[0]) || IS_16_ALIGNED(hdr->read_size));
    ASSERT(!IS_SCSIOP_WRITE(srb->Cdb[0]) || IS_16_ALIGNED(hdr->write_size));

    perfcnt_arr_inc(v4v_scsi, srb->Cdb[0]);

    iov[0].iov_base = (uint64_t)hdr;
    iov[0].iov_len = req_size;

    if (TEST_FLAG(srb->SrbFlags, SRB_FLAGS_DATA_OUT)) {
        iov[1].iov_base = (uint64_t)MmGetSystemAddressForMdlSafe(
            irp->MdlAddress,
            NormalPagePriority);
        ASSERT(iov[1].iov_base);
        iov[1].iov_len = srb->DataTransferLength;
        req_size += srb->DataTransferLength;

#if (DUMP_OUT_DATA_BEGIN_BYTES > 0) || (DUMP_OUT_DATA_END_BYTES > 0)
        uxen_debug("dumping write data");
        buffer_dump_ex(UXEN_KD_DBG, "  ", iov[1].iov_base, srb->DataTransferLength,
                       DUMP_OUT_DATA_BEGIN_BYTES, DUMP_OUT_DATA_END_BYTES);
#endif
    }

    irql = ExAcquireSpinLockShared(&dev_ext->v4v_resume_lock);
    IoCsqInsertIrp(&dev_ext->io_queue, irp, NULL);
    trace_scsi(irp, srb, STATUS_PENDING, (LONG_PTR)new_req_id);
    ret = uxen_v4v_sendv_from_ring_async(
        dev_ext->v4v_ring, &dev_ext->v4v_addr, 
        iov, 2 - (!TEST_FLAG(srb->SrbFlags, SRB_FLAGS_DATA_OUT)),
        V4V_PROTO_DGRAM,
        stor_v4v_e_again_callback, dev_ext, (PVOID)new_req_id);
    ExReleaseSpinLockShared(&dev_ext->v4v_resume_lock, irql);

    if (ret != req_size && ret != -EAGAIN) {
        perfcnt_inc(uxen_v4v_sendv_from_ring_errors);
        perfcnt_inc(v4v_scsi_completed_error);

        uxen_err("failed to send 0x%x bytes of 0x%x/0x%p:0x%p request: %d", 
                 req_size, hdr->data[0], irp, new_req_id, ret);

        if (IoCsqRemoveNextIrp(&dev_ext->io_queue, (PVOID)new_req_id)) {
            srb->SrbStatus = SRB_STATUS_ERROR; /* FIXME: be more specific */
            status = STATUS_INSUFFICIENT_RESOURCES;

            trace_scsi(irp, srb, status, new_req_id);
            irp->Tail.Overlay.DriverContext[0] = NULL;

            irp->IoStatus.Status = status;
            IoCompleteRequest(irp, IO_DISK_INCREMENT);
        } else {
            ASSERT(retry_path);
            uxen_msg("request 0x%p:0x%p already removed", irp, new_req_id);
            perfcnt_inc(zombie_requests);
            status = STATUS_SUCCESS;
        }

    } else {
#if DUMP_RESEND
        if (retry_path)
            uxen_msg("request 0x%p:0x%p sucessfuly resent", irp, new_req_id);
#endif /* DUMP_RESEND */
        perfcnt_inc_if(stor_v4v_e_again, ret == -EAGAIN);
        perfcnt_inc(v4v_scsi_queued);
        status = STATUS_PENDING;
    }

    return status;
}

static
void stor_v4v_e_again_callback(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2)
{
    PUXENSTOR_DEV_EXT dev_ext;
    PIRP irp;

    UNREFERENCED_PARAMETER(ring);

    perfcnt_inc(stor_v4v_e_again_callback);

    dev_ext = (PUXENSTOR_DEV_EXT)ctx;
    irp = IoCsqRemoveNextIrp(&dev_ext->io_queue, ctx2);
    if (irp) {
        irp->Tail.Overlay.DriverContext[0] = NULL;
        perfcnt_inc(stor_v4v_resend_e_again);
#if DUMP_RESEND
        uxen_msg("resending 0x%p:(0x%p) request", irp, ctx2);
#endif /* DUMP_RESEND */
        stor_v4v_scsi(dev_ext, irp,
                      IoGetCurrentIrpStackLocation(irp)->Parameters.Scsi.Srb,
                      TRUE);
    } else
       uxen_msg("request :0x%p not in the queue", ctx2);
}

void stor_v4v_resume_callback(PKDPC dpc,
                              PVOID deferred_context,
                              PVOID arg1, PVOID arg2)
{
    PUXENSTOR_DEV_EXT dev_ext;
    PIRP irp;
    LIST_ENTRY resend_list, *entry;
    int req_to_be_resent;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    dev_ext = (PUXENSTOR_DEV_EXT)deferred_context;
    InitializeListHead(&resend_list);

    perfcnt_inc(stor_v4v_resume_callback);

    uxen_msg("out-paging_io: %I64d; in-paging_io: %I64d", 
             perfcnt_arr_get(out_bytes, 1), perfcnt_arr_get(in_bytes, 1));

    if (ahci_state) {
        uxen_msg("disabling AHCI");
        ahci_state = 0;
    }

    req_to_be_resent = 0;
    ExAcquireSpinLockExclusiveAtDpcLevel(&dev_ext->v4v_resume_lock);
    irp = IoCsqRemoveNextIrp(&dev_ext->io_queue, NULL);
    while (irp) {
        req_to_be_resent++;
#if DUMP_RESEND
        uxen_msg("moving 0x%p:0x%p to resend_list", 
                 irp, irp->Tail.Overlay.DriverContext[0]);
#endif /* DUMP_RESEND */
        InsertTailList(&resend_list, &irp->Tail.Overlay.ListEntry);
        irp = IoCsqRemoveNextIrp(&dev_ext->io_queue, NULL);
    }
    ExReleaseSpinLockExclusiveFromDpcLevel(&dev_ext->v4v_resume_lock);

    uxen_msg("resending %d requests", req_to_be_resent);
    while (!IsListEmpty(&resend_list)) {
        entry = RemoveHeadList(&resend_list);
        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        irp->Tail.Overlay.ListEntry.Blink = NULL;
        irp->Tail.Overlay.ListEntry.Flink = NULL;
        uxen_msg("resending 0x%p(:0x%p)", 
                 irp, irp->Tail.Overlay.DriverContext[0]);
        irp->Tail.Overlay.DriverContext[0] = NULL;
        stor_v4v_scsi(dev_ext, irp,
                      IoGetCurrentIrpStackLocation(irp)->Parameters.Scsi.Srb,
                      TRUE);
        req_to_be_resent--;
        perfcnt_inc(stor_v4v_resend_resume);
    }

    ASSERT(req_to_be_resent == 0);
}

#if MONITOR_SCSI_RESULTS
static
NTSTATUS stor_scsi_compl(PDEVICE_OBJECT dev_obj, PIRP irp, PVOID ctx)
{
    PUXENSTOR_DEV_EXT dev_ext;
    PSCSI_REQUEST_BLOCK srb;

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;
    srb = (PSCSI_REQUEST_BLOCK)ctx;

    if (irp->PendingReturned)
        IoMarkIrpPending(irp);

    if (!NT_SUCCESS(irp->IoStatus.Status) ||
        SRB_STATUS(srb->SrbStatus) != SRB_STATUS_SUCCESS || 
        SRB_STATUS(srb->ScsiStatus) != SCSISTAT_GOOD)
        uxen_debug("[0x%p:0x%p] scsi_request failed: 0x%x, 0x%x, 0x%x",
                   dev_obj, irp, 
                   irp->IoStatus.Status, srb->SrbStatus, srb->ScsiStatus);

    IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 

    return STATUS_CONTINUE_COMPLETION;
}
#endif /* MONITOR_SCSI_RESULTS */

NTSTATUS stor_dispatch_scsi(PDEVICE_OBJECT dev_obj, PIRP irp)
{
    NTSTATUS status;
    PUXENSTOR_DEV_EXT dev_ext;
    PIO_STACK_LOCATION io_stack;
    PSCSI_REQUEST_BLOCK srb;

    io_stack = IoGetCurrentIrpStackLocation(irp);

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;
    status = IoAcquireRemoveLock(&dev_ext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        uxen_debug("[0x%p:0x%p] IoAcquireRemoveLock() failed: 0x%08x",
                   dev_obj, irp, status);
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        goto out_keep_rlock;
    }

    srb = io_stack->Parameters.Scsi.Srb;

    if (!dev_ext->v4v_ring)
        goto pass_thru;

    perfcnt_arr_inc(stor_dispatch_scsi, srb->Function);

    switch (srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI: {
#if LOG_SRB_FUNCTION_EXECUTE_SCSI_NON_IO
        PCDB cdb;

        ASSERT(srb->CdbLength >= sizeof(cdb->CDB6GENERIC.OperationCode));
        cdb = (PCDB)&srb->Cdb;
        if (!IS_SCSIOP_READWRITE(cdb->CDB6GENERIC.OperationCode))
            uxen_msg("[0x%p:0x%p] v4v_SRB_FUNCTION_EXECUTE_SCSI: 0x%02x (%s)",
                     dev_obj, irp,
                     cdb->CDB6GENERIC.OperationCode,
                     scsi_cmd_name(cdb->CDB6GENERIC.OperationCode));
#endif /* LOG_SRB_FUNCTION_EXECUTE_SCSI_NON_IO */

        status = stor_v4v_scsi(dev_ext, irp, srb, FALSE);
        goto out;

    }

    case SRB_FUNCTION_IO_CONTROL: {
#if LOG_SRB_FUNCTION_IO_CONTROL
        PSRB_IO_CONTROL srb_ioctl;

        if (srb->DataTransferLength >= sizeof(*srb_ioctl)) {
            srb_ioctl = (PSRB_IO_CONTROL)srb->DataBuffer;
            uxen_msg("[0x%p:0x%p] SRB_FUNCTION_IO_CONTROL: 0x%x (%s)",
                     dev_obj, irp,
                     srb_ioctl->ControlCode,
                     scsi_ioctl_name(srb_ioctl->ControlCode));
        } else 
            uxen_msg("[0x%p:0x%p] SRB_FUNCTION_IO_CONTROL: invalid",
                     dev_obj, irp);
#endif /* LOG_SRB_FUNCTION_IO_CONTROL */
        break;
    }

    case SRB_FUNCTION_FLUSH: {
#if LOG_SRB_FUNCTION_FLUSH
        uxen_msg("[0x%p:0x%p] v4v_SRB_FUNCTION_FLUSH: 0x%x (%s)",
                 dev_obj, irp,
                 srb->Function, srb_function_name(srb->Function));
#endif /* LOG_SRB_FUNCTION_FLUSH */

        srb->CdbLength = 10;
        RtlZeroMemory(srb->Cdb, srb->CdbLength);
        srb->Cdb[0] = SCSIOP_SYNCHRONIZE_CACHE;

        status = stor_v4v_scsi(dev_ext, irp, srb, FALSE);
        goto out;
    }

    case SRB_FUNCTION_SHUTDOWN:
        uxen_msg("[0x%p:0x%p] SRB_FUNCTION_SHUTDOWN", dev_obj, irp);

        srb->CdbLength = 10;
        RtlZeroMemory(srb->Cdb, srb->CdbLength);
        srb->Cdb[0] = SCSIOP_START_STOP_UNIT;
        status = stor_v4v_scsi(dev_ext, irp, srb, FALSE);

#if DUMP_PERFCNTS_ON_SHUTDOWN
        perfcnt_dump(UXEN_KD_MSG, "  ", 0);
#endif /* DUMP_PERFCNTS_ON_SHUTDOWN */
        goto out;

#if LOG_SRB_UNHANDLED
    default:
        uxen_msg("[0x%p:0x%p] %sSRB_func: 0x%x (%s)",
                 dev_obj, irp,
                 (dev_ext->v4v_ring ? "unhandled v4v " : ""),
                 srb->Function, srb_function_name(srb->Function));
#endif /* LOG_SRB_UNHANDLED */
    }

  pass_thru:
    if (ahci_state) {
#if MONITOR_SCSI_RESULTS
        IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp, stor_scsi_compl, (PVOID)srb,
                               TRUE, TRUE, TRUE);
        status = IoCallDriver(dev_ext->lower_dev_obj, irp);
        goto out_keep_rlock;
#else /* MONITOR_SCSI_RESULTS */
        IoSkipCurrentIrpStackLocation(irp);
        status = IoCallDriver(dev_ext->lower_dev_obj, irp);
#endif /* MONITOR_SCSI_RESULTS */
    } else {
        perfcnt_inc(dropped_ahci_requests);
#if LOG_DROPPED_AHCI_REQUESTS
        uxen_msg("[0x%p:0x%p] dropping %sSRB_func: 0x%x (%s)",
                 dev_obj, irp,
                 (dev_ext->v4v_ring ? "unhandled v4v " : ""),
                 srb->Function, srb_function_name(srb->Function));
#endif /* LOG_DROPPED_AHCI_REQUESTS */
        status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

  out:
    IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 
  
  out_keep_rlock:
    perfcnt_inc_if(stor_dispatch_scsi_failures, !NT_SUCCESS(status));

    return status;
}
