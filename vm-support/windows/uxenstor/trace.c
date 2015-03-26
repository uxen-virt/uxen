/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenstor.h"

#if STOR_TRACE_LEN > 0

enum {
    trace_t_scsi,
    trace_t_ioctl,
};

typedef struct {
    ULONG64 seq;
    PIRP irp;
    LONG_PTR seq_id;
    ULONG status;
    ULONG line;
    UCHAR type;
    union {
        struct {
            UCHAR cdb[16];
            ULONG data_len;
            uint32_t chksum[2];
        } scsi;
    } data;
} TRACE_ITEM;

static ULONG trace_len;
static TRACE_ITEM *trace;
static KSPIN_LOCK trace_lock;
static ULONG trace_prov;
static volatile BOOLEAN trace_wrapped;
static LONG64 trace_seq;

#if STOR_TRACE_IO_CHKSUM
static
uint32_t calc_crc32(const uint32_t *buf, size_t size, uint32_t crc)
{
    ASSERT(IS_4_ALIGNED(size));

    while (size) {
        crc = _mm_crc32_u32(crc, *buf++);
        size -= 4;
    }

    return crc;
}
#endif /* STOR_TRACE_IO_CHKSUM */

void trace_init()
{
    KeInitializeSpinLock(&trace_lock);
    trace_prov = 0;
    trace_wrapped = FALSE;
    trace_seq = 0;

#if STOR_TRACE_IO_CHKSUM
    if (!CPUID_ECX_TEST(1, 20))
        uxen_msg("SSE4.2 not supported");
#endif /* STOR_TRACE_IO_CHKSUM */

    trace_len = STOR_TRACE_LEN;
    trace = (TRACE_ITEM *)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*trace) * trace_len,
        MEMTAG_TRACE);
    if (trace) {
        RtlZeroMemory(trace, sizeof(*trace) * trace_len);
        uxen_msg("tracing is on (len:%d), IO chksums are %s", 
                 trace_len, STOR_TRACE_IO_CHKSUM ? "on" : "off");
    } else
        uxen_err("failed to allocate 0x%x for trace buffer",
        sizeof(*trace) * trace_len);
}

void trace_destroy()
{
    ExFreePoolWithTag(trace, MEMTAG_TRACE);
}

void _trace_scsi(PIRP irp, PSCSI_REQUEST_BLOCK srb, NTSTATUS status, 
                 LONG_PTR seqid, ULONG line)
{
    KIRQL irql;
#if STOR_TRACE_IO_CHKSUM
    uint8_t *buf;
#endif /* STOR_TRACE_IO_CHKSUM */

    if (trace) {
        KeAcquireSpinLock(&trace_lock, &irql);

        trace[trace_prov].seq = (uint64_t)InterlockedIncrement64(&trace_seq);
        trace[trace_prov].irp = irp;
        trace[trace_prov].seq_id = (LONG_PTR)seqid;
        trace[trace_prov].status = status;
        trace[trace_prov].line = line;

        trace[trace_prov].type = trace_t_scsi;

        if (srb) {
            trace[trace_prov].data.scsi.data_len = srb->DataTransferLength;
            RtlCopyMemory(&trace[trace_prov].data.scsi.cdb[0], &srb->Cdb[0],
                          sizeof(srb->Cdb));

#if STOR_TRACE_IO_CHKSUM
            if ((status == STATUS_PENDING && IS_SCSIOP_WRITE(srb->Cdb[0])) ||
                (status == STATUS_SUCCESS && IS_SCSIOP_READ(srb->Cdb[0])))
            {
                buf = (uint8_t *)MmGetSystemAddressForMdlSafe(irp->MdlAddress, 
                                                              NormalPagePriority);
                trace[trace_prov].data.scsi.chksum[1] = calc_crc32((uint32_t *)buf,
                                                                   SECTOR_SIZE,
                                                                   0);
                if (srb->DataTransferLength > SECTOR_SIZE)
                    trace[trace_prov].data.scsi.chksum[0] = calc_crc32(
                        (uint32_t *)((uint8_t *)buf + SECTOR_SIZE),
                        srb->DataTransferLength - SECTOR_SIZE,
                        trace[trace_prov].data.scsi.chksum[1]);
                else
                    trace[trace_prov].data.scsi.chksum[0] = 
                        trace[trace_prov].data.scsi.chksum[1];
            } else {
                trace[trace_prov].data.scsi.chksum[0] = 0;
                trace[trace_prov].data.scsi.chksum[1] = 0;
            }
#endif /* STOR_TRACE_IO_CHKSUM */
        } else {
            trace[trace_prov].data.scsi.data_len = 0;
            RtlZeroMemory(&trace[trace_prov].data.scsi.cdb[0],
                          sizeof(trace[trace_prov].data.scsi.cdb));
        }

        trace_prov = (trace_prov + 1) % trace_len;
        if (trace_prov == 0 && !trace_wrapped)
            trace_wrapped = TRUE;

        KeReleaseSpinLock(&trace_lock, irql);
    }
}

#endif /* STOR_TRACE_LEN */
