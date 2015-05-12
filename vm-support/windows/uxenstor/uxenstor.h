/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENSTOR_H_
#define _UXENSTOR_H_

#include <ntddk.h>
#include <ntdddisk.h>
#include <initguid.h>
#include <ntddstor.h>
#include <wmistr.h>
#include <stdio.h>
#include <dontuse.h>
#include <srb.h>
#include <scsi.h>
#include <acpiioct.h>
#include <ntddft.h>
#include <ntddscsi.h>

#include "wdk8_wdm_excerpt.h"

#include <uxenvmlib.h>
#include <uxenv4vlib.h>
#include "perfcnt.h"
#include "../common/debug.h"

__forceinline ULONG CPUID(int id, int reg) 
{ int regs[4]; __cpuid(regs, id); return regs[reg]; }
#define CPUID_ECX_TEST(id, bit) (CPUID(id, 2) & (1 << bit))

#define MEMTAG_STOR_DESC    (ULONG)'00su'
#define MEMTAG_REMOVE_LOCK  (ULONG)'10su'
#define MEMTAG_TRACE        (ULONG)'20su'

/* compile time goodies */
#define USE_UXENSTOR                     1

#if USE_UXENSTOR
#define DROP_UNSUPPORTED_IOCTLS     1
#else
#define DROP_UNSUPPORTED_IOCTLS     0
#endif

#define MONITOR_SCSI_RESULTS        0
#define MONITOR_IOCTL_RESULTS       0

#define STOR_TRACE_LEN              32
#define STOR_TRACE_IO_CHKSUM        0

#define DUMP_SENSE_DATA             0
#define DUMP_IN_DATA_BEGIN_BYTES    0
#define DUMP_IN_DATA_END_BYTES      0
#define DUMP_OUT_DATA_BEGIN_BYTES   0
#define DUMP_OUT_DATA_END_BYTES     0
#define DUMP_PERFCNTS_ON_SHUTDOWN   1
#define DUMP_RESEND                 0

#define LOG_SRB_FUNCTION_EXECUTE_SCSI_NON_IO  0
#define LOG_SRB_FUNCTION_IO_CONTROL           1
#define LOG_SRB_FUNCTION_FLUSH                0
#define LOG_SRB_UNHANDLED                     1
#define LOG_IOCTL_UNHANDLED                   1
#define LOG_HIGH_QUEUED_DELTA                 0
#define LOG_DROPPED_AHCI_REQUESTS             1

#pragma warning(disable: 4200)

typedef struct _UXENSTOR_DEV_EXT {
    PDEVICE_OBJECT lower_dev_obj;
    IO_REMOVE_LOCK remove_lock;

    IO_CSQ io_queue;
    KSPIN_LOCK io_queue_lock;
    LIST_ENTRY pending_irp_list;

    EX_SPIN_LOCK v4v_resume_lock;
    KDPC v4v_resume_dpc;

    KSPIN_LOCK v4v_lock;
    v4v_addr_t v4v_addr;
    uxen_v4v_ring_handle_t *v4v_ring;
} UXENSTOR_DEV_EXT, *PUXENSTOR_DEV_EXT;

#define GET_DEV_EXT(csq) CONTAINING_RECORD(csq, UXENSTOR_DEV_EXT, io_queue)

#define EAGAIN          11      /* Try again */

#define SET_FLAG(flags, bit)    ((flags) |= (bit))
#define CLEAR_FLAG(flags, bit)  ((flags) &= ~(bit))
#define TEST_FLAG(flags, bit)   (((flags) & (bit)) != 0)

#define IS_SCSIOP_READ(cmd)   \
    ((cmd == SCSIOP_READ6) || \
    (cmd == SCSIOP_READ)   || \
    (cmd == SCSIOP_READ12) || \
    (cmd == SCSIOP_READ16))

#define IS_SCSIOP_WRITE(cmd)   \
    ((cmd == SCSIOP_WRITE6) || \
    (cmd == SCSIOP_WRITE)   || \
    (cmd == SCSIOP_WRITE12) || \
    (cmd == SCSIOP_WRITE16))

#define IS_SCSIOP_READWRITE(cmd) \
    (IS_SCSIOP_READ(cmd) || IS_SCSIOP_WRITE(cmd))

#define IS_PAGING_IO(srb) (TEST_FLAG((srb)->SrbFlags, 0x40000000) ? 1 : 0)

/* FIXME: this shouldn't be hardcoded */
#define SECTOR_SIZE 0x200

#define ROUNDUP_16(x) (((ULONG_PTR)(x) + 0xf) & ~(ULONG_PTR)0xf)
#define IS_4_ALIGNED(x) (((ULONG_PTR)(x) & 0x7) == 0)
#define IS_16_ALIGNED(x) (((ULONG_PTR)(x) & 0xf) == 0)

#pragma pack(push, 1)
typedef struct _XFER_HEADER {
    uint64_t seq;
    uint32_t cdb_size;
    uint32_t write_size;
    uint32_t pagelist_size;
    uint32_t read_size;
    uint32_t sense_size;
    uint32_t status;
    uint8_t data[];
} XFER_HEADER, *PXFER_HEADER;
#pragma pack(pop)

/* v4v stuffs */
#define V4V_STOR_RING_LEN (1 << 20)
#define V4V_STOR_PORT_BASE 0xd0000
#define V4V_STOR_PARTNER_DOMAIN 0

static __inline
void acquire_stor_v4v_addr(PUXENSTOR_DEV_EXT dev_ext) 
{
    static uint32_t port = 0;

    ASSERT(dev_ext);
    dev_ext->v4v_addr.port = V4V_STOR_PORT_BASE + port;
    dev_ext->v4v_addr.domain = (domid_t)V4V_STOR_PARTNER_DOMAIN;

    port++;
}

static __inline
void release_stor_v4v_addr(PUXENSTOR_DEV_EXT dev_ext) 
{
    ASSERT(dev_ext);
    dev_ext->v4v_addr.port = 0;
    dev_ext->v4v_addr.domain = (domid_t)-1;
}

/* diag.c */
char * srb_function_name(UCHAR func);
char * scsi_cmd_name(UCHAR cmd);
char * ioctl_name(ULONG ioctl);
char * stor_prop_name(int id);
char * scsi_ioctl_name(ULONG ioctl);
void buffer_dump(ULONG log_lvl, char *prefix, char *data, size_t data_size, size_t offset);

__forceinline
void buffer_dump_ex(ULONG log_lvl,
                    char *prefix,
                    char *data, size_t data_size,
                    size_t begin_bytes, size_t end_bytes)
{
    if (begin_bytes + end_bytes >= data_size || 
        (begin_bytes == 0 && end_bytes == 0))
        buffer_dump(log_lvl, prefix, data, data_size, 0);
    else {
        if (begin_bytes > 0)
            buffer_dump(log_lvl, prefix, data, min(data_size, begin_bytes), 0);
        if (data_size > begin_bytes && end_bytes > 0) {
            uxen_printk(log_lvl, "%s...", prefix);
            buffer_dump(log_lvl, prefix, data, end_bytes, data_size - end_bytes);
        }
    }
}

/* readwrite.c */
extern ULONG ahci_state;
NTSTATUS stor_dispatch_scsi(__in PDEVICE_OBJECT dev_obj, __inout PIRP irp);
void csq_acquire_lock(__in PIO_CSQ csq, __out __drv_out_deref(__drv_savesIRQL) PKIRQL irql);
void csq_release_lock(__in PIO_CSQ csq, __in __drv_in(__drv_restoresIRQL) KIRQL irql);
void csq_insert_irp(__in PIO_CSQ csq, __in PIRP irp);
PIRP csq_peek_next_irp(__in PIO_CSQ csq, __in PIRP irp, __in PVOID ctx);
void csq_remove_irp(__in PIO_CSQ csq, __in PIRP irp);
void csq_complete_cancelled_irp(__in PIO_CSQ csq, __in PIRP irp);
void stor_v4v_callback(uxen_v4v_ring_handle_t *ring, void *ctx, void *ctx2);
KDEFERRED_ROUTINE stor_v4v_resume_callback;

/* trace.c */
#if STOR_TRACE_LEN
void trace_init();
void trace_destroy();
void _trace_scsi(PIRP irp, PSCSI_REQUEST_BLOCK srb, NTSTATUS status, 
                 LONG_PTR seqid, ULONG line);
#define trace_scsi(irp, srb, status, seqid) \
    _trace_scsi(irp, srb, status, seqid, __LINE__)
#else
#define trace_init()
#define trace_destroy()
#define trace_scsi(irp, srb, status, seqid)
#endif /* STOR_TRACE_LEN */

#endif /* _UXENSTOR_H_ */
