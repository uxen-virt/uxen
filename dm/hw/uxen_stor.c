/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/pci.h>
#include <dm/scsi.h>
#include <dm/block.h>
#include <dm/dmpdev.h>
#include <dm/hw.h>
#include <dm/firmware.h>

#undef QEMU_SCSI

#ifdef QEMU_SCSI
#include <dm/qemu/hw/scsi.h>
#else
#include "uxen_scsi.h"
#endif
#include <dm/block-int.h>



#ifndef SCSIOP_SYNCHRONIZE_CACHE
#define SCSIOP_SYNCHRONIZE_CACHE 0x35
#endif


#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#if defined(_WIN32)
#define _POSIX
#endif
#include <time.h>
#include <sys/time.h>

#define UXEN_STOR_ROUNDUP(x) (((x)  +0xf ) & ~0xf)

#define MAX_CDB 16

#define MAX_PACKET_SIZE (32UL << 20)

#define RING_SIZE (1024*1024) //131072

#define  PCAP 0

static int unit = 0;

static int processed = 0;


static int unit_bitfield[16];

typedef struct v4v_disk_transfer {
    uint64_t seq;
    uint32_t cdb_size;
    uint32_t write_size;
    uint32_t pagelist_size;
    uint32_t read_size;
    uint32_t sense_size;
    uint32_t status;
    uint8_t data[];
} v4v_disk_transfer_t;

typedef enum uxen_stor_state {
    UXS_STATE_NEW,
    UXS_STATE_SCSI_RUNNING,
    UXS_STATE_SCSI_DONE,
    UXS_STATE_V4V_SENDING,
    UXS_STATE_V4V_SENT
} uxen_stor_state_t;


typedef struct {
    struct uxen_stor_req *head, *tail;
} uxen_stor_req_list_t;


typedef struct __attribute__ ((packed))
{
    v4v_datagram_t dg;
    v4v_disk_transfer_t xfr;
}
uxen_stor_xfr_api_t;

typedef struct uxen_stor_req {
    struct uxen_stor_req *prev, *next;

    uxen_stor_state_t state;

    size_t len;

#ifdef QEMU_SCSI
    SCSIRequest *req;
    uint32_t scsi_xfer_ptr;
    ssize_t scsi_data_len;
#else
    UXSCSI scsi;
    struct uxen_stor *parent;
    uint8_t sense_data[18];
    size_t cdb_len;
#endif

    OVERLAPPED overlapped;

    uint8_t cdb[MAX_CDB];

    uint32_t reply_size;


    int scsi_is_read;


    uint8_t *cdb_ptr;
    uint8_t *write_ptr;
    uint8_t *pagelist_ptr;
    uint8_t *read_ptr;
    uint8_t *sense_ptr;

    uxen_stor_xfr_api_t packet;

} uxen_stor_req_t;


typedef struct uxen_stor {
    ISADevice dev;
    //DeviceState dev;
    v4v_context_t a;
    v4v_addr_t dest;

    OVERLAPPED notify_overlapped;
    BOOLEAN notify_pending;

    HANDLE tx_event;

    v4v_ring_t *ring;

    BlockConf conf;

#ifdef QEMU_SCSI
    SCSIBus bus;
    SCSIDevice *scsi_dev;
#endif

    uxen_stor_req_list_t queue;

    uint32_t removable;
    uint32_t parasite;

    uint32_t unit;
#if PCAP
    FILE *pcap;
    int pcap_last_tx_nr;
#endif

    size_t hwm;
    size_t mem;

} uxen_stor_t;


/****************** packet capture *******************/



#if PCAP
static void
uxen_stor_log_packet (uxen_stor_t *s, void *_p, size_t len, int dir)
{
    struct timeval tv;
    uint32_t d;
    uint8_t b, *p = (uint8_t *) _p;

    gettimeofday (&tv, NULL);

    d = tv.tv_sec;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = tv.tv_usec;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = len + 1;
    fwrite (&d, sizeof (d), 1, s->pcap);
    fwrite (&d, sizeof (d), 1, s->pcap);
    b = dir;
    fwrite (&b, sizeof (b), 1, s->pcap);
    fwrite (p, 1, len, s->pcap);

    fflush (s->pcap);

}


static int
uxen_stor_log_init (uxen_stor_t *s, int u)
{
    uint32_t d;
    uint16_t w;
    char name[1024];

    mkdir ("\\pcap");

    sprintf (name, "\\pcap\\uxen_stor.%d.%d.pcap", domid, u);

    s->pcap = fopen (name, "wb");
    if (!s->pcap)
        return -1;

    d = 0xa1b2c3d4;
    fwrite (&d, sizeof (d), 1, s->pcap);
    w = 2;
    fwrite (&w, sizeof (w), 1, s->pcap);
    w = 4;
    fwrite (&w, sizeof (w), 1, s->pcap);
    d = 0;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = 0;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = RING_SIZE;
    fwrite (&d, sizeof (d), 1, s->pcap);
    d = 0x7281928;
    fwrite (&d, sizeof (d), 1, s->pcap);

    return 0;
}
#endif


/******************   Q *************************/

#if 0
static void
req_insert_head (uxen_stor_req_list_t *list, uxen_stor_req_t *req)
{
    assert (list);
    assert (req);
    assert (!req->next);
    assert (!req->prev);

    if (!list->head) {
        list->head = req;
    } else {
        req->next = list->head;
        list->head->prev = req;
        list->head = req;
    }

    if (!list->tail) {
        list->tail = req;
    }
}
#endif

uint32_t validate_xfr(v4v_disk_transfer_t *xfr)
{
    uint32_t size;

    if (xfr->cdb_size > MAX_PACKET_SIZE) return 0;
    if (xfr->write_size > MAX_PACKET_SIZE) return 0;
    if (xfr->pagelist_size > MAX_PACKET_SIZE) return 0;
    if (xfr->read_size > MAX_PACKET_SIZE) return 0;
    if (xfr->sense_size > MAX_PACKET_SIZE) return 0;

    size = sizeof (v4v_disk_transfer_t);

    size += UXEN_STOR_ROUNDUP (xfr->cdb_size);
    size += UXEN_STOR_ROUNDUP (xfr->write_size);
    size += UXEN_STOR_ROUNDUP (xfr->pagelist_size);
    size += UXEN_STOR_ROUNDUP (xfr->read_size);
    size += xfr->sense_size;

    if (size > MAX_PACKET_SIZE) return 0;

    return size;
}


static uint32_t
update_req_ptrs (uxen_stor_req_t *req)
{
    uint32_t size = 0,  new_size;

    new_size = validate_xfr(&req->packet.xfr);
    if ((!new_size) || (new_size > req->len)) {
        debug_printf("%s: request seq=%"PRIx64" invalid\n", __FUNCTION__,
                     req->packet.xfr.seq);
	abort();
    }

    req->cdb_ptr = &req->packet.xfr.data[size];
    size += UXEN_STOR_ROUNDUP (req->packet.xfr.cdb_size);

    req->write_ptr = &req->packet.xfr.data[size];
    size += UXEN_STOR_ROUNDUP (req->packet.xfr.write_size);

    req->pagelist_ptr = &req->packet.xfr.data[size];
    size += UXEN_STOR_ROUNDUP (req->packet.xfr.pagelist_size);

    req->read_ptr = &req->packet.xfr.data[size];
    size += UXEN_STOR_ROUNDUP (req->packet.xfr.read_size);

    req->sense_ptr = &req->packet.xfr.data[size];

    return size;
}


static void
req_insert_tail (uxen_stor_req_list_t *list, uxen_stor_req_t *req)
{
    assert (list);
    assert (req);
    assert (!req->next);
    assert (!req->prev);

    if (!list->tail) {
        list->tail = req;
    } else {
        req->prev = list->tail;
        list->tail->next = req;
        list->tail = req;
    }

    if (!list->head) {
        list->head = req;
    }
}

static void
req_remove (uxen_stor_req_list_t *list, uxen_stor_req_t *req)
{
    assert (req);

    if (!req->prev) {
        list->head = req->next;
    } else {
        req->prev->next = req->next;
    }

    if (!req->next) {
        list->tail = req->prev;
    } else {
        req->next->prev = req->prev;
    }

    req->next = req->prev = NULL;
}


static void
uxen_stor_send_reply (uxen_stor_t *s, uxen_stor_req_t *r)
{

    r->overlapped.hEvent = s->tx_event;

#if PCAP
    uxen_stor_log_packet (s, &r->packet.xfr, r->reply_size, 1);
#endif

    /*send reply */
    if (WriteFile
        (s->a.v4v_handle, &r->packet,
         r->reply_size + sizeof (v4v_datagram_t), NULL, &r->overlapped)) {
        Wwarn("%s: fail path 1 seq=%"PRIx64, __FUNCTION__, r->packet.xfr.seq);
        r->state = UXS_STATE_V4V_SENT;
        return;
    }


    if (GetLastError () == ERROR_IO_PENDING) {
        r->state = UXS_STATE_V4V_SENDING;
    } else {
        r->state = UXS_STATE_V4V_SENT;
        Wwarn("%s: fail path 2 seq=%"PRIx64, __FUNCTION__, r->packet.xfr.seq);
    }
}


#ifdef QEMU_SCSI
static void
uxen_stor_transfer_data (SCSIRequest *req, uint32_t len)
{
    //uxen_stor_t *s = DO_UPCAST (uxen_stor_t, dev.qdev, req->bus->qbus.parent);
    uxen_stor_req_t *r = (uxen_stor_req_t *) req->hba_private;

    void *buf = scsi_req_get_buf (r->req);

    if ((r->scsi_xfer_ptr > MAX_PACKET_SIZE) || 
            (len > MAX_PACKET_SIZE) || 
            ((len + r->scsi_xfer_ptr) > MAX_PACKET_SIZE)) {
        scsi_req_continue (r->req);
        debug_printf("%s: request seq=%"PRIx64" too large, truncating\n",
                     __FUNCTION__, r->packet.xfr.seq);
        return;
    }

    if (r->scsi_is_read) {
        if ((r->scsi_xfer_ptr + len) <= r->packet.xfr.read_size) {
            memcpy (r->read_ptr + r->scsi_xfer_ptr, buf, len);
            r->scsi_xfer_ptr += len;
        }
    } else {
        if ((r->scsi_xfer_ptr + len) <= r->packet.xfr.write_size) {
            memcpy (buf, r->write_ptr + r->scsi_xfer_ptr, len);
            r->scsi_xfer_ptr += len;
        }
    }

    scsi_req_continue (r->req);
}

static void
uxen_stor_request_cancelled (SCSIRequest *req)
{
    //uxen_stor_t *s = DO_UPCAST (uxen_stor_t, dev.qdev, req->bus->qbus.parent);
    uxen_stor_req_t *r = (uxen_stor_req_t *) req->hba_private;


    r->state = UXS_STATE_SCSI_DONE;
    scsi_req_unref (r->req);
    r->req = NULL;
}


static void
uxen_stor_command_complete (SCSIRequest *req, uint32_t status)
{
    uxen_stor_t *s = DO_UPCAST (uxen_stor_t, dev.qdev, req->bus->qbus.parent);
    uxen_stor_req_t *r = (uxen_stor_req_t *) req->hba_private;
    uint32_t size = 0;


    if (r->scsi_is_read) {

        /* Truncate to actual number of bytes written */
        r->packet.xfr.read_size = r->scsi_xfer_ptr;

        size = update_req_ptrs (r);

        if (r->req->sense_len <= r->packet.xfr.sense_size) {
            r->packet.xfr.sense_size = r->req->sense_len;

            if (r->req->sense_len)
                memcpy (r->sense_ptr, r->req->sense, r->req->sense_len);

        } else {
            r->packet.xfr.sense_size = 0;
        }


        size += r->packet.xfr.sense_size;

    } else {
        /*Write data and  add sense data */
        r->packet.xfr.write_size = 0;
        r->packet.xfr.read_size = 0;
        r->packet.xfr.cdb_size = 0;
        r->packet.xfr.pagelist_size = 0;

        size = update_req_ptrs (r);

        if (r->req->sense_len <= r->packet.xfr.sense_size) {
            r->packet.xfr.sense_size = r->req->sense_len;

            if (r->req->sense_len)
                memcpy (r->sense_ptr, r->req->sense, r->req->sense_len);

        } else {
            r->packet.xfr.sense_size = 0;
        }

        size += r->packet.xfr.sense_size;
    }

    r->reply_size = size + sizeof (v4v_disk_transfer_t);

    r->packet.xfr.status = status;


    r->state = UXS_STATE_SCSI_DONE;
    scsi_req_unref (r->req);
    r->req = NULL;

    uxen_stor_send_reply (s, r);
}

static const struct SCSIBusInfo uxen_stor_scsi_info = {
    .tcq = false,
    .max_target = 0,
    .max_lun = 0,

    .transfer_data = uxen_stor_transfer_data,
    .complete = uxen_stor_command_complete,
    .cancel = uxen_stor_request_cancelled
};


#else

static void uxen_stor_uxscsi_complete(void *_r,UXSCSI *scsi)
{
uxen_stor_req_t *r=(uxen_stor_req_t *) _r;
uxen_stor_t *s=r->parent;
uint8_t status=uxscsi_status(scsi);
size_t sense_len;
uint32_t size=0;


fprintf(stderr,"scsi_complete status=%d red=%d sl=%d\n",status,(int) uxscsi_red_len(scsi),(int) uxscsi_sensed_len(scsi));

        r->packet.xfr.write_size = 0;
        r->packet.xfr.pagelist_size = 0;
        r->packet.xfr.cdb_size = 0;


if (status!= SCSIST_GOOD) {
	/*Fail zero everying except sense and fill that in */
        r->packet.xfr.read_size = 0;
        size = update_req_ptrs (r);

	sense_len=uxscsi_sensed_len(scsi);

	if (sense_len > r->packet.xfr.sense_size)
		sense_len=r->packet.xfr.sense_size;

        r->packet.xfr.sense_size = sense_len;

        if (sense_len)
            memcpy (r->sense_ptr, r->sense_data, sense_len);

        size += r->packet.xfr.sense_size;
} else {
	/*Success, zero everything (except read if we're reading) */
        r->packet.xfr.sense_size = 0;

	if (r->scsi_is_read) {
        r->packet.xfr.read_size = uxscsi_red_len(scsi);
	} else {
        r->packet.xfr.read_size = 0;
	}

        size = update_req_ptrs (r);
}

    r->reply_size = size + sizeof (v4v_disk_transfer_t);
    r->packet.xfr.status = status;

    r->state = UXS_STATE_SCSI_DONE;

    uxen_stor_send_reply (s, r);
}


#endif


static void
uxen_stor_run_q (uxen_stor_t *s)
{
    uxen_stor_req_t *r, *next_r;
    int short_circuit;

    for (r = s->queue.head; r;) {


        switch (r->state) {


            case UXS_STATE_NEW:    /*new request from the ring */

                if (!r->packet.xfr.write_size) {
                    /*This is a read so we should rearrange the packet first */
                    r->packet.xfr.cdb_size = 0;
                    r->packet.xfr.pagelist_size = 0;
                    update_req_ptrs (r);
                }

                if (r->packet.xfr.read_size)
                    r->scsi_is_read = 1;


                short_circuit = 0;

                switch (r->cdb[0]) {
                    case SCSIOP_SYNCHRONIZE_CACHE:
                        short_circuit++;
                }

                if (short_circuit) {
                    uint32_t size = 0;

                    r->packet.xfr.write_size = 0;
                    r->packet.xfr.read_size = 0;
                    r->packet.xfr.cdb_size = 0;
                    r->packet.xfr.pagelist_size = 0;

                    size = update_req_ptrs (r);

                    r->packet.xfr.sense_size = 0;
                    //size += r->packet.xfr.sense_size;

                    r->reply_size = size + sizeof (v4v_disk_transfer_t);

                    r->packet.xfr.status = 0;

                    r->state = UXS_STATE_SCSI_DONE;
                    uxen_stor_send_reply (s, r);

                } else {
#ifdef QEMU_SCSI
                    r->req = scsi_req_new (s->scsi_dev, 0, 0, r->cdb, r);
                    r->scsi_xfer_ptr = 0;

                    /*This needs to be here as enqueuing can call completion */
                    r->state = UXS_STATE_SCSI_RUNNING;

                    r->scsi_data_len = scsi_req_enqueue (r->req);
                    r->scsi_is_read = (r->scsi_data_len > 0) ? 1 : 0;

                    if (r->scsi_data_len)
                        scsi_req_continue (r->req);
#else

		/*we use the cdb and sense in r rather than the packet as we've either moved or are about to move the pointers around */

                    r->scsi_is_read = !!r->packet.xfr.read_size;

		    if (uxscsi_start(&r->scsi, s->conf.bs, r->cdb_len, r->cdb, r->packet.xfr.write_size,r->write_ptr,
				 r->packet.xfr.read_size,r->read_ptr,sizeof(r->sense_data),r->sense_data,uxen_stor_uxscsi_complete,r)) {

			/*A return of non-zero means the command failed immediately and that there'll be no callback */


			//FIXME we should send an error here, but since the only cause of this is a cdb < 6 bytes

                    r->state = UXS_STATE_SCSI_DONE; /*Clean up */


		} else {
                    r->state = UXS_STATE_SCSI_RUNNING;
		}
#endif
                }

                break;

            case UXS_STATE_SCSI_RUNNING:
                break;

            case UXS_STATE_SCSI_DONE:
                /*This state is handled in the completion handler */
                break;

            case UXS_STATE_V4V_SENDING:
                if (HasOverlappedIoCompleted (&r->overlapped))
                    r->state = UXS_STATE_V4V_SENT;

                break;
            case UXS_STATE_V4V_SENT: /*compiler, grr */
                break;
        }
        next_r = r->next;

        if (r->state == UXS_STATE_V4V_SENT) {
            if (!(processed % 10000))
                debug_printf("%s: %d requests handled, %"PRIdSIZE" kb in use,"
                             " hwm is %"PRIdSIZE" kb\n", __FUNCTION__,
                             processed, s->mem >> 10, s->hwm >> 10);
            processed++;
            req_remove (&s->queue, r);
            s->mem -= r->len;
            free (r);
        }
        r = next_r;
    }
}


static void
uxen_stor_write_event (void *_s)
{
    uxen_stor_t *s = (uxen_stor_t *) _s;

#ifdef LOG_QUEUE
    debug_printf("%s: write_event\n", __FUNCTION__);
#endif

    ResetEvent (s->tx_event);

    uxen_stor_run_q (s);

}


/*********************** RX path ***************************/


static int
uxen_stor_notify_complete (uxen_stor_t *s, BOOLEAN wait)
{
    DWORD writ;

    if (!s->notify_pending)
        return 1;

    if (GetOverlappedResult
        (s->a.v4v_handle, &s->notify_overlapped, &writ, wait)) {
        s->notify_pending = FALSE;
        return 1;
    }

    if (GetLastError () == ERROR_IO_INCOMPLETE)
        return 0;

    /* XXX: does false mean complete? in this case */
    s->notify_pending = FALSE;

    return 1;
}


static void
uxen_stor_read_event (void *_s)
{
    uxen_stor_t *s = (uxen_stor_t *) _s;
    ssize_t len;
    uint32_t protocol;
    v4v_disk_transfer_t xfr;
    uxen_stor_req_t *req;

    uint32_t size;
#if PCAP
    uint32_t plen;
#endif

    do {
        len =
            v4v_copy_out (s->ring, NULL, &protocol, &xfr,
                          sizeof (v4v_disk_transfer_t), 0);

        if (len < 0)
            break;

        if ((protocol != V4V_PROTO_DGRAM)
            || (len < sizeof (v4v_disk_transfer_t))
            || (xfr.cdb_size > MAX_CDB)) {
            v4v_copy_out (s->ring, NULL, NULL, NULL, 0, 1);
            continue;
        }

        size = validate_xfr(&xfr);

        if ((size < len) || (!size))  {
            /*Packet is too long, drop it */
            debug_printf("%s: dropped a request of size %d"
                         " sequence id %"PRIx64"\n", __FUNCTION__,
                         size, xfr.seq);
            v4v_copy_out (s->ring, NULL, NULL, NULL, 0, 1);
            continue;
        }

        len = (sizeof (uxen_stor_req_t) - sizeof (v4v_disk_transfer_t)) + size;
        req = malloc (len);

        if (!req) {
            // This will retry ad infinitum we probably want to do something else.
            continue;
        }
        memset (req, 0, len);

#ifndef QEMU_SCSI
        req->parent = s;
#endif

        req->len = len;

        s->mem += len;

        if (s->mem > s->hwm) {
            s->hwm = s->mem;
            debug_printf("%s: high water mark now %"PRIdSIZE" kB\n",
                         __FUNCTION__, s->hwm >> 10);
        }

        req->packet.dg.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;

#if PCAP
        plen =
#endif
            v4v_copy_out (s->ring, &req->packet.dg.addr, NULL,
                              &req->packet.xfr, size, 1);

#if PCAP
        uxen_stor_log_packet (s, &req->packet.xfr, plen, 2);
#endif

        size = 0;

        req->state = UXS_STATE_NEW;

        update_req_ptrs (req);

        //length checked above
        memset (req->cdb, 0, MAX_CDB);
        memcpy (req->cdb, req->cdb_ptr, req->packet.xfr.cdb_size);

#ifndef QEMU_SCSI
	req->cdb_len=req->packet.xfr.cdb_size;
#endif



        req_insert_tail (&s->queue, req);
    } while (1);

    if (!((s->notify_pending) && (!uxen_stor_notify_complete (s, FALSE)))) {
        memset (&s->notify_overlapped, 0, sizeof (OVERLAPPED));
        gh_v4v_notify (&s->a, &s->notify_overlapped);

        s->notify_pending = TRUE;
    }

    uxen_stor_run_q (s);
}

/*******************************************************/

static void
uxen_stor_pre_save (void *opaque)
{
    //uxen_stor_t *s = opaque;
}


static int
uxen_stor_post_load (void *opaque, int version_id)
{
    //uxen_stor_t *s = opaque;


    return 0;
}

/*******************************************************/

static const VMStateDescription vmstate_uxen_stor = {
    .name = "uxen_stor",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .post_load = uxen_stor_post_load,
    .pre_save = uxen_stor_pre_save,
    .fields = (VMStateField[])
    {
        VMSTATE_UNUSED (4),
        VMSTATE_END_OF_LIST ()
    },
};


/******************ACPI interface******************************/

static uint32_t
uxen_stor_ioport_read (void *opaque, uint32_t addr)
{
    //uxen_stor_t *s = (uxen_stor_t *) opaque;
    uint8_t ret;

    addr &= 15;

    ret = unit_bitfield[addr];

    // debug_printf("%s: ioport read 0x%x => 0x%x\n", __FUNCTION__, addr, ret);

    return ret;
}

static void present_bitfield_set(uint32_t devid)
{
    int offset;

    for (offset = 0; devid > 7; offset++, devid -= 8);
    if (offset > 15) return;

    unit_bitfield[offset] |= 1UL << devid;
}

/*******************************************************/



#if 0
static void
uxen_stor_cleanup (VLANClientState *nc)
{
    uxen_stor_t *s = DO_UPCAST (NICState, nc, nc)->opaque;

    ioh_del_wait_object (&s->tx_event, NULL);
    ioh_del_wait_object (&s->a.recv_event, NULL);

    CloseHandle (&s->tx_event);

    v4v_close (&s->a);

    s->nic = NULL;
}
#endif

static int
have_v4v (void)
{
    v4v_context_t c = { 0 };

    if (v4v_open (&c, 4096, NULL)) {
        v4v_close (&c);
        return 1;
    }

    return 0;
}

static int
uxen_stor_initfn (ISADevice *dev)
{
    DWORD t;
    v4v_ring_id_t r;
    v4v_mapring_values_t mr;
    OVERLAPPED o = { 0 };
    int v4v_opened = 0;

    uxen_stor_t *s = DO_UPCAST (uxen_stor_t, dev, dev);
    BlockDriverState *bs = s->conf.bs;


    s->queue.head = s->queue.tail = NULL;
    s->unit = unit;

    s->hwm = s->mem = 0;

    debug_printf("%s: unit %d parasite is %d\n", __FUNCTION__,
                 unit, s->parasite);

    do {
#if PCAP
        if (uxen_stor_log_init (s, unit))
            break;
#endif

        if (!have_v4v ()) {
            debug_printf("%s: no v4v detected on the host\n", __FUNCTION__);
            break;
        }

        s->a.flags = V4V_FLAG_OVERLAPPED;
        memset (&o, 0, sizeof (o));

        if (!v4v_open (&s->a, RING_SIZE, &o))
            break;

        if (!GetOverlappedResult (s->a.v4v_handle, &o, &t, TRUE))
            break;

        v4v_opened++;


        r.addr.port = 0xd0000 + unit;
        r.addr.domain = V4V_DOMID_ANY;
        r.partner = vm_id;

        memset (&o, 0, sizeof (o));

        if (!v4v_bind (&s->a, &r, &o))
            break;

        if (!GetOverlappedResult (s->a.v4v_handle, &o, &t, TRUE))
            break;

        memset (&o, 0, sizeof (o));

        mr.ring = NULL;
        if (!v4v_map (&s->a, &mr, &o))
            break;

        if (!GetOverlappedResult (s->a.v4v_handle, &o, &t, TRUE))
            break;

        s->ring = mr.ring;
        if (!s->ring)
            break;

        s->tx_event = CreateEvent (NULL, FALSE, FALSE, NULL);

        if (!s->tx_event)
            break;

        if (!bs) {
            error_report ("uxen-stor: drive property not set");
            return -1;
        }

#ifdef QEMU_SCSI
        /*
         * Hack alert: this pretends to be a block device, but it's really
         * a SCSI bus that can serve only a single device, which it
         * creates automatically.  But first it needs to detach from its
         * blockdev, or else scsi_bus_legacy_add_drive() dies when it
         * attaches again.
         *
         * The hack is probably a bad idea.
         */


        if (!s->parasite)
            bdrv_detach_dev (bs, &s->dev);

        s->conf.bs = NULL;

        scsi_bus_new (&s->bus, &s->dev.qdev, &uxen_stor_scsi_info);
        s->scsi_dev =
            scsi_bus_legacy_add_drive (&s->bus, bs, 0, ! !s->removable,
                                       s->conf.bootindex);

        if (!s->scsi_dev)
            break;
#endif


        present_bitfield_set(unit);

        ioh_add_wait_object (&s->a.recv_event, uxen_stor_read_event, s, NULL);
        ioh_add_wait_object (&s->tx_event, uxen_stor_write_event, s, NULL);

        s->dest.domain = vm_id;
        s->dest.port = 0xd0000 + unit;

        uxen_stor_read_event (s);

        unit++;

        return 0;
    } while (1);

    if (v4v_opened)
        v4v_close (&s->a);

    return -1;
}

ISADevice *
uxen_stor_add_parasite (BlockDriverState *bs)
{
    ISADevice *dev;
    uxen_stor_t *s;

    void *old_dev = bs->dev;
    const BlockDevOps *old_dev_ops = bs->dev_ops;
    void *old_dev_opaque = bs->dev_opaque;


    bs->dev = NULL;

    if (!vm_v4v_storage)
        return NULL;

    dev = isa_create ("uxen_stor");

    s = DO_UPCAST (uxen_stor_t, dev, dev);

    s->conf.bs = bs;
    s->parasite = 1;

    qdev_init_nofail (&dev->qdev);

    bs->dev = old_dev;
    bs->dev_ops = old_dev_ops;
    bs->dev_opaque = old_dev_opaque;

    /* XXX: add code here to disconnect AHCI device when */
    /* we have a uxen_stor boot driver */

    return dev;
}


static ISADeviceInfo uxen_stor_info = {
    .qdev.name = "uxen_stor",
    .qdev.size = sizeof (uxen_stor_t),
    .qdev.vmsd = &vmstate_uxen_stor,
    .init = uxen_stor_initfn,
    .qdev.props = (Property[])
    {
        DEFINE_BLOCK_PROPERTIES (uxen_stor_t, conf),
        DEFINE_PROP_BIT ("removable", uxen_stor_t,
        removable, 0, false),
        DEFINE_PROP_END_OF_LIST (),
    }
};



void
uxen_stor_late_register (void)
{
    debug_printf("%s: registering 0x330 for uxen_stor\n", __FUNCTION__);

    register_ioport_read (0x330, 16, 1, uxen_stor_ioport_read, NULL);
}

static void
uxen_stor_register_devices (void)
{
    isa_qdev_register (&uxen_stor_info);
}

device_init (uxen_stor_register_devices);
