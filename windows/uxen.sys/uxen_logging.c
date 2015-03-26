/*
 *  uxen_logging.c
 *  uxen
 *
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#include "uxen.h"
#include <xen/errno.h>
#include <uxen_ioctl.h>

static struct uxen_logging_buffer_desc
uxen_logging_buffer_desc = UXEN_LOGGING_BUFFER_DESC_INITIALIZER;

int
logging_init(struct uxen_logging_buffer_desc *bd, uint32_t size)
{
    int ret;

    if (!bd)
        bd = &uxen_logging_buffer_desc;

    if (bd->buffer)
        return 0;

    if (!size)
        size = LOGGING_DEFAULT_BUFFER_SIZE;
    else if (size > LOGGING_MAX_BUFFER_SIZE)
        size = LOGGING_MAX_BUFFER_SIZE;

    bd->size = size;
    bd->npages = (size + sizeof(struct uxen_logging_buffer) +
                  PAGE_SIZE - 1) >> PAGE_SHIFT;

    bd->mfns = kernel_malloc(bd->npages * sizeof(bd->mfns[0]));
    if (!bd->mfns) {
        fail_msg("kernel_malloc(mfns) failed");
        ret = ENOMEM;
        return ret;
    }

    bd->buffer = kernel_malloc(bd->npages << PAGE_SHIFT);
    if (!bd->buffer) {
        fail_msg("kernel_malloc(buffer) failed");
        ret = ENOMEM;
        goto out;
    }

    ret = kernel_query_mfns(bd->buffer, bd->npages, bd->mfns, 0);
    if (ret) {
        fail_msg("kernel_query_mfns failed: %d", ret);
        goto out;
    }

    ret = spinlock_initialize(bd->lock);
    if (ret) {
        fail_msg("spinlock_initialize failed");
        goto out;
    }

    bd->buffer->ulb_size = size;

  out:
    if (ret) {
        if (bd->buffer) {
            kernel_free(bd->buffer, bd->npages << PAGE_SHIFT);
            bd->buffer = NULL;
        }
        if (bd->mfns) {
            kernel_free(bd->mfns, bd->npages * sizeof(bd->mfns[0]));
            bd->mfns = NULL;
        }
    }

    return ret;
}

int
uxen_op_logging(struct uxen_logging_desc *uld, struct fd_assoc *fda)
{
    struct uxen_logging_mapping_desc *md;
    struct uxen_logging_buffer_desc *bd;
    int ret;

    md = &fda->logging_mapping;
    if (md->buffer_desc) {
        fail_msg("logging already set");
        return EEXIST;
    }

    if (fda->vmi)
        md->buffer_desc = &fda->vmi->vmi_logging_desc;
    else
        md->buffer_desc = &uxen_logging_buffer_desc;

    bd = md->buffer_desc;
    ret = logging_init(bd, uld->uld_size);
    if (ret) {
        fail_msg("logging_init failed: %d", ret);
        return ret;
    }

    md->user_mapping = user_mmap_pages(bd->npages, bd->mfns,
                                       MAP_PAGE_RANGE_RO, fda);
    if (!md->user_mapping) {
        fail_msg("user_mmap_pages failed: %d", ret);
        return ENOMEM;
    }

    if (uld->uld_event && (!bd->event_fda || bd->event_fda == fda)) {
        NTSTATUS status;

        if (bd->event)
            ObDereferenceObject(bd->event);

        bd->event_fda = fda;

        status = ObReferenceObjectByHandle(uld->uld_event, SYNCHRONIZE,
                                           *ExEventObjectType, UserMode,
                                           &bd->event, NULL);
        if (!NT_SUCCESS(status)) {
            fail_msg("cannot get event: 0x%08X", status);
            bd->event = NULL;
            ret = user_munmap_pages(md->user_mapping, bd->npages, bd->mfns,
                                    fda);
            if (ret)
                fail_msg("unmap_page_range failed: %d", ret);
            md->user_mapping = NULL;
            bd->event_fda = NULL;
            return ret ? ret : EINVAL;
        }
    }

    uld->uld_buffer = md->user_mapping;

    return 0;
}

void
logging_unmap(struct uxen_logging_mapping_desc *md, struct fd_assoc *fda)
{
    struct uxen_logging_buffer_desc *bd;
    int ret;

    /* dprintk("%s\n", __FUNCTION__); */
    bd = md->buffer_desc;
    if (bd->event && bd->event_fda == fda) {
        ObDereferenceObject(bd->event);
        bd->event = NULL;
        bd->event_fda = NULL;
    }
    ret = user_munmap_pages(md->user_mapping, bd->npages, bd->mfns, fda);
    if (ret)
        fail_msg("user_munmap_pages failed: %d", ret);
    md->user_mapping = NULL;
}

void
logging_free(struct uxen_logging_buffer_desc *bd)
{
    int ret;

    dprintk("%s\n", __FUNCTION__);
    if (!bd)
        bd = &uxen_logging_buffer_desc;

    spinlock_free(bd->lock);
    if (bd->buffer) {
        kernel_free(bd->buffer, bd->npages << PAGE_SHIFT);
        bd->buffer = NULL;
    }
    if (bd->mfns) {
        kernel_free(bd->mfns, bd->npages * sizeof(bd->mfns[0]));
        bd->mfns = NULL;
    }
}

#include <ntstrsafe.h>
#include <winerror.h>

#define pos_of(x) ((x) & 0xffffffffULL)
#define ovfl_of(x) ((x) & ~0xffffffffULL)
#define wrap_of(x) (ovfl_of(x) + 0x100000000ULL)

int
uxen_op_logging_vprintk(struct vm_info_shared *vmis,
                        const char *fmt, va_list ap)
{
    struct vm_info *vmi = (struct vm_info *)vmis;
    struct uxen_logging_buffer_desc *bd;
    uint64_t prod, cons;
    preemption_t pre;
    HRESULT res;
    size_t left;

    if (vmi && vmi->vmi_logging_desc.buffer)
        bd = &vmi->vmi_logging_desc;
    else
        bd = &uxen_logging_buffer_desc;

    if (!bd->buffer)
        return 0;

    spinlock_acquire(bd->lock, pre);

    prod = bd->buffer->ulb_producer;
    if (pos_of(prod) >= bd->size)
        prod = wrap_of(prod);
    cons = bd->buffer->ulb_consumer;
    if (pos_of(cons) >= bd->size)
        cons = wrap_of(cons);
    if (ovfl_of(cons) != ovfl_of(prod) && wrap_of(cons) != ovfl_of(prod))
        cons = prod;

#define MAXLINE_LEN 256
    if (pos_of(prod) + MAXLINE_LEN > bd->size) {
        if (pos_of(prod) <= pos_of(cons)) {
            cons = wrap_of(cons);
            bd->buffer->ulb_consumer = cons;
        }
        memset(&bd->buffer->ulb_buffer[pos_of(prod)], 0,
               bd->size - pos_of(prod));
        prod = wrap_of(prod);
    }
    if (pos_of(prod) <= pos_of(cons) &&
        ovfl_of(prod) != ovfl_of(cons) &&
        pos_of(prod) + MAXLINE_LEN > pos_of(cons)) {
        cons = ovfl_of(cons) + pos_of(prod) + MAXLINE_LEN;
        while (pos_of(cons) < bd->size) {
            if (!bd->buffer->ulb_buffer[pos_of(cons)])
                break;
            if (bd->buffer->ulb_buffer[pos_of(cons)] == '\n') {
                cons++;
                break;
            }
            cons++;
        }
        if (pos_of(cons) >= bd->size || !bd->buffer->ulb_buffer[pos_of(cons)])
            cons = wrap_of(cons);
    }
    bd->buffer->ulb_consumer = cons;

    res = RtlStringCbVPrintfExA(&bd->buffer->ulb_buffer[pos_of(prod)],
                                MAXLINE_LEN, NULL, &left,
                                STRSAFE_FILL_ON_FAILURE, fmt, ap);
    if (SUCCEEDED(res)) {
        prod += MAXLINE_LEN - left;
        bd->buffer->ulb_producer = prod;
    } else {
        res = RtlStringCbPrintfExA(&bd->buffer->ulb_buffer[pos_of(prod)],
                                   MAXLINE_LEN, NULL, &left,
                                   STRSAFE_FILL_ON_FAILURE,
                                   "[output failed]\n");
        if (SUCCEEDED(res)) {
            prod += MAXLINE_LEN - left;
            bd->buffer->ulb_producer = prod;
        } else
            bd->buffer->ulb_producer = wrap_of(prod);
    }

    spinlock_release(bd->lock, pre);

    if (bd->event && (KeGetCurrentIrql() <= DISPATCH_LEVEL))
        KeSetEvent(bd->event, 0, FALSE);

    return bd != &uxen_logging_buffer_desc;
}
