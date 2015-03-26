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
#include <uxen_ioctl.h>

static struct uxen_logging_buffer_desc
uxen_logging_buffer_desc = UXEN_LOGGING_BUFFER_DESC_INITIALIZER;

int
logging_init(struct uxen_logging_buffer_desc *bd, uint32_t size)
{
    int i;
    int ret;

    if (!bd)
        bd = &uxen_logging_buffer_desc;

    if (bd->buffer)
        return 0;

    if (!size)
        size = LOGGING_DEFAULT_BUFFER_SIZE;
    else if (size > LOGGING_MAX_BUFFER_SIZE)
        size = LOGGING_MAX_BUFFER_SIZE;

    bd->event.id = -1;

    bd->size = size;
    bd->npages = (size + sizeof(struct uxen_logging_buffer) +
                  PAGE_SIZE - 1) >> PAGE_SHIFT;

    bd->mfns = kernel_malloc(bd->npages * sizeof(bd->mfns[0]));
    if (!bd->mfns) {
        fail_msg("kernel_malloc failed");
        ret = ENOMEM;
        return ret;
    }

    ret = kernel_malloc_mfns(bd->npages, bd->mfns, 0);
    if (ret != bd->npages) {
        fail_msg("kernel_malloc_mfns failed: %d", ret);
        kernel_free(bd->mfns, bd->npages * sizeof(bd->mfns[0]));
        bd->mfns = NULL;
        ret = ENOMEM;
        goto out;
    }
    ret = 0;

    bd->buffer = map_pfn_array(bd->mfns, bd->npages, &bd->map_handle);
    if (!bd->buffer) {
        fail_msg("map_pfn_array failed");
        ret = EINVAL;
        goto out;
    }

    ret = spinlock_initialize(bd->lock);
    if (ret) {
        fail_msg("spinlock_initialize failed");
        goto out;
    }

    memset(bd->buffer, 0, bd->npages << PAGE_SHIFT);
    bd->buffer->ulb_size = size;

  out:
    if (ret) {
        if (bd->buffer) {
            unmap(&bd->map_handle);
            bd->buffer = NULL;
        }
        if (bd->mfns) {
            for (i = 0; i < bd->npages; i++)
                kernel_free_mfn(bd->mfns[i]);
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

    md->user_mapping = user_mmap_pages(bd->npages, bd->mfns, fda);
    if (!md->user_mapping) {
        fail_msg("user_mmap_pages failed");
        return ENOMEM;
    }

    if (uld->uld_event)
        create_notification_event(&fda->events, uld->uld_event, &bd->event);

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
    bd->event.id = -1;

    ret = user_munmap_pages(bd->npages, md->user_mapping, fda);
    if (ret)
        fail_msg("user_munmap_pages failed: %d", ret);
    md->user_mapping = NULL;
}

void
logging_free(struct uxen_logging_buffer_desc *bd)
{
    int i;

    dprintk("%s\n", __FUNCTION__);
    if (!bd)
        bd = &uxen_logging_buffer_desc;

    spinlock_free(bd->lock);
    if (bd->buffer) {
        unmap(&bd->map_handle);
        bd->buffer = NULL;
    }
    if (bd->mfns) {
        for (i = 0; i < bd->npages; i++)
            kernel_free_mfn(bd->mfns[i]);
        kernel_free(bd->mfns, bd->npages * sizeof(bd->mfns[0]));
        bd->mfns = NULL;
    }
}

#include <libkern/libkern.h>

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
    int ret;

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

    ret = vsnprintf(&bd->buffer->ulb_buffer[pos_of(prod)],
                    MAXLINE_LEN, fmt, ap);
    if (ret >= 0) {
        prod += ret;
        bd->buffer->ulb_producer = prod;
    } else {
        ret = snprintf(&bd->buffer->ulb_buffer[pos_of(prod)], MAXLINE_LEN, "%s",
                       "[output failed]\n");
        if (ret >= 0) {
            prod += ret;
            bd->buffer->ulb_producer = prod;
        } else
            bd->buffer->ulb_producer = wrap_of(prod);
    }

    spinlock_release(bd->lock, pre);

    if (bd->event.id != -1)
        signal_notification_event(&bd->event);

    return 0;
}
