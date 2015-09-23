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
 * Copyright 2015, Bromium, Inc.
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

// A line is something like:
// (12 + (16 * 2) + (2 * 1) + 2 + (16 * 1) + (2 * 1) + 1) = 67 --> 128
#define XENV4V_DUMP_SIZE 127

static VOID
gh_v4v_hexdump_ring(void *_b, int len)
{
    uint8_t *b = _b;
    int s = 0;
    int e = len;
    int i, j;
    char *buf;
    char *fmt;

    buf = (char *)ExAllocatePoolWithTag(NonPagedPool, 2 * (XENV4V_DUMP_SIZE + 1), XENV4V_TAG);
    if (buf == NULL) {
        TraceError(("failed to allocate ring dump buffer\n"));
        return;
    }
    RtlZeroMemory(buf, 2 * (XENV4V_DUMP_SIZE + 1));
    // Two areas, the main buffer to cat into and the format buffer
    fmt = buf + XENV4V_DUMP_SIZE + 1;

    for (i = 0; i < (e + 15); i += 16) {
        RtlStringCchPrintfA(buf, XENV4V_DUMP_SIZE, "[%08x]: ", i);
        for (j = 0; j < 16; ++j) {
            int k = i + j;
            if (j == 8) {
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, " ");
            }

            if ((k >= s) && (k < e)) {
                RtlStringCchPrintfA(fmt, XENV4V_DUMP_SIZE, "%02x", b[k]);
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, fmt);
            } else {
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, "  ");
            }
        }

        RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, "  ");

        for (j = 0; j < 16; ++j) {
            int k = i + j;
            if (j == 8) {
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, " ");
            }

            if ((k >= s) && (k < e)) {
                RtlStringCchPrintfA(fmt, XENV4V_DUMP_SIZE, "%c", ((b[k] > 32) && (b[k] < 127)) ? b[k] : '.');
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, fmt);
            } else {
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, " ");
            }
        }
        RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, "\n");
        TraceNotice((buf));
    }

    ExFreePoolWithTag(buf, XENV4V_TAG);
}

// Caller must hold lock
VOID
gh_v4v_dump_ring(v4v_ring_t *r)
{
    TraceNotice(("v4v_ring_t at %p:\n", r));
    TraceNotice(("r->rx_ptr=%d r->tx_ptr=%d r->len=%d\n", r->rx_ptr, r->tx_ptr, r->len));
    gh_v4v_hexdump_ring((void *)r->ring, r->len);
}

// Caller must hold lock
VOID
gh_v4v_recover_ring(xenv4v_context_t *ctx)
{
    // It's all gone horribly wrong
    TraceError(("something went horribly wrong in a ring - dumping and attempting a recovery\n"));

    gh_v4v_dump_ring(ctx->ring_object->ring);
    // Xen updates tx_ptr atomically to always be pointing somewhere sensible
    ctx->ring_object->ring->rx_ptr = ctx->ring_object->ring->tx_ptr;
}

static v4v_pfn_list_t *
gh_v4v_allocate_pfn_list(uint8_t *buf, uint32_t npages)
{
    v4v_pfn_list_t   *pfns;
    PHYSICAL_ADDRESS  pa;
    uint32_t          len = sizeof(v4v_pfn_list_t) + (sizeof(v4v_pfn_t) * npages);
    uint32_t          i;

    pfns = (v4v_pfn_list_t *)ExAllocatePoolWithTag(NonPagedPool, len, XENV4V_TAG);
    if (pfns == NULL) {
        return NULL;
    }
    RtlZeroMemory(pfns, len);
    pfns->magic = V4V_PFN_LIST_MAGIC;
    pfns->npage = npages;

    for (i = 0; i < npages; i++) {
        pa = MmGetPhysicalAddress(buf);
        pfns->pages[i] = pa.QuadPart / PAGE_SIZE;
        buf += PAGE_SIZE;
    }

    return pfns;
}

xenv4v_ring_t *
gh_v4v_allocate_ring(uint32_t ring_length)
{
    uint32_t     length;
    uint32_t     npages;
    xenv4v_ring_t *robj;
    PHYSICAL_ADDRESS low, high;
    SIZE_T bytes;

    if (ring_length > XENV4V_MAX_RING_LENGTH) return NULL;

    // OK, make it
    robj = (xenv4v_ring_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(xenv4v_ring_t), XENV4V_TAG);
    if (robj == NULL) {
        return NULL;
    }
    RtlZeroMemory(robj, sizeof(xenv4v_ring_t));
    InitializeListHead(&robj->le);

    // Add one ref count for the caller creating the ring
    robj->refc = 1;

    length = ring_length + sizeof(v4v_ring_t);
    npages = (length + PAGE_SIZE - 1) >> PAGE_SHIFT;

#if 0
    robj->ring = (v4v_ring_t *)ExAllocatePoolWithTag(NonPagedPool, length, XENV4V_TAG);
    if (robj->ring == NULL) {
        ExFreePoolWithTag(robj, XENV4V_TAG);
        return NULL;
    }
#else
    low.QuadPart = 0;
    high.QuadPart = (ULONGLONG) - 1;
#if 0
    bytes.QuadPart = length;
#else
    bytes = length;
#endif

    robj->mdl = MmAllocatePagesForMdlEx(low, high, low, bytes, MmCached, MM_ALLOCATE_FULLY_REQUIRED);
    if (!robj->mdl) {
        ExFreePoolWithTag(robj, XENV4V_TAG);
        return NULL;
    }

    robj->ring = (v4v_ring_t *) MmMapLockedPagesSpecifyCache(robj->mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (robj->ring == NULL) {
        MmFreePagesFromMdl(robj->mdl);
        IoFreeMdl(robj->mdl);
        ExFreePoolWithTag(robj, XENV4V_TAG);
        return NULL;
    }

    robj->user_map = NULL;
#endif


    RtlZeroMemory(robj->ring, length);
    KeInitializeSpinLock(&robj->lock);
    robj->ring->magic = V4V_RING_MAGIC;
    robj->ring->len = ring_length;
    robj->ring->rx_ptr = robj->ring->tx_ptr = 0;
    robj->ring->id.addr.port = V4V_PORT_NONE;
    robj->ring->id.addr.domain = V4V_DOMID_NONE;

    robj->pfn_list = gh_v4v_allocate_pfn_list((uint8_t *)robj->ring, npages);
    if (robj->pfn_list == NULL) {
#if 0
        ExFreePoolWithTag(robj->ring, XENV4V_TAG);
#else
        MmUnmapLockedPages(robj->ring, robj->mdl);
        MmFreePagesFromMdl(robj->mdl);
        IoFreeMdl(robj->mdl);
#endif
        ExFreePoolWithTag(robj, XENV4V_TAG);
        return NULL;
    }

    return robj;
}

ULONG32
gh_v4v_add_ref_ring(xenv4v_extension_t *pde, xenv4v_ring_t *robj)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG32            count;

    KeAcquireInStackQueuedSpinLock(&pde->ring_lock, &lqh);
    count = ++robj->refc;
    KeReleaseInStackQueuedSpinLock(&lqh);

    return count;
}

ULONG32
gh_v4v_release_ring(xenv4v_extension_t *pde, xenv4v_ring_t *robj)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG32            count;

    KeAcquireInStackQueuedSpinLock(&pde->ring_lock, &lqh);
    ASSERT(robj->refc != 1); // SNO, really bad
    count = --robj->refc;
    if (count == 1) {
        // Nobody but the list is holding us so remove ourself
        RemoveEntryList(&robj->le);
        count = 0;
    }
    KeReleaseInStackQueuedSpinLock(&lqh);

    if (count == 0) {
        // If it was successfully registered, then unregister it here
        if (robj->registered) {
            gh_v4v_unregister_ring(robj);
        }
        if (robj->pfn_list != NULL) {
            ExFreePoolWithTag(robj->pfn_list, XENV4V_TAG);
        }
#if 0
        if (robj->ring != NULL) {
            ExFreePoolWithTag(robj->ring, XENV4V_TAG);
        }
#else
#if 0   // This needs to be done in the process context, so we move it to MJ_CLEANUP
        if (robj->user_map != NULL)
            MmUnmapLockedPages(robj->user_map, robj->mdl);
#endif
        if (robj->ring != NULL )
            MmUnmapLockedPages(robj->ring, robj->mdl);
        if (robj->mdl != NULL) {
            MmFreePagesFromMdl(robj->mdl);
            IoFreeMdl(robj->mdl);
        }
#endif

        ExFreePoolWithTag(robj, XENV4V_TAG);
    }

    return count;
}

static BOOLEAN
gh_v4v_port_in_use(xenv4v_extension_t *pde, uint32_t port, uint32_t *maxOut)
{
    BOOLEAN      ret = FALSE;
    xenv4v_ring_t *robj = NULL;

    if (!IsListEmpty(&pde->ring_list)) {
        robj = (xenv4v_ring_t *)pde->ring_list.Flink;
        while (robj != (xenv4v_ring_t *)&pde->ring_list) {
            if (robj->ring->id.addr.port == port) {
                ret = TRUE; // found one
            }
            // Bump the max
            if ((maxOut != NULL) && (robj->ring->id.addr.port > *maxOut)) {
                *maxOut = robj->ring->id.addr.port;
            }
            robj = (xenv4v_ring_t *)robj->le.Flink;
        }
    }

    return ret;
}

// Must be called at PASSIVE level
uint32_t
gh_v4v_random_port(xenv4v_extension_t *pde)
{
    uint32_t port;

    port = RtlRandomEx(&pde->seed);
    port |= 0x80000000U;
    return ((port > 0xf0000000U) ? (port - 0x10000000) : port);
}

// Must be called holding the lock
uint32_t
gh_v4v_spare_port_number(xenv4v_extension_t *pde, uint32_t port)
{
    uint32_t max = 0x80000000U;

    if (gh_v4v_port_in_use(pde, port, &max)) {
        port = max + 1;
    }

    return port;
}

// Must be called holding the lock
BOOLEAN
gh_v4v_ring_id_in_use(xenv4v_extension_t *pde, struct v4v_ring_id *id)
{
    xenv4v_ring_t *robj = NULL;

    if (!IsListEmpty(&pde->ring_list)) {
        robj = (xenv4v_ring_t *)pde->ring_list.Flink;
        while (robj != (xenv4v_ring_t *)&pde->ring_list) {
            if ((robj->ring->id.addr.port == id->addr.port) &&
                (robj->ring->id.partner == id->partner)) {
                return TRUE;
            }
            robj = (xenv4v_ring_t *)robj->le.Flink;
        }
    }

    return FALSE;
}

// Must be called holding the lock
VOID
gh_v4v_link_to_ring_list(xenv4v_extension_t *pde, xenv4v_ring_t *robj)
{
    // Add a reference for the list - mainly for consistency
    robj->refc++;

    // Link this context into the adapter list
    InsertHeadList(&pde->ring_list, &(robj->le));
    TraceInfo(("added ring object %p to list.\n", robj));
}


