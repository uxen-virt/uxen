/*
 * Copyright 2015-2017, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include "control.h"
#include "cuckoo.h"
#include "cuckoo-uxen.h"
#include "dm.h"
#include "filebuf.h"
#include "priv-heap.h"
#include "qemu_savevm.h"
#include "vm.h"
#include "vm-save.h"

#include <xc_private.h>
#include <lz4.h>

#define MAX_BATCH_SIZE 1023

struct thread_ctx {
    xc_hypercall_buffer_t buffer;
    xen_memory_capture_gpfn_info_t *gpfn_info_list;
};

struct ctx {
    heap_t heap;
    HANDLE cancel_event;
    struct thread_ctx tcs[CUCKOO_NUM_THREADS];
    HANDLE mutexes[cuckoo_num_mutexes];
    void *mappings[cuckoo_num_sections];
    SIZE_T ws_min, ws_max;
    SIZE_T locked[cuckoo_num_sections];
};

static void *alloc_mem(void *opaque, size_t sz)
{
    struct ctx *ctx = (struct ctx *) opaque;
    void *p;

    cuckoo_debug("alloc heap %p size %d\n", ctx->heap, (int)sz);
    p = sz ? priv_malloc(ctx->heap, sz) : NULL;
    cuckoo_debug("alloc heap %p size %d DONE @ %p\n", ctx->heap, (int)sz, p);

    return p;
}

static void free_mem(void *opaque, void *ptr)
{
    struct ctx *ctx = (struct ctx *) opaque;

    cuckoo_debug("free heap %p addr %p\n", ctx->heap, ptr);

    priv_free(ctx->heap, ptr);
}

static int cancelled(void *opaque)
{
    return vm_save_info.save_requested &&
        (vm_save_info.save_abort || vm_quit_interrupt);
}

static void *map_section(void *opaque, enum cuckoo_section_type t, size_t sz)
{
    struct ctx *ctx = opaque;
    HANDLE h;
    void *mapping;
    char *mn;
    char *id;
    char uuid_str[37];
    int keep_handle = 0;

    switch (t) {
        case cuckoo_section_idx0:
            id = "idx0";
            break;
        case cuckoo_section_idx1:
            id = "idx1";
            break;
        case cuckoo_section_pin:
            id = "pin";
            break;
        default:
            return NULL;
    }
    uuid_unparse_lower(vm_template_uuid, uuid_str);
    asprintf(&mn, "cuckoo-%s-%s", id, uuid_str);

    h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                           0, sz, mn);
    if (h) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            debug_printf("duplicating handle for %s to parent\n", mn);
            if (!control_dup_handle(h)) {
                warnx("control_dup_handle failed!");
                /* Useful for stand-alone testing. */
                keep_handle = 1;
            }
        }
    } else {
        Werr(1, "CreateFileMappingA fails");
    }
    mapping = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, sz);
    if (!keep_handle) {
        CloseHandle(h);
    }
    free(mn);
    ctx->mappings[t] = mapping;
    if (!mapping) {
        Werr(1, "MapViewOfFile");
    }
    return mapping;
}

static void unmap_section(void *opaque, enum cuckoo_section_type t)
{
    struct ctx *ctx = opaque;
    size_t locked = ctx->locked[t];
    SIZE_T ws_min, ws_max;
    if (locked) {
        debug_printf("%d was locked\n", t);
        if (!GetProcessWorkingSetSize(GetCurrentProcess(),
                                      &ws_min, &ws_max)) {
            Wwarn("%s: GetProcessWorkingSetSize fails", __FUNCTION__);
        }
        if (!VirtualUnlock(ctx->mappings[t], locked)) {
            Wwarn("%s: VirtualUnlock fails", __FUNCTION__);
        }
        if (!SetProcessWorkingSetSize(GetCurrentProcess(),
            ws_min - locked, ws_max - locked)) {
            Wwarn("%s: SetProcessWorkingSetSize fails", __FUNCTION__);
        }
        ctx->locked[t] = 0;
    }
    if (!UnmapViewOfFile(ctx->mappings[t])) {
        Wwarn("UnmapViewOfFile failed");
    }
}

static void pin_section(void *opaque, enum cuckoo_section_type t, size_t size)
{
    debug_printf("%s %d\n", __FUNCTION__, t);
    struct ctx *ctx = opaque;
    SIZE_T ws_min, ws_max;
    SIZE_T win_page_size = 0x10000;
    SIZE_T locked = (size + win_page_size - 1) & ~(win_page_size - 1);

    if (!GetProcessWorkingSetSize(GetCurrentProcess(), &ws_min, &ws_max)) {
        Wwarn("%s: GetProcessWorkingSetSize fails", __FUNCTION__);
    }
    if (!SetProcessWorkingSetSize(GetCurrentProcess(), ws_min + locked,
                                  ws_max + locked)) {
        Wwarn("%s: SetProcessWorkingSetSize fails", __FUNCTION__);
    }

    if (locked && !VirtualLock(ctx->mappings[t], locked)) {
        Wwarn("%s: VirtualLock fails", __FUNCTION__);
        locked = 0;
    }
    ctx->locked[t] = locked;
    debug_printf("%s %d done\n", __FUNCTION__, t);
}

static void reset_section(void *opaque, void *ptr, size_t sz)
{
    if (!VirtualAlloc(ptr, sz, MEM_RESET, PAGE_READWRITE)) {
        Wwarn("failed to reset memory pages");
    }
}

static int capture_pfns(void *opaque, int tid, int n, void *out, uint64_t *pfns)
{
    unsigned long got;
    int i, j, take;
    uint8_t *p;
    struct ctx *ctx = opaque;
    struct thread_ctx *tc = &ctx->tcs[tid];
    uint8_t *buf = HYPERCALL_BUFFER_ARGUMENT_BUFFER(&tc->buffer);
    xen_memory_capture_gpfn_info_t *gpfn_info_list = tc->gpfn_info_list;
    int ret;

    for (i = 0, p = out; i < n; i += take) {
        take = n - i < MAX_BATCH_SIZE ? n - i : MAX_BATCH_SIZE;

        for (j = 0; j < take; ++j) {
            uint64_t pfn = pfns[i + j];
            gpfn_info_list[j].gpfn = pfn & ~CUCKOO_TEMPLATE_PFN;
            gpfn_info_list[j].flags = pfn & CUCKOO_TEMPLATE_PFN ?
                                                XENMEM_MCGI_FLAGS_TEMPLATE :
                                                (XENMEM_MCGI_FLAGS_VM |
                                                XENMEM_MCGI_FLAGS_REMOVE_PFN);
        }

        ret = xc_domain_memory_capture(
                xc_handle, vm_id, take, gpfn_info_list, &got,
                &tc->buffer, PAGE_SIZE * take);
        if (ret || got != take) {
            debug_printf("xc_domain_memory_capture fail/incomplete: ret %d"
                    " errno %d done %ld/%d", ret, errno, got, take);
            errx(1, "the end");
            return -1;
        }

        for (j = 0; j < take; ++j, p += PAGE_SIZE) {
            uint32_t type = gpfn_info_list[j].type & XENMEM_MCGI_TYPE_MASK;
            if (type == XENMEM_MCGI_TYPE_NORMAL) {
                uint8_t *b = &buf[gpfn_info_list[j].offset];
                if (gpfn_info_list[j].type & XENMEM_MCGI_TYPE_COMPRESSED) {
                    uint16_t sz = *((uint16_t *) b);
                    ret = LZ4_decompress_safe((char *)b + sizeof(uint16_t),
                                              (char *)p, sz, PAGE_SIZE);
                    assert(ret == PAGE_SIZE);
                } else {
                    memcpy(p, &buf[gpfn_info_list[j].offset], PAGE_SIZE);
                }
            } else {
                /* This shouldn't happen. */
                debug_printf("j=%d type=%d pfn=%"PRIx64"\n", j, type,
                             pfns[i + j]);
                assert(0);
                memset(p, 0, PAGE_SIZE);
            }
        }
    }
    return 0;
}

static void *get_buffer(void *opaque, int tid, int *max)
{
    struct ctx *ctx = opaque;
    struct thread_ctx *tc = &ctx->tcs[tid];
    *max = MAX_BATCH_SIZE;
    return HYPERCALL_BUFFER_ARGUMENT_BUFFER(&tc->buffer);
}

static int populate_pfns(void *opaque, int tid, int n, uint64_t *pfns)
{
    struct ctx *ctx = opaque;
    struct thread_ctx *tc = &ctx->tcs[tid];
    int ret;

    ret = xc_domain_populate_physmap_from_buffer(xc_handle, vm_id, n, 0,
                                                 XENMEMF_populate_from_buffer,
                                                 pfns, &tc->buffer);
    return ret;
}

static int lock(void *opaque, enum cuckoo_mutex_type id)
{
    struct ctx *ctx = opaque;
    DWORD r;
    int locked, cancelled, abandoned;

    /* We need the cancel_event handle to go first in the array, otherwise it
     * seems to not always have the desired effect of getting the wait to
     * immediately return when the event gets set. This complicates using a
     * single WFMO call for both one and two-event cases, so instead we have to
     * special case and use both WFMO and WFSO depending on the situation. */
    if (ctx->cancel_event) {
        HANDLE evs[] = {ctx->cancel_event, ctx->mutexes[id]};
        r = WaitForMultipleObjects(2, evs, FALSE, INFINITE);
        cancelled = WAIT_OBJECT_0;
        locked = WAIT_OBJECT_0 + 1;
        abandoned = WAIT_ABANDONED_0 + 1;
    } else {
        cancelled = -1;
        locked = WAIT_OBJECT_0;
        abandoned = WAIT_ABANDONED;
        r = WaitForSingleObject(ctx->mutexes[id], INFINITE);
    }

    if (r == locked || r == abandoned) {
        return 0;
    } else if (r == cancelled) {
        return -1;
    } else {
        debug_printf("%s:%d r %d\n", __FUNCTION__, __LINE__, (int) r);
        assert(0);
        return -1;
    }
}

static void unlock(void *opaque, enum cuckoo_mutex_type id)
{
    struct ctx *ctx = opaque;
    ReleaseMutex(ctx->mutexes[id]);
}

static int is_alive(void *opaque, const uuid_t uuid)
{
    return file_exists(vm_save_file_name(uuid));
}

int cuckoo_uxen_init(struct cuckoo_context *cuckoo_context,
                     struct cuckoo_callbacks *ret_ccb, void **ret_opaque,
                     HANDLE cancel_event)
{
    int i;
    struct ctx *ctx;
    struct cuckoo_callbacks ccb = {
        cancelled,
        map_section,
        unmap_section,
        reset_section,
        pin_section,
        capture_pfns,
        get_buffer,
        populate_pfns,
        alloc_mem,
        free_mem,
        lock,
        unlock,
        is_alive,
    };

    cuckoo_init(cuckoo_context);

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        goto err;
    }
    if (priv_heap_create(&ctx->heap) != 0) {
        goto err;
    }
    ctx->cancel_event = cancel_event;

    for (i = 0; i < CUCKOO_NUM_THREADS; ++i) {
        struct thread_ctx *tc = &ctx->tcs[i];
        DECLARE_HYPERCALL_BUFFER(uint8_t, pp_buffer);
        pp_buffer = xc_hypercall_buffer_alloc_pages(
            xc_handle, pp_buffer, MAX_BATCH_SIZE);
        if (!pp_buffer) {
            goto err;
        }
        tc->buffer = *HYPERCALL_BUFFER(pp_buffer);
        tc->gpfn_info_list = alloc_mem(ctx, MAX_BATCH_SIZE *
                                       sizeof(tc->gpfn_info_list[0]));
    }

    for (i = 0; i < cuckoo_num_mutexes; ++i) {
        char *mn;
        asprintf(&mn, "uxen-cuckoo-mutex-%d", i);
        if (!mn) {
            goto err;
        }
        ctx->mutexes[i] = CreateMutexA(NULL, FALSE, mn);
        free(mn);
        if (!ctx->mutexes[i]) {
            Wwarn("CreateMutexA failed");
            goto err;
        }
    }

    *ret_ccb = ccb;
    *ret_opaque = ctx;
    return 0;

err:
    if (ctx) {
        cuckoo_uxen_close(cuckoo_context, ctx);
    }
    return -ENOMEM;
}

void cuckoo_uxen_close(struct cuckoo_context *cuckoo_context, void *opaque)
{
    struct ctx *ctx = opaque;
    int i;

    cuckoo_debug("uxen close\n");

    for (i = 0; i < CUCKOO_NUM_THREADS; ++i) {
        struct thread_ctx *tc = &ctx->tcs[i];
        if (HYPERCALL_BUFFER_ARGUMENT_BUFFER(&tc->buffer)) {
            xc__hypercall_buffer_free_pages(xc_handle, &tc->buffer,
                                            MAX_BATCH_SIZE);
        }
        free_mem(ctx, tc->gpfn_info_list);
    }
    for (i = 0; i < cuckoo_num_mutexes; ++i) {
        if (ctx->mutexes[i]) {
            CloseHandle(ctx->mutexes[i]);
        }
        ctx->mutexes[i] = NULL;
    }
    if (ctx->heap) {
        priv_heap_destroy(ctx->heap);
    }
    free(ctx);
}
