/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include "dm.h"
#include "uxen.h"
#include "vm.h"

#include "qemu_glue.h"
#include "qemu_savevm.h"

#include <lz4.h>

#include <xenctrl.h>

#include <limits.h>
#if defined(__APPLE__)
#include <sys/mman.h>
#endif

//#include <assert.h>

#include "vram.h"

#if defined(__APPLE__)
#define NULL_HANDLE ((uintptr_t)-1)
#elif defined(_WIN32)
#define NULL_HANDLE ((uintptr_t)NULL)
#endif

#define DEBUG_VRAM

#ifdef DEBUG_VRAM
#define DPRINTF(fmt, ...) debug_printf(fmt, ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#endif

int
vram_init(struct vram_desc *v, size_t max_len)
{
    memset(v, 0, sizeof (*v));
    v->hdl = NULL_HANDLE;
    v->max_len = max_len;

    return 0;
}

static void *
shm_malloc(size_t len, uintptr_t *handle)
{
    void *view = NULL;

#if defined(_WIN32)
    *handle = (uintptr_t)CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                           PAGE_READWRITE | SEC_COMMIT, 0,
                                           len, NULL);
    if (!*handle) {
        Wwarn("CreateFileMapping");
        return NULL;
    }

    view = MapViewOfFile((HANDLE)*handle, FILE_MAP_WRITE, 0, 0, len);
    if (!view) {
        Wwarn("MapViewOfFile");
        CloseHandle((HANDLE)*handle);
        *handle = NULL_HANDLE;
        return NULL;
    }
#elif defined (__APPLE__)
    int ret;
    char name[32];
    uint32_t id;

    generate_random_bytes(&id, sizeof(id));
    snprintf(name, 32, "vram-%08x%08x", getpid(), id);

    *handle = (uintptr_t)shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (*handle == -1) {
        warn("shm_open(%s)", name);
        return NULL;
    }

    /* to work around an OS X kernel bug (?) ftruncate _must_ be called before
     * shm_unlink, otherwise the memory will be leaked. */
    ret = ftruncate((int)*handle, len);
    if (ret) {
        warn("ftruncate(%s)", name);
        shm_unlink(name);
        close((int)*handle);
        *handle = -1;
        return NULL;
    }

    shm_unlink(name);

    view = mmap(NULL, len, PROT_READ | PROT_WRITE,
                MAP_FILE | MAP_SHARED, (int)*handle, 0);
    if (view == MAP_FAILED) {
        warn("mmap(%s)", name);
        close((int)*handle);
        *handle = -1;
        return NULL;
    }
#endif

    DPRINTF("shm_malloc len=%"PRIdSIZE" handle=%"PRIxPTR"\n", len, *handle);

    return view;
}

static void
shm_free(uintptr_t handle, void *view, size_t len)
{
    DPRINTF("shm_free handle=%08"PRIxPTR"\n", handle);

#if defined(_WIN32)
    if (!UnmapViewOfFile(view))
        Wwarn("vram UnmapViewOfFile failed");
    CloseHandle((HANDLE)handle);
#elif defined (__APPLE__)
    munmap(view, len);
    close((int)handle);
#endif
}

int
vram_suspend(struct vram_desc *v)
{
    if (v->shm_len) {
        v->last_gfn = v->gfn;
        if (vram_unmap(v))
            err(1, "vram_unmap failed!\n");
        shm_free(v->hdl, v->view, v->shm_len);
        v->hdl = NULL_HANDLE;
        v->view = NULL;
        if (v->notify)
            v->notify(v, v->priv);
    }
    return 0;
}

int
vram_resume(struct vram_desc *v)
{
    int ret = 0;
    void *buf;

    if (v->shm_len) {
        v->view = shm_malloc(v->shm_len, &v->hdl);
        if (!v->view)
            return -1;

        ret = vram_map(v, v->last_gfn);
        if (ret) {
            shm_free(v->hdl, v->view, v->shm_len);
            return ret;
        }
        v->last_gfn = 0;

        buf = malloc(v->lz4_len);
        if (buf) {
            if (vm_save_read_dm_offset(buf, v->file_offset, v->lz4_len) ==
                    v->lz4_len) {
                ret = LZ4_decompress_safe(buf, (void *)v->view, v->lz4_len,
                                          v->shm_len);

                if (ret < 0)
                    debug_printf("failed to decompress vram data, r=%d\n", ret);
                ret = 0;
            }
            free(buf);
        }

        if (v->notify)
            v->notify(v, v->priv);
    }
    return ret;
}

int
vram_resize(struct vram_desc *v, uint32_t new_shm_len)
{
    int ret;
    uint32_t gfn;
    uintptr_t new_handle, old_handle;
    void *new_view, *old_view;
    size_t old_shm_len, l;

    DPRINTF("vram_resize len=%"PRIdSIZE" new_len=%d\n", v->shm_len,
            new_shm_len);

    if (new_shm_len > v->max_len) {
        debug_printf("%s: invalid mapping length %d (max %"PRIdSIZE")\n",
                     __FUNCTION__, new_shm_len, v->max_len);
        return -1;
    }

    if (new_shm_len == v->shm_len)
        return 0;

    gfn = v->gfn;
    if (gfn && v->shm_len) {
        ret = vram_unmap(v);
        if (ret) {
            debug_printf("%s: vram_unmap failed\n", __FUNCTION__);
            return -1;
        }
    }

    if (new_shm_len) {
        new_view = shm_malloc(new_shm_len, &new_handle);
        if (!new_view) {
            debug_printf("%s: shm_malloc failed\n", __FUNCTION__);
            return -1;
        }
    } else {
        new_view = NULL;
        new_handle = NULL_HANDLE;
    }

    old_handle = v->hdl;
    old_view = v->view;
    old_shm_len = v->shm_len;

    l = (new_shm_len > old_shm_len) ? old_shm_len : new_shm_len;
    memcpy(new_view, v->view, l);

    v->hdl = new_handle;
    v->view = new_view;
    v->shm_len = new_shm_len;

    if (v->notify)
        v->notify(v, v->priv);

    if (old_shm_len)
        shm_free(old_handle, old_view, old_shm_len);

    if (gfn && new_shm_len) {
        ret = vram_map(v, gfn);
        if (ret) {
            debug_printf("%s: vram_map failed\n", __FUNCTION__);
            return -1;
        }
    }

    return 0;
}

int
vram_alloc(struct vram_desc *v, size_t shm_len)
{
    return vram_resize(v, shm_len);
}

int
vram_release(struct vram_desc *v)
{
    return vram_resize(v, 0);
}

int
vram_unmap(struct vram_desc *v)
{
    int ret;

    DPRINTF("vram_unmap\n");

    if (!v->gfn)
        return -1;

    if (v->mapped_len) {
        ret = uxen_unmap_host_pages(uxen_handle, v->view, v->mapped_len);
        if (ret) {
            debug_printf("%s: uxen_unmap_host_pages failed: %d,"
                         " gfn=%x view=%p len=%"PRIdSIZE"\n",
                         __FUNCTION__, errno, v->gfn, v->view, v->shm_len);
            return -1;
        }
        v->mapped_len = 0;
    }
    v->gfn = 0;

    return 0;
}

int
vram_map(struct vram_desc *v, uint32_t gfn)
{
    int ret;

    if (v->gfn && v->mapped_len) {
        ret = uxen_unmap_host_pages(uxen_handle, v->view, v->mapped_len);
        if (ret) {
            debug_printf("%s: uxen_unmap_host_pages failed: %d,"
                         " gfn=%x view=%p len=%"PRIdSIZE"\n",
                         __FUNCTION__, errno, v->gfn, v->view, v->shm_len);
            return -1;
        }
        v->mapped_len = 0;
        v->gfn = 0;
    }

    if (v->shm_len) {
        uint64_t *gpfns;
        size_t gpfn_num = v->shm_len >> UXEN_PAGE_SHIFT;
        int idx;

        gpfns = (uint64_t *)malloc(gpfn_num * sizeof(gpfns[0]));
        if (!gpfns) {
            debug_printf("%s: malloc(%"PRIdSIZE") failed", __FUNCTION__,
                         gpfn_num * sizeof(gpfns[0]));
            return -1;
        }

        for (idx = 0; idx < gpfn_num; ++idx)
            gpfns[idx] = gfn + idx;

        ret = uxen_map_host_pages(uxen_handle, v->view, v->shm_len, gpfns);
        free(gpfns);
        if (ret) {
            debug_printf("%s: uxen_map_host_pages failed: %d,"
                         " view=%p len=%"PRIdSIZE"\n",
                         __FUNCTION__, errno, v->view, v->shm_len);
            return -1;
        }
        v->mapped_len = v->shm_len;
    }
    v->gfn = gfn;

    return 0;
}

void
vram_register_change(struct vram_desc *v,
                     void (*notify)(struct vram_desc *, void *),
                     void *priv)
{
    v->notify = notify;
    v->priv = priv;
}

static int
get_vram(QEMUFile *f, void *pv, size_t size)
{
    struct vram_desc *v = pv;
    size_t len;

    len = qemu_get_be32(f);
    if (len) {
        size_t lz4_len;

        vram_resize(v, len);
        lz4_len = qemu_get_be32(f);

        if (lz4_len) {
            void *p = malloc(lz4_len);
            if (p) {
                qemu_get_buffer(f, p, lz4_len);
                if (LZ4_decompress_safe(p, (void *)v->view, lz4_len, len) < 0)
                    warnx("%s: failed to decompress vram, lz4_len=%"PRIdSIZE,
                          __FUNCTION__, lz4_len);
                free(p);
            } else
                warnx("%s: failed to alloc decompress buffer=%"PRIdSIZE,
                      __FUNCTION__, lz4_len);
        } else {
            int i;
            uint32_t *px = (uint32_t *) v->view;
            const uint32_t c = restore_framebuffer_pattern;
            for (i = 0; i < len / sizeof(*px); ++i)
                px[i] = c;
        }
    }

    return 0;
}

static void
put_vram(QEMUFile *f, void *pv, size_t size)
{
    struct vram_desc *v = pv;

    qemu_put_be32(f, v->shm_len);
    if (v->shm_len) {
        if (!vm_save_info.ignore_framebuffer) {
            void *p = malloc(LZ4_compressBound(v->shm_len));
            size_t lz4_len = LZ4_compress((void *)v->view, p, v->shm_len);
            qemu_put_be32(f, lz4_len);
            v->lz4_len = lz4_len;
            v->file_offset = qemu_ftell(f);
            qemu_put_buffer(f, p, lz4_len);
            free(p);
        } else {
            v->lz4_len = 0;
            v->file_offset = 0;
            qemu_put_be32(f, 0);
        }
    }
}

const VMStateInfo vmstate_info_vram = {
    .name = "vram",
    .get = get_vram,
    .put = put_vram,
};

