/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "dm.h"
#include "console.h"
#include "ioh.h"
#include "atto-agent.h"
#include "queue2.h"
#include "vm.h"
#include <dm/whpx/whpx.h>
#include <err.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <xenctrl.h>
#include <uxen/uxen_desc.h>
#include <xenguest.h>
#include <xc_attovm.h>
#include <xc_private.h>
#include <attoxen-api/ax_attovm.h>
#include <attoimg/attoimg.h>
#include "timer.h"

#define MAX_DIRPATH_LEN (4 * MAX_PATH)
#define ATTOVM_IMAGE_EXT ".attovm"
#define PAGE_ALIGN(x) (((x) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1))

typedef struct win_cursor {
    LIST_ENTRY(win_cursor) entry;
    int x11_type;
    uint64_t x11_ptr;
    int w;
    int h;
    int hot_x;
    int hot_y;
    uint8_t *mask;
    uint8_t *color;
} win_cursor;

static LIST_HEAD(, win_cursor) win_cursor_list =
       LIST_HEAD_INITIALIZER(&win_cursor_list);

static win_cursor *current_cursor = NULL;
static int vm_has_keyboard_focus = 0;
static int host_offer_focus = 0;
static int focused_head_id = 0;

// FIXME: free?
static void *appdef_mem;

void attovm_set_head_focus(int head_id)
{
    focused_head_id = head_id;
}

void attovm_set_keyboard_focus(int offer_focus)
{
    host_offer_focus = !!offer_focus;
}

void attovm_check_keyboard_focus(void)
{
    int rc = 0;

    if (vm_get_run_mode() == DESTROY_VM)
        return;

    atto_agent_request_keyboard_focus(host_offer_focus, focused_head_id);
    if (vm_attovm_mode == ATTOVM_MODE_AX)
        rc = xc_attovm_change_focus(xc_handle, vm_id, host_offer_focus);

    if (rc)
        return;

    vm_has_keyboard_focus = host_offer_focus;
}

static LPCTSTR
map_x11_to_win_cursor(int x11_cursor)
{
    switch (x11_cursor) {
    case 52: /* XC_fleur */
        return IDC_SIZEALL;
    case 68: /* XC_left_ptr */
        return IDC_ARROW;
    case 34: /* XC_crosshair */
        return IDC_CROSS;
    case 58: /* XC_hand1 */
    case 60: /* XC_hand2 */
        return IDC_HAND;
    case 152: /* XC_xterm */
        return IDC_IBEAM;
    case 150: /* XC_watch */
        return IDC_WAIT;
    case 92: /* XC_question_arrow */
        return IDC_HELP;
    case 96: /* XC_right_side */
        return IDC_SIZEWE;
    case 138: /* XC_top_side */
        return IDC_SIZENS;
    case 136: /* XC_top_right_corner */
        return IDC_SIZENESW;
    case 134: /* XC_top_left_corner */
        return IDC_SIZENWSE;
    case 16: /* XC_bottom_side */
        return IDC_SIZENS;
    case 14: /* XC_bottom_right_corner */
        return IDC_SIZENWSE;
    case 12: /* XC_bottom_left_corner */
        return IDC_SIZENESW;
    case 70: /* XC_left_side */
        return IDC_SIZEWE;
    case 116: /* XC_sb_v_double_arrow */
        return IDC_SIZENS;
    case 108: /* XC_sb_h_double_arrow */
        return IDC_SIZEWE;
    default:
        return IDC_ARROW;
    }

    return IDC_ARROW;
}

static void
delete_cursor(win_cursor *wc)
{
    free(wc->mask);
    free(wc->color);
    free(wc);
}

static win_cursor *
x11_get_cursor(uint64_t x11_ptr)
{
    win_cursor *wc = NULL;
    LIST_FOREACH(wc, &win_cursor_list, entry) {
        if (wc->x11_ptr != x11_ptr)
            continue;
        return wc;
    }
    return NULL;
}

static void
x11_make_standard_cursor(win_cursor *wc)
{
    ICONINFO info;
    BITMAP mask_info;
    BITMAP color_info = {0};
    LONG count;
    BOOL ok;
    HCURSOR cursor;

    /* Windows will lie to you about the cursor metrics unless you pretend to be
       DPI aware. Even if you call LoadImage instead and explicitly request the
       larger size*/
    DPI_AWARENESS_CONTEXT old_dpi = Win32_SetThreadDpiAwarenessContext(
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE);
    cursor = LoadCursor(NULL, map_x11_to_win_cursor(wc->x11_type));

    ok = GetIconInfo(cursor, &info);
    if (!ok) {
        debug_printf("Failed to get cursor info err=%d for type %d\n",
            (int)GetLastError(), wc->x11_type);
        goto out;
    }
    GetObject(info.hbmMask, sizeof(BITMAP), &mask_info);
    wc->w = mask_info.bmWidth;
    wc->hot_x = info.xHotspot;
    wc->hot_y = info.yHotspot;
    count = mask_info.bmWidthBytes * mask_info.bmHeight;
    wc->mask = malloc(count);
    GetBitmapBits(info.hbmMask, count, wc->mask);
    if (info.hbmColor) {
        GetObject(info.hbmColor, sizeof(BITMAP), &color_info);
        count = color_info.bmWidthBytes * color_info.bmHeight;
        wc->color = malloc(count);
        GetBitmapBits(info.hbmColor, count, wc->color);
        wc->h = color_info.bmHeight;
    } else {
        /* B&W bitmaps stash the xor mask in there too, doubling the height */
        wc->h = mask_info.bmHeight / 2;
    }
    DeleteObject(info.hbmMask);
    DeleteObject(info.hbmColor);
out:
    Win32_SetThreadDpiAwarenessContext(old_dpi);
}

static void
x11_get_or_create_standard_cursor(int x11_type, uint64_t x11_ptr)
{
    win_cursor *wc = NULL, *wc_next;
    LIST_FOREACH_SAFE(wc, &win_cursor_list, entry, wc_next) {
        if (wc->x11_ptr != x11_ptr)
            continue;
        if (wc->x11_type == x11_type)
            return; /* Already setup */
        LIST_REMOVE(wc, entry);
        delete_cursor(wc);
        wc = NULL;
        break;
    }

    if (!x11_type)
        x11_type = 68 /* XC_left_ptr */;

    wc = calloc(1, sizeof(*wc));
    if (!wc) {
        warn("%s: malloc error\n", __FUNCTION__);
        return;
    }
    wc->x11_type = x11_type;
    wc->x11_ptr = x11_ptr;
    x11_make_standard_cursor(wc);
    LIST_INSERT_HEAD(&win_cursor_list, wc, entry);
}

void
attovm_unmap_x11_cursor(uint64_t x11_ptr)
{
    struct win_cursor *wc = NULL, *wc_next;

    LIST_FOREACH_SAFE(wc, &win_cursor_list, entry, wc_next) {
        if (wc->x11_ptr != x11_ptr)
            continue;
        LIST_REMOVE(wc, entry);
        delete_cursor(wc);
        break;
    }
}

static void
report_cursor_change(struct display_state* ds, win_cursor *wc)
{
    if (!wc) {
        // No cursor yet, probably shouldn't happen...
        return;
    }
    dpy_cursor_shape(ds, wc->w, wc->h, wc->hot_x, wc->hot_y,
                     wc->mask, wc->color);
}

void
attovm_set_x11_cursor(struct display_state* ds, uint64_t x11_ptr)
{
    current_cursor = x11_get_cursor(x11_ptr);
    report_cursor_change(ds, current_cursor);
}

void
attovm_set_current_cursor(struct display_state* ds)
{
    report_cursor_change(ds, current_cursor);
}

void
attovm_map_x11_cursor(int x11_type, uint64_t x11_ptr)
{
    assert(x11_type != -1);
    x11_get_or_create_standard_cursor(x11_type, x11_ptr);
}

void
attovm_create_custom_cursor(uint64_t x11_ptr, int xhot, int yhot,
                            int x11_nx, int x11_ny,
                            int data_len, const uint8_t *data)
{
    int mono_bits_len = ((x11_nx + 7) >> 3) * x11_ny;
    int mono_mask_len = mono_bits_len * 2; /* AND mask plus XOR mask */
    int color_len = x11_nx * x11_ny * 4; /* 32bpp ARGB */

    /* Don't do anything if x11_ptr has already been configured */
    win_cursor *wc = NULL;
    LIST_FOREACH(wc, &win_cursor_list, entry) {
        if (wc->x11_ptr == x11_ptr) {
            return;
        }
    }

    wc = calloc(1, sizeof(*wc));
    if (!wc) {
        warn("%s: malloc error\n", __FUNCTION__);
        return;
    }
    wc->x11_type = -1; /* custom */
    wc->x11_ptr = x11_ptr;
    wc->hot_x = xhot;
    wc->hot_y = yhot;
    wc->w = x11_nx;
    wc->h = x11_ny;

    if (data_len == mono_mask_len + 4 + color_len
        && *(uint32_t*)(data + mono_mask_len) == 32) {
        /* This means it's colour */
        wc->color = malloc(color_len);
        if (!wc->color)
            goto fail;
        memcpy(wc->color, data + mono_mask_len + 4, color_len);

        /* mask should be just the AND mask */
        wc->mask = malloc(mono_bits_len);
        if (!wc->mask)
            goto fail;
        memcpy(wc->mask, data, mono_bits_len);
    } else if (data_len >= mono_mask_len) {
        /* Old pre-color-support guest code would send larger than necessary
           messages, meaning we cannot require data_len to be a specific value
        */
        wc->color = NULL;
        wc->mask = malloc(mono_mask_len);
        if (!wc->mask)
            goto fail;
        memcpy(wc->mask, data, mono_mask_len);
    }
    LIST_INSERT_HEAD(&win_cursor_list, wc, entry);
    return;

fail:
    free(wc->color);
    free(wc->mask);
    free(wc);
}

int
is_attovm_image(const char *image)
{
    const char *ext = NULL;

    while (image && *image) {
        image = strchr(image, '.');
        if (image) {
            ext = image;
            image++;
        }
    }

    return ext && (strcasecmp(ext, ATTOVM_IMAGE_EXT) == 0);
}

void
attovm_init_conf(const char *image)
{
    struct attovm_definition_v1 def = { };
    uint64_t memory;

    if (attoimg_image_read(image, &def, NULL))
        errx(1, "error reading attovm definition from: %s", image);

    /* use vcpus amount from attovm definition */
    vm_vcpus  = def.m.num_vcpus;
    /* vm_mem_mb is actually ignored for attovms, but set it here from .attovm
     * for consistency */
    memory = (uint64_t)def.m.num_pages << PAGE_SHIFT;
    if (memory & ((1 << 20) - 1))
        errx(1, "unexpected memory size: %"PRId64, memory);
    vm_mem_mb = memory >> 20;
}

void
attovm_init_conf_whpx(void)
{
    /* we leverage viridian synth timers on WHP because MS apic virt does not support
     * deadline timer which would otherwise be used */
    if (whpx_enable) {
        vm_viridian = 1;
        /* TODO: leverage reference tsc page to optimize access to partition ref time.
         * Currently causes issues with synchronization between vm_clock and guest tsc when
         * using absolute viridian timers */
        whpx_reftsc = 0;
    }
}

static int
whpx_attovm_put_appdef(
    struct attovm_definition_v1 *def,
    const char *appdef,
    uint32_t appdef_len)
{
    uint32_t alloc_len = PAGE_ALIGN(appdef_len);
    uint32_t npages = alloc_len >> PAGE_SHIFT;

    if (!appdef || !appdef_len)
        return 0;

    if (npages > ATTOVM_UNSIGNED_MEM_MAX_PAGES)
        whpx_panic("attovm appdef is too long: %d bytes", appdef_len);
    appdef_mem = VirtualAlloc(NULL, alloc_len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    assert(appdef_mem);
    memset(appdef_mem, 0, alloc_len);
    memcpy(appdef_mem, appdef, appdef_len);
    whpx_ram_populate_with(ATTOVM_APPDEF_PHYSADDR, alloc_len, appdef_mem, WHPX_RAM_NO_DECOMMIT);
    def->appdef_size = appdef_len;

    return 0;
}

/* we place appdef in highmem memory, which is not signed */
static int
uxen_attovm_put_appdef(
    struct attovm_definition_v1 *definition,
    const char *appdef,
    uint32_t appdef_len)
{
    uint32_t alloc_len, npages;
    xen_pfn_t *pfns = NULL;
    privcmd_mmap_entry_t *mmap_entries = NULL;
    void *mapped = NULL;
    int ret = 0, i;

    alloc_len = PAGE_ALIGN(appdef_len);
    npages = alloc_len >> PAGE_SHIFT;

    if (!appdef || !npages) {
        definition->appdef_size = 0;
        goto out; /* nothing to put */
    }

    if (npages > ATTOVM_UNSIGNED_MEM_MAX_PAGES) {
        debug_printf("attovm appdef is too long: %d bytes", appdef_len);
        ret = -ENOMEM;
        goto out;
    }

    pfns = calloc(npages, sizeof(xen_pfn_t));
    if (!pfns) {
        ret = -ENOMEM;
        goto out;
    }

    for (i = 0; i < npages; i++)
        pfns[i] = (ATTOVM_APPDEF_PHYSADDR >> PAGE_SHIFT) + i;
    /* actual allocate of highmem pages */
    ret = xc_domain_populate_physmap_exact(xc_handle,
        vm_id, npages, 0, 0, &pfns[0]);
    if (ret)
        goto out;

    /* map highmem pages */
    mmap_entries = calloc(npages, sizeof(privcmd_mmap_entry_t));
    if (!mmap_entries) {
        ret = -ENOMEM;
        goto out;
    }

    for (i = 0; i < npages; i++)
        mmap_entries[i].mfn = pfns[i];

    mapped = xc_map_foreign_ranges(xc_handle,
        vm_id, npages << PAGE_SHIFT, PROT_READ | PROT_WRITE,
        1 << PAGE_SHIFT, mmap_entries, npages);

    if (!mapped) {
        ret = -EINVAL;
        goto out;
    }

    memset(mapped, 0, npages << PAGE_SHIFT);
    if (appdef)
        memcpy(mapped, appdef, appdef_len);

    definition->appdef_size = appdef_len;

out:
    if (mapped)
        xc_munmap(xc_handle, vm_id, mapped, npages << PAGE_SHIFT);
    free(pfns);
    free(mmap_entries);

    return ret;
}

int attovm_put_appdef(
    struct attovm_definition_v1 *def,
    const char *appdef,
    uint32_t appdef_len)
{
    if (!whpx_enable)
        return uxen_attovm_put_appdef(def, appdef, appdef_len);
    else
        return whpx_attovm_put_appdef(def, appdef, appdef_len);
}

char *
attovm_load_appdef(const char *file, uint32_t *out_size)
{
    uint32_t sz = 0;
    uint32_t left;
    void *buf;
    void *def = NULL;
    FILE *f;

    f = fopen(file, "rb");
    if (!f)
        goto out;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (!sz)
        goto out;
    def = malloc(sz);
    if (!def)
        goto out;

    left = sz;
    buf = def;
    while (left) {
        uint32_t chunk_read = 0;
        uint32_t chunk = left;

        if (chunk > 0x10000)
            chunk = 0x10000;
        chunk_read = fread(buf, 1, chunk, f);
        if (chunk_read != chunk) {
            free(def);
            def = NULL;
            goto out;
        }
        buf  += chunk;
        left -= chunk;
    }

out:
    if (f)
        fclose(f);
    *out_size = sz;

    return def;
}

int
attovm_seal_guest(struct attovm_definition_v1 *def)
{
    if (!whpx_enable)
        return xc_attovm_seal_guest(xc_handle, vm_id, def);
    else
        return whpx_attovm_seal_guest(def);
}
