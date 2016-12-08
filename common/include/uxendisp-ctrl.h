/*
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef UXENDISP_CTRL_H_
#define UXENDISP_CTRL_H_

#include "uxendisp-common.h"
#include <windows.h>

/* from d3dkmthk.h */
typedef LONG NTSTATUS;
typedef UINT D3DKMT_HANDLE;
typedef UINT D3DDDI_VIDEO_PRESENT_SOURCE_ID;

typedef struct _D3DKMT_OPENADAPTERFROMHDC
{
    HDC                             hDc;            // in:  DC that maps to a single display
    D3DKMT_HANDLE                   hAdapter;       // out: adapter handle
    LUID                            AdapterLuid;    // out: adapter LUID
    D3DDDI_VIDEO_PRESENT_SOURCE_ID  VidPnSourceId;  // out: VidPN source ID for that particular display
} D3DKMT_OPENADAPTERFROMHDC;

typedef struct _D3DKMT_CLOSEADAPTER {
  D3DKMT_HANDLE hAdapter;
} D3DKMT_CLOSEADAPTER;

typedef enum _D3DKMT_ESCAPETYPE
{
    D3DKMT_ESCAPE_DRIVERPRIVATE           = 0,
    D3DKMT_ESCAPE_VIDMM                   = 1,
    D3DKMT_ESCAPE_TDRDBGCTRL              = 2,
    D3DKMT_ESCAPE_VIDSCH                  = 3,
    D3DKMT_ESCAPE_DEVICE                  = 4,
    D3DKMT_ESCAPE_DMM                     = 5,
    D3DKMT_ESCAPE_DEBUG_SNAPSHOT          = 6,
    D3DKMT_ESCAPE_SETDRIVERUPDATESTATUS   = 7,
    D3DKMT_ESCAPE_DRT_TEST                = 8,
    D3DKMT_ESCAPE_DIAGNOSTICS             = 9
} D3DKMT_ESCAPETYPE;

typedef struct _D3DDDI_ESCAPEFLAGS
{
    union
    {
        struct
        {
            UINT    HardwareAccess      : 1;    // 0x00000001
            UINT    Reserved            :31;    // 0xFFFFFFFE
        } Bits;
        UINT        Value;
    };
} D3DDDI_ESCAPEFLAGS;

typedef struct _D3DKMT_ESCAPE
{
    D3DKMT_HANDLE       hAdapter;               // in: adapter handle
    D3DKMT_HANDLE       hDevice;                // in: device handle [Optional]
    D3DKMT_ESCAPETYPE   Type;                   // in: escape type.
    D3DDDI_ESCAPEFLAGS  Flags;                  // in: flags
    VOID*               pPrivateDriverData;     // in/out: escape data
    UINT                PrivateDriverDataSize;  // in: size of escape data
    D3DKMT_HANDLE       hContext;               // in: context handle [Optional]
} D3DKMT_ESCAPE;


typedef NTSTATUS (APIENTRY *PFND3DKMT_OPENADAPTERFROMHDC)(D3DKMT_OPENADAPTERFROMHDC*);
typedef NTSTATUS (APIENTRY *PFND3DKMT_CLOSEADAPTER)(D3DKMT_CLOSEADAPTER*);
typedef NTSTATUS (APIENTRY *PFND3DKMT_ESCAPE)(D3DKMT_ESCAPE*);


/* ------------------------------------- */
typedef struct uxendisp_ctrl_ctx {
    D3DKMT_HANDLE adapter;

    PFND3DKMT_OPENADAPTERFROMHDC D3DKMTOpenAdapterFromHdc;
    PFND3DKMT_CLOSEADAPTER D3DKMTCloseAdapter;
    PFND3DKMT_ESCAPE D3DKMTEscape;
} uxendisp_ctrl_ctx_t;


static uxendisp_ctrl_ctx_t *
uxendisp_ctrl_init(void)
{
    D3DKMT_OPENADAPTERFROMHDC open = { 0 };
    NTSTATUS status;
    HMODULE hm;
    uxendisp_ctrl_ctx_t *ctx = (uxendisp_ctrl_ctx_t*)calloc(1, sizeof(uxendisp_ctrl_ctx_t));

    if (!ctx)
        return NULL;

    hm = LoadLibraryA("gdi32.dll");
    if (!hm)
        goto err;

    ctx->D3DKMTOpenAdapterFromHdc =
        (PFND3DKMT_OPENADAPTERFROMHDC) GetProcAddress(hm, "D3DKMTOpenAdapterFromHdc");
    if (!ctx->D3DKMTOpenAdapterFromHdc)
        goto err;

    ctx->D3DKMTCloseAdapter =
        (PFND3DKMT_CLOSEADAPTER) GetProcAddress(hm, "D3DKMTCloseAdapter");
    if (!ctx->D3DKMTCloseAdapter)
        goto err;

    ctx->D3DKMTEscape =
        (PFND3DKMT_ESCAPE) GetProcAddress(hm, "D3DKMTEscape");
    if (!ctx->D3DKMTEscape)
        goto err;

    open.hDc = CreateDC(TEXT("DISPLAY"), NULL, NULL, NULL);
    if (!open.hDc)
        goto err;

    status = ctx->D3DKMTOpenAdapterFromHdc(&open);
    DeleteDC(open.hDc);
    if (status != 0)
        goto err;

    ctx->adapter = open.hAdapter;
    goto out;
err:
    free(ctx);
    return NULL;
out:
    return ctx;
}

static void
uxendisp_ctrl_release(uxendisp_ctrl_ctx_t *ctx)
{
    if (ctx) {
        D3DKMT_CLOSEADAPTER close = { 0 };

        close.hAdapter = ctx->adapter;
        ctx->D3DKMTCloseAdapter(&close);
        free(ctx);
    }
}

static NTSTATUS
uxendisp_escape(uxendisp_ctrl_ctx_t *ctx, int hwaccess, void *in_buf, int in_buf_size)
{
    D3DKMT_ESCAPE escape;

    if (!ctx->adapter)
        return STATUS_INVALID_PARAMETER;

    escape.hAdapter = ctx->adapter;
    escape.hDevice = 0;
    escape.Type = D3DKMT_ESCAPE_DRIVERPRIVATE;
    escape.Flags.Value = 0;
    escape.Flags.Bits.HardwareAccess = hwaccess;
    escape.pPrivateDriverData = in_buf;
    escape.PrivateDriverDataSize = in_buf_size;
    escape.hContext = 0;
    return ctx->D3DKMTEscape(&escape);
}

static void*
uxendisp_map_fb(uxendisp_ctrl_ctx_t *ctx)
{
    UXENDISPCustomMode m = { 0 };

    m.esc_code = UXENDISP_ESCAPE_MAP_FB;
    if (uxendisp_escape(ctx, 0, &m, sizeof(m)))
        return NULL;

    return (void*)(uintptr_t)m.ptr;
}

static void
uxendisp_unmap_fb(uxendisp_ctrl_ctx_t *ctx, void *mapped)
{
    UXENDISPCustomMode m = { 0 };

    m.esc_code = UXENDISP_ESCAPE_UNMAP_FB;
    m.ptr = (uintptr_t)mapped;
    uxendisp_escape(ctx,0, &m, sizeof(m));
}

static void
uxendisp_update_rect(uxendisp_ctrl_ctx_t *ctx, int x, int y, int w, int h)
{
    UXENDISPCustomMode m = { 0 };

    m.esc_code = UXENDISP_ESCAPE_UPDATE_RECT;
    m.x = x;
    m.y = y;
    m.width = w;
    m.height = h;
    uxendisp_escape(ctx,0, &m, sizeof(m));
}

static void
uxendisp_set_user_draw(uxendisp_ctrl_ctx_t *ctx, int ud)
{
    UXENDISPCustomMode m = { 0 };

    m.esc_code = UXENDISP_ESCAPE_SET_USER_DRAW_ONLY;
    m.user_draw = ud;
    uxendisp_escape(ctx,0, &m, sizeof(m));
}

static void
uxendisp_set_no_present_copy(uxendisp_ctrl_ctx_t *ctx, int nc)
{
    UXENDISPCustomMode m = { 0 };

    m.esc_code = UXENDISP_ESCAPE_SET_NO_PRESENT_COPY;
    m.no_present_copy = nc;
    uxendisp_escape(ctx,0, &m, sizeof(m));
}

static void
uxendisp_flush(uxendisp_ctrl_ctx_t *ctx)
{
    UXENDISPCustomMode m = { 0 };

    m.esc_code = UXENDISP_ESCAPE_FLUSH;
    uxendisp_escape(ctx,0, &m, sizeof(m));
}

#endif
