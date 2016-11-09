/*
 * Copyright 2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/dm.h>
#include <dm/vm.h>
#include <dm/dev.h>

#include "uxendisp-common.h"
#include "uxen_display.h"
#include "uxdisp_hw.h"
#include "pv_vblank.h"

#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>
#include <mmsystem.h>
#include <ntstatus.h>

static uint64_t disp_vsync_rate = 0; /* use host rate as base */
static uint64_t disp_vsync_div  = 1;
static uint64_t disp_vsync_mult = 1;
static uint64_t disp_vsync_skip = 0;

#define HW_VBLANK_MIN_HZ 30
#define HW_VBLANK_MAX_HZ 120

/* software vblank is used as fallback when hw one is temporarily unavailable or when
 * host vsync rate falls out of expected min/max range */
#define SOFT_VBLANK_POWERSAVE_HZ 30
#define SOFT_VBLANK_DEFAULT_HZ 60

struct vblank_query_msg {
    v4v_datagram_t dgram;
    int enabled;
} __attribute__ ((packed));

struct vblank_ctx {
    OVERLAPPED vblank_ov; /* must be first member */
    uxen_thread vblank_thread;
    ioh_event vblank_ev;
    ioh_event vblank_write_ev;
    int vblank_exit;
    int vblank_running;
    int hw_vblank_present;
    int hw_vblank_failing;
    int precise_soft_vblank;
    v4v_channel_t v4v;
    uint64_t vblank_t0;
    uint64_t soft_vblank_period;
    uint64_t frame;
    struct vblank_query_msg query_msg;
    struct uxendisp_state *disp_state;
};

static void CALLBACK vblank_read_done(DWORD a, DWORD b, LPOVERLAPPED c);
static void pv_vblank_respond(struct vblank_ctx *ctx, int enabled);

/* from d3dkmthk.h */
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

typedef struct _D3DKMT_WAITFORVERTICALBLANKEVENT
{
    D3DKMT_HANDLE                   hAdapter;      // in: adapter handle
    D3DKMT_HANDLE                   hDevice;       // in: device handle [Optional]
    D3DDDI_VIDEO_PRESENT_SOURCE_ID  VidPnSourceId; // in: adapter's VidPN Source ID
} D3DKMT_WAITFORVERTICALBLANKEVENT;

typedef NTSTATUS (APIENTRY *PFND3DKMT_OPENADAPTERFROMHDC)(D3DKMT_OPENADAPTERFROMHDC*);
typedef NTSTATUS (APIENTRY *PFND3DKMT_CLOSEADAPTER)(D3DKMT_CLOSEADAPTER*);
typedef NTSTATUS (APIENTRY *PFND3DKMT_WAITFORVERTICALBLANKEVENT)(CONST D3DKMT_WAITFORVERTICALBLANKEVENT*);

PFND3DKMT_OPENADAPTERFROMHDC D3DKMTOpenAdapterFromHdc;
PFND3DKMT_CLOSEADAPTER D3DKMTCloseAdapter;
PFND3DKMT_WAITFORVERTICALBLANKEVENT D3DKMTWaitForVerticalBlankEvent;

static void
d3dkmt_init(void)
{
    HMODULE hm;

    if (D3DKMTOpenAdapterFromHdc)
        return;
    hm = LoadLibrary("gdi32.dll");
    if (!hm) {
        debug_printf("vblank: gdi32 load failed\n");
        return;
    }
    D3DKMTOpenAdapterFromHdc =
        (PFND3DKMT_OPENADAPTERFROMHDC) GetProcAddress(hm, "D3DKMTOpenAdapterFromHdc");
    if (!D3DKMTOpenAdapterFromHdc)
        debug_printf("vblank: FAILED to acquire D3DKMTOpenAdapterFromHdc\n");
    D3DKMTCloseAdapter =
        (PFND3DKMT_CLOSEADAPTER) GetProcAddress(hm, "D3DKMTCloseAdapter");
    if (!D3DKMTCloseAdapter)
        debug_printf("vblank: FAILED to acquire D3DKMTCloseAdapter\n");
    D3DKMTWaitForVerticalBlankEvent =
        (PFND3DKMT_WAITFORVERTICALBLANKEVENT) GetProcAddress(hm, "D3DKMTWaitForVerticalBlankEvent");
    if (!D3DKMTWaitForVerticalBlankEvent)
        debug_printf("vblank: FAILED to acquire D3DKMTWaitForVerticalBlankEvent\n");
}

static void
configure(int method)
{
    switch (method) {
    case PV_VBLANK_NATIVE:
        disp_vsync_div  = 1;
        disp_vsync_mult = 1;
        disp_vsync_skip = 0;
        break;
    case PV_VBLANK_SMOOTH:
        disp_vsync_div  = 1;
        disp_vsync_mult = 2;
        disp_vsync_skip = 0;
        break;
    case PV_VBLANK_EFFICIENT:
        disp_vsync_div  = 2;
        disp_vsync_mult = 1;
        disp_vsync_skip = 1;
        break;
    default:
        break;
    }
}

static int
pv_vblank_get_host_vsynchz(void)
{
    DEVMODE mode = { };

    if (!EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &mode)) {
        debug_printf("failed to enum current display settings\n");
        return 0;
    }

    return mode.dmDisplayFrequency;
}

int
pv_vblank_get_reported_vsync_hz(void)
{
    int r;

    r = disp_vsync_rate ? disp_vsync_rate : pv_vblank_get_host_vsynchz();
    r = r * disp_vsync_mult / disp_vsync_div;

    return r;
}

static void
vblank_event_cb(void *opaque)
{
    struct vblank_ctx *ctx = opaque;

    ioh_event_reset(&ctx->vblank_ev);
    uxendisp_set_interrupt(ctx->disp_state, UXDISP_INTERRUPT_VBLANK);
}

struct vblank_ctx *
pv_vblank_init(struct uxendisp_state *s, int method)
{
    v4v_bind_values_t bind = { };
    struct vblank_ctx *ctx;

    d3dkmt_init();

    configure(method);

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->disp_state = s;

    if (!v4v_open(&ctx->v4v, UXENDISP_RING_SIZE, V4V_FLAG_ASYNC)) {
        debug_printf("%s: error opening v4v %x\n", __FUNCTION__, (int)GetLastError());
        goto error;
    }

    bind.ring_id.addr.port = UXENDISP_VBLANK_PORT;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_UUID;
    memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));

    if (!v4v_bind(&ctx->v4v, &bind)) {
        debug_printf("%s: error binding v4v %x\n", __FUNCTION__, (int)GetLastError());
        v4v_close(&ctx->v4v);
        goto error;
    }

    ioh_event_init(&ctx->vblank_write_ev);
    ioh_event_init(&ctx->vblank_ev);

    ioh_add_wait_object(&ctx->vblank_ev, vblank_event_cb, ctx, NULL);

    debug_printf("pv vblank initialised method=%d rate=%d mult=%d div=%d skip=%d, host rate @ %dhz\n",
                 (int)method,
                 (int)disp_vsync_rate, (int)disp_vsync_mult, (int)disp_vsync_div,
                 (int)disp_vsync_skip,
                 pv_vblank_get_host_vsynchz());
    ReadFileEx(ctx->v4v.v4v_handle, &ctx->query_msg, sizeof(ctx->query_msg),
               &ctx->vblank_ov, vblank_read_done);

    return ctx;

error:
    free(ctx);

    return NULL;
}

void
pv_vblank_cleanup(struct vblank_ctx *ctx)
{
    debug_printf("stopping pv vblank\n");
    pv_vblank_stop(ctx);
    debug_printf("stopped pv vblank\n");

    ioh_del_wait_object(&ctx->vblank_ev, NULL);

    ioh_event_close(&ctx->vblank_ev);
    ioh_event_close(&ctx->vblank_write_ev);

    v4v_close(&ctx->v4v);

    free(ctx);
}

static void
pv_vblank_respond(struct vblank_ctx *ctx, int enabled)
{
    struct vblank_query_msg resp = { };
    DWORD wr;

    resp.enabled = enabled;
    resp.dgram.addr.port = UXENDISP_VBLANK_PORT;
    resp.dgram.addr.domain = vm_id;

    ctx->vblank_ov.hEvent = ctx->vblank_write_ev;

    ResetEvent(ctx->vblank_write_ev);
    if (!WriteFile(ctx->v4v.v4v_handle, &resp, sizeof(resp),
                   &wr, &ctx->vblank_ov)) {
        if (GetLastError() != ERROR_IO_PENDING)
            debug_printf("vblank write failed %x\n", (int)GetLastError());
    }
}

static void CALLBACK
vblank_read_done(DWORD a, DWORD b, LPOVERLAPPED c)
{
    struct vblank_ctx *ctx = (struct vblank_ctx*)c;

    debug_printf("pv vblank query, responding with %d\n", (int)(!!disp_pv_vblank));
    pv_vblank_respond(ctx, !!disp_pv_vblank);
}

static void
hw_vblank_release(struct vblank_ctx *ctx, D3DKMT_WAITFORVERTICALBLANKEVENT *we)
{
    D3DKMT_CLOSEADAPTER ca = { };

    if (we->hAdapter) {
        ca.hAdapter = we->hAdapter;
        D3DKMTCloseAdapter(&ca);
        we->hAdapter = 0;
    }
}

static void
hw_vblank_update(struct vblank_ctx *ctx, D3DKMT_WAITFORVERTICALBLANKEVENT *we)
{
    D3DKMT_OPENADAPTERFROMHDC oa = { };
    NTSTATUS status;
    HDC hdc;
    int hosthz;

    ctx->hw_vblank_present = 0;
    hosthz = pv_vblank_get_host_vsynchz();
    if (hosthz < HW_VBLANK_MIN_HZ || hosthz > HW_VBLANK_MAX_HZ) {
        /* host refresh rate out of expected range, use precise soft blanking instead */
        ctx->soft_vblank_period = 1000000000LL / SOFT_VBLANK_DEFAULT_HZ;
        ctx->precise_soft_vblank = 1;
        return;
    }
    /* soft blank only used when monitors off, use imprecise timing at powersave hz */
    ctx->precise_soft_vblank = 0;
    ctx->soft_vblank_period = 1000000000LL / SOFT_VBLANK_POWERSAVE_HZ;

    if (!D3DKMTOpenAdapterFromHdc)
        return;

    if (we->hAdapter)
        hw_vblank_release(ctx, we);

    /* try from screen dc */
    hdc = GetDC(NULL);
    oa.hDc = hdc;
    status = D3DKMTOpenAdapterFromHdc(&oa);
    ReleaseDC(NULL, hdc);
    if (status != STATUS_SUCCESS) {
        /* try from first display */
        hdc = CreateDC(NULL, "\\\\.\\DISPLAY1", NULL, NULL);
        oa.hDc = hdc;
        status = D3DKMTOpenAdapterFromHdc(&oa);
        DeleteDC(hdc);
    }
    if (status == STATUS_SUCCESS) {
        ctx->hw_vblank_present = 1;
        we->hAdapter = oa.hAdapter;
        we->hDevice = 0;
        we->VidPnSourceId = oa.VidPnSourceId;
    } else {
        ctx->hw_vblank_present = 0;
        debug_printf("vblank: failed to open adapter (status %x)\n", (int)status);
    }
}

static NTSTATUS
hw_wait_vblank(struct vblank_ctx *ctx, D3DKMT_WAITFORVERTICALBLANKEVENT *we)
{
    NTSTATUS status = STATUS_DEVICE_REMOVED;

    if (D3DKMTWaitForVerticalBlankEvent)
        status = D3DKMTWaitForVerticalBlankEvent(we);

    return status;
}

#define ABS(x) (x >= 0 ? x : -x)

static void
soft_wait_vblank(struct vblank_ctx *ctx)
{
    int64_t period  = ctx->soft_vblank_period;
    int64_t delta   = os_get_clock() - ctx->vblank_t0;
    int64_t wait_ns = period * (ctx->frame+1) - delta;

    if (ABS(wait_ns) >= period*2) {
        /* recover from accumulation/period change error */
        debug_printf("vblank: error accumulated (%dms, period %dms), resetting\n",
                     (int)(wait_ns / 1000000),
                     (int)(period / 1000000));
        ctx->vblank_t0 = os_get_clock();
        ctx->frame = 0;
        wait_ns = period;
    }
    if (wait_ns < 0)
        wait_ns = 0;
    Sleep(wait_ns / 1000000);
}

static DWORD WINAPI
vblank_thread_run(PVOID opaque)
{
    struct vblank_ctx *ctx = (struct vblank_ctx*) opaque;
    NTSTATUS status;
    D3DKMT_WAITFORVERTICALBLANKEVENT we = { };
    int tmr_period_changed = 0;
    int using_soft_blank = 0;

    ctx->vblank_t0 = os_get_clock();
    ctx->frame = 0;

    hw_vblank_update(ctx, &we);

    while (!ctx->vblank_exit) {
        int need_soft_blank;

        if (ctx->hw_vblank_present) {
            status = hw_wait_vblank(ctx, &we);

            if (status != STATUS_SUCCESS) {
                if (!ctx->hw_vblank_failing) {
                    debug_printf("hw vblank - device lost? (status %x)\n", (int)status);
                    ctx->hw_vblank_failing = 1;
                }
            } else {
                if (ctx->hw_vblank_failing) {
                    debug_printf("hw vblank recovered\n");
                    ctx->hw_vblank_failing = 0;
                }
            }
        }

        need_soft_blank = !ctx->hw_vblank_present || ctx->hw_vblank_failing;
        if (using_soft_blank != need_soft_blank) {
            using_soft_blank = need_soft_blank;

            if (ctx->precise_soft_vblank) {
                if (using_soft_blank) {
                    tmr_period_changed = 1;
                    timeBeginPeriod(1);
                } else {
                    tmr_period_changed = 0;
                    timeEndPeriod(1);
                }
            }
        }

        if (using_soft_blank)
            soft_wait_vblank(ctx);

        /* inject guest vblank, every other real vblank if skipping enabled */
        if (!disp_vsync_skip || (ctx->frame&1) == 0)
            ioh_event_set(&ctx->vblank_ev);
        ctx->frame++;
    }

    hw_vblank_release(ctx, &we);

    if (tmr_period_changed)
        timeEndPeriod(1);

    return 0;
}

void
pv_vblank_start(struct vblank_ctx *ctx)
{
    if (ctx->vblank_running)
        return;

    ctx->vblank_exit = 0;
    ctx->vblank_running = 1;

    if (create_thread(&ctx->vblank_thread, vblank_thread_run, ctx) < 0) {
        debug_printf("failed to create vblank thread");
        return;
    }
    elevate_thread(ctx->vblank_thread);
}

void
pv_vblank_stop(struct vblank_ctx *ctx)
{
    if (ctx->vblank_running) {
        ctx->vblank_exit = 1;
        wait_thread(ctx->vblank_thread);
        ctx->vblank_running = 0;
    }
}

