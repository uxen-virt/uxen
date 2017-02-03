/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <stdio.h>
#include <mfapi.h>
#include <mftransform.h>
#include <mfplay.h>
#include <d3d11.h>
#include <uxenh264-common.h>
#include <uxenh264lib.h>
#include <uxenh264utils.h>
#include <uxenh264pipeline.h>
#include <uxenconsolelib.h>
#include <atlbase.h>
#include <deque>
#include <algorithm>
#include "uxenh264d3d.h"
#include "debug-user.h"

struct context
{
    struct uxenh264_dm_ctx *dm_ctx;
    struct pipeline *pipeline;
    brh264_ctx ctx;
    HANDLE surface;
    bool fullscreen;
    bool new_fullscreen;
    bool show_ui;
    bool drop_mode;
    unsigned int width;
    unsigned int height;
    unsigned int linesize;
    unsigned int length;
    bool changed;
    HANDLE shm_handle;
    PBYTE frame_buffer;
    PBYTE new_frame;
    CRITICAL_SECTION cs;
    uxenconsole_context_t uxenconsole;
    uxenh264_d3d_ctx *d3d_ctx;
    std::deque<IMFSample *> slack;
    IMFSample *last_sample;
};

static void
send_media_type(struct context *ctx)
{
    struct pipeline *pipeline = ctx->pipeline;
    CComPtr<IMFMediaType> omt = NULL;
    HRESULT result = S_OK;
    brh264_data mt = {};

    if (ctx->fullscreen) {
        result = propagate_media_type(pipeline, UXENH264_FS_OUTPUT_WIDTH, UXENH264_FS_OUTPUT_HEIGHT);
    }
    else {
        result = propagate_media_type(pipeline, UXENH264_OUTPUT_WIDTH, UXENH264_OUTPUT_HEIGHT, true);
    }
    if (FAILED(result)) {
        uxen_err("Failed to propagate media type.");
        return;
    }

    result = pipeline->proc->GetOutputCurrentType(0, &omt);
    if (FAILED(result)) {
        uxen_err("Failed to get output type on video processor.");
        return;
    }

    UINT32 w = 0, h = 0;
    MFGetAttribute2UINT32asUINT64(omt, MF_MT_FRAME_SIZE, &w, &h);
    MFSetAttribute2UINT32asUINT64(omt, MF_MT_FRAME_SIZE, std::min(w, UXENH264_OUTPUT_WIDTH), std::min(h, UXENH264_OUTPUT_HEIGHT));

    brh264_serialize_attributes(omt, &mt.params, &mt.params_size);
    brh264_send_mt(ctx->ctx, &mt);
    if (mt.params) {
        free(mt.params);
    }
}

static void
render(struct context *ctx, IMFSample *pSample)
{
    struct pipeline *pipeline = ctx->pipeline;
    CComPtr<IMFMediaBuffer> spMediaBuffer = NULL;
    CComPtr<IMFDXGIBuffer> spDXGIBuffer = NULL;
    CComPtr<IDXGIResource> spDecodedTexture = NULL;
    CComPtr<ID3D11Texture2D> tex = NULL;

    pSample->GetBufferByIndex(0, &spMediaBuffer);
    if (spMediaBuffer)
        spMediaBuffer->QueryInterface(IID_PPV_ARGS(&spDXGIBuffer));
    if (spDXGIBuffer)
        spDXGIBuffer->GetResource(IID_PPV_ARGS(&spDecodedTexture));
    if (spDecodedTexture)
        spDecodedTexture->QueryInterface<ID3D11Texture2D>(&tex);

    CComPtr<ID3D11Texture2D> new_tex = NULL;
    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = ctx->width;
    desc.Height = ctx->height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8X8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = ctx->frame_buffer;
    initData.SysMemPitch = ctx->linesize;

    if (ctx->show_ui) {
        pipeline->d3d11_dev->CreateTexture2D(&desc, &initData, &new_tex);
    }
    else {
        pipeline->d3d11_dev->CreateTexture2D(&desc, NULL, &new_tex);
    }

    Render(ctx->d3d_ctx, pipeline->d3d11_dev, tex, new_tex);
}

static void
send_output_sample(struct context *ctx)
{
    struct pipeline *pipeline = ctx->pipeline;
    HRESULT result = S_OK;
    HRESULT mftProcessOutput = S_OK;
    MFT_OUTPUT_DATA_BUFFER outputDataBuffer;
    DWORD processOutputStatus = 0;
    int cnt = UXENH264_RETRY_COUNT;

    ZeroMemory(&outputDataBuffer, sizeof(outputDataBuffer));
    mftProcessOutput = pipeline->dec->ProcessOutput(0, 1, &outputDataBuffer, &processOutputStatus);
    if (ctx->new_fullscreen != ctx->fullscreen) {
        ctx->fullscreen = ctx->new_fullscreen;
        ctx->changed = true;
    }
    if (ctx->changed || (outputDataBuffer.dwStatus & MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE)) {
        ctx->changed = false;

        uxen_msg("Fullscreen:%d surface:0x%x res:%dx%d", ctx->fullscreen, ctx->surface, ctx->width, ctx->height);

        send_media_type(ctx);

        CreateRenderTarget(ctx->d3d_ctx, pipeline->d3d11_dev, ctx->width, ctx->height, &ctx->surface);
        uxenconsole_set_shared_surface(ctx->uxenconsole, (ctx->fullscreen) ? ctx->surface : NULL);
    }

    if (SUCCEEDED(mftProcessOutput)) {
        result = pipeline->proc->ProcessInput(0, outputDataBuffer.pSample, 0);
        outputDataBuffer.pSample->Release();
        ZeroMemory(&outputDataBuffer, sizeof(outputDataBuffer));
        mftProcessOutput = pipeline->proc->ProcessOutput(0, 1, &outputDataBuffer, &processOutputStatus);
    }

    while (SUCCEEDED(mftProcessOutput) && cnt--) {
        if (ctx->fullscreen) {
            render(ctx, outputDataBuffer.pSample);
        }

        UINT64 flags = (ctx->show_ui) ? UXENH264_FLAG_SHOW_UI : 0;
        outputDataBuffer.pSample->SetUINT64(MF_QUALITY_NOTIFY_SAMPLE_LAG, flags);

        result = send_media_sample(ctx->ctx, ctx->fullscreen, ctx->new_frame, outputDataBuffer.pSample);
        if (FAILED(result)) {
            stop_pipeline(pipeline);
            if (ctx->fullscreen) {
                result = propagate_media_type(pipeline, UXENH264_FS_OUTPUT_WIDTH, UXENH264_FS_OUTPUT_HEIGHT);
            }
            else {
                result = propagate_media_type(pipeline, UXENH264_OUTPUT_WIDTH, UXENH264_OUTPUT_HEIGHT, true);
            }
            start_pipeline(pipeline);
            uxen_err("Failed to send media sample.");
        }

        outputDataBuffer.pSample->Release();
        ZeroMemory(&outputDataBuffer, sizeof(outputDataBuffer));
        mftProcessOutput = pipeline->proc->ProcessOutput(0, 1, &outputDataBuffer, &processOutputStatus);
    }

    if (outputDataBuffer.pSample) {
        outputDataBuffer.pSample->Release();
    }
}

static void
brh264_flush_queue(struct context *ctx)
{
    while (!ctx->slack.empty()) {
        IMFSample *sample = ctx->slack.front();
        ctx->slack.pop_front();
        sample->Release();
    }
}

static void
brh264_recv_mt(void *priv, struct brh264_data *mt)
{
    struct context *ctx = (struct context *)priv;
    struct pipeline *pipeline = ctx->pipeline;
    CComPtr<IMFMediaType> imt = NULL;
    HRESULT result = S_OK;

    if (!mt) {
        uxen_err("This shouldn't have happened");
        return;
    }

    result = MFCreateMediaType(&imt);
    if (FAILED(result)) {
        uxen_err("Failed to create media type.");
        return;
    }

    stop_pipeline(pipeline);

    brh264_deserialize_attributes(imt, mt->params, mt->params_size);
    result = pipeline->dec->SetInputType(0, imt, 0);
    if (FAILED(result)) {
        uxen_err("Failed to set input type on decoder.");
        return;
    }

    send_media_type(ctx);
    start_pipeline(pipeline);
    brh264_flush_queue(ctx);
}

static void
brh264_recv_enc(void* priv, struct brh264_data* data)
{
    struct context *ctx = (struct context *)priv;
    struct pipeline *pipeline = ctx->pipeline;
    IMFSample *sample = NULL;
    HRESULT result = S_OK;
    UINT64 flags = 0;

    if (!data) {
        uxen_msg("Flushing the pipeline");
        pipeline->dec->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, NULL);
        pipeline->proc->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, NULL);
        brh264_flush_queue(ctx);
        return;
    }

    EnterCriticalSection(&ctx->cs);

    sample = create_media_sample(data->data_size);
    if (!sample) {
        uxen_err("Failed to create media sample.");
        goto exit;
    }

    result = fill_media_sample(sample, data);
    if (FAILED(result)) {
        uxen_err("Failed to fill media sample.");
        goto exit;
    }

    sample->GetUINT64(MF_QUALITY_NOTIFY_SAMPLE_LAG, &flags);
    ctx->new_fullscreen = !!(flags & UXENH264_FLAG_FULLSCREEN);
    ctx->drop_mode = !!(flags & UXENH264_FLAG_DROP_QUALITY);

    ctx->slack.push_back(sample);
    sample = ctx->slack.front();
    ctx->slack.pop_front();

    result = pipeline->dec->ProcessInput(0, sample, 0);
    if (SUCCEEDED(result)) {
        sample->Release();
    }
    else {
        ctx->slack.push_front(sample);
    }

    send_output_sample(ctx);

exit:
    brh264_send_res(ctx->ctx, S_OK);

    LeaveCriticalSection(&ctx->cs);
}

static void
brh264_update_cursor(
    void *priv, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int flags, file_handle_t)
{
    struct context *ctx = (struct context *)priv;
    EnterCriticalSection(&ctx->cs);
    ctx->show_ui = !(flags & CURSOR_UPDATE_FLAG_HIDE);
    if (ctx->show_ui) {
        uxen_msg("Showing UI");
    }
    else {
        uxen_msg("Hidding UI");
    }
    LeaveCriticalSection(&ctx->cs);
}

static void
brh264_resize_surface(void *priv,
    unsigned int width,
    unsigned int height,
    unsigned int linesize,
    unsigned int length,
    unsigned int,
    unsigned int,
    file_handle_t shm_handle)
{
    struct context *ctx = (struct context *)priv;

    EnterCriticalSection(&ctx->cs);

    uxen_msg("New surface 0x%x %dx%d", shm_handle, width, height);

    if (ctx->frame_buffer) {
        UnmapViewOfFile(ctx->frame_buffer);
        ctx->frame_buffer = NULL;
    }

    ctx->width = width;
    ctx->height = height;
    ctx->linesize = linesize;
    ctx->length = length;
    ctx->shm_handle = shm_handle;
    ctx->changed = true;

    if (shm_handle) {
        ctx->frame_buffer = (PBYTE)MapViewOfFile(shm_handle, FILE_MAP_ALL_ACCESS, 0, 0, length);
        ctx->new_frame = ctx->frame_buffer + (linesize * height);
        if (!ctx->frame_buffer) {
            uxen_err("MapViewOfFile has failed handle:0x%x; length:%d", shm_handle, length);
            ctx->new_frame = NULL;
        }
    }

    LeaveCriticalSection(&ctx->cs);
}

static void
event_loop(struct context *ctx)
{
    HANDLE uxenconsole_event = NULL;
    HANDLE uxenh264_event = NULL;
    int retry_count = UXENH264_RETRY_COUNT;

    while ((uxenconsole_event == NULL) && retry_count--) {
        uxenconsole_event = uxenconsole_connect(ctx->uxenconsole);
        if (uxenconsole_event == NULL) {
            Sleep(100);
        }
    }
    if (!uxenconsole_event) {
        uxen_err("Failed to connect to uxenconsole");
        return;
    }

    uxenh264_event = brh264_recv_collect(ctx->ctx, FALSE);
    if (!uxenh264_event) {
        uxen_err("Call to brh264_recv_collect has failed");
        return;
    }

    HANDLE handles[] = { uxenconsole_event, uxenh264_event, ctx->dm_ctx->exit };
    for (;;)
    {
        DWORD w = WaitForMultipleObjects(ARRAYSIZE(handles), handles, FALSE, INFINITE);
        switch (w) {
        case WAIT_OBJECT_0:
            uxenconsole_channel_event(ctx->uxenconsole, uxenconsole_event, 0);
            break;
        case WAIT_OBJECT_0 + 1:
            brh264_recv_collect(ctx->ctx, TRUE);
            break;
        default:
            uxen_msg("Exiting event_loop %d", w);
            return;
        }
    }
}

extern "C" __declspec(dllexport) DWORD
uxenh264_thread_run(PVOID opaque)
{
    ConsoleOps ops = {};
    brh264_recv_callbacks cb = {};
    struct context ctx = { (struct uxenh264_dm_ctx *)opaque };
    char filename[MAX_PATH] = {};

    uxen_ud_set_progname("uxenh264_host");
    uxen_ud_set_printk(ctx.dm_ctx->debug_pfn);

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    MFStartup(MF_VERSION);

    cb.brh264_recv_mt = brh264_recv_mt;
    cb.brh264_recv_enc = brh264_recv_enc;

    sprintf_s(filename, "\\\\.\\pipe\\uxenconsole-" PRIuuid, PRIuuid_arg(ctx.dm_ctx->v4v_idtoken));
    //sprintf_s(filename, "\\\\.\\pipe\\uxenconsole-1234");

    ctx.pipeline = create_pipeline();
    if (!ctx.pipeline) {
        uxen_err("Failed to create pipeline.");
        goto exit;
    }

    ctx.ctx = brh264_create(&ctx, &cb, ctx.dm_ctx->v4v_idtoken);
    if (!ctx.ctx) {
        uxen_err("Call to brh264_create has failed.");
        goto exit;
    }

    InitializeCriticalSectionAndSpinCount(&ctx.cs, 0x00000400);

    ctx.d3d_ctx = InitDevice(ctx.pipeline->d3d11_dev);
    if (!ctx.d3d_ctx) {
        uxen_err("Call to InitDevice has failed.");
        goto exit;
    }

    ops.update_cursor = brh264_update_cursor;
    ops.resize_surface = brh264_resize_surface;
    ctx.uxenconsole = uxenconsole_init(&ops, &ctx, filename);
    if (!ctx.uxenconsole) {
        uxen_err("Call to uxenconsole_init has failed.");
        goto exit;
    }

    event_loop(&ctx);

exit:
    if (ctx.d3d_ctx) {
        CleanupDevice(ctx.d3d_ctx);
    }

    if (ctx.uxenconsole) {
        uxenconsole_cleanup(ctx.uxenconsole);
    }

    if (ctx.ctx) {
        brh264_destroy(ctx.ctx);
    }

    DeleteCriticalSection(&ctx.cs);

    return 0;
}
