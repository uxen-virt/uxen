/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <atlbase.h>
#include <stdio.h>
#include <mfapi.h>
#include <mftransform.h>
#include <Mfidl.h>
#include <d3d11.h>
#include "uxenh264pipeline.h"
#include "uxenh264-common.h"
#include "debug-user.h"

EXTERN_GUID(BR_CLSID_VideoProcessorMFT, 0x88753b26, 0x5b24, 0x49bd, 0xb2, 0xe7, 0x0c, 0x44, 0x5c, 0x78, 0xc9, 0x82);
EXTERN_GUID(BR_CLSID_CMSH264DecoderMFT, 0x62CE7E72, 0x4C71, 0x4d20, 0xB1, 0x5D, 0x45, 0x28, 0x31, 0xA8, 0x7D, 0x9D);

static void
set_d3d_mgr(struct pipeline *pipeline)
{
    D3D_FEATURE_LEVEL feature_level = D3D_FEATURE_LEVEL_11_1;
    HRESULT result = S_OK;
    UINT token = 0;
    CComPtr<IMFDXGIDeviceManager> dev_mgr = NULL;
    CComPtr<ID3D11DeviceContext> pContext = NULL;
    CComQIPtr<IMFQualityAdvise> quality;

    if (pipeline->d3d11_dev) {
        pipeline->d3d11_dev.Release();
    }

    result = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
        &feature_level, 1, D3D11_SDK_VERSION, &pipeline->d3d11_dev, NULL, NULL);
    if (FAILED(result)) {
        uxen_err("Call to D3D11CreateDevice has failed 0x%x", result);
        goto exit;
    }

    pipeline->d3d11_dev->GetImmediateContext(&pContext);
    CComQIPtr<ID3D10Multithread>(pContext)->SetMultithreadProtected(TRUE);

    result = MFCreateDXGIDeviceManager(&token, &dev_mgr);
    if (FAILED(result)) {
        uxen_err("Call to MFCreateDXGIDeviceManager has failed 0x%x", result);
        goto exit;
    }

    result = dev_mgr->ResetDevice(pipeline->d3d11_dev, token);
    if (FAILED(result)) {
        uxen_err("Call to ResetDevice has failed 0x%x", result);
        goto exit;
    }

    result = pipeline->dec->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, (ULONG_PTR)dev_mgr.p);
    if (FAILED(result)) {
        uxen_err("Failed to send MFT_MESSAGE_SET_D3D_MANAGER to h264 decoder 0x%x", result);
    }

    result = pipeline->proc->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, (ULONG_PTR)dev_mgr.p);
    if (FAILED(result)) {
        uxen_err("Failed to send MFT_MESSAGE_SET_D3D_MANAGER to video processor 0x%x", result);
    }

    quality = pipeline->dec;
    if (quality) {
        quality->SetDropMode(MF_DROP_MODE_5);
        quality->SetQualityLevel(MF_QUALITY_NORMAL_MINUS_5);
    }

exit:
    return;
}

static HRESULT
create_processor(struct pipeline *pipeline)
{
    HRESULT result = S_OK;
    CComPtr<IUnknown> proc_unk = NULL;
    CComQIPtr<IMFQualityAdvise> quality;

    result = CoCreateInstance(BR_CLSID_VideoProcessorMFT, NULL, CLSCTX_INPROC_SERVER,
        IID_IUnknown, (void**)&proc_unk);
    if (FAILED(result)) {
        uxen_err("Failed to create video processor instance 0x%x", result);
        goto exit;
    }

    result = proc_unk->QueryInterface(IID_PPV_ARGS(&pipeline->proc));
    if (FAILED(result)) {
        uxen_err("Failed query for an MFT interface on a video processor 0x%x", result);
        goto exit;
    }

    quality = pipeline->proc;
    if (quality) {
        quality->SetDropMode(MF_DROP_MODE_5);
        quality->SetQualityLevel(MF_QUALITY_NORMAL_MINUS_5);
    }

exit:
    return result;
}

HRESULT
propagate_media_type(struct pipeline *pipeline, UINT32 width, UINT32 height, bool limit)
{
    HRESULT result = S_OK;
    CComPtr<IMFMediaType> imt = NULL;
    CComPtr<IMFMediaType> omt = NULL;
    UINT32 w = 0, h = 0;

    result = pipeline->dec->GetInputCurrentType(0, &imt);
    if (FAILED(result)) {
        uxen_err("Failed to get current input type from decoder 0x%x", result);
        goto exit;
    }

    result = pipeline->dec->GetOutputAvailableType(0, 0, &omt);
    if (FAILED(result)) {
        uxen_err("Failed to get available output type from decoder 0x%x", result);
        goto exit;
    }

    MFSetAttributeSize(omt, MF_MT_FRAME_RATE, 30000, 1000);

    result = pipeline->dec->SetOutputType(0, omt, 0);
    if (FAILED(result)) {
        uxen_err("Failed to set output type on decoder 0x%x", result);
        goto exit;
    }

    MFGetAttribute2UINT32asUINT64(omt, MF_MT_FRAME_SIZE, &w, &h);

    if (!pipeline->proc) {
        result = create_processor(pipeline);
        if (FAILED(result)) {
            uxen_err("Failed to create video processor 0x%x", result);
            goto exit;
        }
    }

    result = pipeline->proc->SetInputType(0, omt, 0);
    if (FAILED(result)) {
        uxen_err("Failed to set input type on video processor 0x%x", result);
        goto exit;
    }

    result = pipeline->dec->GetOutputAvailableType(0, 0, &omt);
    if (FAILED(result)) {
        uxen_err("Failed to get available output type from decoder 0x%x", result);
        goto exit;
    }

    result = omt->SetGUID(MF_MT_SUBTYPE, UXENH264_OUTPUT_TYPE);
    if (FAILED(result)) {
        uxen_err("Failed to change the MF_MT_SUBTYPE 0x%x", result);
        goto exit;
    }

    if (limit && ((w < width) || (h < height))) {
        width = w;
        height = h;
    }

    result = MFSetAttributeSize(omt, MF_MT_FRAME_SIZE, width, height);
    if (FAILED(result)) {
        uxen_err("Failed to change the MF_MT_FRAME_SIZE 0x%x", result);
        goto exit;
    }

    result = omt->SetUINT32(MF_MT_DEFAULT_STRIDE, width * UXENH264_OUTPUT_BYTES_PER_PIXEL);
    if (FAILED(result)) {
        uxen_err("Failed to change the MF_MT_DEFAULT_STRIDE 0x%x", result);
        goto exit;
    }

    result = omt->SetUINT32(MF_MT_SAMPLE_SIZE, width * height * UXENH264_OUTPUT_BYTES_PER_PIXEL);
    if (FAILED(result)) {
        uxen_err("Failed to chage the MF_MT_SAMPLE_SIZE 0x%x", result);
        goto exit;
    }

    result = pipeline->proc->SetOutputType(0, omt, 0);
    if (FAILED(result)) {
        uxen_err("Failed to set output type on video processor 0x%x", result);
        goto exit;
    }

exit:
    return result;
}

struct pipeline *
create_pipeline(void)
{
    struct pipeline *pipeline = NULL;
    HRESULT result = S_OK;
    CComPtr<IUnknown> dec_unk = NULL;

    pipeline = (struct pipeline *)calloc(1, sizeof (*pipeline));
    if (!pipeline) {
        uxen_err("Failed to allocate memory for struct pipeline.");
        goto error;
    }

    result = CoCreateInstance(BR_CLSID_CMSH264DecoderMFT, 0, CLSCTX_INPROC_SERVER,
        IID_IUnknown, (void**)&dec_unk);
    if (FAILED(result)) {
        uxen_err("Failed to create H264 decoder instance 0x%x", result);
        goto error;
    }

    result = dec_unk->QueryInterface(IID_PPV_ARGS(&pipeline->dec));
    if (FAILED(result)) {
        uxen_err("Failed query for an MFT interface on a H264 decoder 0x%x", result);
        goto error;
    }

    result = create_processor(pipeline);
    if (FAILED(result)) {
        uxen_err("Failed to create video processor 0x%x", result);
        goto error;
    }

    set_d3d_mgr(pipeline);

    return pipeline;

error:
    if (pipeline) {
        free(pipeline);
    }
    return NULL;
}

void
destroy_pipeline(struct pipeline *pipeline)
{
    if (!pipeline) {
        return;
    }
    if (pipeline->proc) {
        pipeline->proc->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, NULL);
        pipeline->proc->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, NULL);
        pipeline->proc->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, NULL);
        pipeline->proc->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, NULL);
        pipeline->proc = NULL;
    }
    if (pipeline->dec) {
        pipeline->dec->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, NULL);
        pipeline->dec->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, NULL);
        pipeline->dec->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, NULL);
        pipeline->dec->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, NULL);
        pipeline->dec = NULL;
    }
    if (pipeline) {
        free(pipeline);
    }
}

void
start_pipeline(struct pipeline* pipeline)
{
    HRESULT result = S_OK;

    if (pipeline->started) {
        return;
    }

    pipeline->started = true;

    if (!pipeline->proc) {
        result = create_processor(pipeline);
        if (FAILED(result)) {
            uxen_err("Failed to create video processor 0x%x", result);
            goto error;
        }
    }

    pipeline->dec->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, NULL);
    pipeline->dec->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, NULL);
    pipeline->dec->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, NULL);

    pipeline->proc->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, NULL);
    pipeline->proc->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, NULL);
    pipeline->proc->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, NULL);

    return;

error:
    stop_pipeline(pipeline);
}

void
stop_pipeline(struct pipeline *pipeline)
{
    if (!pipeline->started) {
        return;
    }

    if (pipeline->proc) {
        pipeline->proc->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, NULL);
        pipeline->proc->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, NULL);
        pipeline->proc->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, NULL);
    }

    pipeline->dec->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, NULL);
    pipeline->dec->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, NULL);
    pipeline->dec->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, NULL);

    pipeline->started = false;
}
