/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxenh264.h"
#include "CAutoLock.h"
#include <mfapi.h>
#include <mferror.h>
#include <initguid.h>
#include <uxenh264lib.h>
#include <algorithm>
#pragma warning(disable: 4505)
#include <uxenh264utils.h>
#include <uxenh264pipeline.h>
#include <uxendisp-ctrl.h>

// Helper Macros
#define SAFERELEASE(x) \
    if((x) != NULL) \
    { \
        (x)->Release(); \
        (x) = NULL; \
    } \

EXTERN_GUID(BR_CLSID_MSH264DecoderMFT, 0x62CE7E72, 0x4C71, 0x4d20, 0xB1, 0x5D, 0x45, 0x28, 0x31, 0xA8, 0x7D, 0x9D);

void uxenh264::decode_frame(void* priv, struct brh264_data* data)
{
    uxenh264* pMyHWMFT = (uxenh264*)priv;
    pMyHWMFT->DecodeFrame(data);
}

void uxenh264::update_result(void* priv, __int32 res)
{
    uxenh264* pMyHWMFT = (uxenh264*)priv;
    pMyHWMFT->UpdateResult(res);
}

void uxenh264::update_media_types(void* priv, struct brh264_data* mt)
{
    uxenh264* pMyHWMFT = (uxenh264*)priv;
    pMyHWMFT->UpdateMediaTypes(mt);
}

static uxendisp_ctrl_ctx_t *g_uxendisp_ctrl;
BOOL g_fullscreen;

typedef HRESULT (STDMETHODCALLTYPE *VideoPresentType)(
    IDXGISwapChain1 *This, UINT SyncInterval, UINT Flags);
typedef HRESULT (STDMETHODCALLTYPE *ProcessInputType)(
    IMFTransform *This, DWORD dwInputStreamID, IMFSample *pSample, DWORD dwFlags);
typedef HRESULT (STDMETHODCALLTYPE *ProcessOutputType)(
    IMFTransform *This, DWORD dwFlags, DWORD cOutputBufferCount, MFT_OUTPUT_DATA_BUFFER *pOutputSamples, DWORD *pdwStatus);

HRESULT STDMETHODCALLTYPE VideoPresent(
    IDXGISwapChain1 *This, UINT SyncInterval, UINT Flags)
{
    HRESULT result = S_OK;
    VideoPresentType proc = NULL;
    DXGI_SWAP_CHAIN_DESC desc = {};
    UINT32 width = 0;
    UINT32 height = 0;
    static int cnt = 3;

    This->GetDesc(&desc);
    width = GetSystemMetrics(SM_CXSCREEN);
    height = GetSystemMetrics(SM_CYSCREEN);

    if (((width - 5 > desc.BufferDesc.Width) && (height - 5 > desc.BufferDesc.Height)) || g_getReal) {
        g_fullscreen = FALSE;
        cnt = 3;
    }
    else {
        uxendisp_update_rect(g_uxendisp_ctrl, 0, 0, 16384, 16384);
        g_fullscreen = TRUE;
        cnt--;
    }

    proc = (VideoPresentType)g_originalPresent;
    result = proc(This, SyncInterval, Flags | ((g_fullscreen && (cnt < 0)) ? DXGI_PRESENT_TEST : 0));

    return result;
}

// 24
HRESULT STDMETHODCALLTYPE VideoProcessInput(
    IMFTransform *This, DWORD dwInputStreamID, IMFSample *pSample, DWORD dwFlags)
{
    HRESULT hr = S_OK;
    ProcessInputType proc_in = NULL;
    IMFAttributes *attr = NULL;
    LONGLONG time = 0;
    LONGLONG duration = 0;

    if (!g_fullscreen || g_getReal) {
        proc_in = (ProcessInputType)g_originalProcessInput;
        hr = proc_in(This, dwInputStreamID, pSample, dwFlags);
        return hr;
    }

    This->GetAttributes(&attr);
    if (attr && pSample) {
        pSample->GetSampleTime(&time);
        pSample->GetSampleDuration(&duration);
        attr->SetUINT64(BR_MF_SAMPLE_TIME, time);
        attr->SetUINT64(BR_MF_SAMPLE_DURATION, duration);
    }

    return hr;
}

// 25
HRESULT STDMETHODCALLTYPE VideoProcessOutput(
    IMFTransform *This, DWORD dwFlags, DWORD cOutputBufferCount, MFT_OUTPUT_DATA_BUFFER *pOutputSamples, DWORD *pdwStatus)
{
    HRESULT hr = MF_E_TRANSFORM_NEED_MORE_INPUT;
    ProcessOutputType proc_out = NULL;
    IMFAttributes *attr = NULL;
    UINT64 time = 0;
    UINT64 duration = 0;

    if (!g_fullscreen || g_getReal) {
        proc_out = (ProcessOutputType)g_originalProcessOutput;
        hr = proc_out(This, dwFlags, cOutputBufferCount, pOutputSamples, pdwStatus);
        return hr;
    }

    This->GetAttributes(&attr);
    if (attr && pOutputSamples && pOutputSamples->pSample) {
        attr->GetUINT64(BR_MF_SAMPLE_TIME, &time);
        attr->GetUINT64(BR_MF_SAMPLE_DURATION, &duration);
        pOutputSamples->pSample->SetSampleTime(time);
        pOutputSamples->pSample->SetSampleDuration(duration);
        if (time) {
            attr->SetUINT64(BR_MF_SAMPLE_TIME, 0);
            hr = S_OK;
        }
    }

    return hr;
}

// Initializer
HRESULT uxenh264::CreateInstance(IMFTransform** ppHWMFT)
{
    HRESULT hr          = S_OK;
    uxenh264* pMyHWMFT    = NULL;

    uxen_debug("Enter");

    if (ppHWMFT == NULL) {
        uxen_err("ppHWMFT is NULL");
        hr = E_POINTER;
        goto exit;
    }

    pMyHWMFT = new uxenh264();
    if(!pMyHWMFT) {
        uxen_err("new CHWMFT() has failed");
        hr = E_OUTOFMEMORY;
        goto exit;
    }

    hr = pMyHWMFT->InitializeTransform();
    if(FAILED(hr)) {
        uxen_err("InitializeTransform has failed");
        goto exit;
    }

    hr = pMyHWMFT->QueryInterface(IID_IMFTransform, (void**)ppHWMFT);
    if(FAILED(hr)) {
        uxen_err("pMyHWMFT->QueryInterface(IID_IMFTransform) has failed");
        goto exit;
    }

    SAFERELEASE(pMyHWMFT);

exit:
    uxen_debug("Exit 0x%x", hr);
    return hr;
}


uxenh264::uxenh264(void)
{
    // Do no insert anything before this call, this is the DLLs object count
    InterlockedIncrement(&m_ulNumObjects);

    uxen_debug("Enter");

    m_ulRef                 = 1;
    m_pInputMT              = NULL;
    m_pOutputMT             = NULL;
    m_pNewOutputMT          = NULL;
    m_dwStatus              = 0;
    m_dwNeedInputCount      = 0;
    m_dwHaveOutputCount     = 0;
    m_bFirstSample          = TRUE;
    m_LastResult            = 0;
    m_ResultEvent           = NULL;
    m_eDropMode             = MF_DROP_MODE_NONE;
    m_eQualityLevel         = MF_QUALITY_NORMAL;
    m_uXenH264Event = NULL;
    m_realDeal = NULL;
    m_ctx = NULL;
    m_new_frame = NULL;
    InitializeCriticalSection(&m_csLock);

    uxen_debug("Exit");
}

uxenh264::~uxenh264(void)
{
    uxen_debug("Enter");

    if (m_ctx) {
        brh264_destroy(m_ctx);
        m_ctx = NULL;
    }

    uxendisp_unmap_fb((uxendisp_ctrl_ctx_t*)g_uxendisp_ctrl, m_new_frame);
    //uxendisp_ctrl_release((uxendisp_ctrl_ctx_t*)g_uxendisp_ctrl);

    SAFERELEASE(m_pInputMT);
    SAFERELEASE(m_pOutputMT);
    SAFERELEASE(m_pNewOutputMT);
    DeleteCriticalSection(&m_csLock);

    InterlockedDecrement(&m_ulNumObjects);
    uxen_debug("Exit");
}

HRESULT uxenh264::InitializeTransform(void)
{
    HRESULT hr = S_OK;
    struct brh264_recv_callbacks cb = {};
    cb.brh264_recv_dec = uxenh264::decode_frame;
    cb.brh264_recv_res = uxenh264::update_result;
    cb.brh264_recv_mt = uxenh264::update_media_types;

    uxen_debug("Enter");

    m_ResultEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!m_ResultEvent) {
        hr = E_FAIL;
        uxen_err("CreateEvent failed");
        goto exit;
    }

    CreateNewOutputMT(UXENH264_OUTPUT_WIDTH, UXENH264_OUTPUT_HEIGHT);

    if (!g_uxendisp_ctrl) {
        g_uxendisp_ctrl = uxendisp_ctrl_init();
    }

    if (m_ulNumObjects <= UXENH264_DM_MAX_DEC) {
        m_ctx = brh264_create(this, &cb, NULL, true);
        if (!m_ctx) {
            uxen_err("brh264_create failed");
        }
    }

    m_new_frame = (PBYTE)uxendisp_map_fb((uxendisp_ctrl_ctx_t*)g_uxendisp_ctrl);
    if (!m_new_frame) {
        uxen_err("uxendisp_map_fb failed");
    }

    g_getReal = !m_ctx || !m_new_frame;
    if (g_getReal) {
        hr = CoCreateInstance(BR_CLSID_MSH264DecoderMFT, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&m_realDeal));
        uxen_debug("CoCreateInstance(CLSID_MSH264DecoderMFT) 0x%x", hr);
        goto exit;
    }

exit:
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::CheckInputType(
    IMFMediaType*   pMT)
{
    HRESULT hr      = S_OK;
    GUID    guid    = GUID_NULL;

    uxen_debug("Enter");

    hr = pMT->GetGUID(MF_MT_MAJOR_TYPE, &guid);
    if (FAILED(hr)) {
        uxen_err("pMT->GetGUID(MF_MT_MAJOR_TYPE)");
        goto exit;
    }

    if (guid != MFMediaType_Video) {
        uxen_err("guid != MFMediaType_Video");
        hr = MF_E_INVALIDMEDIATYPE;
        goto exit;
    }

    hr = pMT->GetGUID(MF_MT_SUBTYPE, &guid);
    if (FAILED(hr)) {
        uxen_err("pMT->GetGUID(MF_MT_SUBTYPE)");
        goto exit;
    }

    if (guid != MFVideoFormat_H264) {
        uxen_err("guid != MFVideoFormat_H264");
        hr = MF_E_INVALIDMEDIATYPE;
        goto exit;
    }

exit:
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

void uxenh264::CreateNewOutputMT(UINT width, UINT height)
{
    HRESULT hr = S_OK;

    uxen_debug("Enter");

    SAFERELEASE(m_pNewOutputMT);
    hr = MFCreateMediaType(&m_pNewOutputMT);
    if (FAILED(hr)) {
        uxen_err("MFCreateMediaType failed");
        goto exit;
    }

    m_pNewOutputMT->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    m_pNewOutputMT->SetGUID(MF_MT_SUBTYPE, UXENH264_OUTPUT_TYPE);
    m_pNewOutputMT->SetUINT32(MF_MT_FIXED_SIZE_SAMPLES, TRUE);
    m_pNewOutputMT->SetUINT32(MF_MT_ALL_SAMPLES_INDEPENDENT, TRUE);
    m_pNewOutputMT->SetUINT32(MF_MT_SAMPLE_SIZE, UXENH264_OUTPUT_BYTES_PER_PIXEL * width * height);
    MFSetAttributeSize(m_pNewOutputMT, MF_MT_FRAME_SIZE, width, height);
    MFSetAttributeRatio(m_pNewOutputMT, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);

exit:
    uxen_debug("Exit 0x%x", hr);
}

HRESULT uxenh264::CheckOutputType(
    IMFMediaType* pMT)
{
    HRESULT hr = S_OK;
    GUID guid = GUID_NULL;
    GUID OutputVideoType = GUID_NULL;

    uxen_debug("Enter");

    hr = pMT->GetGUID(MF_MT_MAJOR_TYPE, &guid);
    if (FAILED(hr)) {
        uxen_err("pMT->GetGUID(MF_MT_MAJOR_TYPE)");
        goto exit;
    }

    if (guid != MFMediaType_Video) {
        uxen_err("guid != MFMediaType_Video");
        hr = MF_E_INVALIDMEDIATYPE;
        goto exit;
    }

    hr = pMT->GetGUID(MF_MT_SUBTYPE, &guid);
    if (FAILED(hr)) {
        uxen_err("pMT->GetGUID(MF_MT_SUBTYPE)");
        goto exit;
    }

    if (m_pNewOutputMT) {
        m_pNewOutputMT->GetGUID(MF_MT_SUBTYPE, &OutputVideoType);
    }

    if (guid != OutputVideoType) {
        uxen_err("guid != OutputVideoType");
        hr = MF_E_INVALIDMEDIATYPE;
        goto exit;
    }

exit:
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::OnStartOfStream(void)
{
    HRESULT hr = S_OK;
    struct brh264_data mt = {};
    uxen_debug("Enter");

    {
        CAutoLock lock(&m_csLock);
        if (m_dwStatus & MYMFT_STATUS_STREAM_STARTED) {
            goto exit;
        }
        m_dwStatus |= MYMFT_STATUS_STREAM_STARTED;
    }

    brh264_serialize_attributes(m_pInputMT, &mt.params, &mt.params_size);
    brh264_send_mt(m_ctx, &mt);
    if (mt.params)
        free(mt.params);

exit:
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::OnEndOfStream(void)
{
    HRESULT hr = S_OK;
    uxen_debug("Enter");

    CAutoLock lock(&m_csLock);
    m_dwStatus &= (~MYMFT_STATUS_STREAM_STARTED);
    m_dwNeedInputCount = 0;

    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::OnFlush(void)
{
    HRESULT hr = S_OK;
    uxen_debug("Enter");

    m_dwHaveOutputCount = 0;
    while (!m_pOutputSampleQueue.empty()) {
        IMFSample* sample = m_pOutputSampleQueue.front();
        m_pOutputSampleQueue.pop();
        SAFERELEASE(sample);
    }

    m_bFirstSample = TRUE;
    brh264_send_enc(m_ctx, NULL);

    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::GetResult(void)
{
    DWORD err = WaitForSingleObject(m_ResultEvent, UXENH264_DM_TIMEOUT_MS);
    return ((m_LastResult == 0) && (err == WAIT_OBJECT_0)) ? S_OK : E_FAIL;
}

HRESULT uxenh264::DecodeFrame(struct brh264_data* data)
{
    HRESULT hr = S_OK;
    IMFSample* pOutputSample = NULL;

    pOutputSample = create_media_sample(1);
    if(!pOutputSample) {
        uxen_err("AddBuffer failed", hr);
        goto exit;
    }

    brh264_deserialize_attributes(pOutputSample, data->params, data->params_size);

    pOutputSample->AddRef();
    m_pOutputSampleQueue.push(pOutputSample);

    {
        CAutoLock lock(&m_csLock);
        m_dwHaveOutputCount++;
    }

exit:
    SAFERELEASE(pOutputSample);
    return hr;
}

void uxenh264::UpdateResult(__int32 res)
{
    m_LastResult = res;
    SetEvent(m_ResultEvent);
}

HRESULT uxenh264::UpdateMediaTypes(struct brh264_data* mt)
{
    HRESULT hr = S_OK;
    CAutoLock lock(&m_csLock);
    uxen_debug("Enter");
    CreateNewOutputMT(UXENH264_OUTPUT_WIDTH, UXENH264_OUTPUT_HEIGHT);
    brh264_deserialize_attributes(m_pNewOutputMT, mt->params, mt->params_size);
    m_bFirstSample = TRUE;
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

BOOL uxenh264::IsMFTReady(void)
{
    BOOL bReady = FALSE;
    CAutoLock lock(&m_csLock);

    m_dwStatus &= (~MYMFT_STATUS_INPUT_ACCEPT_DATA);

    if (m_pInputMT == NULL)
        goto exit;

    if (m_pOutputMT == NULL)
        goto exit;

    m_dwStatus |= MYMFT_STATUS_INPUT_ACCEPT_DATA;
    bReady = TRUE;

exit:
    return bReady;
}

HRESULT uxenh264::SetDropMode(MF_QUALITY_DROP_MODE eDropMode)
{
    m_eDropMode = eDropMode;
    uxen_debug("Quality eDropMode(%d)", (int)eDropMode);
    return S_OK;
}

HRESULT uxenh264::SetQualityLevel(MF_QUALITY_LEVEL eQualityLevel)
{
    m_eQualityLevel = eQualityLevel;
    uxen_debug("Quality eQualityLevel(%d)", (int)eQualityLevel);
    return S_OK;
}

HRESULT uxenh264::GetDropMode(MF_QUALITY_DROP_MODE * peDropMode)
{
    *peDropMode = m_eDropMode;
    uxen_debug("Quality peDropMode(%d)", (int)m_eDropMode);
    return S_OK;
}

HRESULT uxenh264::GetQualityLevel(MF_QUALITY_LEVEL * peQualityLevel)
{
    *peQualityLevel = m_eQualityLevel;
    uxen_debug("Quality peQualityLevel(%d)", (int)m_eQualityLevel);
    return S_OK;
}

HRESULT uxenh264::DropTime(LONGLONG)
{
    uxen_debug("Quality hnsAmountToDrop");
    return S_OK;
}

HRESULT uxenh264::NotifyQualityEvent(IMFMediaEvent *pEvent, DWORD *pdwFlags)
{
    GUID guid = {};
    PROPVARIANT prop = {};

    UNREFERENCED_PARAMETER(pdwFlags);

    PropVariantInit(&prop);
    pEvent->GetValue(&prop);
    pEvent->GetExtendedType(&guid);
    if (guid == MF_QUALITY_NOTIFY_SAMPLE_LAG) {
        uxen_debug("Quality MF_QUALITY_NOTIFY_SAMPLE_LAG (%lld)", prop.hVal.QuadPart);
    }
    else if (guid == MF_QUALITY_NOTIFY_PROCESSING_LATENCY) {
        uxen_debug("Quality MF_QUALITY_NOTIFY_PROCESSING_LATENCY (%lld)", prop.hVal.QuadPart);
    }
    PropVariantClear(&prop);
    return S_OK;
}
