/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxenh264.h"
#include "CAutoLock.h"
#include <mferror.h>
#include <mfapi.h>
#pragma warning(disable: 4505)
#include <uxenh264utils.h>

// Helper Macros
#define SAFERELEASE(x) \
    if((x) != NULL) \
    { \
        (x)->Release(); \
        (x) = NULL; \
    } \

HRESULT uxenh264::GetInputStatus(
    DWORD a, DWORD* pdwFlags)
{
    HRESULT hr = S_OK;
    CAutoLock lock(&m_csLock);

    if (m_realDeal) {
        hr = m_realDeal->GetInputStatus(a, pdwFlags);
        goto exit;
    }

    if (pdwFlags == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    *pdwFlags = 0;
    if ((m_dwStatus & MYMFT_STATUS_INPUT_ACCEPT_DATA) != 0) {
        *pdwFlags = MFT_INPUT_STATUS_ACCEPT_DATA;
    }

exit:
    return hr;
}

HRESULT uxenh264::GetInputStreamInfo(
    DWORD a, MFT_INPUT_STREAM_INFO* pStreamInfo)
{
    HRESULT hr = S_OK;

    if (m_realDeal) {
        hr = m_realDeal->GetInputStreamInfo(a, pStreamInfo);
        goto exit;
    }

    if (pStreamInfo == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    pStreamInfo->hnsMaxLatency  = 0;
    pStreamInfo->dwFlags        = MFT_INPUT_STREAM_SINGLE_SAMPLE_PER_BUFFER | MFT_INPUT_STREAM_DOES_NOT_ADDREF;
    pStreamInfo->cbSize         = 0; // No minimum size is required
    pStreamInfo->cbMaxLookahead = 0; // No lookahead is performed
    pStreamInfo->cbAlignment    = 0; // No memory allignment is required

exit:
    return hr;
}

HRESULT uxenh264::GetOutputStreamInfo(
    DWORD a, MFT_OUTPUT_STREAM_INFO* pStreamInfo)
{
    HRESULT hr = S_OK;
    UINT32 width = 0;
    UINT32 height = 0;
    CAutoLock lock(&m_csLock);

    if (m_realDeal) {
        hr = m_realDeal->GetOutputStreamInfo(a, pStreamInfo);
        goto exit;
    }

    if (pStreamInfo == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    pStreamInfo->dwFlags = MFT_OUTPUT_STREAM_WHOLE_SAMPLES            | 
                           MFT_OUTPUT_STREAM_SINGLE_SAMPLE_PER_BUFFER |
                           MFT_OUTPUT_STREAM_FIXED_SAMPLE_SIZE;

    MFGetAttributeSize(m_pOutputMT, MF_MT_FRAME_SIZE, &width, &height);

    pStreamInfo->cbSize = width * height * 4;
    pStreamInfo->cbAlignment = 0;

exit:
    return hr;
}

HRESULT uxenh264::ProcessMessage(
    MFT_MESSAGE_TYPE eMessage, ULONG_PTR arg)
{
    HRESULT hr = S_OK;
    uxen_debug("Enter");

    if (m_realDeal) {
        hr = m_realDeal->ProcessMessage(eMessage, arg);
        goto exit;
    }

    if((m_pInputMT == NULL) || (m_pOutputMT == NULL)) {
        hr = MF_E_TRANSFORM_TYPE_NOT_SET;
        goto exit;
    }

    switch(eMessage) {
    case MFT_MESSAGE_NOTIFY_BEGIN_STREAMING:
    case MFT_MESSAGE_NOTIFY_START_OF_STREAM:
        hr = OnStartOfStream();
        break;
    case MFT_MESSAGE_NOTIFY_END_STREAMING:
    case MFT_MESSAGE_NOTIFY_END_OF_STREAM:
        hr = OnEndOfStream();
        break;
    case MFT_MESSAGE_COMMAND_FLUSH:
        hr = OnFlush();
        break;
    default:
        break;
    };

exit:
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::ProcessInput(
    DWORD a, IMFSample* pSample, DWORD c)
{
    HRESULT hr = S_OK;
    IMFMediaBuffer *srcBuf = NULL;
    DWORD srcBufLength = 0;
    byte *srcByteBuffer = NULL;
    DWORD srcBuffCurrLen = 0;
    DWORD srcBuffMaxLen = 0;
    brh264_data data = { 0 };
    HRESULT err;
    LONGLONG duration = 0;
    LONGLONG time = 0;
    UINT64 flags = 0;

    if (m_realDeal) {
        hr = m_realDeal->ProcessInput(a, pSample, c);
        goto exit;
    }

    if (pSample == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    pSample->ConvertToContiguousBuffer(&srcBuf);
    srcBuf->GetCurrentLength(&srcBufLength);
    srcBuf->Lock(&srcByteBuffer, &srcBuffMaxLen, &srcBuffCurrLen);

    flags |= (m_eDropMode | m_eQualityLevel) ? UXENH264_FLAG_DROP_QUALITY : 0;
    flags |= (g_fullscreen) ? UXENH264_FLAG_FULLSCREEN : 0;
    pSample->SetUINT64(MF_QUALITY_NOTIFY_SAMPLE_LAG, flags);

    data.data = srcByteBuffer;
    data.data_size = srcBuffCurrLen;

    err = pSample->GetSampleDuration(&duration);
    if (FAILED(err))
        duration = 0;
    pSample->SetUINT64(BR_MF_SAMPLE_DURATION, duration);

    err = pSample->GetSampleTime(&time);
    if (FAILED(err))
        time = 0;
    pSample->SetUINT64(BR_MF_SAMPLE_TIME, time);

    brh264_serialize_attributes(pSample, &data.params, &data.params_size);

    brh264_send_enc(m_ctx, &data);
    if (data.params)
        free(data.params);

    srcBuf->Unlock();
    SAFERELEASE(srcBuf);

    if (GetResult() != S_OK) {
        hr = MF_E_NOTACCEPTING;
    }

exit:
    return hr;
}

HRESULT uxenh264::ProcessOutput(
    DWORD a,
    DWORD dwOutputBufferCount,
    MFT_OUTPUT_DATA_BUFFER* pOutputSamples,
    DWORD* d)
{
    HRESULT     hr      = S_OK;
    IMFSample*  pSample = NULL;

    if (m_realDeal) {
        hr = m_realDeal->ProcessOutput(a, dwOutputBufferCount, pOutputSamples, d);
        goto exit;
    }

    {
        CAutoLock lock(&m_csLock);

        if (m_dwHaveOutputCount == 0) {
            hr = MF_E_TRANSFORM_NEED_MORE_INPUT;
            goto exit;
        }
        else {
            m_dwHaveOutputCount--;
        }
    }

    if (dwOutputBufferCount < 1) {
        hr = E_INVALIDARG;
        goto exit;
    }

    if (IsMFTReady() == FALSE) {
        hr = MF_E_TRANSFORM_TYPE_NOT_SET;
        goto exit;
    }

    if (m_bFirstSample) {
        m_bFirstSample = FALSE;
        pOutputSamples->dwStatus |= MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE;
        hr = MF_E_TRANSFORM_STREAM_CHANGE;
        goto exit;
    }

    if (!pOutputSamples[0].pSample) {
        hr = E_INVALIDARG;
        goto exit;
    }

    if (!m_pOutputSampleQueue.empty()) {
        pSample = m_pOutputSampleQueue.front();
        m_pOutputSampleQueue.pop();
    }

    if (!pSample) {
        hr = MF_E_TRANSFORM_NEED_MORE_INPUT;
        goto exit;
    }

    hr = pOutputSamples[0].pSample->SetSampleTime(MFGetAttributeUINT64(pSample, BR_MF_SAMPLE_TIME, 0));
    if (FAILED(hr)) {
        uxen_err("SetSampleTime failed", hr);
        goto exit;
    }

    hr = pOutputSamples[0].pSample->SetSampleDuration(MFGetAttributeUINT64(pSample, BR_MF_SAMPLE_DURATION, 0));
    if (FAILED(hr)) {
        uxen_err("SetSampleDuration failed", hr);
        goto exit;
    }

    if (!g_fullscreen) {
        UINT32 w = 0, h = 0;
        IMFMediaBuffer* pBuffer = NULL;
        pOutputSamples[0].dwStreamID = 0;
        hr = pOutputSamples[0].pSample->GetBufferByIndex(0, &pBuffer);

        MFGetAttribute2UINT32asUINT64(m_pNewOutputMT, MF_MT_FRAME_SIZE, &w, &h);

        INT32 pri_width = GetSystemMetrics(SM_CXSCREEN);
        INT32 pri_height = GetSystemMetrics(SM_CYSCREEN);

        PBYTE mem = NULL;
        DWORD cur_len = 0;
        DWORD max_len = 0;
        pBuffer->Lock(&mem, &max_len, &cur_len);
        CopyMemory(mem, m_new_frame + (pri_width * pri_height * 4), w * h * 4);
        pBuffer->Unlock();
        pBuffer->SetCurrentLength(w * h * 4);
        SAFERELEASE(pBuffer);
    }

exit:
    SAFERELEASE(pSample);
    return hr;
}

HRESULT uxenh264::GetInputAvailableType(
    DWORD a, DWORD dwTypeIndex, IMFMediaType** ppType)
{
    HRESULT hr = S_OK;
    IMFMediaType* pMT = NULL;

    uxen_debug("Enter");

    if (m_realDeal) {
        hr = m_realDeal->GetInputAvailableType(a, dwTypeIndex, ppType);
        goto exit;
    }

    if (ppType == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    if (dwTypeIndex > 0) {
        hr = MF_E_NO_MORE_TYPES;
        goto exit;
    }

    hr = MFCreateMediaType(&pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    hr = pMT->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    if (FAILED(hr)) {
        goto exit;
    }

    hr = pMT->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
    if (FAILED(hr)) {
        goto exit;
    }

    (*ppType) = pMT;
    (*ppType)->AddRef();

exit:
    SAFERELEASE(pMT);
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::GetInputCurrentType(
    DWORD a, IMFMediaType** ppType)
{
    HRESULT hr = S_OK;
    IMFMediaType* pMT = NULL;
    CAutoLock lock(&m_csLock);

    uxen_debug("Enter");

    if (m_realDeal) {
        hr = m_realDeal->GetInputCurrentType(a, ppType);
        goto exit;
    }

    if (ppType == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    if (m_pInputMT == NULL) {
        hr = MF_E_TRANSFORM_TYPE_NOT_SET;
        goto exit;
    }

    hr = MFCreateMediaType(&pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    hr = m_pInputMT->CopyAllItems(pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    (*ppType) = pMT;
    (*ppType)->AddRef();

exit:
    SAFERELEASE(pMT);
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::SetInputType(
    DWORD a, IMFMediaType* pType, DWORD c)
{
    HRESULT hr = S_OK;
    IMFMediaType* pMT = NULL;

    uxen_debug("Enter");

    if (m_realDeal) {
        hr = m_realDeal->SetInputType(a, pType, c);
        goto exit;
    }

    if (pType == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    hr = CheckInputType(pType);
    if (FAILED(hr)) {
        goto exit;
    }

    hr = MFCreateMediaType(&pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    hr = pType->CopyAllItems(pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    {
        CAutoLock lock(&m_csLock);
        SAFERELEASE(m_pInputMT);
        m_pInputMT = pMT;
        m_pInputMT->AddRef();
    }
    IsMFTReady();

exit:
    SAFERELEASE(pMT);
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::GetOutputAvailableType(
    DWORD a, DWORD dwTypeIndex, IMFMediaType** ppType)
{
    HRESULT hr = S_OK;
    IMFMediaType* pMT = NULL;
    uxen_debug("Enter");

    if (m_realDeal) {
        hr = m_realDeal->GetOutputAvailableType(a, dwTypeIndex, ppType);
        goto exit;
    }

    if (ppType == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    if (dwTypeIndex > 0) {
        hr = MF_E_NO_MORE_TYPES;
        goto exit;
    }

    hr = MFCreateMediaType(&pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    {
        CAutoLock lock(&m_csLock);
        if (m_pNewOutputMT) {
            hr = m_pNewOutputMT->CopyAllItems(pMT);
            (*ppType) = pMT;
            (*ppType)->AddRef();
        }
        else {
            hr = MF_E_TRANSFORM_TYPE_NOT_SET;
        }
    }

exit:
    SAFERELEASE(pMT);
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::GetOutputCurrentType(
    DWORD a, IMFMediaType** ppType)
{
    HRESULT hr = S_OK;
    IMFMediaType* pMT = NULL;
    CAutoLock lock(&m_csLock);
    uxen_debug("Enter");

    if (m_realDeal) {
        hr = m_realDeal->GetOutputCurrentType(a, ppType);
        goto exit;
    }

    if (ppType == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    if (m_pOutputMT == NULL) {
        hr = MF_E_TRANSFORM_TYPE_NOT_SET;
        goto exit;
    }

    hr = MFCreateMediaType(&pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    hr = m_pOutputMT->CopyAllItems(pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    (*ppType) = pMT;
    (*ppType)->AddRef();

exit:
    SAFERELEASE(pMT);
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::SetOutputType(
    DWORD a, IMFMediaType* pType, DWORD c)
{
    HRESULT hr = S_OK;
    IMFMediaType* pMT = NULL;
    uxen_debug("Enter");

    if (m_realDeal) {
        hr = m_realDeal->SetOutputType(a, pType, c);
        goto exit;
    }

    if (pType == NULL) {
        hr = E_POINTER;
        goto exit;
    }

    hr = CheckOutputType(pType);
    if (FAILED(hr)) {
        goto exit;
    }

    hr = MFCreateMediaType(&pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    hr = pType->CopyAllItems(pMT);
    if (FAILED(hr)) {
        goto exit;
    }

    {
        CAutoLock lock(&m_csLock);
        SAFERELEASE(m_pOutputMT);
        m_pOutputMT = pMT;
        m_pOutputMT->AddRef();
    }

    IsMFTReady();

exit:
    SAFERELEASE(pMT);
    uxen_debug("Exit 0x%x", hr);
    return hr;
}

HRESULT uxenh264::GetAttributes(
    IMFAttributes** ppAttributes)
{
    HRESULT hr = E_NOTIMPL;

    if (m_realDeal) {
        hr = m_realDeal->GetAttributes(ppAttributes);
    }

    return hr;
}

HRESULT uxenh264::GetStreamLimits(
    DWORD* pdwInputMinimum, DWORD* pdwInputMaximum, DWORD* pdwOutputMinimum, DWORD* pdwOutputMaximum)
{
    if ((pdwInputMinimum == NULL) || (pdwInputMaximum == NULL) ||
        (pdwOutputMinimum == NULL) || (pdwOutputMaximum == NULL)) {
        return E_POINTER;
    }
    *pdwInputMinimum  = 1;
    *pdwInputMaximum  = 1;
    *pdwOutputMinimum = 1;
    *pdwOutputMaximum = 1;
    return S_OK;
}

HRESULT uxenh264::GetStreamCount(
    DWORD* pdwInputStreams, DWORD* pdwOutputStreams)
{
    if ((pdwInputStreams == NULL) || (pdwOutputStreams == NULL)) {
        return E_POINTER;
    }
    *pdwInputStreams = 1;
    *pdwOutputStreams = 1;
    return S_OK;
}

HRESULT uxenh264::GetStreamIDs(DWORD, DWORD*, DWORD, DWORD*)
{
    return E_NOTIMPL;
}

HRESULT uxenh264::ProcessEvent(DWORD, IMFMediaEvent*)
{
    return E_NOTIMPL;
}

HRESULT uxenh264::SetOutputBounds(LONGLONG, LONGLONG)
{
    return E_NOTIMPL;
}

HRESULT uxenh264::GetOutputStreamAttributes(DWORD, IMFAttributes**)
{
    return E_NOTIMPL;
}

HRESULT uxenh264::GetInputStreamAttributes(DWORD, IMFAttributes**)
{
    return E_NOTIMPL;
}

HRESULT uxenh264::AddInputStreams(DWORD, DWORD*)
{
    return E_NOTIMPL;
}

HRESULT uxenh264::DeleteInputStream(DWORD)
{
    return E_NOTIMPL;
}

HRESULT uxenh264::GetOutputStatus(DWORD*)
{
    return E_NOTIMPL;
}
