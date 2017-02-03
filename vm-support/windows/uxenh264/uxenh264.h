/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#include <windows.h>
#include <Mfidl.h>
#include "debug-user.h"
#include "uxenh264lib.h"
#include <queue>
#include "uxenh264-common.h"
#include <dxgi1_2.h>

#define SAFERELEASE(x) \
    if((x) != NULL) \
    { \
        (x)->Release(); \
        (x) = NULL; \
    } \

extern UINT_PTR  g_originalProcessOutput;
extern UINT_PTR  g_originalProcessInput;
extern UINT_PTR  g_originalPresent;
extern BOOL g_fullscreen;
extern bool g_getReal;

HRESULT STDMETHODCALLTYPE VideoPresent(
    IDXGISwapChain1 *This, UINT SyncInterval, UINT Flags);

HRESULT STDMETHODCALLTYPE VideoProcessInput(
    IMFTransform *This, DWORD dwInputStreamID, IMFSample *pSample, DWORD dwFlags);

HRESULT STDMETHODCALLTYPE VideoProcessOutput(
    IMFTransform *This, DWORD dwFlags, DWORD cOutputBufferCount, MFT_OUTPUT_DATA_BUFFER *pOutputSamples, DWORD *pdwStatus);

enum eMFTStatus
{
    MYMFT_STATUS_INPUT_ACCEPT_DATA      = 0x00000001,
    MYMFT_STATUS_STREAM_STARTED         = 0x00000004,
};

class uxenh264: 
    public IMFTransform,
    public IMFQualityAdvise2
{
public:
    static  volatile    ULONG   m_ulNumObjects;                 // Total object count

    // Initializer
    static  HRESULT     CreateInstance(IMFTransform** ppHWMFT);

    static void decode_frame(void* priv, struct brh264_data* data);
    static void update_result(void* priv, __int32 res);
    static void update_media_types(void* priv, struct brh264_data* mt);

#pragma region IUnknown
    // IUnknown Implementations
    ULONG   __stdcall   AddRef(void);
    HRESULT __stdcall   QueryInterface(
                                REFIID  riid,
                                void**  ppvObject
                                );
    ULONG   __stdcall   Release(void);
#pragma endregion IUnknown

#pragma region IMFTransform
    // IMFTransform Implementations
    HRESULT __stdcall   AddInputStreams(
                                  DWORD   dwStreams,
                                  DWORD*  pdwStreamIDs
                                  );
    HRESULT __stdcall   DeleteInputStream(
                                  DWORD   dwStreamID
                                  );
    HRESULT __stdcall   GetAttributes(
                                  IMFAttributes** ppAttributes
                                  );
    HRESULT __stdcall   GetInputAvailableType(
                                  DWORD           dwInputStreamID,
                                  DWORD           dwTypeIndex,
                                  IMFMediaType**  ppType
                                  );
    HRESULT __stdcall   GetInputCurrentType(
                                  DWORD           dwInputStreamID,
                                  IMFMediaType**  ppType
                                  );
    HRESULT __stdcall   GetInputStatus(
                                  DWORD   dwInputStreamID,
                                  DWORD*  pdwFlags
                                  );
    HRESULT __stdcall   GetInputStreamAttributes(
                                  DWORD           dwInputStreamID,
                                  IMFAttributes** ppAttributes
                                  );
    HRESULT __stdcall   GetInputStreamInfo(
                                  DWORD                   dwInputStreamID,
                                  MFT_INPUT_STREAM_INFO*  pStreamInfo
                                  );
    HRESULT __stdcall   GetOutputAvailableType(
                                  DWORD           dwOutputStreamID,
                                  DWORD           dwTypeIndex,
                                  IMFMediaType**  ppType
                                  );
    HRESULT __stdcall   GetOutputCurrentType(
                                  DWORD           dwOutputStreamID,
                                  IMFMediaType**  ppType
                                  );
    HRESULT __stdcall   GetOutputStatus(
                                  DWORD*  pdwFlags
                                  );
    HRESULT __stdcall   GetOutputStreamAttributes(
                                  DWORD           dwOutputStreamID,
                                  IMFAttributes** ppAttributes
                                  );
    HRESULT __stdcall   GetOutputStreamInfo(
                                  DWORD                   dwOutputStreamID,
                                  MFT_OUTPUT_STREAM_INFO* pStreamInfo
                                  );
    HRESULT __stdcall   GetStreamCount(
                                  DWORD*  pdwInputStreams,
                                  DWORD*  pdwOutputStreams
                                  );
    HRESULT __stdcall   GetStreamIDs(
                                  DWORD   dwInputIDArraySize,
                                  DWORD*  pdwInputIDs,
                                  DWORD   dwOutputIDArraySize,
                                  DWORD*  pdwOutputIDs
                                  );
    HRESULT __stdcall   GetStreamLimits(
                                  DWORD*  pdwInputMinimum,
                                  DWORD*  pdwInputMaximum,
                                  DWORD*  pdwOutputMinimum,
                                  DWORD*  pdwOutputMaximum
                                  );
    HRESULT __stdcall   ProcessEvent(
                                  DWORD           dwInputStreamID,
                                  IMFMediaEvent*  pEvent
                                  );
    HRESULT __stdcall   ProcessInput(
                                  DWORD       dwInputStreamID,
                                  IMFSample*  pSample,
                                  DWORD       dwFlags
                                  );
    HRESULT __stdcall   ProcessMessage(
                                  MFT_MESSAGE_TYPE eMessage,
                                  ULONG_PTR ulParam
                                  );
    HRESULT __stdcall   ProcessOutput(
                                  DWORD                   dwFlags,
                                  DWORD                   dwOutputBufferCount,
                                  MFT_OUTPUT_DATA_BUFFER* pOutputSamples,
                                  DWORD*                  pdwStatus
                                  );
    HRESULT __stdcall   SetInputType(
                                  DWORD           dwInputStreamID,
                                  IMFMediaType*   pType,
                                  DWORD           dwFlags
                                  );
    HRESULT __stdcall   SetOutputBounds(
                                  LONGLONG hnsLowerBound,
                                  LONGLONG hnsUpperBound
                                  );
    HRESULT __stdcall   SetOutputType(
                                DWORD           dwOutputStreamID,
                                IMFMediaType*   pType,
                                DWORD           dwFlags
                                );
#pragma endregion IMFTransform

    // Inherited via IMFQualityAdvise2
    virtual HRESULT __stdcall SetDropMode(MF_QUALITY_DROP_MODE eDropMode) override;
    virtual HRESULT __stdcall SetQualityLevel(MF_QUALITY_LEVEL eQualityLevel) override;
    virtual HRESULT __stdcall GetDropMode(MF_QUALITY_DROP_MODE * peDropMode) override;
    virtual HRESULT __stdcall GetQualityLevel(MF_QUALITY_LEVEL * peQualityLevel) override;
    virtual HRESULT __stdcall DropTime(LONGLONG hnsAmountToDrop) override;
    virtual HRESULT __stdcall NotifyQualityEvent(IMFMediaEvent * pEvent, DWORD * pdwFlags) override;

    HRESULT __stdcall   DecodeFrame(struct brh264_data* data);
    HRESULT __stdcall   UpdateMediaTypes(struct brh264_data* mt);
    void                CreateNewOutputMT(UINT width, UINT height);

protected:
                        uxenh264(void);
                        ~uxenh264(void);

    HRESULT             InitializeTransform(void);
    HRESULT             CheckInputType(
                                IMFMediaType*   pMT
                                );
    HRESULT             CheckOutputType(
                                IMFMediaType*   pMT
                                );

    /******* MFT Media Event Handlers**********/
    HRESULT             OnStartOfStream(void);
    HRESULT             OnEndOfStream(void);
    HRESULT             OnFlush(void);

    /***********End Event Handlers************/
    HRESULT             GetResult(void);
    void                UpdateResult(__int32 res);
    BOOL                IsMFTReady(void);

    // Member variables
    volatile    ULONG               m_ulRef;
                HANDLE              m_ResultEvent;
                HANDLE              m_uXenH264Event;
                __int32             m_LastResult;
                IMFMediaType*       m_pInputMT;
                IMFMediaType*       m_pOutputMT;
                IMFMediaType*       m_pNewOutputMT;
                DWORD               m_dwStatus;
                DWORD               m_dwNeedInputCount;
                DWORD               m_dwHaveOutputCount;
                BOOL                m_bFirstSample;
                std::queue<IMFSample*> m_pOutputSampleQueue;
                brh264_ctx          m_ctx;
                CRITICAL_SECTION    m_csLock;
                MF_QUALITY_DROP_MODE m_eDropMode;
                MF_QUALITY_LEVEL     m_eQualityLevel;
                IMFTransform        *m_realDeal;
                PBYTE                m_new_frame;
};
