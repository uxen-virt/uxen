/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxenh264.h"

ULONG uxenh264::AddRef(void)
{
    return InterlockedIncrement(&m_ulRef);
}

HRESULT uxenh264::QueryInterface(
    REFIID riid,
    void** ppvObject)
{
    if (ppvObject == NULL) {
        return E_POINTER;
    }

    if (riid == IID_IMFTransform) {
        *ppvObject = (IMFTransform*)this;
    }
    else if (riid == IID_IMFAttributes) {
        *ppvObject = (IMFAttributes*)this;
    }
    else if (riid == IID_IMFQualityAdvise) {
        *ppvObject = (IMFQualityAdvise*)this;
    }
    else if (riid == IID_IUnknown) {
        *ppvObject = this;
    }
    else {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }

    AddRef();
    return S_OK;
}

ULONG uxenh264::Release(void)
{
    ULONG ulRef = 0;
    
    if (m_ulRef > 0) {
        ulRef = InterlockedDecrement(&m_ulRef);
    }

    if (ulRef == 0) {
        delete this;
    }

    return ulRef;
}