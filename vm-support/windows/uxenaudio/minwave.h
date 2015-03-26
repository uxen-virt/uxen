/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    minwave.h

Abstract:

    Definition of wavecyclic miniport class.

--*/
/*
 * uXen changes:
 *
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _UXENAUDIO_MINWAVE_H_
#define _UXENAUDIO_MINWAVE_H_

#include "basewave.h"

//=============================================================================
// Referenced Forward
//=============================================================================
class CMiniportWaveCyclicStream;
typedef CMiniportWaveCyclicStream *PCMiniportWaveCyclicStream;

//=============================================================================
// Classes
//=============================================================================
///////////////////////////////////////////////////////////////////////////////
// CMiniportWaveCyclic 
//   

class CMiniportWaveCyclic : 
    public CMiniportWaveCyclicUXenAudio,
    public IMiniportWaveCyclic,
    public CUnknown
{
private:
    BOOL                        m_fCaptureAllocated;
    BOOL                        m_fRenderAllocated;

public:
    DECLARE_STD_UNKNOWN();
    DEFINE_STD_CONSTRUCTOR(CMiniportWaveCyclic);
    ~CMiniportWaveCyclic();

    IMP_IMiniportWaveCyclic;

    NTSTATUS                    PropertyHandlerComponentId
    (
        IN PPCPROPERTY_REQUEST  PropertyRequest
    );

    NTSTATUS                    PropertyHandlerProposedFormat
    (
        IN PPCPROPERTY_REQUEST  PropertyRequest
    );

    // Friends
    friend class                CMiniportWaveCyclicStream;
    friend class                CMiniportTopologySimple;
};
typedef CMiniportWaveCyclic *PCMiniportWaveCyclic;

///////////////////////////////////////////////////////////////////////////////
// CMiniportWaveCyclicStream 
//   

class CMiniportWaveCyclicStream : 
    public CMiniportWaveCyclicStreamUXenAudio,
    public CUnknown
{
protected:
    PCMiniportWaveCyclic        m_pMiniportLocal;  

public:
    DECLARE_STD_UNKNOWN();
    DEFINE_STD_CONSTRUCTOR(CMiniportWaveCyclicStream);
    ~CMiniportWaveCyclicStream();

    NTSTATUS                    Init
    ( 
        IN  PCMiniportWaveCyclic Miniport,
        IN  ULONG               Channel,
        IN  BOOLEAN             Capture,
        IN  PKSDATAFORMAT       DataFormat
    );

    // Friends
    friend class                CMiniportWaveCyclic;
};
typedef CMiniportWaveCyclicStream *PCMiniportWaveCyclicStream;

#endif

