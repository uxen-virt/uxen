
/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    basetopo.h

Abstract:

    Declaration of topology miniport.

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

#ifndef _UXENAUDIO_BASETOPO_H_
#define _UXENAUDIO_BASETOPO_H_

//=============================================================================
// Classes
//=============================================================================

///////////////////////////////////////////////////////////////////////////////
// CMiniportTopologyUXenAudio
//

class CMiniportTopologyUXenAudio
{
  protected:
    PADAPTERCOMMON              m_AdapterCommon;    // Adapter common object.
    PPCFILTER_DESCRIPTOR        m_FilterDescriptor; // Filter descriptor.

  public:
    CMiniportTopologyUXenAudio();
    ~CMiniportTopologyUXenAudio();

    NTSTATUS                    GetDescription
    (   
        OUT PPCFILTER_DESCRIPTOR *  Description
    );

    NTSTATUS                    DataRangeIntersection
    (   
        IN  ULONG               PinId,
        IN  PKSDATARANGE        ClientDataRange,
        IN  PKSDATARANGE        MyDataRange,
        IN  ULONG               OutputBufferLength,
        OUT PVOID               ResultantFormat OPTIONAL,
        OUT PULONG              ResultantFormatLength
    );

    NTSTATUS                    Init
    ( 
        IN  PUNKNOWN            UnknownAdapter,
        IN  PPORTTOPOLOGY       Port_ 
    );

    // PropertyHandlers.
    NTSTATUS                    PropertyHandlerBasicSupportVolume
    (
        IN  PPCPROPERTY_REQUEST PropertyRequest
    );
    
    NTSTATUS                    PropertyHandlerCpuResources
    ( 
        IN  PPCPROPERTY_REQUEST PropertyRequest 
    );

    NTSTATUS                    PropertyHandlerGeneric
    (
        IN  PPCPROPERTY_REQUEST PropertyRequest
    );

    NTSTATUS                    PropertyHandlerMute
    (
        IN  PPCPROPERTY_REQUEST PropertyRequest
    );

    NTSTATUS                    PropertyHandlerMuxSource
    (
        IN  PPCPROPERTY_REQUEST PropertyRequest
    );

    NTSTATUS                    PropertyHandlerVolume
    (
        IN  PPCPROPERTY_REQUEST PropertyRequest
    );

    NTSTATUS                    PropertyHandlerDevSpecific
    (
        IN  PPCPROPERTY_REQUEST PropertyRequest
    );
};

#endif

