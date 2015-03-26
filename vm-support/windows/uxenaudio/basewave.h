/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    basewave.h

Abstract:

    Definition of base wavecyclic and wavecyclic stream class.

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

#ifndef _UXENAUDIO_BASEWAVE_H_
#define _UXENAUDIO_BASEWAVE_H_

//=============================================================================
// Referenced Forward
//=============================================================================
KDEFERRED_ROUTINE TimerNotify;

class CMiniportWaveCyclicStreamUXenAudio;
typedef CMiniportWaveCyclicStreamUXenAudio *PCMiniportWaveCyclicStreamUXenAudio;

//=============================================================================
// Classes
//=============================================================================

///////////////////////////////////////////////////////////////////////////////
// CMiniportWaveCyclicUXenAudio
//   This is the common base class for all UXenAudio samples. It implements basic
//   functionality.

class CMiniportWaveCyclicUXenAudio
{
protected:
    PADAPTERCOMMON              m_AdapterCommon;    // Adapter common object
    PPORTWAVECYCLIC             m_Port;             // Callback interface
    PPCFILTER_DESCRIPTOR        m_FilterDescriptor; // Filter descriptor

    ULONG                       m_NotificationInterval; // milliseconds.
    ULONG                       m_SamplingFrequency;    // Frames per second.

    PSERVICEGROUP               m_ServiceGroup;     // For notification.
    KMUTEX                      m_SampleRateSync;   // Sync for sample rate 

    ULONG                       m_MaxDmaBufferSize; // Dma buffer size.

    // All the below members should be updated by the child classes
    //
    ULONG                       m_MaxOutputStreams; // Max stream caps
    ULONG                       m_MaxInputStreams;
    ULONG                       m_MaxTotalStreams;

    ULONG                       m_MinChannels;      // Format caps
    ULONG                       m_MaxChannelsPcm;
    ULONG                       m_MinBitsPerSamplePcm;
    ULONG                       m_MaxBitsPerSamplePcm;
    ULONG                       m_MinSampleRatePcm;
    ULONG                       m_MaxSampleRatePcm;

protected:
    NTSTATUS                    ValidateFormat
    (
        IN  PKSDATAFORMAT       pDataFormat 
    );

    NTSTATUS                    ValidatePcm
    (
        IN  PWAVEFORMATEX       pWfx
    );

public:
    CMiniportWaveCyclicUXenAudio();
    ~CMiniportWaveCyclicUXenAudio();

    STDMETHODIMP                GetDescription
    (   
        OUT PPCFILTER_DESCRIPTOR *Description
    );

    STDMETHODIMP                Init
    (   IN PUNKNOWN             UnknownAdapter,
        IN PRESOURCELIST        ResourceList,
        IN PPORTWAVECYCLIC      Port
    );

    NTSTATUS                    PropertyHandlerCpuResources
    ( 
        IN  PPCPROPERTY_REQUEST PropertyRequest 
    );

    NTSTATUS                    PropertyHandlerGeneric
    (
        IN  PPCPROPERTY_REQUEST PropertyRequest
    );

    // Friends
    friend class                CMiniportWaveCyclicStreamUXenAudio;
    friend class                CMiniportTopologyUXenAudio;
    friend void                 TimerNotify
    ( 
        IN  PKDPC               Dpc, 
        IN  PVOID               DeferredContext, 
        IN  PVOID               SA1, 
        IN  PVOID               SA2 
    );
};
typedef CMiniportWaveCyclicUXenAudio *PCMiniportWaveCyclicUXenAudio;

///////////////////////////////////////////////////////////////////////////////
// CMiniportWaveCyclicStreamUXenAudio
//   This is the common base class for all UXenAudio samples. It implements basic
//   functionality for wavecyclic streams.

class CMiniportWaveCyclicStreamUXenAudio : 
    public IMiniportWaveCyclicStream,
    public IDmaChannel
{
protected:
    PCMiniportWaveCyclicUXenAudio   m_pMiniport;                        // Miniport that created us
    BOOLEAN                     m_fCapture;                         // Capture or render.
    BOOLEAN                     m_fFormat16Bit;                     // 16- or 8-bit samples.
    USHORT                      m_usBlockAlign;                     // Block alignment of current format.
    KSSTATE                     m_ksState;                          // Stop, pause, run.
    ULONG                       m_ulPin;                            // Pin Id.

    PRKDPC                      m_pDpc;                             // Deferred procedure call object
    PKTIMER                     m_pTimer;                           // Timer object

    BOOLEAN                     m_fDmaActive;                       // Dma currently active? 
    ULONG                       m_ulDmaPosition;                    // Position in Dma
    PVOID                       m_pvDmaBuffer;                      // Dma buffer pointer
    ULONG                       m_ulDmaBufferSize;                  // Size of dma buffer
    ULONG                       m_ulDmaMovementRate;                // Rate of transfer specific to system
    ULONGLONG                   m_ullDmaTimeStamp;                  // Dma time elasped 
    ULONGLONG                   m_ullElapsedTimeCarryForward;       // Time to carry forward in position calc.
    ULONG                       m_ulByteDisplacementCarryForward;   // Bytes to carry forward to next calc.

//    CSaveData                   m_SaveData;                         // Object to save settings.
    ULONG			m_nVoiceNumber;
  
public:
    CMiniportWaveCyclicStreamUXenAudio();
    ~CMiniportWaveCyclicStreamUXenAudio();

    IMP_IMiniportWaveCyclicStream;
    IMP_IDmaChannel;

    NTSTATUS                    Init
    ( 
        IN  PCMiniportWaveCyclicUXenAudio  Miniport,
        IN  ULONG               Pin,
        IN  BOOLEAN             Capture,
        IN  PKSDATAFORMAT       DataFormat
    );

    // Friends
    friend class CMiniportWaveCyclicUXenAudio;
};
typedef CMiniportWaveCyclicStreamUXenAudio *PCMiniportWaveCyclicStreamUXenAudio;

#endif

