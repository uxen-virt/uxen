/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    Common.h

Abstract:
    
    CAdapterCommon class declaration.

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

#ifndef _UXENAUDIO_COMMON_H_
#define _UXENAUDIO_COMMON_H_

//=============================================================================
// Defines
//=============================================================================

#if 0
DEFINE_GUID(IID_IAdapterCommon,
0x7eda2950, 0xbf9f, 0x11d0, 0x87, 0x1f, 0x0, 0xa0, 0xc9, 0x11, 0xb5, 0x44);
#else
DEFINE_GUID(IID_IAdapterCommon,
0xa9b66a93, 0x69ea, 0x4fa5, 0x87, 0x73, 0x26, 0xfc, 0xfb, 0xf2, 0xb2, 0x39);
#endif

//=============================================================================
// Interfaces
//=============================================================================

///////////////////////////////////////////////////////////////////////////////
// IAdapterCommon
//
DECLARE_INTERFACE_(IAdapterCommon, IUnknown)
{
    STDMETHOD_(NTSTATUS,        Init) 
    ( 
        THIS_
        IN  PRESOURCELIST	ResourceList,
        IN  PDEVICE_OBJECT      DeviceObject 
    ) PURE;

    STDMETHOD_(PDEVICE_OBJECT,  GetDeviceObject)
    (
        THIS
    ) PURE;

    STDMETHOD_(VOID,            SetWaveServiceGroup) 
    ( 
        THIS_
        IN PSERVICEGROUP        ServiceGroup 
    ) PURE;

    STDMETHOD_(PUNKNOWN *,      WavePortDriverDest) 
    ( 
        THIS 
    ) PURE;

    STDMETHOD_(BOOL,            bDevSpecificRead)
    (
        THIS_
    ) PURE;

    STDMETHOD_(VOID,            bDevSpecificWrite)
    (
        THIS_
        IN  BOOL                bDevSpecific
    );

    STDMETHOD_(INT,             iDevSpecificRead)
    (
        THIS_
    ) PURE;

    STDMETHOD_(VOID,            iDevSpecificWrite)
    (
        THIS_
        IN  INT                 iDevSpecific
    );

    STDMETHOD_(UINT,            uiDevSpecificRead)
    (
        THIS_
    ) PURE;

    STDMETHOD_(VOID,            uiDevSpecificWrite)
    (
        THIS_
        IN  UINT                uiDevSpecific
    );

    STDMETHOD_(BOOL,            MixerMuteRead)
    (
        THIS_
        IN  ULONG               Index
    ) PURE;

    STDMETHOD_(VOID,            MixerMuteWrite)
    (
        THIS_
        IN  ULONG               Index,
        IN  BOOL                Value
    );

    STDMETHOD_(ULONG,           MixerMuxRead)
    (
        THIS
    );

    STDMETHOD_(VOID,            MixerMuxWrite)
    (
        THIS_
        IN  ULONG               Index
    );

    STDMETHOD_(LONG,            MixerVolumeRead) 
    ( 
        THIS_
        IN  ULONG               Index,
        IN  LONG                Channel
    ) PURE;

    STDMETHOD_(VOID,            MixerVolumeWrite) 
    ( 
        THIS_
        IN  ULONG               Index,
        IN  LONG                Channel,
        IN  LONG                Value 
    ) PURE;

    STDMETHOD_(VOID,            MixerReset) 
    ( 
        THIS_ 
    ) PURE;

    STDMETHOD_(UINT,     	VoiceCount)
    ( 
		THIS_
		VOID
    ) PURE;

    STDMETHOD_(NTSTATUS,     VoiceStart)
    ( 
		THIS_
		IN UINT		Voice
    ) PURE;

    STDMETHOD_(NTSTATUS,     VoiceStop)
    ( 
		THIS_
		IN UINT		Voice
    ) PURE;

    STDMETHOD_(NTSTATUS,     VoiceCopyTo)
    ( 
		THIS_
		IN UINT		Voice,
		IN ULONG 	Offset,
		IN PUCHAR	Data,
		IN UINT		Len
    ) PURE;

    STDMETHOD_(NTSTATUS,     VoiceReadOffset)
    ( 
		THIS_
		IN UINT		Voice,
		OUT PULONG	Position
    ) PURE;

    STDMETHOD_(NTSTATUS,     VoiceNotify)
    ( 
		THIS_
		IN UINT		Voice
    ) PURE;

    STDMETHOD_(NTSTATUS,     VoiceRingSize)
    ( 
		THIS_
		IN UINT		Voice,
		OUT PULONG	RingSize
    ) PURE;



};
typedef IAdapterCommon *PADAPTERCOMMON;

//=============================================================================
// Function Prototypes
//=============================================================================
NTSTATUS
NewAdapterCommon
( 
    OUT PUNKNOWN *              Unknown,
    IN  REFCLSID,
    IN  PUNKNOWN                UnknownOuter OPTIONAL,
    IN  POOL_TYPE               PoolType 
);

#endif  //_COMMON_H_

