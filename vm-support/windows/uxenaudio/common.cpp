/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    common.cpp

Abstract:

    Implementation of the AdapterCommon class. 

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

#pragma warning (disable : 4127)

#include <uxenaudio.h>
#include "uxaud_hw.h"
#include "common.h"
#include "hw.h"
#include "voice.h"

//=============================================================================
// Classes
//=============================================================================

///////////////////////////////////////////////////////////////////////////////
// CAdapterCommon
//   
//

class CAdapterCommon : 
    public IAdapterCommon,
    public IAdapterPowerManagement,
    public CUnknown    
{
    private:
        PPORTWAVECYCLIC         m_pPortWave;    // Port interface
        PSERVICEGROUP           m_pServiceGroupWave;
        PDEVICE_OBJECT          m_pDeviceObject;      
        DEVICE_POWER_STATE      m_PowerState;        

	PVOICE			m_pVoices[HW_MAX_VOICE];

        PCUXENAUDIOHW           m_pHW;          // Virtual UXenAudio HW object

	PHYSICAL_ADDRESS	m_MMIOBase_phys;
	ULONG			m_MMIOBase_len;
	PUCHAR			m_pMMIOBase;

	PHYSICAL_ADDRESS	m_RAMBase_phys;
	ULONG			m_RAMBase_len;
	PUCHAR			m_pRAMBase;

	UINT			m_nVoice;		

    public:
        //=====================================================================
        // Default CUnknown
        DECLARE_STD_UNKNOWN();
        DEFINE_STD_CONSTRUCTOR(CAdapterCommon);
        ~CAdapterCommon();

        //=====================================================================
        // Default IAdapterPowerManagement
        IMP_IAdapterPowerManagement;

        //=====================================================================
        // IAdapterCommon methods                                               
        STDMETHODIMP_(NTSTATUS) Init
        (   
    	    IN  PRESOURCELIST 		ResourceList,
            IN  PDEVICE_OBJECT          DeviceObject 
        );

        STDMETHODIMP_(PDEVICE_OBJECT)   GetDeviceObject(void);

        STDMETHODIMP_(PUNKNOWN *)       WavePortDriverDest(void);

        STDMETHODIMP_(void)     SetWaveServiceGroup
        (   
            IN  PSERVICEGROUP   ServiceGroup
        );

        STDMETHODIMP_(BOOL)     bDevSpecificRead();

        STDMETHODIMP_(void)     bDevSpecificWrite
        (
            IN  BOOL            bDevSpecific
        );
        STDMETHODIMP_(INT)      iDevSpecificRead();

        STDMETHODIMP_(void)     iDevSpecificWrite
        (
            IN  INT             iDevSpecific
        );
        STDMETHODIMP_(UINT)     uiDevSpecificRead();

        STDMETHODIMP_(void)     uiDevSpecificWrite
        (
            IN  UINT            uiDevSpecific
        );

        STDMETHODIMP_(BOOL)     MixerMuteRead
        (
            IN  ULONG           Index
        );

        STDMETHODIMP_(void)     MixerMuteWrite
        (
            IN  ULONG           Index,
            IN  BOOL            Value
        );

        STDMETHODIMP_(ULONG)    MixerMuxRead(void);

        STDMETHODIMP_(void)     MixerMuxWrite
        (
            IN  ULONG           Index
        );

        STDMETHODIMP_(void)     MixerReset(void);

        STDMETHODIMP_(LONG)     MixerVolumeRead
        ( 
            IN  ULONG           Index,
            IN  LONG            Channel
        );

        STDMETHODIMP_(void)     MixerVolumeWrite
        ( 
            IN  ULONG           Index,
            IN  LONG            Channel,
            IN  LONG            Value 
        );

        STDMETHODIMP_(NTSTATUS)     Probe
        ( 
		VOID
        );

        STDMETHODIMP_(NTSTATUS)     CheckSig
        ( 
		VOID
        );

        STDMETHODIMP_(ULONG)     ReadMMIO32
        ( 
            IN  ULONG           ulOffset
        );

        STDMETHODIMP_(VOID)     WriteMMIO32
        ( 
            IN  ULONG           ulOffset,
            IN  ULONG           ulValue
        );

        STDMETHODIMP_(ULONG)     ReadRAM32
        ( 
            IN  ULONG           ulOffset
        );

        STDMETHODIMP_(VOID)     WriteRAM32
        ( 
            IN  ULONG           ulOffset,
            IN  ULONG           ulValue
        );

        STDMETHODIMP_(UINT)     	VoiceCount
        ( 
		VOID
        );
    
        STDMETHODIMP_(NTSTATUS)     VoiceStart
        ( 
            IN UINT Voice,
            IN BOOL capture
        );
    
        STDMETHODIMP_(NTSTATUS)     VoiceStop
        ( 
    		IN UINT		Voice
        );
    
        STDMETHODIMP_(NTSTATUS)     VoiceCopyTo
        ( 
    		IN UINT		Voice,
		IN ULONG	Offset,
    		IN PUCHAR	Data,
    		IN UINT		Len
        );

        STDMETHODIMP_(NTSTATUS)     VoiceCopyFrom
        ( 
    		IN UINT		Voice,
		IN ULONG	Offset,
    		IN PUCHAR	Data,
    		IN UINT		Len
        );
    
        STDMETHODIMP_(NTSTATUS)     VoiceNotify
        ( 
    		IN UINT		Voice
        );
    
        STDMETHODIMP_(NTSTATUS)     VoiceReadOffset
        ( 
    		IN UINT		Voice,
    		OUT PULONG 	Position
        );
    
        STDMETHODIMP_(NTSTATUS)     VoiceRingSize
        ( 
    		IN UINT		Voice,
    		OUT PULONG 	RingSize
        );
    


        //=====================================================================
        // friends

        friend NTSTATUS         NewAdapterCommon
        ( 
            OUT PADAPTERCOMMON * OutAdapterCommon, 
            IN  PRESOURCELIST   ResourceList 
        );
};

//-----------------------------------------------------------------------------
// Functions
//-----------------------------------------------------------------------------

//=============================================================================
#pragma code_seg("PAGE")
NTSTATUS
NewAdapterCommon
( 
    OUT PUNKNOWN *              Unknown,
    IN  REFCLSID,
    IN  PUNKNOWN                UnknownOuter OPTIONAL,
    IN  POOL_TYPE               PoolType 
)
/*++

Routine Description:

  Creates a new CAdapterCommon

Arguments:

  Unknown - 

  UnknownOuter -

  PoolType

Return Value:

  NT status code.

--*/
{
    PAGED_CODE();

    ASSERT(Unknown);

    STD_CREATE_BODY_
    ( 
        CAdapterCommon, 
        Unknown, 
        UnknownOuter, 
        PoolType,      
        PADAPTERCOMMON 
    );
} // NewAdapterCommon

//=============================================================================
CAdapterCommon::~CAdapterCommon
( 
    void 
)
/*++

Routine Description:

  Destructor for CAdapterCommon.

Arguments:

Return Value:

  void

--*/
{
    UINT i;
    PAGED_CODE();

    DPF_ENTER;

    if (m_pHW)
    {
        delete m_pHW;
    }

    //CSaveData::DestroyWorkItems();

    if (m_pPortWave)
    {
        m_pPortWave->Release();
    }

    if (m_pServiceGroupWave)
    {
        m_pServiceGroupWave->Release();
    }

	for (i=0;i<m_nVoice;++i) 
	{
		if (m_pVoices[i]) delete m_pVoices[i];
	}

} // ~CAdapterCommon  

//=============================================================================
STDMETHODIMP_(PDEVICE_OBJECT)   
CAdapterCommon::GetDeviceObject
(
    void
)
/*++

Routine Description:

  Returns the deviceobject

Arguments:

Return Value:

  PDEVICE_OBJECT

--*/
{
    PAGED_CODE();
    
    return m_pDeviceObject;
} // GetDeviceObject

ULONG CAdapterCommon::ReadMMIO32
(
	IN ULONG ulOffset
)
{
	ULONG ulValue = ULONG(-1);

	ulValue = READ_REGISTER_ULONG((PULONG) (m_pMMIOBase + ulOffset));

  	DOUT (DBG_REGS, "ReadMMIO32(0x%p)=0x%8x", ulOffset,ulValue);

	return ulValue;
}

void CAdapterCommon::WriteMMIO32
(
	IN ULONG ulOffset,
	IN ULONG ulValue
)
{
	WRITE_REGISTER_ULONG((PULONG) (m_pMMIOBase + ulOffset), ulValue);

        DOUT (DBG_REGS, "WriteMMIO32(0x%p,0x%8x)", ulOffset,ulValue);

}

ULONG CAdapterCommon::ReadRAM32
(
	IN ULONG ulOffset
)
{
	ULONG ulValue = ULONG(-1);

	ulValue = READ_REGISTER_ULONG((PULONG) (m_pRAMBase + ulOffset));

  	DOUT (DBG_REGS, "ReadRAM32(0x%p)=0x%8x", ulOffset,ulValue);

	return ulValue;
}

void CAdapterCommon::WriteRAM32
(
	IN ULONG ulOffset,
	IN ULONG ulValue
)
{

	WRITE_REGISTER_ULONG((PULONG) (m_pRAMBase + ulOffset), ulValue);

        DOUT (DBG_REGS, "WriteRAM32(0x%p,0x%8x)", ulOffset,ulValue);
}

NTSTATUS
CAdapterCommon::CheckSig
(
    VOID
)
{
    if (ReadMMIO32(UXAU_SIGNATURE) != UXAU_SIGNATURE_VALUE )
	return STATUS_INVALID_PARAMETER;


    return STATUS_SUCCESS;
}


NTSTATUS
CAdapterCommon::Probe
( 
    VOID
)
{
	NTSTATUS ntStatus;
	UINT i;

	DOUT(DBG_PRINT, "[CAdapterCommon::Probe]");

	ntStatus = CheckSig();

	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	m_nVoice=ReadMMIO32(UXAU_NVOICE);

	if (m_nVoice<HW_MIN_VOICE) 
		return STATUS_INVALID_PARAMETER;

	if (m_nVoice>HW_MAX_VOICE)
		m_nVoice=HW_MAX_VOICE;

	for (i=0;i<m_nVoice;++i) 
	{
                m_pVoices[i] = new (NonPagedPool, UXENAUDIO_POOLTAG)  CVoice(i);
		ntStatus=m_pVoices[i]->Probe(m_pMMIOBase+UXAU_V_BASE(i),m_pRAMBase);
		if (!NT_SUCCESS(ntStatus)) return ntStatus;
	}

	return ntStatus;
}


//=============================================================================
NTSTATUS
CAdapterCommon::Init
( 
    IN  PRESOURCELIST 		ResourceList,
    IN  PDEVICE_OBJECT          DeviceObject 
)
/*++

Routine Description:

    Initialize adapter common object.

Arguments:

    DeviceObject - pointer to the device object

Return Value:

  NT status code.

--*/
{
    PAGED_CODE();

    ASSERT(DeviceObject);

    NTSTATUS                    ntStatus = STATUS_SUCCESS;

    DPF_ENTER;

    m_pDeviceObject = DeviceObject;
    m_PowerState    = PowerDeviceD0;


    ASSERT(ResourceList->FindTranslatedMemory(0));
    m_MMIOBase_phys = ResourceList->FindTranslatedMemory(0)->u.Memory.Start;
    m_MMIOBase_len = (ULONG) ResourceList->FindTranslatedMemory(0)->u.Memory.Length;
    m_pMMIOBase = (PUCHAR) MmMapIoSpace(m_MMIOBase_phys,m_MMIOBase_len,MmNonCached);

    ASSERT(ResourceList->FindTranslatedMemory(1));
    m_RAMBase_phys = ResourceList->FindTranslatedMemory(1)->u.Memory.Start;
    m_RAMBase_len = (ULONG) ResourceList->FindTranslatedMemory(1)->u.Memory.Length;
    m_pRAMBase = (PUCHAR) MmMapIoSpace(m_RAMBase_phys,m_RAMBase_len,MmCached);

#if 0
    m_pMMIOBase = (PUCHAR) MmMapIoSpace(m_MMIOBase_phys,m_MMIOBase_len,MmCached);
    m_pRAMBase = (PUCHAR) MmMapIoSpace(m_RAMBase_phys,m_RAMBase_len,MmCached);

#endif
    
    DOUT (DBG_SYSINFO, "Configuration:"
          "   MMIOBase   = 0x%p+0x%x -> 0x%p"
          "   RAMBase    = 0x%p+0x%x -> 0x%p",
          (PVOID) m_MMIOBase_phys.QuadPart, m_MMIOBase_len, m_pMMIOBase,
          (PVOID) m_RAMBase_phys.QuadPart, m_RAMBase_len, m_pRAMBase);

    DOUT (DBG_SYSINFO, "Configuration:"
          "   RAMBase[0]= 0x%lx"
          "   RAMBase[1]= 0x%lx"
          "   RAMBase[0x100]= 0x%lx"
          "   RAMBase[0x1000]= 0x%lx",
          (ULONG) ReadRAM32(0),
          (ULONG) ReadRAM32(1),
          (ULONG) ReadRAM32(0x100),
          (ULONG) ReadRAM32(0x1000));


    ntStatus = Probe ();

    if (!NT_SUCCESS(ntStatus)) {
	DOUT(DBG_ERROR, "Probe failed!");
        return ntStatus;
    }

    
    // Initialize HW.
    // 
    m_pHW = new (NonPagedPool, UXENAUDIO_POOLTAG)  CUXENAUDIOHW;
    if (!m_pHW)
    {
        DWARN("Insufficient memory for UXenAudio HW");
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        m_pHW->MixerReset();
    }

    //CSaveData::SetDeviceObject(DeviceObject);   //device object is needed by CSaveData

    return ntStatus;
} // Init

//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::MixerReset
( 
    void 
)
/*++

Routine Description:

  Reset mixer registers from registry.

Arguments:

Return Value:

  void

--*/
{
    PAGED_CODE();
    
    if (m_pHW)
    {
        m_pHW->MixerReset();
    }
} // MixerReset

//=============================================================================
STDMETHODIMP
CAdapterCommon::NonDelegatingQueryInterface
( 
    REFIID                      Interface,
    PVOID *                     Object 
)
/*++

Routine Description:

  QueryInterface routine for AdapterCommon

Arguments:

  Interface - 

  Object -

Return Value:

  NT status code.

--*/
{
    PAGED_CODE();

    ASSERT(Object);

    if (IsEqualGUIDAligned(Interface, IID_IUnknown))
    {
        *Object = PVOID(PUNKNOWN(PADAPTERCOMMON(this)));
    }
    else if (IsEqualGUIDAligned(Interface, IID_IAdapterCommon))
    {
        *Object = PVOID(PADAPTERCOMMON(this));
    }
    else if (IsEqualGUIDAligned(Interface, IID_IAdapterPowerManagement))
    {
        *Object = PVOID(PADAPTERPOWERMANAGEMENT(this));
    }
    else
    {
        *Object = NULL;
    }

    if (*Object)
    {
        PUNKNOWN(*Object)->AddRef();
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
} // NonDelegatingQueryInterface

//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::SetWaveServiceGroup
( 
    IN PSERVICEGROUP            ServiceGroup 
)
/*++

Routine Description:


Arguments:

Return Value:

  NT status code.

--*/
{
    PAGED_CODE();
    
    DPF_ENTER;
    
    if (m_pServiceGroupWave)
    {
        m_pServiceGroupWave->Release();
    }

    m_pServiceGroupWave = ServiceGroup;

    if (m_pServiceGroupWave)
    {
        m_pServiceGroupWave->AddRef();
    }
} // SetWaveServiceGroup

//=============================================================================
STDMETHODIMP_(PUNKNOWN *)
CAdapterCommon::WavePortDriverDest
( 
    void 
)
/*++

Routine Description:

  Returns the wave port.

Arguments:

Return Value:

  PUNKNOWN : pointer to waveport

--*/
{
    PAGED_CODE();

    return (PUNKNOWN *)&m_pPortWave;
} // WavePortDriverDest
#pragma code_seg()

//=============================================================================
STDMETHODIMP_(BOOL)
CAdapterCommon::bDevSpecificRead()
/*++

Routine Description:

  Fetch Device Specific information.

Arguments:

  N/A

Return Value:

    BOOL - Device Specific info

--*/
{
    if (m_pHW)
    {
        return m_pHW->bGetDevSpecific();
    }

    return FALSE;
} // bDevSpecificRead

//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::bDevSpecificWrite
(
    IN  BOOL                    bDevSpecific
)
/*++

Routine Description:

  Store the new value in the Device Specific location.

Arguments:

  bDevSpecific - Value to store

Return Value:

  N/A.

--*/
{
    if (m_pHW)
    {
        m_pHW->bSetDevSpecific(bDevSpecific);
    }
} // DevSpecificWrite

//=============================================================================
STDMETHODIMP_(INT)
CAdapterCommon::iDevSpecificRead()
/*++

Routine Description:

  Fetch Device Specific information.

Arguments:

  N/A

Return Value:

    INT - Device Specific info

--*/
{
    if (m_pHW)
    {
        return m_pHW->iGetDevSpecific();
    }

    return 0;
} // iDevSpecificRead

//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::iDevSpecificWrite
(
    IN  INT                    iDevSpecific
)
/*++

Routine Description:

  Store the new value in the Device Specific location.

Arguments:

  iDevSpecific - Value to store

Return Value:

  N/A.

--*/
{
    if (m_pHW)
    {
        m_pHW->iSetDevSpecific(iDevSpecific);
    }
} // iDevSpecificWrite

//=============================================================================
STDMETHODIMP_(UINT)
CAdapterCommon::uiDevSpecificRead()
/*++

Routine Description:

  Fetch Device Specific information.

Arguments:

  N/A

Return Value:

    UINT - Device Specific info

--*/
{
    if (m_pHW)
    {
        return m_pHW->uiGetDevSpecific();
    }

    return 0;
} // uiDevSpecificRead

//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::uiDevSpecificWrite
(
    IN  UINT                    uiDevSpecific
)
/*++

Routine Description:

  Store the new value in the Device Specific location.

Arguments:

  uiDevSpecific - Value to store

Return Value:

  N/A.

--*/
{
    if (m_pHW)
    {
        m_pHW->uiSetDevSpecific(uiDevSpecific);
    }
} // uiDevSpecificWrite

//=============================================================================
STDMETHODIMP_(BOOL)
CAdapterCommon::MixerMuteRead
(
    IN  ULONG                   Index
)
/*++

Routine Description:

  Store the new value in mixer register array.

Arguments:

  Index - node id

Return Value:

    BOOL - mixer mute setting for this node

--*/
{
    if (m_pHW)
    {
        return m_pHW->GetMixerMute(Index);
    }

    return 0;
} // MixerMuteRead

//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::MixerMuteWrite
(
    IN  ULONG                   Index,
    IN  BOOL                    Value
)
/*++

Routine Description:

  Store the new value in mixer register array.

Arguments:

  Index - node id

  Value - new mute settings

Return Value:

  NT status code.

--*/
{
    if (m_pHW)
    {
        m_pHW->SetMixerMute(Index, Value);
    }
} // MixerMuteWrite

//=============================================================================
STDMETHODIMP_(ULONG)
CAdapterCommon::MixerMuxRead() 
/*++

Routine Description:

  Return the mux selection

Arguments:

  Index - node id

  Value - new mute settings

Return Value:

  NT status code.

--*/
{
    if (m_pHW)
    {
        return m_pHW->GetMixerMux();
    }

    return 0;
} // MixerMuxRead

//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::MixerMuxWrite
(
    IN  ULONG                   Index
)
/*++

Routine Description:

  Store the new mux selection

Arguments:

  Index - node id

  Value - new mute settings

Return Value:

  NT status code.

--*/
{
    if (m_pHW)
    {
        m_pHW->SetMixerMux(Index);
    }
} // MixerMuxWrite

//=============================================================================
STDMETHODIMP_(LONG)
CAdapterCommon::MixerVolumeRead
( 
    IN  ULONG                   Index,
    IN  LONG                    Channel
)
/*++

Routine Description:

  Return the value in mixer register array.

Arguments:

  Index - node id

  Channel = which channel

Return Value:

    Byte - mixer volume settings for this line

--*/
{
    if (m_pHW)
    {
        return m_pHW->GetMixerVolume(Index, Channel);
    }

    return 0;
} // MixerVolumeRead

//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::MixerVolumeWrite
( 
    IN  ULONG                   Index,
    IN  LONG                    Channel,
    IN  LONG                    Value
)
/*++

Routine Description:

  Store the new value in mixer register array.

Arguments:

  Index - node id

  Channel - which channel

  Value - new volume level

Return Value:

    void

--*/
{
    if (m_pHW)
    {
        m_pHW->SetMixerVolume(Index, Channel, Value);
    }
} // MixerVolumeWrite

STDMETHODIMP_(UINT)     	CAdapterCommon::VoiceCount
( 
	VOID
)
{
	return m_nVoice;

}

STDMETHODIMP_(NTSTATUS)     CAdapterCommon::VoiceNotify
( 
	IN UINT		Voice
)
{
	return m_pVoices[Voice]->Notify();
}
    
STDMETHODIMP_(NTSTATUS)     CAdapterCommon::VoiceStart
( 
    IN UINT Voice,
    IN BOOL capture
)
{
    return m_pVoices[Voice]->Start(capture);
}
    
STDMETHODIMP_(NTSTATUS)     CAdapterCommon::VoiceStop
( 
	IN UINT		Voice
)
{    
	return m_pVoices[Voice]->Stop();
}

STDMETHODIMP_(NTSTATUS)     CAdapterCommon::VoiceCopyTo
( 
	IN UINT		Voice,
	IN ULONG 	Offset,
    	IN PUCHAR	Data,
    	IN UINT		Len
)
{
	return m_pVoices[Voice]->CopyTo(Offset,Data,Len);
}

STDMETHODIMP_(NTSTATUS)     CAdapterCommon::VoiceCopyFrom
( 
	IN UINT		Voice,
	IN ULONG 	Offset,
    	IN PUCHAR	Data,
    	IN UINT		Len
)
{
	return m_pVoices[Voice]->CopyFrom(Offset,Data,Len);
}

STDMETHODIMP_(NTSTATUS)     CAdapterCommon::VoiceReadOffset
( 
	IN UINT		Voice,
    	OUT PULONG	Position
)
{
	return m_pVoices[Voice]->ReadOffset(Position);
}
 
 
STDMETHODIMP_(NTSTATUS)     CAdapterCommon::VoiceRingSize
( 
	IN UINT		Voice,
    	OUT PULONG	RingSize
)
{
	return m_pVoices[Voice]->RingSize(RingSize);
}
 
    
//=============================================================================
STDMETHODIMP_(void)
CAdapterCommon::PowerChangeState
( 
    IN  POWER_STATE             NewState 
)
/*++

Routine Description:


Arguments:

  NewState - The requested, new power state for the device. 

Return Value:

    void

--*/
{
    DPF_ENTER;

    // is this actually a state change??
    //
    if (NewState.DeviceState != m_PowerState)
    {
        // switch on new state
        //
        switch (NewState.DeviceState)
        {
            case PowerDeviceD0:
            case PowerDeviceD1:
            case PowerDeviceD2:
            case PowerDeviceD3:
                m_PowerState = NewState.DeviceState;

                DOUT(DBG_POWER, "Entering D%d", ULONG(m_PowerState) - ULONG(PowerDeviceD0));

                break;
    
            default:
                DWARN("Unknown Device Power State");
                break;
        }
    }
} // PowerStateChange

//=============================================================================
STDMETHODIMP_(NTSTATUS)
CAdapterCommon::QueryDeviceCapabilities
( 
    IN  PDEVICE_CAPABILITIES    PowerDeviceCaps 
)
/*++

Routine Description:

    Called at startup to get the caps for the device.  This structure provides 
    the system with the mappings between system power state and device power 
    state.  This typically will not need modification by the driver.         

Arguments:

  PowerDeviceCaps - The device's capabilities. 

Return Value:

  NT status code.

--*/
{
    UNREFERENCED_PARAMETER(PowerDeviceCaps);

    DPF_ENTER;

    return (STATUS_SUCCESS);
} // QueryDeviceCapabilities

//=============================================================================
STDMETHODIMP_(NTSTATUS)
CAdapterCommon::QueryPowerChangeState
( 
    IN  POWER_STATE             NewStateQuery 
)
/*++

Routine Description:

  Query to see if the device can change to this power state 

Arguments:

  NewStateQuery - The requested, new power state for the device

Return Value:

  NT status code.

--*/
{
    UNREFERENCED_PARAMETER(NewStateQuery);

    DPF_ENTER;

    return STATUS_SUCCESS;
} // QueryPowerChangeState
