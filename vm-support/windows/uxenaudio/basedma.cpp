/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    basedma.cpp

Abstract:

    IDmaChannel implementation. Does nothing HW related.

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
#include "common.h"
#include "basewave.h"

#pragma code_seg("PAGE")
//=============================================================================
STDMETHODIMP_(NTSTATUS)
CMiniportWaveCyclicStreamUXenAudio::AllocateBuffer
(
    IN ULONG                    BufferSize,
    IN PPHYSICAL_ADDRESS        PhysicalAddressConstraint OPTIONAL
)
/*++

Routine Description:

  The AllocateBuffer function allocates a buffer associated with the DMA object.
  The buffer is nonPaged.
  Callers of AllocateBuffer should run at a passive IRQL.

Arguments:

  BufferSize - Size in bytes of the buffer to be allocated.

  PhysicalAddressConstraint - Optional constraint to place on the physical
                              address of the buffer. If supplied, only the bits
                              that are set in the constraint address may vary
                              from the beginning to the end of the buffer.
                              For example, if the desired buffer should not
                              cross a 64k boundary, the physical address
                              constraint 0x000000000000ffff should be specified

Return Value:

  NT status code.

--*/
{
    UNREFERENCED_PARAMETER(PhysicalAddressConstraint);

    PAGED_CODE();

    DPF_ENTER;

    ULONG RingBufferSize;


    NTSTATUS                    ntStatus = STATUS_SUCCESS;

    m_pMiniport->m_AdapterCommon->VoiceRingSize(m_nVoiceNumber,&RingBufferSize);

    if (BufferSize !=RingBufferSize)
	return  STATUS_INSUFFICIENT_RESOURCES;

    m_pvDmaBuffer = (PVOID)
        ExAllocatePoolWithTag
        (
            NonPagedPool,
            BufferSize,
            UXENAUDIO_POOLTAG
        );
    if (!m_pvDmaBuffer)
    {
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
	RtlFillMemory(m_pvDmaBuffer,BufferSize,0);
        m_ulDmaBufferSize = BufferSize;
    }

    return ntStatus;
} // AllocateBuffer
#pragma code_seg()

//=============================================================================
STDMETHODIMP_(ULONG)
CMiniportWaveCyclicStreamUXenAudio::AllocatedBufferSize
(
    void
)
/*++

Routine Description:

  AllocatedBufferSize returns the size of the allocated buffer.
  Callers of AllocatedBufferSize can run at any IRQL.

Arguments:

Return Value:

  ULONG

--*/
{
    DPF_ENTER;

    return m_ulDmaBufferSize;
} // AllocatedBufferSize

//=============================================================================
STDMETHODIMP_(ULONG)
CMiniportWaveCyclicStreamUXenAudio::BufferSize
(
    void
)
/*++

Routine Description:

  BufferSize returns the size set by SetBufferSize or the allocated buffer size
  if the buffer size has not been set. The DMA object does not actually use
  this value internally. This value is maintained by the object to allow its
  various clients to communicate the intended size of the buffer. This call
  is often used to obtain the map size parameter to the Start member
  function. Callers of BufferSize can run at any IRQL

Arguments:

Return Value:

  //ULONG

--*/
{
    return m_ulDmaBufferSize;
} // BufferSize

//=============================================================================
STDMETHODIMP_(void)
CMiniportWaveCyclicStreamUXenAudio::CopyFrom
(
    IN  PVOID                   Destination,
    IN  PVOID                   Source,
    IN  ULONG                   ByteCount
)
/*++

Routine Description:

  The CopyFrom function copies sample data from the DMA buffer.
  Callers of CopyFrom can run at any IRQL

Arguments:

  Destination - Points to the destination buffer.

  Source - Points to the source buffer.

  ByteCount - Points to the source buffer.

Return Value:

  void

--*/
{
    ULONG offset = (ULONG) ((PUCHAR) Source - (PUCHAR) m_pvDmaBuffer);

    if (offset >= m_ulDmaBufferSize) {
        DWARN("read attempt past buffer %d %d", offset, m_ulDmaBufferSize);
        return;
    }
    if (offset+ByteCount > m_ulDmaBufferSize) {
        DWARN("read attempt past buffer %d %d", offset + ByteCount, m_ulDmaBufferSize);
        return;
    }

    m_pMiniport->m_AdapterCommon->VoiceCopyFrom(m_nVoiceNumber,offset,(PUCHAR) Destination,ByteCount);
} // CopyFrom

//=============================================================================
STDMETHODIMP_(void)
CMiniportWaveCyclicStreamUXenAudio::CopyTo
(
    IN  PVOID                   Destination,
    IN  PVOID                   Source,
    IN  ULONG                   ByteCount
/*++

Routine Description:

  The CopyTo function copies sample data to the DMA buffer.
  Callers of CopyTo can run at any IRQL.

Arguments:

  Destination - Points to the destination buffer.

  Source - Points to the source buffer

  ByteCount - Number of bytes to be copied

Return Value:

  void

--*/
)
{
    ULONG offset = (ULONG) ((PUCHAR) Destination - (PUCHAR) m_pvDmaBuffer);

    if (offset >= m_ulDmaBufferSize) {
        DWARN("write attempt past buffer %d %d", offset, m_ulDmaBufferSize);
        return;
    }
    if (offset+ByteCount > m_ulDmaBufferSize) {
        DWARN("write attempt past buffer %d %d", offset + ByteCount, m_ulDmaBufferSize);
        return;
    }

    m_pMiniport->m_AdapterCommon->VoiceCopyTo(m_nVoiceNumber,offset,(PUCHAR) Source,ByteCount);
} // CopyTo

//=============================================================================
#pragma code_seg("PAGE")
STDMETHODIMP_(void)
CMiniportWaveCyclicStreamUXenAudio::FreeBuffer
(
    void
)
/*++

Routine Description:

  The FreeBuffer function frees the buffer allocated by AllocateBuffer. Because
  the buffer is automatically freed when the DMA object is deleted, this
  function is not normally used. Callers of FreeBuffer should run at
  IRQL PASSIVE_LEVEL.

Arguments:

Return Value:

  void

--*/
{
    PAGED_CODE();

    DPF_ENTER;

    if ( m_pvDmaBuffer )
    {
        ExFreePoolWithTag( m_pvDmaBuffer, UXENAUDIO_POOLTAG );
        m_ulDmaBufferSize = 0;
    }
} // FreeBuffer
#pragma code_seg()

//=============================================================================
STDMETHODIMP_(PADAPTER_OBJECT)
CMiniportWaveCyclicStreamUXenAudio::GetAdapterObject
(
    void
)
/*++

Routine Description:

  The GetAdapterObject function returns the DMA object's internal adapter
  object. Callers of GetAdapterObject can run at any IRQL.

Arguments:

Return Value:

  PADAPTER_OBJECT - The return value is the object's internal adapter object.

--*/
{
    DPF_ENTER;

    // UXenAudio does not have need a physical DMA channel. Therefore it
    // does not have physical DMA structure.

    return NULL;
} // GetAdapterObject

//=============================================================================
STDMETHODIMP_(ULONG)
CMiniportWaveCyclicStreamUXenAudio::MaximumBufferSize
(
    void
)
/*++

Routine Description:

Arguments:

Return Value:

  NT status code.

--*/
{
    DPF_ENTER;

    return m_pMiniport->m_MaxDmaBufferSize;
} // MaximumBufferSize

//=============================================================================
STDMETHODIMP_(PHYSICAL_ADDRESS)
CMiniportWaveCyclicStreamUXenAudio::PhysicalAddress
(
    void
)
/*++

Routine Description:

  MaximumBufferSize returns the size in bytes of the largest buffer this DMA
  object is configured to support. Callers of MaximumBufferSize can run
  at any IRQL

Arguments:

Return Value:

  PHYSICAL_ADDRESS - The return value is the size in bytes of the largest
                     buffer this DMA object is configured to support.

--*/
{
    DPF_ENTER;

    PHYSICAL_ADDRESS            pAddress;

    pAddress.QuadPart = (LONGLONG) m_pvDmaBuffer;

    return pAddress;
} // PhysicalAddress

//=============================================================================
STDMETHODIMP_(void)
CMiniportWaveCyclicStreamUXenAudio::SetBufferSize
(
    IN ULONG                    BufferSize
)
/*++

Routine Description:

  The SetBufferSize function sets the current buffer size. This value is set to
  the allocated buffer size when AllocateBuffer is called. The DMA object does
  not actually use this value internally. This value is maintained by the object
  to allow its various clients to communicate the intended size of the buffer.
  Callers of SetBufferSize can run at any IRQL.

Arguments:

  BufferSize - Current size in bytes.

Return Value:

  void

--*/
{
    DPF_ENTER;

    if ( BufferSize <= m_ulDmaBufferSize )
    {
        m_ulDmaBufferSize = BufferSize;
    }
    else
    {
        DERR("Tried to enlarge dma buffer size");
    }
} // SetBufferSize

//=============================================================================
STDMETHODIMP_(PVOID)
CMiniportWaveCyclicStreamUXenAudio::SystemAddress
(
    void
)
/*++

Routine Description:

  The SystemAddress function returns the virtual system address of the
  allocated buffer. Callers of SystemAddress can run at any IRQL.

Arguments:

Return Value:

  PVOID - The return value is the virtual system address of the
          allocated buffer.

--*/
{
    return m_pvDmaBuffer;
} // SystemAddress

//=============================================================================
STDMETHODIMP_(ULONG)
CMiniportWaveCyclicStreamUXenAudio::TransferCount
(
    void
)
/*++

Routine Description:

  The TransferCount function returns the size in bytes of the buffer currently
  being transferred by a DMA object. Callers of TransferCount can run
  at any IRQL.

Arguments:

Return Value:

  ULONG - The return value is the size in bytes of the buffer currently
          being transferred.

--*/
{
    DPF_ENTER;

    return m_ulDmaBufferSize;
}
