/******************************Module*Header*******************************\
* Module Name: blthw.cxx
*
* Sample display driver functions for a HW blt simulation. This file is 
* only provided to simulate how a real hardware-accelerated display-only 
* driver functions, and should not be used in a real driver.
*
* Copyright (c) 2011 Microsoft Corporation
\**************************************************************************/
/*
 * uXen changes:
 *
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
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

#include "BDD.hxx"

struct DoPresentMemory
{
    PVOID                     DstAddr;
    UINT                      DstStride;
    ULONG                     DstBitPerPixel;
    UINT                      SrcWidth;
    UINT                      SrcHeight;
    BYTE*                     SrcAddr;
    LONG                      SrcPitch;
    ULONG                     NumMoves;             // in:  Number of screen to screen moves
    D3DKMT_MOVE_RECT*         Moves;               // in:  Point to the list of moves
    ULONG                     NumDirtyRects;        // in:  Number of direct rects
    RECT*                     DirtyRect;           // in:  Point to the list of dirty rects
    D3DKMDT_VIDPN_PRESENT_PATH_ROTATION Rotation;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID  SourceID;
    HANDLE                    hAdapter;
    PMDL                      Mdl;
    BDD_HWBLT*                DisplaySource;
};

void
HwExecutePresentDisplayOnly(
    HANDLE Context);

void
BDD_HWBLT::Init()
{
    KeInitializeEvent(&m_hThreadStartupEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&m_hThreadSuspendEvent, SynchronizationEvent, FALSE);

    m_DevExt = NULL;
    m_hPresentWorkerThread = NULL;
    m_pPresentWorkerThread = NULL;
}

void
BDD_HWBLT::CleanUp()
{
}

NTSTATUS
BDD_HWBLT::ExecutePresentDisplayOnly(
    _In_ BYTE*             DstAddr,
    _In_ UINT              DstBitPerPixel,
    _In_ LONG              DstPitch,
    _In_ BYTE*             SrcAddr,
    _In_ UINT              SrcBytesPerPixel,
    _In_ LONG              SrcPitch,
    _In_ ULONG             NumMoves,
    _In_ D3DKMT_MOVE_RECT* Moves,
    _In_ ULONG             NumDirtyRects,
    _In_ RECT*             DirtyRect,
    _In_ D3DKMDT_VIDPN_PRESENT_PATH_ROTATION Rotation)
/*++

  Routine Description:

    The method creates present worker thread and provides context
    for it filled with present commands

  Arguments:

    DstAddr - address of destination surface
    DstBitPerPixel - color depth of destination surface
    SrcAddr - address of source surface
    SrcBytesPerPixel - bytes per pixel of source surface
    SrcPitch - source surface pitch (bytes in a row)
    NumMoves - number of moves to be copied
    Moves - moves' data
    NumDirtyRects - number of rectangles to be copied
    DirtyRect - rectangles' data
    Rotation - roatation to be performed when executing copy
    CallBack - callback for present worker thread to report execution status

  Return Value:

    Status

--*/
{
#if 0
    NTSTATUS Status = STATUS_SUCCESS;
#endif
    UNREFERENCED_PARAMETER(SrcBytesPerPixel);

    SIZE_T sizeMoves = NumMoves*sizeof(D3DKMT_MOVE_RECT);
    SIZE_T sizeRects = NumDirtyRects*sizeof(RECT);
    SIZE_T size = sizeof(DoPresentMemory) + sizeMoves + sizeRects;

    DoPresentMemory* ctx = (DoPresentMemory *)ExAllocatePoolWithTag(
        NonPagedPool, size, BDDTAG);

    if (!ctx)
    {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(ctx,size);

    const CURRENT_BDD_MODE* pModeCur = m_DevExt->GetCurrentMode(m_SourceId);

    ctx->DstAddr          = DstAddr;
    ctx->DstBitPerPixel   = DstBitPerPixel;
    ctx->DstStride        = DstPitch;
    ctx->SrcWidth         = pModeCur->SrcModeWidth;
    ctx->SrcHeight        = pModeCur->SrcModeHeight;
    ctx->SrcAddr          = SrcAddr;
    ctx->SrcPitch         = SrcPitch;
    ctx->Rotation         = Rotation;
    ctx->NumMoves         = NumMoves;
    ctx->Moves            = Moves;
    ctx->NumDirtyRects    = NumDirtyRects;
    ctx->DirtyRect        = DirtyRect;
    ctx->SourceID         = m_SourceId;
    ctx->hAdapter         = m_DevExt;
    ctx->Mdl              = NULL;
    ctx->DisplaySource    = this;

#if 0
    {
        // Map Source into kernel space, as Blt will be executed by system worker thread
        UINT sizeToMap = SrcPitch*pModeCur->SrcModeHeight;

        PMDL mdl = IoAllocateMdl((PVOID)SrcAddr, sizeToMap,  FALSE, FALSE, NULL);
        if(!mdl)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KPROCESSOR_MODE AccessMode = (KPROCESSOR_MODE)(( SrcAddr <=
                        (BYTE* const) MM_USER_PROBE_ADDRESS)?UserMode:KernelMode);
        __try
        {
            // Probe and lock the pages of this buffer in physical memory.
            // We need only IoReadAccess.
            MmProbeAndLockPages(mdl, AccessMode, IoReadAccess);
        }
        #pragma prefast(suppress: __WARNING_EXCEPTIONEXECUTEHANDLER, "try/except is only able to protect against user-mode errors and these are the only errors we try to catch here");
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = GetExceptionCode();
            IoFreeMdl(mdl);
            return Status;
        }

        // Map the physical pages described by the MDL into system space.
        // Note: double mapping the buffer this way causes lot of system
        // overhead for large size buffers.
        ctx->SrcAddr = (BYTE*)
            (MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority ));

        if(!ctx->SrcAddr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return Status;
        }

        // Save Mdl to unmap and unlock the pages in worker thread
        ctx->Mdl = mdl;
    }
#endif

    BYTE* rects = (BYTE*)(ctx+1);

    // copy moves and update pointer
    if (Moves)
    {
        memcpy(rects,Moves,sizeMoves);
        ctx->Moves = (D3DKMT_MOVE_RECT*)(rects);
        rects += sizeMoves;
    }

    // copy dirty rects and update pointer
    if (DirtyRect)
    {
        memcpy(rects,DirtyRect,sizeRects);
        ctx->DirtyRect = (RECT*)(rects);
    }

    HwExecutePresentDisplayOnly((PVOID)ctx);
    return STATUS_SUCCESS;
}

void
HwExecutePresentDisplayOnly(
    HANDLE Context)
/*++

  Routine Description:

    The routine executes present's commands and report progress to the OS

  Arguments:

    Context - Context with present's command

  Return Value:

    None

--*/
{
    DoPresentMemory* ctx = (DoPresentMemory*)(Context);

    // Set up destination blt info
    BLT_INFO DstBltInfo;
    DstBltInfo.pBits = ctx->DstAddr;
    DstBltInfo.Pitch = ctx->DstStride;
    DstBltInfo.BitsPerPel = ctx->DstBitPerPixel;
    DstBltInfo.Offset.x = 0;
    DstBltInfo.Offset.y = 0;
    DstBltInfo.Rotation = ctx->Rotation;
    DstBltInfo.Width = ctx->SrcWidth;
    DstBltInfo.Height = ctx->SrcHeight;

    // Set up source blt info
    BLT_INFO SrcBltInfo;
    SrcBltInfo.pBits = ctx->SrcAddr;
    SrcBltInfo.Pitch = ctx->SrcPitch;
    SrcBltInfo.BitsPerPel = 32;
    SrcBltInfo.Offset.x = 0;
    SrcBltInfo.Offset.y = 0;
    SrcBltInfo.Rotation = D3DKMDT_VPPR_IDENTITY;
    if (ctx->Rotation == D3DKMDT_VPPR_ROTATE90 ||
        ctx->Rotation == D3DKMDT_VPPR_ROTATE270)
    {
        SrcBltInfo.Width = DstBltInfo.Height;
        SrcBltInfo.Height = DstBltInfo.Width;
    }
    else
    {
        SrcBltInfo.Width = DstBltInfo.Width;
        SrcBltInfo.Height = DstBltInfo.Height;
    }


    // Copy all the scroll rects from source image to video frame buffer.
    for (UINT i = 0; i < ctx->NumMoves; i++)
    {
        BltBits(&DstBltInfo,
        &SrcBltInfo,
        1, // NumRects
        &ctx->Moves[i].DestRect);
    }

    // Copy all the dirty rects from source image to video frame buffer.
    for (UINT i = 0; i < ctx->NumDirtyRects; i++)
    {

        BltBits(&DstBltInfo,
        &SrcBltInfo,
        1, // NumRects
        &ctx->DirtyRect[i]);
    }

    // Unmap unmap and unlock the pages.
#if 0
    if (ctx->Mdl)
    {
        MmUnlockPages(ctx->Mdl);
        IoFreeMdl(ctx->Mdl);
    }
#endif
    ExFreePool(ctx);
}
