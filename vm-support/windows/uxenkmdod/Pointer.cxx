/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "BDD.hxx"
#include "bochs.h"
#include "pointer.h"


const ULONG HWPTR_WIDTH_MAX     = 128;
const ULONG HWPTR_HEIGHT_MAX    = 128;

#define HWPTR_MEM_MAX           (HWPTR_WIDTH_MAX * HWPTR_HEIGHT_MAX * 4)
#define HWPTR_FLAG_HIDE         (1 << 0)
#define HWPTR_FLAG_MONOCHROME   (1 << 1)

struct hwptr_desc {
    ULONG pos_x, pos_y;
    ULONG width, height;
    ULONG hot_x, hot_y;
    ULONG64 bitmap_addr;
    ULONG64 bitmap_len;
    ULONG argb_offset;
    ULONG flags;
};


__forceinline VOID HwptrFlush(_In_ PUXEN_MOUSE_RESOURCES pMouse)
{
    UNREFERENCED_PARAMETER(pMouse);
    // FIXME(kris): IO port details should be taken from pMouse.
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_HWCURSOR_FLUSH);
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_DATA, 0);
}

NTSTATUS UxenSetPointerPosition(
    _In_ CONST DXGKARG_SETPOINTERPOSITION* pSetPointerPosition,
    _Inout_ PUXEN_MOUSE_RESOURCES pMouse)
{
    hwptr_desc* pHwptrDesc = (hwptr_desc*)pMouse->pHwptrDesc;
    static ULONG64 cnt = 0;

    ASSERT(NULL != pSetPointerPosition);
    ASSERT(pSetPointerPosition->VidPnSourceId < MAX_VIEWS);
    ASSERT(NULL != pMouse);

    pHwptrDesc->pos_x = pSetPointerPosition->X;
    pHwptrDesc->pos_y = pSetPointerPosition->Y;

    if (((1 == pSetPointerPosition->Flags.Visible)
         != (0 == (pHwptrDesc->flags & HWPTR_FLAG_HIDE))))
    {
        if (1 == pSetPointerPosition->Flags.Visible) {
            pHwptrDesc->flags &= ~HWPTR_FLAG_HIDE;
        } else {
            pHwptrDesc->flags |= HWPTR_FLAG_HIDE;
        }
        HwptrFlush(pMouse);
    }

    return STATUS_SUCCESS;
}

NTSTATUS UxenSetPointerShape(
    _In_ CONST DXGKARG_SETPOINTERSHAPE* pSetPointerShape,
    _Inout_ PUXEN_MOUSE_RESOURCES pMouse)
{
    hwptr_desc* pHwptrDesc = (hwptr_desc*)pMouse->pHwptrDesc;
    ULONG cbBitmapSize = 0;
    static ULONG64 cnt = 0;

    ASSERT(NULL != pSetPointerShape);
    ASSERT(NULL != pMouse);

    pHwptrDesc->width = pSetPointerShape->Width;
    pHwptrDesc->height = pSetPointerShape->Height;
    pHwptrDesc->hot_x = pSetPointerShape->XHot;
    pHwptrDesc->hot_y = pSetPointerShape->YHot;
    pHwptrDesc->flags &= ~HWPTR_FLAG_HIDE;

    if (pSetPointerShape->Flags.Color) {
        pHwptrDesc->flags &= ~HWPTR_FLAG_MONOCHROME;
        pHwptrDesc->argb_offset = 0;
        cbBitmapSize += pSetPointerShape->Pitch * pSetPointerShape->Height;

    } else if (pSetPointerShape->Flags.Monochrome) {
        pHwptrDesc->flags |= HWPTR_FLAG_MONOCHROME;
        pHwptrDesc->argb_offset = 0;
        cbBitmapSize = 2 * ((pSetPointerShape->Width + 7) / 8) * pSetPointerShape->Height;

    } else {
        ASSERT_FAIL("");
    }
    
    if ((cbBitmapSize < HWPTR_MEM_MAX) && (cbBitmapSize > 0)) {
        RtlCopyMemory(pMouse->pHwptrBitmap, pSetPointerShape->pPixels, cbBitmapSize);
        HwptrFlush(pMouse);
    } else {
        ASSERT_FAIL("");
    }

    return STATUS_SUCCESS;
}

VOID UxenQueryMousePointerCaps(
    _In_ DXGK_DRIVERCAPS* pDriverCaps)
{
    ASSERT(NULL != pDriverCaps);

    pDriverCaps->PointerCaps.Color = 1;
    pDriverCaps->PointerCaps.Monochrome = 1;
    pDriverCaps->PointerCaps.MaskedColor = 0;

    pDriverCaps->MaxPointerWidth = HWPTR_WIDTH_MAX;
    pDriverCaps->MaxPointerHeight = HWPTR_HEIGHT_MAX;
}

NTSTATUS UxenMousePointerInitialize(
    _In_ CONST DXGK_DEVICE_INFO* pDeviceInfo,
    _Inout_ PUXEN_MOUSE_RESOURCES pMouse)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    hwptr_desc* pHwptrDesc = NULL;
    PHYSICAL_ADDRESS highestAcceptableAddress = {(ULONG)-1, -1};

    UNREFERENCED_PARAMETER(pDeviceInfo);
    ASSERT(NULL != pMouse);
    ASSERT(NULL == pMouse->pHwptrDesc);
    ASSERT(NULL == pMouse->pHwptrBitmap);

    // Allocate hardware pointer descriptor.
    pMouse->pHwptrDesc = ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(hwptr_desc),
        BDDTAG);
    if (NULL == pMouse->pHwptrDesc) {
        ASSERT_FAIL("");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    pMouse->hwptrDescAddr = MmGetPhysicalAddress(pMouse->pHwptrDesc);

    // Allocate hardware pointer bitmap.
    pMouse->pHwptrBitmap = MmAllocateContiguousMemory(
        ROUND_TO_PAGES(HWPTR_MEM_MAX),
        highestAcceptableAddress);
    if (NULL == pMouse->pHwptrBitmap) {
        uxen_err("Failed to allocate 0x%x bytes", ROUND_TO_PAGES(HWPTR_MEM_MAX));
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlZeroMemory(pMouse->pHwptrBitmap, HWPTR_MEM_MAX);
    pMouse->hwptrBitmapAddr = MmGetPhysicalAddress(pMouse->pHwptrBitmap);

    pHwptrDesc = (hwptr_desc*)pMouse->pHwptrDesc;
    pHwptrDesc->bitmap_addr = pMouse->hwptrBitmapAddr.QuadPart;
    pHwptrDesc->bitmap_len = HWPTR_MEM_MAX;

    // FIXME(kris): there is currently no guarantee that physical address is below 4GB.
    ASSERT(!(pMouse->hwptrDescAddr.QuadPart & 0xFFFFFFFF00000000));
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_HWCURSOR_HI);
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_DATA,
                      (pMouse->hwptrDescAddr.QuadPart >> 16) & 0xFFFF);
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_HWCURSOR_LO);
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_DATA,
                      pMouse->hwptrDescAddr.QuadPart & 0xFFFF);

    status = STATUS_SUCCESS;

out:
    // Cleanup on failure.
    if (!NT_SUCCESS(status))
        UxenMousePointerCleanup(pMouse);
        
    return status;
}

VOID UxenMousePointerCleanup(
    _Inout_ PUXEN_MOUSE_RESOURCES pMouse)
{
    if (NULL != pMouse->pHwptrDesc) {
        ExFreePoolWithTag(pMouse->pHwptrDesc, BDDTAG);
        pMouse->pHwptrDesc = NULL;
        pMouse->hwptrDescAddr.QuadPart = NULL;
    }
    if (NULL != pMouse->pHwptrBitmap) {
        MmFreeContiguousMemory(pMouse->pHwptrBitmap);
        pMouse->pHwptrBitmap = NULL;
        pMouse->hwptrBitmapAddr.QuadPart = NULL;
    }
}
