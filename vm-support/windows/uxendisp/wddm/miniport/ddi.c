/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include <dispmprt.h>
#include <dderror.h>
#include <devioctl.h>

#include <debug.h>
#include <uxendisp_esc.h>
#include "uxendisp.h"
#include "dirty_rect.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE,uXenDispControlEtwLogging)
#pragma alloc_text(PAGE,uXenDispQueryAdapterInfo)
#pragma alloc_text(PAGE,uXenDispCreateDevice)
#pragma alloc_text(PAGE,uXenDispCreateAllocation)
#pragma alloc_text(PAGE,uXenDispDestroyAllocation)
#pragma alloc_text(PAGE,uXenDispDescribeAllocation)
#pragma alloc_text(PAGE,uXenDispGetStandardAllocationDriverData)
#pragma alloc_text(PAGE,uXenDispAcquireSwizzlingRange)
#pragma alloc_text(PAGE,uXenDispReleaseSwizzlingRange)
#pragma alloc_text(PAGE,uXenDispBuildPagingBuffer)
#pragma alloc_text(PAGE,uXenDispSetPalette)
#pragma alloc_text(PAGE,uXenDispSetPointerPosition)
#pragma alloc_text(PAGE,uXenDispSetPointerShape)
#pragma alloc_text(PAGE,uXenDispEscape)
#pragma alloc_text(PAGE,uXenDispQueryCurrentFence)
#pragma alloc_text(PAGE,uXenDispGetScanLine)
#pragma alloc_text(PAGE,uXenDispStopCapture)
#pragma alloc_text(PAGE,uXenDispControlInterrupt)
#pragma alloc_text(PAGE,uXenDispDestroyDevice)
#pragma alloc_text(PAGE,uXenDispOpenAllocation)
#pragma alloc_text(PAGE,uXenDispCloseAllocation)
#pragma alloc_text(PAGE,uXenDispRender)
#pragma alloc_text(PAGE,uXenDispPresent)
#pragma alloc_text(PAGE,uXenDispCreateContext)
#pragma alloc_text(PAGE,uXenDispDestroyContext)
#endif

static PVOID
map_fb(DEVICE_EXTENSION * dev, UXENDISP_DRIVER_ALLOCATION *drvalloc,
       SIZE_T *len)
{
    PVOID fb;
    PHYSICAL_ADDRESS addr;
    SIZE_T l;

    addr = dev->vram_phys;
    addr.QuadPart += drvalloc->addr.QuadPart;

    l = drvalloc->surface_desc.YResolution * drvalloc->surface_desc.Stride;
    fb = MmMapIoSpace(addr, l, MmNonCached);

    if (!fb) {
        uxen_err("failed to map rectangle from framebuffer");
        return NULL;
    }

    if (len)
        *len = l;

    return fb;
}

static __inline PUCHAR
rect_address(PUCHAR fb, UXENDISP_DRIVER_ALLOCATION *drvalloc,
             RECT *rect)
{
    return fb +
           (rect->top * drvalloc->surface_desc.Stride) +
           (rect->left * drvalloc->surface_desc.BytesPerPixel);
}

static void
subrect_blit(UXENDISP_DMA_PRESENT *dma_present,
             PUCHAR dst, PUCHAR src,
             SUBRECT *subrect,
             BOOLEAN v_overlap, BOOLEAN h_overlap)
{
    UXENDISP_DRIVER_ALLOCATION *srcalloc = dma_present->srcalloc;
    UXENDISP_DRIVER_ALLOCATION *dstalloc = dma_present->dstalloc;
    ULONG width;
    ULONG i;
    LONG delta_x, overlap;

    width = subrect->width * srcalloc->surface_desc.BytesPerPixel;

    if (v_overlap) {
        /* Copy bottom up */
        src += ((subrect->top + subrect->height - 1) *
                srcalloc->surface_desc.Stride) +
               (subrect->left * srcalloc->surface_desc.BytesPerPixel);
        dst += ((subrect->top + subrect->height - 1) *
                dstalloc->surface_desc.Stride) +
               (subrect->left * dstalloc->surface_desc.BytesPerPixel);
    } else {
        /* Copy top to bottom */
        src += (subrect->top * srcalloc->surface_desc.Stride) +
               (subrect->left * srcalloc->surface_desc.BytesPerPixel);
        dst += (subrect->top * dstalloc->surface_desc.Stride) +
               (subrect->left * dstalloc->surface_desc.BytesPerPixel);
    }

    if (h_overlap) {
        delta_x = (dma_present->dstrect.left - dma_present->srcrect.left) *
                  dstalloc->surface_desc.BytesPerPixel;
        overlap = width - delta_x;
        if (overlap < 0)
            h_overlap = FALSE;
    }

    for (i = 0; i < subrect->height; i++) {
        if (!h_overlap)
            /* Copy left to right */
            RtlCopyMemory(dst, src, width);
        else {
            /* Copy in to non-overlapping right to left segments */
            UCHAR *from, *to;

            from = dst;
            to = dst + delta_x;
            RtlCopyMemory(to, from, overlap);

            to = dst;
            from = src;
            RtlCopyMemory(to, from, delta_x);
        }

        if (v_overlap) {
            dst -= dstalloc->surface_desc.Stride;
            src -= srcalloc->surface_desc.Stride;
        } else {
            dst += dstalloc->surface_desc.Stride;
            src += srcalloc->surface_desc.Stride;
        }
    }
}

static NTSTATUS
do_blit(DEVICE_EXTENSION *dev, UXENDISP_DMA_PRESENT *dma_present)
{
    UXENDISP_DRIVER_ALLOCATION *srcalloc, *dstalloc;
    PVOID src_fb, dst_fb;
    SIZE_T src_len, dst_len;
    PUCHAR src, dst;
    BOOLEAN h_overlap, v_overlap;
    SUBRECT *subrects;
    ULONG i;

    srcalloc = dma_present->srcalloc;
    dstalloc = dma_present->dstalloc;

    src_fb = map_fb(dev, srcalloc, &src_len);
    if (!src_fb) {
        uxen_err("failed to map source framebuffer");
        return STATUS_NO_MEMORY;
    }
    dst_fb = map_fb(dev, dstalloc, &dst_len);
    if (!dst_fb) {
        uxen_err("failed to map destination framebuffer");
        MmUnmapIoSpace(src_fb, src_len);
        return STATUS_NO_MEMORY;
    }

    src = rect_address(src_fb, srcalloc, &dma_present->srcrect);
    dst = rect_address(dst_fb, dstalloc, &dma_present->dstrect);

    /* Determine direction of bitblt */
    v_overlap = FALSE;
    h_overlap = FALSE;
    if (dstalloc == srcalloc) {
        if (dma_present->srcrect.top < dma_present->dstrect.top)
            v_overlap = TRUE;
        else if (dma_present->srcrect.top == dma_present->dstrect.top &&
                 dma_present->srcrect.left < dma_present->dstrect.left &&
                 (dma_present->srcrect.left + dma_present->srcrect.right) >
                  dma_present->dstrect.left)
            h_overlap = TRUE;
    }

    subrects = (SUBRECT *)(dma_present + 1);
    for (i = 0; i < dma_present->subrect_count; i++)
        subrect_blit(dma_present, dst, src, &subrects[i], v_overlap, h_overlap);

    MmUnmapIoSpace(dst_fb, dst_len);
    MmUnmapIoSpace(src_fb, src_len);

    return STATUS_SUCCESS;
}

static NTSTATUS
do_command(DEVICE_EXTENSION *dev, PHYSICAL_ADDRESS dma_addr, SIZE_T length)
{
    UINT i;
    UXENDISP_DMA_PRESENT *dma_present;

    /* Map the DMA buffer */
    dma_present = MmMapIoSpace(dma_addr, length, MmNonCached);
    if (!dma_present) {
        uxen_err("Out of Memory");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (dma_present->flags.Flip) {
        for (i = 0; i < dev->crtc_count; i++) {
            if (dev->crtcs[i].sourceid != dma_present->srcalloc->sourceid)
                continue;
            uXenDispCrtcEnable(dev, &dev->crtcs[i]);
        }
    } else if (dma_present->flags.Blt) {
        /* Do the blit  */
        do_blit(dev, dma_present);
    }

    MmUnmapIoSpace(dma_present, length);

    return STATUS_SUCCESS;
}

static int
uXenDispBppFromDdiFormat(D3DDDIFORMAT format)
{
    switch (format) {
    case D3DDDIFMT_A8R8G8B8:
    case D3DDDIFMT_X8R8G8B8:
        return 32;
    case D3DDDIFMT_R8G8B8:
        return 24;
    case D3DDDIFMT_R5G6B5:
    case D3DDDIFMT_X1R5G5B5:
        return 16;
    }

    return -1;
}

VOID APIENTRY
uXenDispControlEtwLogging(BOOLEAN Enable, ULONG Flags, UCHAR Level)
{
    UNREFERENCED_PARAMETER(Enable);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Level);

    PAGED_CODE();

    /* Not using ETW logging at this point. */
}

NTSTATUS APIENTRY
uXenDispQueryAdapterInfo(CONST HANDLE hAdapter,
                         CONST DXGKARG_QUERYADAPTERINFO *
                         pQueryAdapterInfo)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *) hAdapter;
    NTSTATUS status = STATUS_SUCCESS;
    DXGK_DRIVERCAPS *pDriverCaps;
    DXGK_QUERYSEGMENTOUT *pQuerySegmentOut;

    uxen_msg("Enter");
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pQueryAdapterInfo))
        return STATUS_INVALID_PARAMETER;

    switch (pQueryAdapterInfo->Type) {
    case DXGKQAITYPE_UMDRIVERPRIVATE:
        if (pQueryAdapterInfo->OutputDataSize <
            sizeof(UXENDISP_UMDRIVERPRIVATE)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        /* Copy over the private data for our display driver */
        RtlMoveMemory(pQueryAdapterInfo->pOutputData,
                      &dev->private_data,
                      sizeof(UXENDISP_UMDRIVERPRIVATE));
        break;
    case DXGKQAITYPE_DRIVERCAPS:
        pDriverCaps = (DXGK_DRIVERCAPS *) pQueryAdapterInfo->pOutputData;
        RtlZeroMemory(pDriverCaps, sizeof *pDriverCaps);

        /* TODO some of these fields need more investigation */
        pDriverCaps->HighestAcceptableAddress.QuadPart = (ULONG64) - 1;
        pDriverCaps->MaxAllocationListSlotId = 74;
        pDriverCaps->ApertureSegmentCommitLimit = 0;
        pDriverCaps->MaxPointerWidth = 64;
        pDriverCaps->MaxPointerHeight = 64;
        pDriverCaps->PointerCaps.Value = 0;
        pDriverCaps->PointerCaps.Color = 1;
        pDriverCaps->PointerCaps.MaskedColor = 1;
        pDriverCaps->InterruptMessageNumber = 0;
        pDriverCaps->NumberOfSwizzlingRanges = 0;       /* none for now */
        pDriverCaps->MaxOverlays = 0;
        pDriverCaps->GammaRampCaps.Value = 0;
        pDriverCaps->GammaRampCaps.Gamma_Rgb256x3x16 = 1;
        pDriverCaps->PresentationCaps.Value = 0;
        pDriverCaps->MaxQueuedFlipOnVSync = 1;
        pDriverCaps->FlipCaps.Value = 0;
        pDriverCaps->FlipCaps.FlipOnVSyncWithNoWait = 1;
        pDriverCaps->FlipCaps.FlipOnVSyncMmIo = 1;
        pDriverCaps->SchedulingCaps.Value = 0;
        pDriverCaps->SchedulingCaps.MultiEngineAware = 1;
        pDriverCaps->MemoryManagementCaps.Value = 0;
        pDriverCaps->MemoryManagementCaps.PagingNode = 0;
        pDriverCaps->GpuEngineTopology.NbAsymetricProcessingNodes = 2;
        pDriverCaps->WDDMVersion = DXGKDDI_WDDMv1;

        break;
    case DXGKQAITYPE_QUERYSEGMENT:
        {
            PHYSICAL_ADDRESS baseaddr = { 0 };

            pQuerySegmentOut = (DXGK_QUERYSEGMENTOUT *)pQueryAdapterInfo->pOutputData;

            /* First call */
            if (!pQuerySegmentOut->pSegmentDescriptor) {
                pQuerySegmentOut->NbSegment = 1;
                break;
            }

            RtlZeroMemory(pQuerySegmentOut->pSegmentDescriptor,
                          pQuerySegmentOut->NbSegment * sizeof(DXGK_SEGMENTDESCRIPTOR));

            /* Setup one linear aperture-space segment */
            pQuerySegmentOut->pSegmentDescriptor[0].BaseAddress = baseaddr;
            pQuerySegmentOut->pSegmentDescriptor[0].CpuTranslatedAddress = dev->vram_phys;
            pQuerySegmentOut->pSegmentDescriptor[0].Size = dev->vram_len;
            pQuerySegmentOut->pSegmentDescriptor[0].CommitLimit = dev->vram_len;
            pQuerySegmentOut->pSegmentDescriptor[0].Flags.Value = 0;
            pQuerySegmentOut->pSegmentDescriptor[0].Flags.CpuVisible = 1;
            //pQuerySegmentOut->pSegmentDescriptor[0].Flags.Aperture = 1;
            pQuerySegmentOut->PagingBufferSegmentId = 0;
            pQuerySegmentOut->PagingBufferSize = 64 * 1024; /* TODO  */
            pQuerySegmentOut->PagingBufferPrivateDataSize = 0;

            break;
        }
    default:
        uxen_msg("DXGKARG_QUERYADAPTERINFO type unrecognized - type: %d",
                 pQueryAdapterInfo->Type);
        status = STATUS_NOT_SUPPORTED;
    };

    uxen_msg("Leave");
    return status;
}

NTSTATUS APIENTRY
uXenDispCreateDevice(CONST HANDLE hAdapter,
                     DXGKARG_CREATEDEVICE *pCreateDevice)
{
    UXENDISP_D3D_DEVICE *d3ddev;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pCreateDevice))
        return STATUS_INVALID_PARAMETER;

    d3ddev = ExAllocatePoolWithTag(NonPagedPool,
                                   sizeof(UXENDISP_D3D_DEVICE),
                                   UXENDISP_TAG);
    if (!d3ddev)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(d3ddev, sizeof(UXENDISP_D3D_DEVICE));

    d3ddev->devhdl = pCreateDevice->hDevice;
    d3ddev->dev = (DEVICE_EXTENSION *)hAdapter;

    pCreateDevice->hDevice = d3ddev;

    return STATUS_SUCCESS;
}

static void
uXenDispSetDriverAllocation(DEVICE_EXTENSION * dev,
                            D3DDDI_VIDEO_PRESENT_SOURCE_ID sourceID,
                            PUXENDISP_DRIVER_ALLOCATION pDrvAllocation,
                            BOOLEAN flag)
{
    KIRQL irql;

    KeAcquireSpinLock(&dev->sources_lock, &irql);
    if (flag && dev->sources[sourceID].in_use) {
        uxen_err("Failed to associate primary allocation with a VidPN source",
                 sourceID);
    } else {
        dev->sources[sourceID].in_use = flag;
        dev->sources[sourceID].primary_allocation = pDrvAllocation;
        if (pDrvAllocation)
            pDrvAllocation->state |= UXENDISP_ALLOCATION_STATE_ASSIGNED;
    }
    KeReleaseSpinLock(&dev->sources_lock, irql);
}

NTSTATUS APIENTRY
uXenDispCreateAllocation(CONST HANDLE hAdapter,
                         DXGKARG_CREATEALLOCATION *pCreateAllocation)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    UXENDISP_D3D_ALLOCATION *d3dalloc;
    UXENDISP_DRIVER_ALLOCATION *drvalloc;
    DXGK_ALLOCATIONINFO *alloc_info;
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pCreateAllocation))
        return STATUS_INVALID_PARAMETER;

    alloc_info = pCreateAllocation->pAllocationInfo;

    /* Not using outer pPrivateDriverData struct, loop and fill in allocations. */
    for (i = 0; i < pCreateAllocation->NumAllocations; i++, alloc_info++) {
        drvalloc = ExAllocatePoolWithTag(NonPagedPool,
                                         sizeof(UXENDISP_DRIVER_ALLOCATION),
                                         UXENDISP_TAG);
        if (!drvalloc) {
            status = STATUS_NO_MEMORY;
            break;
        }
        RtlZeroMemory(drvalloc, sizeof(UXENDISP_DRIVER_ALLOCATION));
        alloc_info->hAllocation = (HANDLE)drvalloc;

        /*
         * Get the allocation private data passed in from UM or as a
         * standard allocation from the directx kernel and copy the
         * bits the driver needs.
         */
        d3dalloc = (UXENDISP_D3D_ALLOCATION *)alloc_info->pPrivateDriverData;
        if (!d3dalloc ||
            (alloc_info->PrivateDriverDataSize < sizeof(UXENDISP_D3D_ALLOCATION))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        /* Validate the allocation information passed in */
        if (!d3dalloc->SurfaceDesc.BytesPerPixel ||
            !d3dalloc->SurfaceDesc.XResolution ||
            !d3dalloc->SurfaceDesc.YResolution) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

#if 0
        /*
         * Should always be using MaxStrideAlignment + 1 for all allocations.
         * Note that though the source ID is known at this point, the target
         * is potentially not yet known or could change. Only during the
         * DxgkDdiCommitVidPn are sources tied to targets.
         */
        if (d3dalloc->ByteAlignment != (dev->MaxStrideAlignment + 1)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
#endif

        /*
         * Update the driver allocation structure that is now associated
         * with this particular dx kernel allocation.
         */
        drvalloc->type = d3dalloc->Type;
        drvalloc->state = UXENDISP_ALLOCATION_STATE_NONE;
        drvalloc->sourceid = d3dalloc->VidPnSourceId;
        drvalloc->surface_desc = d3dalloc->SurfaceDesc;
        drvalloc->align = d3dalloc->ByteAlignment;

        /* If this is a primary allocation, it will have an association with a VidPN source so */
        /* set this up here. */
        if (d3dalloc->Primary) {
            ASSERT(d3dalloc->VidPnSourceId < dev->crtc_count);
            uXenDispSetDriverAllocation(dev, d3dalloc->VidPnSourceId,
                                        drvalloc, TRUE);
        } else if (d3dalloc->Type == UXENDISP_SHADOWSURFACE_TYPE) {
            dev->sources[0].shadow_allocation = drvalloc;
        }

        /* Fill in allocation information */
        alloc_info->Alignment = drvalloc->align;
        alloc_info->Size = d3dalloc->SurfaceDesc.Stride *
                           d3dalloc->SurfaceDesc.YResolution;
        alloc_info->PitchAlignedSize = 0;
        alloc_info->HintedBank.Value = 0;
        alloc_info->PreferredSegment.Value = 0;
        alloc_info->SupportedReadSegmentSet = 1;
        alloc_info->SupportedWriteSegmentSet = 1;
        alloc_info->EvictionSegmentSet = 0;
        alloc_info->MaximumRenamingListLength = 0;
        alloc_info->pAllocationUsageHint = NULL;
        alloc_info->Flags.Value = 0;
        alloc_info->Flags.CpuVisible = 1;
        alloc_info->AllocationPriority = D3DDDI_ALLOCATIONPRIORITY_NORMAL;
    }

    /* NOTE not using hResource now */

    if (!NT_SUCCESS(status)) {
        alloc_info = pCreateAllocation->pAllocationInfo;
        for (i = 0; i < pCreateAllocation->NumAllocations; i++, alloc_info++) {
            if (alloc_info->hAllocation != NULL) {
                ExFreePoolWithTag(alloc_info->hAllocation, UXENDISP_TAG);
                alloc_info->hAllocation = NULL;
            }
        }
    }

    return status;
}

NTSTATUS APIENTRY
uXenDispDestroyAllocation(CONST HANDLE hAdapter,
                          CONST DXGKARG_DESTROYALLOCATION *pDestroyAllocation)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    UXENDISP_DRIVER_ALLOCATION *drvalloc;
    ULONG i;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pDestroyAllocation))
        return STATUS_INVALID_PARAMETER;

    for (i = 0; i < pDestroyAllocation->NumAllocations; i++) {
        /* Primary allocations have associated VidPN sources that need to be freed */
        drvalloc = (UXENDISP_DRIVER_ALLOCATION *)
            pDestroyAllocation->pAllocationList[i];
        if (drvalloc->sourceid != D3DDDI_ID_UNINITIALIZED) {
            ASSERT(drvalloc->sourceid < dev->crtc_count);
            uXenDispSetDriverAllocation(dev, drvalloc->sourceid,
                                        NULL, FALSE);
        }

        ExFreePoolWithTag(pDestroyAllocation->pAllocationList[i],
                          UXENDISP_TAG);
    }

    if (pDestroyAllocation->Flags.DestroyResource &&
        pDestroyAllocation->hResource)
        ExFreePoolWithTag(pDestroyAllocation->hResource, UXENDISP_TAG);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispDescribeAllocation(CONST HANDLE hAdapter,
                           DXGKARG_DESCRIBEALLOCATION * pDescribeAlloc)
{
    UXENDISP_DRIVER_ALLOCATION *drvalloc;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pDescribeAlloc))
        return STATUS_INVALID_PARAMETER;

    drvalloc = (UXENDISP_DRIVER_ALLOCATION *)pDescribeAlloc->hAllocation;
    if (!drvalloc)
        return STATUS_INVALID_PARAMETER;

    pDescribeAlloc->Width = drvalloc->surface_desc.XResolution;
    pDescribeAlloc->Height = drvalloc->surface_desc.YResolution;
    pDescribeAlloc->Format = drvalloc->surface_desc.Format;
    pDescribeAlloc->RefreshRate = drvalloc->surface_desc.RefreshRate;

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispGetStandardAllocationDriverData(CONST HANDLE hAdapter,
                                        DXGKARG_GETSTANDARDALLOCATIONDRIVERDATA* pStandardAllocationDriverData)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    UXENDISP_D3D_ALLOCATION *d3dalloc;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pStandardAllocationDriverData))
        return STATUS_INVALID_PARAMETER;

    /* Size reguest */
    if (!pStandardAllocationDriverData->pAllocationPrivateDriverData) {
        pStandardAllocationDriverData->AllocationPrivateDriverDataSize = sizeof(UXENDISP_D3D_ALLOCATION);
        return STATUS_SUCCESS;
    }

    if (pStandardAllocationDriverData->AllocationPrivateDriverDataSize != sizeof(UXENDISP_D3D_ALLOCATION))
        return STATUS_INVALID_PARAMETER;

    /*
     * This routine is used to describe the private data passed to standard
     * allocations when the uXenDisp display DLL is not the source of the
     * allocation. The non-primary surfaces below use the max stride and
     * alignment values for all CRTC so they are usable for any target.
     */
    d3dalloc = (UXENDISP_D3D_ALLOCATION *)pStandardAllocationDriverData->pAllocationPrivateDriverData;
    pStandardAllocationDriverData->ResourcePrivateDriverDataSize = 0;

    switch (pStandardAllocationDriverData->StandardAllocationType) {
    case D3DKMDT_STANDARDALLOCATION_SHAREDPRIMARYSURFACE:
        {
            D3DKMDT_SHAREDPRIMARYSURFACEDATA *pSPSD;
            int bpp;

            pSPSD = pStandardAllocationDriverData->pCreateSharedPrimarySurfaceData;
            bpp = uXenDispBppFromDdiFormat(pSPSD->Format);

            d3dalloc->Type = UXENDISP_SHAREDPRIMARYSURFACE_TYPE;
            d3dalloc->Primary = TRUE;
            d3dalloc->VidPnSourceId = pSPSD->VidPnSourceId;
            d3dalloc->SurfaceDesc.XResolution = pSPSD->Width;
            d3dalloc->SurfaceDesc.YResolution = pSPSD->Height;
            d3dalloc->SurfaceDesc.BytesPerPixel = (bpp + 7) / 8;
            d3dalloc->SurfaceDesc.Stride = ((bpp + 7) / 8) * pSPSD->Width;
            d3dalloc->SurfaceDesc.Format = pSPSD->Format;
            d3dalloc->SurfaceDesc.RefreshRate = pSPSD->RefreshRate;
            d3dalloc->ByteAlignment = 1;
            return STATUS_SUCCESS;
        }
    case D3DKMDT_STANDARDALLOCATION_SHADOWSURFACE:
        {
            D3DKMDT_SHADOWSURFACEDATA *pSSD;
            int bpp;

            pSSD = pStandardAllocationDriverData->pCreateShadowSurfaceData;
            bpp = uXenDispBppFromDdiFormat(pSSD->Format);

            d3dalloc->Type = UXENDISP_SHADOWSURFACE_TYPE;
            d3dalloc->Primary = FALSE;
            d3dalloc->VidPnSourceId = D3DDDI_ID_UNINITIALIZED;
            d3dalloc->SurfaceDesc.XResolution = pSSD->Width;
            d3dalloc->SurfaceDesc.YResolution = pSSD->Height;
            d3dalloc->SurfaceDesc.BytesPerPixel = (bpp + 7) / 8;
            d3dalloc->SurfaceDesc.Stride = ((bpp + 7) / 8) * pSSD->Width;
            d3dalloc->SurfaceDesc.Format = pSSD->Format;
            d3dalloc->SurfaceDesc.RefreshRate.Numerator = 60000;
            d3dalloc->SurfaceDesc.RefreshRate.Denominator = 1000;
            d3dalloc->ByteAlignment = 1;

            /* Return the stride/pitch requirement */
            pSSD->Pitch = d3dalloc->SurfaceDesc.Stride;
            return STATUS_SUCCESS;
        }
    case D3DKMDT_STANDARDALLOCATION_STAGINGSURFACE:
        {
            D3DKMDT_STAGINGSURFACEDATA *pSSD;
            int bpp;

            pSSD = pStandardAllocationDriverData->pCreateStagingSurfaceData;

            d3dalloc->Type = UXENDISP_STAGINGSURFACE_TYPE;
            d3dalloc->Primary = FALSE;
            d3dalloc->VidPnSourceId = D3DDDI_ID_UNINITIALIZED;
            d3dalloc->SurfaceDesc.XResolution = pSSD->Width;
            d3dalloc->SurfaceDesc.YResolution = pSSD->Height;
            d3dalloc->SurfaceDesc.BytesPerPixel = 4;
            d3dalloc->SurfaceDesc.Stride = 4 * pSSD->Width;
            d3dalloc->SurfaceDesc.Format = D3DDDIFMT_X8B8G8R8;
            d3dalloc->SurfaceDesc.RefreshRate.Numerator = 60000;
            d3dalloc->SurfaceDesc.RefreshRate.Denominator = 1000;
            d3dalloc->ByteAlignment = 1;

            /* Return the stride/pitch requirement */
            pSSD->Pitch = d3dalloc->SurfaceDesc.Stride;
            return STATUS_SUCCESS;
        }
    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispAcquireSwizzlingRange(CONST HANDLE hAdapter,
                              DXGKARG_ACQUIRESWIZZLINGRANGE *
                              pAcquireSwizzlingRange)
{
    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pAcquireSwizzlingRange))
        return STATUS_INVALID_PARAMETER;

    /* TODO implement later. */

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispReleaseSwizzlingRange(CONST HANDLE hAdapter,
                              CONST DXGKARG_RELEASESWIZZLINGRANGE *
                              pReleaseSwizzlingRange)
{
    PAGED_CODE();

    uxen_msg("Enter");
    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pReleaseSwizzlingRange))
        return STATUS_INVALID_PARAMETER;

    /* TODO implement later. */

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispPatch(CONST HANDLE hAdapter, CONST DXGKARG_PATCH * pPatch)
{
    UXENDISP_DMA_PRESENT *dma_present;
    ULONG size;
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pPatch))
        return STATUS_INVALID_PARAMETER;

    /* No patching locations or allocation list for paging operations. */
    if (pPatch->Flags.Paging == 1)
        return STATUS_SUCCESS;

    /*
     * Patching addresses for source and destination that were potentially
     * mapped in in a call to uXenDispBuildPagingBuffer() prior to this
     * call being made.
     */
    ASSERT(pPatch->AllocationListSize == 3);
    ASSERT(pPatch->pAllocationList[DXGK_PRESENT_SOURCE_INDEX].SegmentId == 1);
    ASSERT(pPatch->pAllocationList[DXGK_PRESENT_DESTINATION_INDEX].SegmentId == 1);

    size = pPatch->DmaBufferSubmissionEndOffset - pPatch->DmaBufferSubmissionStartOffset;
    dma_present = (UXENDISP_DMA_PRESENT *)pPatch->pDmaBuffer;
    if (dma_present->size != size) {
        uxen_debug("Invalid DMA buffer size: 0x%x expecting: 0x%x",
                   size, dma_present->size);
        return STATUS_UNSUCCESSFUL;
    }

    /* N.B. store the physical address of the allocation. Not currently used. */
    dma_present->srcalloc->addr =
        pPatch->pAllocationList[DXGK_PRESENT_SOURCE_INDEX].PhysicalAddress;
    dma_present->dstalloc->addr =
        pPatch->pAllocationList[DXGK_PRESENT_DESTINATION_INDEX].PhysicalAddress;
    uxen_msg("Leave");

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispSubmitCommand(CONST HANDLE hAdapter,
                      CONST DXGKARG_SUBMITCOMMAND *pSubmitCommand)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    DXGKARGCB_NOTIFY_INTERRUPT_DATA notify = { 0 };
    PHYSICAL_ADDRESS addr;
    SIZE_T length;

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pSubmitCommand))
        return STATUS_INVALID_PARAMETER;

    /* Get DMA Address and length */
    addr = pSubmitCommand->DmaBufferPhysicalAddress;
    addr.QuadPart += pSubmitCommand->DmaBufferSubmissionStartOffset;
    length = pSubmitCommand->DmaBufferSubmissionEndOffset -
             pSubmitCommand->DmaBufferSubmissionStartOffset;

    do_command(dev, addr, length);

    dev->current_fence = pSubmitCommand->SubmissionFenceId;

    notify.InterruptType = DXGK_INTERRUPT_DMA_COMPLETED;
    notify.DmaCompleted.SubmissionFenceId = dev->current_fence;
    dev->dxgkif.DxgkCbNotifyInterrupt(dev->dxgkhdl, &notify);
    dev->dxgkif.DxgkCbQueueDpc(dev->dxgkhdl);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispPreemptCommand(CONST HANDLE hAdapter,
                       CONST DXGKARG_PREEMPTCOMMAND *pPreemptCommand)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    DXGKARGCB_NOTIFY_INTERRUPT_DATA notify = { 0 };
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pPreemptCommand))
        return STATUS_INVALID_PARAMETER;

    notify.InterruptType = DXGK_INTERRUPT_DMA_PREEMPTED;
    notify.DmaPreempted.PreemptionFenceId = pPreemptCommand->PreemptionFenceId;
    notify.DmaPreempted.LastCompletedFenceId = dev->current_fence;
    notify.DmaPreempted.NodeOrdinal = pPreemptCommand->NodeOrdinal;
    notify.DmaPreempted.EngineOrdinal = pPreemptCommand->EngineOrdinal;
    dev->dxgkif.DxgkCbNotifyInterrupt(dev->dxgkhdl, &notify);
    dev->dxgkif.DxgkCbQueueDpc(dev->dxgkhdl);

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

static NTSTATUS
xfer(DEVICE_EXTENSION *dev,
     MDL *srcmdl, LARGE_INTEGER srcaddr,
     MDL *dstmdl, LARGE_INTEGER dstaddr,
     UINT xferoffset, UINT mdloffset,
     SIZE_T size)
{
    UCHAR *src = NULL, *dst = NULL;
    PHYSICAL_ADDRESS addr;
    NTSTATUS status;
    uxen_msg("Enter");

    if (srcmdl) {
        src = MmGetSystemAddressForMdlSafe(srcmdl, HighPagePriority);
        if (!src) {
            status = STATUS_NO_MEMORY;
            goto err;
        }
        src += mdloffset * PAGE_SIZE;
    } else {
        addr = dev->vram_phys;
        addr.QuadPart += srcaddr.QuadPart + xferoffset;
        src = MmMapIoSpace(addr, size, MmNonCached);
        if (!src) {
            status = STATUS_NO_MEMORY;
            goto err;
        }
    }

    if (dstmdl) {
        dst = MmGetSystemAddressForMdlSafe(dstmdl, HighPagePriority);
        if (!dst) {
            status = STATUS_NO_MEMORY;
            goto err;
        }
        dst += mdloffset * PAGE_SIZE;
    } else {
        addr = dev->vram_phys;
        addr.QuadPart += /*dstaddr.QuadPart +*/ xferoffset;
        dst = MmMapIoSpace(addr, size, MmNonCached);
        if (!dst) {
            status = STATUS_NO_MEMORY;
            goto err;
        }
    }

    RtlMoveMemory(dst, src, size);
    status = STATUS_SUCCESS;

err:
    if (src && !srcmdl)
        MmUnmapIoSpace(src, size);

    if (dst && !dstmdl)
        MmUnmapIoSpace(dst, size);

    uxen_msg("Leave");
    return status;
}

NTSTATUS APIENTRY
uXenDispBuildPagingBuffer(CONST HANDLE hAdapter,
                          DXGKARG_BUILDPAGINGBUFFER *pBuildPagingBuffer)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *) hAdapter;
    NTSTATUS status = STATUS_SUCCESS;
    MDL *srcmdl = NULL, *dstmdl = NULL;
    LARGE_INTEGER srcaddr = { 0 } , dstaddr = { 0 };

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pBuildPagingBuffer))
        return STATUS_INVALID_PARAMETER;

    switch (pBuildPagingBuffer->Operation) {
    case DXGK_OPERATION_TRANSFER:
        if (!pBuildPagingBuffer->Transfer.TransferSize)
            break;              /* nothing to do */

        if ((pBuildPagingBuffer->Transfer.Source.SegmentId != 0) &&
            (pBuildPagingBuffer->Transfer.Source.SegmentId != 1)) {
            /* This is bad, SNO */
            ASSERT(((pBuildPagingBuffer->Transfer.Source.SegmentId == 0) ||
                    (pBuildPagingBuffer->Transfer.Source.SegmentId == 1)));
            uxen_err("DXGK_OPERATION_TRANSFER invalid source segment %d.",
                     pBuildPagingBuffer->Transfer.Source.SegmentId);
            break;
        }

        if ((pBuildPagingBuffer->Transfer.Destination.SegmentId != 0) &&
            (pBuildPagingBuffer->Transfer.Destination.SegmentId != 1)) {
            /* This is bad, SNO */
            ASSERT(((pBuildPagingBuffer->Transfer.Destination.SegmentId == 0) ||
                   (pBuildPagingBuffer->Transfer.Destination.SegmentId == 1)));
            uxen_err("DXGK_OPERATION_TRANSFER invalid destination segment %d.",
                     pBuildPagingBuffer->Transfer.Destination.SegmentId);
            break;
        }

        /* Not expecting any swizzle flags set */
        if ((pBuildPagingBuffer->Transfer.Flags.Swizzle == 1) ||
            (pBuildPagingBuffer->Transfer.Flags.Unswizzle == 1)) {
            ASSERT(((pBuildPagingBuffer->Transfer.Flags.Swizzle == 0) &&
                    (pBuildPagingBuffer->Transfer.Flags.Unswizzle == 0)));
            uxen_err("DXGK_OPERATION_TRANSFER unexpected flags set: 0x%x.",
                     pBuildPagingBuffer->Transfer.Flags);
            break;
        }

        /* Call routine to do the transfer */
        if (!pBuildPagingBuffer->Transfer.Source.SegmentId)
            srcmdl = pBuildPagingBuffer->Transfer.Source.pMdl;
        else
            srcaddr = pBuildPagingBuffer->Transfer.Source.SegmentAddress;

        if (!pBuildPagingBuffer->Transfer.Destination.SegmentId)
            dstmdl = pBuildPagingBuffer->Transfer.Destination.pMdl;
        else
            dstaddr = pBuildPagingBuffer->Transfer.Destination.SegmentAddress;

        status = STATUS_SUCCESS;
        status = xfer(dev,
                      srcmdl,
                      srcaddr,
                      dstmdl,
                      dstaddr,
                      pBuildPagingBuffer->Transfer.TransferOffset,
                      pBuildPagingBuffer->Transfer.MdlOffset,
                      pBuildPagingBuffer->Transfer.TransferSize);

        /* This should not fail unless something is seriously wrong. */
        ASSERT(NT_SUCCESS(status));
        break;
    case DXGK_OPERATION_FILL:
        //ASSERT(pBuildPagingBuffer->Operation != DXGK_OPERATION_FILL);
        uxen_msg("Illegal DXGK_OPERATION_FILL operation.");
        break;
    case DXGK_OPERATION_DISCARD_CONTENT:
        /* Not needed */
        break;
    case DXGK_OPERATION_READ_PHYSICAL:
    case DXGK_OPERATION_WRITE_PHYSICAL:
        /*
         * The WDK documentation is vague on this but these are actually
         * memory barrier reads and writes for GPU access to the AGP aperture.
         * We do not use AGP so...
         */
        break;
    case DXGK_OPERATION_MAP_APERTURE_SEGMENT:
        ASSERT(0);
        break;
    case DXGK_OPERATION_UNMAP_APERTURE_SEGMENT:
        ASSERT(0);
        break;
    case DXGK_OPERATION_SPECIAL_LOCK_TRANSFER:
        /* Not using UseAlternateVA */
        break;
    default:
        break;
    };

    /* Always return success - any failures (which should not occur) will be traced. */
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispSetPalette(CONST HANDLE hAdapter,
                   CONST DXGKARG_SETPALETTE *pSetPalette)
{
    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pSetPalette))
        return STATUS_INVALID_PARAMETER;

    /* TODO may not have to deal with this */
    uxen_msg("Leave");

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispSetPointerPosition(CONST HANDLE hAdapter,
                           CONST DXGKARG_SETPOINTERPOSITION *pSetPointerPosition)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pSetPointerPosition))
        return STATUS_INVALID_PARAMETER;

    if (pSetPointerPosition->Flags.Visible) {
        uxdisp_write(dev, UXDISP_REG_CURSOR_CRTC,
                     pSetPointerPosition->VidPnSourceId);
        uxdisp_write(dev, UXDISP_REG_CURSOR_POS_X, pSetPointerPosition->X);
        uxdisp_write(dev, UXDISP_REG_CURSOR_POS_Y, pSetPointerPosition->Y);

        if (!dev->cursor_visible) {
            uxdisp_write(dev, UXDISP_REG_CURSOR_ENABLE, UXDISP_CURSOR_SHOW);
            dev->cursor_visible = TRUE;
        }
    } else if (dev->cursor_visible) {
        uxdisp_write(dev, UXDISP_REG_CURSOR_ENABLE, 0);
        dev->cursor_visible = FALSE;
    }

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispSetPointerShape(CONST HANDLE hAdapter,
                        CONST DXGKARG_SETPOINTERSHAPE * pSetPointerShape)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    ULONG width = 0;
    ULONG y, height = 0;
    ULONG len;
    UCHAR *s, *d;
    ULONG flags = 0;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pSetPointerShape))
        return STATUS_INVALID_PARAMETER;

    width = pSetPointerShape->Width;
    height = pSetPointerShape->Height;

    if (pSetPointerShape->Flags.Color) {
        len = 4 * width * height; /* ARGB data */
        len += ((width + 7) / 8) * height; /* AND mask */

        if (len > (UXDISP_REG_CRTC(0) - UXDISP_REG_CURSOR_DATA))
            return STATUS_NO_MEMORY;

        s = (UCHAR *)pSetPointerShape->pPixels;
        d = dev->mmio + UXDISP_REG_CURSOR_DATA;
        for (y = 0; y < height; y++) {
            RtlCopyMemory(d, s, (width + 7) / 8);
            d += (width + 7) / 8;
            s += (width + 7) / 8;
        }
        s = (UCHAR *)pSetPointerShape->pPixels;
        s += ((((width + 7) / 8) * height) + 3) & ~3;
        for (y = 0; y < height; y++) {
            RtlCopyMemory(d, s, 4 * width);
            d += 4 * width;
            s += pSetPointerShape->Pitch;
        }
    } else {
        len = ((width + 7) / 8) * height * 2;

        if (len > (UXDISP_REG_CRTC(0) - UXDISP_REG_CURSOR_DATA))
            return STATUS_NO_MEMORY;

        s = (UCHAR *)pSetPointerShape->pPixels;
        d = dev->mmio + UXDISP_REG_CURSOR_DATA;
        for (y = 0; y < (height * 2); y++) {
            RtlCopyMemory(d, s, (width + 7) / 8);
            d += (width + 7) / 8;
            s += (width + 7) / 8;
        }

        flags |= UXDISP_CURSOR_FLAG_1BPP;
    }

    flags |= UXDISP_CURSOR_FLAG_MASK_PRESENT;

    uxdisp_write(dev, UXDISP_REG_CURSOR_WIDTH, pSetPointerShape->Width);
    uxdisp_write(dev, UXDISP_REG_CURSOR_HEIGHT, pSetPointerShape->Height);
    uxdisp_write(dev, UXDISP_REG_CURSOR_HOT_X, pSetPointerShape->XHot);
    uxdisp_write(dev, UXDISP_REG_CURSOR_HOT_Y, pSetPointerShape->YHot);
    uxdisp_write(dev, UXDISP_REG_CURSOR_CRTC, 0);
    uxdisp_write(dev, UXDISP_REG_CURSOR_FLAGS, flags);
    uxdisp_write(dev, UXDISP_REG_CURSOR_ENABLE, UXDISP_CURSOR_SHOW);

    dev->cursor_visible = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY CALLBACK uXenDispResetFromTimeout(CONST HANDLE hAdapter)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    ULONG ControlReg;
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter))
        return STATUS_INVALID_PARAMETER;

    /* Disable interrupts */
    uxdisp_write(dev, UXDISP_REG_INTERRUPT_ENABLE, 0);
    uxen_msg("Leave");

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY CALLBACK
uXenDispRestartFromTimeout(CONST HANDLE hAdapter)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter))
        return STATUS_INVALID_PARAMETER;
    uxen_msg("Leave");

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispEscape(CONST HANDLE hAdapter, CONST DXGKARG_ESCAPE *pEscape)
{
    NTSTATUS status;
    UXENDISPCustomMode mode;
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    DXGK_CHILD_STATUS child_status;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) || !ARGUMENT_PRESENT(pEscape))
        return STATUS_INVALID_PARAMETER;

    /* for now we can just assume that there is only one kind of escape calls */
    if (pEscape->PrivateDriverDataSize == sizeof(mode)) {
        mode = *((UXENDISPCustomMode*)pEscape->pPrivateDriverData);
        dev->crtcs[0].next_mode.xres = mode.width;
        dev->crtcs[0].next_mode.yres = mode.height;
        dev->crtcs[0].next_mode.stride = mode.width * 4;
        dev->crtcs[0].next_mode.fmt = 0;
        dev->crtcs[0].next_mode.flags = UXENDISP_MODE_FLAG_PREFERRED;

        /* disconnect monitor... */
        child_status.Type = StatusConnection;
        child_status.ChildUid = 0;
        child_status.HotPlug.Connected = FALSE;
        status = dev->dxgkif.DxgkCbIndicateChildStatus(dev->dxgkhdl, &child_status);
        if (!NT_SUCCESS(status)) {
            ASSERT_FAIL("DxgkCbIndicateChildStatus(off) failed: %d\n", status);
        }

        /* ...and connect it again */
        child_status.Type = StatusConnection;
        child_status.ChildUid = 0;
        child_status.HotPlug.Connected = TRUE;
        status = dev->dxgkif.DxgkCbIndicateChildStatus(dev->dxgkhdl, &child_status);
        if (!NT_SUCCESS(status)) {
            ASSERT_FAIL("DxgkCbIndicateChildStatus(on) failed: %d\n", status);
        }
    } else {
        status = STATUS_INVALID_PARAMETER;
    }

    return status;
}

NTSTATUS APIENTRY
uXenDispCollectDbgInfo(HANDLE hAdapter,
                       CONST DXGKARG_COLLECTDBGINFO *pCollectDbgInfo)
{
#define DBG_INFO_UNKNOWN "************: uXenDisp - Unknown reason."
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pCollectDbgInfo))
        return STATUS_INVALID_PARAMETER;

    if (pCollectDbgInfo->BufferSize >= sizeof(DBG_INFO_UNKNOWN)) {
        ULONG *buf;

        RtlCopyMemory(pCollectDbgInfo->pBuffer, DBG_INFO_UNKNOWN,
                      sizeof(DBG_INFO_UNKNOWN));

        buf = (ULONG *)pCollectDbgInfo->pBuffer;
        buf[0] = DXGK_SECONDARY_BUCKETING_TAG;
        buf[1] = 0xBADC0DE;
        buf[2] = pCollectDbgInfo->Reason;
    uxen_msg("Leave");

        return STATUS_SUCCESS;
    }
    uxen_msg("Leave");

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS APIENTRY
uXenDispQueryCurrentFence(CONST HANDLE hAdapter,
                          DXGKARG_QUERYCURRENTFENCE *pCurrentFence)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;

    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pCurrentFence))
        return STATUS_INVALID_PARAMETER;

    pCurrentFence->CurrentFence = dev->current_fence;
    uxen_msg("Leave");

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispGetScanLine(CONST HANDLE hAdapter,
                    DXGKARG_GETSCANLINE *pGetScanLine)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;

    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pGetScanLine))
        return STATUS_INVALID_PARAMETER;

    ASSERT(pGetScanLine->VidPnTargetId < dev->crtc_count);

    pGetScanLine->InVerticalBlank = TRUE;
    pGetScanLine->ScanLine = (UINT)-1;
    uxen_msg("Leave");

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispStopCapture(CONST HANDLE hAdapter,
                    CONST DXGKARG_STOPCAPTURE *pStopCapture)
{
    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pStopCapture))
        return STATUS_INVALID_PARAMETER;

    /* Probably don't care about this one. */

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispControlInterrupt(CONST HANDLE hAdapter,
                         CONST DXGK_INTERRUPT_TYPE InterruptType,
                         BOOLEAN Enable)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION *)hAdapter;
    UXENDISP_CRTC *crtc;
    ULONG interrupt;
    ULONG ien;

    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hAdapter))
        return STATUS_INVALID_PARAMETER;

    switch (InterruptType) {
    case DXGK_INTERRUPT_CRTC_VSYNC:
        interrupt = UXDISP_INTERRUPT_VBLANK;
        break;
    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    ien = uxdisp_read(dev, UXDISP_REG_INTERRUPT_ENABLE);
    if (Enable)
        ien |= interrupt;
    else
        ien &= ~interrupt;
    uxdisp_write(dev, UXDISP_REG_INTERRUPT_ENABLE, ien);

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY uXenDispDestroyDevice(CONST HANDLE hDevice)
{
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hDevice))
        return STATUS_INVALID_PARAMETER;

    ExFreePoolWithTag(hDevice, UXENDISP_TAG);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispOpenAllocation(CONST HANDLE hDevice,
                       CONST DXGKARG_OPENALLOCATION *pOpenAllocation)
{
    UXENDISP_D3D_DEVICE *d3ddev = (UXENDISP_D3D_DEVICE *)hDevice;
    UXENDISP_D3D_ALLOCATION *d3dalloc;
    UXENDISP_DRIVER_ALLOCATION *drvalloc;
    DXGK_OPENALLOCATIONINFO *info;
    DXGKARGCB_GETHANDLEDATA handle_data = { 0, DXGK_HANDLE_ALLOCATION, 0 };
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hDevice) ||
        !ARGUMENT_PRESENT(pOpenAllocation))
        return STATUS_INVALID_PARAMETER;

    info = pOpenAllocation->pOpenAllocation;

    for (i = 0; i < pOpenAllocation->NumAllocations; i++, info++) {
        /*
         * Get the allocation private data passed in from UM or as a
         * standard allocation from the directx kernel and copy the bits
         * the driver needs.
         * This is really just a sanity check at this point.
         */
        d3dalloc = (UXENDISP_D3D_ALLOCATION *)info->pPrivateDriverData;
        if (!d3dalloc ||
            (info->PrivateDriverDataSize < sizeof(UXENDISP_D3D_ALLOCATION))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        handle_data.hObject = info->hAllocation;
        drvalloc = (UXENDISP_DRIVER_ALLOCATION *)d3ddev->dev->dxgkif.DxgkCbGetHandleData(&handle_data);
        info->hDeviceSpecificAllocation = (HANDLE)drvalloc;
        drvalloc->allochdl = info->hAllocation;
    }

    if (!NT_SUCCESS(status)) {
        info = pOpenAllocation->pOpenAllocation;
        for (i = 0; i < pOpenAllocation->NumAllocations; i++, info++) {
            /* Undo it all if anything failed */
            handle_data.hObject = info->hAllocation;
            drvalloc = (UXENDISP_DRIVER_ALLOCATION *)d3ddev->dev->dxgkif.DxgkCbGetHandleData(&handle_data);
            info->hDeviceSpecificAllocation = NULL;
            drvalloc->allochdl = 0;
        }
    }

    return status;
}

NTSTATUS APIENTRY
uXenDispCloseAllocation(CONST HANDLE hDevice,
                        CONST DXGKARG_CLOSEALLOCATION *pCloseAllocation)
{
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hDevice) ||
        !ARGUMENT_PRESENT(pCloseAllocation))
        return STATUS_INVALID_PARAMETER;

    /*
     * Nothing to do. The allocation is going to be destroyed so the open
     * mapping done above will just go away.
     */

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispRender(CONST HANDLE hContext, DXGKARG_RENDER *pRender)
{
    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hContext) ||
        !ARGUMENT_PRESENT(pRender))
        return STATUS_INVALID_PARAMETER;

    /*
     * N.B. This routine can be skipped for now since this will never be called
     * by GDI (only uXenDispPresent is used). For a full 3D implementation,
     * this will need to be implemented.
     */

    uxen_msg("Leave");
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS APIENTRY
uXenDispPresent(CONST HANDLE hContext, DXGKARG_PRESENT *pPresent)
{
    UXENDISP_D3D_CONTEXT *d3dctx = (UXENDISP_D3D_CONTEXT *)hContext;
    DEVICE_EXTENSION *dev = d3dctx->d3ddev->dev;
    UXENDISP_DMA_PRESENT *dma_present;
    UINT size, subrects_size;
    ULONG i;
    SUBRECT *subrects;
    ULONG srcwidth, srcheight;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hContext) ||
        !ARGUMENT_PRESENT(pPresent))
        return STATUS_INVALID_PARAMETER;

    /* TODO support these later? */
    if (!pPresent->pAllocationList[DXGK_PRESENT_SOURCE_INDEX].hDeviceSpecificAllocation) {
        uxen_debug("ColorFill operation not supported, Flags=0x%x",
                   pPresent->Flags);
        return STATUS_ILLEGAL_INSTRUCTION;
    } else if (!pPresent->pAllocationList[DXGK_PRESENT_DESTINATION_INDEX].hDeviceSpecificAllocation) {
        uxen_debug("Flip operation not supported, Flags=0x%x",
                   pPresent->Flags);
        return STATUS_ILLEGAL_INSTRUCTION;
    }

    if (!pPresent->pDmaBuffer) {
        /* This SNO since FLIPCAPS specify no HW flip support right now. */
        uxen_msg("HW MMIO Flip operation not supported, Flags=0x%x",
                 pPresent->Flags);
        return STATUS_ILLEGAL_INSTRUCTION;
    }

    /* TODO check allocation types (shared primary only)? */

    /* Allocate a DMA buffer to hold all the values for this present operation. */
    subrects_size = pPresent->SubRectCnt * sizeof(RECT);
    size = sizeof(UXENDISP_DMA_PRESENT) + subrects_size;
    if (pPresent->DmaSize < size) {
        uxen_debug("pDmaBuffer too small, size=0x%x", pPresent->DmaSize);
        return STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER;
    }

    /* Allocate DMA chunk and advance the buffer */
    dma_present = (UXENDISP_DMA_PRESENT *)pPresent->pDmaBuffer;
    pPresent->pDmaBuffer = (UCHAR *)pPresent->pDmaBuffer + size;

    /* Copy the present values into the DMA buffer */
    dma_present->size = size;
    dma_present->srcalloc = pPresent->pAllocationList[DXGK_PRESENT_SOURCE_INDEX].hDeviceSpecificAllocation;
    dma_present->dstalloc = pPresent->pAllocationList[DXGK_PRESENT_DESTINATION_INDEX].hDeviceSpecificAllocation;
    dma_present->srcrect = pPresent->SrcRect;
    dma_present->dstrect = pPresent->DstRect;
    dma_present->subrect_count = pPresent->SubRectCnt;
    dma_present->flags = pPresent->Flags;

    subrects = (SUBRECT *)((UCHAR *)dma_present + sizeof(UXENDISP_DMA_PRESENT));

    srcwidth = pPresent->SrcRect.right - pPresent->SrcRect.left;
    srcheight = pPresent->SrcRect.bottom - pPresent->SrcRect.top;
    for (i = 0; i < pPresent->SubRectCnt; i++) {
        subrects[i].left = min((ULONG)pPresent->pDstSubRects[i].left -
                               pPresent->DstRect.left, srcwidth);
        subrects[i].top =  min((ULONG)pPresent->pDstSubRects[i].top -
                               pPresent->DstRect.top, srcheight);
        subrects[i].width = min((ULONG)pPresent->pDstSubRects[i].right -
                                pPresent->pDstSubRects[i].left, srcwidth);
        subrects[i].height = min((ULONG)pPresent->pDstSubRects[i].bottom -
                                 pPresent->pDstSubRects[i].top, srcheight);
    }

    /* Set the patch locations and advance the location counter */
    RtlZeroMemory(pPresent->pPatchLocationListOut, 2 * sizeof(D3DDDI_PATCHLOCATIONLIST));
    pPresent->pPatchLocationListOut[0].AllocationIndex = DXGK_PRESENT_SOURCE_INDEX;
    pPresent->pPatchLocationListOut[1].AllocationIndex = DXGK_PRESENT_DESTINATION_INDEX;
    pPresent->pPatchLocationListOut += 2;

    dr_send(dev->dr_ctx, 1, &pPresent->DstRect);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispCreateContext(CONST HANDLE hDevice,
                      DXGKARG_CREATECONTEXT *pCreateContext)
{
    UXENDISP_D3D_DEVICE *d3ddev = (UXENDISP_D3D_DEVICE *)hDevice;
    UXENDISP_D3D_CONTEXT *d3dctx;

    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(hDevice) ||
        !ARGUMENT_PRESENT(pCreateContext))
        return STATUS_INVALID_PARAMETER;

    d3dctx = ExAllocatePoolWithTag(NonPagedPool,
                                   sizeof(UXENDISP_D3D_CONTEXT),
                                   UXENDISP_TAG);
    if (!d3dctx)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(d3dctx, sizeof(UXENDISP_D3D_CONTEXT));

    d3dctx->d3ddev = d3ddev;
    if (pCreateContext->Flags.SystemContext)
        d3dctx->type = UXENDISP_CONTEXT_TYPE_SYSTEM;
    else
        d3dctx->type = UXENDISP_CONTEXT_TYPE_NONE;

    d3dctx->node_ordinal = pCreateContext->NodeOrdinal;
    d3dctx->engine_affinity = pCreateContext->EngineAffinity;

    /* Return context and DMA allocation values. */
    pCreateContext->hContext = d3dctx;
    pCreateContext->ContextInfo.DmaBufferSize = 64 * 1024;

    /* Allocates the DMA buffer in the gart. */
    pCreateContext->ContextInfo.DmaBufferSegmentSet = 0;
    pCreateContext->ContextInfo.AllocationListSize = 3 * 1024;
    pCreateContext->ContextInfo.PatchLocationListSize = 3 * 1024;
    pCreateContext->ContextInfo.DmaBufferPrivateDataSize = 128;

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY uXenDispDestroyContext(CONST HANDLE hContext)
{
    PAGED_CODE();

    uxen_msg("Enter");
    if (!ARGUMENT_PRESENT(hContext))
        return STATUS_INVALID_PARAMETER;

    ExFreePoolWithTag(hContext, UXENDISP_TAG);
    uxen_msg("Leave");

    return STATUS_SUCCESS;
}
