/******************************Module*Header*******************************\
* Module Name: bdd_dmm.hxx
*
* Basic Display Driver display-mode management (DMM) function implementations
*
*
* Copyright (c) 2010 Microsoft Corporation
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
#include "hw.h"
#include "user_vram.h"

// Display-Only Devices can only return display modes of D3DDDIFMT_A8R8G8B8.
// Color conversion takes place if the app's fullscreen backbuffer has different format.
// Full display drivers can add more if the hardware supports them.
D3DDDIFORMAT gBddPixelFormats[] = {
    D3DDDIFMT_A8R8G8B8
};

// TODO: Need to also check pinned modes and the path parameters, not just topology
NTSTATUS BASIC_DISPLAY_DRIVER::IsSupportedVidPn(_Inout_ DXGKARG_ISSUPPORTEDVIDPN* pIsSupportedVidPn)
{
    ASSERT(pIsSupportedVidPn != NULL);

    if (pIsSupportedVidPn->hDesiredVidPn == 0)
    {
        // A null desired VidPn is supported
        pIsSupportedVidPn->IsVidPnSupported = TRUE;
        return STATUS_SUCCESS;
    }

    // Default to not supported, until shown it is supported
    pIsSupportedVidPn->IsVidPnSupported = FALSE;

    CONST DXGK_VIDPN_INTERFACE* pVidPnInterface;
    NTSTATUS Status = m_DxgkInterface.DxgkCbQueryVidPnInterface(pIsSupportedVidPn->hDesiredVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &pVidPnInterface);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("DxgkCbQueryVidPnInterface failed with Status = 0x%I64x, hDesiredVidPn = 0x%I64x", Status, pIsSupportedVidPn->hDesiredVidPn);
        return Status;
    }

    D3DKMDT_HVIDPNTOPOLOGY hVidPnTopology;
    CONST DXGK_VIDPNTOPOLOGY_INTERFACE* pVidPnTopologyInterface;
    Status = pVidPnInterface->pfnGetTopology(pIsSupportedVidPn->hDesiredVidPn, &hVidPnTopology, &pVidPnTopologyInterface);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("pfnGetTopology failed with Status = 0x%I64x, hDesiredVidPn = 0x%I64x", Status, pIsSupportedVidPn->hDesiredVidPn);
        return Status;
    }

    // For every source in this topology, make sure they don't have more paths than there are targets
    for (D3DDDI_VIDEO_PRESENT_SOURCE_ID SourceId = 0; SourceId < MAX_VIEWS; ++SourceId)
    {
        SIZE_T NumPathsFromSource = 0;
        Status = pVidPnTopologyInterface->pfnGetNumPathsFromSource(hVidPnTopology, SourceId, &NumPathsFromSource);
        if (Status == STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY)
        {
            continue;
        }
        else if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnGetNumPathsFromSource failed with Status = 0x%I64x. hVidPnTopology = 0x%I64x, SourceId = 0x%I64x",
                           Status, hVidPnTopology, SourceId);
            return Status;
        }
        else if (NumPathsFromSource > MAX_CHILDREN)
        {
            // This VidPn is not supported, which has already been set as the default
            return STATUS_SUCCESS;
        }
    }

    // All sources succeeded so this VidPn is supported
    pIsSupportedVidPn->IsVidPnSupported = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::RecommendFunctionalVidPn(_In_ CONST DXGKARG_RECOMMENDFUNCTIONALVIDPN* CONST pRecommendFunctionalVidPn)
{
    UNREFERENCED_PARAMETER(pRecommendFunctionalVidPn);

    ASSERT(pRecommendFunctionalVidPn == NULL);

    return STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN;
}

NTSTATUS BASIC_DISPLAY_DRIVER::RecommendMonitorModes(_In_ CONST DXGKARG_RECOMMENDMONITORMODES* CONST pRecommendMonitorModes)
{
    // This is always called to recommend modes for the monitor. The sample driver doesn't provide EDID for a monitor, so 
    // the OS prefills the list with default monitor modes. Since the required mode might not be in the list, it should 
    // be provided as a recommended mode.
    return AddSingleMonitorMode(pRecommendMonitorModes);
}

// Tell DMM about all the modes, etc. that are supported
NTSTATUS BASIC_DISPLAY_DRIVER::EnumVidPnCofuncModality(_In_ CONST DXGKARG_ENUMVIDPNCOFUNCMODALITY* CONST pEnumCofuncModality)
{
    ASSERT(pEnumCofuncModality != NULL);

    D3DKMDT_HVIDPNTOPOLOGY                   hVidPnTopology = 0;
    D3DKMDT_HVIDPNSOURCEMODESET              hVidPnSourceModeSet = 0;
    D3DKMDT_HVIDPNTARGETMODESET              hVidPnTargetModeSet = 0;
    CONST DXGK_VIDPN_INTERFACE*              pVidPnInterface = NULL;
    CONST DXGK_VIDPNTOPOLOGY_INTERFACE*      pVidPnTopologyInterface = NULL;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE* pVidPnSourceModeSetInterface = NULL;
    CONST DXGK_VIDPNTARGETMODESET_INTERFACE* pVidPnTargetModeSetInterface = NULL;
    CONST D3DKMDT_VIDPN_PRESENT_PATH*        pVidPnPresentPath = NULL;
    CONST D3DKMDT_VIDPN_PRESENT_PATH*        pVidPnPresentPathTemp = NULL; // Used for AcquireNextPathInfo
    CONST D3DKMDT_VIDPN_SOURCE_MODE*         pVidPnPinnedSourceModeInfo = NULL;
    CONST D3DKMDT_VIDPN_TARGET_MODE*         pVidPnPinnedTargetModeInfo = NULL;

    // Get the VidPn Interface so we can get the 'Source Mode Set', 'Target Mode Set' and 'VidPn Topology' interfaces
    NTSTATUS Status = m_DxgkInterface.DxgkCbQueryVidPnInterface(pEnumCofuncModality->hConstrainingVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &pVidPnInterface);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("DxgkCbQueryVidPnInterface failed with Status = 0x%I64x, hFunctionalVidPn = 0x%I64x", Status, pEnumCofuncModality->hConstrainingVidPn);
        return Status;
    }

    // Get the VidPn Topology interface so we can enumerate all paths
    Status = pVidPnInterface->pfnGetTopology(pEnumCofuncModality->hConstrainingVidPn, &hVidPnTopology, &pVidPnTopologyInterface);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("pfnGetTopology failed with Status = 0x%I64x, hFunctionalVidPn = 0x%I64x", Status, pEnumCofuncModality->hConstrainingVidPn);
        return Status;
    }

    // Get the first path before we start looping through them
    Status = pVidPnTopologyInterface->pfnAcquireFirstPathInfo(hVidPnTopology, &pVidPnPresentPath);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("pfnAcquireFirstPathInfo failed with Status = 0x%I64x, hVidPnTopology = 0x%I64x", Status, hVidPnTopology);
        return Status;
    }

    // Loop through all available paths.
    while (Status != STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET)
    {
        // Get the Source Mode Set interface so the pinned mode can be retrieved
        Status = pVidPnInterface->pfnAcquireSourceModeSet(pEnumCofuncModality->hConstrainingVidPn,
                                                          pVidPnPresentPath->VidPnSourceId,
                                                          &hVidPnSourceModeSet,
                                                          &pVidPnSourceModeSetInterface);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnAcquireSourceModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, SourceId = 0x%I64x",
                           Status, pEnumCofuncModality->hConstrainingVidPn, pVidPnPresentPath->VidPnSourceId);
            break;
        }

        // Get the pinned mode, needed when VidPnSource isn't pivot, and when VidPnTarget isn't pivot
        Status = pVidPnSourceModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnSourceModeSet, &pVidPnPinnedSourceModeInfo);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnAcquirePinnedModeInfo failed with Status = 0x%I64x, hVidPnSourceModeSet = 0x%I64x", Status, hVidPnSourceModeSet);
            break;
        }

        // SOURCE MODES: If this source mode isn't the pivot point, do work on the source mode set
        if (!((pEnumCofuncModality->EnumPivotType == D3DKMDT_EPT_VIDPNSOURCE) &&
              (pEnumCofuncModality->EnumPivot.VidPnSourceId == pVidPnPresentPath->VidPnSourceId)))
        {
            // If there's no pinned source add possible modes (otherwise they've already been added)
            if (pVidPnPinnedSourceModeInfo == NULL)
            {
                // Release the acquired source mode set, since going to create a new one to put all modes in
                Status = pVidPnInterface->pfnReleaseSourceModeSet(pEnumCofuncModality->hConstrainingVidPn, hVidPnSourceModeSet);
                if (!NT_SUCCESS(Status))
                {
                    uxen_err("pfnReleaseSourceModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, hVidPnSourceModeSet = 0x%I64x",
                                   Status, pEnumCofuncModality->hConstrainingVidPn, hVidPnSourceModeSet);
                    break;
                }
                hVidPnSourceModeSet = 0; // Successfully released it

                // Create a new source mode set which will be added to the constraining VidPn with all the possible modes
                Status = pVidPnInterface->pfnCreateNewSourceModeSet(pEnumCofuncModality->hConstrainingVidPn,
                                                                    pVidPnPresentPath->VidPnSourceId,
                                                                    &hVidPnSourceModeSet,
                                                                    &pVidPnSourceModeSetInterface);
                if (!NT_SUCCESS(Status))
                {
                    uxen_err("pfnCreateNewSourceModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, SourceId = 0x%I64x",
                                   Status, pEnumCofuncModality->hConstrainingVidPn, pVidPnPresentPath->VidPnSourceId);
                    break;
                }

                // Add the appropriate modes to the source mode set
                {
                    Status = AddSingleSourceMode(pVidPnSourceModeSetInterface, hVidPnSourceModeSet, pVidPnPresentPath->VidPnSourceId);
                }

                if (!NT_SUCCESS(Status))
                {
                    break;
                }

                // Give DMM back the source modes just populated
                Status = pVidPnInterface->pfnAssignSourceModeSet(pEnumCofuncModality->hConstrainingVidPn, pVidPnPresentPath->VidPnSourceId, hVidPnSourceModeSet);
                if (!NT_SUCCESS(Status))
                {
                    uxen_err("pfnAssignSourceModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, SourceId = 0x%I64x, hVidPnSourceModeSet = 0x%I64x",
                                   Status, pEnumCofuncModality->hConstrainingVidPn, pVidPnPresentPath->VidPnSourceId, hVidPnSourceModeSet);
                    break;
                }
                hVidPnSourceModeSet = 0; // Successfully assigned it (equivalent to releasing it)
            }
        }// End: SOURCE MODES

        // TARGET MODES: If this target mode isn't the pivot point, do work on the target mode set
        if (!((pEnumCofuncModality->EnumPivotType == D3DKMDT_EPT_VIDPNTARGET) &&
              (pEnumCofuncModality->EnumPivot.VidPnTargetId == pVidPnPresentPath->VidPnTargetId)))
        {
            // Get the Target Mode Set interface so modes can be added if necessary
            Status = pVidPnInterface->pfnAcquireTargetModeSet(pEnumCofuncModality->hConstrainingVidPn,
                                                              pVidPnPresentPath->VidPnTargetId,
                                                              &hVidPnTargetModeSet,
                                                              &pVidPnTargetModeSetInterface);
            if (!NT_SUCCESS(Status))
            {
                uxen_err("pfnAcquireTargetModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, TargetId = 0x%I64x",
                               Status, pEnumCofuncModality->hConstrainingVidPn, pVidPnPresentPath->VidPnTargetId);
                break;
            }

            Status = pVidPnTargetModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnTargetModeSet, &pVidPnPinnedTargetModeInfo);
            if (!NT_SUCCESS(Status))
            {
                uxen_err("pfnAcquirePinnedModeInfo failed with Status = 0x%I64x, hVidPnTargetModeSet = 0x%I64x", Status, hVidPnTargetModeSet);
                break;
            }

            // If there's no pinned target add possible modes (otherwise they've already been added)
            if (pVidPnPinnedTargetModeInfo == NULL)
            {
                // Release the acquired target mode set, since going to create a new one to put all modes in
                Status = pVidPnInterface->pfnReleaseTargetModeSet(pEnumCofuncModality->hConstrainingVidPn, hVidPnTargetModeSet);
                if (!NT_SUCCESS(Status))
                {
                    ASSERT_FAIL("pfnReleaseTargetModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, hVidPnTargetModeSet = 0x%I64x",
                                       Status, pEnumCofuncModality->hConstrainingVidPn, hVidPnTargetModeSet);
                    break;
                }
                hVidPnTargetModeSet = 0; // Successfully released it

                // Create a new target mode set which will be added to the constraining VidPn with all the possible modes
                Status = pVidPnInterface->pfnCreateNewTargetModeSet(pEnumCofuncModality->hConstrainingVidPn,
                                                                    pVidPnPresentPath->VidPnTargetId,
                                                                    &hVidPnTargetModeSet,
                                                                    &pVidPnTargetModeSetInterface);
                if (!NT_SUCCESS(Status))
                {
                    uxen_err("pfnCreateNewTargetModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, TargetId = 0x%I64x",
                                   Status, pEnumCofuncModality->hConstrainingVidPn, pVidPnPresentPath->VidPnTargetId);
                    break;
                }

                Status = AddSingleTargetMode(pVidPnTargetModeSetInterface, hVidPnTargetModeSet, pVidPnPinnedSourceModeInfo, pVidPnPresentPath->VidPnSourceId);

                if (!NT_SUCCESS(Status))
                {
                    break;
                }

                // Give DMM back the source modes just populated
                Status = pVidPnInterface->pfnAssignTargetModeSet(pEnumCofuncModality->hConstrainingVidPn, pVidPnPresentPath->VidPnTargetId, hVidPnTargetModeSet);
                if (!NT_SUCCESS(Status))
                {
                    uxen_err("pfnAssignTargetModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, TargetId = 0x%I64x, hVidPnTargetModeSet = 0x%I64x",
                                   Status, pEnumCofuncModality->hConstrainingVidPn, pVidPnPresentPath->VidPnTargetId, hVidPnTargetModeSet);
                    break;
                }
                hVidPnTargetModeSet = 0; // Successfully assigned it (equivalent to releasing it)
            }
            else
            {
                // Release the pinned target as there's no other work to do
                Status = pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pVidPnPinnedTargetModeInfo);
                if (!NT_SUCCESS(Status))
                {
                    ASSERT_FAIL("pfnReleaseModeInfo failed with Status = 0x%I64x, hVidPnTargetModeSet = 0x%I64x, pVidPnPinnedTargetModeInfo = 0x%I64x",
                                        Status, hVidPnTargetModeSet, pVidPnPinnedTargetModeInfo);
                    break;
                }
                pVidPnPinnedTargetModeInfo = NULL; // Successfully released it

                // Release the acquired target mode set, since it is no longer needed
                Status = pVidPnInterface->pfnReleaseTargetModeSet(pEnumCofuncModality->hConstrainingVidPn, hVidPnTargetModeSet);
                if (!NT_SUCCESS(Status))
                {
                    ASSERT_FAIL("pfnReleaseTargetModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, hVidPnTargetModeSet = 0x%I64x",
                                       Status, pEnumCofuncModality->hConstrainingVidPn, hVidPnTargetModeSet);
                    break;
                }
                hVidPnTargetModeSet = 0; // Successfully released it
            }
        }// End: TARGET MODES

        // Nothing else needs the pinned source mode so release it
        if (pVidPnPinnedSourceModeInfo != NULL)
        {
            Status = pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pVidPnPinnedSourceModeInfo);
            if (!NT_SUCCESS(Status))
            {
                ASSERT_FAIL("pfnReleaseModeInfo failed with Status = 0x%I64x, hVidPnSourceModeSet = 0x%I64x, pVidPnPinnedSourceModeInfo = 0x%I64x",
                                    Status, hVidPnSourceModeSet, pVidPnPinnedSourceModeInfo);
                break;
            }
            pVidPnPinnedSourceModeInfo = NULL; // Successfully released it
        }

        // With the pinned source mode now released, if the source mode set hasn't been released, release that as well
        if (hVidPnSourceModeSet != 0)
        {
            Status = pVidPnInterface->pfnReleaseSourceModeSet(pEnumCofuncModality->hConstrainingVidPn, hVidPnSourceModeSet);
            if (!NT_SUCCESS(Status))
            {
                uxen_err("pfnReleaseSourceModeSet failed with Status = 0x%I64x, hConstrainingVidPn = 0x%I64x, hVidPnSourceModeSet = 0x%I64x",
                               Status, pEnumCofuncModality->hConstrainingVidPn, hVidPnSourceModeSet);
                break;
            }
            hVidPnSourceModeSet = 0; // Successfully released it
        }

        // If modifying support fields, need to modify a local version of a path structure since the retrieved one is const
        D3DKMDT_VIDPN_PRESENT_PATH LocalVidPnPresentPath = *pVidPnPresentPath;
        BOOLEAN SupportFieldsModified = FALSE;

        // SCALING: If this path's scaling isn't the pivot point, do work on the scaling support
        if (!((pEnumCofuncModality->EnumPivotType == D3DKMDT_EPT_SCALING) &&
              (pEnumCofuncModality->EnumPivot.VidPnSourceId == pVidPnPresentPath->VidPnSourceId) &&
              (pEnumCofuncModality->EnumPivot.VidPnTargetId == pVidPnPresentPath->VidPnTargetId)))
        {
            // If the scaling is unpinned, then modify the scaling support field
            if (pVidPnPresentPath->ContentTransformation.Scaling == D3DKMDT_VPPS_UNPINNED)
            {
                // Identity and centered scaling are supported, but not any stretch modes
                RtlZeroMemory(&(LocalVidPnPresentPath.ContentTransformation.ScalingSupport), sizeof(D3DKMDT_VIDPN_PRESENT_PATH_SCALING_SUPPORT));
                LocalVidPnPresentPath.ContentTransformation.ScalingSupport.Identity = 1;
                LocalVidPnPresentPath.ContentTransformation.ScalingSupport.Centered = 1;
                SupportFieldsModified = TRUE;
            }
        } // End: SCALING

        // ROTATION: If this path's rotation isn't the pivot point, do work on the rotation support
        if (!((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_ROTATION) &&
              (pEnumCofuncModality->EnumPivot.VidPnSourceId == pVidPnPresentPath->VidPnSourceId) &&
              (pEnumCofuncModality->EnumPivot.VidPnTargetId == pVidPnPresentPath->VidPnTargetId)))
        {
            // If the rotation is unpinned, then modify the rotation support field
            if (pVidPnPresentPath->ContentTransformation.Rotation == D3DKMDT_VPPR_UNPINNED)
            {
                LocalVidPnPresentPath.ContentTransformation.RotationSupport.Identity = 1;
                // Sample supports only Rotate90
                LocalVidPnPresentPath.ContentTransformation.RotationSupport.Rotate90 = 1;
                LocalVidPnPresentPath.ContentTransformation.RotationSupport.Rotate180 = 0;
                LocalVidPnPresentPath.ContentTransformation.RotationSupport.Rotate270 = 0;
                SupportFieldsModified = TRUE;
            }
        } // End: ROTATION

        if (SupportFieldsModified)
        {
            // The correct path will be found by this function and the appropriate fields updated
            Status = pVidPnTopologyInterface->pfnUpdatePathSupportInfo(hVidPnTopology, &LocalVidPnPresentPath);
            if (!NT_SUCCESS(Status))
            {
                uxen_err("pfnUpdatePathSupportInfo failed with Status = 0x%I64x, hVidPnTopology = 0x%I64x", Status, hVidPnTopology);
                break;
            }
        }

        // Get the next path...
        // (NOTE: This is the value of Status that will return STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET when it's time to quit the loop)
        pVidPnPresentPathTemp = pVidPnPresentPath;
        Status = pVidPnTopologyInterface->pfnAcquireNextPathInfo(hVidPnTopology, pVidPnPresentPathTemp, &pVidPnPresentPath);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnAcquireNextPathInfo failed with Status = 0x%I64x, hVidPnTopology = 0x%I64x, pVidPnPresentPathTemp = 0x%I64x", Status, hVidPnTopology, pVidPnPresentPathTemp);
            break;
        }

        // ...and release the last path
        NTSTATUS TempStatus = pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pVidPnPresentPathTemp);
        if (!NT_SUCCESS(TempStatus))
        {
            uxen_err("pfnReleasePathInfo failed with Status = 0x%I64x, hVidPnTopology = 0x%I64x, pVidPnPresentPathTemp = 0x%I64x", TempStatus, hVidPnTopology, pVidPnPresentPathTemp);
            Status = TempStatus;
            break;
        }
        pVidPnPresentPathTemp = NULL; // Successfully released it
    }// End: while loop for paths in topology

    // If quit the while loop normally, set the return value to success
    if (Status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET)
    {
        Status = STATUS_SUCCESS;
    }

    // Release any resources hanging around because the loop was quit early.
    // Since in normal execution everything should be released by this point, TempStatus is initialized to a bogus error to be used as an
    //  assertion that if anything had to be released now (TempStatus changing) Status isn't successful.
    NTSTATUS TempStatus = STATUS_NOT_FOUND;

    if ((pVidPnSourceModeSetInterface != NULL) &&
        (pVidPnPinnedSourceModeInfo != NULL))
    {
        TempStatus = pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pVidPnPinnedSourceModeInfo);
        ASSERT(NT_SUCCESS(TempStatus));
    }

    if ((pVidPnTargetModeSetInterface != NULL) &&
        (pVidPnPinnedTargetModeInfo != NULL))
    {
        TempStatus = pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pVidPnPinnedTargetModeInfo);
        ASSERT(NT_SUCCESS(TempStatus));
    }

    if (pVidPnPresentPath != NULL)
    {
        TempStatus = pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pVidPnPresentPath);
        ASSERT(NT_SUCCESS(TempStatus));
    }

    if (pVidPnPresentPathTemp != NULL)
    {
        TempStatus = pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pVidPnPresentPathTemp);
        ASSERT(NT_SUCCESS(TempStatus));
    }

    if (hVidPnSourceModeSet != 0)
    {
        TempStatus = pVidPnInterface->pfnReleaseSourceModeSet(pEnumCofuncModality->hConstrainingVidPn, hVidPnSourceModeSet);
        ASSERT(NT_SUCCESS(TempStatus));
    }

    if (hVidPnTargetModeSet != 0)
    {
        TempStatus = pVidPnInterface->pfnReleaseTargetModeSet(pEnumCofuncModality->hConstrainingVidPn, hVidPnTargetModeSet);
        ASSERT(NT_SUCCESS(TempStatus));
    }

    ASSERT(TempStatus == STATUS_NOT_FOUND || Status != STATUS_SUCCESS);

    return Status;
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetVidPnSourceVisibility(_In_ CONST DXGKARG_SETVIDPNSOURCEVISIBILITY* pSetVidPnSourceVisibility)
{
    ASSERT(pSetVidPnSourceVisibility != NULL);
    ASSERT((pSetVidPnSourceVisibility->VidPnSourceId < MAX_VIEWS) ||
               (pSetVidPnSourceVisibility->VidPnSourceId == D3DDDI_ID_ALL));

    UINT StartVidPnSourceId = (pSetVidPnSourceVisibility->VidPnSourceId == D3DDDI_ID_ALL) ? 0 : pSetVidPnSourceVisibility->VidPnSourceId;
    UINT MaxVidPnSourceId = (pSetVidPnSourceVisibility->VidPnSourceId == D3DDDI_ID_ALL) ? MAX_VIEWS : pSetVidPnSourceVisibility->VidPnSourceId + 1;

    for (UINT SourceId = StartVidPnSourceId; SourceId < MaxVidPnSourceId; ++SourceId)
    {
        if (pSetVidPnSourceVisibility->Visible)
        {
            m_CurrentModes[SourceId].Flags.FullscreenPresent = TRUE;
        }
        else
        {
#ifdef BLACKOUT_SCREEN
            BlackOutScreen(SourceId, 100);
#endif  /* BLACKOUT_SCREEN */
        }

        // Store current visibility so it can be dealt with during Present call
        m_CurrentModes[SourceId].Flags.SourceNotVisible = !(pSetVidPnSourceVisibility->Visible);
    }

    return STATUS_SUCCESS;
}

// NOTE: The value of pCommitVidPn->MonitorConnectivityChecks is ignored, since BDD is unable to recognize whether a monitor is connected or not
// The value of pCommitVidPn->hPrimaryAllocation is also ignored, since BDD is a display only driver and does not deal with allocations
NTSTATUS BASIC_DISPLAY_DRIVER::CommitVidPn(_In_ CONST DXGKARG_COMMITVIDPN* CONST pCommitVidPn)
{
    ASSERT(pCommitVidPn != NULL);
    ASSERT(pCommitVidPn->AffectedVidPnSourceId < MAX_VIEWS);

    NTSTATUS                                 Status;
    SIZE_T                                   NumPaths = 0;
    D3DKMDT_HVIDPNTOPOLOGY                   hVidPnTopology = 0;
    D3DKMDT_HVIDPNSOURCEMODESET              hVidPnSourceModeSet = 0;
    CONST DXGK_VIDPN_INTERFACE*              pVidPnInterface = NULL;
    CONST DXGK_VIDPNTOPOLOGY_INTERFACE*      pVidPnTopologyInterface = NULL;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE* pVidPnSourceModeSetInterface = NULL;
    CONST D3DKMDT_VIDPN_PRESENT_PATH*        pVidPnPresentPath = NULL;
    CONST D3DKMDT_VIDPN_SOURCE_MODE*         pPinnedVidPnSourceModeInfo = NULL;

    // Check this CommitVidPn is for the mode change notification when monitor is in power off state.
    if (pCommitVidPn->Flags.PathPoweredOff)
    {
        // Ignore the commitVidPn call for the mode change notification when monitor is in power off state.
        Status = STATUS_SUCCESS;
        goto CommitVidPnExit;
    }

    // Get the VidPn Interface so we can get the 'Source Mode Set' and 'VidPn Topology' interfaces
    Status = m_DxgkInterface.DxgkCbQueryVidPnInterface(pCommitVidPn->hFunctionalVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &pVidPnInterface);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("DxgkCbQueryVidPnInterface failed with Status = 0x%I64x, hFunctionalVidPn = 0x%I64x", Status, pCommitVidPn->hFunctionalVidPn);
        goto CommitVidPnExit;
    }

    // Get the VidPn Topology interface so can enumerate paths from source
    Status = pVidPnInterface->pfnGetTopology(pCommitVidPn->hFunctionalVidPn, &hVidPnTopology, &pVidPnTopologyInterface);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("pfnGetTopology failed with Status = 0x%I64x, hFunctionalVidPn = 0x%I64x", Status, pCommitVidPn->hFunctionalVidPn);
        goto CommitVidPnExit;
    }

    // Find out the number of paths now, if it's 0 don't bother with source mode set and pinned mode, just clear current and then quit
    Status = pVidPnTopologyInterface->pfnGetNumPaths(hVidPnTopology, &NumPaths);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("pfnGetNumPaths failed with Status = 0x%I64x, hVidPnTopology = 0x%I64x", Status, hVidPnTopology);
        goto CommitVidPnExit;
    }

    if (NumPaths != 0)
    {
        // Get the Source Mode Set interface so we can get the pinned mode
        Status = pVidPnInterface->pfnAcquireSourceModeSet(pCommitVidPn->hFunctionalVidPn,
                                                          pCommitVidPn->AffectedVidPnSourceId,
                                                          &hVidPnSourceModeSet,
                                                          &pVidPnSourceModeSetInterface);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnAcquireSourceModeSet failed with Status = 0x%I64x, hFunctionalVidPn = 0x%I64x, SourceId = 0x%I64x", Status, pCommitVidPn->hFunctionalVidPn, pCommitVidPn->AffectedVidPnSourceId);
            goto CommitVidPnExit;
        }

        // Get the mode that is being pinned
        Status = pVidPnSourceModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnSourceModeSet, &pPinnedVidPnSourceModeInfo);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnAcquirePinnedModeInfo failed with Status = 0x%I64x, hFunctionalVidPn = 0x%I64x", Status, pCommitVidPn->hFunctionalVidPn);
            goto CommitVidPnExit;
        }
    }
    else
    {
        // This will cause the successful quit below
        pPinnedVidPnSourceModeInfo = NULL;
    }

    if (m_CurrentModes[pCommitVidPn->AffectedVidPnSourceId].FrameBuffer.Ptr &&
        !m_CurrentModes[pCommitVidPn->AffectedVidPnSourceId].Flags.DoNotMapOrUnmap)
    {
        Status = UnmapFrameBuffer(m_CurrentModes[pCommitVidPn->AffectedVidPnSourceId].FrameBuffer.Ptr,
                                  m_CurrentModes[pCommitVidPn->AffectedVidPnSourceId].DispInfo.Pitch * m_CurrentModes[pCommitVidPn->AffectedVidPnSourceId].DispInfo.Height);
        m_CurrentModes[pCommitVidPn->AffectedVidPnSourceId].FrameBuffer.Ptr = NULL;
        m_CurrentModes[pCommitVidPn->AffectedVidPnSourceId].Flags.FrameBufferIsActive = FALSE;

        if (!NT_SUCCESS(Status))
        {
            goto CommitVidPnExit;
        }
    }

    if (pPinnedVidPnSourceModeInfo == NULL)
    {
        // There is no mode to pin on this source, any old paths here have already been cleared
        Status = STATUS_SUCCESS;
        goto CommitVidPnExit;
    }

#ifdef VERIFY_VIDPN
    Status = IsVidPnSourceModeFieldsValid(pPinnedVidPnSourceModeInfo);
    if (!NT_SUCCESS(Status))
    {
        goto CommitVidPnExit;
    }
#endif  /* VERIFY_VIDPN */

    // Get the number of paths from this source so we can loop through all paths
    SIZE_T NumPathsFromSource = 0;
    Status = pVidPnTopologyInterface->pfnGetNumPathsFromSource(hVidPnTopology, pCommitVidPn->AffectedVidPnSourceId, &NumPathsFromSource);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("pfnGetNumPathsFromSource failed with Status = 0x%I64x, hVidPnTopology = 0x%I64x", Status, hVidPnTopology);
        goto CommitVidPnExit;
    }

    // Loop through all paths to set this mode
    for (SIZE_T PathIndex = 0; PathIndex < NumPathsFromSource; ++PathIndex)
    {
        // Get the target id for this path
        D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId = D3DDDI_ID_UNINITIALIZED;
        Status = pVidPnTopologyInterface->pfnEnumPathTargetsFromSource(hVidPnTopology, pCommitVidPn->AffectedVidPnSourceId, PathIndex, &TargetId);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnEnumPathTargetsFromSource failed with Status = 0x%I64x, hVidPnTopology = 0x%I64x, SourceId = 0x%I64x, PathIndex = 0x%I64x",
                            Status, hVidPnTopology, pCommitVidPn->AffectedVidPnSourceId, PathIndex);
            goto CommitVidPnExit;
        }

        // Get the actual path info
        Status = pVidPnTopologyInterface->pfnAcquirePathInfo(hVidPnTopology, pCommitVidPn->AffectedVidPnSourceId, TargetId, &pVidPnPresentPath);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnAcquirePathInfo failed with Status = 0x%I64x, hVidPnTopology = 0x%I64x, SourceId = 0x%I64x, TargetId = 0x%I64x",
                            Status, hVidPnTopology, pCommitVidPn->AffectedVidPnSourceId, TargetId);
            goto CommitVidPnExit;
        }

#ifdef VERIFY_VIDPN
        Status = IsVidPnPathFieldsValid(pVidPnPresentPath);
        if (!NT_SUCCESS(Status))
        {
            goto CommitVidPnExit;
        }
#endif  /* VERIFY_VIDPN */

        Status = SetSourceModeAndPath(pPinnedVidPnSourceModeInfo, pVidPnPresentPath);
        if (!NT_SUCCESS(Status))
        {
            goto CommitVidPnExit;
        }

        Status = pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pVidPnPresentPath);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnReleasePathInfo failed with Status = 0x%I64x, hVidPnTopoogy = 0x%I64x, pVidPnPresentPath = 0x%I64x",
                            Status, hVidPnTopology, pVidPnPresentPath);
            goto CommitVidPnExit;
        }
        pVidPnPresentPath = NULL; // Successfully released it
    }

CommitVidPnExit:

    NTSTATUS TempStatus;
    UNREFERENCED_PARAMETER(TempStatus);

    if (!NT_SUCCESS(Status)) {
        ASSERT_FAIL("CommitVidPn() failed: %d\n", Status);
    }

    if ((pVidPnSourceModeSetInterface != NULL) &&
        (hVidPnSourceModeSet != 0) &&
        (pPinnedVidPnSourceModeInfo != NULL))
    {
        TempStatus = pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pPinnedVidPnSourceModeInfo);
        NT_ASSERT(NT_SUCCESS(TempStatus));
    }

    if ((pVidPnInterface != NULL) &&
        (pCommitVidPn->hFunctionalVidPn != 0) &&
        (hVidPnSourceModeSet != 0))
    {
        TempStatus = pVidPnInterface->pfnReleaseSourceModeSet(pCommitVidPn->hFunctionalVidPn, hVidPnSourceModeSet);
        NT_ASSERT(NT_SUCCESS(TempStatus));
    }

    if ((pVidPnTopologyInterface != NULL) &&
        (hVidPnTopology != 0) &&
        (pVidPnPresentPath != NULL))
    {
        TempStatus = pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pVidPnPresentPath);
        NT_ASSERT(NT_SUCCESS(TempStatus));
    }

    return Status;
}

NTSTATUS BASIC_DISPLAY_DRIVER::UpdateActiveVidPnPresentPath(_In_ CONST DXGKARG_UPDATEACTIVEVIDPNPRESENTPATH* CONST pUpdateActiveVidPnPresentPath)
{
    ASSERT(pUpdateActiveVidPnPresentPath != NULL);

#ifdef VERIFY_VIDPN
    NTSTATUS Status = IsVidPnPathFieldsValid(&(pUpdateActiveVidPnPresentPath->VidPnPresentPathInfo));
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
#endif  /* VERIFY_VIDPN */

    // Mark the next present as fullscreen to make sure the full rotation comes through
    m_CurrentModes[pUpdateActiveVidPnPresentPath->VidPnPresentPathInfo.VidPnSourceId].Flags.FullscreenPresent = TRUE;

    m_CurrentModes[pUpdateActiveVidPnPresentPath->VidPnPresentPathInfo.VidPnSourceId].Rotation = pUpdateActiveVidPnPresentPath->VidPnPresentPathInfo.ContentTransformation.Rotation;

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetSourceModeAndPath(CONST D3DKMDT_VIDPN_SOURCE_MODE* pSourceMode,
                                                    CONST D3DKMDT_VIDPN_PRESENT_PATH* pPath)
{
    CURRENT_BDD_MODE* pCurrentBddMode = &m_CurrentModes[pPath->VidPnSourceId];
    VIDEO_MODE_INFORMATION mode;

    NTSTATUS Status = STATUS_SUCCESS;
    pCurrentBddMode->Scaling = pPath->ContentTransformation.Scaling;
    pCurrentBddMode->SrcModeWidth = pSourceMode->Format.Graphics.PrimSurfSize.cx;
    pCurrentBddMode->SrcModeHeight = pSourceMode->Format.Graphics.PrimSurfSize.cy;
    pCurrentBddMode->Rotation = pPath->ContentTransformation.Rotation;

    pCurrentBddMode->DispInfo.Pitch = pCurrentBddMode->SrcModeWidth * 4;
    pCurrentBddMode->DispInfo.Width = pSourceMode->Format.Graphics.PrimSurfSize.cx;
    pCurrentBddMode->DispInfo.Height = pSourceMode->Format.Graphics.PrimSurfSize.cy;
    pCurrentBddMode->DispInfo.ColorFormat = D3DDDIFMT_A8R8G8B8;

    m_VirtMode.width = pSourceMode->Format.Graphics.PrimSurfSize.cx;
    m_VirtMode.height = pSourceMode->Format.Graphics.PrimSurfSize.cy;

    mode.VisScreenWidth = pSourceMode->Format.Graphics.PrimSurfSize.cx;
    mode.VisScreenHeight = pSourceMode->Format.Graphics.PrimSurfSize.cy;
    mode.ScreenStride = pSourceMode->Format.Graphics.Stride;
    mode.BitsPerPlane = 32;

    if (m_Flags.StopCopy) {
        mode.ScreenStride += (mode.VisScreenWidth & 1) * 4;
    }
    hw_set_mode(&m_HwResources, &mode);

    if (!pCurrentBddMode->Flags.DoNotMapOrUnmap)
    {
        // Map the new frame buffer
        ASSERT(pCurrentBddMode->FrameBuffer.Ptr == NULL);
        Status = MapFrameBuffer(pCurrentBddMode->DispInfo.PhysicAddress,
                                pCurrentBddMode->DispInfo.Pitch * pCurrentBddMode->DispInfo.Height,
                                &(pCurrentBddMode->FrameBuffer.Ptr));
    }

    if (NT_SUCCESS(Status))
    {
        pCurrentBddMode->Flags.FrameBufferIsActive = TRUE;

        BlackOutScreen(pPath->VidPnSourceId, 255);

        // Mark that the next present should be fullscreen so the screen doesn't go from black to actual pixels one dirty rect at a time.
        pCurrentBddMode->Flags.FullscreenPresent = TRUE;
    }

    return Status;
}

#ifdef VERIFY_VIDPN
NTSTATUS BASIC_DISPLAY_DRIVER::IsVidPnPathFieldsValid(CONST D3DKMDT_VIDPN_PRESENT_PATH* pPath) const
{
    if (pPath->VidPnSourceId >= MAX_VIEWS)
    {
        uxen_err("VidPnSourceId is 0x%I64x is too high (MAX_VIEWS is 0x%I64x)",
                        pPath->VidPnSourceId, MAX_VIEWS);
        return STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE;
    }
    else if (pPath->VidPnTargetId >= MAX_CHILDREN)
    {
        uxen_err("VidPnTargetId is 0x%I64x is too high (MAX_CHILDREN is 0x%I64x)",
                        pPath->VidPnTargetId, MAX_CHILDREN);
        return STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET;
    }
    else if (pPath->GammaRamp.Type != D3DDDI_GAMMARAMP_DEFAULT)
    {
        uxen_err("pPath contains a gamma ramp (0x%I64x)", pPath->GammaRamp.Type);
        return STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED;
    }
    else if ((pPath->ContentTransformation.Scaling != D3DKMDT_VPPS_IDENTITY) &&
             (pPath->ContentTransformation.Scaling != D3DKMDT_VPPS_CENTERED) &&
             (pPath->ContentTransformation.Scaling != D3DKMDT_VPPS_NOTSPECIFIED) &&
             (pPath->ContentTransformation.Scaling != D3DKMDT_VPPS_UNINITIALIZED))
    {
        uxen_err("pPath contains a non-identity scaling (0x%I64x)", pPath->ContentTransformation.Scaling);
        return STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED;
    }
    else if ((pPath->ContentTransformation.Rotation != D3DKMDT_VPPR_IDENTITY) &&
             (pPath->ContentTransformation.Rotation != D3DKMDT_VPPR_ROTATE90) &&
             (pPath->ContentTransformation.Rotation != D3DKMDT_VPPR_NOTSPECIFIED) &&
             (pPath->ContentTransformation.Rotation != D3DKMDT_VPPR_UNINITIALIZED))
    {
        uxen_err("pPath contains a not-supported rotation (0x%I64x)", pPath->ContentTransformation.Rotation);
        return STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED;
    }
    else if ((pPath->VidPnTargetColorBasis != D3DKMDT_CB_SCRGB) &&
             (pPath->VidPnTargetColorBasis != D3DKMDT_CB_UNINITIALIZED))
    {
        uxen_err("pPath has a non-linear RGB color basis (0x%I64x)", pPath->VidPnTargetColorBasis);
        return STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE;
    }
    else
    {
        return STATUS_SUCCESS;
    }
}

NTSTATUS BASIC_DISPLAY_DRIVER::IsVidPnSourceModeFieldsValid(CONST D3DKMDT_VIDPN_SOURCE_MODE* pSourceMode) const
{
    if (pSourceMode->Type != D3DKMDT_RMT_GRAPHICS)
    {
        uxen_err("pSourceMode is a non-graphics mode (0x%I64x)", pSourceMode->Type);
        return STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE;
    }
    else if ((pSourceMode->Format.Graphics.ColorBasis != D3DKMDT_CB_SCRGB) &&
             (pSourceMode->Format.Graphics.ColorBasis != D3DKMDT_CB_UNINITIALIZED))
    {
        uxen_err("pSourceMode has a non-linear RGB color basis (0x%I64x)", pSourceMode->Format.Graphics.ColorBasis);
        return STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE;
    }
    else if (pSourceMode->Format.Graphics.PixelValueAccessMode != D3DKMDT_PVAM_DIRECT)
    {
        uxen_err("pSourceMode has a palettized access mode (0x%I64x)", pSourceMode->Format.Graphics.PixelValueAccessMode);
        return STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE;
    }
    else
    {
        for (UINT PelFmtIdx = 0; PelFmtIdx < ARRAYSIZE(gBddPixelFormats); ++PelFmtIdx)
        {
            if (pSourceMode->Format.Graphics.PixelFormat == gBddPixelFormats[PelFmtIdx])
            {
                return STATUS_SUCCESS;
            }
        }

        uxen_err("pSourceMode has an unknown pixel format (0x%I64x)", pSourceMode->Format.Graphics.PixelFormat);
        return STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE;
    }
}
#endif  /* VERIFY_VIDPN */
    
NTSTATUS BASIC_DISPLAY_DRIVER::SetNextMode(UXENDISPCustomMode *pNewMode)
{
    NTSTATUS status;
    DXGK_CHILD_STATUS childStatus;

    perfcnt_inc(SetNextMode);
#ifdef DBG
//    uxen_debug("called: %dx%d@%dHz", pNewMode->width, pNewMode->height, pNewMode->vsync);
#else
//    if (perfcnt_get(SetNextMode) < 64)
//        uxen_msg("called: %dx%d@%dHz", pNewMode->width, pNewMode->height, pNewMode->vsync);
#endif  /* DBG */

    m_NextMode = *pNewMode;

    /* disconnect monitor... */
    childStatus.Type = StatusConnection;
    childStatus.ChildUid = 0;
    childStatus.HotPlug.Connected = FALSE;
    status = m_DxgkInterface.DxgkCbIndicateChildStatus(
        m_DxgkInterface.DeviceHandle,
        &childStatus);
    if (!NT_SUCCESS(status)) {
        ASSERT_FAIL("DxgkCbIndicateChildStatus(off) failed: %d\n", status);
        goto out;
    }

    /* ...and connect it again */
    childStatus.Type = StatusConnection;
    childStatus.ChildUid = 0;
    childStatus.HotPlug.Connected = TRUE;
    status = m_DxgkInterface.DxgkCbIndicateChildStatus(
        m_DxgkInterface.DeviceHandle,
        &childStatus);
    if (!NT_SUCCESS(status)) {
        ASSERT_FAIL("DxgkCbIndicateChildStatus(on) failed: %d\n", status);
        goto out;
    }

out:
    return status;
}

NTSTATUS BASIC_DISPLAY_DRIVER::MapUserVram(PVOID data)
{
    PVOID mem = user_vram_map(m_VmemMdl);
    RtlCopyMemory(data, &mem, sizeof mem);
    m_Flags.StopCopy = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetVirtMode(UXENDISPCustomMode *pNewMode)
{
    VIDEO_MODE_INFORMATION mode;

    KeWaitForSingleObject(&m_PresentLock, Executive, KernelMode, FALSE, NULL);

    mode.VisScreenWidth = pNewMode->width;
    mode.VisScreenHeight = pNewMode->height;
    mode.ScreenStride = pNewMode->width * 4;
    mode.BitsPerPlane = 32;

    if (m_Flags.StopCopy) {
        CURRENT_BDD_MODE* pCurrentBddMode = &m_CurrentModes[0];
        mode.ScreenStride = pCurrentBddMode->DispInfo.Pitch;
        mode.ScreenStride += (pCurrentBddMode->DispInfo.Width & 1) * 4;
    }
    hw_set_mode(&m_HwResources, &mode);

    m_VirtMode = *pNewMode;

    KeReleaseSemaphore(&m_PresentLock, 0, 1, FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::AddSingleSourceMode(_In_ CONST DXGK_VIDPNSOURCEMODESET_INTERFACE* pVidPnSourceModeSetInterface,
                                                   D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet,
                                                   D3DDDI_VIDEO_PRESENT_SOURCE_ID /*SourceId*/)
{
    // There is only one source format supported by display-only drivers, but more can be added in a 
    // full WDDM driver if the hardware supports them
    for (UINT PelFmtIdx = 0; PelFmtIdx < ARRAYSIZE(gBddPixelFormats); ++PelFmtIdx)
    {
        // Create new mode info that will be populated
        D3DKMDT_VIDPN_SOURCE_MODE* pVidPnSourceModeInfo = NULL;
        NTSTATUS Status = pVidPnSourceModeSetInterface->pfnCreateNewModeInfo(hVidPnSourceModeSet, &pVidPnSourceModeInfo);
        if (!NT_SUCCESS(Status))
        {
            uxen_err("pfnCreateNewModeInfo failed with Status = 0x%I64x, hVidPnSourceModeSet = 0x%I64x", Status, hVidPnSourceModeSet);
            return Status;
        }

        // Always report 32 bpp format, this will be color converted during the present if the mode was < 32bpp
        pVidPnSourceModeInfo->Type = D3DKMDT_RMT_GRAPHICS;
        pVidPnSourceModeInfo->Format.Graphics.PrimSurfSize.cx = m_NextMode.width;
        pVidPnSourceModeInfo->Format.Graphics.PrimSurfSize.cy = m_NextMode.height;
        pVidPnSourceModeInfo->Format.Graphics.VisibleRegionSize = pVidPnSourceModeInfo->Format.Graphics.PrimSurfSize;
        pVidPnSourceModeInfo->Format.Graphics.Stride = 4 * m_NextMode.width;
        pVidPnSourceModeInfo->Format.Graphics.PixelFormat = gBddPixelFormats[PelFmtIdx];
        pVidPnSourceModeInfo->Format.Graphics.ColorBasis = D3DKMDT_CB_SCRGB;
        pVidPnSourceModeInfo->Format.Graphics.PixelValueAccessMode = D3DKMDT_PVAM_DIRECT;

        // Add the mode to the source mode set
        Status = pVidPnSourceModeSetInterface->pfnAddMode(hVidPnSourceModeSet, pVidPnSourceModeInfo);
        if (!NT_SUCCESS(Status))
        {
            if (Status != STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET)
                uxen_err("pfnAddMode failed with Status = 0x%I64x, hVidPnSourceModeSet = 0x%I64x, pVidPnSourceModeInfo = 0x%I64x",
                    Status, hVidPnSourceModeSet, pVidPnSourceModeInfo);

            NT_VERIFY(NT_SUCCESS(
                pVidPnSourceModeSetInterface->pfnReleaseModeInfo(
                    hVidPnSourceModeSet, pVidPnSourceModeInfo)));
        }
    }

    return STATUS_SUCCESS;
}

#define HSYNC_RATE 23456

#define InitVideoSignalParams(vsi, w, h, r, s) do {                           \
    (vsi)->VideoStandard = D3DKMDT_VSS_OTHER;                                 \
    (vsi)->TotalSize.cx = (w);                                                \
    (vsi)->TotalSize.cy = (h);                                                \
    (vsi)->ActiveSize = (s);                                                  \
    (vsi)->VSyncFreq.Numerator = (m_VSync) ? (r) : D3DKMDT_FREQUENCY_NOTSPECIFIED;               \
    (vsi)->VSyncFreq.Denominator = (m_VSync) ? 1 : D3DKMDT_FREQUENCY_NOTSPECIFIED;               \
    (vsi)->HSyncFreq.Numerator = (m_VSync) ? HSYNC_RATE : D3DKMDT_FREQUENCY_NOTSPECIFIED;        \
    (vsi)->HSyncFreq.Denominator = (m_VSync) ? 1 : D3DKMDT_FREQUENCY_NOTSPECIFIED;               \
    (vsi)->PixelRate = (m_VSync) ? (r) * (h + 100) * (w + 100) : D3DKMDT_FREQUENCY_NOTSPECIFIED; \
    (vsi)->ScanLineOrdering = D3DDDI_VSSLO_PROGRESSIVE;                       \
} while (0, 0)

// Add the current mode information (acquired from the POST frame buffer) as the target mode.
NTSTATUS BASIC_DISPLAY_DRIVER::AddSingleTargetMode(_In_ CONST DXGK_VIDPNTARGETMODESET_INTERFACE* pVidPnTargetModeSetInterface,
                                                   D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet,
                                                   _In_opt_ CONST D3DKMDT_VIDPN_SOURCE_MODE* /*pVidPnPinnedSourceModeInfo*/,
                                                   D3DDDI_VIDEO_PRESENT_SOURCE_ID /*SourceId*/)
{
    D3DKMDT_VIDPN_TARGET_MODE* pVidPnTargetModeInfo = NULL;
    NTSTATUS Status;

    pVidPnTargetModeInfo = NULL;
    Status = pVidPnTargetModeSetInterface->pfnCreateNewModeInfo(hVidPnTargetModeSet, &pVidPnTargetModeInfo);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("pfnCreateNewModeInfo failed with Status = 0x%I64x, hVidPnTargetModeSet = 0x%I64x",
                  Status, hVidPnTargetModeSet);
        return Status;
    }

    InitVideoSignalParams(
        &pVidPnTargetModeInfo->VideoSignalInfo,
        m_NextMode.width,
        m_NextMode.height,
        hw_pv_vblank_getrate(&m_HwResources),
        pVidPnTargetModeInfo->VideoSignalInfo.TotalSize);

    pVidPnTargetModeInfo->Preference = D3DKMDT_MP_PREFERRED;

    Status = pVidPnTargetModeSetInterface->pfnAddMode(hVidPnTargetModeSet, pVidPnTargetModeInfo);
    if (!NT_SUCCESS(Status))
    {
        if (Status != STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET)
            uxen_err("pfnAddMode failed with Status = 0x%I64x, hVidPnTargetModeSet = 0x%I64x, pVidPnTargetModeInfo = 0x%I64x",
                      Status, hVidPnTargetModeSet, pVidPnTargetModeInfo);
        NT_VERIFY(NT_SUCCESS(
            pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pVidPnTargetModeInfo)));
    }

    return STATUS_SUCCESS;
}


NTSTATUS BASIC_DISPLAY_DRIVER::AddSingleMonitorMode(_In_ CONST DXGKARG_RECOMMENDMONITORMODES* CONST pRecommendMonitorModes)
{
    D3DKMDT_MONITOR_SOURCE_MODE* pMonitorSourceMode = NULL;
    NTSTATUS Status = pRecommendMonitorModes->pMonitorSourceModeSetInterface->pfnCreateNewModeInfo(pRecommendMonitorModes->hMonitorSourceModeSet, &pMonitorSourceMode);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("pfnCreateNewModeInfo failed with Status = 0x%I64x, hMonitorSourceModeSet = 0x%I64x", Status, pRecommendMonitorModes->hMonitorSourceModeSet);
        return Status;
    }

    InitVideoSignalParams(
        &pMonitorSourceMode->VideoSignalInfo,
        m_NextMode.width,
        m_NextMode.height,
        hw_pv_vblank_getrate(&m_HwResources),
        pMonitorSourceMode->VideoSignalInfo.TotalSize);

    // We set the preference to PREFERRED since this is the only supported mode
    pMonitorSourceMode->Origin = D3DKMDT_MCO_DRIVER;
    pMonitorSourceMode->Preference = D3DKMDT_MP_PREFERRED;
    pMonitorSourceMode->ColorBasis = D3DKMDT_CB_SCRGB;
    pMonitorSourceMode->ColorCoeffDynamicRanges.FirstChannel = 8;
    pMonitorSourceMode->ColorCoeffDynamicRanges.SecondChannel = 8;
    pMonitorSourceMode->ColorCoeffDynamicRanges.ThirdChannel = 8;
    pMonitorSourceMode->ColorCoeffDynamicRanges.FourthChannel = 0;

    Status = pRecommendMonitorModes->pMonitorSourceModeSetInterface->pfnAddMode(pRecommendMonitorModes->hMonitorSourceModeSet, pMonitorSourceMode);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET)
            uxen_err("pfnAddMode failed with Status = 0x%I64x, hMonitorSourceModeSet = 0x%I64x, pMonitorSourceMode = 0x%I64x",
                      Status, pRecommendMonitorModes->hMonitorSourceModeSet, pMonitorSourceMode);
        NT_VERIFY(NT_SUCCESS(
            pRecommendMonitorModes->pMonitorSourceModeSetInterface->pfnReleaseModeInfo(
                pRecommendMonitorModes->hMonitorSourceModeSet, pMonitorSourceMode)));
    }

    return STATUS_SUCCESS;
}
