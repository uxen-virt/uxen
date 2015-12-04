/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxendisp.h"

typedef struct _UXENDISP_SOURCE_MAP_ENTRY {
    D3DDDI_VIDEO_PRESENT_SOURCE_ID sourceid;
    D3DKMDT_GRAPHICS_RENDERING_FORMAT fmt;
    BOOLEAN fmt_set;
} UXENDISP_SOURCE_MAP_ENTRY, *PUXENDISP_SOURCE_MAP_ENTRY;

typedef struct _UXENDISP_PINNED_MODES {
    BOOLEAN src_pinned;
    D3DKMDT_2DREGION src_primary_surf_size;
    BOOLEAN tgt_pinned;
    D3DKMDT_2DREGION tgt_active_size;
} UXENDISP_PINNED_MODES, *PUXENDISP_PINNED_MODES;

typedef enum _UXENDISP_PINNED_STATE {
    UXENDISP_PS_UNPINNED = 0,
    UXENDISP_PS_PINNED   = 1,
    UXENDISP_PS_ERROR    = 2
} UXENDISP_PINNED_STATE;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE,uXenDispIsSupportedVidPn)
#pragma alloc_text(PAGE,uXenDispRecommendFunctionalVidPn)
#pragma alloc_text(PAGE,uXenDispEnumVidPnCofuncModality)
#pragma alloc_text(PAGE,uXenDispSetVidPnSourceAddress)
#pragma alloc_text(PAGE,uXenDispSetVidPnSourceVisibility)
#pragma alloc_text(PAGE,uXenDispUpdateActiveVidPnPresentPath)
#pragma alloc_text(PAGE,uXenDispRecommendMonitorModes)
#pragma alloc_text(PAGE,uXenDispRecommendVidPnTopology)
#endif

static __inline UXENDISP_PINNED_STATE
pinned_mode_state(NTSTATUS status, VOID *mode)
{
    if (status == STATUS_SUCCESS)
        return mode ? UXENDISP_PS_PINNED : UXENDISP_PS_UNPINNED;
    else if (!NT_SUCCESS(status))
        return UXENDISP_PS_ERROR;
   else /* status == STATUS_GRAPHICS_MODE_NOT_PINNED) */
        return UXENDISP_PS_UNPINNED;
}

NTSTATUS APIENTRY
uXenDispIsSupportedVidPn(CONST HANDLE  hAdapter,
                         DXGKARG_ISSUPPORTEDVIDPN *pIsSupportedVidPn)
{
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pIsSupportedVidPn))
        return STATUS_INVALID_PARAMETER;

    pIsSupportedVidPn->IsVidPnSupported = TRUE;

    return STATUS_SUCCESS;
}

static NTSTATUS
add_target_mode(D3DKMDT_HVIDPNTARGETMODESET tgt_mode_set_hdl,
                CONST DXGK_VIDPNTARGETMODESET_INTERFACE *target_mode_set_if,
                UXENDISP_MODE *mode)
{
    D3DKMDT_VIDPN_TARGET_MODE *target_mode;
    D3DKMDT_VIDEO_SIGNAL_INFO *signal_info;
    NTSTATUS status;

    PAGED_CODE();

    status = target_mode_set_if->pfnCreateNewModeInfo(tgt_mode_set_hdl,
                                                      &target_mode);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnCreateNewModeInfo failed: 0x%x", status);
        return status; /* low memory.*/
    }

    /* Let OS assign the ID, set the preferred mode field.*/
    target_mode->Preference = D3DKMDT_MP_PREFERRED;

    /*
     * Init signal information (much like what is done for setting
     * up a monitor mode).
     */
    signal_info = &target_mode->VideoSignalInfo;
    signal_info->VideoStandard = D3DKMDT_VSS_OTHER;
    signal_info->TotalSize.cx = mode->xres;
    signal_info->TotalSize.cy = mode->yres;
    signal_info->ActiveSize.cx = mode->xres;
    signal_info->ActiveSize.cy = mode->yres;
    signal_info->PixelRate = mode->xres * mode->yres * UXENDISP_REFRESH_RATE;
    signal_info->VSyncFreq.Numerator = UXENDISP_REFRESH_RATE * 1000;
    signal_info->VSyncFreq.Denominator = 1000;
    signal_info->HSyncFreq.Numerator = (UINT)((signal_info->PixelRate / signal_info->TotalSize.cy) * 1000);
    signal_info->HSyncFreq.Denominator = 1000;
    signal_info->ScanLineOrdering = D3DDDI_VSSLO_PROGRESSIVE;

    /* Add it*/
    status = target_mode_set_if->pfnAddMode(tgt_mode_set_hdl, target_mode);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnAddMode failed: 0x%x", status);
        target_mode_set_if->pfnReleaseModeInfo(tgt_mode_set_hdl, target_mode);
        return status; /* low memory.*/
    }

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispRecommendFunctionalVidPn(CONST HANDLE hAdapter,
                                 CONST DXGKARG_RECOMMENDFUNCTIONALVIDPN *CONST pRecommendFunctionalVidPn)
{
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pRecommendFunctionalVidPn))
        return STATUS_INVALID_PARAMETER;

    /*
     * Though this routine is still used on Vista (not Win7), it is only
     * caused by either a D3DKMTInvalidateActiveVidPn from user mode or
     * due to display altering hot keys. The former is unlikely because
     * our display DLL currently does nothing. The latter is not present
     * on the virtual HW. So for now, just ignore it.
     */
    return STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN;
}

static NTSTATUS
update_target_mode_set(UXENDISP_CRTC *crtc,
                       CONST D3DKMDT_HVIDPN vidpn_hdl,
                       DXGK_VIDPN_INTERFACE *vidpn_if,
                       D3DKMDT_VIDPN_PRESENT_PATH *curr_path_info)
{
    D3DKMDT_HVIDPNTARGETMODESET tgt_mode_set_hdl = NULL;
    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *target_mode_set_if;
    D3DKMDT_VIDPN_TARGET_MODE *tgt_mode_info = NULL;
    UXENDISP_PINNED_STATE pinned_state;
    UXENDISP_MODE *mode;
    NTSTATUS status = STATUS_SUCCESS;
    PAGED_CODE();

    status = vidpn_if->pfnAcquireTargetModeSet(vidpn_hdl,
                                                      curr_path_info->VidPnTargetId,
                                                      &tgt_mode_set_hdl,
                                                      &target_mode_set_if);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnAcquireTargetModeSet failed: 0x%x", status);
        return status; /* low memory - bail out on operation.*/
    }

    do {
        /* If the target mode set already has a pinned mode, don't do any updates.*/
        status = target_mode_set_if->pfnAcquirePinnedModeInfo(tgt_mode_set_hdl, &tgt_mode_info);
        pinned_state = pinned_mode_state(status, tgt_mode_info);
        if (pinned_state == UXENDISP_PS_PINNED) {
            /* Drop out*/
            status = STATUS_SUCCESS;
            break;
        }
        if (pinned_state == UXENDISP_PS_ERROR) {
            uxen_err("pfnAcquirePinnedModeInfo(target) failed: 0x%x", status);
            tgt_mode_info = NULL;
            break; /* unknown nasty failure*/
        }

        /* Done with existing target mode set*/
        vidpn_if->pfnReleaseTargetModeSet(vidpn_hdl, tgt_mode_set_hdl);
        tgt_mode_set_hdl = NULL;

        /* Make a new target mode set*/
        status = vidpn_if->pfnCreateNewTargetModeSet(vidpn_hdl,
                                                            curr_path_info->VidPnTargetId,
                                                            &tgt_mode_set_hdl,
                                                            &target_mode_set_if);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnCreateNewTargetModeSet failed: 0x%x", status);
            tgt_mode_set_hdl = NULL;
            break; /* no memory*/
        }

        status = add_target_mode(tgt_mode_set_hdl,
                                 target_mode_set_if,
                                 &crtc->next_mode);
        if (!NT_SUCCESS(status)) {
            uxen_err("uXenDispAddTargetMode failed: 0x%x", status);
            break;
        }

        status = vidpn_if->pfnAssignTargetModeSet(vidpn_hdl,
                                                  curr_path_info->VidPnTargetId,
                                                  tgt_mode_set_hdl);
        if (NT_SUCCESS(status))
            tgt_mode_set_hdl = NULL;
        else
            uxen_err("pfnAssignTargetModeSet failed: 0x%x", status);

    } while (FALSE);

    if (tgt_mode_info != NULL)
        target_mode_set_if->pfnReleaseModeInfo(tgt_mode_set_hdl, tgt_mode_info);

    if (tgt_mode_set_hdl != NULL)
        vidpn_if->pfnReleaseTargetModeSet(vidpn_hdl, tgt_mode_set_hdl);

    return status;
}

static NTSTATUS
add_source_mode(D3DKMDT_HVIDPNSOURCEMODESET source_mode_set_hdl,
                CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *source_mode_set_if,
                UXENDISP_MODE *mode)
{
    D3DKMDT_VIDPN_SOURCE_MODE *source_mode;
    D3DKMDT_GRAPHICS_RENDERING_FORMAT *fmt;
    NTSTATUS status;

    PAGED_CODE();

    status = source_mode_set_if->pfnCreateNewModeInfo(source_mode_set_hdl,
                                                      &source_mode);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnCreateNewModeInfo failed: 0x%x", status);
        return status; /* low memory.*/
    }

    /* Let OS assign the ID, set the type.*/
    source_mode->Type = D3DKMDT_RMT_GRAPHICS;

    /* Initialize the rendering format per our constraints and the current mode. */
    fmt = &source_mode->Format.Graphics;
    fmt->PrimSurfSize.cx = mode->xres;
    fmt->PrimSurfSize.cy = mode->yres;
    fmt->VisibleRegionSize.cx = mode->xres;
    fmt->VisibleRegionSize.cy = mode->yres;
    fmt->Stride = mode->stride;
    fmt->PixelFormat = uxendisp_to_ddi_fmt(mode->fmt);
    fmt->ColorBasis = D3DKMDT_CB_SRGB;
    fmt->PixelValueAccessMode = D3DKMDT_PVAM_DIRECT;

    /* Add it */
    status = source_mode_set_if->pfnAddMode(source_mode_set_hdl, source_mode);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnAddMode failed: 0x%x", status);
        source_mode_set_if->pfnReleaseModeInfo(source_mode_set_hdl, source_mode);
        return status; /* low memory. */
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
update_source_mode_set(UXENDISP_CRTC *crtc,
                       CONST D3DKMDT_HVIDPN vidpn_hdl,
                       DXGK_VIDPN_INTERFACE *vidpn_if,
                       D3DKMDT_VIDPN_PRESENT_PATH *curr_path_info)
{
    D3DKMDT_HVIDPNSOURCEMODESET source_mode_set_hdl = NULL;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *source_mode_set_if;
    D3DKMDT_VIDPN_SOURCE_MODE *src_mode_info = NULL;
    UXENDISP_PINNED_STATE pinned_state;
    UXENDISP_MODE *mode;
    NTSTATUS status = STATUS_SUCCESS;
    PAGED_CODE();

    status = vidpn_if->pfnAcquireSourceModeSet(vidpn_hdl,
                                               curr_path_info->VidPnSourceId,
                                               &source_mode_set_hdl,
                                               &source_mode_set_if);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnAcquireSourceModeSet failed: 0x%x", status);
        return status; /* low memory - bail out on operation.*/
    }

    do {
        /* If the source mode set already has a pinned mode, don't do any updates.*/
        status = source_mode_set_if->pfnAcquirePinnedModeInfo(source_mode_set_hdl,
                                                              &src_mode_info);
        pinned_state = pinned_mode_state(status, src_mode_info);
        if (pinned_state == UXENDISP_PS_PINNED) {
            /* Drop out */
            status = STATUS_SUCCESS;
            break;
        }
        if (pinned_state == UXENDISP_PS_ERROR) {
            uxen_err("pfnAcquirePinnedModeInfo(source) failed: 0x%x", status);
            src_mode_info = NULL;
            break; /* unknown nasty failure*/
        }
        /* Done with existing target mode set*/
        vidpn_if->pfnReleaseSourceModeSet(vidpn_hdl, source_mode_set_hdl);
        source_mode_set_hdl = NULL;

        /* Make a new source mode set*/
        status = vidpn_if->pfnCreateNewSourceModeSet(vidpn_hdl,
                                                     curr_path_info->VidPnSourceId,
                                                     &source_mode_set_hdl,
                                                     &source_mode_set_if);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnCreateNewSourceModeSet failed: 0x%x", status);
            break; /* no memory*/
        }

        status = add_source_mode(source_mode_set_hdl,
                                 source_mode_set_if,
                                 &crtc->next_mode);
        if (!NT_SUCCESS(status)) {
            uxen_err("add_source_mode failed: 0x%x", status);
            break;
        }

        status = vidpn_if->pfnAssignSourceModeSet(vidpn_hdl,
                                                  curr_path_info->VidPnSourceId,
                                                  source_mode_set_hdl);
        if (NT_SUCCESS(status))
            source_mode_set_hdl = NULL;
        else
            uxen_err("pfnAssignSourceModeSet failed: 0x%x", status);

    } while (FALSE);

    if (src_mode_info != NULL)
        source_mode_set_if->pfnReleaseModeInfo(source_mode_set_hdl, src_mode_info);

    if (source_mode_set_hdl != NULL)
        vidpn_if->pfnReleaseSourceModeSet(vidpn_hdl, source_mode_set_hdl);

    return status;
}

NTSTATUS APIENTRY
uXenDispEnumVidPnCofuncModality(CONST HANDLE hAdapter,
                                CONST DXGKARG_ENUMVIDPNCOFUNCMODALITY *CONST pEnumCofuncModality)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION*)hAdapter;
    DXGK_VIDPN_INTERFACE *vidpn_if = NULL;
    D3DKMDT_HVIDPNTOPOLOGY topology_hdl;
    DXGK_VIDPNTOPOLOGY_INTERFACE *topology_if;
    D3DKMDT_VIDPN_PRESENT_PATH *curr_path_info;
    D3DKMDT_VIDPN_PRESENT_PATH *next_path_info;
    NTSTATUS status;
    BOOLEAN End = FALSE;
    ULONG i;
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pEnumCofuncModality))
        return STATUS_INVALID_PARAMETER;

    status = dev->dxgkif.DxgkCbQueryVidPnInterface(pEnumCofuncModality->hConstrainingVidPn,
                                                   DXGK_VIDPN_INTERFACE_VERSION_V1,
                                                   &vidpn_if);
    if (!NT_SUCCESS(status)) {
        uxen_err("DxgkCbQueryVidPnInterface failed: 0x%x", status);
        return STATUS_NO_MEMORY; /* SNO */
    }

    status = vidpn_if->pfnGetTopology(pEnumCofuncModality->hConstrainingVidPn, &topology_hdl, &topology_if);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnGetTopology failed: 0x%x", status);
        return STATUS_NO_MEMORY; /* SNO */
    }

    status = topology_if->pfnAcquireFirstPathInfo(topology_hdl, &curr_path_info);
    if (status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        /* Empty topology, nothing to do. */
        return STATUS_SUCCESS;
    }
    else if (!NT_SUCCESS(status)) {
        uxen_err("pfnAcquireFirstPathInfo failed: 0x%x", status);
        return STATUS_NO_MEMORY; /* bad topology? - probably low memory       */
    }

    /* can't be more paths than sources/targets*/
    for (i = 0; i < dev->crtc_count; i++) {
        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_VIDPNTARGET)||
            (pEnumCofuncModality->EnumPivot.VidPnTargetId != curr_path_info->VidPnTargetId)) {
            status = update_target_mode_set(&dev->crtcs[curr_path_info->VidPnTargetId],
                                            pEnumCofuncModality->hConstrainingVidPn,
                                            vidpn_if,
                                            curr_path_info);
            if (!NT_SUCCESS(status)) {
                uxen_err("uXenDispUpdateTargetModeSet failed: 0x%x", status);
                break;
            }
        }

        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_VIDPNSOURCE)||
            (pEnumCofuncModality->EnumPivot.VidPnSourceId != curr_path_info->VidPnSourceId)) {
            status = update_source_mode_set(&dev->crtcs[curr_path_info->VidPnTargetId],
                                            pEnumCofuncModality->hConstrainingVidPn,
                                            vidpn_if,
                                            curr_path_info);
            if (!NT_SUCCESS(status)) {
                uxen_err("uXenDispUpdateSourceModeSet failed: 0x%x", status);
                break;
            }
        }

        /* -- Next --*/
        status = topology_if->pfnAcquireNextPathInfo(topology_hdl, curr_path_info, &next_path_info);
        /* Done with the last path.*/
        topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);

        if (status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            End = TRUE;
            break;
        }
        else if (!NT_SUCCESS(status)) {
            uxen_err("pfnAcquireNextPathInfo failed: 0x%x", status);
            break;
        }
        curr_path_info = next_path_info;
    }

    if (!End) {
        /* Broke out early, cleanup current path and release any mode set*/
        topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);
    }

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispSetVidPnSourceAddress(CONST HANDLE hAdapter,
                              CONST DXGKARG_SETVIDPNSOURCEADDRESS *pSetVidPnSourceAddress)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION*)hAdapter;
    UXENDISP_CRTC *crtc;
    KIRQL irql;
    ULONG i;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pSetVidPnSourceAddress))
        return STATUS_INVALID_PARAMETER;

    /*
     * Set the source address for each CRTC that is a target of the source.
     * For clone mode this could be > 1.
     * Note this routine could be called at DIRQL for an MMIO based flip.
     */
    for (i = 0; i < dev->crtc_count; i++) {
        crtc = &dev->crtcs[i];
        if (crtc->sourceid == pSetVidPnSourceAddress->VidPnSourceId)
            crtc->primary_address = pSetVidPnSourceAddress->PrimaryAddress;
    }

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispSetVidPnSourceVisibility(CONST HANDLE hAdapter,
                                 CONST DXGKARG_SETVIDPNSOURCEVISIBILITY *pSetVidPnSourceVisibility)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION*)hAdapter;
    UXENDISP_CRTC *crtc;
    ULONG i;
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pSetVidPnSourceVisibility))
        return STATUS_INVALID_PARAMETER;

    /*
     * Reconfigure each CRTC that is a target of the source.
     * For clone mode this could be > 1.
     */
    for (i = 0; i < dev->crtc_count; i++) {
        crtc = &dev->crtcs[i];
        if (crtc->sourceid == pSetVidPnSourceVisibility->VidPnSourceId) {
            if (pSetVidPnSourceVisibility->Visible) {
                /* start scanning source */
                uxdisp_crtc_write(dev, crtc->crtcid, UXDISP_REG_CRTC_ENABLE, 1);
                uxdisp_crtc_write(dev, crtc->crtcid, UXDISP_REG_CRTC_XRES,
                                  crtc->curr_mode.xres);
                uxdisp_crtc_write(dev, crtc->crtcid, UXDISP_REG_CRTC_YRES,
                                  crtc->curr_mode.yres);
                uxdisp_crtc_write(dev, crtc->crtcid, UXDISP_REG_CRTC_STRIDE,
                                  crtc->curr_mode.stride);
                uxdisp_crtc_write(dev, crtc->crtcid, UXDISP_REG_CRTC_FORMAT,
                                  crtc->curr_mode.fmt);
                /* Flush */
                uxdisp_crtc_write(dev, crtc->crtcid, UXDISP_REG_CRTC_OFFSET,
                                  crtc->primary_address.LowPart);
            } else {
                /* stop scanning source */
                // uXenDispCrtcDisable(dev, crtc);
            }
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispCommitVidPn(CONST HANDLE hAdapter,
                    CONST DXGKARG_COMMITVIDPN *CONST pCommitVidPn)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION*)hAdapter;
    DXGK_VIDPN_INTERFACE *vidpn_if = NULL;
    D3DKMDT_HVIDPNTOPOLOGY topology_hdl;
    DXGK_VIDPNTOPOLOGY_INTERFACE *topology_if;
    D3DKMDT_VIDPN_PRESENT_PATH *curr_path_info;
    D3DKMDT_VIDPN_PRESENT_PATH *next_path_info;
    D3DKMDT_HVIDPNSOURCEMODESET source_mode_set_hdl;
    DXGK_VIDPNSOURCEMODESET_INTERFACE *source_mode_set_if;
    D3DKMDT_VIDPN_SOURCE_MODE *src_mode_info;
    UXENDISP_SOURCE_MAP_ENTRY *source_map;
    UXENDISP_PINNED_STATE pinned_state;
    UXENDISP_CRTC *crtc;
    NTSTATUS status;
    KIRQL irql;
    ULONG i;

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pCommitVidPn))
        return STATUS_INVALID_PARAMETER;

    /* This is where a new VidPN is set for the adapter. The source -> target mapping*/
    /* must be saved for all the paths.*/
    status = dev->dxgkif.DxgkCbQueryVidPnInterface(pCommitVidPn->hFunctionalVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &vidpn_if);
    if (!NT_SUCCESS(status)) {
        uxen_err("DxgkCbQueryVidPnInterface failed: 0x%x", status);
        return status; /* SNO*/
    }

    status = vidpn_if->pfnGetTopology(pCommitVidPn->hFunctionalVidPn, &topology_hdl, &topology_if);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnGetTopology failed: 0x%x", status);
        return status; /* SNO*/
    }

    /* Enumerate paths and determine which sources are associated with which targets. */
    status = topology_if->pfnAcquireFirstPathInfo(topology_hdl, &curr_path_info);
    if (status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        /* Empty topology */
        return STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
    }
    else if (!NT_SUCCESS(status)) {
        uxen_err("pfnAcquireFirstPathInfo failed: 0x%x", status);
        return STATUS_NO_MEMORY; /* bad topology? - probably low memory */
    }

    /* Alloc a buffer to temporarily hold the new mappings */
    source_map = ExAllocatePoolWithTag(NonPagedPool,
                                       dev->crtc_count * sizeof(UXENDISP_SOURCE_MAP_ENTRY),
                                       UXENDISP_TAG);
    if (!source_map)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(source_map, dev->crtc_count * sizeof(UXENDISP_SOURCE_MAP_ENTRY));
    for (i = 0; i < dev->crtc_count; i++)
        source_map[i].sourceid = D3DDDI_ID_UNINITIALIZED;

    for (i = 0; i < dev->crtc_count; i++) {
        /* can't be more paths than sources/targets*/

        /*
         * Do we care about this path further? Note that in the case where a
         * single source is specified, if it has been removed from a path to
         * a target, the map below will include this information since
         * the value will be left as D3DDDI_ID_UNINITIALIZED and will be seen
         * when reconciled.
         */
        if ((pCommitVidPn->AffectedVidPnSourceId != D3DDDI_ID_ALL)&&
            (pCommitVidPn->AffectedVidPnSourceId != curr_path_info->VidPnSourceId)) {
            topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);
            continue;
        }

        /* Path targets must have a monitor attached if D3DKMDT_MCC_ENFORCE is specified. If not then the*/
        /* new VidPN must be rejected and the current one kept.*/
        if (pCommitVidPn->MonitorConnectivityChecks == D3DKMDT_MCC_ENFORCE) {
            crtc = &dev->crtcs[curr_path_info->VidPnTargetId];

            /*
             * Check at this point in time by just reading the status
             * register whether a monitor is connected even though a DPC
             * could be running or run to change the CRTC state
             * simultaneously.
             */
            if (!uxdisp_crtc_read(dev, crtc->crtcid, UXDISP_REG_CRTC_STATUS)) {
                status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
                topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);
                break;
            }
        }

        /*
         * On each path with source changes, set the source associated
         * with the target/CRTC.
         */
        source_map[curr_path_info->VidPnTargetId].sourceid = curr_path_info->VidPnSourceId;

        /* Fetch the pinned mode information to update the CRTCs with*/
        status = vidpn_if->pfnAcquireSourceModeSet(pCommitVidPn->hFunctionalVidPn,
                                                   curr_path_info->VidPnSourceId,
                                                   &source_mode_set_hdl,
                                                   &source_mode_set_if);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnAcquireSourceModeSet on path in new VidPN failed: 0x%x", status);
            topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);
            break;
        }

        status = source_mode_set_if->pfnAcquirePinnedModeInfo(source_mode_set_hdl, &src_mode_info);
        pinned_state = pinned_mode_state(status, src_mode_info);
        if (pinned_state == UXENDISP_PS_PINNED) {
            if (src_mode_info->Type == D3DKMDT_RMT_GRAPHICS) {
                source_map[curr_path_info->VidPnTargetId].fmt = src_mode_info->Format.Graphics;
                source_map[curr_path_info->VidPnTargetId].fmt_set = TRUE;
            }
            else {
                uxen_msg("pfnAcquirePinnedModeInfo returned non-graphical information, keeping current mode values.");
            }
            source_mode_set_if->pfnReleaseModeInfo(source_mode_set_hdl, src_mode_info);
        }
        else if (pinned_state == UXENDISP_PS_ERROR) {
            uxen_err("pfnAcquirePinnedModeInfo for current source failed: 0x%x", status);
            vidpn_if->pfnReleaseSourceModeSet(pCommitVidPn->hFunctionalVidPn, source_mode_set_hdl);
            topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);
            break;
        }

        vidpn_if->pfnReleaseSourceModeSet(pCommitVidPn->hFunctionalVidPn, source_mode_set_hdl);

        status = topology_if->pfnAcquireNextPathInfo(topology_hdl, curr_path_info, &next_path_info);
        /* Done with the last path.*/
        topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);

        if (status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            break;
        }
        else if (!NT_SUCCESS(status)) {
            uxen_err("pfnAcquireNextPathInfo failed: 0x%x", status);
            break;
        }
        curr_path_info = next_path_info;
    }

    if (status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET)
        status = STATUS_SUCCESS;

    /* Drop out here for errors*/
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(source_map, UXENDISP_TAG);
        return status;
    }

    /* Reconcile the new map with the old, determine what has changed. Stage everything*/
    /* and only commit changes when everything is validated.*/
    for (i = 0; i < dev->crtc_count; i++) {
        crtc = &dev->crtcs[i];

        /* Reset all staging values to defaults.*/
        crtc->staged_sourceid = D3DDDI_ID_UNINITIALIZED;
        crtc->staged_flags = 0;

        /* Test if new mode information could be obtained above.*/
        if (!source_map[i].fmt_set) {
            crtc->staged_flags |= UXENDISP_CRTC_STAGED_FLAG_SKIP;
            continue;
        }

        /*
         * Case: |T| ... |T|
         * Do nothing.
         */
        if ((crtc->sourceid == D3DDDI_ID_UNINITIALIZED) &&
            (source_map[i].sourceid == D3DDDI_ID_UNINITIALIZED))
            continue;

        /*
         * Case: |T|<-|S| ... |T|
         * Path was removed, stage a reset
         */
        if ((crtc->sourceid != D3DDDI_ID_UNINITIALIZED)&&
            (source_map[i].sourceid == D3DDDI_ID_UNINITIALIZED)) {
            crtc->staged_flags |= UXENDISP_CRTC_STAGED_FLAG_DISABLE;
            continue;
        }

        crtc->staged_sourceid = source_map[i].sourceid;
        /*
         * Want to do a reset to stop scanning to any primary surface
         * that is currently programmed for the CRTC.
         */
        crtc->staged_flags |= UXENDISP_CRTC_STAGED_FLAG_DISABLE;
    }

    /*
     * Lock for the VidPN commit since the CRTCs mode information
     * (which is transient) will be accessed.
     */
    KeAcquireSpinLock(&dev->crtc_lock, &irql);

    for (i = 0; i < dev->crtc_count; i++) {
        crtc = &dev->crtcs[i];

        /*
         * Commit all staged values if everything is reconciled and
         * validated above else reject the VidPN.
         */
        if (NT_SUCCESS(status)) {
            if (!(crtc->staged_flags & UXENDISP_CRTC_STAGED_FLAG_SKIP)) {
                crtc->sourceid = crtc->staged_sourceid;
                if (crtc->fb)
                    MmUnmapIoSpace(crtc->fb, crtc->curr_mode.stride * crtc->curr_mode.yres);
                /*
                 * Make a copy of the current mode that can be accessed
                 * outside of the lock.
                 */
                RtlMoveMemory(&crtc->curr_mode, &crtc->next_mode,
                              sizeof(UXENDISP_MODE));
                if (crtc->staged_flags & UXENDISP_CRTC_STAGED_FLAG_DISABLE) {
                    //uXenDispCrtcDisable(dev, crtc);
                }
                crtc->fb = MmMapIoSpace(dev->vram_phys, crtc->curr_mode.stride * crtc->curr_mode.yres, MmNonCached);
                ASSERT(crtc->fb);
            }
        }

        /* Clear all staging values*/
        crtc->staged_sourceid = D3DDDI_ID_UNINITIALIZED;
        crtc->staged_flags = 0;
    }

    KeReleaseSpinLock(&dev->crtc_lock, irql);

    ExFreePoolWithTag(source_map, UXENDISP_TAG);

    return status;
}

NTSTATUS APIENTRY
uXenDispUpdateActiveVidPnPresentPath(CONST HANDLE hAdapter,
                                   CONST DXGKARG_UPDATEACTIVEVIDPNPRESENTPATH *CONST pUpdateActiveVidPnPresentPath)
{
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pUpdateActiveVidPnPresentPath))
        return STATUS_INVALID_PARAMETER;

    /* Probably don't need to do too much with this one.*/
    return STATUS_SUCCESS;
}

static VOID
init_monitor_source_mode(D3DKMDT_MONITOR_SOURCE_MODE *pVidPnMonitorSourceModeInfo,
                         UXENDISP_MODE *mode)
{
    D3DKMDT_VIDEO_SIGNAL_INFO *signal_info = &pVidPnMonitorSourceModeInfo->VideoSignalInfo;

    PAGED_CODE();

    pVidPnMonitorSourceModeInfo->ColorBasis = D3DKMDT_CB_SRGB;
    pVidPnMonitorSourceModeInfo->ColorCoeffDynamicRanges.FirstChannel = 8;
    pVidPnMonitorSourceModeInfo->ColorCoeffDynamicRanges.SecondChannel = 8;
    pVidPnMonitorSourceModeInfo->ColorCoeffDynamicRanges.ThirdChannel = 8;
    pVidPnMonitorSourceModeInfo->ColorCoeffDynamicRanges.FourthChannel = 0;
    pVidPnMonitorSourceModeInfo->Origin = D3DKMDT_MCO_DRIVER;
    pVidPnMonitorSourceModeInfo->Preference = D3DKMDT_MP_PREFERRED;

    signal_info->VideoStandard = D3DKMDT_VSS_OTHER;
    signal_info->TotalSize.cx = mode->xres;
    signal_info->TotalSize.cy = mode->yres;
    signal_info->ActiveSize.cx = mode->xres;
    signal_info->ActiveSize.cy = mode->yres;
    signal_info->PixelRate = mode->xres * mode->yres * UXENDISP_REFRESH_RATE;
    signal_info->VSyncFreq.Numerator = UXENDISP_REFRESH_RATE * 1000;
    signal_info->VSyncFreq.Denominator = 1000;
    signal_info->HSyncFreq.Numerator = (UINT)((signal_info->PixelRate / signal_info->TotalSize.cy) * 1000);
    signal_info->HSyncFreq.Denominator = 1000;
    signal_info->ScanLineOrdering = D3DDDI_VSSLO_PROGRESSIVE;
}

NTSTATUS APIENTRY
uXenDispRecommendMonitorModes(CONST HANDLE hAdapter,
                              CONST DXGKARG_RECOMMENDMONITORMODES *CONST pRecommendMonitorModes)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION*)hAdapter;
    D3DKMDT_MONITOR_SOURCE_MODE *mon_src_mode_info;
    NTSTATUS status = STATUS_SUCCESS;
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pRecommendMonitorModes))
        return STATUS_INVALID_PARAMETER;

    status = pRecommendMonitorModes->pMonitorSourceModeSetInterface->pfnCreateNewModeInfo(
            pRecommendMonitorModes->hMonitorSourceModeSet, &mon_src_mode_info);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnCreateNewModeInfo failed: 0x%x", status);
    }

    if (NT_SUCCESS(status)) {
        init_monitor_source_mode(mon_src_mode_info, &dev->crtcs[0].next_mode);

        status = pRecommendMonitorModes->pMonitorSourceModeSetInterface->pfnAddMode(
                pRecommendMonitorModes->hMonitorSourceModeSet, mon_src_mode_info);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnCreateNewModeInfo pfnAddMode: 0x%x", status);
            pRecommendMonitorModes->pMonitorSourceModeSetInterface->pfnReleaseModeInfo(
                    pRecommendMonitorModes->hMonitorSourceModeSet, mon_src_mode_info);
        }
    }

    return status;
}

NTSTATUS APIENTRY
uXenDispRecommendVidPnTopology(CONST HANDLE hAdapter,
                             CONST DXGKARG_RECOMMENDVIDPNTOPOLOGY *CONST pRecommendVidPnTopology)
{
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pRecommendVidPnTopology))
        return STATUS_INVALID_PARAMETER;

    return STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY;
}

NTSTATUS APIENTRY
uXenDispQueryVidPnHWCapability(CONST HANDLE hAdapter,
                               DXGKARG_QUERYVIDPNHWCAPABILITY* pVidPnHWCaps)
{
    ASSERT(pVidPnHWCaps != NULL);

    pVidPnHWCaps->VidPnHWCaps.DriverRotation             = 0;
    pVidPnHWCaps->VidPnHWCaps.DriverScaling              = 0;
    pVidPnHWCaps->VidPnHWCaps.DriverCloning              = 0;
    pVidPnHWCaps->VidPnHWCaps.DriverColorConvert         = 0;
    pVidPnHWCaps->VidPnHWCaps.DriverLinkedAdapaterOutput = 0;
    pVidPnHWCaps->VidPnHWCaps.DriverRemoteDisplay        = 0;

    return STATUS_SUCCESS;
}
