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

static BOOLEAN
is_supported_path(D3DKMDT_VIDPN_PRESENT_PATH *path_info)
{
    /*
     * Bare minimum support to start with. OK with any of the uncommited
     * states for transformations.
     */
    if ((path_info->ContentTransformation.Scaling != D3DKMDT_VPPS_UNINITIALIZED)&&
        (path_info->ContentTransformation.Scaling != D3DKMDT_VPPS_IDENTITY)&&
        (path_info->ContentTransformation.Scaling != D3DKMDT_VPPS_UNPINNED)&&
        (path_info->ContentTransformation.Scaling != D3DKMDT_VPPS_NOTSPECIFIED)) {
        uxen_debug("unsupported Scaling value: %d", path_info->ContentTransformation.Scaling);
        return FALSE;
    }

    if ((path_info->ContentTransformation.ScalingSupport.Centered != 0)||
        (path_info->ContentTransformation.ScalingSupport.Stretched != 0)) {
        /*(path_info->ContentTransformation.ScalingSupport.AspectRatioCenteredMax != 0)*/
        /*(path_info->ContentTransformation.ScalingSupport.Custom != 0)*/
        uxen_debug("unsupported ScalingSupport value: %d", path_info->ContentTransformation.ScalingSupport);
        return FALSE;
    }

    if ((path_info->ContentTransformation.Rotation != D3DKMDT_VPPR_UNINITIALIZED)&&
        (path_info->ContentTransformation.Rotation != D3DKMDT_VPPR_IDENTITY)&&
        (path_info->ContentTransformation.Rotation != D3DKMDT_VPPR_UNPINNED)&&
        (path_info->ContentTransformation.Rotation != D3DKMDT_VPPR_NOTSPECIFIED)) {
        uxen_debug("unsupported Rotation value: %d", path_info->ContentTransformation.Rotation);
        return FALSE;
    }

    if ((path_info->ContentTransformation.RotationSupport.Rotate90 != 0)||
        (path_info->ContentTransformation.RotationSupport.Rotate180 != 0)||
        (path_info->ContentTransformation.RotationSupport.Rotate270 != 0)) {
        uxen_debug("unsupported RotationSupport value: %d", path_info->ContentTransformation.RotationSupport);
        return FALSE;
    }

    if ((path_info->VisibleFromActiveTLOffset.cx != 0)||
        (path_info->VisibleFromActiveTLOffset.cy != 0)||
        (path_info->VisibleFromActiveBROffset.cx != 0)||
        (path_info->VisibleFromActiveBROffset.cy != 0)) {
        uxen_debug("TL/BR offsets not supported.");
        return FALSE;
    }

    if ((path_info->VidPnTargetColorBasis != D3DKMDT_CB_SRGB)&&
        (path_info->VidPnTargetColorBasis != D3DKMDT_CB_UNINITIALIZED)) {
        uxen_debug("unsupported ColorBasis: %d.", path_info->VidPnTargetColorBasis);
        return FALSE;
    }

    if ((path_info->Content != D3DKMDT_VPPC_UNINITIALIZED)&&
        (path_info->Content != D3DKMDT_VPPC_GRAPHICS)&&
        (path_info->Content != D3DKMDT_VPPC_NOTSPECIFIED)) {
        uxen_debug("unsupported Content: %d.");
        return FALSE;
    }

    if ((path_info->CopyProtection.CopyProtectionType != D3DKMDT_VPPMT_NOPROTECTION)&&
        (path_info->CopyProtection.CopyProtectionType != D3DKMDT_VPPMT_UNINITIALIZED)) {
        uxen_debug("CopyProtection not supported.");
        return FALSE;
    }

    if ((path_info->GammaRamp.Type != D3DDDI_GAMMARAMP_DEFAULT)&&
        (path_info->GammaRamp.Type != D3DDDI_GAMMARAMP_UNINITIALIZED)) {
        uxen_debug("non-default gamma ramp not supported.");
        return FALSE;
    }

    return TRUE;
}

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

static __inline BOOLEAN
region_compare(D3DKMDT_2DREGION *r1, D3DKMDT_2DREGION *r2)
{
    return (r1->cx == r2->cx) && (r1->cy == r2->cy);
}

static BOOLEAN
is_supported_target_mode(UXENDISP_CRTC *crtc,
                         D3DKMDT_VIDPN_TARGET_MODE *target_mode)
{
    D3DKMDT_VIDEO_SIGNAL_INFO *signal_info;
    PAGED_CODE();

    signal_info = &target_mode->VideoSignalInfo;

    if ((signal_info->ActiveSize.cx > UXENDISP_CRTC_MAX_XRES) ||
        (signal_info->ActiveSize.cy > UXENDISP_CRTC_MAX_YRES)) {
        uxen_debug("target mode resolution to large for CRTC.");
        return FALSE;
    }

    /* Expected values without resolution values being present.*/
    if ((signal_info->VideoStandard != D3DKMDT_VSS_OTHER)||
        (signal_info->TotalSize.cx != D3DKMDT_DIMENSION_NOTSPECIFIED)||
        (signal_info->TotalSize.cy != D3DKMDT_DIMENSION_NOTSPECIFIED)||
        (signal_info->VSyncFreq.Numerator != 60 * 1000)||
        (signal_info->VSyncFreq.Denominator != 1000)||
        (signal_info->HSyncFreq.Denominator != 1000)||
        (signal_info->ScanLineOrdering != D3DDDI_VSSLO_PROGRESSIVE)) {
        uxen_debug("unsupported target mode value(s).");
        return FALSE;
    }

    return TRUE;
}


static BOOLEAN
is_supported_target_mode_set(UXENDISP_CRTC *crtc,
                             D3DKMDT_HVIDPNTARGETMODESET tgt_mode_set_hdl,
                             CONST DXGK_VIDPNTARGETMODESET_INTERFACE *target_mode_set_if,
                             UXENDISP_PINNED_MODES *pinned_modes)
{
    D3DKMDT_VIDPN_TARGET_MODE *curr_mode_info;
    D3DKMDT_VIDPN_TARGET_MODE *next_mode_info;
    UXENDISP_PINNED_STATE pinned_state;
    NTSTATUS status;
    BOOLEAN r;

    PAGED_CODE();

    /* If there is a pinned, mode validate only this mode.*/
    status = target_mode_set_if->pfnAcquirePinnedModeInfo(tgt_mode_set_hdl, &curr_mode_info);
    pinned_state = pinned_mode_state(status, curr_mode_info);
    if (pinned_state == UXENDISP_PS_PINNED) {
        r = is_supported_target_mode(crtc, curr_mode_info);
        if (r) {
            pinned_modes->tgt_pinned = TRUE;
            pinned_modes->tgt_active_size = curr_mode_info->VideoSignalInfo.ActiveSize;
        }
        target_mode_set_if->pfnReleaseModeInfo(tgt_mode_set_hdl, curr_mode_info);
        return r;
    }
    else if (pinned_state == UXENDISP_PS_ERROR) {
        uxen_err("pfnAcquirePinnedModeInfo failed: 0x%x", status);
        return FALSE; /* bad handles - probably low memory*/
    }

    status = target_mode_set_if->pfnAcquireFirstModeInfo(tgt_mode_set_hdl, &curr_mode_info);
    if (status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        /* Empty set, that is OK*/
        return TRUE;
    }
    else if (!NT_SUCCESS(status)) {
        uxen_err("pfnAcquireFirstModeInfo failed: 0x%x", status);
        return FALSE; /* bad handles - probably low memory       */
    }

    while (TRUE) {
        /* Test the unpinned modes, only need to find one that will potentially work to*/
        /* report this is supported.*/
        if (is_supported_target_mode(crtc, curr_mode_info)) {
            target_mode_set_if->pfnReleaseModeInfo(tgt_mode_set_hdl, curr_mode_info);
            return TRUE;
        }

        status = target_mode_set_if->pfnAcquireNextModeInfo(tgt_mode_set_hdl, curr_mode_info, &next_mode_info);
        /* Done with the last path.*/
        target_mode_set_if->pfnReleaseModeInfo(tgt_mode_set_hdl, curr_mode_info);

        if (status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            return FALSE; /* done enumerating, did not find any that can be implemented.*/
        }
        else if (!NT_SUCCESS(status)) {
            uxen_err("pfnAcquireNextModeInfo failed: 0x%x", status);
            return FALSE;
        }
        curr_mode_info = next_mode_info;
    }

    /* Nothing supported found.*/
    return FALSE;
}

static BOOLEAN
is_supported_source_mode(UXENDISP_CRTC *crtc, D3DKMDT_VIDPN_SOURCE_MODE *source_mode_info)
{
    PAGED_CODE();

    /* Only supporting graphics type for now.*/
    if (source_mode_info->Type != D3DKMDT_RMT_GRAPHICS) {
        uxen_debug("unsupported mode type: %d", source_mode_info->Type);
        return FALSE;
    }

    /* Check the visible and primary surfaces match*/
    if (!region_compare(&source_mode_info->Format.Graphics.VisibleRegionSize,
                        &source_mode_info->Format.Graphics.PrimSurfSize)) {
        uxen_debug("visible and primary surface size mismatch.");
        return FALSE;
    }

    if ((source_mode_info->Format.Graphics.PrimSurfSize.cx > UXENDISP_CRTC_MAX_XRES) ||
        (source_mode_info->Format.Graphics.PrimSurfSize.cy > UXENDISP_CRTC_MAX_YRES)) {
        uxen_debug("source mode resolution too large for CRTC.");
        return FALSE;
    }

    if ((source_mode_info->Format.Graphics.ColorBasis != D3DKMDT_CB_SRGB)&&
        (source_mode_info->Format.Graphics.ColorBasis != D3DKMDT_CB_UNINITIALIZED)) {
        uxen_debug("unsupported color basis: %d.", source_mode_info->Format.Graphics.ColorBasis);
        return FALSE;
    }

    if (ddi_to_uxendisp_fmt(source_mode_info->Format.Graphics.PixelFormat) == -1) {
        uxen_debug("unsupported pixel format: %d.", source_mode_info->Format.Graphics.PixelFormat);
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
is_supported_source_mode_set(UXENDISP_CRTC *crtc,
                            D3DKMDT_HVIDPNSOURCEMODESET source_mode_set_hdl,
                            CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *source_mode_set_if,
                            UXENDISP_PINNED_MODES *pinned_modes)
{
    D3DKMDT_VIDPN_SOURCE_MODE *curr_source_mode_info = NULL;
    D3DKMDT_VIDPN_SOURCE_MODE *next_source_mode_info;
    UXENDISP_PINNED_STATE pinned_state;
    NTSTATUS status;
    BOOLEAN r;

    PAGED_CODE();

    /* If there is a pinned, mode validate only this mode.*/
    status = source_mode_set_if->pfnAcquirePinnedModeInfo(source_mode_set_hdl, &curr_source_mode_info);
    pinned_state = pinned_mode_state(status, curr_source_mode_info);
    if (pinned_state == UXENDISP_PS_PINNED) {
        r = is_supported_source_mode(crtc, curr_source_mode_info);
        if (r) {
            pinned_modes->src_pinned = TRUE;
            pinned_modes->src_primary_surf_size = curr_source_mode_info->Format.Graphics.PrimSurfSize;
        }
        source_mode_set_if->pfnReleaseModeInfo(source_mode_set_hdl, curr_source_mode_info);
        return r;
    }
    else if (pinned_state == UXENDISP_PS_ERROR) {
        uxen_err("pfnAcquirePinnedModeInfo failed: 0x%x", status);
        return FALSE; /* bad handles - probably low memory*/
    }

    status = source_mode_set_if->pfnAcquireFirstModeInfo(source_mode_set_hdl, &curr_source_mode_info);
    if (status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        /* Empty set, that is OK*/
        return TRUE;
    }
    else if (!NT_SUCCESS(status)) {
        uxen_err("pfnAcquireFirstModeInfo failed: 0x%x", status);
        return FALSE; /* bad handles - probably low memory       */
    }

    while (TRUE) {
        /* Test the unpinned modes, only need to find one that will potentially work to*/
        /* report this is supported.*/
        if (is_supported_source_mode(crtc, curr_source_mode_info)) {
            source_mode_set_if->pfnReleaseModeInfo(source_mode_set_hdl, curr_source_mode_info);
            return TRUE;
        }

        status = source_mode_set_if->pfnAcquireNextModeInfo(source_mode_set_hdl, curr_source_mode_info, &next_source_mode_info);
        /* Done with the last path.*/
        source_mode_set_if->pfnReleaseModeInfo(source_mode_set_hdl, curr_source_mode_info);

        if (status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            return FALSE; /* done enumerating, did not find any that can be implemented.*/
        }
        else if (!NT_SUCCESS(status)) {
            uxen_err("pfnAcquireNextModeInfo failed: 0x%x", status);
            return FALSE;
        }
        curr_source_mode_info = next_source_mode_info;
    }

    /* Nothing supported found.*/
    return FALSE;
}

static UXENDISP_MODE_SET *
get_mode_set(DEVICE_EXTENSION *dev, ULONG child_uid)
{
    KIRQL irql;
    UXENDISP_CRTC *crtc = &dev->crtcs[child_uid];
    UXENDISP_MODE_SET *mode_set;

    if (child_uid >= dev->crtc_count)
        return NULL;

    KeAcquireSpinLock(&dev->crtc_lock, &irql);
    mode_set = crtc->mode_set;
    mode_set->refcount++;
    KeReleaseSpinLock(&dev->crtc_lock, irql);

    return mode_set;
}

static VOID
put_mode_set(DEVICE_EXTENSION *dev, UXENDISP_MODE_SET *mode_set)
{
    KIRQL irql;

    KeAcquireSpinLock(&dev->crtc_lock, &irql);
    if (--mode_set->refcount == 0) {
        ExFreePoolWithTag(mode_set->modes, UXENDISP_TAG);
        ExFreePoolWithTag(mode_set, UXENDISP_TAG);
    }
    KeReleaseSpinLock(&dev->crtc_lock, irql);
}

NTSTATUS APIENTRY
uXenDispIsSupportedVidPn(CONST HANDLE  hAdapter,
                         DXGKARG_ISSUPPORTEDVIDPN *pIsSupportedVidPn)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION*)hAdapter;
    DXGK_VIDPN_INTERFACE *vidpn_if = NULL;
    D3DKMDT_HVIDPNTOPOLOGY topology_hdl;
    DXGK_VIDPNTOPOLOGY_INTERFACE *topology_if;
    D3DKMDT_VIDPN_PRESENT_PATH *curr_path_info;
    D3DKMDT_VIDPN_PRESENT_PATH *next_path_info;
    D3DKMDT_HVIDPNSOURCEMODESET source_mode_set_hdl;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *source_mode_set_if;
    D3DKMDT_HVIDPNTARGETMODESET tgt_mode_set_hdl;
    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *target_mode_set_if;
    UXENDISP_PINNED_MODES pinned_modes;
    NTSTATUS status;
    BOOLEAN End = FALSE;

    ULONG i = 0;
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pIsSupportedVidPn))
        return STATUS_INVALID_PARAMETER;

    pIsSupportedVidPn->IsVidPnSupported = FALSE;

    status = dev->dxgkif.DxgkCbQueryVidPnInterface(pIsSupportedVidPn->hDesiredVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &vidpn_if);
    if (!NT_SUCCESS(status)) {
        uxen_err("DxgkCbQueryVidPnInterface failed: 0x%x", status);
        return STATUS_NO_MEMORY; /* SNO*/
    }

    status = vidpn_if->pfnGetTopology(pIsSupportedVidPn->hDesiredVidPn, &topology_hdl, &topology_if);
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnGetTopology failed: 0x%x", status);
        return STATUS_NO_MEMORY; /* SNO*/
    }

    status = topology_if->pfnAcquireFirstPathInfo(topology_hdl, &curr_path_info);
    if (status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        /* Empty topology, that is OK (case 3 in the docs)*/
        pIsSupportedVidPn->IsVidPnSupported = TRUE;
        return STATUS_SUCCESS;
    }
    else if (!NT_SUCCESS(status)) {
        uxen_err("pfnAcquireFirstPathInfo failed: 0x%x", status);
        return STATUS_NO_MEMORY; /* bad topology? - probably low memory       */
    }

    /*
     * TODO for now actual monitor modes are not being used to validate
     * the proposed topology. If this is needed, the block below would
     * need to be locked.
     */

    /*
     * The topology is the set of all paths and the sources/targets they
     * connect to. A path brings those objects and their mode sets/modes
     * into the topology by being connected to them. Other sources/targets
     * may exist outside the topology. We do not care about those. The loop
     * below will handle cases 1 and 2 in the docs. Don't need to lock for
     * CRTC access right now - only reading read-only values to check CRTC
     * codec capabilities for the topology.
     */
    while (TRUE) {
        pinned_modes.src_pinned = pinned_modes.tgt_pinned = FALSE;

        /* -- Path --*/
        if (i == dev->crtc_count) {
            /* Can't be more paths than sources/targets?*/
            uxen_err("more paths in topology than there are targets/sources??");
            status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        if (!is_supported_path(curr_path_info)) {
            topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);
            status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        /* -- Target --*/
        if (curr_path_info->VidPnTargetId >= dev->crtc_count) {
            /* Invalid VidPnTargetId*/
            uxen_err("invalid VidPnTargetId %d for path at %d??",
                     curr_path_info->VidPnTargetId, i);
            status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        /* Check the target mode set for the VidPnTargetId of this path. Note there is*/
        /* a 1 to 1 mapping from targets to paths.*/
        status = vidpn_if->pfnAcquireTargetModeSet(pIsSupportedVidPn->hDesiredVidPn,
                                                          curr_path_info->VidPnTargetId,
                                                          &tgt_mode_set_hdl,
                                                          &target_mode_set_if);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnAcquireTargetModeSet failed: 0x%x", status);
            break;
        }

        if (!is_supported_target_mode_set(&dev->crtcs[curr_path_info->VidPnTargetId],
                                          tgt_mode_set_hdl,
                                          target_mode_set_if,
                                          &pinned_modes)) {
            vidpn_if->pfnReleaseTargetModeSet(pIsSupportedVidPn->hDesiredVidPn, tgt_mode_set_hdl);
            status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        vidpn_if->pfnReleaseTargetModeSet(pIsSupportedVidPn->hDesiredVidPn, tgt_mode_set_hdl);

        /* -- Source --*/
        if (curr_path_info->VidPnSourceId >= dev->crtc_count) {
            /* Invalid VidPnTargetId*/
            uxen_err("invalid VidPnSourceId %d for path at %d??",
                     curr_path_info->VidPnSourceId, i);
            status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        /* Check the source mode set for the VidPnSourceId of this path. Note we could scan*/
        /* the sets more than once if a source is on multiple paths - this is OK.*/
        status = vidpn_if->pfnAcquireSourceModeSet(pIsSupportedVidPn->hDesiredVidPn,
                                                          curr_path_info->VidPnSourceId,
                                                          &source_mode_set_hdl,
                                                          &source_mode_set_if);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnAcquireSourceModeSet failed: 0x%x", status);
            break;
        }

        if (!is_supported_source_mode_set(&dev->crtcs[curr_path_info->VidPnTargetId],
                                         source_mode_set_hdl,
                                         source_mode_set_if,
                                         &pinned_modes)) {
            vidpn_if->pfnReleaseSourceModeSet(pIsSupportedVidPn->hDesiredVidPn, source_mode_set_hdl);
            status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        vidpn_if->pfnReleaseSourceModeSet(pIsSupportedVidPn->hDesiredVidPn, source_mode_set_hdl);

        /* -- Pinned -- */
        /*
         * Since transformation, rotation, etc is not supported right now,
         * the pinned target and source must match eachothers
         * to support this pinning. The check handles clone mode also in
         * that it tests each source against its target.
         */
        if (pinned_modes.src_pinned && pinned_modes.tgt_pinned) {
            if (!region_compare(&pinned_modes.src_primary_surf_size,
                                &pinned_modes.tgt_active_size)) {
                uxen_debug("pinned source and target modes don't match.", status);
                status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
                break;
            }
        }

        /* -- Next -- */
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
        i++;
    }

    if (!End) /* broke out early, cleanup current path*/
        topology_if->pfnReleasePathInfo(topology_hdl, curr_path_info);

    if (!NT_SUCCESS(status))
        return status;

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
    if (mode->flags & UXENDISP_MODE_FLAG_PREFERRED)
        target_mode->Preference = D3DKMDT_MP_PREFERRED;
    else
        target_mode->Preference = D3DKMDT_MP_NOTPREFERRED;

    /*
     * Init signal information (much like what is done for setting
     * up a monitor mode).
     */
    signal_info = &target_mode->VideoSignalInfo;
    signal_info->VideoStandard = D3DKMDT_VSS_OTHER;
    signal_info->TotalSize.cx = D3DKMDT_DIMENSION_NOTSPECIFIED;
    signal_info->TotalSize.cy = D3DKMDT_DIMENSION_NOTSPECIFIED;
    signal_info->ActiveSize.cx = mode->xres;
    signal_info->ActiveSize.cy = mode->yres;
    signal_info->VSyncFreq.Numerator = 60 * 1000;
    signal_info->VSyncFreq.Denominator = 1000;
    signal_info->HSyncFreq.Numerator = 60 * mode->yres * 1000 * (105 / 100);
    signal_info->HSyncFreq.Denominator = 1000;
    signal_info->PixelRate = mode->xres * mode->yres * 60;
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
                       UXENDISP_MODE_SET *mode_set,
                       CONST D3DKMDT_HVIDPN vidpn_hdl,
                       DXGK_VIDPN_INTERFACE *vidpn_if,
                       D3DKMDT_VIDPN_PRESENT_PATH *curr_path_info)
{
    D3DKMDT_HVIDPNTARGETMODESET tgt_mode_set_hdl = NULL;
    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *target_mode_set_if;
    D3DKMDT_VIDPN_TARGET_MODE *tgt_mode_info = NULL;
    D3DKMDT_HVIDPNSOURCEMODESET source_mode_set_hdl = NULL;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *source_mode_set_if;
    D3DKMDT_VIDPN_SOURCE_MODE *src_mode_info = NULL;
    UXENDISP_PINNED_STATE pinned_state;
    UXENDISP_MODE *mode;
    ULONG count = 0, i;
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

    status = vidpn_if->pfnAcquireSourceModeSet(vidpn_hdl,
                                                      curr_path_info->VidPnSourceId,
                                                      &source_mode_set_hdl,
                                                      &source_mode_set_if);
    if (!NT_SUCCESS(status)) {
        vidpn_if->pfnReleaseTargetModeSet(vidpn_hdl, tgt_mode_set_hdl);
        uxen_err("pfnAcquireSourceModeSet failed: 0x%x", status);
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

        /* Acquire any pinned source mode since this will constrain the target modes that are added.*/
        status = source_mode_set_if->pfnAcquirePinnedModeInfo(source_mode_set_hdl, &src_mode_info);
        pinned_state = pinned_mode_state(status, src_mode_info);
        if (pinned_state == UXENDISP_PS_ERROR) {
            uxen_err("pfnAcquirePinnedModeInfo(source) failed: 0x%x", status);
            src_mode_info = NULL;
            break; /* unknown nasty failure*/
        }
        if (pinned_state == UXENDISP_PS_UNPINNED)
            src_mode_info = NULL;

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

        /*
         * Enumerate over the modes for the CRTC adding them. This is more
         * or less what the sample does. This could be done using the monitor
         * modes set but it is not clear whether that would contain all
         * the modes needed.
         */
        /*
         * N.B. If there is no mode set, commit an empty set to this path
         * since there is nothing to initialize it with. Other possible
         * options would be to leave it as is or add a default mode set.
         * It seems the sample would effectively do what is done here.
         */
        if (mode_set != NULL)
            count = mode_set->mode_count;

        for (i = 0; i < count; i++) {
            mode = &mode_set->modes[i];

            /* Only target modes that match a pinned source mode*/
            if (src_mode_info != NULL) {
                if ((src_mode_info->Format.Graphics.PrimSurfSize.cx == mode->xres)&&
                    (src_mode_info->Format.Graphics.PrimSurfSize.cy == mode->yres)) {
                    if (ddi_to_uxendisp_fmt(src_mode_info->Format.Graphics.PixelFormat) == -1)
                        continue;
                }
                else {
                    continue;
                }
            }

            /* Add the next mode to the set.*/
            status = add_target_mode(tgt_mode_set_hdl,
                                     target_mode_set_if,
                                     mode);
            if (!NT_SUCCESS(status)) {
                uxen_err("uXenDispAddTargetMode failed: 0x%x", status);
                break;
            }
        }

        if (!NT_SUCCESS(status))
            break;

        status = vidpn_if->pfnAssignTargetModeSet(vidpn_hdl,
                                                         curr_path_info->VidPnTargetId,
                                                         tgt_mode_set_hdl);
        if (NT_SUCCESS(status))
            tgt_mode_set_hdl = NULL;
        else
            uxen_err("pfnAssignTargetModeSet failed: 0x%x", status);

    } while (FALSE);

    if (src_mode_info != NULL)
        source_mode_set_if->pfnReleaseModeInfo(source_mode_set_hdl, src_mode_info);

    if (tgt_mode_info != NULL)
        target_mode_set_if->pfnReleaseModeInfo(tgt_mode_set_hdl, tgt_mode_info);

    if (source_mode_set_hdl != NULL)
        vidpn_if->pfnReleaseSourceModeSet(vidpn_hdl, source_mode_set_hdl);

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
                       UXENDISP_MODE_SET *mode_set,
                       CONST D3DKMDT_HVIDPN vidpn_hdl,
                       DXGK_VIDPN_INTERFACE *vidpn_if,
                       D3DKMDT_VIDPN_PRESENT_PATH *curr_path_info)
{
    D3DKMDT_HVIDPNSOURCEMODESET source_mode_set_hdl = NULL;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *source_mode_set_if;
    D3DKMDT_VIDPN_SOURCE_MODE *src_mode_info = NULL;
    D3DKMDT_HVIDPNTARGETMODESET tgt_mode_set_hdl = NULL;
    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *target_mode_set_if;
    D3DKMDT_VIDPN_TARGET_MODE *tgt_mode_info = NULL;
    UXENDISP_PINNED_STATE pinned_state;
    UXENDISP_MODE *mode;
    ULONG count = 0, i;
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

    status = vidpn_if->pfnAcquireTargetModeSet(vidpn_hdl,
                                               curr_path_info->VidPnTargetId,
                                               &tgt_mode_set_hdl,
                                               &target_mode_set_if);
    if (!NT_SUCCESS(status)) {
        vidpn_if->pfnReleaseSourceModeSet(vidpn_hdl, source_mode_set_hdl);
        uxen_err("pfnAcquireTargetModeSet failed: 0x%x", status);
        return status; /* low memory - bail out on operation.*/
    }

    do {
        /* If the source mode set already has a pinned mode, don't do any updates.*/
        status = source_mode_set_if->pfnAcquirePinnedModeInfo(source_mode_set_hdl,
                                                              &src_mode_info);
        pinned_state = pinned_mode_state(status, src_mode_info);
        if (pinned_state == UXENDISP_PS_PINNED) {
            /*
             * Sanity check to make sure this pinned source mode specifies
             * a pixel format that this CRTC can handle.
             */
            if (ddi_to_uxendisp_fmt(src_mode_info->Format.Graphics.PixelFormat) != -1)
                status = STATUS_SUCCESS;
            else
                status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            /* Drop out */
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

        /*
         * Acquire any pinned target mode since this will constrain the
         * source modes that are added.
         */
        status = target_mode_set_if->pfnAcquirePinnedModeInfo(tgt_mode_set_hdl,
                                                              &tgt_mode_info);
        pinned_state = pinned_mode_state(status, tgt_mode_info);
        if (pinned_state == UXENDISP_PS_ERROR) {
            uxen_err("pfnAcquirePinnedModeInfo(target) failed: 0x%x", status);
            tgt_mode_info = NULL;
            break; /* unknown nasty failure*/
        }
        if (pinned_state == UXENDISP_PS_UNPINNED)
            tgt_mode_info = NULL;

        /* Make a new source mode set*/
        status = vidpn_if->pfnCreateNewSourceModeSet(vidpn_hdl,
                                                     curr_path_info->VidPnSourceId,
                                                     &source_mode_set_hdl,
                                                     &source_mode_set_if);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnCreateNewSourceModeSet failed: 0x%x", status);
            tgt_mode_set_hdl = NULL;
            break; /* no memory*/
        }

        /*
         * Enumerate over the modes for the CRTC adding them. This is more
         * or less what the sample does. This could be done using the
         * monitor modes set but it is not clear whether that would contain
         * all the modes needed.
         */

        /*
         * N.B. If there is no mode set, commit an empty set to this path
         * since there is nothing to initialize it with. Other possible
         * options would be to leave it as is or add a default mode set.
         * It seems the sample would effectively do what is done here.
         */
        if (mode_set != NULL)
            count = mode_set->mode_count;

        for (i = 0; i < count; i++) {
            mode = &mode_set->modes[i];

            /* Only target modes that match a pinned source mode*/
            if (tgt_mode_info != NULL) {
                if ((tgt_mode_info->VideoSignalInfo.ActiveSize.cx != mode->xres) ||
                    (tgt_mode_info->VideoSignalInfo.ActiveSize.cy != mode->yres)) {
                    continue;
                }
            }

            /* Add the next mode to the set.*/
            status = add_source_mode(source_mode_set_hdl,
                                     source_mode_set_if,
                                     mode);
            if (!NT_SUCCESS(status)) {
                uxen_err("add_source_mode failed: 0x%x", status);
                break;
            }
        }

        if (!NT_SUCCESS(status))
            break;

        status = vidpn_if->pfnAssignSourceModeSet(vidpn_hdl,
                                                  curr_path_info->VidPnSourceId,
                                                  source_mode_set_hdl);
        if (NT_SUCCESS(status))
            source_mode_set_hdl = NULL;
        else
            uxen_err("pfnAssignSourceModeSet failed: 0x%x", status);

    } while (FALSE);

    if (tgt_mode_info != NULL)
        target_mode_set_if->pfnReleaseModeInfo(tgt_mode_set_hdl, tgt_mode_info);

    if (src_mode_info != NULL)
        source_mode_set_if->pfnReleaseModeInfo(source_mode_set_hdl, src_mode_info);

    if (tgt_mode_set_hdl != NULL)
        vidpn_if->pfnReleaseTargetModeSet(vidpn_hdl, tgt_mode_set_hdl);

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
    DXGK_MONITOR_INTERFACE *monitor_interface;
    D3DKMDT_HVIDPNTOPOLOGY topology_hdl;
    DXGK_VIDPNTOPOLOGY_INTERFACE *topology_if;
    D3DKMDT_VIDPN_PRESENT_PATH *curr_path_info;
    D3DKMDT_VIDPN_PRESENT_PATH *next_path_info;
    D3DKMDT_VIDPN_PRESENT_PATH CurrPathInfo;
    BOOLEAN UpdatePath;
    UXENDISP_MODE_SET *mode_set = NULL;
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

    status = dev->dxgkif.DxgkCbQueryMonitorInterface(dev->dxgkhdl, DXGK_MONITOR_INTERFACE_VERSION_V1, &monitor_interface);
    if (!NT_SUCCESS(status)) {
        uxen_err("DxgkCbQueryMonitorInterface failed: 0x%x", status);
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
        /* -- Path --*/
        UpdatePath = FALSE;
        RtlMoveMemory(&CurrPathInfo, curr_path_info, sizeof(D3DKMDT_VIDPN_PRESENT_PATH));

        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_SCALING)&&
            (curr_path_info->ContentTransformation.Scaling == D3DKMDT_VPPS_UNPINNED)) {
            RtlZeroMemory(&CurrPathInfo.ContentTransformation.ScalingSupport, sizeof(D3DKMDT_VIDPN_PRESENT_PATH_SCALING_SUPPORT));
            CurrPathInfo.ContentTransformation.ScalingSupport.Identity = TRUE;
            UpdatePath = TRUE;
        }

        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_ROTATION)&&
            (curr_path_info->ContentTransformation.Rotation == D3DKMDT_VPPS_UNPINNED)) {
            RtlZeroMemory(&CurrPathInfo.ContentTransformation.RotationSupport, sizeof(D3DKMDT_VIDPN_PRESENT_PATH_ROTATION_SUPPORT));
            CurrPathInfo.ContentTransformation.RotationSupport.Identity = TRUE;
            UpdatePath = TRUE;
        }

        if (CurrPathInfo.CopyProtection.CopyProtectionType != D3DKMDT_VPPMT_NOPROTECTION) {
            RtlZeroMemory(&CurrPathInfo.CopyProtection, sizeof(D3DKMDT_VIDPN_PRESENT_PATH_COPYPROTECTION));
            CurrPathInfo.CopyProtection.CopyProtectionType = D3DKMDT_VPPMT_NOPROTECTION;
            UpdatePath = TRUE;
        }

        /*
         * TODO how exactly do you specify the other path values? Like:
         * VisibleFromActive*, ColorBasis values, Content, Gamma etc.
         * According to the docs, pfnUpdatePathSupportInfo only updates
         * transforms and content protection!
         */

        if (UpdatePath) {
            status = topology_if->pfnUpdatePathSupportInfo(topology_hdl, &CurrPathInfo);
            if (!NT_SUCCESS(status)) {
                uxen_err("pfnUpdatePathSupportInfo failed: 0x%x", status);
                break;
            }
        }

        /* -- Target & Source --*/
        mode_set = get_mode_set(dev, curr_path_info->VidPnTargetId);

        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_VIDPNTARGET)||
            (pEnumCofuncModality->EnumPivot.VidPnTargetId != curr_path_info->VidPnTargetId)) {
            status = update_target_mode_set(&dev->crtcs[curr_path_info->VidPnTargetId],
                                            mode_set,
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
                                            mode_set,
                                            pEnumCofuncModality->hConstrainingVidPn,
                                            vidpn_if,
                                            curr_path_info);
            if (!NT_SUCCESS(status)) {
                uxen_err("uXenDispUpdateSourceModeSet failed: 0x%x", status);
                break;
            }
        }

        if (mode_set != NULL)
            put_mode_set(dev, mode_set);

        mode_set = NULL;

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
        if (mode_set != NULL)
            put_mode_set(dev, mode_set);
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
            if (pSetVidPnSourceVisibility->Visible)
                /* start scanning source */
                uXenDispCrtcEnable(dev, crtc);
            else
                /* stop scanning source */
                uXenDispCrtcDisable(dev, crtc);
        }
    }



    return STATUS_SUCCESS;
}

static LONG
validate_new_mode(UXENDISP_CRTC *crtc, UXENDISP_SOURCE_MAP_ENTRY *entry)
{
    ULONG i;
    UXENDISP_MODE *mode;

    /* already checked there is a monitor connected*/
    ASSERT(crtc->mode_set != NULL);
    /* already checked there is a monitor connected*/
    ASSERT(crtc->mode_set->modes != NULL);
    /* already checked there is a new mode set*/
    ASSERT(entry->fmt_set);

    if (crtc->mode_set->mode_count < 1) {
        uxen_err("monitor connected but no modes for CRTC %p", crtc);
        return -1;
    }

    for (i = 0; i < crtc->mode_set->mode_count; i++) {
        mode = &crtc->mode_set->modes[i];
        if (mode->xres == entry->fmt.VisibleRegionSize.cx &&
            mode->yres == entry->fmt.VisibleRegionSize.cy &&
            ddi_to_uxendisp_fmt(entry->fmt.PixelFormat) != -1 &&
            mode->stride == entry->fmt.Stride)
            return i;
    }

    return -1;
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
        crtc->staged_modeidx = -1;
        crtc->staged_sourceid = D3DDDI_ID_UNINITIALIZED;
        crtc->staged_fmt = -1;
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

        /*
         * All other cases:
         *      |T|       ... |T|<-|S|     new path and source
         *      |T|<-|S1| ... |T|<-|S2|    new source
         *      |T|<-|S1| ... |T|<-|S1|    same source
         *      |T|<-|S1| ... |T|<-|S1'|   same source, new mode
         * Check for monitor, validate mode, stage values
         */
        if (crtc->connected) {
            crtc->staged_modeidx = validate_new_mode(crtc, &source_map[i]);
            if (crtc->staged_modeidx == -1) {
                status = STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED;
                break;
            }
        }

        crtc->staged_sourceid = source_map[i].sourceid;
        crtc->staged_fmt = ddi_to_uxendisp_fmt(source_map[i].fmt.PixelFormat);
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
                crtc->modeidx = crtc->staged_modeidx;
                crtc->sourceid = crtc->staged_sourceid;

                /* Set the new mode format*/
                if (crtc->staged_fmt != -1)
                    crtc->mode_set->modes[crtc->modeidx].fmt = crtc->staged_fmt;

                /*
                 * Make a copy of the current mode that can be accessed
                 * outside of the lock.
                 */
                RtlMoveMemory(&crtc->curr_mode, &crtc->mode_set->modes[crtc->modeidx],
                              sizeof(UXENDISP_MODE));

                if (crtc->staged_flags & UXENDISP_CRTC_STAGED_FLAG_DISABLE)
                    uXenDispCrtcDisable(dev, crtc);
            }
        }

        /* Clear all staging values*/
        crtc->staged_modeidx = -1;
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

static BOOLEAN
compare_monitor_modes(UXENDISP_MODE *mode,
                      D3DKMDT_HMONITORSOURCEMODESET mon_src_mode_set_hdl,
                      CONST DXGK_MONITORSOURCEMODESET_INTERFACE *mon_src_mode_set_if)
{
    D3DKMDT_MONITOR_SOURCE_MODE *curr_info;
    D3DKMDT_MONITOR_SOURCE_MODE *next_info;
    D3DKMDT_2DREGION active_size;
    NTSTATUS status;
    BOOLEAN r = TRUE;

    PAGED_CODE();

    /*
     * Enumerate monitor modes and determine if the mode already exists.
     */
    status = mon_src_mode_set_if->pfnAcquireFirstModeInfo(mon_src_mode_set_hdl,
                                                          &curr_info);
    if (status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        /* Empty set, that is OK */
        return FALSE;
    }
    if (!NT_SUCCESS(status)) {
        uxen_err("pfnAcquireFirstModeInfo failed: 0x%x", status);
        return TRUE; /* bad mode set? - more likely low memory - probably can't add to it*/
    }

    while (TRUE) {
        active_size = curr_info->VideoSignalInfo.ActiveSize;

        /* Match, then it is already there.*/
        if ((active_size.cx == mode->xres) &&
            (active_size.cy == mode->yres)) {
            mon_src_mode_set_if->pfnReleaseModeInfo(mon_src_mode_set_hdl, curr_info);
            break;
        }

        status = mon_src_mode_set_if->pfnAcquireNextModeInfo(mon_src_mode_set_hdl, curr_info, &next_info);
        mon_src_mode_set_if->pfnReleaseModeInfo(mon_src_mode_set_hdl, curr_info);

        if (status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            r = FALSE;
            break;
        }
        else if (!NT_SUCCESS(status)) {
            uxen_err("pfnAcquireNextPathInfo failed: 0x%x", status);
            break; /* bad mode set? - more likely low memory - probably can't add to it*/
        }
        curr_info = next_info;
    }

    return r;
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

    if (mode->flags & UXENDISP_MODE_FLAG_PREFERRED)
        pVidPnMonitorSourceModeInfo->Preference = D3DKMDT_MP_PREFERRED;
    else
        pVidPnMonitorSourceModeInfo->Preference = D3DKMDT_MP_NOTPREFERRED;

    signal_info->VideoStandard = D3DKMDT_VSS_OTHER;
    signal_info->TotalSize.cx = D3DKMDT_DIMENSION_NOTSPECIFIED;
    signal_info->TotalSize.cy = D3DKMDT_DIMENSION_NOTSPECIFIED;
    signal_info->ActiveSize.cx = mode->xres;
    signal_info->ActiveSize.cy = mode->yres;
    signal_info->VSyncFreq.Numerator = 60 * 1000;
    signal_info->VSyncFreq.Denominator = 1000;
    signal_info->HSyncFreq.Numerator = 60 * mode->yres * 1000 * (105 / 100);
    signal_info->HSyncFreq.Denominator = 1000;
    signal_info->PixelRate = mode->xres * mode->yres * 60;
    signal_info->ScanLineOrdering = D3DDDI_VSSLO_PROGRESSIVE;
}

NTSTATUS APIENTRY
uXenDispRecommendMonitorModes(CONST HANDLE hAdapter,
                              CONST DXGKARG_RECOMMENDMONITORMODES *CONST pRecommendMonitorModes)
{
    DEVICE_EXTENSION *dev = (DEVICE_EXTENSION*)hAdapter;
    D3DKMDT_HMONITORSOURCEMODESET mon_src_mode_set_hdl;
    CONST DXGK_MONITORSOURCEMODESET_INTERFACE *mon_src_mode_set_if;
    D3DKMDT_MONITOR_SOURCE_MODE *mon_src_mode_info;
    UXENDISP_MODE_SET *mode_set;
    UXENDISP_MODE *mode;
    UXENDISP_MODE **mode_list;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hAdapter) ||
        !ARGUMENT_PRESENT(pRecommendMonitorModes))
        return STATUS_INVALID_PARAMETER;

    ASSERT(pRecommendMonitorModes->VideoPresentTargetId < dev->crtc_count);
    mon_src_mode_set_hdl = pRecommendMonitorModes->hMonitorSourceModeSet;
    mon_src_mode_set_if = pRecommendMonitorModes->pMonitorSourceModeSetInterface;

    /*
     * It seems reasonable to assume this is called when a monitor is
     * hotplugged to allow modes to be added the the monitor source mode set.
     */
    /*
     * N.B. The working assumption here is that the monitor modes are gotten
     * from the EDID query on the child device. This set should include 3
     * standard timings and the detailed timing for the preferred mode. This
     * corresponds to the modes with either UXENDISP_MODE_FLAG_BASE_SET
     * or UXENDISP_MODE_FLAG_EDID_MODE flags set. It remains to be seen how
     * the directx kernel handles this.
     */
    mode_set = get_mode_set(dev, pRecommendMonitorModes->VideoPresentTargetId);
    if (!mode_set)
        return STATUS_SUCCESS; /* no monitor at this point*/

    /* Temp queue to hold modes to recommend.*/
    mode_list = ExAllocatePoolWithTag(NonPagedPool,
                                      mode_set->mode_count * sizeof(UXENDISP_MODE),
                                      UXENDISP_TAG);
    if (!mode_list) {
        put_mode_set(dev, mode_set);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(mode_list, mode_set->mode_count * sizeof(UXENDISP_MODE));

    for (i = 0; i < mode_set->mode_count; i++) {
        if (!compare_monitor_modes(&mode_set->modes[i],
                                   mon_src_mode_set_hdl,
                                   mon_src_mode_set_if)) {
            mode_list[i] = &mode_set->modes[i];
        }
    }

    /* Add any missing modes*/
    for (i = 0; i < mode_set->mode_count; i++) {
        if (mode_list[i] == NULL)
            continue;

        status = mon_src_mode_set_if->pfnCreateNewModeInfo(mon_src_mode_set_hdl, &mon_src_mode_info);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnCreateNewModeInfo failed: 0x%x", status);
            break; /* bad mode set? - probably low memory       */
        }

        init_monitor_source_mode(mon_src_mode_info, mode_list[i]);

        status = mon_src_mode_set_if->pfnAddMode(mon_src_mode_set_hdl, mon_src_mode_info);
        if (!NT_SUCCESS(status)) {
            uxen_err("pfnCreateNewModeInfo pfnAddMode: 0x%x", status);
            mon_src_mode_set_if->pfnReleaseModeInfo(mon_src_mode_set_hdl, mon_src_mode_info);
        }
    }

    ExFreePoolWithTag(mode_list, UXENDISP_TAG);
    put_mode_set(dev, mode_set);

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

