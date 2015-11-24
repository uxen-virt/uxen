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

static NTSTATUS
connect_helper(DEVICE_EXTENSION *dev, UXENDISP_CRTC *crtc)
{
    UXENDISP_MODE_SET *mode_set;
    UXENDISP_MODE *modes;

    if (!crtc->edid) {
        crtc->edid_len = 128;
        crtc->edid = ExAllocatePoolWithTag(NonPagedPool,
                                           crtc->edid_len,
                                           UXENDISP_TAG);
    }
    if (!crtc->edid)
        return STATUS_NO_MEMORY;

    ASSERT(crtc->edid_len >= 128);

    RtlCopyMemory(crtc->edid,
                  dev->mmio + UXDISP_REG_CRTC(crtc->crtcid) + UXDISP_REG_CRTC_EDID_DATA,
                  crtc->edid_len);

    mode_set = ExAllocatePoolWithTag(NonPagedPool,
                                     sizeof(UXENDISP_MODE_SET),
                                     UXENDISP_TAG);
    if (!mode_set)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(mode_set, sizeof(UXENDISP_MODE_SET));

    modes = ExAllocatePoolWithTag(NonPagedPool,
                                  UXENDISP_MAX_MODE_COUNT * sizeof(UXENDISP_MODE),
                                  UXENDISP_TAG);
    if (!modes) {
        ExFreePoolWithTag(mode_set, UXENDISP_TAG);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(modes, UXENDISP_MAX_MODE_COUNT * sizeof(UXENDISP_MODE));

    mode_set->mode_count = edid_get_modes(crtc->edid,
                                          crtc->edid_len,
                                          modes,
                                          UXENDISP_MAX_MODE_COUNT);
    mode_set->refcount = 1;
    mode_set->child_uid = crtc->crtcid;
    mode_set->modes = modes;

    if (crtc->mode_set) {
        ExFreePoolWithTag(crtc->mode_set->modes, UXENDISP_TAG);
        ExFreePoolWithTag(crtc->mode_set, UXENDISP_TAG);
    }
    crtc->mode_set = mode_set;

    return STATUS_SUCCESS;
}


static NTSTATUS
disconnect_helper(UXENDISP_CRTC *crtc)
{
    if (crtc->edid) {
        ExFreePoolWithTag(crtc->edid, UXENDISP_TAG);
        crtc->edid = NULL;
        crtc->edid_len = 0;
    }
    if (crtc->mode_set) {
        ExFreePoolWithTag(crtc->mode_set->modes, UXENDISP_TAG);
        ExFreePoolWithTag(crtc->mode_set, UXENDISP_TAG);
        crtc->mode_set = NULL;
    }

    return STATUS_SUCCESS;
}

VOID
uXenDispDetectChildStatusChanges(DEVICE_EXTENSION *dev)
{
    KIRQL irql;
    ULONG i;
    DXGK_CHILD_STATUS child_status;

    if (!InterlockedExchangeAdd(&dev->initialized, 0))
        return;

    KeAcquireSpinLock(&dev->crtc_lock, &irql);
    for (i = 0; i < dev->crtc_count; i++) {
        UXENDISP_CRTC *crtc = &dev->crtcs[i];
        ULONG status;

        status = uxdisp_crtc_read(dev, crtc->crtcid, UXDISP_REG_CRTC_STATUS);
        if (status) {
            connect_helper(dev, crtc);
            if (!crtc->connected) {
                child_status.ChildUid = crtc->crtcid;
                child_status.Type = StatusConnection;
                child_status.HotPlug.Connected = TRUE;
                crtc->connected = TRUE;
                dev->dxgkif.DxgkCbIndicateChildStatus(dev->dxgkhdl, &child_status);
            }
        } else {
            disconnect_helper(crtc);
            if (crtc->connected) {
                child_status.ChildUid = crtc->crtcid;
                child_status.Type = StatusConnection;
                child_status.HotPlug.Connected = FALSE;
                crtc->connected = FALSE;
                dev->dxgkif.DxgkCbIndicateChildStatus(dev->dxgkhdl, &child_status);
            }
        }
    }
    KeReleaseSpinLock(&dev->crtc_lock, irql);
}

VOID
uXenDispCrtcDisablePageTracking(DEVICE_EXTENSION *dev)
{
    ULONG val = uxdisp_read(dev, UXDISP_REG_MODE);
    val |= UXDISP_MODE_PAGE_TRACKING_DISABLED;
    uxdisp_write(dev, UXDISP_REG_MODE, val);
}

NTSTATUS
uXenDispCrtcEnable(DEVICE_EXTENSION *dev, UXENDISP_CRTC *crtc)
{
    if (!crtc->connected) {
        uxen_err("CRTC=%p no monitor present\n", crtc);
        return STATUS_INVALID_PARAMETER;
    }

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

    return STATUS_SUCCESS;
}

NTSTATUS
uXenDispCrtcDisable(DEVICE_EXTENSION *dev, UXENDISP_CRTC *crtc)
{
    //uxdisp_crtc_write(dev, crtc->crtcid, UXDISP_REG_CRTC_ENABLE, 0);
    /* Flush */
    //uxdisp_crtc_write(dev, crtc->crtcid, UXDISP_REG_CRTC_OFFSET, 0);

    return STATUS_SUCCESS;
}
