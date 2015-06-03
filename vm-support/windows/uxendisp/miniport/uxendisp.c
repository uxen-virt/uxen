/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxendisp.h"

#include "hw.h"
#include "dirty_rect.h"

#include <uxendisp_ioctl.h>
#include <uxendisp_esc.h>

VP_STATUS FindAdapter(PVOID dev_extension,
                      PVOID reserved,
                      PWSTR arg_str,
                      PVIDEO_PORT_CONFIG_INFO conf_info,
                      PUCHAR again);

BOOLEAN Initialize(PVOID dev_extension);

VP_STATUS GetPowerState(PVOID dev_extension,
                        ULONG hw_id,
                        PVIDEO_POWER_MANAGEMENT state);

VP_STATUS SetPowerState(PVOID dev_extension,
                        ULONG hw_wId,
                        PVIDEO_POWER_MANAGEMENT state);

VP_STATUS GetChildDescriptor(IN PVOID dev_extension,
                             IN PVIDEO_CHILD_ENUM_INFO  enum_info,
                             OUT PVIDEO_CHILD_TYPE  type,
                             OUT PUCHAR descriptor,
                             OUT PULONG uid,
                             OUT PULONG unused);

BOOLEAN StartIO(PVOID dev_extension, PVIDEO_REQUEST_PACKET packet);

BOOLEAN Interrupt(PVOID  HwDeviceExtension);

BOOLEAN ResetHw(PVOID dev_ext, ULONG colums, ULONG Rows);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, DriverEntry)
#pragma alloc_text(PAGE, FindAdapter)
#pragma alloc_text(PAGE, Initialize)
#pragma alloc_text(PAGE, GetPowerState)
#pragma alloc_text(PAGE, SetPowerState)
#pragma alloc_text(PAGE, GetChildDescriptor)
#pragma alloc_text(PAGE, StartIO)
#endif

static VIDEO_ACCESS_RANGE legacyRanges[] = {
    { 0x000003b0, 0x00000000, 0x0000000C, 1, 1, 1, 0 },
    { 0x000003c0, 0x00000000, 0x00000020, 1, 1, 1, 0 },
    { 0x000A0000, 0x00000000, 0x00020000, 0, 0, 1, 0 },
};

ULONG DriverEntry(PVOID context1, PVOID context2)
{
    VIDEO_HW_INITIALIZATION_DATA init_data;
    ULONG ret;

    PAGED_CODE();

    DBG_INFO("");

    VideoPortZeroMemory(&init_data, sizeof(VIDEO_HW_INITIALIZATION_DATA));
    init_data.HwInitDataSize = sizeof(VIDEO_HW_INITIALIZATION_DATA);
    init_data.HwDeviceExtensionSize = sizeof(DEVICE_EXTENSION);

    init_data.HwFindAdapter = FindAdapter;
    init_data.HwInitialize = Initialize;
    init_data.HwGetPowerState = GetPowerState;
    init_data.HwSetPowerState = SetPowerState;
    init_data.HwGetVideoChildDescriptor = GetChildDescriptor;
    init_data.HwStartIO = StartIO;
    init_data.HwInterrupt = Interrupt;
    init_data.HwResetHw = ResetHw;
    init_data.HwLegacyResourceList = legacyRanges;
    init_data.HwLegacyResourceCount = 3;

    ret = VideoPortInitialize(context1, context2, &init_data, NULL);

    if (ret != NO_ERROR) {
        init_data.HwInitDataSize = SIZE_OF_W2K_VIDEO_HW_INITIALIZATION_DATA;
        ret = VideoPortInitialize(context1, context2, &init_data, NULL);
    }
    return ret;
}

#if defined(ALLOC_PRAGMA)
VP_STATUS InitIO(PDEVICE_EXTENSION dev, PVIDEO_ACCESS_RANGE range);
#pragma alloc_text(PAGE, InitIO)
#endif

VP_STATUS InitIO(PDEVICE_EXTENSION dev, PVIDEO_ACCESS_RANGE range)
{
    UINT8 *mmio = NULL;
    ULONG mmio_size = range->RangeLength;
    ULONG io_space = VIDEO_MEMORY_SPACE_MEMORY;
    VP_STATUS ret;

    PAGED_CODE();

    DBG_INFO("range=%x/%x,io=%d", range->RangeStart,
                                  range->RangeLength,
                                  range->RangeInIoSpace);

    ret = VideoPortMapMemory(dev, range->RangeStart,
                             &mmio_size, &io_space, &mmio);
    if (ret != NO_ERROR) {
        return ret;
    }

    if (mmio_size < range->RangeLength) {
        ret = ERROR_NOT_ENOUGH_MEMORY;
        goto err_map;
    }

    dev->mmio_physical = range->RangeStart;
    dev->mmio_start = mmio;
    dev->mmio_size = mmio_size;

    return NO_ERROR;

err_map:
    VideoPortUnmapMemory(dev, mmio, NULL);
    return ret;
}

#if defined(ALLOC_PRAGMA)
VP_STATUS InitVRAM(PDEVICE_EXTENSION dev, PVIDEO_ACCESS_RANGE range);
#pragma alloc_text(PAGE, InitVRAM)
#endif

VP_STATUS InitVRAM(PDEVICE_EXTENSION dev, PVIDEO_ACCESS_RANGE range)
{
    UINT8 *vram = NULL;
    ULONG vram_size = range->RangeLength;
    ULONG io_space = VIDEO_MEMORY_SPACE_MEMORY;
    VP_STATUS ret;

    PAGED_CODE();

    DBG_INFO("range=%x/%x,io=%d", range->RangeStart,
                                        range->RangeLength,
                                        range->RangeInIoSpace);

    ret = VideoPortMapMemory(dev, range->RangeStart,
                             &vram_size, &io_space, &vram);
    if (ret != NO_ERROR) {
        return ret;
    }

    if (vram_size < range->RangeLength) {
        ret = ERROR_NOT_ENOUGH_MEMORY;
        goto err_map;
    }

    dev->vram_physical = range->RangeStart;
    dev->vram_start = vram;
    dev->vram_size = hw_get_vram_size(dev);

    DBG_INFO("vram_size=%d RangeLength=%d",
             dev->vram_size, range->RangeLength);

    if (dev->vram_size > range->RangeLength)
        dev->vram_size = range->RangeLength;

    return NO_ERROR;

err_map:
    VideoPortUnmapMemory(dev, vram, NULL);
    return ret;
}


#if defined(ALLOC_PRAGMA)
VP_STATUS Prob(PDEVICE_EXTENSION dev, VIDEO_PORT_CONFIG_INFO *conf_info,
               PVIDEO_ACCESS_RANGE ranges, int n_ranges);
#pragma alloc_text(PAGE, Prob)
#endif

VP_STATUS Prob(PDEVICE_EXTENSION dev, VIDEO_PORT_CONFIG_INFO *conf_info,
               PVIDEO_ACCESS_RANGE ranges, int n_ranges)
{
    PCI_COMMON_CONFIG pci_conf;
    ULONG  bus_data_size;
    VP_STATUS ret;

    PAGED_CODE();

    DBG_INFO("n_ranges=%d", n_ranges);

    bus_data_size = VideoPortGetBusData(dev,
                                        PCIConfiguration,
                                        0,
                                        &pci_conf,
                                        0,
                                        sizeof(PCI_COMMON_CONFIG));

    if (bus_data_size != sizeof(PCI_COMMON_CONFIG)) {
        return ERROR_INVALID_PARAMETER;
    }

    if (pci_conf.VendorID != UXENDISP_PCI_VEN) {
        return ERROR_INVALID_PARAMETER;
    }

    if (pci_conf.DeviceID != UXENDISP_PCI_DEV) {
        return ERROR_INVALID_PARAMETER;
    }

    VideoPortZeroMemory(ranges, sizeof(VIDEO_ACCESS_RANGE) * n_ranges);
    ret = VideoPortGetAccessRanges(dev, 0, NULL, n_ranges,
                                   ranges, NULL, NULL,
                                   NULL);

    return ret;
}

#if defined(ALLOC_PRAGMA)
VP_STATUS InitModes(PDEVICE_EXTENSION dev);
#pragma alloc_text(PAGE, InitModes)
#endif

VP_STATUS InitModes(PDEVICE_EXTENSION dev)
{
    PVIDEO_MODE_INFORMATION modes_info;
    ULONG n_modes;
    ULONG i;
    VP_STATUS ret;

    PAGED_CODE();

    DBG_INFO("");

    n_modes = hw_get_nmodes(dev);

    /* Custom modes */
    dev->custom_mode = n_modes;
    n_modes += 2;

#if (WINVER < 0x0501) //Win2K
    ret = VideoPortAllocateBuffer(dev, n_modes * sizeof(VIDEO_MODE_INFORMATION), &modes_info);

    if(!modes_info || ret != NO_ERROR) {
        DBG_ERR("Failed to allocate Buffer. ret=%d", ret);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
#else
    if (!(modes_info = VideoPortAllocatePool(dev, VpPagedPool,
                                             n_modes * sizeof(VIDEO_MODE_INFORMATION),
                                             'uxdi'))) {
        DBG_ERR("Failed to allocate Pool");
        return ERROR_NOT_ENOUGH_MEMORY;
    }
#endif
    VideoPortZeroMemory(modes_info, sizeof(VIDEO_MODE_INFORMATION) * n_modes);

    for (i = 0; i < dev->custom_mode; i++) {
        ret = hw_get_mode_info(dev, i, &modes_info[i]);
        if (ret != NO_ERROR) {
            DBG_ERR("Error getting mode information (idx=%d): %d", i, ret);
            VideoPortFreePool(dev, modes_info);
            return ret;
        }
    }

    for (; i < n_modes; ++i) {
        memcpy(&modes_info[i], &modes_info[0], sizeof(VIDEO_MODE_INFORMATION));
        modes_info[i].ModeIndex = 0x200 + (i - dev->custom_mode);
    }

    dev->n_modes = n_modes;
    dev->modes = modes_info;
    DBG_INFO("Found %d modes", dev->n_modes);

    return NO_ERROR;
}


#if defined(ALLOC_PRAGMA)
void DevExtensionCleanup(PDEVICE_EXTENSION dev);
#pragma alloc_text(PAGE, DevExtensionCleanup)
#endif

void DevExtensionCleanup(PDEVICE_EXTENSION dev)
{
    PAGED_CODE();

    DBG_INFO("");

    if (dev->vram_start) {
        VideoPortUnmapMemory(dev, dev->vram_start, NULL);
    }

    if (dev->modes) {
        VideoPortFreePool(dev, dev->modes);
    }

    VideoPortZeroMemory(dev, sizeof(DEVICE_EXTENSION));
}

VP_STATUS FindAdapter(PVOID dev_ext,
                      PVOID reserved,
                      PWSTR arg_str,
                      PVIDEO_PORT_CONFIG_INFO conf_info,
                      PUCHAR again)
{
    PDEVICE_EXTENSION dev = dev_ext;
    VP_STATUS status;
    VIDEO_ACCESS_RANGE ranges[3];
#if (WINVER >= 0x0501)
    VPOSVERSIONINFO  sys_info;
#endif
    PAGED_CODE();

    DBG_INFO("");

#if (WINVER >= 0x0501)
    VideoPortZeroMemory(&sys_info, sizeof(VPOSVERSIONINFO));
    sys_info.Size = sizeof(VPOSVERSIONINFO);
    if ((status = VideoPortGetVersion(dev, &sys_info)) != NO_ERROR ||
        sys_info.MajorVersion < 5 || (sys_info.MajorVersion == 5 && sys_info.MinorVersion < 1) ) {
        return ERROR_NOT_SUPPORTED;
    }
#endif

    if (conf_info->Length < sizeof(VIDEO_PORT_CONFIG_INFO)) {
        return ERROR_INVALID_PARAMETER;
    }

    if (conf_info->AdapterInterfaceType != PCIBus) {
        return ERROR_DEV_NOT_EXIST;
    }

    if ((status = Prob(dev, conf_info, ranges, 3)) != NO_ERROR ||
        (status = InitIO(dev, &ranges[1])) != NO_ERROR ||
        (status = InitVRAM(dev, &ranges[0])) != NO_ERROR ||
        (status = InitModes(dev)) != NO_ERROR) {
        DevExtensionCleanup(dev);
    }

    conf_info->NumEmulatorAccessEntries = 0;
    conf_info->EmulatorAccessEntries = NULL;
    conf_info->EmulatorAccessEntriesContext = 0;
    conf_info->HardwareStateSize = 0;
    conf_info->VdmPhysicalVideoMemoryAddress.LowPart = 0;
    conf_info->VdmPhysicalVideoMemoryAddress.HighPart = 0;
    conf_info->VdmPhysicalVideoMemoryLength = 0;

    *again = 0;

    return NO_ERROR;
}

BOOLEAN ResetHw(PVOID dev_ext, ULONG colums, ULONG Rows)
{
    PDEVICE_EXTENSION dev = dev_ext;

    dr_deinit(dev->dr_ctx);
    hw_disable(dev);

    return FALSE;
}

BOOLEAN Initialize(PVOID dev_ext)
{
    PDEVICE_EXTENSION dev = dev_ext;
    VP_DEVICE_DESCRIPTION dev_desc;

    PAGED_CODE();

    DBG_INFO("");

    dev_desc.ScatterGather = FALSE;
    dev_desc.Dma32BitAddresses = TRUE;
    dev_desc.Dma64BitAddresses = FALSE;
    dev_desc.MaximumLength = 4096;
    dev->dma = VideoPortGetDmaAdapter(dev, &dev_desc);

    hw_init(dev);

    dev->dr_ctx = dr_init(dev, hw_disable_page_tracking);
    if (dev->dr_ctx == NULL)
    {
        DBG_ERR("Error dr_init failed.\n");
        return FALSE;
    }

    return TRUE;
}

VP_STATUS GetPowerState(PVOID dev_ext,
                        ULONG hw_id,
                        PVIDEO_POWER_MANAGEMENT pm_stat)
{
    PDEVICE_EXTENSION dev = dev_ext;

    PAGED_CODE();

    DBG_INFO("");

    switch (hw_id) {
    case DISPLAY_ADAPTER_HW_ID:
        switch (pm_stat->PowerState) {
        case VideoPowerOn:
        case VideoPowerStandBy:
        case VideoPowerSuspend:
        case VideoPowerOff:
        case VideoPowerShutdown:
        case VideoPowerHibernate:
            return NO_ERROR;
        }
        break;
    default:
        break;
    }
    return ERROR_DEVICE_REINITIALIZATION_NEEDED;
}

VP_STATUS SetPowerState(PVOID dev_ext,
                        ULONG hw_id,
                        PVIDEO_POWER_MANAGEMENT pm_stat)
{
    PDEVICE_EXTENSION dev = dev_ext;

    DBG_INFO("");

    PAGED_CODE();

    switch (hw_id) {
    case DISPLAY_ADAPTER_HW_ID:
        switch (pm_stat->PowerState) {
        case VideoPowerOn:
            break;
        case VideoPowerStandBy:
            break;
        case VideoPowerSuspend:
            break;
        case VideoPowerOff:
            break;
        case VideoPowerShutdown:
            /* Important: you cannot call out to qxldd.dll here or you get a BSOD. */
            break;
        case VideoPowerHibernate:
            break;
        default:
            return ERROR_DEVICE_REINITIALIZATION_NEEDED;
        }
        break;
    default:
        return ERROR_DEVICE_REINITIALIZATION_NEEDED;
    }
    return NO_ERROR;
}

VP_STATUS GetChildDescriptor(IN PVOID dev_ext,
                             IN PVIDEO_CHILD_ENUM_INFO enum_info,
                             OUT PVIDEO_CHILD_TYPE type,
                             OUT PUCHAR descriptor,
                             OUT PULONG uid,
                             OUT PULONG unused)
{
    PDEVICE_EXTENSION dev = dev_ext;

    PAGED_CODE();

    DBG_INFO("ChildIndex=%d", enum_info->ChildIndex);

    switch (enum_info->ChildIndex) {
    case 0:
        return ERROR_NO_MORE_DEVICES;
    case 1:
        *type = Monitor;
        //*uid = DISPLAY_ADAPTER_HW_ID;
        *uid = 0x1;
        /* EDID ? */
        return VIDEO_ENUM_MORE_DEVICES;
    }
    return ERROR_NO_MORE_DEVICES;
}

BOOLEAN StartIO(PVOID dev_ext, PVIDEO_REQUEST_PACKET packet)
{
    PDEVICE_EXTENSION dev = dev_ext;
    VP_STATUS error;

    PAGED_CODE();

    switch (packet->IoControlCode) {
    case IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES: {
            PVIDEO_NUM_MODES num_modes = (PVIDEO_NUM_MODES)packet->OutputBuffer;

            DBG_INFO("QUERY_NUM_AVAIL_MODES");

            if (packet->OutputBufferLength < (packet->StatusBlock->Information =
                                              sizeof(VIDEO_NUM_MODES))) {
                DBG_ERR("Output buffer not large enough");
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            num_modes->NumModes = dev->n_modes;
            num_modes->ModeInformationLength = sizeof(VIDEO_MODE_INFORMATION);
        }
        break;
    case IOCTL_VIDEO_QUERY_AVAIL_MODES: {
            VIDEO_MODE_INFORMATION *inf;
            VIDEO_MODE_INFORMATION *end;
            VIDEO_MODE_INFORMATION *out;

            DBG_INFO("QUERY_AVAIL_MODES");

            if (packet->OutputBufferLength < (packet->StatusBlock->Information =
                                              dev->n_modes * sizeof(VIDEO_MODE_INFORMATION))) {
                DBG_ERR("Output buffer not large enough");
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            out = packet->OutputBuffer;
            inf = dev->modes;
            end = inf + dev->n_modes;
            for ( ;inf < end; out++, inf++) {
                *out = *inf;
            }
        }
        break;
    case IOCTL_VIDEO_SET_CURRENT_MODE: {
            ULONG request_mode;
            ULONG i;
            PVIDEO_MODE_INFORMATION m = NULL;

            DBG_INFO("SET_CURRENT_MODE");

            if (packet->InputBufferLength < sizeof(VIDEO_MODE)) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }
            request_mode = ((PVIDEO_MODE)packet->InputBuffer)->RequestedMode;

            for (i = 0; i < dev->n_modes; i++) {
                if (dev->modes[i].ModeIndex == request_mode) {
                    m = dev->modes + i;
                    break;
                }
            }

            if (!m) {
                error = ERROR_INVALID_DATA;
                goto err;
            }

            error = hw_set_mode(dev, m);
            if (error != NO_ERROR)
                goto err;

            dev->current_mode = m;
        }
        break;
    case IOCTL_VIDEO_QUERY_CURRENT_MODE: {
            PVIDEO_MODE_INFORMATION info = packet->OutputBuffer;

            DBG_INFO("QUERY_CURRENT_MODE");

            if (packet->OutputBufferLength < (packet->StatusBlock->Information =
                                              sizeof(VIDEO_MODE_INFORMATION))) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            *info = *dev->current_mode;
        }
        break;
    case IOCTL_VIDEO_MAP_VIDEO_MEMORY: {
            PVIDEO_MEMORY_INFORMATION mem_info =
                (PVIDEO_MEMORY_INFORMATION)packet->OutputBuffer;

            DBG_INFO("MAP_VIDEO_MEMORY");

            if (packet->OutputBufferLength < (packet->StatusBlock->Information =
                                              sizeof(VIDEO_MEMORY_INFORMATION)) ||
                                            ( packet->InputBufferLength < sizeof(VIDEO_MEMORY) ) ) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            ASSERT(((PVIDEO_MEMORY)(packet->InputBuffer))->RequestedVirtualAddress == NULL);

            mem_info->VideoRamBase = mem_info->FrameBufferBase = dev->vram_start;
            mem_info->VideoRamLength = mem_info->FrameBufferLength = dev->vram_size;
        }
        break;
    case IOCTL_VIDEO_UNMAP_VIDEO_MEMORY: {
            DBG_INFO("UNMAP_VIDEO_MEMORY");
        }
        break;
    case IOCTL_VIDEO_RESET_DEVICE: {
            DBG_INFO("RESET_DEVICE");
        }
        break;
    case IOCTL_VIDEO_GET_CHILD_STATE: {
            PULONG child = (PULONG)packet->InputBuffer;
            PULONG child_state = (PULONG)packet->OutputBuffer;

            if (packet->InputBufferLength < sizeof(ULONG)) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            DBG_INFO("GET_CHILD_STATE child=%x", *child);

            if (packet->OutputBufferLength < (packet->StatusBlock->Information =
                                              sizeof(ULONG))) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            *child_state = VIDEO_CHILD_ACTIVE;
            /* VIDEO_CHILD_NOPRUNE_FREQ | VIDEO_CHILD_NOPRUNE_SIZE */
        }
        break;
    case IOCTL_UXENDISP_SET_CUSTOM_MODE: {
            UXENDISPCustomMode *mode = (UXENDISPCustomMode *)packet->InputBuffer;
            PVIDEO_MODE_INFORMATION info;

            if (packet->InputBufferLength < sizeof (*mode)) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            DBG_INFO("SET_CUSTOM_MODE %dx%d", mode->width, mode->height);

            if (dev->custom_mode == (dev->n_modes - 1))
                dev->custom_mode = dev->n_modes - 2;
            else
                dev->custom_mode = dev->n_modes - 1;

            info = &dev->modes[dev->custom_mode];
            info->VisScreenWidth = mode->width;
            info->VisScreenHeight = mode->height;
            info->ScreenStride = mode->width * 4;
            info->BitsPerPlane = 32;
            info->VideoMemoryBitmapWidth = mode->width;
            info->VideoMemoryBitmapHeight = mode->height;
        }
        break;
    case IOCTL_VIDEO_QUERY_POINTER_CAPABILITIES: {
            PVIDEO_POINTER_CAPABILITIES ptr_cap = packet->OutputBuffer;

            DBG_INFO("QUERY_POINTER_CAPABILITIES");

            if (packet->OutputBufferLength < (packet->StatusBlock->Information =
                                              sizeof(VIDEO_POINTER_CAPABILITIES))) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            ptr_cap->Flags = VIDEO_MODE_ASYNC_POINTER |
                             VIDEO_MODE_COLOR_POINTER |
                             VIDEO_MODE_MONO_POINTER;
            ptr_cap->MaxWidth = POINTER_WIDTH_MAX;
            ptr_cap->MaxHeight = POINTER_HEIGHT_MAX;
            ptr_cap->HWPtrBitmapEnd = -1;
            ptr_cap->HWPtrBitmapStart = -1;
        }
        break;
    case IOCTL_VIDEO_SET_POINTER_ATTR: {
            PVIDEO_POINTER_ATTRIBUTES ptr_attr = packet->InputBuffer;

            if (packet->InputBufferLength < sizeof(*ptr_attr)) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            if (ptr_attr->Width > POINTER_WIDTH_MAX ||
                ptr_attr->Height > POINTER_HEIGHT_MAX) {
                error = ERROR_INVALID_PARAMETER;
                goto err;
            }

            if (ptr_attr->Enable)
                hw_pointer_update(dev, ptr_attr->Width, ptr_attr->Height,
                                  ptr_attr->Column, ptr_attr->Row,
                                  ptr_attr->WidthInBytes, ptr_attr->Pixels,
                                  ptr_attr->Flags & VIDEO_MODE_COLOR_POINTER);
            else
                hw_pointer_enable(dev, FALSE);
        }
        break;
    case IOCTL_VIDEO_SET_POINTER_POSITION: {
            PVIDEO_POINTER_POSITION ptr_pos = packet->InputBuffer;

            if (packet->InputBufferLength < sizeof(*ptr_pos)) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            hw_pointer_setpos(dev, ptr_pos->Column, ptr_pos->Row);
        }
        break;
    case IOCTL_VIDEO_DISABLE_POINTER: {
            hw_pointer_enable(dev, FALSE);
        }
        break;
    case IOCTL_VIDEO_ENABLE_POINTER: {
            hw_pointer_enable(dev, TRUE);
        }
        break;
    case IOCTL_UXENDISP_GET_UPDATE_RECT: {
            GET_UPDATE_RECT_DATA *updateRect = packet->OutputBuffer;

            if (packet->OutputBufferLength < (packet->StatusBlock->Information =
                                              sizeof(*updateRect))) {
                error = ERROR_INSUFFICIENT_BUFFER;
                goto err;
            }

            updateRect->dev = dev->dr_ctx;
            updateRect->update = dr_update;
            updateRect->safe_to_draw = dr_safe_to_draw;
        }
        break;
    default:
        DBG_ERR("invalid function: %x", (packet->IoControlCode >> 2) & 0xFFF);
        error = ERROR_INVALID_FUNCTION;
        goto err;
    }
    packet->StatusBlock->Status = NO_ERROR;

    return TRUE;

err:
    DBG_ERR("error %d", error);
    packet->StatusBlock->Information = 0;
    packet->StatusBlock->Status = error;

    return TRUE;
}

BOOLEAN Interrupt(PVOID dev_ext)
{
    return FALSE;
}
