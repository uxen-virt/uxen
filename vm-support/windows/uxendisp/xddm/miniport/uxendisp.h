/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENDISP_H_
#define _UXENDISP_H_

#include "winerror.h"
#include "devioctl.h"
#include "miniport.h"
#include "ntddvdeo.h"
#include "video.h"
#include "dirty_rect.h"

#ifndef _M_AMD64
#include "ioaccess.h"
#endif  /* _M_AMD64 */

/* PCI vendor and device IDs. */
#define UXENDISP_PCI_VEN    0x5853
#define UXENDISP_PCI_DEV    0x5102

typedef struct _DEVICE_EXTENSION {
    PVP_DMA_ADAPTER dma;

    PVOID rom;
    ULONG rom_size;

    PHYSICAL_ADDRESS vram_physical;
    ULONG vram_size;
    UINT8 *vram_start;

    PHYSICAL_ADDRESS mmio_physical;
    ULONG mmio_size;
    UINT8 *mmio_start;

    PVIDEO_MODE_INFORMATION modes;
    ULONG n_modes;
    ULONG custom_mode;
    PVIDEO_MODE_INFORMATION current_mode;

    void *hwptr_desc_ptr;
    PHYSICAL_ADDRESS hwptr_desc_addr;
    void *hwptr_bitmap_ptr;
    PHYSICAL_ADDRESS hwptr_bitmap_addr;

    dr_ctx_t dr_ctx;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

static /* inline */ ULONG
FB_Len(PDEVICE_EXTENSION dev)
{
    PVIDEO_MODE_INFORMATION m = dev->current_mode;

    return m ? m->VideoMemoryBitmapHeight * m->ScreenStride : 0;
}

#define DBG_INFO(fmt, ...) \
    VideoPortDebugPrint(3, "%s:" fmt "\n", __FUNCTION__, __VA_ARGS__)
#define DBG_ERR(fmt, ...) \
    VideoPortDebugPrint(0, "%s:" fmt "\n", __FUNCTION__, __VA_ARGS__)

#endif /* _UXENDISP_H_ */
