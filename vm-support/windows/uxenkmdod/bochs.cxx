/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "BDD.hxx"
#include "bochs.h"

static
USHORT dispi_read(USHORT reg)
{
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_INDEX, reg);
    return READ_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_DATA);
}

static 
void dispi_write(USHORT reg, USHORT val)
{
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_INDEX, reg);
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_DATA, val);
}

VP_STATUS bochs_init()
{
    dispi_write(VBE_DISPI_INDEX_ID, VBE_DISPI_ID0);
    if (dispi_read(VBE_DISPI_INDEX_ID) != VBE_DISPI_ID0) {
        return ERROR_DEV_NOT_EXIST;
    }

    dispi_write(VBE_DISPI_INDEX_ID, VBE_DISPI_ID5);

    return NO_ERROR;
}

NTSTATUS bochs_set_mode(VIDEO_MODE_INFORMATION *mode)
{
    USHORT width = (USHORT)mode->VisScreenWidth;
    USHORT height = (USHORT)mode->VisScreenHeight;
    USHORT bpp = (USHORT)mode->BitsPerPlane;

    perfcnt_inc(bochs_set_mode);
#ifdef DBG
    uxen_debug("called: %dx%dx%d", width, height, bpp);
#else
    if (perfcnt_get(bochs_set_mode) < 64)
        uxen_msg("called: %dx%dx%d", width, height, bpp);
#endif  /* DBG */

    /* Program DISPI */
    dispi_write(VBE_DISPI_INDEX_XRES, width);
    dispi_write(VBE_DISPI_INDEX_YRES, height);
    dispi_write(VBE_DISPI_INDEX_BPP, bpp);
    dispi_write(VBE_DISPI_INDEX_BANK, 0);

    /* Flush */
    dispi_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED |
                VBE_DISPI_8BIT_DAC | VBE_DISPI_NOCLEARMEM);

    return STATUS_SUCCESS;
}

VP_STATUS bochs_disable()
{
    dispi_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);

    return NO_ERROR;
}
