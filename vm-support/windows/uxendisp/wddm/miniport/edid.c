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

#pragma pack(push, 1)
struct edid_detailed_timing
{
    unsigned short pixclock;
    unsigned char hactive_lo;
    unsigned char hblank_lo;
    unsigned char hblank_hi:4;
    unsigned char hactive_hi:4;
    unsigned char vactive_lo;
    unsigned char vblank_lo;
    unsigned char vblank_hi:4;
    unsigned char vactive_hi:4;
    unsigned char hsync_off_lo;
    unsigned char hsync_width_lo;
    unsigned char vsync_width_lo:4;
    unsigned char vsync_off_lo:4;
    unsigned char vsync_width_hi:2;
    unsigned char vsync_off_hi:2;
    unsigned char hsync_width_hi:2;
    unsigned char hsync_off_hi:2;
    unsigned char hsize_lo;
    unsigned char vsize_lo;
    unsigned char vsize_hi:4;
    unsigned char hsize_hi:4;
    unsigned char hborder;
    unsigned char vborder;
    unsigned char signal;
};
#pragma pack(pop)

static LONG
edid_mode_add(ULONG width, ULONG height, ULONG stride, ULONG fmt, ULONG flags,
              UXENDISP_MODE *modes, ULONG max_modes)
{
    ULONG i;

    for (i = 0; i < max_modes; i++) {
        if (modes[i].xres == width &&
            modes[i].yres == height &&
            modes[i].stride == stride &&
            modes[i].fmt == fmt) {
            modes[i].flags |= flags;
            return i;
        }
    }
    for (i = 0; i < max_modes; i++) {
        if (modes[i].xres == 0 || modes[i].yres == 0) {
            modes[i].xres = width;
            modes[i].yres = height;
            modes[i].stride = stride;
            modes[i].fmt = fmt;
            modes[i].flags = flags;
            return i;
        }
    }

    return -1;
}

static LONG
edid_mode_add_all(ULONG width, ULONG height, ULONG flags,
                  UXENDISP_MODE *modes, ULONG max_modes)
{
    LONG index;
    LONG max = -1;

    index = edid_mode_add(width, height, 4 * width,
                          UXDISP_CRTC_FORMAT_BGRX_8888, flags,
                          modes, max_modes);
    if (index > max)
        max = index;

    return max;
}

LONG
edid_get_modes(UCHAR *edid, SIZE_T edid_len,
               UXENDISP_MODE *modes, ULONG max_modes)
{
    UCHAR sum = 0;
    ULONG i;
    int w, h, r;
    UCHAR t, ar;
    struct edid_detailed_timing *det;
    LONG index, max = -1;

#define mode_add_all(w, h, r)                                   \
    do {                                                        \
        (void)r;                                                \
        index = edid_mode_add_all(w, h, 0, modes, max_modes);   \
        if (index > max)                                        \
            max = index;                                        \
    } while (1 == 0)

    RtlZeroMemory(modes, max_modes * sizeof(UXENDISP_MODE));

    if (edid_len < 128)
        return -1;

    if (RtlCompareMemory(edid, "\x00\xff\xff\xff\xff\xff\xff\x00", 8) != 8) {
        uxen_err("invalid EDID header");
        return -1;
    }

    for (i = 0; i < 128; i++)
        sum += edid[i];

    if (sum) {
        uxen_err("invalid EDID checksum");
        return -1;
    }

    /* Established timings I */
    t = edid[0x23];
    if (t & 0x01)
        mode_add_all(800, 600, 60);
    if (t & 0x02)
        mode_add_all(800, 600, 56);
    if (t & 0x04)
        mode_add_all(640, 480, 75);
    if (t & 0x08)
        mode_add_all(640, 480, 72);
    if (t & 0x10)
        mode_add_all(640, 480, 67);
    if (t & 0x20)
        mode_add_all(640, 480, 60);
    if (t & 0x40)
        mode_add_all(720, 400, 88);
    if (t & 0x80)
        mode_add_all(720, 400, 70);

    /* Established timings II */
    t = edid[0x24];
    if (t & 0x01)
        mode_add_all(1280, 1024, 75);
    if (t & 0x02)
        mode_add_all(1024, 768, 75);
    if (t & 0x04)
        mode_add_all(1024, 768, 70);
    if (t & 0x08)
        mode_add_all(1024, 768, 60);
    if (t & 0x10)
        mode_add_all(1024, 768, 87);
    if (t & 0x20)
        mode_add_all(832, 624, 75);
    if (t & 0x40)
        mode_add_all(800, 600, 75);
    if (t & 0x80)
        mode_add_all(800, 600, 72);
    /* Manufacturer's timings */
    t = edid[0x25];
    if (t & 0x80)
        mode_add_all(1152, 870, 75);

    /* Standard timings */
    for (i = 0; i < 8; i++) {
        t = edid[0x26 + i * 2];
        ar = edid[0x27 + i * 2];

        if (t == 0x00 || (t == 0x01 && ar == 0x01))
            continue;

        w = (t + 31) * 8;
        switch (ar >> 6) {
        case 0x0:
            h = (w * 10) / 16;
            break;
        case 0x1:
            h = (w * 3) / 4;
            break;
        case 0x2:
            h = (w * 4) / 5;
            break;
        case 0x3:
            h = (w * 9) / 16;
            break;
        }
        r = (ar & 0x3f) + 60;

        mode_add_all(w, h, r);
    }

    /* Detailed timings */
    det = (struct edid_detailed_timing *)(edid + 0x36);
    for (i = 0; i < 4; i++) {
        int hblank, vblank;

        if (det[i].pixclock == 0x0000)
            continue;

        w = det[i].hactive_lo | (det[i].hactive_hi << 8);
        h = det[i].vactive_lo | (det[i].vactive_hi << 8);
        hblank = det[i].hblank_lo | (det[i].hblank_hi << 8);
        vblank = det[i].vblank_lo | (det[i].vblank_hi << 8);
        r = (det[i].pixclock * 10000UL) / ((w + hblank) * (h + vblank));

        index = edid_mode_add(w, h, 4 * w, UXDISP_CRTC_FORMAT_BGRX_8888,
                              UXENDISP_MODE_FLAG_PREFERRED,
                              modes, max_modes);
        if (index > max)
            max = index;
    }

    return max + 1;
}
