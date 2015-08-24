/*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/
/*
 * uXen changes:
 *
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
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

#include "config.h"

#include <string.h>
#include <stdlib.h>

#include "edid.h"

struct edid_vendor_info
{
    unsigned short vendor_id;
    unsigned short product_id;
    unsigned int serial;
    unsigned char week;
    unsigned char year;
} __attribute__ ((packed));

static int checksum(void *buf, size_t len)
{
    unsigned char sum = 0;
    size_t i = 0;
    unsigned char *b = buf;

    for (;i < len; i++)
        sum += b[i];

    return sum;
}

unsigned char *
edid_set_header(unsigned char *e)
{
    unsigned char hdr[] = HEADER_PATTERN;

    memcpy(e, hdr, 8);
    return e;
}

unsigned char *
edid_set_vendor(unsigned char *e,
                const char *vendor,
                unsigned short product_id,
                unsigned int serial,
                unsigned char week,
                unsigned int year)
{
    struct edid_vendor_info *info = (void *)(e + VENDOR_SECTION);
    int i = 0;

    info->vendor_id = 0;
    for (; i < 3; i++) {
        unsigned char c;

        if (vendor[i] < '@' || vendor[i] > 'Z')
            return NULL;

        c = vendor[i] - '@';
        info->vendor_id |= ((c & 0x1f) << ((2 - i) * 5));
    }

    info->product_id = product_id;
    info->serial = serial;
    info->week = week;
    info->year = year - 1990;

    return e;
}

unsigned char *
edid_set_version(unsigned char *e,
                 unsigned char version,
                 unsigned char revision)
{
    unsigned char *v = e + VERSION_SECTION;

    v[0] = version;
    v[1] = revision;

    return e;
}

unsigned char *
edid_set_display_features(unsigned char *e,
                          unsigned char input,
                          unsigned short size_or_aspect_ratio,
                          float gamma,
                          unsigned char support)
{
    unsigned char *f = e + DISPLAY_SECTION;

    f[0] = input;
    f[1] = size_or_aspect_ratio & 0xff;
    f[2] = size_or_aspect_ratio >> 8;
    f[3] = (int)((gamma * 100) - 100) & 0xff;
    f[4] = support;

    return e;
}

unsigned char *
edid_set_color_attr(unsigned char *e,
                    unsigned short redx, unsigned short redy,
                    unsigned short greenx, unsigned short greeny,
                    unsigned short bluex, unsigned short bluey,
                    unsigned short whitex, unsigned short whitey)
{
    unsigned char *c = e + 0x19;

    if (redx > 0x3ff || redy > 0x3ff ||
        greenx > 0x3ff || greeny > 0x3ff ||
        bluex > 0x3ff || bluey > 0x3ff ||
        whitex > 0x3ff || whitey > 0x3ff)
        return NULL;

    c[0] = ((redx & 0x3) << 6) | ((redy & 0x3) << 4) |
           ((greenx & 0x3) << 2) | (greeny & 0x3);
    c[1] = ((bluex & 0x3) << 6) | ((bluey & 0x3) << 4) |
           ((whitex & 0x3) << 2) | (whitey & 0x3);
    c[2] = redx >> 2;
    c[3] = redy >> 2;
    c[4] = greenx >> 2;
    c[5] = greeny >> 2;
    c[6] = bluex >> 2;
    c[7] = bluey >> 2;
    c[8] = whitex >> 2;
    c[9] = whitey >> 2;

    return e;
}

unsigned char *
edid_set_established_timings(unsigned char *e, unsigned int timings)
{
    unsigned char *t = e + ESTABLISHED_TIMING_SECTION;

    t[0] = timings & 0xff;
    t[1] = (timings >> 8) & 0xff;
    t[2] = (timings >> 16) & 0xff;

    return e;
}

unsigned char *
edid_set_standard_timing(unsigned char *e, int id, unsigned short std_timing)
{
    unsigned short *t = (unsigned short *)(e + STD_TIMING_SECTION);

    if (id < 0 || id >= 8)
        return NULL;

    t[id] = std_timing;

    return e;
}

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
} __attribute__ ((packed));

unsigned char *
edid_set_detailed_timing(unsigned char *e, int id, int pixclock,
                         int hactive, int hblank, int hsync_off,
                         int hsync_width,
                         int vactive, int vblank, int vsync_off,
                         int vsync_width,
                         int hsize, int vsize, int hborder, int vborder,
                         unsigned char signal)
{
    struct edid_detailed_timing *t = (void *)(e + DET_TIMING_SECTION +
                                              id * DET_TIMING_INFO_LEN);

    t->pixclock = pixclock;
    t->hactive_lo = hactive & 0xff;
    t->hactive_hi = (hactive >> 8) & 0xf;
    t->hblank_lo = hblank & 0xff;
    t->hblank_hi = (hblank >> 8) & 0xf;
    t->hsync_off_lo = hsync_off & 0xff;
    t->hsync_off_hi = (hsync_off >> 8) & 0x3;
    t->hsync_width_lo = hsync_width & 0xff;
    t->hsync_width_hi = (hsync_width >> 8) & 0x3;
    t->hsize_lo = hsize & 0xff;
    t->hsize_hi = (hsize >> 8) & 0xf;
    t->hborder = hborder;
    t->vactive_lo = vactive & 0xff;
    t->vactive_hi = (vactive >> 8) & 0xf;
    t->vblank_lo = vblank & 0xff;
    t->vblank_hi = (vblank >> 8) & 0xf;
    t->vsync_width_lo = vsync_width & 0xf;
    t->vsync_width_hi = (vsync_width >> 4) & 0x3;
    t->vsync_off_lo = vsync_off & 0xf;
    t->vsync_off_hi = (vsync_off >> 4) & 0x3;
    t->vsize_lo = vsize & 0xff;
    t->vsize_hi = (vsize >> 8) & 0xf;
    t->vborder = vborder;
    t->signal = signal;

    return e;
}

struct edid_display_descriptor
{
    unsigned short signature;
    unsigned char reserved1;
    unsigned char tag;
    unsigned char reserved2;
    unsigned char data[13];
} __attribute__ ((packed));

unsigned char *
edid_set_display_descriptor(unsigned char *e, int id,
                            unsigned char tag,
                            void *data, size_t len)
{
    struct edid_display_descriptor *d = (void *)(e + DET_TIMING_SECTION +
                                                 id * DET_TIMING_INFO_LEN);

    d->signature = EDID_DISPLAY_DESCR;
    d->reserved1 = 0x00;
    d->tag = tag;
    d->reserved2 = 0x00;
    memcpy(d->data, data, len);
    memset(d->data + len, 0, sizeof (d->data) - len);

    return e;
}

unsigned char *
edid_finalize(unsigned char *e, int block_count)
{
    unsigned char sum;

    e[126] = block_count;
    e[127] = 0;
    sum = checksum(e, 128);
    e[127] = -sum;

    return e;
}

static uint32_t hash_update(uint32_t h, void *data, size_t len)
{
    uint8_t *p = data;
    size_t i;

    for (i = 0; i < len; i++)
        h ^= (h << 5) + p[i] + (h >> 2);

    return h;
}

static uint32_t hash(void *data, size_t len)
{
    return hash_update(0x4e67c6a7, data, len);
}

unsigned char *
edid_init_common(unsigned char *e, int hres, int vres)
{
    int serial;
    int pixclock;
    char serial_string[14];

    memset(e, 0, 128);
    edid_set_header(e);
    edid_set_version(e, 1, 4);
    edid_set_display_features(e, EDID_VIDEO_INPUT_SIGNAL_DIGITAL |
                              EDID_VIDEO_INPUT_COLOR_DEPTH_8BITS |
                              EDID_VIDEO_INPUT_INTERFACE_DVI,
                              EDID_DISPLAY_SIZE(33, 25),
                              2.2f,
                              EDID_DISPLAY_SUPPORT_DPM_STANDBY |
                              EDID_DISPLAY_SUPPORT_DPM_SUSPEND |
                              EDID_DISPLAY_SUPPORT_SRGB_DEFAULT |
                              EDID_DISPLAY_SUPPORT_COLOR_RGB444 |
                              EDID_DISPLAY_SUPPORT_PREFERRED_MODE |
                              EDID_DISPLAY_SUPPORT_FREQ_CONTINUOUS);
    edid_set_color_attr(e, 665, 343, 290, 620, 155, 75, 321, 337);

    edid_set_established_timings(e, EDID_EST_TIMING_640x480_75HZ |
                                 EDID_EST_TIMING_720x400_88HZ |
                                 EDID_EST_TIMING_800x600_75HZ |
                                 EDID_EST_TIMING_1024x768_75HZ |
                                 EDID_EST_TIMING_1280x1024_75HZ);
    edid_set_standard_timing(e, 0,
                             EDID_STD_TIMING(640, EDID_STD_TIMING_AR_4_3, 85));
    edid_set_standard_timing(e, 1,
                             EDID_STD_TIMING(800, EDID_STD_TIMING_AR_4_3, 85));
    edid_set_standard_timing(e, 2,
                             EDID_STD_TIMING(1024, EDID_STD_TIMING_AR_4_3, 85));
    edid_set_standard_timing(e, 3,
                             EDID_STD_TIMING(640, EDID_STD_TIMING_AR_4_3, 70));
    edid_set_standard_timing(e, 4,
                             EDID_STD_TIMING(1280, EDID_STD_TIMING_AR_4_3, 70));
    edid_set_standard_timing(e, 5,
                             EDID_STD_TIMING(1600, EDID_STD_TIMING_AR_4_3, 60));
    edid_set_standard_timing(e, 6, EDID_STD_TIMING_UNUSED);
    edid_set_standard_timing(e, 7, EDID_STD_TIMING_UNUSED);

#define HBLANK_COMMON 184
#define HSYNC_OFF_COMMON 48
#define HSYNC_WIDTH_COMMON 112
#define HSIZE_COMMON 300
#define VBLANK_COMMON 7
#define VSYNC_OFF_COMMON 1
#define VSYNC_WIDTH_COMMON 3
#define VSIZE_COMMON 225
#define REFRESH_DEFAULT 75

    /* Compute clock for 75Hz display refresh */
    pixclock = (hres + HBLANK_COMMON) * (vres + VBLANK_COMMON);
    pixclock *= REFRESH_DEFAULT;
    pixclock /= 10000;
    edid_set_detailed_timing(e, 0, pixclock,
                             hres, HBLANK_COMMON, HSYNC_OFF_COMMON,
                             HSYNC_WIDTH_COMMON,
                             vres, VBLANK_COMMON, VSYNC_OFF_COMMON,
                             VSYNC_WIDTH_COMMON,
                             HSIZE_COMMON, VSIZE_COMMON, 0, 0,
                             EDID_DET_TIMING_SIGNAL_DIGITAL);

    edid_set_display_descriptor(e, 1, EDID_DISPLAY_DESCR_TAG_DUMMY,
                                NULL, 0);
    edid_set_display_descriptor(e, 3, EDID_DISPLAY_DESCR_TAG_NAME,
                                "uXen display\n", 13);

    serial = hash(e, 128);
    snprintf(serial_string, sizeof(serial_string), "A%010d\n ", serial);

    edid_set_vendor(e, "UXE", 0xF00D, serial, 39, 2014);
    edid_set_display_descriptor(e, 2, EDID_DISPLAY_DESCR_TAG_SERIAL,
                                serial_string, 13);


    return edid_finalize(e, 0);
}
