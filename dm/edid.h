/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _EDID_H_
#define _EDID_H_

#define STD_TIMINGS 8
#define DET_TIMINGS 4

/* header */
#define HEADER_PATTERN { 0x00, 0xFF, 0xFF, 0xFF, \
                         0xFF, 0xFF, 0xFF, 0x00 }
#define HEADER_SECTION 0
#define HEADER_LENGTH 8

/* vendor section */
#define VENDOR_SECTION (HEADER_SECTION + HEADER_LENGTH)
#define V_MANUFACTURER 0
#define V_PROD_ID (V_MANUFACTURER + 2)
#define V_SERIAL (V_PROD_ID + 2)
#define V_WEEK (V_SERIAL + 4)
#define V_YEAR (V_WEEK + 1)
#define VENDOR_LENGTH (V_YEAR + 1)

/* EDID version */
#define VERSION_SECTION (VENDOR_SECTION + VENDOR_LENGTH)
#define V_VERSION 0
#define V_REVISION (V_VERSION + 1)
#define VERSION_LENGTH (V_REVISION + 1)

/* display information */
#define DISPLAY_SECTION (VERSION_SECTION + VERSION_LENGTH)
#define D_INPUT 0
#define D_HSIZE (D_INPUT + 1)
#define D_VSIZE (D_HSIZE + 1)
#define D_GAMMA (D_VSIZE + 1)
#define FEAT_S (D_GAMMA + 1)
#define D_RG_LOW (FEAT_S + 1)
#define D_BW_LOW (D_RG_LOW + 1)
#define D_REDX (D_BW_LOW + 1)
#define D_REDY (D_REDX + 1)
#define D_GREENX (D_REDY + 1)
#define D_GREENY (D_GREENX + 1)
#define D_BLUEX (D_GREENY + 1)
#define D_BLUEY (D_BLUEX + 1)
#define D_WHITEX (D_BLUEY + 1)
#define D_WHITEY (D_WHITEX + 1)
#define DISPLAY_LENGTH (D_WHITEY + 1)

/* supported VESA and other standard timings */
#define ESTABLISHED_TIMING_SECTION (DISPLAY_SECTION + DISPLAY_LENGTH)
#define E_T1 0
#define E_T2 (E_T1 + 1)
#define E_TMANU (E_T2 + 1)
#define E_TIMING_LENGTH (E_TMANU + 1)
/* non predefined standard timings supported by display */
#define STD_TIMING_SECTION (ESTABLISHED_TIMING_SECTION + E_TIMING_LENGTH)
#define STD_TIMING_INFO_LEN 2
#define STD_TIMING_INFO_NUM STD_TIMINGS
#define STD_TIMING_LENGTH (STD_TIMING_INFO_LEN * STD_TIMING_INFO_NUM)
/* detailed timing info of non standard timings */
#define DET_TIMING_SECTION (STD_TIMING_SECTION + STD_TIMING_LENGTH)
#define DET_TIMING_INFO_LEN 18
#define MONITOR_DESC_LEN DET_TIMING_INFO_LEN
#define DET_TIMING_INFO_NUM DET_TIMINGS
#define DET_TIMING_LENGTH (DET_TIMING_INFO_LEN * DET_TIMING_INFO_NUM)

#define EDID_SIZE 256

#define EDID_VIDEO_INPUT_SIGNAL_ANALOG                  0x00
#define EDID_VIDEO_INPUT_LVL_0700_0300_1000V            0x00
#define EDID_VIDEO_INPUT_LVL_0714_0286_1000V            0x20
#define EDID_VIDEO_INPUT_LVL_1000_0400_1400V            0x40
#define EDID_VIDEO_INPUT_LVL_0700_0000_0700V            0x60
#define EDID_VIDEO_INPUT_SETUP_BLANK_EQ_BLACK           0x00
#define EDID_VIDEO_INPUT_SETUP_B2B_PEDESTRAL            0x10
#define EDID_VIDEO_INPUT_SYNC_SEPARATE                  0x08
#define EDID_VIDEO_INPUT_SYNC_COMPOSITE_ON_HORIZ        0x04
#define EDID_VIDEO_INPUT_SYNC_COMPOSITE_ON_GREEN        0x02
#define EDID_VIDEO_INPUT_SERRATION_ON_VSYNC             0x01

#define EDID_VIDEO_INPUT_SIGNAL_DIGITAL                 0x80
#define EDID_VIDEO_INPUT_COLOR_DEPTH_UNDEFINED          0x00
#define EDID_VIDEO_INPUT_COLOR_DEPTH_6BITS              0x10
#define EDID_VIDEO_INPUT_COLOR_DEPTH_8BITS              0x20
#define EDID_VIDEO_INPUT_COLOR_DEPTH_10BITS             0x30
#define EDID_VIDEO_INPUT_COLOR_DEPTH_12BITS             0x40
#define EDID_VIDEO_INPUT_COLOR_DEPTH_14BITS             0x50
#define EDID_VIDEO_INPUT_COLOR_DEPTH_16BITS             0x60
#define EDID_VIDEO_INPUT_INTERFACE_UNDEFINED            0x00
#define EDID_VIDEO_INPUT_INTERFACE_DVI                  0x01
#define EDID_VIDEO_INPUT_INTERFACE_HDMIA                0x02
#define EDID_VIDEO_INPUT_INTERFACE_HDMIB                0x03
#define EDID_VIDEO_INPUT_INTERFACE_MDDI                 0x04
#define EDID_VIDEO_INPUT_INTERFACE_DP                   0x05

#define EDID_DISPLAY_SIZE_UNDEFINED                     0
#define EDID_DISPLAY_SIZE(h,v) \
    ((((v) & 0xff) << 8) | ((h) & 0xff))
#define EDID_DISPLAY_LANDSCAPE_ASPECT_RATIO(ar) \
    ((int)(((ar) * 100f) - 99f) & 0xff)
#define EDID_DISPLAY_PORTRAIT_ASPECT_RATIO(ar) \
    (((int)((100f / (ar)) - 99f) & 0xff) << 8)

#define EDID_DISPLAY_SUPPORT_DPM_STANDBY                0x80
#define EDID_DISPLAY_SUPPORT_DPM_SUSPEND                0x40
#define EDID_DISPLAY_SUPPORT_DPM_VLP                    0x20
#define EDID_DISPLAY_SUPPORT_COLOR_GREYSCALE            0x00
#define EDID_DISPLAY_SUPPORT_COLOR_RGB                  0x08
#define EDID_DISPLAY_SUPPORT_COLOR_NONRGB               0x10
#define EDID_DISPLAY_SUPPORT_COLOR_UNDEF                0x18
#define EDID_DISPLAY_SUPPORT_COLOR_RGB444               0x00
#define EDID_DISPLAY_SUPPORT_COLOR_YCRCB444             0x08
#define EDID_DISPLAY_SUPPORT_COLOR_YCRCB422             0x10
#define EDID_DISPLAY_SUPPORT_SRGB_DEFAULT               0x04
#define EDID_DISPLAY_SUPPORT_PREFERRED_MODE             0x02
#define EDID_DISPLAY_SUPPORT_FREQ_CONTINUOUS            0x01

#define EDID_EST_TIMING_800x600_60HZ                 0x00001
#define EDID_EST_TIMING_800x600_56HZ                 0x00002
#define EDID_EST_TIMING_640x480_75HZ                 0x00004
#define EDID_EST_TIMING_640x480_72HZ                 0x00008
#define EDID_EST_TIMING_640x480_67HZ                 0x00010
#define EDID_EST_TIMING_640x480_60HZ                 0x00020
#define EDID_EST_TIMING_720x400_88HZ                 0x00040
#define EDID_EST_TIMING_720x400_70HZ                 0x00080
#define EDID_EST_TIMING_1280x1024_75HZ               0x00100
#define EDID_EST_TIMING_1024x768_75HZ                0x00200
#define EDID_EST_TIMING_1024x768_70HZ                0x00400
#define EDID_EST_TIMING_1024x768_60HZ                0x00800
#define EDID_EST_TIMING_1024x768_87HZ                0x01000
#define EDID_EST_TIMING_832x624_75HZ                 0x02000
#define EDID_EST_TIMING_800x600_75HZ                 0x04000
#define EDID_EST_TIMING_800x600_72HZ                 0x08000
#define EDID_EST_TIMING_1152x870_75HZ                0x10000

#define EDID_STD_TIMING_AR_16_10                        0
#define EDID_STD_TIMING_AR_4_3                          1
#define EDID_STD_TIMING_AR_5_4                          2
#define EDID_STD_TIMING_AR_16_9                         3

#define EDID_STD_TIMING_UNUSED                          0x0101
#define EDID_STD_TIMING(hres, aspect_ratio, hz) \
    ((aspect_ratio << 14) | (((hz - 60) & 0x3f) << 8) | ((((hres) / 8) - 31) & 0xff))

#define EDID_DET_TIMING_10KHZ                           (1)
#define EDID_DET_TIMING_SIGNAL_INTERLACED               0x80
#define EDID_DET_TIMING_STEREO_FIELD_SEQ_R              0x20
#define EDID_DET_TIMING_STEREO_FIELD_SEQ_L              0x40
#define EDID_DET_TIMING_STEREO_2WAY_INTRLVD_R           0x21
#define EDID_DET_TIMING_STEREO_2WAY_INTRLVD_L           0x41
#define EDID_DET_TIMING_STEREO_4WAY_INTRLVD             0x60
#define EDID_DET_TIMING_STEREO_SIDE_BY_SIDE_INTRLVD     0x61
#define EDID_DET_TIMING_SIGNAL_ANALOG                   0x00
#define EDID_DET_TIMING_BIPOLAR_COMPOSITE_SYNC          0x08
#define EDID_DET_TIMING_HSYNC_DURING_VSYNC              0x04
#define EDID_DET_TIMING_SYNC_ON_GREEN                   0x02
#define EDID_DET_TIMING_SYNC_ON_RGB                     0x02
#define EDID_DET_TIMING_SIGNAL_DIGITAL                  0x10
#define EDID_DET_TIMING_SYNC_SEPARATE                   0x08
#define EDID_DET_TIMING_VSYNC_NEGATIVE                  0x00
#define EDID_DET_TIMING_VSYNC_POSITIVE                  0x04
#define EDID_DET_TIMING_HSYNC_NEGATIVE                  0x00
#define EDID_DET_TIMING_HSYNC_POSITIVE                  0x02

#define EDID_DISPLAY_DESCR                              (0x0000)

#define EDID_DISPLAY_DESCR_TAG_SERIAL                   0xff
#define EDID_DISPLAY_DESCR_TAG_STRING                   0xfe
#define EDID_DISPLAY_DESCR_TAG_RANGE_LIMITS             0xfd
#define EDID_DISPLAY_DESCR_TAG_NAME                     0xfc
#define EDID_DISPLAY_DESCR_TAG_COLOR_POINT              0xfb
#define EDID_DISPLAY_DESCR_TAG_STD_TIMINGS              0xfa
#define EDID_DISPLAY_DESCR_TAG_DCM                      0xf9
#define EDID_DISPLAY_DESCR_TAG_CVT_TIMINGS              0xf8
#define EDID_DISPLAY_DESCR_TAG_EST_TIMINGS              0xf7
#define EDID_DISPLAY_DESCR_TAG_DUMMY                    0x10

unsigned char *edid_set_header(unsigned char *e);
unsigned char *edid_set_vendor(unsigned char *e,
                               const char *vendor,
                               unsigned short product_id,
                               unsigned int serial,
                               unsigned char week,
                               unsigned int year);
unsigned char *edid_set_version(unsigned char *e,
                                unsigned char version,
                                unsigned char revision);
unsigned char *edid_set_display_features(unsigned char *e,
                                         unsigned char input,
                                         unsigned short size_or_aspect_ratio,
                                         float gamma,
                                         unsigned char support);
unsigned char *edid_set_color_attr(unsigned char *e,
                    unsigned short redx, unsigned short redy,
                    unsigned short greenx, unsigned short greeny,
                    unsigned short bluex, unsigned short bluey,
                    unsigned short whitex, unsigned short whitey);
unsigned char *edid_set_established_timings(unsigned char *e,
                                            unsigned int timings);
unsigned char *edid_set_standard_timing(unsigned char *e, int id,
                                        unsigned short std_timing);
unsigned char *edid_set_detailed_timing(unsigned char *e, int id, int pixclock,
                                        int hactive,
                                        int hblank,
                                        int hsync_off,
                                        int hsync_width,
                                        int vactive,
                                        int vblank,
                                        int vsync_off,
                                        int vsync_width,
                                        int hsize,
                                        int vsize,
                                        int hborder,
                                        int vborder,
                                        unsigned char signal);
unsigned char *edid_set_display_descriptor(unsigned char *e, int id,
                                           unsigned char tag,
                                           void *data, size_t len);
unsigned char *edid_finalize(unsigned char *e, int block_count);
unsigned char *edid_init_common(unsigned char *e, int hres, int vres);

#endif /* _EDID_H_ */
