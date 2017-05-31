/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __UXENH264_COMMON_H__
#define __UXENH264_COMMON_H__

#ifndef PRIuuid
#define PRIuuid "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#endif

#ifndef PRIuuid_arg
#define PRIuuid_arg(uuid)                                             \
    uuid[ 0], uuid[ 1], uuid[ 2], uuid[ 3], uuid[ 4], uuid[ 5], \
    uuid[ 6], uuid[ 7], uuid[ 8], uuid[ 9], uuid[10], uuid[11], \
    uuid[12], uuid[13], uuid[14], uuid[15]
#endif

#define UXENH264_RETRY_COUNT 5

#define UXENH264_DM_MAX_DEC 2
#define UXENH264_DM_TIMEOUT_MS 500

#define UXENH264_SIZE_LIMIT (32 * 1024 * 1024)

#define UXENH264_FS_OUTPUT_WIDTH 1920u
#define UXENH264_FS_OUTPUT_HEIGHT 1080u
#define UXENH264_OUTPUT_WIDTH 854u
#define UXENH264_OUTPUT_HEIGHT 480u
#define UXENH264_OUTPUT_TYPE MFVideoFormat_RGB32
#define UXENH264_OUTPUT_BYTES_PER_PIXEL 4

#define UXENH264_FLAG_FULLSCREEN   0x01
#define UXENH264_FLAG_SHOW_UI      0x02
#define UXENH264_FLAG_DROP_QUALITY 0x04

struct uxenh264_dm_ctx {
    void *debug_pfn;
    HANDLE thread;
    HANDLE exit;
    unsigned char v4v_idtoken[16];
};

#endif //__UXENH264_COMMON_H__
