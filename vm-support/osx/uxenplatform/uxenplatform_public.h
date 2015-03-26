/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENPLATFORM_PUBLIC_H_
#define _UXENPLATFORM_PUBLIC_H_

#ifdef __cplusplus
extern "C" {
#endif

struct uXenPlatformInfo
{
    unsigned short uxen_version_major;
    unsigned short uxen_version_minor;
    unsigned char uxen_version_extra[16];
};

struct uXenPlatformBalloonStats
{
    size_t balloon_mb;
};

struct uXenPlatformBalloonTarget
{
    size_t target_mb;
    size_t balloon_old_size_mb;
    size_t balloon_new_size_mb;
};

enum {
    kIOuXenPlatformMethodGetInfo,
    kIOuXenPlatformMethodGetBalloonStats,
    kIOuXenPlatformMethodSetBalloonTarget,

    kIOuXenPlatformMethodCount,
};

#ifdef __cplusplus
}
#endif

#endif
