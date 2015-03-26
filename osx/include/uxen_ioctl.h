/*
 *  uxen_ioctl.h
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_IOCTL_H_
#define _UXEN_IOCTL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <uxen/uxen_desc.h>
#include <uxen_desc_sys.h>

#define UXEN_IOR_FLAG       0x80000000
#define UXEN_IOW_FLAG       0x40000000
#define UXEN_IO_SIZE(sz)    (((sz) & 0x3fffff) << 8)

#define UXEN_IO(nr)         (nr & 0xff)
#define UXEN_IOR(nr, type)  \
    (UXEN_IO(nr) | UXEN_IO_SIZE(sizeof(type)) | UXEN_IOR_FLAG)
#define UXEN_IOW(nr, type)  \
    (UXEN_IO(nr) | UXEN_IO_SIZE(sizeof(type)) | UXEN_IOW_FLAG)
#define UXEN_IOWR(nr, type) \
    (UXEN_IO(nr) | UXEN_IO_SIZE(sizeof(type)) | UXEN_IOR_FLAG | UXEN_IOW_FLAG)

#include <uxen_ioctl_def.h>

#ifdef __cplusplus
}
#endif

#endif /* _UXEN_IOCTL_H_ */
