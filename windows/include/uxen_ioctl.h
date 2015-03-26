/*
 *  uxen_ioctl.h
 *  uxen
 *
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
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

#define UXEN_IOCTL_SIZE_SHIFT 32

#define UXEN_FLAG_INBUFFER 0x800
#define UXEN_FLAG_OUTBUFFER 0x400

#define UXEN_IO(nr)							\
    CTL_CODE(FILE_DEVICE_UNKNOWN, nr, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define UXEN_IOR(nr, type)					\
    (UXEN_IO(nr | UXEN_FLAG_OUTBUFFER) |                        \
     ((uint64_t)sizeof(type) << UXEN_IOCTL_SIZE_SHIFT))
#define UXEN_IOW(nr, type)                                      \
    (UXEN_IO(nr | UXEN_FLAG_INBUFFER) |                         \
     ((uint64_t)sizeof(type) << UXEN_IOCTL_SIZE_SHIFT))
#define UXEN_IOWR(nr, type)                                     \
    (UXEN_IO(nr | UXEN_FLAG_OUTBUFFER | UXEN_FLAG_INBUFFER) |   \
     ((uint64_t)sizeof(type) << UXEN_IOCTL_SIZE_SHIFT))

#define FUNCTION_FROM_CTL_CODE(ctl)             \
    ((ctl) >> 2 & 0xfff)

#include <uxen_ioctl_def.h>

#define UXEN_NTSTATUS_FACILITY 0x08E50000L
#define UXEN_NTSTATUS_FACILITY_MASK 0x0FFF0000L
#define UXEN_NTSTATUS_ERRNO_MASK 0xFFFFL
#define UXEN_NTSTATUS_FROM_ERRNO(errno)		       \
    ((NTSTATUS)(0xE0000000L | UXEN_NTSTATUS_FACILITY | \
		(errno & UXEN_NTSTATUS_ERRNO_MASK)))
#define UXEN_ERRNO_FROM_NTSTATUS(ntstatus)	\
    ((int)(ntstatus & UXEN_NTSTATUS_ERRNO_MASK))
#define UXEN_IS_ERRNO_NTSTATUS(ntstatus)				\
    ((ntstatus & UXEN_NTSTATUS_FACILITY_MASK) == UXEN_NTSTATUS_FACILITY)

#ifdef __cplusplus
}
#endif

#endif /* _UXEN_IOCTL_H_ */
