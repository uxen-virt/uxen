/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PLATFORM_PUBLIC_H_
#define _PLATFORM_PUBLIC_H_

// {E2B610CF-AF8C-4B59-A6D0-1EF2BDE1006D}
DEFINE_GUID(GUID_DEVINTERFACE_UXENPLATFORM, 
    0xe2b610cf, 0xaf8c, 0x4b59, 0xa6, 0xd0, 0x1e, 0xf2, 0xbd, 0xe1, 0x0, 0x6d);

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


struct uxen_platform_set_time_update_event {
    HANDLE time_update_event;
};

#define IOCTL_UXEN_PLATFORM_SET_TIME_UPDATE_EVENT               \
    UXEN_IOW(1, struct uxen_platform_set_time_update_event)

struct uxen_platform_set_balloon_update_event {
    HANDLE balloon_update_event;
};

#define IOCTL_UXEN_PLATFORM_SET_BALLOON_UPDATE_EVENT               \
    UXEN_IOW(2, struct uxen_platform_set_balloon_update_event)

struct uxen_platform_map_shared_info {
    struct shared_info *shared_info;
};

#define IOCTL_UXEN_PLATFORM_MAP_SHARED_INFO             \
    UXEN_IOR(1, struct uxen_platform_map_shared_info)

struct uxen_platform_balloon_configuration {
    ULONG       maximum_number_of_retries;
    ULONG       retry_delay_in_ms;
    ULONG       target_size_mb;
};

struct uxen_platform_balloon_statistics {
    ULONG                                           current_size_mb;
    ULONG                                           min_size_mb;
    ULONG                                           max_size_mb;
};

#define IOCTL_UXEN_PLATFORM_BALLOON_GET_CONFIGURATION   \
    UXEN_IOR(2, struct uxen_platform_balloon_configuration)

#define IOCTL_UXEN_PLATFORM_BALLOON_GET_STATISTICS      \
    UXEN_IOR(3, struct uxen_platform_balloon_statistics)

#define IOCTL_UXEN_PLATFORM_BALLOON_SET_CONFIGURATION   \
    UXEN_IOW(3, struct uxen_platform_balloon_configuration)

#define IOCTL_UXEN_PLATFORM_GET_FTIME \
    UXEN_IOR(4, uint64_t)


/* Child PDOs IOCTLs */
#define UXENPLATFORM_BUS_IO(nr)                     \
    CTL_CODE(FILE_DEVICE_UNKNOWN,                   \
             (nr) | 0x8000,                         \
             METHOD_BUFFERED,                       \
             FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_UXEN_PLATFORM_BUS_GET_DEVICE_PROPERTY  UXENPLATFORM_BUS_IO(0)

#endif  /* _PLATFORM_PUBLIC_H_ */
