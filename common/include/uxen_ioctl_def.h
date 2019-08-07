/*
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_IOCTL_DEF_H_
#define _UXEN_IOCTL_DEF_H_

struct uxen_version_desc_v1 {
    uint32_t uvd_driver_version_major;
    uint32_t uvd_driver_version_minor;
    char uvd_driver_version_tag[32];
};

struct uxen_version_desc {
    struct uxen_version_desc_v1;

    char uvd_driver_changeset[64];
};

struct uxen_load_desc {
    XEN_GUEST_HANDLE_64(uint8) uld_uvaddr;
    uint32_t uld_size;
};

struct uxen_status_desc {
    uint64_t usd_whp_mode;
};

#define	UXENVERSION		UXEN_IOR(1, struct uxen_version_desc)
#define	UXENLOAD		UXEN_IOW(2, struct uxen_load_desc)
#define	UXENUNLOAD		UXEN_IO(3)
#define	UXENINIT		UXEN_IOW(4, struct uxen_init_desc)
#define	UXENSHUTDOWN		UXEN_IO(5)
#ifdef _WIN32
#define	UXENPROCESSEXITHELPER	UXEN_IO(6)
#endif

#define	UXEN_MAX_KEYHANDLER_KEYS 16
#define	UXENKEYHANDLER		UXEN_IOW(7, char[UXEN_MAX_KEYHANDLER_KEYS])

#define	UXENHYPERCALL		UXEN_IOWR(10, struct uxen_hypercall_desc)
#define	UXENCREATEVM		UXEN_IOWR(11, struct uxen_createvm_desc)
#define	UXENMALLOC		UXEN_IOWR(12, struct uxen_malloc_desc)
#define	UXENFREE		UXEN_IOW(13, struct uxen_free_desc)
#define	UXENMMAPBATCH		UXEN_IOWR(14, struct uxen_mmapbatch_desc)
#define	UXENMUNMAP		UXEN_IOW(15, struct uxen_munmap_desc)
#define	UXENEXECUTE		UXEN_IOW(17, struct uxen_execute_desc)
#define	UXENSETEVENT		UXEN_IOW(18, struct uxen_event_desc)
#define	UXENTARGETVM		UXEN_IOWR(19, struct uxen_targetvm_desc)
#define	UXENDESTROYVM		UXEN_IOW(20, struct uxen_destroyvm_desc)
#define	UXENSETEVENTCHANNEL	UXEN_IOW(23, struct uxen_event_channel_desc)
#define	UXENQUERYVM		UXEN_IOWR(24, struct uxen_queryvm_desc)
#define	UXENPOWER		UXEN_IOW(25, uint32_t)
#define	UXENWAITVMEXIT		UXEN_IO(26)
#ifdef __APPLE__
#define	UXENLOADSYMS		UXEN_IOW(27, struct uxen_syms_desc)
#define	UXENSIGNALEVENT		UXEN_IOW(28, void *)
#endif
#define	UXENLOGGING		UXEN_IOWR(29, struct uxen_logging_desc)
#define	UXENMAPHOSTPAGES	UXEN_IOW(30, struct uxen_map_host_pages_desc)
#define	UXENUNMAPHOSTPAGES	UXEN_IOW(31, struct uxen_map_host_pages_desc)
#if defined(_WIN32) && defined(__i386__)
#define UXENWAITFORS4           UXEN_IO(32)
#define UXENWAITFORRESUMEFROMS4 UXEN_IO(33)
#endif /* _WIN32 && __i386__ */
#ifdef __APPLE__
#define UXENPOLLEVENT           UXEN_IOR(34, struct uxen_event_poll_desc)
#endif
#define UXENSTATUS              UXEN_IOR(35, struct uxen_status_desc)

#endif  /* _UXEN_IOCTL_DEF_H_ */
