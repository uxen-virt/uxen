/*
 *  uxen_desc_sys.h
 *  uxen
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_DESC_SYS_H_
#define _UXEN_DESC_SYS_H_

#if defined(_WIN32)
#if !defined(__XEN__) && !defined(KERNEL)
#include <windows.h>
#endif  /* __XEN__ || KERNEL */

typedef HANDLE UXEN_HANDLE_T;
typedef HANDLE UXEN_EVENT_HANDLE_T;
typedef HANDLE UXEN_USER_EVENT_HANDLE_T;

#elif defined(__APPLE__)
#if !defined(__XEN__) && !defined(KERNEL)
#include <IOKit/IOKitLib.h>
typedef struct {
    io_connect_t connection;
    mach_port_t notify_port;
} *UXEN_HANDLE_T;
#endif  /* __XEN__ || KERNEL */
typedef void *UXEN_EVENT_HANDLE_T;
typedef void *UXEN_USER_EVENT_HANDLE_T;
#define INVALID_HANDLE_VALUE    NULL
#endif

#define UXEN_EVENT_REQUEST	0
#define UXEN_EVENT_COMPLETED	1
#define UXEN_EVENT_EXCEPTION	2
#define UXEN_EVENT_VRAM		3

struct uxen_event_desc {
    union {
        UXEN_EVENT_HANDLE_T ued_event;
        uint64_t fill0;
    };
    uint32_t ued_id;
};

struct uxen_event_channel_desc {
    union {
        UXEN_EVENT_HANDLE_T uecd_request_event;
	uint64_t fill0;
    };
    union {
        UXEN_USER_EVENT_HANDLE_T uecd_completed_event;
	uint64_t fill1;
    };
    uint32_t uecd_vcpu;
    uint32_t uecd_port;
};

#ifdef __APPLE__
struct uxen_xnu_sym {
    uint64_t addr;
    uint64_t name;
};

struct uxen_syms_desc {
    uint8_t *usd_xnu_syms;
    uint32_t usd_size;
    uint32_t usd_symnum;
};

struct uxen_event_poll_desc {
    uint32_t signaled;
};
#endif

struct uxen_logging_buffer {
    volatile uint64_t ulb_consumer;
    volatile uint64_t ulb_producer;
    volatile uint32_t ulb_size;
#if !(defined(_MSC_VER) && defined(__cplusplus))
    char ulb_buffer[];
#endif
};

struct uxen_logging_desc {
    union {
        UXEN_EVENT_HANDLE_T uld_event;
        uint64_t fill0;
    };
    union {
        /* out: logging buffer address */
        struct uxen_logging_buffer *uld_buffer;
        uint64_t fill1;
    };
    uint32_t uld_size;
};

struct uxen_malloc_desc {
    uint64_t umd_addr;
    uint32_t umd_npages;
};

struct uxen_free_desc {
    uint64_t ufd_addr;
    uint32_t ufd_npages;
};

struct uxen_map_host_pages_desc {
    UXEN_PTR(void, umhpd_va);
    uint64_t umhpd_len;
    UXEN_PTR(uint64_t, umhpd_gpfns);
};

#endif  /* _UXEN_DESC_SYS_H_ */
