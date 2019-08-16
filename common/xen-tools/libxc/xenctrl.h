/******************************************************************************
 * xenctrl.h
 *
 * A library for low-level access to the Xen control interfaces.
 *
 * Copyright (c) 2003-2004, K A Fraser.
 *
 * xc_gnttab functions:
 * Copyright (c) 2007-2008, D G Murray <Derek.Murray@cl.cam.ac.uk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
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

#ifndef XENCTRL_H
#define XENCTRL_H

/* Tell the Xen public headers we are a user-space tools build. */
#ifndef __XEN_TOOLS__
#define __XEN_TOOLS__ 1
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <xen/xen.h>
#include <xen/domctl.h>
#include <xen/physdev.h>
#include <xen/sysctl.h>
#include <xen/version.h>
#include <xen/event_channel.h>
#include <xen/sched.h>
#include <xen/memory.h>
#include <xen/grant_table.h>
#include <xen/hvm/params.h>

#include "xentoollog.h"

#if defined(__i386__) || defined(__x86_64__)
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#endif

#ifdef __ia64__
#define XC_PAGE_SHIFT           14
#else
#define XC_PAGE_SHIFT           12
#endif
#define XC_PAGE_SIZE            (1UL << XC_PAGE_SHIFT)
#define XC_PAGE_MASK            (~(XC_PAGE_SIZE-1))

#define INVALID_MFN  (~0UL)

/*
 *  DEFINITIONS FOR CPU BARRIERS
 */

#if defined(__i386__)
#define xen_mb()  asm volatile ( "lock; addl $0,0(%%esp)" : : : "memory" )
#define xen_rmb() asm volatile ( "lock; addl $0,0(%%esp)" : : : "memory" )
#define xen_wmb() asm volatile ( "" : : : "memory")
#elif defined(__x86_64__)
#define xen_mb()  asm volatile ( "mfence" : : : "memory")
#define xen_rmb() asm volatile ( "lfence" : : : "memory")
#define xen_wmb() asm volatile ( "" : : : "memory")
#elif defined(__ia64__)
#define xen_mb()   asm volatile ("mf" ::: "memory")
#define xen_rmb()  asm volatile ("mf" ::: "memory")
#define xen_wmb()  asm volatile ("mf" ::: "memory")
#else
#error "Define barriers"
#endif


#define XENCTRL_HAS_XC_INTERFACE 1
/* In Xen 4.0 and earlier, xc_interface_open and xc_evtchn_open would
 * both return ints being the file descriptor.  In 4.1 and later, they
 * return an xc_interface* and xc_evtchn*, respectively - ie, a
 * pointer to an opaque struct.  This #define is provided in 4.1 and
 * later, allowing out-of-tree callers to more easily distinguish
 * between, and be compatible with, both versions.
 */


/*
 *  GENERAL
 *
 * Unless otherwise specified, each function here returns zero or a
 * non-null pointer on success; or in case of failure, sets errno and
 * returns -1 or a null pointer.
 *
 * Unless otherwise specified, errors result in a call to the error
 * handler function, which by default prints a message to the
 * FILE* passed as the caller_data, which by default is stderr.
 * (This is described below as "logging errors".)
 *
 * The error handler can safely trash errno, as libxc saves it across
 * the callback.
 */

typedef struct xc_interface_core xc_interface;
typedef struct xc_interface_core xc_evtchn;
typedef struct xc_interface_core xc_gnttab;
typedef struct xc_interface_core xc_gntshr;
typedef enum xc_error_code xc_error_code;


/*
 *  INITIALIZATION FUNCTIONS
 */

/**
 * This function opens a handle to the hypervisor interface.  This function can
 * be called multiple times within a single process.  Multiple processes can
 * have an open hypervisor interface at the same time.
 *
 * Each call to this function should have a corresponding call to
 * xc_interface_close().
 *
 * This function can fail if the caller does not have superuser permission or
 * if a Xen-enabled kernel is not currently running.
 *
 * @return a handle to the hypervisor interface
 */
xc_interface *xc_interface_open(xentoollog_logger *logger,
                                xentoollog_logger *dombuild_logger,
                                unsigned open_flags,
                                const char *load_path);
  /* if logger==NULL, will log to stderr
   * if dombuild_logger=NULL, will log to a file
   */

/*
 * Note: if XC_OPENFLAG_NON_REENTRANT is passed then libxc must not be
 * called reentrantly and the calling application is responsible for
 * providing mutual exclusion surrounding all libxc calls itself.
 *
 * In particular xc_{get,clear}_last_error only remain valid for the
 * duration of the critical section containing the call which failed.
 */
enum xc_open_flags {
    XC_OPENFLAG_DUMMY =  1<<0, /* do not actually open a xenctrl interface */
    XC_OPENFLAG_NON_REENTRANT = 1<<1, /* assume library is only every called from a single thread */
};

/**
 * This function closes an open hypervisor interface.
 *
 * This function can fail if the handle does not represent an open interface or
 * if there were problems closing the interface.  In the latter case
 * the interface is still closed.
 *
 * @parm xch a handle to an open hypervisor interface
 * @return 0 on success, -1 otherwise.
 */
int xc_interface_close(xc_interface *xch);

int xc_interface_set_handle(xc_interface *xch, uintptr_t h);

uintptr_t xc_interface_handle(xc_interface *xch);

/*
 * HYPERCALL SAFE MEMORY BUFFER
 *
 * Ensure that memory which is passed to a hypercall has been
 * specially allocated in order to be safe to access from the
 * hypervisor.
 *
 * Each user data pointer is shadowed by an xc_hypercall_buffer data
 * structure. You should never define an xc_hypercall_buffer type
 * directly, instead use the DECLARE_HYPERCALL_BUFFER* macros below.
 *
 * The strucuture should be considered opaque and all access should be
 * via the macros and helper functions defined below.
 *
 * Once the buffer is declared the user is responsible for explicitly
 * allocating and releasing the memory using
 * xc_hypercall_buffer_alloc(_pages) and
 * xc_hypercall_buffer_free(_pages).
 *
 * Once the buffer has been allocated the user can initialise the data
 * via the normal pointer. The xc_hypercall_buffer structure is
 * transparently referenced by the helper macros (such as
 * xen_set_guest_handle) in order to check at compile time that the
 * correct type of memory is being used.
 */
struct xc_hypercall_buffer {
    /* Hypercall safe memory buffer. */
    void *hbuf;

    /*
     * Reference to xc_hypercall_buffer passed as argument to the
     * current function.
     */
    struct xc_hypercall_buffer *param_shadow;

    /*
     * Direction of copy for bounce buffering.
     */
    int dir;

    /* Used iff dir != 0. */
    void *ubuf;
    size_t sz;
};
typedef struct xc_hypercall_buffer xc_hypercall_buffer_t;

/*
 * Construct the name of the hypercall buffer for a given variable.
 * For internal use only
 */
#define XC__HYPERCALL_BUFFER_NAME(_name) xc__hypercall_buffer_##_name

/*
 * Returns the hypercall_buffer associated with a variable.
 */
#define HYPERCALL_BUFFER(_name)                                                              \
    ({  xc_hypercall_buffer_t _val1;                                                         \
        typeof(XC__HYPERCALL_BUFFER_NAME(_name)) *_val2 = &XC__HYPERCALL_BUFFER_NAME(_name); \
        (void)(&_val1 == _val2);                                                             \
        (_val2)->param_shadow ? (_val2)->param_shadow : (_val2);                             \
     })

#define HYPERCALL_BUFFER_INIT_NO_BOUNCE .dir = 0, .sz = 0, .ubuf = (void *)-1

/*
 * Defines a hypercall buffer and user pointer with _name of _type.
 *
 * The user accesses the data as normal via _name which will be
 * transparently converted to the hypercall buffer as necessary.
 */
#define DECLARE_HYPERCALL_BUFFER(_type, _name)                 \
    _type *_name = NULL;                                       \
    xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(_name) = { \
        .hbuf = NULL,                                          \
        .param_shadow = NULL,                                  \
        HYPERCALL_BUFFER_INIT_NO_BOUNCE                        \
    }

/*
 * Declare the necessary data structure to allow a hypercall buffer
 * passed as an argument to a function to be used in the normal way.
 */
#define DECLARE_HYPERCALL_BUFFER_ARGUMENT(_name)               \
    xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(_name) = { \
        .hbuf = (void *)-1,                                    \
        .param_shadow = _name,                                 \
        HYPERCALL_BUFFER_INIT_NO_BOUNCE                        \
    }

/*
 * Get the hypercall buffer data pointer in a form suitable for use
 * directly as a hypercall argument.
 */
#define HYPERCALL_BUFFER_AS_ARG(_name)                                             \
    ({  xc_hypercall_buffer_t _val1;                                               \
        typeof(XC__HYPERCALL_BUFFER_NAME(_name)) *_val2 = HYPERCALL_BUFFER(_name); \
        (void)(&_val1 == _val2);                                                   \
        (uintptr_t)(_val2)->hbuf;                                              \
     })

#define HYPERCALL_BUFFER_ARGUMENT_BUFFER(_name) \
    (_name)->hbuf

/*
 * Set a xen_guest_handle in a type safe manner, ensuring that the
 * data pointer has been correctly allocated.
 */
#undef set_xen_guest_handle
#define set_xen_guest_handle(_hnd, _val)                                         \
    do {                                                                         \
        xc_hypercall_buffer_t _val1;                                             \
        typeof(XC__HYPERCALL_BUFFER_NAME(_val)) *_val2 = HYPERCALL_BUFFER(_val); \
        (void) (&_val1 == _val2);                                                 \
        set_xen_guest_handle_raw(_hnd, (_val2)->hbuf);                           \
    } while (0)

/* Use with set_xen_guest_handle in place of NULL */
extern xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(HYPERCALL_BUFFER_NULL);

/*
 * Allocate and free hypercall buffers with byte granularity.
 */
void *xc__hypercall_buffer_alloc(xc_interface *xch, xc_hypercall_buffer_t *b, size_t size);
#define xc_hypercall_buffer_alloc(_xch, _name, _size) xc__hypercall_buffer_alloc(_xch, HYPERCALL_BUFFER(_name), _size)
void xc__hypercall_buffer_free(xc_interface *xch, xc_hypercall_buffer_t *b);
#define xc_hypercall_buffer_free(_xch, _name) xc__hypercall_buffer_free(_xch, HYPERCALL_BUFFER(_name))

/*
 * Allocate and free hypercall buffers with page alignment.
 */
void *xc__hypercall_buffer_alloc_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages);
#define xc_hypercall_buffer_alloc_pages(_xch, _name, _nr) xc__hypercall_buffer_alloc_pages(_xch, HYPERCALL_BUFFER(_name), _nr)
void xc__hypercall_buffer_free_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages);
#define xc_hypercall_buffer_free_pages(_xch, _name, _nr) xc__hypercall_buffer_free_pages(_xch, HYPERCALL_BUFFER(_name), _nr)

/*
 * CPUMAP handling
 */
typedef uint8_t *xc_cpumap_t;

#ifdef __UXEN_debugger__
/*
 * DOMAIN DEBUGGING FUNCTIONS
 */

typedef struct xc_core_header {
    unsigned int xch_magic;
    unsigned int xch_nr_vcpus;
    unsigned int xch_nr_pages;
    unsigned int xch_ctxt_offset;
    unsigned int xch_index_offset;
    unsigned int xch_pages_offset;
} xc_core_header_t;

#define XC_CORE_MAGIC     0xF00FEBED
#define XC_CORE_MAGIC_HVM 0xF00FEBEE
#endif  /* __UXEN_debugger__ */

/*
 * DOMAIN MANAGEMENT FUNCTIONS
 */

typedef struct xc_dominfo {
    uint32_t      domid;
    uint32_t      ssidref;
    unsigned int  dying:1, crashed:1, shutdown:1,
                  paused:1, blocked:1, running:1,
                  hvm:1, debugged:1, shutting_down:1;
    unsigned int  shutdown_reason; /* only meaningful if shutdown==1 */
    unsigned long nr_pages; /* current number, not maximum */
    unsigned long nr_host_mapped_pages;
    unsigned long nr_hidden_pages;
    unsigned long nr_pod_pages;
    unsigned long nr_zero_shared_pages;
    unsigned long nr_tmpl_shared_pages;
    unsigned long shared_info_frame;
    uint64_t      cpu_time;
    unsigned long max_memkb;
    unsigned int  nr_online_vcpus;
    unsigned int  max_vcpu_id;
    xen_domain_handle_t handle;
    unsigned int  cpupool;
    uint64_t      pause_time;
} xc_dominfo_t;

typedef xen_domctl_getdomaininfo_t xc_domaininfo_t;

typedef union 
{
#if defined(__i386__) || defined(__x86_64__)
    vcpu_guest_context_x86_64_t x64;
    vcpu_guest_context_x86_32_t x32;   
#endif
    vcpu_guest_context_t c;
} vcpu_guest_context_any_t;


int xc_domain_create(xc_interface *xch,
                     uint32_t ssidref,
                     xen_domain_handle_t handle,
                     uint32_t flags,
                     uint32_t *pdomid);


#ifndef __UXEN_debugger__
/* Functions to produce a dump of a given domain
 *  xc_domain_dumpcore - produces a dump to a specified file
 *  xc_domain_dumpcore_via_callback - produces a dump, using a specified
 *                                    callback function
 */
int xc_domain_dumpcore(xc_interface *xch,
                       uint32_t domid,
                       const char *corename);

/* Define the callback function type for xc_domain_dumpcore_via_callback.
 *
 * This function is called by the coredump code for every "write",
 * and passes an opaque object for the use of the function and
 * created by the caller of xc_domain_dumpcore_via_callback.
 */
typedef int (dumpcore_rtn_t)(xc_interface *xch,
                             void *arg, char *buffer, unsigned int length);

int xc_domain_dumpcore_via_callback(xc_interface *xch,
                                    uint32_t domid,
                                    void *arg,
                                    dumpcore_rtn_t dump_rtn);
#endif  /* __UXEN_debugger__ */

/*
 * This function sets the maximum number of vcpus that a domain may create.
 *
 * @parm xch a handle to an open hypervisor interface.
 * @parm domid the domain id in which vcpus are to be created.
 * @parm max the maximum number of vcpus that the domain may create.
 * @return 0 on success, -1 on failure.
 */
int xc_domain_max_vcpus(xc_interface *xch,
                        uint32_t domid,
                        unsigned int max);

/**
 * This function pauses a domain. A paused domain still exists in memory
 * however it does not receive any timeslices from the hypervisor.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to pause
 * @return 0 on success, -1 on failure.
 */
int xc_domain_pause(xc_interface *xch,
                    uint32_t domid);
/**
 * This function unpauses a domain.  The domain should have been previously
 * paused.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to unpause
 * return 0 on success, -1 on failure
 */
int xc_domain_unpause(xc_interface *xch,
                      uint32_t domid);

/**
 * This function will destroy a domain.  Destroying a domain removes the domain
 * completely from memory.  This function should be called after sending the
 * domain a SHUTDOWN control message to free up the domain resources.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to destroy
 * @return 0 on success, -1 on failure
 */
int xc_domain_destroy(xc_interface *xch,
                      uint32_t domid);


/**
 * This function resumes a suspended domain. The domain should have
 * been previously suspended.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to resume
 * return 0 on success, -1 on failure
 */
int xc_domain_resume(xc_interface *xch, uint32_t domid);

/**
 * This function will shutdown a domain. This is intended for use in
 * fully-virtualized domains where this operation is analogous to the
 * sched_op operations in a paravirtualized domain. The caller is
 * expected to give the reason for the shutdown.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to destroy
 * @parm reason is the reason (SHUTDOWN_xxx) for the shutdown
 * @return 0 on success, -1 on failure
 */
int xc_domain_shutdown(xc_interface *xch,
                       uint32_t domid,
                       int reason);

/**
 * This function will return information about one or more domains. It is
 * designed to iterate over the list of domains. If a single domain is
 * requested, this function will return the next domain in the list - if
 * one exists. It is, therefore, important in this case to make sure the
 * domain requested was the one returned.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm first_domid the first domain to enumerate information from.  Domains
 *                   are currently enumerate in order of creation.
 * @parm max_doms the number of elements in info
 * @parm info an array of max_doms size that will contain the information for
 *            the enumerated domains.
 * @return the number of domains enumerated or -1 on error
 */
int xc_domain_getinfo(xc_interface *xch,
                      uint32_t first_domid,
                      unsigned int max_doms,
                      xc_dominfo_t *info);


/**
 * This function will return information about one or more domains, using a
 * single hypercall.  The domain information will be stored into the supplied
 * array of xc_domaininfo_t structures.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm first_domain the first domain to enumerate information from.
 *                    Domains are currently enumerate in order of creation.
 * @parm max_domains the number of elements in info
 * @parm info an array of max_doms size that will contain the information for
 *            the enumerated domains.
 * @return the number of domains enumerated or -1 on error
 */
int xc_domain_getinfolist(xc_interface *xch,
                          uint32_t first_domain,
                          unsigned int max_domains,
                          xc_domaininfo_t *info);

/**
 * This function returns information about the context of a hvm domain
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to get information from
 * @parm ctxt_buf a pointer to a structure to store the execution context of
 *            the hvm domain
 * @parm size the size of ctxt_buf in bytes
 * @return 0 on success, -1 on failure
 */
int xc_domain_hvm_getcontext(xc_interface *xch,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size);


/**
 * This function returns one element of the context of a hvm domain
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to get information from
 * @parm typecode which type of elemnt required 
 * @parm instance which instance of the type
 * @parm ctxt_buf a pointer to a structure to store the execution context of
 *            the hvm domain
 * @parm size the size of ctxt_buf (must be >= HVM_SAVE_LENGTH(typecode))
 * @return 0 on success, -1 on failure
 */
int xc_domain_hvm_getcontext_partial(xc_interface *xch,
                                     uint32_t domid,
                                     uint16_t typecode,
                                     uint16_t instance,
                                     void *ctxt_buf,
                                     uint32_t size);

/**
 * This function will set the context for hvm domain
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to set the hvm domain context for
 * @parm hvm_ctxt pointer to the the hvm context with the values to set
 * @parm size the size of hvm_ctxt in bytes
 * @return 0 on success, -1 on failure
 */
int xc_domain_hvm_setcontext(xc_interface *xch,
                             uint32_t domid,
                             uint8_t *hvm_ctxt,
                             uint32_t size);

/**
 * This function returns information about the execution context of a
 * particular vcpu of a domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to get information from
 * @parm vcpu the vcpu number
 * @parm ctxt a pointer to a structure to store the execution context of the
 *            domain
 * @return 0 on success, -1 on failure
 */
int xc_vcpu_getcontext(xc_interface *xch,
                       uint32_t domid,
                       uint32_t vcpu,
                       vcpu_guest_context_any_t *ctxt);

typedef xen_domctl_getvcpuinfo_t xc_vcpuinfo_t;
int xc_vcpu_getinfo(xc_interface *xch,
                    uint32_t domid,
                    uint32_t vcpu,
                    xc_vcpuinfo_t *info);

#ifdef __UXEN_cpu_usage__
long long xc_domain_get_cpu_usage(xc_interface *xch,
                                  domid_t domid,
                                  int vcpu);
#endif  /* __UXEN_cpu_usage__ */

int xc_domain_sethandle(xc_interface *xch, uint32_t domid,
                        xen_domain_handle_t handle);

#ifdef __UXEN_sendtrigger__
/**
 * This function sends a trigger to a domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to send trigger
 * @parm trigger the trigger type
 * @parm vcpu the vcpu number to send trigger 
 * return 0 on success, -1 on failure
 */
int xc_domain_send_trigger(xc_interface *xch,
                           uint32_t domid,
                           uint32_t trigger,
                           uint32_t vcpu);
#endif  /* __UXEN_sendtrigger__ */

#ifdef __UXEN_debugger__
/**
 * This function enables or disable debugging of a domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to send trigger
 * @parm enable true to enable debugging
 * return 0 on success, -1 on failure
 */
int xc_domain_setdebugging(xc_interface *xch,
                           uint32_t domid,
                           unsigned int enable);
#endif  /* __UXEN_debugger__ */

typedef xen_sysctl_physinfo_t xc_physinfo_t;

int xc_physinfo(xc_interface *xch, xc_physinfo_t *info);

int xc_domain_setmaxmem(xc_interface *xch,
                        uint32_t domid,
                        unsigned int max_memkb);

int xc_domain_set_time_offset(xc_interface *xch,
                              uint32_t domid,
                              int32_t time_offset_seconds);

int xc_domain_set_tsc_info(xc_interface *xch,
                           uint32_t domid,
                           uint32_t tsc_mode,
                           uint64_t elapsed_nsec,
                           uint32_t gtsc_khz,
                           uint32_t incarnation);

int xc_domain_get_tsc_info(xc_interface *xch,
                           uint32_t domid,
                           uint32_t *tsc_mode,
                           uint64_t *elapsed_nsec,
                           uint32_t *gtsc_khz,
                           uint32_t *incarnation);

int xc_domain_maximum_gpfn(xc_interface *xch, domid_t domid);

int xc_domain_add_to_physmap(xc_interface *xch,
                             uint32_t domid,
                             unsigned int space,
                             unsigned long idx,
                             xen_pfn_t gpfn);

int xc_domain_populate_physmap(xc_interface *xch,
                               uint32_t domid,
                               unsigned long nr_extents,
                               unsigned int extent_order,
                               unsigned int mem_flags,
                               xen_pfn_t *extent_start);

int xc_domain_populate_physmap_exact(xc_interface *xch,
                                     uint32_t domid,
                                     unsigned long nr_extents,
                                     unsigned int extent_order,
                                     unsigned int mem_flags,
                                     xen_pfn_t *extent_start);

int xc_domain_populate_physmap_from_buffer(xc_interface *xch,
                                           uint32_t domid,
                                           unsigned long nr_extents,
                                           unsigned int extent_order,
                                           unsigned int mem_flags,
                                           xen_pfn_t *extent_start,
                                           xc_hypercall_buffer_t *buffer);

int
xc_domain_memory_capture(xc_interface *xch,
                         uint32_t domid,
                         unsigned long nr_pfns,
                         xen_memory_capture_gpfn_info_t *pfn_list,
                         unsigned long *nr_done,
                         xc_hypercall_buffer_t *buffer,
                         uint32_t buffer_size);

int xc_domain_clone_physmap(xc_interface *xch,
                            uint32_t domid,
                            xen_domain_handle_t parentuuid);

int xc_domain_set_pod_target(xc_interface *xch,
                             uint32_t domid,
                             uint64_t target_pages,
                             uint64_t *tot_pages,
                             uint64_t *pod_cache_pages,
                             uint64_t *pod_entries);

/**
 * Memory maps a range within one domain to a local address range.  Mappings
 * should be unmapped with munmap and should follow the same rules as mmap
 * regarding page alignment.  Returns NULL on failure.
 *
 * @parm xch a handle on an open hypervisor interface
 * @parm dom the domain to map memory from
 * @parm size the amount of memory to map (in multiples of page size)
 * @parm prot same flag as in mmap().
 * @parm mfn the frame address to map.
 */
void *xc_map_foreign_range(xc_interface *xch, uint32_t dom,
                            int size, int prot,
                            unsigned long mfn );

int xc_munmap(xc_interface *xch, uint32_t dom, void *, uint32_t);

#ifndef PROT_READ
#define PROT_READ       0x1             /* page can be read */
#endif
#ifndef PROT_WRITE
#define PROT_WRITE      0x2             /* page can be written */
#endif

void *xc_map_foreign_pages(xc_interface *xch, uint32_t dom, int prot,
                           const xen_pfn_t *arr, int num );

/**
 * DEPRECATED - use xc_map_foreign_bulk() instead.
 *
 * Like xc_map_foreign_pages(), except it can succeeed partially.
 * When a page cannot be mapped, its PFN in @arr is or'ed with
 * 0xF0000000 to indicate the error.
 */
void *xc_map_foreign_batch(xc_interface *xch, uint32_t dom, int prot,
                           xen_pfn_t *arr, int num );

/**
 * Like xc_map_foreign_pages(), except it can succeed partially.
 * When a page cannot be mapped, its respective field in @err is
 * set to the corresponding errno value.
 */
void *xc_map_foreign_bulk(xc_interface *xch, uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err, unsigned int num);

/**
 * Translates a range of virtual addresses in the context of a given domain and
 * vcpu returning GFNs containing the addresses (that is, an MFN for
 * PV guests, a PFN for HVM guests).  Returns -1 for failure.
 *
 * @parm xch a handle on an open hypervisor interface
 * @parm dom the domain to perform the translation in
 * @parm vcpu the vcpu to perform the translation on
 * @parm virt_begin start of virtual address range to translate
 * @parm npages number of pages to translate
 */
int xc_translate_foreign_address_range(
    xc_interface *xch, uint32_t dom,
    int vcpu, unsigned long long virt_begin, unsigned int npages,
    uint64_t *gfn);
unsigned long xc_translate_foreign_address(
    xc_interface *xch, uint32_t dom,
    int vcpu, unsigned long long virt);

int xc_clear_domain_page(xc_interface *xch, uint32_t domid,
                         unsigned long dst_pfn);

int xc_domctl(xc_interface *xch, struct xen_domctl *domctl);

int xc_sysctl(xc_interface *xch, struct xen_sysctl *sysctl);

int xc_version(xc_interface *xch, int cmd, void *arg);

int xc_hvm_set_pci_intx_level(
    xc_interface *xch, domid_t dom,
    uint8_t domain, uint8_t bus, uint8_t device, uint8_t intx,
    unsigned int level);
int xc_hvm_set_isa_irq_level(
    xc_interface *xch, domid_t dom,
    uint8_t isa_irq,
    unsigned int level);

int xc_hvm_set_pci_link_route(
    xc_interface *xch, domid_t dom, uint8_t link, uint8_t isa_irq);

#ifdef __UXEN_vmsi__
int xc_hvm_inject_msi(
    xc_interface *xch, domid_t dom, uint64_t addr, uint32_t data);
#endif  /* __UXEN_vmsi__ */

/*
 * Track dirty bit changes in the VRAM area
 *
 * All of this is done atomically:
 * - get the dirty bitmap since the last call
 * - set up dirty tracking area for period up to the next call
 * - clear the dirty tracking area.
 *
 * Returns -ENODATA and does not fill bitmap if the area has changed since the
 * last call.
 */
int xc_hvm_track_dirty_vram(
    xc_interface *xch, domid_t dom,
    uint64_t first_pfn, uint64_t nr,
    uint8_t *bitmap, uint16_t want_events);

/*
 * Notify that some pages got modified by the Device Model
 */
int xc_hvm_modified_memory(
    xc_interface *xch, domid_t dom, uint64_t first_pfn, uint64_t nr);

/*
 * Set a range of memory to a specific type.
 * Allowed types are HVMMEM_ram_rw, HVMMEM_ram_ro, HVMMEM_mmio_dm
 */
int xc_hvm_set_mem_type(
    xc_interface *xch, domid_t dom, hvmmem_type_t memtype, uint64_t first_pfn, uint64_t nr);

/*
 * Injects a hardware/software CPU trap, to take effect the next time the HVM 
 * resumes. 
 */
int xc_hvm_inject_trap(
    xc_interface *xch, domid_t dom, int vcpu, uint32_t trap, uint32_t error_code, 
    uint64_t cr2);

/*
 *  LOGGING AND ERROR REPORTING
 */


enum xc_error_code {
  XC_ERROR_NONE = 0,
  XC_INTERNAL_ERROR = 1,
  XC_INVALID_KERNEL = 2,
  XC_INVALID_PARAM = 3,
  XC_OUT_OF_MEMORY = 4,
  /* new codes need to be added to xc_error_level_to_desc too */
};

#define XC_MAX_ERROR_MSG_LEN 1024
typedef struct xc_error {
  enum xc_error_code code;
  char message[XC_MAX_ERROR_MSG_LEN];
} xc_error;


/*
 * Convert an error code or level into a text description.  Return values
 * are pointers to fixed strings and do not need to be freed.
 * Do not fail, but return pointers to generic strings if fed bogus input.
 */
const char *xc_error_code_to_desc(int code);

/*
 * Convert an errno value to a text description.
 */
const char *xc_strerror(xc_interface *xch, int errcode);


/*
 * Return a pointer to the last error with level XC_REPORT_ERROR. This
 * pointer and the data pointed to are only valid until the next call
 * to libxc in the same thread.
 */
const xc_error *xc_get_last_error(xc_interface *handle);

/*
 * Clear the last error
 */
void xc_clear_last_error(xc_interface *xch);

int xc_set_hvm_param(xc_interface *handle, domid_t dom, int param, uint64_t value);
int xc_get_hvm_param(xc_interface *handle, domid_t dom, int param, uint64_t *value);

int xc_hvm_register_ioreq_server(xc_interface *xch, domid_t dom,
                                 unsigned int *id);
enum xc_hvm_iopage_type {
    XC_HVM_IOPAGE,
};
xen_pfn_t xc_hvm_iopage(xc_interface *xch, domid_t dom, int serverid,
                        enum xc_hvm_iopage_type type);
int xc_hvm_get_ioreq_server_buf_channel(xc_interface *xch, domid_t dom,
                                        servid_t id, unsigned int *channel);
int xc_hvm_map_io_range_to_ioreq_server(xc_interface *xch, domid_t dom,
                                        servid_t id, char is_mmio,
                                        uint64_t start, uint64_t end);
int xc_hvm_unmap_io_range_from_ioreq_server(xc_interface *xch, domid_t dom,
                                            servid_t id, char is_mmio,
                                            uint64_t addr);
/*
 * Register a PCI device
 */
int xc_hvm_register_pcidev(xc_interface *xch, domid_t dom, unsigned int id,
                           uint16_t bdf);

int xc_domain_set_introspection_features(xc_interface *xch,
                                         uint32_t domid, uint64_t mask);

#ifdef __UXEN_debugger__
/* Control the domain for debug */
int xc_domain_debug_control(xc_interface *xch,
                            uint32_t domid,
                            uint32_t sop,
                            uint32_t vcpu);
#endif  /* __UXEN_debugger__ */

#if defined(__i386__) || defined(__x86_64__)
void xc_cpuid(const unsigned int *input, unsigned int *regs);
void xc_cpuid_brand_get(char *str);
#ifdef __UXEN_cpuid__
int xc_cpuid_check(xc_interface *xch,
                   const unsigned int *input,
                   const char **config,
                   char **config_transformed);
int xc_cpuid_set(xc_interface *xch,
                 domid_t domid,
                 const unsigned int *input,
                 const char **config,
                 char **config_transformed);
#endif  /* __UXEN_cpuid__ */
int xc_cpuid_apply_policy(xc_interface *xch,
                          domid_t domid);
#endif

#endif /* XENCTRL_H */
