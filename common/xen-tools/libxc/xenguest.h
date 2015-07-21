/******************************************************************************
 * xenguest.h
 *
 * A library for guest domain management in Xen.
 *
 * Copyright (c) 2003-2004, K A Fraser.
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
 * Copyright 2012-2015, Bromium, Inc.
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

#ifndef XENGUEST_H
#define XENGUEST_H

#ifndef __UXEN_TOOLS__
#define XCFLAGS_LIVE      1
#define XCFLAGS_DEBUG     2
#define XCFLAGS_HVM       4
#define XCFLAGS_STDVGA    8
#define X86_64_B_SIZE   64 
#define X86_32_B_SIZE   32

/* callbacks provided by xc_domain_save */
struct save_callbacks {
    int (*suspend)(void* data);
    /* callback to rendezvous with external checkpoint functions */
    int (*postcopy)(void* data);
    /* returns:
     * 0: terminate checkpointing gracefully
     * 1: take another checkpoint */
    int (*checkpoint)(void* data);

    /* Enable qemu-dm logging dirty pages to xen */
    int (*switch_qemu_logdirty)(int domid, unsigned enable, void *data); /* HVM only */

    /* to be provided as the last argument to each callback function */
    void* data;
};

/**
 * This function will save a running domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm fd the file descriptor to save a domain to
 * @parm dom the id of the domain
 * @return 0 on success, -1 on failure
 */
int xc_domain_save(xc_interface *xch, int io_fd, uint32_t dom, uint32_t max_iters,
                   uint32_t max_factor, uint32_t flags /* XCFLAGS_xxx */,
                   struct save_callbacks* callbacks, int hvm);


/**
 * This function will restore a saved domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm fd the file descriptor to restore a domain from
 * @parm dom the id of the domain
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm hvm non-zero if this is a HVM restore
 * @parm pae non-zero if this HVM domain has PAE support enabled
 * @parm superpages non-zero to allocate guest memory with superpages
 * @return 0 on success, -1 on failure
 */
int xc_domain_restore(xc_interface *xch, int io_fd, uint32_t dom,
                      unsigned int store_evtchn, unsigned long *store_mfn,
                      unsigned int console_evtchn, unsigned long *console_mfn,
                      unsigned int hvm, unsigned int pae, int superpages);
/**
 * xc_domain_restore writes a file to disk that contains the device
 * model saved state.
 * The pathname of this file is XC_DEVICE_MODEL_RESTORE_FILE; The domid
 * of the new domain is automatically appended to the filename,
 * separated by a ".".
 */
#define XC_DEVICE_MODEL_RESTORE_FILE "/var/lib/xen/qemu-resume"

/**
 * This function will create a domain for a paravirtualized Linux
 * using file names pointing to kernel and ramdisk
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the id of the domain
 * @parm mem_mb memory size in megabytes
 * @parm image_name name of the kernel image file
 * @parm ramdisk_name name of the ramdisk image file
 * @parm cmdline command line string
 * @parm flags domain creation flags
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm console_evtchn the console event channel for this domain to use
 * @parm conole_mfn returned with the mfn of the console page
 * @return 0 on success, -1 on failure
 */
int xc_linux_build(xc_interface *xch,
                   uint32_t domid,
                   unsigned int mem_mb,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   const char *features,
                   unsigned long flags,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn,
                   unsigned int console_evtchn,
                   unsigned long *console_mfn);

/** The same interface, but the dom structure is managed by the caller */
struct xc_dom_image;
int xc_dom_linux_build(xc_interface *xch,
		       struct xc_dom_image *dom,
		       uint32_t domid,
		       unsigned int mem_mb,
		       const char *image_name,
		       const char *ramdisk_name,
		       unsigned long flags,
		       unsigned int store_evtchn,
		       unsigned long *store_mfn,
		       unsigned int console_evtchn,
		       unsigned long *console_mfn);

/**
 * This function will create a domain for a paravirtualized Linux
 * using buffers for kernel and initrd
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the id of the domain
 * @parm mem_mb memory size in megabytes
 * @parm image_buffer buffer containing kernel image
 * @parm image_size size of the kernel image buffer
 * @parm initrd_buffer name of the ramdisk image file
 * @parm initrd_size size of the ramdisk buffer
 * @parm cmdline command line string
 * @parm flags domain creation flags
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm console_evtchn the console event channel for this domain to use
 * @parm conole_mfn returned with the mfn of the console page
 * @return 0 on success, -1 on failure
 */
int xc_linux_build_mem(xc_interface *xch,
                       uint32_t domid,
                       unsigned int mem_mb,
                       const char *image_buffer,
                       unsigned long image_size,
                       const char *initrd_buffer,
                       unsigned long initrd_size,
                       const char *cmdline,
                       const char *features,
                       unsigned long flags,
                       unsigned int store_evtchn,
                       unsigned long *store_mfn,
                       unsigned int console_evtchn,
                       unsigned long *console_mfn);
#endif  /* __UXEN_TOOLS__ */

enum xc_hvm_module_type {
    XC_HVM_MODULE_ACPI = 0,
    XC_HVM_MODULE_SMBIOS,
};

struct xc_hvm_mod_entry {
    int flags;
    size_t len;
    void *base;
};

struct xc_hvm_module {
    int type;
    size_t nent; /* Number of entries in the module */
    struct xc_hvm_mod_entry *entries;
};

#define XC_HVM_OEM_ID           (1 << 0)
#define XC_HVM_OEM_TABLE_ID     (1 << 1)
#define XC_HVM_OEM_REVISION     (1 << 2)
#define XC_HVM_CREATOR_ID       (1 << 3)
#define XC_HVM_CREATOR_REVISION (1 << 4)
#define XC_HVM_SMBIOS_MAJOR     (1 << 5)
#define XC_HVM_SMBIOS_MINOR     (1 << 6)

struct xc_hvm_oem_info {
    int flags;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    char creator_id[4];
    uint32_t creator_revision;
    uint8_t smbios_version_major;
    uint8_t smbios_version_minor;
};

int xc_hvm_build(xc_interface *xch,
                 uint32_t domid,
                 int memsize,
                 uint32_t nr_ioreq_servers,
                 const char *image_name,
                 struct xc_hvm_module *modules,
                 size_t mod_count,
                 struct xc_hvm_oem_info *oem_info);

#ifndef __UXEN_TOOLS__
int xc_hvm_build_target_mem(xc_interface *xch,
                            uint32_t domid,
                            int memsize,
                            int target,
                            uint32_t nr_ioreq_servers,
                            const char *image_name);

int xc_hvm_build_mem(xc_interface *xch,
                     uint32_t domid,
                     int memsize,
                     uint32_t nr_ioreq_servers,
                     const char *image_buffer,
                     unsigned long image_size);

int xc_suspend_evtchn_release(xc_interface *xch, xc_evtchn *xce, int domid, int suspend_evtchn);

int xc_suspend_evtchn_init(xc_interface *xch, xc_evtchn *xce, int domid, int port);

int xc_await_suspend(xc_interface *xch, xc_evtchn *xce, int suspend_evtchn);

int xc_get_bit_size(xc_interface *xch,
                    const char *image_name, const char *cmdline,
                    const char *features, int *type);

int xc_mark_page_online(xc_interface *xch, unsigned long start,
                        unsigned long end, uint32_t *status);

int xc_mark_page_offline(xc_interface *xch, unsigned long start,
                          unsigned long end, uint32_t *status);

int xc_query_page_offline_status(xc_interface *xch, unsigned long start,
                                 unsigned long end, uint32_t *status);

int xc_exchange_page(xc_interface *xch, int domid, xen_pfn_t mfn);


/**
 * This function map m2p table
 * @parm xch a handle to an open hypervisor interface
 * @parm max_mfn the max pfn
 * @parm prot the flags to map, such as read/write etc
 * @parm mfn0 return the first mfn, can be NULL
 * @return mapped m2p table on success, NULL on failure
 */
xen_pfn_t *xc_map_m2p(xc_interface *xch,
                      unsigned long max_mfn,
                      int prot,
                      unsigned long *mfn0);
#endif  /* __UXEN_TOOLS__ */
#endif /* XENGUEST_H */
