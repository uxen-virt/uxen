/*
 *  xc_uxen.c
 *  uxen
 *
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#include "xc_private.h"

#include <mm_malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <uxenctllib.h>

#if defined(_WIN32)
#define mlock(addr, len) (!VirtualLock(addr, len))
#define munlock(addr, len) (!VirtualUnlock(addr, len))
#elif defined(__APPLE__)
#include <sys/mman.h>
#endif

int xc_use_foreign_mappings = 1;

static xc_osdep_handle uxen_privcmd_open(xc_interface *xch)
{
    UXEN_HANDLE_T h;

    h = uxen_open(0, TRUE, xch->load_path);
    if (h == INVALID_HANDLE_VALUE) {
	PERROR("Could not obtain handle on privileged command interface");
	return XC_OSDEP_OPEN_ERROR;
    }

    return (xc_osdep_handle)h;
}

static int
uxen_privcmd_close(xc_interface *xch, xc_osdep_handle h)
{
    uxen_close((UXEN_HANDLE_T)h);
    return 0;
}

static void *
uxen_privcmd_alloc_hypercall_buffer(xc_interface *xch, xc_osdep_handle h,
                                    int npages)
{

    return uxen_malloc((UXEN_HANDLE_T)h, npages);
}

static void
uxen_privcmd_free_hypercall_buffer(xc_interface *xch, xc_osdep_handle h,
                                   void *p, int npages)
{

    (void)uxen_free((UXEN_HANDLE_T)h, p, npages);
}

static int
uxen_privcmd_hypercall(xc_interface *xc_handle, xc_osdep_handle h,
			  privcmd_hypercall_t *hypercall)
{

    return uxen_hypercall((UXEN_HANDLE_T)h,
                          (struct uxen_hypercall_desc *)hypercall);
}

static void *
uxen_privcmd_map_foreign_bulk(xc_interface *xch, xc_osdep_handle h,
				 uint32_t dom, int prot,
				 const xen_pfn_t *arr, int *err,
				 unsigned int num)
{
    int ret;
    struct uxen_mmapbatch_desc umd = { };

    umd.umd_num = num;
    switch (prot) {
    case PROT_READ:
	umd.umd_prot = UXEN_MMAPBATCH_PROT_READ;
	break;
    case PROT_WRITE:
    case PROT_READ | PROT_WRITE:
	umd.umd_prot = UXEN_MMAPBATCH_PROT_WRITE;
	break;
    }
    umd.umd_arr = (xen_pfn_t *)arr;
    umd.umd_err = err;
    ret = uxen_mmapbatch((UXEN_HANDLE_T)h, &umd);
    if (ret != 0)
	umd.umd_addr = 0;
    return (void *)(uintptr_t)umd.umd_addr;
}

static void *
uxen_privcmd_map_foreign_range(xc_interface *xch, xc_osdep_handle h,
				  uint32_t dom, int size, int prot,
				  unsigned long mfn)
{
    xen_pfn_t *arr;
    int num;
    int i;
    void *ret;

    num = (size + XC_PAGE_SIZE - 1) >> XC_PAGE_SHIFT;
    arr = calloc(num, sizeof(xen_pfn_t));

    for ( i = 0; i < num; i++ )
        arr[i] = mfn + i;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

static void *
uxen_privcmd_map_foreign_ranges(xc_interface *xch, xc_osdep_handle h,
				   uint32_t dom, size_t size, int prot,
				   size_t chunksize,
				   privcmd_mmap_entry_t entries[],
				   int nentries)
{
    xen_pfn_t *arr;
    int num_per_entry;
    int num;
    int i;
    int j;
    void *ret;

    num_per_entry = chunksize >> XC_PAGE_SHIFT;
    num = num_per_entry * nentries;
    arr = calloc(num, sizeof(xen_pfn_t));

    for ( i = 0; i < nentries; i++ )
        for ( j = 0; j < num_per_entry; j++ )
            arr[i * num_per_entry + j] = entries[i].mfn + j;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

static int
uxen_privcmd_munmap(xc_interface *xch, xc_osdep_handle h,
                   uint32_t dom, void *addr, uint32_t size)
{
    struct uxen_munmap_desc umd = { };

    umd.umd_num = size >> PAGE_SHIFT;
    umd.umd_addr = (uint64_t)(uintptr_t)addr;
    return uxen_munmap((UXEN_HANDLE_T)h, &umd);
}

static struct xc_osdep_ops uxen_privcmd_ops = {
    .open = &uxen_privcmd_open,
    .close = &uxen_privcmd_close,

    .u.privcmd = {
        .alloc_hypercall_buffer = &uxen_privcmd_alloc_hypercall_buffer,
        .free_hypercall_buffer = &uxen_privcmd_free_hypercall_buffer,

        .hypercall = &uxen_privcmd_hypercall,

        .map_foreign_bulk = &uxen_privcmd_map_foreign_bulk,
        .map_foreign_range = &uxen_privcmd_map_foreign_range,
        .map_foreign_ranges = &uxen_privcmd_map_foreign_ranges,

	.munmap = &uxen_privcmd_munmap,
    },
};

static struct xc_osdep_ops *
uxen_osdep_init(xc_interface *xch, enum xc_osdep_type type)
{
    switch ( type )
    {
    case XC_OSDEP_PRIVCMD:
        return &uxen_privcmd_ops;
    default:
        return NULL;
    }
}

xc_osdep_info_t xc_osdep_info = {
    .name = "UXEN Native OS interface",
    .init = &uxen_osdep_init,
    .fake = 0,
};
