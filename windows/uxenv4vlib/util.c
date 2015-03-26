/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"


#if 0
v4v_pfn_list_t *
uxen_v4v_make_pfn_list (v4v_ring_t *ring)
{
    uint32_t npages;
    uint32_t ring_length;
    uint32_t len;
    uint8_t *buf;
    unsigned i;
    v4v_pfn_list_t *pfns;

    PHYSICAL_ADDRESS pa;

    ring_length = sizeof (v4v_ring_t) + ring->len;
    npages = (ring_length + PAGE_SIZE - 1) >> PAGE_SHIFT;

    len = sizeof (v4v_pfn_list_t) + (sizeof (v4v_pfn_t) * npages);

    pfns =
        (v4v_pfn_list_t *) ExAllocatePoolWithTag (NonPagedPool, len,
                UXEN_V4V_TAG);

    if (!pfns)
        return pfns;

    RtlZeroMemory (pfns, len);

    pfns->magic = V4V_PFN_LIST_MAGIC;
    pfns->npage = npages;

    for (i = 0, buf = (uint8_t *) ring->ring; i < npages; i++, buf += PAGE_SIZE) {
        pa = MmGetPhysicalAddress (buf);
        pfns->pages[i] = pa.QuadPart / PAGE_SIZE;
    }

    return pfns;
}

#define EAGAIN          11      /* Try again */
#define EINVAL          22      /* Invalid argument */
#define ENOMEM          12      /* Out of memory */
#define ENOSPC          28      /* No space left on device */
#define EMSGSIZE        90      /* Message too long */
#define ENOTCONN        107     /* Transport endpoint is not connected */
#define ECONNREFUSED    111     /* Connection refused */
#define EFAULT          14      /* Bad address */
#define ENOSYS          38      /* Function not implemented */



NTSTATUS uxenerrno_to_ntstatus(int err)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (err < 0) {
        switch (err) {
            case -EAGAIN:
                status = STATUS_RETRY;
                break;
            case -EINVAL:
                status = STATUS_INVALID_PARAMETER;
                break;
            case -ENOMEM:
                status = STATUS_NO_MEMORY;
                break;
            case -ENOSPC:
            case -EMSGSIZE:
                status = STATUS_BUFFER_OVERFLOW;
                break;
            case -ENOSYS:
                status = STATUS_NOT_IMPLEMENTED;
                break;
            case -ENOTCONN:
            case -ECONNREFUSED:
                status = STATUS_VIRTUAL_CIRCUIT_CLOSED;
                break;
            case -EFAULT:
            default:
                DbgPrint("send data fault - hypercall err: %d\n", err);
                status = STATUS_UNSUCCESSFUL;
        };
    }

    return status;
}
#endif

