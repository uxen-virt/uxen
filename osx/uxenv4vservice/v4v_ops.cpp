/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "v4v_ops.h"
#include <xen/v4v.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <sys/errno.h>
#include <uxen_xnu_errno.h>
#include <uxen/uxen_desc.h>

static const uint64_t PFN_ALLOC_MASK = 0xffffffffull << PAGE_SHIFT;

static errno_t
xnu_errno_from_uxen(ssize_t ret)
{
    /* Note: uxen_translate_xen_errno() takes a negative errno and spits out a
     * positive one. */
    return uxen_translate_xen_errno(static_cast<errno_t>(-ret));
}

static ssize_t
xnu_size_or_errno_from_uxen(ssize_t ret)
{

    if (ret < 0)
        return -xnu_errno_from_uxen(-ret);
    return ret;
}

static errno_t
v4v_register_ring(
    uxen_v4v_device *device, uxen_v4v_ring *uxen_ring)
{

    return xnu_errno_from_uxen(
        device->v4vOpHypercall_with_priv(
            uxen_ring->admin_access ? UXEN_ADMIN_HYPERCALL : 0,
            V4VOP_register_ring, uxen_ring->ring, uxen_ring->pfn_list,
            &uxen_ring->partner_idtoken, NULL, NULL));
}

static intptr_t
v4v_send_ring(
    uxen_v4v_device *device,
    v4v_addr_t *source_address, v4v_addr_t *destination_address,
    const void *buffer, uint32_t len_bytes, uint32_t protocol_number)
{
    intptr_t send_res;
    
    send_res =
        device->v4vOpHypercall(
            V4VOP_send, source_address, destination_address,
            const_cast<void*>(buffer),
            reinterpret_cast<void*>(len_bytes),
            reinterpret_cast<void*>(protocol_number));
    return xnu_size_or_errno_from_uxen(send_res);
}

static intptr_t
v4v_sendv_ring(
    uxen_v4v_device *device,
    v4v_addr_t *source_address, v4v_addr_t *destination_address,
    const v4v_iov_t buffers[], uint32_t num_buffers, uint32_t protocol_number)
{

    return xnu_size_or_errno_from_uxen(
        device->v4vOpHypercall(
            V4VOP_sendv, source_address, destination_address,
            const_cast<v4v_iov_t*>(buffers),
            reinterpret_cast<void*>(static_cast<uintptr_t>(num_buffers)),
            reinterpret_cast<void*>(static_cast<uintptr_t>(protocol_number))));
}


errno_t
uxen_v4v_ring_poke(uxen_v4v_device *device, v4v_addr_t dest)
{

    return xnu_errno_from_uxen(device->v4vOpHypercall(
        V4VOP_poke, &dest, NULL, NULL, NULL, NULL));
}

errno_t
uxen_v4v_notify(uxen_v4v_device *device, v4v_ring_data_t *notify_data)
{

    return xnu_errno_from_uxen(device->v4vOpHypercall(
        V4VOP_notify, notify_data, NULL, NULL, NULL, NULL));
}


static errno_t
v4v_unregister_ring(uxen_v4v_device *device, uxen_v4v_ring *uxen_ring)
{

    return xnu_errno_from_uxen(
        device->v4vOpHypercall(
            V4VOP_unregister_ring, uxen_ring->ring, NULL, NULL, NULL, NULL));
}

size_t
uxen_v4v_ring_mem_size_for_length(unsigned length_bytes)
{

    return round_page(length_bytes + sizeof(v4v_ring_t));
}

errno_t
uxen_v4v_alloc_and_bind_ring(
    uxen_v4v_device *device, unsigned length_bytes, domid_t partner_domain,
    uint32_t local_port, bool admin_access, uxen_v4v_ring **created_ring)
{
    size_t total_bytes;
    IOBufferMemoryDescriptor *ring_mem;
    errno_t res;

    if(length_bytes > V4V_MAX_RING_SIZE || length_bytes % 16 != 0) {
        kprintf("uxen_v4v_create_ring bad ring length: %u\n", length_bytes);
        return EINVAL;
    }
   
    total_bytes = uxen_v4v_ring_mem_size_for_length(length_bytes);
    ring_mem = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task, kIODirectionInOut | kIOMemoryMapperNone,
        total_bytes, PFN_ALLOC_MASK);
    
    if (ring_mem == nullptr)
        return ENOMEM;

    res = uxen_v4v_bind_ring_with_buffer(
        device, length_bytes, &partner_domain, local_port, NULL,
        admin_access, created_ring, ring_mem);
    ring_mem->release();
    return res;
}
    
int
uxen_v4v_bind_ring_with_buffer(
    uxen_v4v_device *device, unsigned length_bytes, domid_t *partner_domain,
    uint32_t local_port, v4v_idtoken_t *partner_idtoken, bool admin_access,
    uxen_v4v_ring **created_ring, IOBufferMemoryDescriptor* ring_mem)
{
    size_t total_bytes;
    size_t num_pages;
    size_t pfn_bytes;
    v4v_pfn_list_t *pfn_list;
    v4v_ring_t *ring;
    uxen_v4v_ring *uxen_ring;
    int error;
    
    total_bytes = uxen_v4v_ring_mem_size_for_length(length_bytes);
    if (total_bytes != ring_mem->getLength())
        return EINVAL;
    memset(ring_mem->getBytesNoCopy(), 0, total_bytes);
    
    num_pages = total_bytes >> PAGE_SHIFT;
    pfn_bytes = sizeof(v4v_pfn_list_t) + sizeof(v4v_pfn_t) * num_pages;
    pfn_list = static_cast<v4v_pfn_list_t*>(
        IOMallocAligned(pfn_bytes, alignof(v4v_pfn_list_t)));
    
    memset(pfn_list, 0, sizeof(*pfn_list));
    
    pfn_list->magic = V4V_PFN_LIST_MAGIC;
    pfn_list->npage = static_cast<uint32_t>(num_pages);
    for(unsigned i = 0; i < num_pages; i++) {
        pfn_list->pages[i] =
            ring_mem->getPhysicalSegment(i * PAGE_SIZE, NULL) >> PAGE_SHIFT;
    }
    ring = static_cast<v4v_ring_t*>(ring_mem->getBytesNoCopy());
    ring->id.addr.domain = V4V_DOMID_ANY;
    ring->id.addr.port = local_port;
    ring->id.partner = *partner_domain;
    ring->magic = V4V_RING_MAGIC;
    ring->len = length_bytes;
    
    uxen_ring = static_cast<uxen_v4v_ring*>(
        IOMallocAligned(sizeof(uxen_v4v_ring), alignof(uxen_v4v_ring)));
    uxen_ring->ring = ring;
    uxen_ring->ring_mem = ring_mem;
    uxen_ring->length = length_bytes;
    uxen_ring->pfn_list = pfn_list;
    uxen_ring->admin_access = admin_access;
    if (partner_idtoken)
        memcpy(&uxen_ring->partner_idtoken, partner_idtoken,
               sizeof(v4v_idtoken_t));
    
    error = v4v_register_ring(device, uxen_ring);
    if(error != 0) {
        IOFreeAligned(pfn_list, pfn_bytes);
        IOFreeAligned(uxen_ring, sizeof(uxen_v4v_ring));
        kprintf("v4v_register_ring: returned %d\n", error);
        return error;
    }
    
    uxen_ring->source_address.domain = ring->id.addr.domain;
    uxen_ring->source_address.port = ring->id.addr.port;
    uxen_ring->protocol_number = V4V_PROTO_DGRAM;
    uxen_ring->local_port = local_port;
    uxen_ring->partner_domain = ring->id.partner;
    
    *created_ring = uxen_ring;
    *partner_domain = uxen_ring->partner_domain;
    
    ring_mem->retain();
    
    return 0;
}

void
uxen_v4v_destroy_ring(uxen_v4v_device *device, uxen_v4v_ring *created_ring)
{
    int error;
    size_t pfn_list_size;
    
    error = v4v_unregister_ring(device, created_ring);
    if(error != 0) {
        kprintf("v4v_destroy_ring: error %d", error);
    }
    OSSafeRelease(created_ring->ring_mem);

    pfn_list_size =
        sizeof(v4v_pfn_list_t)
        + sizeof(v4v_pfn_t) * created_ring->pfn_list->npage;
    IOFreeAligned(created_ring->pfn_list, pfn_list_size);
    
    IOFreeAligned(created_ring, sizeof(uxen_v4v_ring));
}

errno_t
uxen_v4v_reregister_ring(uxen_v4v_device *device, uxen_v4v_ring *uxen_ring)
{

    v4v_unregister_ring(device, uxen_ring);
    
    uxen_ring->ring->id.addr.domain = V4V_DOMID_ANY;
    uxen_ring->ring->id.addr.port = uxen_ring->local_port;
    uxen_ring->ring->id.partner = uxen_ring->partner_domain;
    uxen_ring->ring->magic = V4V_RING_MAGIC;
    uxen_ring->ring->len = static_cast<uint32_t>(uxen_ring->length);
    
    return v4v_register_ring(device, uxen_ring);
}

intptr_t
uxen_v4v_send_ring(
    uxen_v4v_device *device, uxen_v4v_ring *ring,
    v4v_addr_t *_destination_address,
    const void *buffer, uint32_t len_bytes)
{
    v4v_addr_t destination_address = *_destination_address;

    if (ring->partner_domain != V4V_DOMID_ANY)
        destination_address.domain = ring->partner_domain;

    return v4v_send_ring(
        device, &ring->source_address, &destination_address,
        buffer, len_bytes, ring->protocol_number);
}

intptr_t
uxen_v4v_sendv_ring(
    uxen_v4v_device *device, uxen_v4v_ring *ring,
    struct v4v_addr *_destination_address,
    const v4v_iov_t buffers[], uint32_t num_buffers)
{
    v4v_addr_t destination_address = *_destination_address;

    if (ring->partner_domain != V4V_DOMID_ANY)
        destination_address.domain = ring->partner_domain;

    return v4v_sendv_ring(
        device, &ring->source_address, &destination_address,
        buffers, num_buffers, ring->protocol_number);
}

ssize_t
uxen_v4v_ring_copy_out(
    uxen_v4v_ring *ring, struct v4v_addr *from, uint32_t *protocol,
    void *buf, size_t buf_len, bool consume)
{

    static_assert(sizeof(v4v_ring_message_header) == 16, "");

    return v4v_copy_out(ring->ring, from, protocol, buf, buf_len, consume);
}

errno_t
uxen_v4v_create_ring(uxen_v4v_device *device, v4v_addr_t dest)
{

    return xnu_errno_from_uxen(
        device->v4vOpHypercall(
            V4VOP_create_ring, &dest, nullptr, nullptr, nullptr, nullptr));
}
