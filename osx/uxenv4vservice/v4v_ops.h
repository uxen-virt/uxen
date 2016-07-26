/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _V4V_OPS_H_
#define _V4V_OPS_H_

#include "v4v_device.h"
#include <xen/v4v.h>

struct uxen_v4v_ring;
struct v4v_addr;
class IOBufferMemoryDescriptor;

struct uxen_v4v_ring {
    v4v_ring_t *ring;
    IOBufferMemoryDescriptor *ring_mem;
    size_t length;
    v4v_pfn_list_t *pfn_list;
    v4v_addr_t source_address;
    uint32_t protocol_number;
    uint32_t local_port;
    domid_t partner_domain;
    bool admin_access;
};

size_t uxen_v4v_ring_mem_size_for_length(unsigned length_bytes);

errno_t uxen_v4v_alloc_and_bind_ring(
    uxen_v4v_device *device, unsigned length_bytes,
    domid_t partner_domain, uint32_t local_port, bool admin_access,
    uxen_v4v_ring **created_ring);
errno_t uxen_v4v_bind_ring_with_buffer(
    uxen_v4v_device *device, unsigned length_bytes,
    domid_t partner_domain, uint32_t local_port, bool admin_access,
    uxen_v4v_ring **created_ring, IOBufferMemoryDescriptor* ring_mem);
errno_t uxen_v4v_reregister_ring(uxen_v4v_device *device, uxen_v4v_ring *ring);
void uxen_v4v_destroy_ring(uxen_v4v_device *device, uxen_v4v_ring *created_ring);

intptr_t uxen_v4v_send_ring(
    uxen_v4v_device *device, uxen_v4v_ring *ring,
    struct v4v_addr *destination_address,
    const void *buffer, uint32_t len_bytes);
intptr_t uxen_v4v_sendv_ring(
    uxen_v4v_device *device, uxen_v4v_ring *ring,
    struct v4v_addr *destination_address,
    const v4v_iov_t buffers[], uint32_t num_buffers);
ssize_t uxen_v4v_ring_copy_out(
    uxen_v4v_ring *ring, struct v4v_addr *from, uint32_t *protocol,
    void *buf, size_t buf_len, bool consume);
errno_t uxen_v4v_ring_poke(uxen_v4v_device *device, v4v_addr_t dest);
errno_t uxen_v4v_notify(uxen_v4v_device *device, v4v_ring_data_t *notify_data);

errno_t uxen_v4v_create_ring(uxen_v4v_device *device, v4v_addr_t dest);


#endif /* _UXENV4VOPS_H_ */
