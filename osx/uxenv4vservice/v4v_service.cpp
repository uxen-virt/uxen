/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "v4v_service.h"
#include "v4v_device.h"
#include "v4v_service_shared.h"
#include "v4v_ops.h"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <sys/errno.h>

extern "C" kern_return_t _start(kmod_info_t *ki, void *data);
extern "C" kern_return_t _stop(kmod_info_t *ki, void *data);
__attribute__((visibility("default")))
KMOD_EXPLICIT_DECL(org.uxen.driver.uxenv4vservice, "1.0.0", _start, _stop)
extern "C" {
    kmod_start_func_t *_realmain = 0;
    kmod_stop_func_t *_antimain = 0;
    int _kext_apple_cc = __APPLE_CC__ ;
};

OSDefineMetaClassAndStructors(uxen_v4v_service, IOService);

void
uxen_v4v_service::notifyV4VEvent()
{

    this->messageClients(kUxenV4VServiceRingNotification);
}

void
uxen_v4v_service::notifyV4VRingResetEvent()
{

    this->messageClients(kUxenV4VServiceRingResetNotification);
}

bool
uxen_v4v_service::start(IOService *provider)
{
    uxen_v4v_device *v4v_dev;

    if (!IOService::start(provider))
        return false;
    v4v_dev = OSDynamicCast(uxen_v4v_device, provider);
    if (v4v_dev == nullptr)
        return false;

    this->v4v_device = v4v_dev;
    
    this->registerService();
    
    return true;
}

IOReturn
uxen_v4v_service::newUserClient(
    task_t owningTask, void * securityID,
    UInt32 type, OSDictionary * properties,
    IOUserClient ** handler )
{

    return this->IOService::newUserClient(
        owningTask, securityID, type, properties, handler);
}

void
uxen_v4v_service::stop(IOService *provider)
{

    IOService::stop(provider);
}


int
uxen_v4v_service::allocAndBindSharedRing(
    unsigned length, uint16_t partner_domain, uint32_t source_port,
    uxen_v4v_ring **out_new_ring, IOBufferMemoryDescriptor **out_ring_buf)
{
    static const uint64_t PFN_ALLOC_MASK = 0xffffffffull << PAGE_SHIFT;
    size_t total_bytes;
    IOBufferMemoryDescriptor *ring_mem;
    int result;

    total_bytes = uxen_v4v_ring_mem_size_for_length(length);
    // kIOMemoryMapperNone: physical addresses in CPU space, not I/O space
    ring_mem = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        kIODirectionInOut | kIOMemoryMapperNone | kIOMemoryKernelUserShared,
        total_bytes, PFN_ALLOC_MASK);
    if (ring_mem == nullptr)
        return ENOMEM;
    result = uxen_v4v_bind_ring_with_buffer(
        this->v4v_device, length, partner_domain,
        source_port, out_new_ring, ring_mem);
    if (result != 0) {
        *out_ring_buf = nullptr;
        OSSafeReleaseNULL(ring_mem);
    } else {
        *out_ring_buf = ring_mem;
    }
    return result;
}
    
int
uxen_v4v_service::allocAndBindRing(
    unsigned length, uint16_t partner_domain, uint32_t source_port,
    uxen_v4v_ring **out_new_ring)
{

    return uxen_v4v_alloc_and_bind_ring(
        this->v4v_device, length, partner_domain, source_port, out_new_ring);
}

errno_t
uxen_v4v_service::reregisterRing(uxen_v4v_ring *ring)
{

    return uxen_v4v_reregister_ring(this->v4v_device, ring);
}

    
void
uxen_v4v_service::destroyRing(uxen_v4v_ring *ring)
{

    uxen_v4v_destroy_ring(this->v4v_device, ring);
}
    
ssize_t
uxen_v4v_service::sendOnRing(
    uxen_v4v_ring *ring, v4v_addr_t dest, const void *data, unsigned data_len)
{

    return uxen_v4v_send_ring(this->v4v_device, ring, &dest, data, data_len);
}

ssize_t
uxen_v4v_service::sendvOnRing(
    uxen_v4v_ring *ring, v4v_addr_t dest,
    const v4v_iov_t buffers[], unsigned num_bufs)
{

    return uxen_v4v_sendv_ring(
        this->v4v_device, ring, &dest, buffers, num_bufs);
}

    
ssize_t
uxen_v4v_service::receiveFromRing(
    uxen_v4v_ring *ring, void *buffer, unsigned max_len, bool consume)
{
    v4v_addr_t from = {};
    uint32_t protocol = {};
    
    return uxen_v4v_ring_copy_out(
        ring, &from, &protocol, buffer, max_len, consume);
}
    
int
uxen_v4v_service::notify()
{
    v4v_ring_data_t data =
    {
        .magic = V4V_RING_DATA_MAGIC,
        .nent = 0,
    };
    
    return uxen_v4v_notify(this->v4v_device, &data);
}
int
uxen_v4v_service::notify(v4v_ring_data_t *data)
{

    return uxen_v4v_notify(this->v4v_device, data);
}

errno_t
uxen_v4v_service::createRingInDomain(v4v_addr_t dest)
{

    return uxen_v4v_create_ring(this->v4v_device, dest);
}

