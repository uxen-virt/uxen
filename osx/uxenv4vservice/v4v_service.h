/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _V4V_SERVICE_H_
#define _V4V_SERVICE_H_

#include <IOKit/IOService.h>
#include <xen/v4v.h>
#include "v4v_device.h"

struct uxen_v4v_ring;

#define uxen_v4v_service org_uxen_driver_v4v_service

class IOBufferMemoryDescriptor;

/** The class providing any V4V communications services. This class will allow
 * both kernel and user client services to make use of V4V rings.
 */
class uxen_v4v_service : public IOService
{
    OSDeclareDefaultStructors(uxen_v4v_service);
    uxen_v4v_device *v4v_device;
public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;

    virtual IOReturn newUserClient(
        task_t owningTask, void * securityID,
        UInt32 type, OSDictionary * properties,
        IOUserClient ** handler ) override;

    void notifyV4VEvent();
    void notifyV4VRingResetEvent();
    
    errno_t allocAndBindSharedRing(
        unsigned length, uint16_t *partner_domain,
        uint32_t source_port, v4v_idtoken_t *partner_idtoken,
        uxen_v4v_ring **out_new_ring, IOBufferMemoryDescriptor **out_ring_buf);
    
    errno_t allocAndBindRing(
        unsigned length, uint16_t partner_domain, uint32_t local_port,
        uxen_v4v_ring **out_new_ring);
    errno_t reregisterRing(uxen_v4v_ring *ring);
    void destroyRing(uxen_v4v_ring *ring);
    
    ssize_t sendOnRing(
        uxen_v4v_ring *ring, v4v_addr_t dest,
        const void *data, unsigned data_len);
    ssize_t sendvOnRing(
        uxen_v4v_ring *ring, v4v_addr_t dest,
        const v4v_iov_t buffers[], unsigned num_bufs);
    
    ssize_t receiveFromRing(
        uxen_v4v_ring *ring, void *buffer, unsigned max_len, bool consume);
    
    errno_t createRingInDomain(v4v_addr_t dest);
    
    int notify();
    int notify(v4v_ring_data_t *data);
};

#endif /* _UXENV4VSERVICE_H_ */
