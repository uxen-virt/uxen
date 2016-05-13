/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _V4V_USER_RING_H_
#define _V4V_USER_RING_H_

#include <IOKit/IOUserClient.h>
#include <xen/v4v.h>

#define uxen_v4v_user_ring org_uxen_driver_v4v_user_ring

struct uxen_v4v_ring;
class IOBufferMemoryDescriptor;
class org_uxen_driver_v4v_service;

class uxen_v4v_user_ring : public IOUserClient
{
    OSDeclareDefaultStructors(uxen_v4v_user_ring)
public:
    virtual bool initWithTask(
        task_t owningTask, void *securityToken,
        UInt32 type, OSDictionary *properties) override;
    virtual bool start(IOService *provider) override;

    virtual IOReturn registerNotificationPort(
        mach_port_t port, UInt32 type, UInt32 refCon) override;
    
    virtual void free() override;

    virtual IOReturn clientMemoryForType(
        uint32_t type, IOOptionBits *options,
        IOMemoryDescriptor **memory) override;
    virtual IOReturn message(
        UInt32 type, IOService *provider, void *argument = 0) override;
    virtual IOReturn clientClose() override;
    virtual void detach(IOService *provider) override;


    IOReturn createRing(
	void* reference, IOExternalMethodArguments* arguments);
    IOReturn createRing(
        uint32_t length, uint16_t partner_domain, uint32_t local_port,
        v4v_idtoken_t *partner_idtoken,
        uint64_t *out_result, uint64_t *out_partner_domain);

    IOReturn sendTo(
	void* reference, IOExternalMethodArguments* arguments);
    IOReturn sendTo(
        const void *data, unsigned data_len, v4v_addr_t dest, unsigned flags,
        ssize_t* out_result);

    IOReturn notify(
	void *reference, IOExternalMethodArguments *arguments);
    IOReturn notify(int *out_result);
    
    void destroyRingAndClearService();
    
    virtual IOReturn externalMethod(
        uint32_t selector, IOExternalMethodArguments *arguments,
        IOExternalMethodDispatch *dispatch,
        OSObject *target, void *reference) override;

    IORWLock* lock;

    /** Mach port created in userspace for notifying the client when data is
     * received in the ring. */
    mach_port_t receive_event_port;
    mach_port_t send_event_port;
    /** Mach port created in userspace for notifying the client when the
     * previously failed send may be retried. */
    mach_msg_header_t receive_notify_msg;
    mach_msg_header_t send_notify_msg;
    
    IOBufferMemoryDescriptor *ring_mem;
    
    org_uxen_driver_v4v_service *v4v_service;
    uxen_v4v_ring *ring;
    
    // set with write lock, clear with read lock held
    bool last_send_failed;
    // update with write lock held
    uint32_t last_send_size;
    v4v_addr_t last_send_dest;
    
    domid_t destination_domain;
};

#endif /* _V4V_USER_RING_H_ */
