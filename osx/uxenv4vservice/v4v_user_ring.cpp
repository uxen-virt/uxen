/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "v4v_user_ring.h"
#include "v4v_service_shared.h"
#include "v4v_service.h"
#include "v4v_ops.h"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <sys/errno.h>

OSDefineMetaClassAndStructors(uxen_v4v_user_ring, IOUserClient)

bool
uxen_v4v_user_ring::initWithTask(
    task_t owningTask, void *securityToken,
    UInt32 type, OSDictionary *properties)
{

    this->receive_event_port = MACH_PORT_NULL;
    this->send_event_port = MACH_PORT_NULL;
    bool ok = this->IOUserClient::initWithTask(
        owningTask, securityToken, type, properties);
    if (!ok)
        return false;
/* Do we want to limit V4V to root processes?
    IOReturn priv_ret = this->clientHasPrivilege(
        securityToken, kIOClientPrivilegeAdministrator);
    if (priv_ret != kIOReturnSuccess)
        return false;
*/
    if (type != 0)
        return false;
    
    this->lock = IORWLockAlloc();
    
    return true;
}

bool
uxen_v4v_user_ring::start(IOService *provider)
{
    uxen_v4v_service *v4v;
    
    v4v = OSDynamicCast(uxen_v4v_service, provider);
    if (v4v == nullptr)
        return false;
    if (!this->IOUserClient::start(provider))
        return false;
    IORWLockWrite(this->lock);
    this->v4v_service = v4v;
    IORWLockUnlock(this->lock);
    return true;
}

IOReturn
uxen_v4v_user_ring::registerNotificationPort(
    mach_port_t port, uint32_t type, uint32_t refCon)
{
    mach_port_t prev_port;

    if (type != kUxenV4VPort_ReceiveEvent && type != kUxenV4VPort_SendEvent)
        return kIOReturnBadArgument;
    
    mach_port_t &port_field =
        ((type == kUxenV4VPort_ReceiveEvent)
        ? this->receive_event_port : this->send_event_port);
    mach_msg_header_t &notify_msg =
        ((type == kUxenV4VPort_ReceiveEvent)
        ? this->receive_notify_msg : this->send_notify_msg);

    IORWLockWrite(this->lock);

    prev_port = port_field;
    port_field = port;
    memset(&notify_msg, 0, sizeof(notify_msg));
    notify_msg.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    notify_msg.msgh_size = sizeof(mach_msg_header_t);
    notify_msg.msgh_remote_port = port;
    
    IORWLockUnlock(this->lock);


    if (prev_port != MACH_PORT_NULL) {
        this->releaseNotificationPort(prev_port);
    }
    
    return kIOReturnSuccess;
}

IOReturn
uxen_v4v_user_ring::clientMemoryForType(
    uint32_t type, IOOptionBits *options, IOMemoryDescriptor **memory)
{
    IOReturn result;

    *options = 0;
    *memory = nullptr;
    
    if (type != 0)
        return kIOReturnBadArgument;

    IORWLockRead(this->lock);
    if (this->ring_mem == nullptr || this->ring == nullptr) {
        result = kIOReturnNotReady;
    } else {
        *memory = this->ring_mem;
        this->ring_mem->retain(); // caller releases
        result = kIOReturnSuccess;
    }
    IORWLockUnlock(this->lock);
    
    return result;
}

namespace
{
    template <class UCC> struct userclient_external_methods
    {
        template <IOReturn (UCC::*method)(void*, IOExternalMethodArguments*)>
            static IOReturn
            external_method(
                OSObject* target, void* reference,
                IOExternalMethodArguments* arguments)
        {
            UCC* uc;
            
            uc = OSDynamicCast(UCC, target);
            if (!uc) {
                return kIOReturnBadArgument;
            }
            return (uc->*method)(reference, arguments);
        }
    };
}

typedef userclient_external_methods<uxen_v4v_user_ring> um;
static const IOExternalMethodDispatch USER_METHODS[] =
{
    //kUxenV4V_BindRing
    {
        &um::external_method<&uxen_v4v_user_ring::createRing>,
        3, // input count: length (bytes), partner domain, source port number
        sizeof(v4v_idtoken_t), // input struct size
        2, // output count: result, partner domain
        0  // output struct size
        /* return value: IOReturn OR errno (errno is xnu-ified pass-through from
         * hypercall) */
    },
    //kUxenV4V_SendTo
    {
        &um::external_method<&uxen_v4v_user_ring::sendTo>,
        3, // input count: destination domain, destination port, flags
        kIOUCVariableStructureSize, // input struct size - variable message size
        1, // output count: result
        0  // output struct size
    },
    //kUxenV4V_Notify
    {
        &um::external_method<&uxen_v4v_user_ring::notify>,
        0, // input count
        0, // input struct size
        1, // output count: result
        0  // output struct size
    },
};

IOReturn
uxen_v4v_user_ring::externalMethod(
    uint32_t selector, IOExternalMethodArguments* arguments,
    IOExternalMethodDispatch* dispatch, OSObject* target, void* reference)
{
    IOExternalMethodDispatch method;
    
    static_assert(kUxenV4V_BindRing == 0, "");
    static_assert(
        sizeof(USER_METHODS)/sizeof(USER_METHODS[0]) ==
        kUxenV4V_UserMethodCount,
        "USER_METHODS length must match kUxenV4V_UserMethodCount");
    
    if (selector >= kUxenV4V_UserMethodCount)
        return kIOReturnBadArgument;
    
    method = USER_METHODS[selector];
    dispatch = &method;
    target = this;
    
    return this->IOUserClient::externalMethod(
        selector, arguments, dispatch, target, reference);
}


IOReturn
uxen_v4v_user_ring::createRing(
    void *reference, IOExternalMethodArguments *arguments)
{
    uint32_t length = static_cast<uint32_t>(arguments->scalarInput[0]);
    uint16_t partner_domain = static_cast<uint16_t>(arguments->scalarInput[1]);
    uint32_t local_port = static_cast<uint32_t>(arguments->scalarInput[2]);
    v4v_idtoken_t partner_idtoken;

    if (arguments->scalarInput[0] > UINT32_MAX
        || arguments->scalarInput[1] > UINT16_MAX
        || arguments->scalarInput[2] > UINT32_MAX
        || (arguments->structureInputDescriptor ?
            arguments->structureInputDescriptor->getLength() :
            arguments->structureInputSize) != sizeof(v4v_idtoken_t)) {
        IOLog(
            "uxen_v4v_user_ring::createRing: bad argument - length = %llu, "
            "partner_domain = %llu, local_port = %llu, "
            "partner_idtoken len = %u\n",
            arguments->scalarInput[0], arguments->scalarInput[1],
            arguments->scalarInput[2],
            arguments->structureInputDescriptor ?
            (int)arguments->structureInputDescriptor->getLength() :
            arguments->structureInputSize);
        return kIOReturnBadArgument;
    }
    
    if (!arguments->structureInputDescriptor)
        memcpy(&partner_idtoken, arguments->structureInput,
               sizeof(v4v_idtoken_t));
    else {
        arguments->structureInputDescriptor->prepare(kIODirectionOut);
        arguments->structureInputDescriptor->readBytes(
            0, &partner_idtoken, sizeof(v4v_idtoken_t));
        arguments->structureInputDescriptor->complete(kIODirectionOut);
    }
    
    return this->createRing(
        length, partner_domain, local_port, &partner_idtoken,
        &arguments->scalarOutput[0], &arguments->scalarOutput[1]);
}
IOReturn
uxen_v4v_user_ring::createRing(
    uint32_t length, uint16_t partner_domain, uint32_t local_port,
    v4v_idtoken_t *partner_idtoken,
    uint64_t *out_result, uint64_t *out_partner_domain)
{
    IOReturn ret;
    uxen_v4v_ring *new_ring = nullptr;
    IOBufferMemoryDescriptor *ring_buf = nullptr;
    int result;

    *out_result = EIO;
    *out_partner_domain = partner_domain;
    IORWLockWrite(this->lock);
    if (this->v4v_service == nullptr) {
        ret = kIOReturnNotReady;
    } else if (this->ring != nullptr) {
        ret = kIOReturnInvalid; // ring already created
    } else {
        result = this->v4v_service->allocAndBindSharedRing(
            length, &partner_domain, local_port, partner_idtoken,
            &new_ring, &ring_buf);
        *out_result = result;
        if (result == 0) {
            this->ring = new_ring;
            this->ring_mem = ring_buf;
            this->destination_domain = partner_domain;
            *out_partner_domain = partner_domain;
            ret = kIOReturnSuccess;
        } else {
            ret = result;
        }
    }
    IORWLockUnlock(this->lock);
    return ret;
}

IOReturn
uxen_v4v_user_ring::notify(
    void *reference, IOExternalMethodArguments *arguments)
{
    int result = 0;
    IOReturn ret = this->notify(&result);
    arguments->scalarOutput[0] = static_cast<int64_t>(result);
    return ret;
}

IOReturn
uxen_v4v_user_ring::notify(int *out_result)
{
    IOReturn ret = kIOReturnSuccess;
    IORWLockRead(this->lock);
    if (this->v4v_service == nullptr)
        ret = kIOReturnNotReady;
    else
        *out_result = this->v4v_service->notify();
    IORWLockUnlock(this->lock);
    return ret;
}

static void
prefault_mapping(const uint8_t *input_data, uint32_t input_size)
{
    const uint8_t *end = input_data + input_size;

    asm volatile("cmpb $0x0,%0\n" : : "m" (input_data[0]) : "cc");
    input_data += PAGE_SIZE - ((uintptr_t)input_data & (PAGE_SIZE - 1));
    while (input_data < end) {
        asm volatile("cmpb $0x0,%0\n" : : "m" (input_data[0]) : "cc");
        input_data += PAGE_SIZE;
    }
}

IOReturn
uxen_v4v_user_ring::sendTo(
    void *reference, IOExternalMethodArguments *arguments)
{
    const void* input_data = arguments->structureInput;
    uint32_t input_size = arguments->structureInputSize;
    void* allocd_mem = nullptr;
    IOMemoryMap* map = nullptr;
    IOMemoryDescriptor* prepared_desc = nullptr;
    ssize_t result = 0;
    IOReturn ret;

    if (arguments->structureInputDescriptor != nullptr) {
        if (arguments->structureInputDescriptor->getLength() > UINT32_MAX)
            return kIOReturnOverrun;

        prepared_desc = arguments->structureInputDescriptor;
        prepared_desc->prepare(kIODirectionOut);

        // First try mapping into kernel space.
        map = arguments->structureInputDescriptor->createMappingInTask(
            kernel_task,
            0 /* don't care about mapping address */, kIOMapAnywhere);
        if (map != nullptr) {
            /* wireRange() appears to be the correct way to ensure kernel-mapped
             * memory ranges get prefaulted on OS X 10.10+.
             * prepare() won't do it; kIOMapPrefault fails for kernel_task. */
            ret = map->wireRange(kIODirectionOut, 0, map->getLength());
            if (ret != kIOReturnSuccess) {
                kprintf(
                    "uxen_v4v_user_ring::sendTo: wiring mapping failed: %x\n",
                    ret);
                OSSafeReleaseNULL(map);
            }
        }
        if (map != nullptr) {
            input_data = reinterpret_cast<const void*>(map->getAddress());
            input_size = static_cast<uint32_t>(map->getSize());
            prefault_mapping((const uint8_t *)input_data, input_size);
        } else {
            /* Fallback if mapping fails for some reason: copy to temp bounce
             * buffer. */
            input_size = static_cast<uint32_t>(prepared_desc->getLength());
            allocd_mem = IOMalloc(input_size);
            if (!allocd_mem) {
                ret = kIOReturnNoMemory;
                goto out;
            }
            
            prepared_desc->readBytes(0, allocd_mem, input_size);
            input_data = allocd_mem;
        }
    }
    
    ret = this->sendTo(
        input_data,
        input_size,
        (v4v_addr_t){
            .port =  (uint32_t)arguments->scalarInput[1],
            .domain = (domid_t)arguments->scalarInput[0] },
        static_cast<unsigned>(arguments->scalarInput[2]),
        &result);
    arguments->scalarOutput[0] = static_cast<int64_t>(result);
  out:
    if (map != nullptr) {
        map->wireRange(
            kIODirectionNone, 0, map->getLength()); // direction=none -> unwire
        OSSafeReleaseNULL(map);
    }
    if (prepared_desc != nullptr)
        prepared_desc->complete(kIODirectionOut);
    if (allocd_mem)
        IOFree(allocd_mem, input_size);
    return ret;
}


IOReturn
uxen_v4v_user_ring::sendTo(
    const void *data, unsigned data_len, v4v_addr_t dest, unsigned flags, ssize_t* out_result)
{
    IOReturn ret;
    ssize_t sent;
    errno_t dlo_result;
    
    if ((flags & ~kUxenV4V_SendFlag_IgnoreDLO) != 0)
        return kIOReturnBadArgument;
    
    IORWLockRead(this->lock);
    if (this->v4v_service == nullptr || this->ring == nullptr) {
        ret = kIOReturnNotReady;
    } else {
retry:
        sent = this->v4v_service->sendOnRing(this->ring, dest, data, data_len);
        if (sent == -ECONNREFUSED
            && 0 == (flags & kUxenV4V_SendFlag_IgnoreDLO)) {
            dlo_result = this->v4v_service->createRingInDomain(dest);
            if (dlo_result == 0) {
                sent = this->v4v_service->sendOnRing(this->ring, dest, data, data_len);
            }
        }
            
        *out_result = sent;
        if (sent >= 0) {
            this->last_send_failed = false;
        } else if (sent == -EAGAIN) {
            if (!this->last_send_failed
                || this->last_send_size != data_len
                || this->last_send_dest.domain != dest.domain
                || this->last_send_dest.port != dest.port) {
                lck_rw_t *l = IORWLockGetMachLock(this->lock);
                if (!lck_rw_lock_shared_to_exclusive(l)) {
                    /* Lock has been dropped, this could race with the
                     * interrupt, so we have to retry once we have the write
                     * lock. */
                    IORWLockWrite(this->lock);
                    goto retry;
                }
                this->last_send_failed = true;
                this->last_send_size = data_len;
                this->last_send_dest = dest;
            }
        }
        ret = kIOReturnSuccess;
    }
    IORWLockUnlock(this->lock);
    return ret;
}


IOReturn
uxen_v4v_user_ring::message(
    UInt32 type, IOService *provider, void *argument)
{
    if (type == kUxenV4VServiceRingResetNotification) {
        IORWLockWrite(this->lock);
        if (this->ring != nullptr)
            this->v4v_service->reregisterRing(this->ring);
        IORWLockUnlock(this->lock);
    }
    if (type == kUxenV4VServiceRingNotification
        || type == kUxenV4VServiceRingResetNotification) {
        IORWLockRead(this->lock);
        // V4V service received an interrupt/upcall, ring may need servicing
        if (this->ring != nullptr
            && this->receive_event_port != MACH_PORT_NULL) {
            uint32_t waiting = v4v_ring_bytes_to_read(this->ring->ring);
            if (waiting > 0) {
                mach_msg_return_t result = mach_msg_send_from_kernel_proper(
                    &this->receive_notify_msg,
                    this->receive_notify_msg.msgh_size);
                switch (result) {
                case MACH_MSG_SUCCESS:
                case MACH_SEND_TIMED_OUT:
                case MACH_SEND_NO_BUFFER:
                    break;
                default:
                    IOLog(
                        "uxen_v4v_user_ring::message: failed to send notification "
                        "to receive event port: %d (%x)\n", result, result);
                    break;
                }
            }
        }
        
        if (this->send_event_port != MACH_PORT_NULL && this->last_send_failed) {
            union {
                v4v_ring_data_t hdr;
                char bytes[sizeof(v4v_ring_data_t)+sizeof(v4v_ring_data_ent_t)];
            } data =
                {
                    {.magic = V4V_RING_DATA_MAGIC,
                    .nent = 1,
                    }
                };
            v4v_ring_data_ent_t *ent = &data.hdr.data[0];
            *ent = { this->last_send_dest, 0, this->last_send_size };
            
            if (0 == this->v4v_service->notify(&data.hdr)) {
                if (0 == (ent->flags & V4V_RING_DATA_F_SUFFICIENT)){
                    /* don't trigger a write event as the last failed send
                     * wouldn't succeed anyway. */
                    IORWLockUnlock(this->lock);
                    return kIOReturnSuccess;
                }
            }
            
            mach_msg_return_t result = mach_msg_send_from_kernel_proper(
                &this->send_notify_msg, this->send_notify_msg.msgh_size);
            switch (result) {
            case MACH_MSG_SUCCESS:
            case MACH_SEND_TIMED_OUT:
            case MACH_SEND_NO_BUFFER:
                this->last_send_failed = false;
                break;
            default:
                IOLog(
                    "uxen_v4v_user_ring::message: failed to send notification to "
                    "send event port: %d (%x)\n", result, result);
                break;
            }
        }
        IORWLockUnlock(this->lock);
        
        return kIOReturnSuccess;
    } else {
        return this->IOUserClient::message(type, provider, argument);
    }
}

void
uxen_v4v_user_ring::destroyRingAndClearService()
{
    mach_port_t recv_port;
    mach_port_t send_port;
    uxen_v4v_service* service;
    uxen_v4v_ring* v4v_ring;
    IOBufferMemoryDescriptor* v4v_ring_mem;
    
    IORWLockWrite(this->lock);
    
    recv_port = this->receive_event_port;
    this->receive_event_port = MACH_PORT_NULL;
    send_port = this->send_event_port;
    this->send_event_port = MACH_PORT_NULL;
    
    assert(this->ring == nullptr || this->v4v_service != nullptr);
    service = this->v4v_service;
    v4v_ring = this->ring;
    v4v_ring_mem = this->ring_mem;
    this->ring = nullptr;
    this->ring_mem = nullptr;
    this->v4v_service = nullptr;
    
    IORWLockUnlock(this->lock);
    
    if (recv_port != MACH_PORT_NULL)
        this->releaseNotificationPort(recv_port);
    if (send_port != MACH_PORT_NULL)
        this->releaseNotificationPort(send_port);
    if (v4v_ring != nullptr && service != nullptr)
        service->destroyRing(v4v_ring);
    OSSafeRelease(v4v_ring_mem);
}

IOReturn
uxen_v4v_user_ring::clientClose()
{
    this->destroyRingAndClearService();
    
    if(!this->isInactive())
        this->terminate();
    
    return kIOReturnSuccess;
}

void
uxen_v4v_user_ring::detach(IOService *provider)
{
    this->destroyRingAndClearService();
    this->IOUserClient::detach(provider);
}

void
uxen_v4v_user_ring::free()
{
    assert(this->ring == nullptr || this->v4v_service != nullptr);
    if (this->ring != nullptr && this->v4v_service != nullptr) {
        this->v4v_service->destroyRing(this->ring);
        this->ring = nullptr;
    }
    OSSafeReleaseNULL(this->ring_mem);
    
    if (this->lock != nullptr) {
        IORWLockFree(this->lock);
        this->lock = nullptr;
    }

    this->IOUserClient::free();
}

