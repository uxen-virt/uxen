/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "uxennet.h"
#include <IOKit/acpi/IOACPIPlatformDevice.h>
#include <IOKit/IOLib.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <v4v_service_shared.h>
#include <v4v_ops.h>
#include <sys/errno.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <net/ethernet.h>
#include "../uxenplatform/uXenPlatformDevice.h"

OSDefineMetaClassAndStructors(uxen_net, IOEthernetController);

static const unsigned UXENNET_RING_SIZE = 131072;
static const uint16_t UXENNET_DEST_DOMAIN = 0;
static const uint32_t UXENNET_DEST_PORT = 0xC0000;

static unsigned acpi_get_number_property(
    IOACPIPlatformDevice* acpiDevice, const char* propertyName,
    unsigned default_val);
static OSData* acpi_get_data_property(
    IOACPIPlatformDevice* acpi_device, const char* property_name);

#define uxen_net_interface org_uxen_driver_uxen_net_interface

class uxen_net_interface : public IOEthernetInterface
{
    OSDeclareDefaultStructors(uxen_net_interface);
    friend class uxen_net; // grant access to setMaxTransferUnit
/*
protected:
    virtual SInt32 performCommand(IONetworkController * controller,
                                  unsigned long         cmd,
                                  void *                arg0,
                                  void *                arg1) override;
*/
};
OSDefineMetaClassAndStructors(uxen_net_interface, IOEthernetInterface);

/*
SInt32 uxen_net_interface::performCommand(IONetworkController * controller,
                                  unsigned long         cmd,
 void *                arg0,
 void *                arg1)
{
    SInt32 result = IOEthernetInterface::performCommand(controller, cmd, arg0, arg1);
    if (result != 0)
        IOLog("uxen_net_interface::performCommand result = %d\n controller = %p\n cmd = %lx\n arg0 = %p\n arg1 = %p\n\n", result, &controller, cmd, &arg0, &arg1);
    return result;
}
*/

IONetworkInterface *
uxen_net::createInterface()
{
    uxen_net_interface* netif;
    
    netif = new uxen_net_interface();
    if (netif != nullptr && !netif->init(this)) {
        netif->release();
        netif = nullptr;
    }
    return netif;
}

bool
uxen_net::configureInterface(IONetworkInterface *interface)
{
    bool ok;
    
    ok = this->super::configureInterface(interface);
    if (ok && OSDynamicCast(uxen_net_interface, interface)) {
        // default to the MTU reported by the uxennet node (minus overhead)
        static_cast<uxen_net_interface*>(interface)->setMaxTransferUnit(
            this->mtu - kIOEthernetCRCSize - sizeof(struct ether_header));
    }
    return ok;
}

bool
uxen_net::queryDeviceProperties(IOACPIPlatformDevice *acpi_device)
{
    this->mtu = acpi_get_number_property(
        acpi_device, "VMTU", kIOEthernetMaxPacketSize);
	
    OSData* mac_address_data = acpi_get_data_property(acpi_device, "VMAC");
    if (mac_address_data == nullptr) {
        kprintf(
            "uxen_net::queryDeviceProperties "
            "Failed to obtain MAC address for device\n");
        return false;
    }
    if(mac_address_data->getLength() < 6) {
        kprintf("uxen_net::queryDeviceProperties: VMAC length too short\n");
        OSSafeReleaseNULL(mac_address_data);
        return false;
    }
    memcpy(this->mac_address.bytes, mac_address_data->getBytesNoCopy(0, 6), 6);
    OSSafeReleaseNULL(mac_address_data);

    return true;
}

bool uxen_net::start(IOService *provider)
{
    uXenPlatformDevice *xenbus_device;
    OSDictionary *medium_dict;
    IONetworkMedium *medium;
    IOOutputQueue *queue;
    OSDictionary *matching_dict;
    IOService *matching_service;
    IOWorkLoop *wl;
    uxen_v4v_ring *new_ring;
    errno_t err;
    uxen_v4v_service *service;
    IOACPIPlatformDevice *acpi_device;
    OSObject *mtu_prop;
    OSNumber *mtu_num;
    OSObject *mac_prop;
    OSData *mac_data;

    acpi_device = OSDynamicCast(IOACPIPlatformDevice, provider);
    xenbus_device = OSDynamicCast(uXenPlatformDevice, provider);
    if(acpi_device == nullptr) {
        // Determine device parameters (MTU & MAC)
        if (!this->queryDeviceProperties(acpi_device))
            return false;
    } else if (xenbus_device != nullptr) {
        // extract MTU
        mtu_prop =
            xenbus_device->copyProperty(kUXenPlatformXenBusPropertyMTUKey);
        mtu_num = OSDynamicCast(OSNumber, mtu_prop);
        if (mtu_num != nullptr)
            this->mtu = mtu_num->unsigned16BitValue();
        else
            this->mtu = kIOEthernetMaxPacketSize;
        OSSafeReleaseNULL(mtu_prop);
        // extract MAC
        mac_prop =
            xenbus_device->copyProperty(kUXenPlatformXenBusPropertyMACAddrKey);
        mac_data = OSDynamicCast(OSData, mac_prop);
        if (mac_data == nullptr || mac_data->getLength() < 6) {
            OSSafeReleaseNULL(mac_prop);
            IOLog(
                "uxen_net::start Failed to get MAC address from XenBus node\n");
            return false;
        }
        memcpy(this->mac_address.bytes, mac_data->getBytesNoCopy(0, 6), 6);
        OSSafeReleaseNULL(mac_prop);
    } else {
        return false;
    }
    IOLog("uxen_net device: MAC %02x:%02x:%02x:%02x:%02x:%02x, MTU %u\n",
        this->mac_address.bytes[0], this->mac_address.bytes[1],
        this->mac_address.bytes[2], this->mac_address.bytes[3],
        this->mac_address.bytes[4], this->mac_address.bytes[5],
        this->mtu);
    
    
    medium_dict = OSDictionary::withCapacity(1);
    if (medium_dict == nullptr)
        return false;
    medium =
        IONetworkMedium::medium(
            kIOMediumEthernetAuto, UINT64_C(10000000000) /* 10gbit */);
    IONetworkMedium::addMedium(medium_dict, medium);
    OSSafeRelease(medium);

    this->send_workloop = IOWorkLoop::workLoop();
    
    /* this calls getHardwareAddress()/getMaxPacketSize(), so we can't call it
     * any earlier */
    if (!this->super::start(provider)) {
        OSSafeReleaseNULL(this->send_workloop);
        return false;
    }

    if (!this->publishMediumDictionary(medium_dict)) {
        IOLog("uxen_net::start: note - failed to publish medium dictionary\n");
    }
    medium_dict->release();

    queue = this->getOutputQueue();
    if (queue == nullptr) {
        IOLog("uxen_net::start - aborting, failed to get output queue.\n");
        this->super::stop(provider);
        OSSafeReleaseNULL(this->send_workloop);
        return false;
    }
    
    // Establish the V4V communication channel
    matching_dict = this->serviceMatching(kUxenV4VServiceClassName);
    /* This waits synchronously for up to 10 seconds. Installing an async
     * notification may be cleaner but this seems to work fine and uses less
     * code. */
    matching_service =
        this->waitForMatchingService(matching_dict, NSEC_PER_SEC * 10);
    service = OSDynamicCast(uxen_v4v_service, matching_service);
    if (service == nullptr) {
        kprintf("uxenv4vnet::start - v4v service not found\n");
        OSSafeRelease(matching_service); // balances waitForMatchingService()
        this->super::stop(provider);
        wl = this->send_workloop;
        this->send_workloop = nullptr;
        OSSafeReleaseNULL(wl);
        return false;
    }
    this->attach(service);
    this->v4v_service = service;
    service->release(); // balances waitForMatchingService()

    new_ring = nullptr;
    err = service->allocAndBindRing(
        UXENNET_RING_SIZE, UXENNET_DEST_DOMAIN, UXENNET_DEST_PORT, &new_ring);
    if (err != 0) {
        kprintf("uxen_net::start Failed to create v4v ring, error %d\n", err);
        this->detach(service);
        this->super::stop(provider);
        OSSafeReleaseNULL(this->send_workloop);
        return false;
    }
    this->v4v_ring = new_ring;

    // Bring up the network interface startup
    if(!this->attachInterface(&this->interface, true /*register with IOKit*/)) {
        this->detach(service);
        kprintf("uxen_net::start Could not attach interface \n");
        this->super::stop(provider);
        OSSafeReleaseNULL(this->send_workloop);
        return false;
    }
    
    queue->start();
    this->attachDebuggerClient(&this->debugger);
    return true;
}

void
uxen_net::stop(IOService *provider) {
    if (this->v4v_ring != nullptr) {
        this->v4v_service->destroyRing(this->v4v_ring);
        this->v4v_ring = nullptr;
    }
    this->super::stop(provider);
}

void
uxen_net::free() {

    OSSafeReleaseNULL(this->interface);
    this->super::free();
    /* The output queue uses the send workloop until it's destroyed
     * in IONetworkController::free, so delete it last */
    OSSafeReleaseNULL(this->send_workloop);
}


static OSData*
acpi_get_data_property(IOACPIPlatformDevice* acpi_device, const char* property_name)
{
    OSObject* property = nullptr;
    IOReturn ret = acpi_device->evaluateObject(property_name, &property, 0, 0, 0);
    if (ret != kIOReturnSuccess || property == nullptr) {
        return nullptr;
    }
      
    OSData* property_data = OSDynamicCast(OSData, property);
    if (property_data == nullptr) {
        OSSafeReleaseNULL(property);
        return nullptr;
    }
      
    return property_data;
}


static unsigned
acpi_get_number_property(
    IOACPIPlatformDevice* acpi_device, const char* property_name, unsigned default_val)
{
    OSObject* property = nullptr;
    IOReturn ret = acpi_device->evaluateObject(property_name, &property, 0, 0, 0);
    if (ret != kIOReturnSuccess || property == nullptr) {
        return default_val;
    }
    
    OSNumber* number = OSDynamicCast(OSNumber, property);
    if (number == nullptr) {
        OSSafeReleaseNULL(property);
        return default_val;
    }
    
    unsigned val = number->unsigned32BitValue();
    OSSafeRelease(property);
    return val;
}

IOReturn
uxen_net::getHardwareAddress(IOEthernetAddress * addrP)
{

    *addrP = this->mac_address;
    return kIOReturnSuccess;
}

IOOutputQueue *
uxen_net::createOutputQueue()
{
    UInt32 capacity;
    IOGatedOutputQueue* queue;
    
    capacity = UXENNET_RING_SIZE / min(this->mtu, kIOEthernetMaxPacketSize);
    queue = IOGatedOutputQueue::withTarget(this, this->send_workloop, capacity);
    if (queue == nullptr) {
        IOLog(
            "uxen_net::createOutputQueue: failed to create output queue "
            "with capacity %u (MTU %u, ring size %u) on workloop %p.\n",
            capacity, this->mtu, UXENNET_RING_SIZE,
            static_cast<void*>(this->send_workloop));
    }
    return queue;
}

UInt32
uxen_net::outputPacket(mbuf_t packet, void *param)
{
    /* must return kIOReturnOutputSuccess, kIOReturnOutputStall, or
     * kIOReturnOutputDropped */
    ssize_t bytes_sent;
    unsigned i, num_bufs;
    mbuf_t cur;
    
    if (packet == nullptr) {
        return kIOReturnOutputDropped;
    }

    // turn mbuf chain into v4v_iov_t array
    for (cur = packet, num_bufs = 0; cur != nullptr; cur = mbuf_next(cur)) {
        num_bufs++;
    }
    
    v4v_iov_t net_packet[num_bufs];
    for (cur = packet, i = 0; cur != nullptr; cur = mbuf_next(cur)) {
        net_packet[i].iov_base = reinterpret_cast<uintptr_t>(mbuf_data(cur));
        net_packet[i].iov_len = mbuf_len(cur);
        i++;
    }
    
    bytes_sent = this->v4v_service->sendvOnRing(
        this->v4v_ring,
        (v4v_addr_t){ .domain = UXENNET_DEST_DOMAIN, .port = UXENNET_DEST_PORT},
        net_packet, num_bufs);
    
    if (bytes_sent > 0) {
        this->freePacket(packet);
        return kIOReturnOutputSuccess;
    } else if (bytes_sent == -EAGAIN) {
        // stalled queue, try again later
        return kIOReturnOutputStall;
    } else {
        this->freePacket(packet);
        IOLog("failed to send v4v message %ld\n", bytes_sent);
        return kIOReturnOutputDropped;
    }
}

IOReturn
uxen_net::message(UInt32 type, IOService *provider, void *argument )
{
    if ((type == kUxenV4VServiceRingNotification
         || type == kUxenV4VServiceRingResetNotification)
        && provider == this->v4v_service) {
        if (type == kUxenV4VServiceRingResetNotification) {
            kprintf(
                "uxen_net::message: "
                "reregistering ring due to reset notification\n");
            this->v4v_service->reregisterRing(this->v4v_ring);
        }
        this->getOutputQueue()->service();
        this->processReceivedPackets();
        return kIOReturnSuccess;
    } else {
        return this->super::message(type, provider, argument);
    }
}

IOReturn
uxen_net::enable(IONetworkInterface *interface)
{

    this->processReceivedPackets();
    return kIOReturnSuccess;
}


void
uxen_net::processReceivedPackets()
{
    // go through the packets on the ring, pass them to the network stack
    bool a_message_received = false;
    ssize_t receive_message;
    mbuf_t packet;
    size_t pos_in_mbuf;
    mbuf_t cur;
    uint32_t msg_size;
    
    if (this->v4v_ring == nullptr) {
        kprintf(
            "uxen_net::processReceivedPackets: warning: V4V ring is NULL\n");
        return;
    }
    
    while (true) {
        receive_message = this->v4v_service->receiveFromRing(
            this->v4v_ring, nullptr, 0, false);
        if (receive_message >= 0) {
            // cast is safe, max message is <= UINT32_MAX
            msg_size = static_cast<uint32_t>(receive_message);
            packet = this->allocatePacket(msg_size);
            if (packet != nullptr) {
                pos_in_mbuf = 0;
                a_message_received = true;
                for (cur = packet; cur != NULL; cur = mbuf_next(cur)) {
                    v4v_copy_out_offset(
                        this->v4v_ring->ring,
                        nullptr, nullptr,
                        mbuf_data(cur),
                        // NOT number of bytes to copy, but end of submessage:
                        pos_in_mbuf + mbuf_len(cur),
                        false, // do not consume
                        pos_in_mbuf); // offset
                    pos_in_mbuf += mbuf_len(cur);
                }
                this->interface->inputPacket(
                    packet, msg_size,
                    IONetworkInterface::kInputOptionQueuePacket);
            }
            // consume from queue if done, or drop packet if alloc failed.
            this->v4v_service->receiveFromRing(
                this->v4v_ring, nullptr, 0, true);
        } else {
            break;
        }
    }
        
    if (a_message_received) {
        this->interface->flushInputQueue();
        this->v4v_service->notify();
    }
}

IOReturn
uxen_net::getMaxPacketSize(UInt32 *maxSize) const
{

    *maxSize = this->mtu;
    return kIOReturnSuccess;
}

IOReturn
uxen_net::setMaxPacketSize(UInt32 maxSize)
{

    if (maxSize <= this->mtu)
        return kIOReturnSuccess;
    else
        return kIOReturnBadArgument;
}



IOReturn
uxen_net::enable(IOKernelDebugger *debugger)
{

    return kIOReturnSuccess;
}


void
uxen_net::receivePacket(void *pkt, UInt32 *pktSize, UInt32 timeout_ms)
{
    uint32_t total_time_waited = 0;
    uint32_t next_wait_ms = 1;
    ssize_t receive_message;
    uint32_t wait_ms;

    *pktSize = 0;
    // Poll for packets, with increasing sleep intervals until timeout is reached
    while (true) {
        receive_message =
            this->v4v_service->receiveFromRing(this->v4v_ring, pkt, 1518, true);
        if (receive_message > 0) {
            // cast is safe, max message is <= UINT32_MAX
            *pktSize = min(static_cast<uint32_t>(receive_message), 1518);
            this->v4v_service->notify();
            return;
        } else if (total_time_waited >= timeout_ms) {
            break;
        } else {
            wait_ms = min(timeout_ms - total_time_waited, next_wait_ms);
            IOSleep(wait_ms);
            total_time_waited += wait_ms;
            ++next_wait_ms;
        }
    }
}

void
uxen_net::sendPacket(void *pkt, UInt32 pktSize)
{

    this->v4v_service->sendOnRing(
        this->v4v_ring,
        v4v_addr_t({ .domain = UXENNET_DEST_DOMAIN, .port = UXENNET_DEST_PORT}),
        pkt, pktSize);
}

