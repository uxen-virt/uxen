/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENV4VNET_H_
#define _UXENV4VNET_H_

#include <IOKit/network/IOEthernetController.h>
#include <v4v_service.h>
#define uxen_net org_uxen_driver_uxen_net

class IOACPIPlatformDevice;
class uxen_net : public IOEthernetController
{
    OSDeclareDefaultStructors(uxen_net);
    
protected:
    typedef IOEthernetController super;

    unsigned mtu;
    IOEthernetAddress mac_address;
    uxen_v4v_service* v4v_service;
    IONetworkInterface* interface;
    uxen_v4v_ring* v4v_ring;
    IOKernelDebugger* debugger;
	
	// Workloop (thread) used for sending. The inherited V4V workloop is used for receiving.
    IOWorkLoop* send_workloop;
    
    bool queryDeviceProperties(IOACPIPlatformDevice *acpi_device);
    void processReceivedPackets();
    
public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual void free() override;
    virtual IOReturn getHardwareAddress(IOEthernetAddress *addrP) override;
    virtual IOOutputQueue *createOutputQueue() override;
    virtual UInt32 outputPacket(mbuf_t, void *param) override;
    virtual IOReturn message(UInt32 type, IOService *provider, void *argument = 0) override;
    virtual IOReturn enable(IONetworkInterface *interface) override;
    virtual IOReturn getMaxPacketSize(UInt32 *maxSize) const override;
    virtual IOReturn enable(IOKernelDebugger * debugger) override;
    virtual void receivePacket(void * pkt, UInt32 * pktSize, UInt32 timeout) override;
    virtual void sendPacket(void * pkt, UInt32 pktSize) override;
    
    virtual IONetworkInterface *createInterface() override;
    virtual IOReturn setMaxPacketSize(UInt32 maxSize) override;
    virtual bool configureInterface(IONetworkInterface *interface) override;
};

#endif
