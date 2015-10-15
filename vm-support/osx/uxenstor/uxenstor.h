/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef UxenV4VDevice_UxenGuestV4VDevice_h
#define UxenV4VDevice_UxenGuestV4VDevice_h

#include <IOKit/acpi/IOACPIPlatformDevice.h>
#include <IOKit/scsi/IOSCSIProtocolServices.h>
#include "../../../osx/uxenv4vservice/v4v_service.h"
#include <libkern/tree.h>

#define uxen_v4v_storage_controller org_uxen_driver_v4v_storage_controller
#define uxen_v4v_storage_device org_uxen_driver_v4v_storage_device
#define uxen_ahci_blocker org_uxen_driver_ahci_blocker
#define kUxenAHCIBlockerClassName "org_uxen_driver_ahci_blocker"

/** Acts as client to the uxenstor ACPI nub, instantiating uxen_v4v_storage_device
 * instances for each disk present in the ACPI resource's bit field. This only
 * happens once the uxen_ahci_blocker has been located, to avoid multiple mounts
 * of the same underlying drive, and once the V4V driver stack is available. */
class uxen_v4v_storage_controller : public IOService
{
    OSDeclareDefaultStructors(uxen_v4v_storage_controller);
    typedef IOService super;
protected:
    
    IOLock *dependency_lock;
    
    IOACPIPlatformDevice *acpi_device;
    bool ahci_blocker_discovered;
    IONotifier *ahci_blocker_notifier;
    uxen_v4v_service *v4v_service;
    IONotifier *v4v_service_notifier;

    static bool ahciBlockerMatchingNotificationHandler(
        void *target, void *refCon, IOService *newService, IONotifier *notifier);
    static bool v4vServiceMatchingNotificationHandler(
        void *target, void *refCon, IOService *newService, IONotifier *notifier);
    bool startStorageController();
public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual void free() override;
};

/** Matches any AHCI controller PCI device with a higher probe score than
 * Apple's own driver, but will only claim the device if the uxenstor ACPI nub
 * is found within 10 seconds. */
class uxen_ahci_blocker : public IOService
{
    OSDeclareDefaultStructors(uxen_ahci_blocker);
protected:
public:
    virtual IOService *probe(IOService *provider, SInt32 *score) override;
    virtual bool start(IOService *provider) override;    
};

struct SCSITaskIdentifier_rb_entry
{
    RB_ENTRY(SCSITaskIdentifier_rb_entry) entry;
    SCSITaskIdentifier task;
    /* The following fields are protected by the device's task lock. If
     * received_response is true before submitted becomes true, then the
     * submitting thread needs to call the completion fn. (and the
     * response-receiving thread must not) */
    bool submitted;
    bool received_response;
    SCSITaskStatus response_status;
};
RB_HEAD(SCSITaskIdentifier_rb_head, SCSITaskIdentifier_rb_entry);

/** Driver for a single uxenstor storage device. Instances are created by
 * and clients of uxen_v4v_storage_controller, and are also clients of
 * uxen_v4v_service (in order to receive messages and to make V4V hypercalls).
 * Marshals SCSI requests and responses via V4V ring. */
class uxen_v4v_storage_device : public IOSCSIProtocolServices
{
    OSDeclareDefaultStructors(uxen_v4v_storage_device);
protected:
    typedef IOSCSIProtocolServices super;
    using IOSCSIProtocolServices::init;
    unsigned deviceIndex;
    uxen_v4v_service *v4v_service;
    uxen_v4v_ring *v4v_ring;
    IOCommandGate *command_gate;
    
    void* bounce_buffer;
    IOLock* bounce_buffer_lock;
    
    /* Maximum number of payload bytes in a write. Depends on the destination
     * V4V ring size. */
    uint32_t max_write_size;
    
    IOSimpleLock *live_tasks_lock;
    SCSITaskIdentifier_rb_head live_tasks;
    
    bool shortCircuitRequestResponse(
        const SCSICommandDescriptorBlock* cdbData, uint32_t cdb_size, SCSITaskIdentifier request);
    
public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual bool SendSCSICommand(
        SCSITaskIdentifier request,
        SCSIServiceResponse *serviceResponse,
        SCSITaskStatus *taskStatus) override;
    virtual SCSIServiceResponse	AbortSCSICommand(
        SCSITaskIdentifier request) override;
    virtual bool IsProtocolServiceSupported(
        SCSIProtocolFeature feature, void *serviceValue) override;
    virtual bool HandleProtocolServiceFeature(
        SCSIProtocolFeature feature, void *serviceValue) override;
    virtual bool initWithDeviceIndex(
        unsigned device_idx, uxen_v4v_service *service,
        OSDictionary *propTable = 0);
    virtual IOReturn message(
        UInt32 type, IOService *provider, void *argument = 0) override;
    void processCompletedRequests();
    static IOReturn gatedProcessCompletedRequests(
        OSObject *owner, void *arg0, void *arg1, void *arg2, void *arg3);
    virtual void free(void) override;
    virtual IOWorkLoop *getWorkLoop() const override;
};

#endif
