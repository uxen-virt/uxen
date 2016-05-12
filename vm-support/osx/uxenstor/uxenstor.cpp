/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "uxenstor.h"
#include <IOKit/acpi/IOACPIPlatformDevice.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/scsi/IOSCSIProtocolServices.h>
#include <sys/errno.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/scsi/SCSICommandOperationCodes.h>
#include "../../../osx/uxenv4vservice/v4v_service_shared.h"
#include "../../../osx/uxenv4vservice/v4v_ops.h"

OSDefineMetaClassAndStructors(uxen_v4v_storage_controller, IOService);
OSDefineMetaClassAndStructors(uxen_ahci_blocker, IOService);
OSDefineMetaClassAndStructors(uxen_v4v_storage_device, IOSCSIProtocolServices);

static const unsigned UXENSTOR_RING_SIZE = 1048576;
static const uint16_t UXENSTOR_DEST_DOMAIN = 0;
static const uint32_t UXENSTOR_DEST_PORT = 0xD0000;

typedef struct v4v_disk_transfer {
    uint64_t seq;
    uint32_t cdb_size;
    uint32_t write_size;
    uint32_t pagelist_size;
    uint32_t read_size;
    uint32_t sense_size;
    uint32_t status;
} v4v_disk_transfer_t;
static const uint64_t UXENSTOR_MAX_READ_IO_SIZE =
    UXENSTOR_RING_SIZE // receive ring size
    - sizeof(v4v_disk_transfer_t) // uxenstor message header
    - sizeof(struct v4v_ring_message_header) // V4V message overhead
    - V4V_ROUNDUP(1); // ring can't be completely full

static int
SCSITaskIdentifier_rb_entry_compare(struct SCSITaskIdentifier_rb_entry* a,
    struct SCSITaskIdentifier_rb_entry* b)
{
    uintptr_t val_a;
    uintptr_t val_b;
    
	val_a = reinterpret_cast<uintptr_t>(static_cast<void*>(a->task));
	val_b = reinterpret_cast<uintptr_t>(static_cast<void*>(b->task));
    if (val_a == val_b)
        return 0;
    else if (val_a < val_b)
        return 1;
    else
        return -1;
}

RB_PROTOTYPE_SC(static, SCSITaskIdentifier_rb_head, SCSITaskIdentifier_rb_entry,
    entry, SCSITaskIdentifier_rb_entry_compare);
RB_GENERATE(SCSITaskIdentifier_rb_head, SCSITaskIdentifier_rb_entry, entry,
    SCSITaskIdentifier_rb_entry_compare)


#pragma mark V4V Storage Controller

bool
uxen_v4v_storage_controller::start(IOService *provider)
{
    OSDictionary *blocker_matching_dict;
    OSDictionary *v4v_matching_dict;
    IONotifier *n;
    bool ok;
    
    this->acpi_device = OSDynamicCast(IOACPIPlatformDevice, provider);
    if (this->acpi_device == nullptr) {
        kprintf(
            "uxen_v4v_storage_controller::start "
            "aborting - provider must be IOACPIPlatformDevice\n");
        return false;
    }
    if (this->acpi_device->getDeviceMemoryCount() == 0) {
        kprintf(
            "uxen_v4v_storage_controller::start aborting - "
            "provider must have at least one range of device memory\n");
        return false;
    }
    
    this->acpi_device->retain();
    
    this->setName("uxen_v4v_storage_controller");

    ok = this->super::start(provider);
    if (!ok)
        return false;
    
    this->dependency_lock = IOLockAlloc();
    
    /* only allow driver to load if we've blocked AHCI, so actual startup 
     * happens in startStorageController via
     * ahciBlockerMatchingNotificationHandler */
    blocker_matching_dict = this->serviceMatching(kUxenAHCIBlockerClassName);
    n = IOService::addMatchingNotification(
        gIOPublishNotification,
        blocker_matching_dict,
        ahciBlockerMatchingNotificationHandler,
        this);
    OSSafeReleaseNULL(blocker_matching_dict);
    
    IOLockLock(this->dependency_lock);
    if (!this->ahci_blocker_discovered)
        this->ahci_blocker_notifier = n;
    IOLockUnlock(this->dependency_lock);
    
    if (n != nullptr) {
        /* We also need to wait until the V4V driver stack has started up. */
        v4v_matching_dict =
            this->serviceMatching(kUxenV4VServiceClassName);
        n = IOService::addMatchingNotification(
            gIOPublishNotification,
            v4v_matching_dict,
            v4vServiceMatchingNotificationHandler,
            this);
        OSSafeRelease(v4v_matching_dict);
    }
    return n != nullptr;
}

void
uxen_v4v_storage_controller::stop(IOService *provider)
{

    if (this->dependency_lock != nullptr) {
        IOLockLock(this->dependency_lock);
        
        if (this->ahci_blocker_notifier != nullptr) {
            this->ahci_blocker_notifier->remove();
            this->ahci_blocker_notifier = nullptr;
        }
        
        if (this->v4v_service_notifier != nullptr) {
            this->v4v_service_notifier->remove();
            this->v4v_service_notifier = nullptr;
        }

        OSSafeReleaseNULL(this->v4v_service);
        OSSafeReleaseNULL(this->acpi_device);
        
        IOLockUnlock(this->dependency_lock);
    }
    this->super::stop(provider);
}

void
uxen_v4v_storage_controller::free()
{

    if (this->dependency_lock != nullptr) {
        IOLockFree(this->dependency_lock);
        this->dependency_lock = nullptr;
    }
    OSSafeReleaseNULL(this->acpi_device);
    OSSafeReleaseNULL(this->v4v_service);
    
    this->super::free();
}


bool
uxen_v4v_storage_controller::ahciBlockerMatchingNotificationHandler(
    void *target, void *refCon, IOService *newService, IONotifier *notifier)
{
    uxen_v4v_storage_controller* controller;
    
    controller = static_cast<uxen_v4v_storage_controller*>(target);

    IOLockLock(controller->dependency_lock);
    notifier->remove();
    controller->ahci_blocker_discovered = true;
    controller->ahci_blocker_notifier = nullptr;
    bool start = controller->v4v_service != nullptr;
    IOLockUnlock(controller->dependency_lock);
    
    if (start)
        controller->startStorageController();

    return true; // it seems the return value isn't used anywhere?
}

bool
uxen_v4v_storage_controller::v4vServiceMatchingNotificationHandler(
    void *target, void *refCon, IOService *newService, IONotifier *notifier)
{
    uxen_v4v_storage_controller* controller;
    uxen_v4v_service* v4v_service;
    bool start;
    
    controller = static_cast<uxen_v4v_storage_controller*>(target);
    v4v_service = OSDynamicCast(uxen_v4v_service, newService);
    if (v4v_service != nullptr) {
        IOLockLock(controller->dependency_lock);
        notifier->remove();
        controller->v4v_service_notifier = nullptr;
        controller->v4v_service = v4v_service;
        v4v_service->retain();
        start = controller->ahci_blocker_discovered;
        IOLockUnlock(controller->dependency_lock);
        
        if (start)
            controller->startStorageController();
    }
    return true;
}

bool
uxen_v4v_storage_controller::startStorageController()
{
    IOMemoryMap *mem_map;
    IOByteCount length;
    unsigned offset;
    uint8_t stor_dev_set;
    unsigned bit_num, bit_mask;
    uxen_v4v_storage_device *storage_device;
    
    mem_map = this->acpi_device->mapDeviceMemoryWithIndex(0);
    if(mem_map == nullptr) {
        kprintf("uxen_v4v_storage_controller::startStorageController: failed to"
        "map device memory\n");
        return false;
    }
    
    assert(this->v4v_service != nullptr);
    
    length = mem_map->getLength();
    for (offset = 0; offset < length; offset++) {
        stor_dev_set = this->acpi_device->ioRead8(offset, mem_map);
    
        for (bit_num = 0; bit_num < 8; bit_num++) {
            bit_mask = 1u << bit_num;
            if ((bit_mask & stor_dev_set) != 0) {
                storage_device = new uxen_v4v_storage_device();
                storage_device->initWithDeviceIndex(
                    bit_num + offset * 8, this->v4v_service);
                storage_device->attach(this);
                if (!storage_device->start(this)) {
                    storage_device->detach(this);
                    storage_device->release();
                }
            }
        }
    }
    
    OSSafeReleaseNULL(mem_map);

    IOLockLock(this->dependency_lock);
    OSSafeReleaseNULL(this->v4v_service);
    OSSafeReleaseNULL(this->acpi_device);
    IOLockUnlock(this->dependency_lock);
    
    return true;
}

#pragma mark -

#pragma mark AHCI Blocker

IOService *
uxen_ahci_blocker::probe(IOService *provider, SInt32 *score)
{
    OSDictionary *matching_dict;
    OSString *uxenstor_acpi_name;
    IOService *service;

    /* Check if uxenstor is active. If it is, capture the AHCI device otherwise,
     * allow the stock AHCI driver to load. */
    matching_dict = this->serviceMatching("IOACPIPlatformDevice");
    uxenstor_acpi_name = OSString::withCString("UXS0FFF");
    matching_dict->setObject("IONameMatch", uxenstor_acpi_name);
    uxenstor_acpi_name->release();
    //OSIterator* uxenstor_acpi_services = this->getMatchingServices(matching_dict);
    service = this->waitForMatchingService(matching_dict, 10 * NSEC_PER_SEC);
    OSSafeRelease(matching_dict);
    
    if (service != nullptr) {
        service->release();
        return this;
    }

    kprintf("uxen_ahci_blocker::probe - no uxen storage ACPI devices found\n");
    IOLog("uxen_ahci_blocker::probe - no uxen storage ACPI devices found\n");
    return nullptr;
}

bool
uxen_ahci_blocker::start(IOService *provider)
{
    if (!this->IOService::start(provider))
        return false;

    this->setName("uxen_ahci_blocker");

    // allow the V4V storage controller to find the blocker
    this->registerService();
    return true;
}

#pragma mark -

#pragma mark V4V Storage Device

static uint32_t
max_write_payload_size_for_device(uxen_v4v_service *v4v_service,
    uint32_t device_index)
{
    errno_t err;
    uint32_t max_write_size = 0;
    
    /* find out the maximum message size and from it, deduce the maximum write
     * size */
    union {
        v4v_ring_data_t data;
        char bytes[sizeof(v4v_ring_data_t) + sizeof(v4v_ring_data_ent_t)];
    } notify = {
        {
            .magic = V4V_RING_DATA_MAGIC,
            .nent = 1,
        },
    };
    notify.data.data[0] = (v4v_ring_data_ent_t){
        { .domain = UXENSTOR_DEST_DOMAIN, .port = UXENSTOR_DEST_PORT + device_index },
        0, 0, 0 };
    err = v4v_service->notify(&notify.data);
    if (err == 0 && 0 != (notify.data.data[0].flags & V4V_RING_DATA_F_EXISTS)) {
        if (notify.data.data[0].max_message_size > sizeof(v4v_disk_transfer_t)
            + 16) {
            max_write_size = notify.data.data[0].max_message_size -
                sizeof(v4v_disk_transfer_t) - 16 /*CDB+padding*/;
        } else if (notify.data.data[0].max_message_size == 0) {
            printf(
                "uxenstor Warning: Max message size for uxenstor disk %u reported as 0."
                "Probably an outdated uxen version, so assuming 1MiB ring size.\n",
                device_index);
            max_write_size = UXENSTOR_MAX_READ_IO_SIZE - 16 /* CDB+padding */;
        } else {
            printf(
                "uxenstor Error: Max message size for uxenstor disk %u reported as %u."
                "This is too small to work properly!\n",
                device_index, notify.data.data[0].max_message_size);
        }
    } else if (err == 0) {
        kprintf(
            "Warning: Failed to get max message size for uxenstor disk %u "
            "because the host-side ring does not exist.\n", device_index);
    } else {
        kprintf(
            "Warning: Failed to get max message size for uxenstor disk %u "
            "- return value %d.\n", device_index, err);
    }
    return max_write_size;
}

bool
uxen_v4v_storage_device::start(IOService *provider)
{
    uxen_v4v_ring *new_ring;
    OSDictionary *device_characteristics;
    OSNumber *max_read_size_num;
    OSNumber *max_write_size_num;
    OSDictionary *proto_characteristics;
    OSString *v4v;
    OSString *internal;
    
    this->attach(this->v4v_service);
    
    //create the ring
    new_ring = nullptr;
    int err = this->v4v_service->allocAndBindRing(
        UXENSTOR_RING_SIZE, UXENSTOR_DEST_DOMAIN,
        UXENSTOR_DEST_PORT + this->deviceIndex, &new_ring);
    if (err != 0) {
        kprintf(
            "uxen_v4v_storage_device::start Failed to create v4v ring for disk"
            "index %u, error %d\n", this->deviceIndex, err);
        this->detach(this->v4v_service);
        return false;
    }
    
    this->max_write_size = max_write_payload_size_for_device(
        this->v4v_service, this->deviceIndex) >> 2;
    if (this->max_write_size == 0) {
        this->detach(this->v4v_service);
        return false;
    }
    
    this->v4v_ring = new_ring;
    
    this->live_tasks_lock = IOSimpleLockAlloc();
    RB_INIT(&this->live_tasks);

    this->bounce_buffer = IOMalloc(UXENSTOR_RING_SIZE);
    this->bounce_buffer_lock = IOLockAlloc();

    this->setName("uxen_v4v_storage_device");
    char dev_index_str[11] = "";
    snprintf(dev_index_str, sizeof(dev_index_str), "%u", this->deviceIndex);
    this->setLocation(dev_index_str);

    device_characteristics = OSDictionary::withCapacity(2);
    max_read_size_num = OSNumber::withNumber(UXENSTOR_MAX_READ_IO_SIZE, 64);
    device_characteristics->setObject(kIOMaximumByteCountReadKey, max_read_size_num);
    OSSafeReleaseNULL(max_read_size_num);
    max_write_size_num = OSNumber::withNumber(this->max_write_size, 32);
    device_characteristics->setObject(kIOMaximumByteCountWriteKey, max_write_size_num);
    OSSafeReleaseNULL(max_write_size_num);
    this->setProperty(kIOPropertySCSIDeviceCharacteristicsKey, device_characteristics);
    OSSafeReleaseNULL(device_characteristics);
    
    proto_characteristics = OSDictionary::withCapacity(2);
    v4v = OSString::withCStringNoCopy("V4V");
    proto_characteristics->setObject(kIOPropertyPhysicalInterconnectTypeKey, v4v);
    OSSafeReleaseNULL(v4v);
    internal = OSString::withCStringNoCopy(kIOPropertyInternalKey);
    proto_characteristics->setObject(kIOPropertyPhysicalInterconnectLocationKey,
        internal);
    OSSafeReleaseNULL(internal);
    this->setProperty(kIOPropertyProtocolCharacteristicsKey, proto_characteristics);
    OSSafeReleaseNULL(proto_characteristics);


    if (!this->IOSCSIProtocolServices::start(provider))
        return false;
    
    this->registerService();

    return true;
}

void
uxen_v4v_storage_device::stop(IOService *provider)
{

    if (this->v4v_ring != nullptr) {
        this->v4v_service->destroyRing(this->v4v_ring);
        this->v4v_ring = nullptr;
    }
    if (this->v4v_service != nullptr) {
        this->detach(this->v4v_service);
        this->v4v_service = nullptr;
    }
    if (this->bounce_buffer != nullptr) {
        IOFree(this->bounce_buffer, UXENSTOR_RING_SIZE);
        this->bounce_buffer = nullptr;
    }
    if (this->bounce_buffer_lock != nullptr) {
        IOLockFree(this->bounce_buffer_lock);
        this->bounce_buffer_lock = nullptr;
    }
    if (this->live_tasks_lock != nullptr) {
        IOSimpleLockFree(this->live_tasks_lock);
        this->live_tasks_lock = nullptr;
    }
    
    this->super::stop(provider);
}

static bool
uxen4v4storage_can_send_message_with_size(unsigned device_index,
    uxen_v4v_service *v4v_service, uint32_t msg_size)
{

    union {
        v4v_ring_data_t data;
        char bytes[sizeof(v4v_ring_data_t) + sizeof(v4v_ring_data_ent_t)];
    } notify = {
        {
            .magic = V4V_RING_DATA_MAGIC,
            .nent = 1,
        },
    };
    notify.data.data[0] = (v4v_ring_data_ent_t)
        {
            { .domain = UXENSTOR_DEST_DOMAIN,
                .port = UXENSTOR_DEST_PORT + device_index },
            .space_required = msg_size
        };
    errno_t err = v4v_service->notify(&notify.data);
    return !(err == 0 && 0 == (notify.data.data[0].flags & V4V_RING_DATA_F_SUFFICIENT));
}

static SCSITaskIdentifier_rb_entry *task_rb_entry_alloc()
{
    SCSITaskIdentifier_rb_entry *e;

    e = static_cast<SCSITaskIdentifier_rb_entry*>(
        IOMalloc(sizeof(*e)));
    return e;
}

static void
task_rb_entry_free(SCSITaskIdentifier_rb_entry *e)
{

    IOFree(e, sizeof(*e));
}

bool
uxen_v4v_storage_device::SendSCSICommand(
    SCSITaskIdentifier request,
    SCSIServiceResponse *serviceResponse, SCSITaskStatus *taskStatus)
{
    SCSITaskIdentifier_rb_entry *tree_entry;
    uint8_t dataDir;
    bool writeData;
    uint32_t remainder;
    uint32_t paddingSize;
    unsigned int num_bufs;
    IOMemoryMap *mmap;
    IOMemoryDescriptor *dataBuffer;
    void* copy;
    UInt64 dataLength;
    UInt64 dataOffset;
    ssize_t bytes_sent;
    bool already_responded;
    
    struct
    {
        v4v_disk_transfer_t header;
        SCSICommandDescriptorBlock cdb_data;
    } msg __attribute__((aligned(16))) = {};
    _Static_assert(sizeof(msg) % 16 == 0,"message is padded to 16 byte boundary");
    if (!GetCommandDescriptorBlock(request, &msg.cdb_data)) {
        kprintf("UxenV4VStorageDevice::SendSCSICommand GetCommandDescriptorBlock"
            " failed\n");
        return false;
    }
    uint32_t cdb_size = GetCommandDescriptorBlockSize(request);
    
    tree_entry = task_rb_entry_alloc();
    if (tree_entry == nullptr)
        return false;
    tree_entry->submitted = false;
    tree_entry->received_response = false;
    
    msg.header.seq = reinterpret_cast<uintptr_t>(request);
    msg.header.cdb_size = cdb_size;
    dataDir = GetDataTransferDirection(request);
    writeData = false;
    if( dataDir == kSCSIDataTransfer_FromInitiatorToTarget) {
        writeData = true;
    }
    
    if (writeData) {
        msg.header.write_size = static_cast<uint32_t>
            (GetRequestedDataTransferCount(request));
        msg.header.read_size = 0;
    } else {
        msg.header.read_size = static_cast<uint32_t>
            (GetRequestedDataTransferCount(request));
        msg.header.write_size = 0;
    }
    
    msg.header.pagelist_size = 0;
    msg.header.sense_size = static_cast<uint32_t>
        (GetAutosenseRequestedDataTransferCount(request));
    msg.header.status = 0;
    
    remainder = (sizeof(v4v_disk_transfer_t) + cdb_size) % 16;
    paddingSize = 0;
    if(remainder != 0) {
        paddingSize = 16 - remainder;
    }
    
    num_bufs = 1;
    if(writeData)
        num_bufs += 1;
    v4v_iov_t buffer [num_bufs];

    buffer[0].iov_base = reinterpret_cast<uintptr_t>(&msg);
    buffer[0].iov_len = sizeof(v4v_disk_transfer_t) + cdb_size + paddingSize;
    
    mmap = nullptr;
    dataBuffer = nullptr;
    copy = nullptr;
    dataLength = 0;
    
    if (writeData) {
        /* before we do any expensive copying or mapping, check if we can even
         * send this much data */
        dataLength = GetRequestedDataTransferCount(request);
        if (!uxen4v4storage_can_send_message_with_size(
                this->deviceIndex, this->v4v_service,
                static_cast<uint32_t>(buffer[0].iov_len + dataLength)))
            return false;
        
        dataBuffer = GetDataBuffer(request);
        dataOffset = GetDataBufferOffset(request);
        mmap = dataBuffer->createMappingInTask(kernel_task, 0,
            kIOMapAnywhere | kIOMapReadOnly, dataOffset, dataLength);
        if (mmap != nullptr && mmap->getLength() >= dataLength
              && kIOReturnSuccess
                 == mmap->wireRange(kIODirectionOut, 0, dataLength)) {
            buffer[1].iov_base = mmap->getAddress();
        } else {
            /* mapping failed or ended up too short - can happen e.g. if it's
             * an IOMultiMemoryDescriptor */
            OSSafeReleaseNULL(mmap);
            IOLockLock(this->bounce_buffer_lock);
            copy = this->bounce_buffer;
            assert(UXENSTOR_RING_SIZE >= dataLength);
            assert(copy != nullptr);
            dataBuffer->readBytes(dataOffset, copy, dataLength);
            buffer[1].iov_base = reinterpret_cast<uint64_t>(copy);
        }
        buffer[1].iov_len = dataLength;
    } else {
        /* No operations need to be performed on the request once it's been
         * passed to the device if no payload data is being written. */
        tree_entry->submitted = true;
    }
    
    tree_entry->task = request;
    IOSimpleLockLock(this->live_tasks_lock);
    RB_INSERT(SCSITaskIdentifier_rb_head, &this->live_tasks, tree_entry);
    IOSimpleLockUnlock(this->live_tasks_lock);
    
    bytes_sent = this->v4v_service->sendvOnRing(
        this->v4v_ring,
        v4v_addr_t({ .domain = UXENSTOR_DEST_DOMAIN,
            .port = UXENSTOR_DEST_PORT + this->deviceIndex }),
        buffer,
        num_bufs);
    if (bytes_sent == -EFAULT && copy == nullptr) {
        /* Hypercall did not like pointer we gave it. Try again with a copy 
         * of the data. */
        assert(UXENSTOR_RING_SIZE >= dataLength);
        IOLockLock(this->bounce_buffer_lock);
        copy = this->bounce_buffer;
        assert(copy != nullptr);
        dataBuffer->prepare(kIODirectionOut);
        dataBuffer->readBytes(GetDataBufferOffset(request), copy, dataLength);
        dataBuffer->complete(kIODirectionOut);
        buffer[1].iov_base = reinterpret_cast<uint64_t>(copy);

        bytes_sent = this->v4v_service->sendvOnRing(
            this->v4v_ring,
            v4v_addr_t({ .domain = UXENSTOR_DEST_DOMAIN,
                .port = UXENSTOR_DEST_PORT + this->deviceIndex }),
            buffer,
            num_bufs);
    }
    
    if (copy != nullptr)
        IOLockUnlock(this->bounce_buffer_lock);
    
    if (mmap != nullptr)
        mmap->wireRange(kIODirectionNone, 0, dataLength); // direction=none->unwire
    OSSafeReleaseNULL(mmap);
    
    if (bytes_sent > 0) {
        *serviceResponse = kSCSIServiceResponse_Request_In_Process;
        *taskStatus = kSCSITaskStatus_GOOD;
        if (writeData) {
            if (bytes_sent > buffer[0].iov_len)
                this->SetRealizedDataTransferCount(request,
                    bytes_sent - buffer[0].iov_len);
            
            IOSimpleLockLock(this->live_tasks_lock);
            tree_entry->submitted = true;
            already_responded = tree_entry->received_response;
            IOSimpleLockUnlock(this->live_tasks_lock);
            
            if (already_responded) {
                // Another thread has already received the response.
                CommandCompleted(request, kSCSIServiceResponse_TASK_COMPLETE,
                    tree_entry->response_status);
                task_rb_entry_free(tree_entry);
            }
        }
        return true;
    } else {
        IOSimpleLockLock(this->live_tasks_lock);
        RB_REMOVE(SCSITaskIdentifier_rb_head, &this->live_tasks, tree_entry);
        IOSimpleLockUnlock(this->live_tasks_lock);
        this->SetRealizedDataTransferCount(request, 0);
        if (bytes_sent == -EAGAIN) {
            //not enough space
            return false;
        } else {
            kprintf("uxen_v4v_storage_device::SendSCSICommand: error %ld while"
                "sending %llu + %llu byte request\n",
                bytes_sent, buffer[0].iov_len, writeData ? buffer[1].iov_len : 0);
            IOLog("uxen_v4v_storage_device::SendSCSICommand: error %ld while sending"
                " %llu + %llu byte request\n",
                bytes_sent, buffer[0].iov_len, writeData ? buffer[1].iov_len : 0);
            *serviceResponse = kSCSIServiceResponse_SERVICE_DELIVERY_OR_TARGET_FAILURE;
            *taskStatus = kSCSITaskStatus_DeliveryFailure;
            return true;
        }
    }
}


SCSIServiceResponse
uxen_v4v_storage_device::AbortSCSICommand (SCSITaskIdentifier request)
{

    return kSCSIServiceResponse_SERVICE_DELIVERY_OR_TARGET_FAILURE;
}

bool
uxen_v4v_storage_device::IsProtocolServiceSupported(
    SCSIProtocolFeature feature, void *serviceValue)
{
    uint64_t *maxReadBytes;
    uint64_t *maxWriteBytes;
    
    if(feature == kSCSIProtocolFeature_MaximumReadTransferByteCount) {
        maxReadBytes = static_cast<uint64_t*>(serviceValue);
        *maxReadBytes = UXENSTOR_MAX_READ_IO_SIZE;
        return true;
    } else if (feature == kSCSIProtocolFeature_MaximumWriteTransferByteCount) {
        maxWriteBytes = static_cast<uint64_t*>(serviceValue);
        *maxWriteBytes = this->max_write_size;
        return true;
    }
    return false;
}
bool
uxen_v4v_storage_device::HandleProtocolServiceFeature(
    SCSIProtocolFeature feature, void *serviceValue)
{

    return false;
}

bool
uxen_v4v_storage_device::initWithDeviceIndex(
    unsigned device_idx, uxen_v4v_service *service, OSDictionary *propTable)
{

    if (!this->IOSCSIProtocolServices::init(propTable))
        return false;
    this->v4v_service = service;
    IOWorkLoop* work_loop = this->v4v_service->getWorkLoop();
    this->command_gate = IOCommandGate::commandGate(this);
    this->command_gate->setWorkLoop(work_loop);
    this->deviceIndex = device_idx;
    return true;
}


IOReturn
uxen_v4v_storage_device::message(
    UInt32 type, IOService *provider, void *argument)
{
    bool resetRing;
    
    if (type == kUxenV4VServiceRingNotification && provider == this->v4v_service) {
        resetRing = false;
        this->command_gate->runAction(&gatedProcessCompletedRequests, &resetRing);
        return kIOReturnSuccess;
    } else if(type == kUxenV4VServiceRingResetNotification && provider ==
        this->v4v_service) {
        resetRing = true;
        this->command_gate->runAction(&gatedProcessCompletedRequests, &resetRing);
        return kIOReturnSuccess;
    } else {
        return this->IOSCSIProtocolServices::message(type, provider, argument);
    }
}

IOReturn
uxen_v4v_storage_device::gatedProcessCompletedRequests(
    OSObject *owner, void *arg0, void *arg1, void *arg2, void *arg3)
{
    bool resetRing;
    
    resetRing = *static_cast<const bool*>(arg0);
    static_cast<uxen_v4v_storage_device*>(owner)->processCompletedRequests(
        resetRing);
    
    return kIOReturnSuccess;
}

static SCSITaskIdentifier_rb_entry*
find_and_remove_task(IOSimpleLock *lock, SCSITaskIdentifier_rb_head* task_tree,
    uintptr_t seq)
{
    SCSITaskIdentifier_rb_entry *found;
    SCSITaskIdentifier_rb_entry find;

    find = {{}, static_cast<SCSITaskIdentifier>(reinterpret_cast<void*>(seq)) };
    IOSimpleLockLock(lock);
    found = RB_FIND(SCSITaskIdentifier_rb_head, task_tree, &find);
    if (found != nullptr)
        RB_REMOVE(SCSITaskIdentifier_rb_head, task_tree, found);
    IOSimpleLockUnlock(lock);
    return found;
}

void
uxen_v4v_storage_device::processCompletedRequests(bool resetRing)
{
    bool a_message_received;
    v4v_disk_transfer_t header;
    ssize_t messageSize;
    SCSITaskIdentifier_rb_entry *task_entry;
    SCSITaskIdentifier request;
    IOMemoryMap *mmap;
    IOMemoryDescriptor *dataBuffer;
    UInt64 dataOffset;
    UInt64 dataLength;
    size_t actual_payload_size;
    SCSI_Sense_Data senseData;
    size_t actual_sense_size;
    bool complete;

    if (this->v4v_ring == nullptr)
        return;
    if(resetRing)
        this->v4v_service->reregisterRing(this->v4v_ring);
    a_message_received = false;
    while (true) {
        header = {};
        messageSize = this->v4v_service->receiveFromRing(this->v4v_ring, &header,
            sizeof(header), false);
        if (messageSize < 0)
            break;
        if (messageSize < sizeof(header)) {
            kprintf(
                "uxen_v4v_storage_device::processRequestCompleted() message size "
                "(%lu) is smaller than the header (%lu)\n",
                messageSize, sizeof(header));
            this->v4v_service->receiveFromRing(this->v4v_ring, nullptr, 0, true);
            continue;
        }
        

        task_entry = find_and_remove_task(
            this->live_tasks_lock, &this->live_tasks, header.seq);
        if (task_entry == nullptr) {
            kprintf("uxen_v4v_storage_device::processRequestCompleted(): task"
                "response from device with seq %016llx, no matching request"
                "found\n", header.seq);
            this->v4v_service->receiveFromRing(this->v4v_ring, nullptr, 0, true);
            continue;
        }
        request = task_entry->task;
        

        
        if(header.read_size > 0) {
            mmap = nullptr;
            //data to be read
            dataBuffer = GetDataBuffer(request);
            dataOffset = GetDataBufferOffset(request);
            dataLength = GetRequestedDataTransferCount(request);
            dataBuffer->prepare(kIODirectionIn);
            mmap = dataBuffer->createMappingInTask(kernel_task, 0, kIOMapAnywhere,
                dataOffset, dataLength);
            actual_payload_size = min(min(header.read_size, dataLength),
                messageSize - sizeof(header));
            if (mmap != nullptr) {
                void* dataAddress = reinterpret_cast<void*>(mmap->getAddress());
                v4v_copy_out_offset(
                    this->v4v_ring->ring,
                    nullptr, nullptr,
                    dataAddress,
                    sizeof(header) + actual_payload_size, // NOT no of bytes to
                    //copy, but end of submessage
                    false,
                    sizeof(header)); // offset
            } else {
                // failed to map memory descriptor - might be a
                // multimemorydescriptor etc.
                // use bounce buffer instead
                assert(actual_payload_size <= UXENSTOR_RING_SIZE);
                IOLockLock(this->bounce_buffer_lock);
                v4v_copy_out_offset(
                    this->v4v_ring->ring,
                    nullptr, nullptr,
                    this->bounce_buffer,
                    sizeof(header) + actual_payload_size, // NOT no of bytes to
                    //copy, but end of submessage
                    false,
                    sizeof(header)); // offset
                dataBuffer->writeBytes(dataOffset, this->bounce_buffer,
                    actual_payload_size);
                IOLockUnlock(this->bounce_buffer_lock);
            }
            dataBuffer->complete(kIODirectionIn);
            
            SetRealizedDataTransferCount(request, actual_payload_size);
            OSSafeRelease(mmap);
        } else if(header.sense_size > 0) {
            //sense data to be read
            senseData = {};
            v4v_copy_out_offset(
                this->v4v_ring->ring,
                nullptr, nullptr,
                &senseData,
                sizeof(header) + sizeof(senseData), // NOT no of bytes to copy,
                //but end of submessage
                false, sizeof(header));
            actual_sense_size = min(min(header.sense_size, sizeof(senseData)),
                messageSize - sizeof(header));
            SetAutoSenseData(request, &senseData, actual_sense_size);
        }
        
        this->v4v_service->receiveFromRing(this->v4v_ring, nullptr, 0, true);
        a_message_received = true;

        IOSimpleLockLock(this->live_tasks_lock);
        complete = task_entry->submitted; // only finish up if the submission is
        //already done.
        task_entry->response_status = static_cast<SCSITaskStatus>(header.status);
        task_entry->received_response = true;
        IOSimpleLockUnlock(this->live_tasks_lock);
        if (complete) {
            CommandCompleted(request, kSCSIServiceResponse_TASK_COMPLETE,
                static_cast<SCSITaskStatus>(header.status));
            task_rb_entry_free(task_entry);
        } /* else {
            kprintf("uxen_v4v_storage_device::processCompletedRequests: "
                "Requesting thread not finished yet.\n");
        } */
    }
    if (a_message_received) {
        this->v4v_service->notify();
    }
}


IOWorkLoop *
uxen_v4v_storage_device::getWorkLoop() const
{

    if(this->v4v_service == nullptr) {
        return nullptr;
    }
    return this->v4v_service->getWorkLoop();
}


void
uxen_v4v_storage_device::free(void)
{

    OSSafeReleaseNULL(this->command_gate);
    this->super::free();
}

#pragma mark -

