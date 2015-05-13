/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Gianluca Guida <glguida@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"
#include "dom0_v4v_device.h"

extern "C" kern_return_t _start(kmod_info_t *ki, void *data);
extern "C" kern_return_t _stop(kmod_info_t *ki, void *data);
KMOD_EXPLICIT_DECL(org.uxen.uxen, 0, _start, _stop)
extern "C" {
    kmod_start_func_t *_realmain = 0;
    kmod_stop_func_t *_antimain = 0;
};

void
uxen_driver_publish_v4v_service()
{
    OSDictionary *driver_match;
    IOService *driver;
    OSIterator *clients;
    bool v4v_device_exists;
    OSObject *client;
    uxen_dom0_v4v_device* v4v_dev;
    
    driver_match = IOService::serviceMatching("uxen_driver");
    driver = IOService::copyMatchingService(driver_match);
    OSSafeReleaseNULL(driver_match);
    if (driver != nullptr) {
        if (driver->lockForArbitration()) {
            clients = driver->getClientIterator();
            v4v_device_exists = false;
            if (clients != nullptr) {
                while ((client = clients->getNextObject())) {
                    if (OSDynamicCast(uxen_dom0_v4v_device, client) != nullptr){
                        v4v_device_exists = true;
                        break;
                    }
                }
                clients->release();
            }
            
            if (!v4v_device_exists) {
                IOLog("uxen_driver_publish_v4v_service() - creating device\n");
                v4v_dev = new uxen_dom0_v4v_device();
                if (v4v_dev != nullptr && v4v_dev->init(nullptr)) {
                    v4v_dev->attach(driver);
                    
                    driver->unlockForArbitration();
                    
                    if (!v4v_dev->start(driver)) {
                        v4v_dev->detach(driver);
                    }
                }
                OSSafeReleaseNULL(v4v_dev);
            } else {
                kprintf("uxen_driver_publish_v4v_service() - v4v device object already exists\n");
                driver->unlockForArbitration();
            }
            
        } else {
            IOLog("uxen_driver_publish_v4v_service() - failed to lockForArbitration()\n");
        }
        driver->release();
    } else {
        IOLog("uxen_driver_publish_v4v_service() - no driver object found\n");
    }
}

void
uxen_driver_shutdown_v4v_service()
{
    OSDictionary* device_match;
    IOService* device;
    
    device_match = IOService::serviceMatching("org_uxen_driver_dom0_v4v_device");
    device = IOService::copyMatchingService(device_match);
    OSSafeReleaseNULL(device_match);

    if (device != nullptr) {
        device->terminate();
        device->release();
    } else {
        IOLog("uxen_driver_shutdown_v4v_service() - no live device object found\n");
    }
}

OSDefineMetaClassAndStructors(uxen_driver, IOService);

bool
uxen_driver::init(OSDictionary *dict)
{
    bool rc = IOService::init(dict);

    return rc;
}

void
uxen_driver::free(void)
{
    IOService::free();
}

IOService *
uxen_driver::probe(IOService *provider, SInt32 *score)
{
    IOService *ret;

    ret = IOService::probe(provider, score);

    return ret;
}

bool
uxen_driver::start(IOService *provider)
{
#ifdef UXEN_DRIVER_VERSION_CHANGESET
    kmod_info_t *ki = &KMOD_INFO_NAME;
#endif
    bool rc = false;
    int ret;

    rc = IOService::start(provider);
    if (!rc)
        return false;

    ret = uxen_driver_load();
    if (ret)
        goto out;

    rc = true;
    this->setProperty("IOUserClientClass", "uxen_user_client");
    this->registerService();

#ifdef UXEN_DRIVER_VERSION_CHANGESET
    strlcat(ki->version, "-" UXEN_DRIVER_VERSION_CHANGESET, KMOD_MAX_NAME);
#endif

    dprintk("kernel extension loaded sucessfuly\n");

  out:
    if (!rc)
        IOService::stop(provider);
    return rc;
}

void
uxen_driver::stop(IOService *provider)
{

    uxen_driver_unload();
    IOService::stop(provider);
}
