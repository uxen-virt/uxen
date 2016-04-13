/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Gianluca Guida <glguida@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"

extern "C" kern_return_t _start(kmod_info_t *ki, void *data);
extern "C" kern_return_t _stop(kmod_info_t *ki, void *data);
KMOD_EXPLICIT_DECL(org.uxen.uxen, 0, _start, _stop)
extern "C" {
    kmod_start_func_t *_realmain = 0;
    kmod_stop_func_t *_antimain = 0;
};

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
