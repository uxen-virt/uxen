/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENPLATFORM_H_
#define _UXENPLATFORM_H_

#include <IOKit/IOService.h>
#include <IOKit/IOFilterInterruptEventSource.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/pci/IOPCIDevice.h>

#include <xen/version.h>
#include <xen/xen.h>

#include <uxen/platform_interface.h>

#include "uxenplatform_public.h"
#include "balloon.h"

#if DEBUG
#define dprintk(fmt, ...) IOLog("uxenplatform: " fmt, ## __VA_ARGS__)
#else
#define dprintk(fmt, ...) do {} while (0);
#endif

class uXenPlatform : public IOService
{
    OSDeclareDefaultStructors(uXenPlatform);

public:
    /* IOService */
    virtual bool init(OSDictionary *dict = NULL);
    virtual void free(void);
    virtual IOService *probe(IOService *provider, SInt32 *score);

    virtual bool start(IOService *provider);
    virtual void stop(IOService *provider);

    /* hypercall */
    int hypercall_version(int cmd, void *arg);
    int hypercall_memory_op(int cmd, void *arg);
    int hypercall_hvm_op(int cmd, void *arg);

    /* client methods */
    IOReturn get_info(struct uXenPlatformInfo *arg);
    IOReturn get_balloon_stats(struct uXenPlatformBalloonStats *arg);
    IOReturn set_balloon_target(struct uXenPlatformBalloonTarget *arg);

private:
    bool filterInterrupt(IOFilterInterruptEventSource *src);
    void handleInterrupt(IOInterruptEventSource *src, int count);

    static bool filter_interrupt(OSObject *owner,
                                 IOFilterInterruptEventSource *src)
    {
        uXenPlatform *platform = (uXenPlatform *)owner;
        return platform->filterInterrupt(src);
    }
    static void handle_interrupt(OSObject *owner,
                                 IOInterruptEventSource *src,
                                 int count)
    {
        uXenPlatform *platform = (uXenPlatform *)owner;
        platform->handleInterrupt(src, count);
    }

    bool hypercall_init(void);
    void hypercall_cleanup(void);

    IOPCIDevice *pcidev;
    IODeviceMemory *bar0;
    IODeviceMemory *bar2;
    IOBufferMemoryDescriptor *hypercall_desc;
    IOFilterInterruptEventSource *evtsrc;

    xen_extraversion_t extraversion;
    uint16_t uxen_version_major, uxen_version_minor;

    uXenBalloon balloon;
    OSArray *nubs;

    void enable_interrupt(int events);
    uint32_t pending_events;

    void enumerate_devices(void);
    void stop_devices(void);
};

#endif /* _UXENPLATFORM_H_ */
