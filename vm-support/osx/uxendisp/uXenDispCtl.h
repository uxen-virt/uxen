/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENDISP_CTL_H_
#define _UXENDISP_CTL_H_

#include <IOKit/IOUserClient.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

enum {
    kIOuXenDispCtlConnectType = kIOFBSharedConnectType + 1
};

enum {
    kIOuXenDispCtlMethodSetCustomMode = 0,

    kIOuXenDispCtlMethodCount,
};

struct uXenDispCustomMode
{
    unsigned long width;
    unsigned long height;
};

class uXenDispCtl : public IOUserClient
{
    OSDeclareDefaultStructors(uXenDispCtl);

public:
    virtual bool initWithTask(task_t, void *, UInt32, OSDictionary *);
    virtual bool start(IOService *);
    virtual IOReturn clientClose(void);
    virtual void stop(IOService *);
    virtual void free(void);
    virtual IOReturn externalMethod(uint32_t, IOExternalMethodArguments *,
                                    IOExternalMethodDispatch *, OSObject *,
                                    void *);

    IOReturn setCustomMode(struct uXenDispCustomMode *);

private:
    task_t task;
    uXenDispFB *owner;

};

#endif /* _UXENDISP_CTL_H_ */
