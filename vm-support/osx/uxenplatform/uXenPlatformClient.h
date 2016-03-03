/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENPLATFORMCLIENT_H_
#define _UXENPLATFORMCLIENT_H_

#include <IOKit/IOUserClient.h>

class uXenPlatformClient : public IOUserClient
{
    OSDeclareDefaultStructors(uXenPlatformClient);

public:
    virtual bool initWithTask(task_t, void *, UInt32, OSDictionary *) override;
    virtual bool start(IOService *) override;
    virtual IOReturn clientClose(void) override;
    virtual void stop(IOService *) override;
    virtual void free(void) override;
    virtual IOReturn externalMethod(uint32_t, IOExternalMethodArguments *,
                                    IOExternalMethodDispatch *, OSObject *,
                                    void *) override;

private:
    static IOExternalMethodDispatch methods[];

    static IOReturn GetInfo(OSObject *target, void *ref,
                            IOExternalMethodArguments *args);
    static IOReturn GetBalloonStats(OSObject *target, void *ref,
                                    IOExternalMethodArguments *args);
    static IOReturn SetBalloonTarget(OSObject *target, void *ref,
                                     IOExternalMethodArguments *args);

    task_t task;
    uXenPlatform *owner;
};

#endif /* _UXENPLATFORMCLIENT_H_ */
