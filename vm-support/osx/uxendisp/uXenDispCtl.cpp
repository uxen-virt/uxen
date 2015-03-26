/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <IOKit/IOUserClient.h>

#include "uXenDispFB.h"
#include "uXenDispCtl.h"

#define super IOUserClient

OSDefineMetaClassAndStructors(uXenDispCtl, IOUserClient)

bool
uXenDispCtl::initWithTask(task_t owningTask, void *securityToken,
                                 UInt32 type, OSDictionary *properties)
{
    dprintk("%s: task=%p token=%p, type=%d, prop=%p", __func__,
            owningTask, securityToken, type, properties);

    if (!owningTask)
        return false;

    if (type != kIOuXenDispCtlConnectType)
        return false;

    if (!super::initWithTask(owningTask, securityToken, type, properties))
        return false;

    if (clientHasPrivilege(securityToken, kIOClientPrivilegeAdministrator) !=
        kIOReturnSuccess)
        return false;

    task = owningTask;

    return true;
}

bool
uXenDispCtl::start(IOService *provider)
{
    if (!super::start(provider))
        return false;

    owner = OSDynamicCast(uXenDispFB, provider);
    if (!owner)
        return false;

    return true;
}

IOReturn
uXenDispCtl::clientClose(void)
{
    terminate();

    return kIOReturnSuccess;
}

void
uXenDispCtl::stop(IOService *provider)
{
    super::stop(provider);
}

void
uXenDispCtl::free(void)
{
    super::free();
}

IOReturn
uXenDispCtl::setCustomMode(struct uXenDispCustomMode *mode)
{
    dprintk("%s: %ldx%ld", __func__, mode->width, mode->height);

    return owner->setCustomMode(mode->width, mode->height);
}

static IOReturn mSetCustomMode(OSObject *target, void *reference,
                               IOExternalMethodArguments *args)
{
    struct uXenDispCustomMode *in =
        (struct uXenDispCustomMode *)args->structureInput;
    uXenDispCtl *object = (uXenDispCtl *)target;

    return object->setCustomMode(in);
}

static IOExternalMethodDispatch methods[kIOuXenDispCtlMethodCount] = {
    /* kIOuXenDispCtlMethodSetCustomMode */
    { mSetCustomMode, 0, sizeof (struct uXenDispCustomMode), 0, 0 },
};

IOReturn
uXenDispCtl::externalMethod(uint32_t selector,
                            IOExternalMethodArguments *args,
                            IOExternalMethodDispatch *dispatch,
                            OSObject *target,
                            void *reference)
{
    if (selector >= kIOuXenDispCtlMethodCount)
        return kIOReturnUnsupported;

    dispatch = &methods[selector];
    target = this;
    reference = NULL;
    return super::externalMethod(selector, args, dispatch, target, reference);
}
