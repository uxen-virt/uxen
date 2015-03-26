/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <IOKit/IOLib.h>
#include <IOKit/IOUserClient.h>

#include "uXenPlatform.h"
#include "uXenPlatformClient.h"

#define super IOUserClient

OSDefineMetaClassAndStructors(uXenPlatformClient, IOUserClient)

bool
uXenPlatformClient::initWithTask(task_t owningTask, void *securityToken,
                                 UInt32 type, OSDictionary *properties)
{
    if (!owningTask)
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
uXenPlatformClient::start(IOService *provider)
{
    if (!super::start(provider))
        return false;

    owner = OSDynamicCast(uXenPlatform, provider);
    if (!owner)
        return false;

    return true;
}

IOReturn
uXenPlatformClient::clientClose(void)
{
    terminate();

    return kIOReturnSuccess;
}

void
uXenPlatformClient::stop(IOService *provider)
{
    super::stop(provider);
}

void
uXenPlatformClient::free(void)
{
    super::free();
}

IOExternalMethodDispatch
uXenPlatformClient::methods[kIOuXenPlatformMethodCount] = {
    [kIOuXenPlatformMethodGetInfo] = {
        uXenPlatformClient::GetInfo,
        0,
        0,
        0,
        sizeof (struct uXenPlatformInfo)
    },
    [kIOuXenPlatformMethodGetBalloonStats] = {
        uXenPlatformClient::GetBalloonStats,
        0,
        0,
        0,
        sizeof (struct uXenPlatformBalloonStats)
    },
    [kIOuXenPlatformMethodSetBalloonTarget] = {
        uXenPlatformClient::SetBalloonTarget,
        0,
        sizeof (struct uXenPlatformBalloonTarget),
        0,
        sizeof (struct uXenPlatformBalloonTarget)
    }
};

IOReturn
uXenPlatformClient::GetInfo(OSObject *target, void *ref,
                               IOExternalMethodArguments *args)
{
    struct uXenPlatformInfo *out;
    uXenPlatformClient *client;

    out = (struct uXenPlatformInfo *)args->structureOutput;
    client = (uXenPlatformClient *)target;

    return client->owner->get_info(out);
}

IOReturn
uXenPlatformClient::GetBalloonStats(OSObject *target, void *ref,
                                    IOExternalMethodArguments *args)
{
    struct uXenPlatformBalloonStats *out;
    uXenPlatformClient *client;

    out = (struct uXenPlatformBalloonStats *)args->structureOutput;
    client = (uXenPlatformClient *)target;

    return client->owner->get_balloon_stats(out);
}

IOReturn
uXenPlatformClient::SetBalloonTarget(OSObject *target, void *ref,
                                     IOExternalMethodArguments *args)
{
    struct uXenPlatformBalloonTarget *out, *in;
    uXenPlatformClient *client;

    out = (struct uXenPlatformBalloonTarget *)args->structureOutput;
    in = (struct uXenPlatformBalloonTarget *)args->structureInput;
    *out = *in;
    client = (uXenPlatformClient *)target;

    return client->owner->set_balloon_target(out);
}

IOReturn
uXenPlatformClient::externalMethod(uint32_t selector,
                                   IOExternalMethodArguments *args,
                                   IOExternalMethodDispatch *dispatch,
                                   OSObject *target,
                                   void *reference)
{
    if (selector >= (sizeof (methods) / sizeof (methods[0])))
        return kIOReturnUnsupported;

    dispatch = &methods[selector];
    target = this;
    reference = NULL;
    return super::externalMethod(selector, args, dispatch, target, reference);
}
