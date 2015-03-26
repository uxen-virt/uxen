/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Gianluca Guida <glguida@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"

OSDefineMetaClassAndStructors(uxen_user_client, IOUserClient)

bool
uxen_user_client::initWithTask(task_t owningTask, void *securityToken,
                               UInt32 type, OSDictionary *properties)
{
    if (!owningTask)
        return false;

    if (type != 0)
        return false;

    if (!IOUserClient::initWithTask(owningTask, securityToken, type, properties))
        return false;

    this->task = owningTask;

    return true;
}

bool
uxen_user_client::start(IOService *provider)
{
    int ret;

    if (!IOUserClient::start(provider))
        return false;

    this->owner = OSDynamicCast(uxen_driver, provider);
    if (!this->owner)
        return false;

    dprintk("%s task %p client %p\n", __FUNCTION__, this->task, this);

    ret = uxen_open(&this->fd_assoc, this->task);

    if (ret)
        return false;

    return true;
}

IOReturn
uxen_user_client::externalMethod(uint32_t cmd,
                                 IOExternalMethodArguments *args,
                                 IOExternalMethodDispatch *dispatch,
                                 OSObject *target,
                                 void *reference)
{
    IOReturn ret = 0;
    void *in_buf = NULL;
    void *out_buf = NULL;
    size_t in_len = 0;
    size_t out_len = 0;
    IOMemoryMap *in_map = NULL;
    IOMemoryMap *out_map = NULL;
    struct vm_info *vmi;
    struct fd_assoc *fda;

    if (args->structureOutputSize) {
        out_buf = args->structureOutput;
        out_len = args->structureOutputSize;
    } else if (args->structureOutputDescriptor) {
        out_map = args->structureOutputDescriptor->createMappingInTask(
                kernel_task, 0, kIOMapAnywhere);
        if (!out_map) {
            fail_msg("%s: failed to map output buffer. cmd=%x", __FUNCTION__,
                     cmd);
            ret = EINVAL;
            goto out;
        }
        out_buf = (void *)out_map->getVirtualAddress();
        out_len = out_map->getLength();
    }

    if (args->structureInputSize) {
        in_buf = (void *)args->structureInput;
        in_len = args->structureInputSize;
    } else if (args->structureInputDescriptor) {
        in_map = args->structureInputDescriptor->createMappingInTask(
                kernel_task, 0, kIOMapReadOnly | kIOMapAnywhere);
        if (!in_map) {
            fail_msg("%s: failed to map input buffer. cmd=%x", __FUNCTION__,
                     cmd);
            ret = EINVAL;
            goto out;
        }
        in_buf = (void *)in_map->getVirtualAddress();
        in_len = in_map->getLength();
    }

    /* RW ioctl -> use output buffer */
    if (out_len && in_len) {
        if (out_buf != in_buf)
            memcpy(out_buf, in_buf, in_len < out_len ? in_len : out_len);
        in_buf = out_buf;
        in_len = out_len;
    }

    fda = &fd_assoc;
    vmi = fda->vmi;

    ret = uxen_ioctl(cmd, fda, vmi, in_buf, in_len, out_buf, out_len);

  out:
    if (in_map)
        in_map->release();
    if (out_map)
        out_map->release();

    return ret;
}

IOReturn uxen_user_client::registerNotificationPort(mach_port_t port,
                                                    UInt32 type,
                                                    UInt32 refCon)
{
    struct fd_assoc *fda = &this->fd_assoc;


    if (type != 0)
        return kIOReturnUnsupported;


    if (fda->notification_port != MACH_PORT_NULL)
        return kIOReturnPortExists;

    fda->notification_port = port;

    return kIOReturnSuccess;
}


IOReturn
uxen_user_client::clientClose(void)
{

    dprintk("%s task %p client %p\n", __FUNCTION__, task, this);

    uxen_close(&this->fd_assoc);

    dprintk("%s task %p client %p done\n", __FUNCTION__, task, this);

    this->terminate();

    return kIOReturnSuccess;
}

void
uxen_user_client::stop(IOService *provider)
{
    IOUserClient::stop(provider);
}

void
uxen_user_client::free(void)
{
    IOUserClient::free();
}

