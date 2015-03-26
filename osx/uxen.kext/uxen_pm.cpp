/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"

#include <IOKit/IOLib.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPM.h>

static IONotifier *notifier;

static IOReturn pm_handler(void *target, void *ref,
                           UInt32 msg_type, IOService *provider,
                           void *msg_arg, vm_size_t arg_sz)
{
#if 0
    dprintk("%s: target=%p, ref=%p, msg_type=%x, provider=%p, msg_arg=%p, arg_sz=%ld\n",
            __FUNCTION__, target, ref, msg_type, provider, msg_arg, arg_sz);
#endif

    switch (msg_type) {
    case kIOMessageSystemWillSleep:
        uxen_power_state(1);
        break;
    case kIOMessageSystemHasPoweredOn:
        uxen_power_state(0);
        break;
    default:
        break;
    }

    acknowledgeSleepWakeNotification(ref);

    return 0;
}

int uxen_pm_init(void)
{
    notifier = registerPrioritySleepWakeInterest(pm_handler, NULL, NULL);
    if (!notifier)
        return -1;

    return 0;
}

void uxen_pm_cleanup(void)
{
    if (notifier)
        notifier->remove();
}

