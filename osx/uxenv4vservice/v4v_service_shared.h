/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _V4V_SERVICE_SHARED_H_
#define _V4V_SERVICE_SHARED_H_

#include <IOKit/IOMessage.h>

enum uxen_v4v_user_method
{
    kUxenV4V_BindRing,
    kUxenV4V_SendTo,
    kUxenV4V_Notify,
	
    kUxenV4V_UserMethodCount
};

static const unsigned kUxenV4V_SendFlag_IgnoreDLO = (1u << 0);


enum uxen_v4v_user_notification_port_type
{
    kUxenV4VPort_ReceiveEvent,
    kUxenV4VPort_SendEvent,
};

static const uint32_t kUxenV4VServiceRingNotification =
    iokit_vendor_specific_msg(0);
static const uint32_t kUxenV4VServiceRingResetNotification =
    iokit_vendor_specific_msg(1);

#define kUxenV4VServiceClassName "org_uxen_driver_v4v_service"

#endif
